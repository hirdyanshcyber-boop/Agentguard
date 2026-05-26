import httpx
import structlog
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..models.nhi import NHIIdentity, CredentialAlert, AuditLog, RiskLevel
from ..core.config import get_settings

log = structlog.get_logger()
settings = get_settings()


class RotationService:

    async def check_all(self, db: AsyncSession) -> dict:
        """Scan all active NHIs against rotation policy. Create alerts for violations."""
        nhis = await db.scalars(select(NHIIdentity).where(NHIIdentity.is_active == True))
        nhis = list(nhis.all())

        overdue: list[dict] = []
        never_rotated: list[dict] = []
        expiring_soon: list[dict] = []
        now = datetime.now(timezone.utc)
        policy_days = settings.credential_rotation_days
        warn_days = policy_days - 14  # warn 2 weeks before deadline

        for nhi in nhis:
            created = nhi.created_at
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)

            last_rotated = nhi.last_rotated
            reference_date = last_rotated if last_rotated else created
            if reference_date.tzinfo is None:
                reference_date = reference_date.replace(tzinfo=timezone.utc)

            age_days = (now - reference_date).days

            if nhi.last_rotated is None and age_days > policy_days:
                never_rotated.append({"nhi": nhi, "age_days": age_days})
                await self._raise_alert(db, nhi, "never_rotated", RiskLevel.CRITICAL,
                                        f"Credential '{nhi.name}' never rotated — {age_days} days old (policy: {policy_days}d)")

            elif age_days > policy_days:
                overdue.append({"nhi": nhi, "age_days": age_days})
                await self._raise_alert(db, nhi, "rotation_overdue", RiskLevel.HIGH,
                                        f"Credential '{nhi.name}' rotation overdue by {age_days - policy_days} days")

            elif age_days > warn_days:
                expiring_soon.append({"nhi": nhi, "age_days": age_days, "days_remaining": policy_days - age_days})
                await self._raise_alert(db, nhi, "rotation_due_soon", RiskLevel.MEDIUM,
                                        f"Credential '{nhi.name}' due for rotation in {policy_days - age_days} days")

        await db.commit()

        summary = {
            "scanned": len(nhis),
            "never_rotated": len(never_rotated),
            "overdue": len(overdue),
            "expiring_soon": len(expiring_soon),
            "policy_days": policy_days,
            "timestamp": now.isoformat(),
        }

        if settings.alert_webhook_url and (never_rotated or overdue):
            await self._send_webhook(summary, never_rotated + overdue)

        await self._write_audit(db, action="rotation_check_complete", detail=summary)
        log.info("rotation_check_complete", **summary)
        return summary

    async def generate_rotation_report(self, db: AsyncSession) -> dict:
        """Full rotation status report for all NHIs — APRA CPS 234 Attachment G compatible."""
        now = datetime.now(timezone.utc)
        nhis = await db.scalars(select(NHIIdentity).where(NHIIdentity.is_active == True))
        records = []
        for nhi in nhis.all():
            created = nhi.created_at
            if created and created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            last_rotated = nhi.last_rotated
            if last_rotated and last_rotated.tzinfo is None:
                last_rotated = last_rotated.replace(tzinfo=timezone.utc)

            ref = last_rotated or created
            age_days = (now - ref).days if ref else None
            status = "compliant"
            if age_days is None:
                status = "unknown"
            elif age_days > settings.credential_rotation_days:
                status = "overdue"
            elif age_days > settings.credential_rotation_days - 14:
                status = "due_soon"

            records.append({
                "id": nhi.id,
                "name": nhi.name,
                "provider": nhi.provider,
                "credential_type": nhi.credential_type,
                "owner_team": nhi.owner_team,
                "created_at": created.isoformat() if created else None,
                "last_rotated": last_rotated.isoformat() if last_rotated else None,
                "age_days": age_days,
                "rotation_status": status,
                "risk_level": nhi.risk_level,
            })

        compliant = sum(1 for r in records if r["rotation_status"] == "compliant")
        return {
            "report_type": "credential_rotation",
            "apra_cps234_aligned": True,
            "generated_at": now.isoformat(),
            "policy_rotation_days": settings.credential_rotation_days,
            "summary": {
                "total": len(records),
                "compliant": compliant,
                "overdue": sum(1 for r in records if r["rotation_status"] == "overdue"),
                "due_soon": sum(1 for r in records if r["rotation_status"] == "due_soon"),
                "unknown": sum(1 for r in records if r["rotation_status"] == "unknown"),
                "compliance_rate_pct": round(compliant / len(records) * 100, 1) if records else 0,
            },
            "credentials": records,
        }

    async def mark_rotated(self, db: AsyncSession, nhi_id: int, rotated_by: str) -> NHIIdentity | None:
        nhi = await db.get(NHIIdentity, nhi_id)
        if not nhi:
            return None
        now = datetime.now(timezone.utc)
        nhi.last_rotated = now
        # Downgrade risk if rotation was the only issue
        if nhi.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) and not nhi.is_over_privileged:
            nhi.risk_level = RiskLevel.LOW
        await db.commit()
        await self._write_audit(db, action="credential_rotated", actor=rotated_by,
                                identity_id=nhi.id, resource=nhi.external_id,
                                outcome="success", detail={"rotated_at": now.isoformat()})
        log.info("credential_rotated", nhi_id=nhi_id, rotated_by=rotated_by)
        return nhi

    async def _raise_alert(self, db: AsyncSession, nhi: NHIIdentity, alert_type: str,
                           severity: str, message: str):
        # Deduplicate: don't spam same unresolved alert type for same NHI
        existing = await db.scalar(
            select(CredentialAlert).where(
                CredentialAlert.identity_id == nhi.id,
                CredentialAlert.alert_type == alert_type,
                CredentialAlert.resolved == False,
            )
        )
        if existing:
            return
        alert = CredentialAlert(identity_id=nhi.id, alert_type=alert_type,
                                severity=severity, message=message)
        db.add(alert)

    async def _send_webhook(self, summary: dict, violations: list[dict]):
        payload = {
            "source": "agentguard",
            "event": "rotation_violations_detected",
            "summary": summary,
            "violations": [
                {"name": v["nhi"].name, "age_days": v["age_days"],
                 "provider": v["nhi"].provider, "risk_level": v["nhi"].risk_level}
                for v in violations
            ],
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(settings.alert_webhook_url, json=payload)
                log.info("webhook_sent", status=resp.status_code, violations=len(violations))
        except Exception as e:
            log.warning("webhook_failed", error=str(e))

    async def _write_audit(self, db: AsyncSession, action: str, actor: str = "agentguard:rotation-monitor",
                           identity_id: int | None = None, resource: str | None = None,
                           outcome: str = "success", detail: dict | None = None):
        entry = AuditLog(
            event_type="rotation_check",
            actor=actor,
            action=action,
            identity_id=identity_id,
            resource=resource,
            outcome=outcome,
            detail=detail,
            timestamp=datetime.now(timezone.utc),
        )
        db.add(entry)
        await db.commit()
