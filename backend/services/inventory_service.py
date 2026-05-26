import structlog
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from ..models.nhi import NHIIdentity, AuditLog, RiskLevel
from ..scanners.aws_scanner import AWSScanner
from ..scanners.azure_scanner import AzureScanner
from ..scanners.gcp_scanner import GCPScanner
from ..core.config import get_settings

log = structlog.get_logger()
settings = get_settings()


class InventoryService:

    async def run_aws_scan(self, db: AsyncSession) -> dict:
        scanner = AWSScanner(
            access_key_id=settings.aws_access_key_id,
            secret_access_key=settings.aws_secret_access_key,
            region=settings.aws_default_region,
        )
        raw = scanner.scan_all()
        upserted = 0
        flagged = 0

        for item in raw:
            existing = await db.scalar(
                select(NHIIdentity).where(NHIIdentity.external_id == item["external_id"])
            )
            if existing:
                for k, v in item.items():
                    if hasattr(existing, k) and k not in ("id", "external_id"):
                        setattr(existing, k, v)
            else:
                nhi = NHIIdentity(**{k: v for k, v in item.items() if hasattr(NHIIdentity, k)})
                db.add(nhi)

            if item.get("risk_level") in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                flagged += 1

            upserted += 1

        await db.commit()

        await self._write_audit(db, event_type="inventory_scan", action="aws_scan_complete",
                                actor="agentguard:scanner", outcome="success",
                                detail={"upserted": upserted, "flagged": flagged})
        log.info("aws_scan_complete", upserted=upserted, flagged=flagged)
        return {"provider": "aws", "scanned": upserted, "flagged": flagged, "timestamp": datetime.now(timezone.utc).isoformat()}

    async def run_azure_scan(self, db: AsyncSession) -> dict:
        scanner = AzureScanner(
            tenant_id=settings.azure_tenant_id,
            client_id=settings.azure_client_id,
            client_secret=settings.azure_client_secret,
            subscription_id=settings.azure_subscription_id,
        )
        return await self._run_scan(db, scanner, provider="azure")

    async def run_gcp_scan(self, db: AsyncSession) -> dict:
        scanner = GCPScanner(
            project_id=settings.gcp_project_id,
            service_account_key=settings.gcp_service_account_key,
        )
        return await self._run_scan(db, scanner, provider="gcp")

    async def _run_scan(self, db: AsyncSession, scanner, provider: str) -> dict:
        raw = scanner.scan_all()
        upserted = flagged = 0
        for item in raw:
            existing = await db.scalar(
                select(NHIIdentity).where(NHIIdentity.external_id == item["external_id"])
            )
            if existing:
                for k, v in item.items():
                    if hasattr(existing, k) and k not in ("id", "external_id"):
                        setattr(existing, k, v)
            else:
                db.add(NHIIdentity(**{k: v for k, v in item.items() if hasattr(NHIIdentity, k)}))
            if item.get("risk_level") in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                flagged += 1
            upserted += 1
        await db.commit()
        await self._write_audit(db, event_type="inventory_scan", action=f"{provider}_scan_complete",
                                actor="agentguard:scanner", outcome="success",
                                detail={"upserted": upserted, "flagged": flagged})
        log.info(f"{provider}_scan_complete", upserted=upserted, flagged=flagged)
        return {"provider": provider, "scanned": upserted, "flagged": flagged,
                "timestamp": datetime.now(timezone.utc).isoformat()}

    async def get_all_nhis(self, db: AsyncSession, risk_level: str | None = None) -> list[NHIIdentity]:
        q = select(NHIIdentity).where(NHIIdentity.is_active == True)
        if risk_level:
            q = q.where(NHIIdentity.risk_level == risk_level)
        result = await db.scalars(q)
        return list(result.all())

    async def get_nhi_by_id(self, db: AsyncSession, nhi_id: int) -> NHIIdentity | None:
        return await db.get(NHIIdentity, nhi_id)

    async def _write_audit(self, db: AsyncSession, **kwargs):
        log_entry = AuditLog(**kwargs)
        db.add(log_entry)
        await db.commit()
