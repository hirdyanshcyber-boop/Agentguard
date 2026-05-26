import structlog
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from ..models.nhi import NHIIdentity, AuditLog, RiskLevel
from ..scanners.aws_scanner import AWSScanner
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
