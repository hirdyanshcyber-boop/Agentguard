import json
import structlog
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..models.nhi import AuditLog, NHIIdentity

log = structlog.get_logger()


class AuditService:
    """APRA CPS 234 compliant audit log service."""

    async def get_logs(
        self,
        db: AsyncSession,
        identity_id: int | None = None,
        event_type: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditLog]:
        q = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
        if identity_id:
            q = q.where(AuditLog.identity_id == identity_id)
        if event_type:
            q = q.where(AuditLog.event_type == event_type)
        if since:
            q = q.where(AuditLog.timestamp >= since)
        result = await db.scalars(q)
        return list(result.all())

    async def write_log(self, db: AsyncSession, **kwargs) -> AuditLog:
        entry = AuditLog(timestamp=datetime.now(timezone.utc), **kwargs)
        db.add(entry)
        await db.commit()
        await db.refresh(entry)
        log.info("audit_log_written", event_type=entry.event_type, actor=entry.actor)
        return entry

    def export_cps234_json(self, logs: list[AuditLog]) -> str:
        """APRA CPS 234 Attachment G — structured JSON export."""
        records = []
        for entry in logs:
            records.append({
                "timestamp": entry.timestamp.isoformat(),
                "event_type": entry.event_type,
                "actor": entry.actor,
                "action": entry.action,
                "resource": entry.resource,
                "outcome": entry.outcome,
                "risk_level": entry.risk_level,
                "trace_id": entry.trace_id,
                "source_ip": entry.source_ip,
                "detail": entry.detail,
            })
        return json.dumps({
            "report": "APRA CPS 234 Audit Log",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "record_count": len(records),
            "records": records,
        }, indent=2, default=str)
