from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from datetime import datetime
from ...core.database import get_db
from ...services.audit_service import AuditService

router = APIRouter(prefix="/audit", tags=["audit"])
svc = AuditService()


class AuditLogResponse(BaseModel):
    id: int
    identity_id: int | None
    event_type: str
    actor: str
    action: str
    resource: str | None
    outcome: str
    risk_level: str
    timestamp: datetime
    trace_id: str | None

    model_config = {"from_attributes": True}


@router.get("/logs", response_model=list[AuditLogResponse])
async def get_audit_logs(
    identity_id: int | None = Query(None),
    event_type: str | None = Query(None),
    since: datetime | None = Query(None),
    limit: int = Query(100, le=1000),
    db: AsyncSession = Depends(get_db),
):
    logs = await svc.get_logs(db, identity_id=identity_id, event_type=event_type, since=since, limit=limit)
    return logs


@router.get("/export/cps234", response_class=PlainTextResponse)
async def export_cps234(
    since: datetime | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Export APRA CPS 234 compliant audit log as JSON."""
    logs = await svc.get_logs(db, since=since, limit=10000)
    return PlainTextResponse(content=svc.export_cps234_json(logs), media_type="application/json")
