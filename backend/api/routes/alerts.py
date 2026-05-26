from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from datetime import datetime
from ...core.database import get_db
from ...models.nhi import CredentialAlert

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertResponse(BaseModel):
    id: int
    identity_id: int
    alert_type: str
    severity: str
    message: str
    resolved: bool
    created_at: datetime

    model_config = {"from_attributes": True}


@router.get("/", response_model=list[AlertResponse])
async def list_alerts(
    resolved: bool = Query(False),
    severity: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(CredentialAlert).where(CredentialAlert.resolved == resolved).order_by(CredentialAlert.created_at.desc())
    if severity:
        q = q.where(CredentialAlert.severity == severity)
    result = await db.scalars(q)
    return list(result.all())


@router.patch("/{alert_id}/resolve")
async def resolve_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    alert = await db.get(CredentialAlert, alert_id)
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.resolved = True
    alert.resolved_at = datetime.utcnow()
    await db.commit()
    return {"status": "resolved", "alert_id": alert_id}
