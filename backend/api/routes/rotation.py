from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from datetime import datetime
from ...core.database import get_db
from ...services.rotation_service import RotationService

router = APIRouter(prefix="/rotation", tags=["rotation"])
svc = RotationService()


class RotationCheckResponse(BaseModel):
    scanned: int
    never_rotated: int
    overdue: int
    expiring_soon: int
    policy_days: int
    timestamp: str


class MarkRotatedRequest(BaseModel):
    rotated_by: str


class NHIRotationStatus(BaseModel):
    id: int
    name: str
    provider: str
    credential_type: str
    owner_team: str | None
    age_days: int | None
    rotation_status: str
    risk_level: str
    last_rotated: str | None


@router.post("/check", response_model=RotationCheckResponse)
async def run_rotation_check(db: AsyncSession = Depends(get_db)):
    """Check all NHIs against rotation policy. Creates alerts for violations."""
    return await svc.check_all(db)


@router.get("/report")
async def get_rotation_report(db: AsyncSession = Depends(get_db)):
    """APRA CPS 234 compatible rotation status report for all credentials."""
    return await svc.generate_rotation_report(db)


@router.post("/nhis/{nhi_id}/rotate")
async def mark_rotated(
    nhi_id: int,
    body: MarkRotatedRequest,
    db: AsyncSession = Depends(get_db),
):
    """Record that a credential has been rotated. Clears rotation alerts."""
    nhi = await svc.mark_rotated(db, nhi_id, rotated_by=body.rotated_by)
    if not nhi:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="NHI not found")
    return {"status": "rotated", "nhi_id": nhi_id, "rotated_at": nhi.last_rotated.isoformat()}
