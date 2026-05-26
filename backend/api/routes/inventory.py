from fastapi import APIRouter, Depends, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from datetime import datetime
from ...core.database import get_db
from ...services.inventory_service import InventoryService
from ...models.nhi import RiskLevel

router = APIRouter(prefix="/inventory", tags=["inventory"])
svc = InventoryService()


class NHIResponse(BaseModel):
    id: int
    external_id: str
    name: str
    credential_type: str
    provider: str
    owner_team: str | None
    owner_agent: str | None
    risk_level: str
    is_over_privileged: bool
    is_active: bool
    last_used: datetime | None
    created_at: datetime
    last_rotated: datetime | None

    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    provider: str
    scanned: int
    flagged: int
    timestamp: str


@router.post("/scan/aws", response_model=ScanResponse)
async def trigger_aws_scan(db: AsyncSession = Depends(get_db)):
    return await svc.run_aws_scan(db)


@router.post("/scan/azure", response_model=ScanResponse)
async def trigger_azure_scan(db: AsyncSession = Depends(get_db)):
    return await svc.run_azure_scan(db)


@router.post("/scan/gcp", response_model=ScanResponse)
async def trigger_gcp_scan(db: AsyncSession = Depends(get_db)):
    return await svc.run_gcp_scan(db)


@router.post("/scan/all", response_model=list[ScanResponse])
async def trigger_full_scan(db: AsyncSession = Depends(get_db)):
    """Scan all configured cloud providers sequentially."""
    results = []
    for runner in [svc.run_aws_scan, svc.run_azure_scan, svc.run_gcp_scan]:
        try:
            results.append(await runner(db))
        except Exception as e:
            results.append({"provider": runner.__name__, "scanned": 0, "flagged": 0,
                            "error": str(e), "timestamp": __import__("datetime").datetime.utcnow().isoformat()})
    return results


@router.get("/nhis", response_model=list[NHIResponse])
async def list_nhis(
    risk_level: RiskLevel | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    nhis = await svc.get_all_nhis(db, risk_level=risk_level)
    return nhis


@router.get("/nhis/{nhi_id}", response_model=NHIResponse)
async def get_nhi(nhi_id: int, db: AsyncSession = Depends(get_db)):
    nhi = await svc.get_nhi_by_id(db, nhi_id)
    if not nhi:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="NHI not found")
    return nhi


@router.get("/stats")
async def inventory_stats(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select, func
    from ...models.nhi import NHIIdentity
    total = await db.scalar(select(func.count()).where(NHIIdentity.is_active == True))
    critical = await db.scalar(select(func.count()).where(NHIIdentity.risk_level == RiskLevel.CRITICAL, NHIIdentity.is_active == True))
    high = await db.scalar(select(func.count()).where(NHIIdentity.risk_level == RiskLevel.HIGH, NHIIdentity.is_active == True))
    over_privileged = await db.scalar(select(func.count()).where(NHIIdentity.is_over_privileged == True, NHIIdentity.is_active == True))
    return {
        "total_nhis": total or 0,
        "critical_risk": critical or 0,
        "high_risk": high or 0,
        "over_privileged": over_privileged or 0,
    }
