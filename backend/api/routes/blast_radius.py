from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from ...core.database import get_db
from ...services.blast_radius_service import BlastRadiusService

router = APIRouter(prefix="/blast-radius", tags=["blast-radius"])
svc = BlastRadiusService()


@router.get("/{nhi_id}")
async def get_blast_radius(
    nhi_id: int,
    max_depth: int = Query(6, ge=1, le=10),
    db: AsyncSession = Depends(get_db),
):
    """
    Calculate blast radius for a compromised NHI.
    Returns full lateral movement graph and APRA CPS 234 impact summary.
    """
    return await svc.calculate(db, nhi_id, max_depth=max_depth)


@router.post("/graph/rebuild")
async def rebuild_identity_graph(db: AsyncSession = Depends(get_db)):
    """Rebuild identity relationship graph from current NHI scan data."""
    return await svc.build_graph_from_scan(db)
