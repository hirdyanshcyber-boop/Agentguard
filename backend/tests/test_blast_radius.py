import pytest
from unittest.mock import AsyncMock, MagicMock
from ..services.blast_radius_service import BlastRadiusService
from ..models.nhi import RiskLevel


def make_nhi(nhi_id: int, name: str, risk_level: str = RiskLevel.LOW) -> MagicMock:
    nhi = MagicMock()
    nhi.id = nhi_id
    nhi.name = name
    nhi.provider = "aws"
    nhi.credential_type = "iam_role"
    nhi.risk_level = risk_level
    nhi.is_active = True
    nhi.access_pattern_embedding = None
    return nhi


def make_edge(source: int, target: int) -> MagicMock:
    edge = MagicMock()
    edge.source_id = source
    edge.target_id = target
    edge.relationship_type = "can_assume"
    return edge


@pytest.mark.asyncio
async def test_blast_radius_single_hop():
    svc = BlastRadiusService()
    db = AsyncMock()
    db.add = MagicMock()

    origin = make_nhi(1, "compromised-role")
    target = make_nhi(2, "prod-db-role", risk_level=RiskLevel.CRITICAL)
    edge = make_edge(1, 2)

    # 3 db.get calls: origin → target (reachable) → origin again in _find_similar_exposure
    db.get.side_effect = [origin, target, origin]
    db.scalars.return_value.all.side_effect = [
        [edge],  # edges from node 1
        [],      # edges from node 2
    ]

    result = await svc.calculate(db, nhi_id=1, max_depth=6)

    assert result["blast_radius"]["total_reachable"] == 1
    assert result["blast_radius"]["critical_reachable"] == 1
    assert result["blast_radius"]["overall_severity"] == "critical"


@pytest.mark.asyncio
async def test_blast_radius_no_edges():
    svc = BlastRadiusService()
    db = AsyncMock()
    db.add = MagicMock()

    origin = make_nhi(1, "isolated-key")
    db.get.return_value = origin
    db.scalars.return_value.all.return_value = []

    result = await svc.calculate(db, nhi_id=1)

    assert result["blast_radius"]["total_reachable"] == 0
    assert result["blast_radius"]["overall_severity"] == "low"


@pytest.mark.asyncio
async def test_blast_radius_nhi_not_found():
    svc = BlastRadiusService()
    db = AsyncMock()
    db.get.return_value = None

    result = await svc.calculate(db, nhi_id=999)
    assert "error" in result


def test_severity_thresholds():
    svc = BlastRadiusService()
    assert svc._severity(1, 0, 5) == "critical"
    assert svc._severity(0, 3, 10) == "high"
    assert svc._severity(0, 1, 3) == "medium"
    assert svc._severity(0, 0, 2) == "low"
