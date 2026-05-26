import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from ..services.rotation_service import RotationService
from ..models.nhi import RiskLevel


def make_nhi(age_days: int, last_rotated_days: int | None = None) -> MagicMock:
    now = datetime.now(timezone.utc)
    nhi = MagicMock()
    nhi.id = 1
    nhi.name = "test-key"
    nhi.external_id = "aws:iam:key:AKIATEST"
    nhi.credential_type = "api_key"
    nhi.provider = "aws"
    nhi.created_at = now - timedelta(days=age_days)
    nhi.last_rotated = (now - timedelta(days=last_rotated_days)) if last_rotated_days is not None else None
    nhi.is_active = True
    nhi.risk_level = RiskLevel.LOW
    nhi.is_over_privileged = False
    return nhi


def mock_scalars(db: AsyncMock, items: list) -> None:
    """Return a sync MagicMock from db.scalars so .all() is not a coroutine."""
    result = MagicMock()
    result.all.return_value = items
    db.scalars.return_value = result


@pytest.mark.asyncio
async def test_rotation_check_flags_overdue():
    svc = RotationService()
    db = AsyncMock()
    db.add = MagicMock()

    nhi = make_nhi(age_days=95)
    mock_scalars(db, [nhi])
    db.scalar.return_value = None  # no existing alert

    with patch("backend.services.rotation_service.settings") as mock_settings:
        mock_settings.credential_rotation_days = 90
        mock_settings.alert_webhook_url = ""
        result = await svc.check_all(db)

    assert result["never_rotated"] == 1
    assert result["overdue"] == 0


@pytest.mark.asyncio
async def test_rotation_check_compliant():
    svc = RotationService()
    db = AsyncMock()
    db.add = MagicMock()

    nhi = make_nhi(age_days=30, last_rotated_days=5)
    mock_scalars(db, [nhi])

    with patch("backend.services.rotation_service.settings") as mock_settings:
        mock_settings.credential_rotation_days = 90
        mock_settings.alert_webhook_url = ""
        result = await svc.check_all(db)

    assert result["overdue"] == 0
    assert result["never_rotated"] == 0


@pytest.mark.asyncio
async def test_mark_rotated_clears_risk():
    svc = RotationService()
    db = AsyncMock()
    db.add = MagicMock()

    nhi = make_nhi(age_days=100)
    nhi.risk_level = RiskLevel.HIGH
    db.get.return_value = nhi

    result = await svc.mark_rotated(db, nhi_id=1, rotated_by="ops-team")

    assert result is not None
    assert result.last_rotated is not None
    assert result.risk_level == RiskLevel.LOW
