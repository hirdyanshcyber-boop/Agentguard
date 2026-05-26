import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from ..services.rotation_service import RotationService
from ..models.nhi import NHIIdentity, RiskLevel, CredentialType, CloudProvider


def make_nhi(age_days: int, last_rotated_days: int | None = None) -> NHIIdentity:
    now = datetime.now(timezone.utc)
    nhi = NHIIdentity()
    nhi.id = 1
    nhi.name = "test-key"
    nhi.external_id = "aws:iam:key:AKIATEST"
    nhi.credential_type = CredentialType.API_KEY
    nhi.provider = CloudProvider.AWS
    nhi.created_at = now - timedelta(days=age_days)
    nhi.last_rotated = (now - timedelta(days=last_rotated_days)) if last_rotated_days is not None else None
    nhi.is_active = True
    nhi.risk_level = RiskLevel.LOW
    nhi.is_over_privileged = False
    return nhi


@pytest.mark.asyncio
async def test_rotation_check_flags_overdue():
    svc = RotationService()
    db = AsyncMock()
    # NHI 95 days old, never rotated — overdue (policy=90)
    nhi = make_nhi(age_days=95)
    db.scalars.return_value.all.return_value = [nhi]
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
    # NHI 30 days old — compliant
    nhi = make_nhi(age_days=30, last_rotated_days=5)
    db.scalars.return_value.all.return_value = [nhi]

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
    nhi = make_nhi(age_days=100)
    nhi.risk_level = RiskLevel.HIGH
    db.get.return_value = nhi

    result = await svc.mark_rotated(db, nhi_id=1, rotated_by="ops-team")

    assert result is not None
    assert result.last_rotated is not None
    assert result.risk_level == RiskLevel.LOW
