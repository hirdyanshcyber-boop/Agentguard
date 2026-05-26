from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from sqlalchemy import String, DateTime, JSON, Integer, Boolean, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from pgvector.sqlalchemy import Vector
from ..core.database import Base


class CredentialType(str, Enum):
    API_KEY = "api_key"
    OAUTH_TOKEN = "oauth_token"
    SERVICE_ACCOUNT = "service_account"
    IAM_ROLE = "iam_role"
    MANAGED_IDENTITY = "managed_identity"
    AGENT_CREDENTIAL = "agent_credential"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    LOCAL = "local"


class NHIIdentity(Base):
    __tablename__ = "nhi_identities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    external_id: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(256))
    credential_type: Mapped[str] = mapped_column(String(64))
    provider: Mapped[str] = mapped_column(String(32))
    owner_team: Mapped[Optional[str]] = mapped_column(String(128))
    owner_agent: Mapped[Optional[str]] = mapped_column(String(256))

    permissions: Mapped[Optional[dict]] = mapped_column(JSON)
    tags: Mapped[Optional[dict]] = mapped_column(JSON)
    metadata_raw: Mapped[Optional[dict]] = mapped_column(JSON)

    last_used: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_rotated: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_over_privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_level: Mapped[str] = mapped_column(String(16), default=RiskLevel.LOW)

    # pgvector embedding for similarity-based anomaly detection
    access_pattern_embedding: Mapped[Optional[list[float]]] = mapped_column(Vector(384), nullable=True)

    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="identity", lazy="select")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    identity_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("nhi_identities.id"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(256))
    action: Mapped[str] = mapped_column(String(256))
    resource: Mapped[Optional[str]] = mapped_column(String(512))
    outcome: Mapped[str] = mapped_column(String(32))
    risk_level: Mapped[str] = mapped_column(String(16), default=RiskLevel.LOW)
    detail: Mapped[Optional[dict]] = mapped_column(JSON)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

    # APRA CPS 234 — every log entry is immutable and traceable
    trace_id: Mapped[Optional[str]] = mapped_column(String(64))
    source_ip: Mapped[Optional[str]] = mapped_column(String(64))

    identity: Mapped[Optional["NHIIdentity"]] = relationship("NHIIdentity", back_populates="audit_logs")


class CredentialAlert(Base):
    __tablename__ = "credential_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    identity_id: Mapped[int] = mapped_column(Integer, ForeignKey("nhi_identities.id"))
    alert_type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    message: Mapped[str] = mapped_column(Text)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
