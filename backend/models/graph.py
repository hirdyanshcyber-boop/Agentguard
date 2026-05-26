from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from sqlalchemy import String, DateTime, Float, Integer, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from ..core.database import Base


class RelationshipType(str, Enum):
    CAN_ASSUME = "can_assume"         # role A can assume role B
    SHARES_RESOURCE = "shares_resource"  # two creds access same resource
    INHERITS_FROM = "inherits_from"   # child inherits parent permissions
    DELEGATES_TO = "delegates_to"     # service account delegates to another
    CREATED_BY = "created_by"         # agent credential created by another identity
    PEER_ACCESS = "peer_access"       # lateral movement path (same trust boundary)


class IdentityRelationship(Base):
    __tablename__ = "identity_relationships"
    __table_args__ = (
        UniqueConstraint("source_id", "target_id", "relationship_type", name="uq_relationship"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(Integer, ForeignKey("nhi_identities.id"), index=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("nhi_identities.id"), index=True)
    relationship_type: Mapped[str] = mapped_column(String(32))
    # weight = attack traversal cost — lower = easier lateral movement
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    provider: Mapped[Optional[str]] = mapped_column(String(32))
    detail: Mapped[Optional[str]] = mapped_column(String(512))
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
