from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, DateTime, JSON, Text
from sqlalchemy.orm import relationship
from datetime import datetime

from .database import Base


class ScanRun(Base):
    """Represents one 'discovery scan' -- an ingestion + evaluation pass."""
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, nullable=True)
    environment = Column(String, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    identities_discovered = Column(Integer, default=0)
    orphans_found = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    warning_findings = Column(Integer, default=0)


class Identity(Base):
    """A single Non-Human Identity (API key or service account)."""
    __tablename__ = "identities"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(String, unique=True, index=True, nullable=False)
    credential_type = Column(String, nullable=False)  # "api_key" | "service_account"
    owner_agent = Column(String, nullable=True)        # null => not linked to any registered agent
    registered_purpose = Column(String, nullable=True)
    granted_permissions = Column(JSON, default=list)   # list[str], e.g. ["read:invoices", ...]
    is_orphan = Column(Boolean, default=False)
    environment = Column(String, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)

    activity_events = relationship(
        "ActivityEvent",
        back_populates="identity",
        cascade="all, delete-orphan",
        primaryjoin="Identity.account_id==foreign(ActivityEvent.account_id)",
    )
    findings = relationship(
        "RiskFinding",
        back_populates="identity",
        cascade="all, delete-orphan",
        primaryjoin="Identity.account_id==foreign(RiskFinding.account_id)",
    )


class ActivityEvent(Base):
    """One observed action from a 30-day activity log, e.g. read:invoices."""
    __tablename__ = "activity_events"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(String, ForeignKey("identities.account_id"), index=True, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    action = Column(String, nullable=False)     # "read" | "write" | "approve" | "login" | ...
    resource = Column(String, nullable=False)   # "invoices" | "payments" | ...

    identity = relationship(
        "Identity",
        back_populates="activity_events",
        primaryjoin="foreign(ActivityEvent.account_id)==Identity.account_id",
    )

    @property
    def permission_key(self) -> str:
        # same "action:resource" format as granted_permissions, for diffing
        return f"{self.action}:{self.resource}"


class RiskFinding(Base):
    """A single actionable governance finding produced by the risk engine."""
    __tablename__ = "risk_findings"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(String, ForeignKey("identities.account_id"), index=True, nullable=False)
    check_type = Column(String, nullable=False)   # orphan | least_privilege | sod | purpose_boundary
    severity = Column(String, nullable=False)     # critical | warning | info
    title = Column(String, nullable=False)
    message = Column(Text, nullable=False)        # plain-language audit reasoning
    related_permission = Column(String, nullable=True)
    recommended_action = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    identity = relationship(
        "Identity",
        back_populates="findings",
        primaryjoin="foreign(RiskFinding.account_id)==Identity.account_id",
    )
