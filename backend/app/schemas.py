from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict


# ---------- Ingestion payload shapes (mirror the mock JSON files) ----------

class DiscoveredAccount(BaseModel):
    account_id: str
    type: str  # "api_key" | "service_account"
    owner_agent: Optional[str] = None
    registered_purpose: Optional[str] = None
    granted_permissions: List[str] = []
    environment: Optional[str] = None


class DirectoryDiscoveryPayload(BaseModel):
    scan_id: Optional[str] = None
    environment: Optional[str] = None
    discovered_accounts: List[DiscoveredAccount]


class ActivityEventIn(BaseModel):
    timestamp: datetime
    action: str
    resource: str


class ActivityLogPayload(BaseModel):
    account_id: str
    activity_period_days: Optional[int] = 30
    events: List[ActivityEventIn] = []


class ActivityLogBatchPayload(BaseModel):
    """Allows uploading either one account's log or a list of them in a
    single file, matching how real SIEM exports usually look."""
    logs: List[ActivityLogPayload]


# ---------- Response shapes ----------

class RiskFindingOut(BaseModel):
    check_type: str
    severity: str
    title: str
    message: str
    related_permission: Optional[str] = None
    recommended_action: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class IdentityOut(BaseModel):
    account_id: str
    credential_type: str
    owner_agent: Optional[str] = None
    registered_purpose: Optional[str] = None
    granted_permissions: List[str] = []
    is_orphan: bool
    overall_status: str  # "compliant" | "non_compliant" | "critical"
    critical_count: int
    warning_count: int

    model_config = ConfigDict(from_attributes=True)


class PermissionComparisonEntry(BaseModel):
    permission: str
    granted: bool
    used_in_window: bool
    last_used: Optional[datetime] = None
    sensitive: bool = False
    recommendation: Optional[str] = None  # e.g. "Revoke - unused in 30 days"


class ActivityTimelineEntry(BaseModel):
    timestamp: datetime
    action: str
    resource: str
    flagged: bool = False
    flag_reason: Optional[str] = None


class AgentRiskDashboardOut(BaseModel):
    account_id: str
    owner_agent: Optional[str] = None
    registered_purpose: Optional[str] = None
    is_orphan: bool
    overall_status: str
    permission_comparison: List[PermissionComparisonEntry]
    timeline: List[ActivityTimelineEntry]
    findings: List[RiskFindingOut]


class DashboardSummaryOut(BaseModel):
    total_identities: int
    orphan_identities: int
    critical_findings: int
    warning_findings: int
    sod_violations: int
    over_provisioned: int
    last_scan_at: Optional[datetime] = None
