
#Policy rules for the risk engine. Kept as data here so adding a new
# rule doesn't mean touching risk_engine.py. Would move to a DB table
# if this went further.


# --- Segregation of Duties (SoD) ---
# Each tuple is a pair of permissions that must NEVER be held by the same
# identity at the same time. Order does not matter.
SOD_CONFLICT_PAIRS = [
    ("write:payments", "approve:payments"),
    ("create:vendor", "approve:vendor"),
    ("write:payroll", "approve:payroll"),
    ("create:user", "approve:access_request"),
]

# --- Purpose Boundary Mapping ---
# Maps a registered_purpose (as declared in the directory scan) to the set
# of resource keywords that purpose is legitimately allowed to touch.
# Any activity event whose resource is NOT in this allow-list (and isn't
# a generic/system resource) is treated as "out-of-purpose" access.
PURPOSE_RESOURCE_ALLOWLIST = {
    "Invoice Processing": {"invoices", "payments", "vendors"},
    "Customer Support Bot": {"tickets", "customers", "knowledge_base"},
    "HR Analytics": {"hr_salaries", "employees", "hr_reports"},
    "DevOps Automation": {"deployments", "infrastructure", "logs"},
    "Marketing Analytics": {"campaigns", "customers", "analytics"},
}

# Resources that are considered high-sensitivity. If an identity holds a
# permission touching one of these but never uses it, that is flagged more
# severely than an ordinary unused permission.
SENSITIVE_RESOURCES = {"hr_salaries", "payroll", "ssn", "credit_cards", "payments"}

# Permission strings that grant unusually broad access and should always be
# treated with suspicion, especially on orphaned/unowned identities.
BROAD_PERMISSION_MARKERS = {"read:all_data", "write:all_data", "*:*", "admin:*"}

# Activity window used for the least-privilege comparison. This mirrors the
# "activity_period_days" field expected in the activity log payload.
DEFAULT_ACTIVITY_WINDOW_DAYS = 30
