
#Risk evaluation engine.

# The 4 checks: orphan identity, least privilege, segregation of duties,
# purpose boundary. Each one returns a list of RiskFinding rows with a
# severity + plain-language reason.

from datetime import datetime, timedelta
from typing import List
from sqlalchemy.orm import Session

from . import models
from .config import (
    SOD_CONFLICT_PAIRS,
    PURPOSE_RESOURCE_ALLOWLIST,
    SENSITIVE_RESOURCES,
    BROAD_PERMISSION_MARKERS,
    DEFAULT_ACTIVITY_WINDOW_DAYS,
)

SEVERITY_CRITICAL = "critical"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"


def _used_permissions(events: List[models.ActivityEvent]) -> dict:
    # builds action:resource -> last seen timestamp, from the raw events

    used = {}
    for e in events:
        key = f"{e.action}:{e.resource}"
        if key not in used or e.timestamp > used[key]:
            used[key] = e.timestamp
    return used


def check_orphan(identity: models.Identity) -> List[models.RiskFinding]:
    findings = []
    if identity.is_orphan:
        broad = [p for p in (identity.granted_permissions or []) if p in BROAD_PERMISSION_MARKERS]
        severity = SEVERITY_CRITICAL if broad else SEVERITY_WARNING
        broad_note = (
            f" It also holds broad/unscoped access ({', '.join(broad)}), which "
            f"significantly raises the blast radius of this unmanaged credential."
            if broad else ""
        )
        findings.append(
            models.RiskFinding(
                account_id=identity.account_id,
                check_type="orphan",
                severity=severity,
                title="Orphan Identity Detected",
                message=(
                    f"'{identity.account_id}' is an active {identity.credential_type.replace('_', ' ')} "
                    f"discovered in the environment, but it is not linked to any registered AI agent or "
                    f"human owner (owner_agent/registered_purpose are both missing)."
                    f"{broad_note} Orphaned credentials are a common way former employees' or abandoned "
                    f"test scripts' access survives undetected."
                ),
                recommended_action="Assign an owner or revoke this credential immediately.",
            )
        )
    return findings


def check_least_privilege(
    identity: models.Identity, events: List[models.ActivityEvent]
) -> List[models.RiskFinding]:
    findings = []
    used = _used_permissions(events)
    granted = identity.granted_permissions or []

    for perm in granted:
        if perm in BROAD_PERMISSION_MARKERS:
            # Broad wildcard-style grants can't be "used" in a single event;
            # flag them directly as over-provisioned by design.
            findings.append(
                models.RiskFinding(
                    account_id=identity.account_id,
                    check_type="least_privilege",
                    severity=SEVERITY_CRITICAL,
                    title="Unscoped Wildcard Permission",
                    message=(
                        f"'{identity.account_id}' holds the wildcard-style permission '{perm}', which "
                        f"grants access far beyond anything observable in normal least-privilege review. "
                        f"Wildcard grants should be replaced with the specific resource permissions the "
                        f"identity actually needs."
                    ),
                    related_permission=perm,
                    recommended_action="Replace with scoped, resource-specific permissions.",
                )
            )
            continue

        if perm not in used:
            resource = perm.split(":", 1)[1] if ":" in perm else perm
            sensitive = resource in SENSITIVE_RESOURCES
            severity = SEVERITY_CRITICAL if sensitive else SEVERITY_WARNING
            sensitivity_note = (
                " This permission also covers a sensitive resource category, making the unused "
                "grant a higher-priority risk." if sensitive else ""
            )
            findings.append(
                models.RiskFinding(
                    account_id=identity.account_id,
                    check_type="least_privilege",
                    severity=severity,
                    title="Unused Permission (Over-Provisioned)",
                    message=(
                        f"'{identity.account_id}' was granted '{perm}' but recorded zero usage of it "
                        f"over the last {DEFAULT_ACTIVITY_WINDOW_DAYS} days of activity logs."
                        f"{sensitivity_note} Under the principle of least privilege, access that is "
                        f"never exercised should be revoked."
                    ),
                    related_permission=perm,
                    recommended_action=f"Revoke '{perm}' — unused in last {DEFAULT_ACTIVITY_WINDOW_DAYS} days.",
                )
            )
    return findings


def check_sod(identity: models.Identity) -> List[models.RiskFinding]:
    findings = []
    granted = set(identity.granted_permissions or [])
    for perm_a, perm_b in SOD_CONFLICT_PAIRS:
        if perm_a in granted and perm_b in granted:
            findings.append(
                models.RiskFinding(
                    account_id=identity.account_id,
                    check_type="sod",
                    severity=SEVERITY_CRITICAL,
                    title="Segregation of Duties Violation",
                    message=(
                        f"'{identity.account_id}' simultaneously holds '{perm_a}' and '{perm_b}'. "
                        f"A single identity that can both perform and approve the same class of "
                        f"transaction can create or approve fraudulent activity with no independent "
                        f"check, violating standard financial/operational segregation-of-duties controls."
                    ),
                    related_permission=f"{perm_a} + {perm_b}",
                    recommended_action=f"Split '{perm_a}' and '{perm_b}' across two separate identities.",
                )
            )
    return findings


def check_purpose_boundary(
    identity: models.Identity, events: List[models.ActivityEvent]
) -> List[models.RiskFinding]:
    findings = []
    if not identity.registered_purpose:
        return findings  # orphan check already covers unregistered identities

    allowlist = PURPOSE_RESOURCE_ALLOWLIST.get(identity.registered_purpose)
    if not allowlist:
        return findings  # unknown purpose category -- nothing to compare against

    out_of_purpose_resources = set()
    for e in events:
        if e.resource not in allowlist:
            out_of_purpose_resources.add(e.resource)

    for resource in sorted(out_of_purpose_resources):
        sensitive = resource in SENSITIVE_RESOURCES
        severity = SEVERITY_CRITICAL if sensitive else SEVERITY_WARNING
        findings.append(
            models.RiskFinding(
                account_id=identity.account_id,
                check_type="purpose_boundary",
                severity=severity,
                title="Out-of-Purpose Data Access",
                message=(
                    f"'{identity.account_id}' is registered for '{identity.registered_purpose}' "
                    f"(expected to touch: {', '.join(sorted(allowlist))}), but its activity logs show it "
                    f"accessing '{resource}', which falls outside its declared purpose. This can indicate "
                    f"scope creep, a compromised credential, or an agent exceeding its intended boundaries."
                ),
                related_permission=resource,
                recommended_action=f"Investigate access to '{resource}' and narrow the agent's scope if unintended.",
            )
        )
    return findings


def evaluate_identity(
    identity: models.Identity, events: List[models.ActivityEvent]
) -> List[models.RiskFinding]:
    """Runs all four checks for a single identity and returns the combined
    list of findings (not yet persisted)."""
    findings: List[models.RiskFinding] = []
    findings += check_orphan(identity)
    findings += check_least_privilege(identity, events)
    findings += check_sod(identity)
    findings += check_purpose_boundary(identity, events)
    return findings


def run_full_evaluation(db: Session) -> models.ScanRun:
    """Evaluates every identity currently in the database, replacing any
    previously-stored findings with fresh results, and records a ScanRun
    summary row."""
    identities = db.query(models.Identity).all()

    # Clear stale findings so re-running a scan doesn't duplicate alerts.
    db.query(models.RiskFinding).delete()

    critical_count = 0
    warning_count = 0
    orphan_count = 0

    for identity in identities:
        events = (
            db.query(models.ActivityEvent)
            .filter(models.ActivityEvent.account_id == identity.account_id)
            .all()
        )
        findings = evaluate_identity(identity, events)
        for f in findings:
            db.add(f)
            if f.severity == SEVERITY_CRITICAL:
                critical_count += 1
            elif f.severity == SEVERITY_WARNING:
                warning_count += 1
        if identity.is_orphan:
            orphan_count += 1

    scan = models.ScanRun(
        identities_discovered=len(identities),
        orphans_found=orphan_count,
        critical_findings=critical_count,
        warning_findings=warning_count,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def overall_status_for(findings: List[models.RiskFinding]) -> str:
    if any(f.severity == SEVERITY_CRITICAL for f in findings):
        return "critical"
    if any(f.severity == SEVERITY_WARNING for f in findings):
        return "non_compliant"
    return "compliant"
