# Screen 2 - single identity detail: permission comparison, timeline, findings.


from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas, risk_engine
from ..config import SOD_CONFLICT_PAIRS, SENSITIVE_RESOURCES, DEFAULT_ACTIVITY_WINDOW_DAYS
from ..database import get_db

router = APIRouter(prefix="/api", tags=["agents"])


def _resource_of(permission: str) -> str:
    return permission.split(":", 1)[1] if ":" in permission else permission


@router.get("/agents/{account_id}/risk", response_model=schemas.AgentRiskDashboardOut)
def agent_risk_dashboard(account_id: str, db: Session = Depends(get_db)):
    identity = db.query(models.Identity).filter(models.Identity.account_id == account_id).first()
    if not identity:
        raise HTTPException(status_code=404, detail=f"No identity registered for '{account_id}'.")

    events = (
        db.query(models.ActivityEvent)
        .filter(models.ActivityEvent.account_id == account_id)
        .order_by(models.ActivityEvent.timestamp)
        .all()
    )

    # Evaluate fresh so the dashboard is always accurate even before a scan
    # has been explicitly (re-)run after new data was uploaded.
    findings = risk_engine.evaluate_identity(identity, events)

    used = risk_engine._used_permissions(events)
    granted = identity.granted_permissions or []

    # --- Permissions Granted vs. Used comparison ---
    comparison: List[schemas.PermissionComparisonEntry] = []
    for perm in granted:
        last_used = used.get(perm)
        sensitive = _resource_of(perm) in SENSITIVE_RESOURCES
        recommendation = None
        if last_used is None:
            recommendation = f"Revoke — unused in last {DEFAULT_ACTIVITY_WINDOW_DAYS} days"
        comparison.append(
            schemas.PermissionComparisonEntry(
                permission=perm,
                granted=True,
                used_in_window=last_used is not None,
                last_used=last_used,
                sensitive=sensitive,
                recommendation=recommendation,
            )
        )
    # Shadow access: exercised in logs but never formally granted. Not
    # explicitly required by the spec, but a real least-privilege review
    # always checks for this too (e.g. inherited/legacy role access).
    for perm, last_used in used.items():
        if perm not in granted:
            comparison.append(
                schemas.PermissionComparisonEntry(
                    permission=perm,
                    granted=False,
                    used_in_window=True,
                    last_used=last_used,
                    sensitive=_resource_of(perm) in SENSITIVE_RESOURCES,
                    recommendation="Investigate — used without a matching directory grant",
                )
            )

    # --- Timeline with per-event flags ---
    sod_resources = set()
    for a, b in SOD_CONFLICT_PAIRS:
        if a in granted and b in granted:
            sod_resources.add(a)
            sod_resources.add(b)

    purpose_flagged_resources = {
        f.related_permission for f in findings if f.check_type == "purpose_boundary"
    }

    timeline: List[schemas.ActivityTimelineEntry] = []
    for e in events:
        key = f"{e.action}:{e.resource}"
        flagged, reason = False, None
        if key in sod_resources:
            flagged, reason = True, "Part of a Segregation of Duties violation on this identity"
        elif e.resource in purpose_flagged_resources:
            flagged, reason = True, "Out-of-purpose data access"
        timeline.append(
            schemas.ActivityTimelineEntry(
                timestamp=e.timestamp,
                action=e.action,
                resource=e.resource,
                flagged=flagged,
                flag_reason=reason,
            )
        )

    return schemas.AgentRiskDashboardOut(
        account_id=identity.account_id,
        owner_agent=identity.owner_agent,
        registered_purpose=identity.registered_purpose,
        is_orphan=identity.is_orphan,
        overall_status=risk_engine.overall_status_for(findings),
        permission_comparison=comparison,
        timeline=timeline,
        findings=[schemas.RiskFindingOut.model_validate(f) for f in findings],
    )
