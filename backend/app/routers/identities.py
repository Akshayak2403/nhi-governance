"""
Screen 1 backend: Identity Register View.

Exposes every discovered identity with its computed compliance status,
derived from whatever RiskFinding rows the last scan produced for it.
"""
from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models, schemas, risk_engine
from ..database import get_db

router = APIRouter(prefix="/api", tags=["identities"])


@router.get("/identities", response_model=List[schemas.IdentityOut])
def list_identities(db: Session = Depends(get_db)):
    identities = db.query(models.Identity).order_by(models.Identity.account_id).all()
    out = []
    for identity in identities:
        findings = (
            db.query(models.RiskFinding)
            .filter(models.RiskFinding.account_id == identity.account_id)
            .all()
        )
        critical_count = sum(1 for f in findings if f.severity == "critical")
        warning_count = sum(1 for f in findings if f.severity == "warning")
        out.append(
            schemas.IdentityOut(
                account_id=identity.account_id,
                credential_type=identity.credential_type,
                owner_agent=identity.owner_agent,
                registered_purpose=identity.registered_purpose,
                granted_permissions=identity.granted_permissions or [],
                is_orphan=identity.is_orphan,
                overall_status=risk_engine.overall_status_for(findings),
                critical_count=critical_count,
                warning_count=warning_count,
            )
        )
    return out


@router.get("/dashboard/summary", response_model=schemas.DashboardSummaryOut)
def dashboard_summary(db: Session = Depends(get_db)):
    identities = db.query(models.Identity).all()
    findings = db.query(models.RiskFinding).all()
    last_scan = (
        db.query(models.ScanRun).order_by(models.ScanRun.started_at.desc()).first()
    )
    return schemas.DashboardSummaryOut(
        total_identities=len(identities),
        orphan_identities=sum(1 for i in identities if i.is_orphan),
        critical_findings=sum(1 for f in findings if f.severity == "critical"),
        warning_findings=sum(1 for f in findings if f.severity == "warning"),
        sod_violations=sum(1 for f in findings if f.check_type == "sod"),
        over_provisioned=sum(1 for f in findings if f.check_type == "least_privilege"),
        last_scan_at=last_scan.started_at if last_scan else None,
    )
