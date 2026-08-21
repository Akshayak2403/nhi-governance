# Upload endpoints - accepts the directory + activity log JSON as file
# uploads, hands off to ingestion.py.


import json
from typing import Optional, Union, List
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Body
from sqlalchemy.orm import Session

from .. import schemas, ingestion, risk_engine
from ..database import get_db

router = APIRouter(prefix="/api", tags=["ingestion"])


async def _read_json(file: Optional[UploadFile]):
    if file is None:
        return None
    raw = await file.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON in {file.filename}: {exc}")


def _normalize_activity_payload(data: Union[dict, list]) -> schemas.ActivityLogBatchPayload:
    """Accepts any of the realistic shapes activity log exports show up in:
    a single account object, a bare list of account objects, or an object
    that already wraps them under a "logs" key.
    """
    if isinstance(data, dict) and "logs" in data:
        logs = data["logs"]
    elif isinstance(data, list):
        logs = data
    elif isinstance(data, dict) and "account_id" in data:
        logs = [data]
    else:
        raise HTTPException(status_code=400, detail="Unrecognized activity log JSON shape.")
    return schemas.ActivityLogBatchPayload(logs=logs)


@router.post("/ingest/directory", response_model=dict)
async def ingest_directory(
    db: Session = Depends(get_db),
    file: Optional[UploadFile] = File(None),
    body: Optional[dict] = Body(None),
):
    """Simulates a cloud directory discovery scan. Accepts a file upload
    (preferred, matches the UI) or a raw JSON body (useful for scripting)."""
    data = await _read_json(file) if file else body
    if data is None:
        raise HTTPException(status_code=400, detail="No directory JSON provided.")
    payload = schemas.DirectoryDiscoveryPayload(**data)
    identities = ingestion.ingest_directory(db, payload)
    return {
        "message": f"Ingested {len(identities)} discovered accounts.",
        "scan_id": payload.scan_id,
        "count": len(identities),
    }


@router.post("/ingest/activity", response_model=dict)
async def ingest_activity(
    db: Session = Depends(get_db),
    file: Optional[UploadFile] = File(None),
    body: Optional[Union[dict, list]] = Body(None),
):
    """Simulates pulling 30-day activity logs. Accepts one account's log,
    a list of them, or {"logs": [...]}."""
    data = await _read_json(file) if file else body
    if data is None:
        raise HTTPException(status_code=400, detail="No activity log JSON provided.")
    payload = _normalize_activity_payload(data)
    count = ingestion.ingest_activity_logs(db, payload)
    return {"message": f"Ingested {count} activity events.", "count": count}


@router.post("/scan/run", response_model=dict)
def run_scan(db: Session = Depends(get_db)):
    """Runs the full evaluation pipeline (orphan / least-privilege / SoD /
    purpose-boundary) across every currently-ingested identity."""
    scan = risk_engine.run_full_evaluation(db)
    return {
        "scan_id": scan.scan_id,
        "identities_discovered": scan.identities_discovered,
        "orphans_found": scan.orphans_found,
        "critical_findings": scan.critical_findings,
        "warning_findings": scan.warning_findings,
        "started_at": scan.started_at,
    }


@router.delete("/reset", response_model=dict)
def reset_all(db: Session = Depends(get_db)):
    """Clears all ingested data -- useful for demoing the upload flow
    repeatedly without restarting the server."""
    from .. import models
    db.query(models.RiskFinding).delete()
    db.query(models.ActivityEvent).delete()
    db.query(models.Identity).delete()
    db.query(models.ScanRun).delete()
    db.commit()
    return {"message": "All data cleared."}
