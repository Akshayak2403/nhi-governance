
#Ingestion layer

# Maps the raw directory/activity JSON onto the Identity and ActivityEvent
# tables. Kept separate from risk_engine.py - this just loads the data,
# risk_engine decides if it's risky.


from typing import List
from sqlalchemy.orm import Session

from . import models, schemas


def ingest_directory(db: Session, payload: schemas.DirectoryDiscoveryPayload) -> List[models.Identity]:
    """Upserts every discovered account as an Identity row.

    An identity is treated as an "orphan" when it has no owner_agent AND
    no registered_purpose -- i.e. nothing in the directory scan links it
    to a known AI agent or human owner.
    """
    saved: List[models.Identity] = []
    for acc in payload.discovered_accounts:
        existing = db.query(models.Identity).filter(
            models.Identity.account_id == acc.account_id
        ).first()

        is_orphan = not acc.owner_agent and not acc.registered_purpose

        if existing:
            existing.credential_type = acc.type
            existing.owner_agent = acc.owner_agent
            existing.registered_purpose = acc.registered_purpose
            existing.granted_permissions = acc.granted_permissions
            existing.is_orphan = is_orphan
            existing.environment = acc.environment or payload.environment
            identity = existing
        else:
            identity = models.Identity(
                account_id=acc.account_id,
                credential_type=acc.type,
                owner_agent=acc.owner_agent,
                registered_purpose=acc.registered_purpose,
                granted_permissions=acc.granted_permissions,
                is_orphan=is_orphan,
                environment=acc.environment or payload.environment,
            )
            db.add(identity)
        saved.append(identity)

    db.commit()
    for identity in saved:
        db.refresh(identity)
    return saved


def ingest_activity_logs(db: Session, payload: schemas.ActivityLogBatchPayload) -> int:
    """Replaces stored activity events for each account_id present in the
    payload with the freshly-uploaded set, so re-uploading a log file
    doesn't create duplicate events. Returns the number of events stored.

    Events for account_ids that are not (yet) registered identities are
    still stored -- an activity log for an unmapped credential is itself
    useful signal (e.g. confirms an orphan key is actually being used).
    """
    total = 0
    for log in payload.logs:
        db.query(models.ActivityEvent).filter(
            models.ActivityEvent.account_id == log.account_id
        ).delete()
        for event in log.events:
            db.add(
                models.ActivityEvent(
                    account_id=log.account_id,
                    timestamp=event.timestamp,
                    action=event.action,
                    resource=event.resource,
                )
            )
            total += 1
    db.commit()
    return total
