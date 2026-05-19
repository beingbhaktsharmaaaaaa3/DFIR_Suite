from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from database import get_db
from auth import get_current_user, require_investigator
import models, schemas

router = APIRouter(prefix="/api/timeline", tags=["Timeline"])

@router.get("/case/{case_id}", response_model=List[schemas.TimelineEventOut])
def get_timeline(
    case_id: int,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    flagged_only: bool = False,
    skip: int = 0, limit: int = 1000,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    query = db.query(models.TimelineEvent).filter(models.TimelineEvent.case_id == case_id)
    if start:
        query = query.filter(models.TimelineEvent.timestamp >= start)
    if end:
        query = query.filter(models.TimelineEvent.timestamp <= end)
    if severity:
        query = query.filter(models.TimelineEvent.severity == severity)
    if source:
        query = query.filter(models.TimelineEvent.source == source)
    if mitre_technique:
        query = query.filter(models.TimelineEvent.mitre_technique == mitre_technique)
    if flagged_only:
        query = query.filter(models.TimelineEvent.is_flagged == True)
    return query.order_by(models.TimelineEvent.timestamp.asc()).offset(skip).limit(limit).all()

@router.post("/", response_model=schemas.TimelineEventOut, status_code=201)
def add_event(
    payload: schemas.TimelineEventCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    event = models.TimelineEvent(**payload.dict())
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

@router.patch("/{event_id}/flag")
def flag_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    event = db.query(models.TimelineEvent).filter(models.TimelineEvent.id == event_id).first()
    if not event:
        raise HTTPException(404, "Event not found")
    event.is_flagged = not event.is_flagged
    db.commit()
    return {"id": event_id, "is_flagged": event.is_flagged}

@router.get("/case/{case_id}/stats")
def timeline_stats(
    case_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    from sqlalchemy import func
    events = db.query(models.TimelineEvent).filter(models.TimelineEvent.case_id == case_id).all()
    if not events:
        return {"total": 0, "by_severity": {}, "by_source": {}, "by_tactic": {}, "flagged": 0}
    severity_counts = {}
    source_counts = {}
    tactic_counts = {}
    for e in events:
        sev = e.severity.value if e.severity else "info"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        src = e.source or "unknown"
        source_counts[src] = source_counts.get(src, 0) + 1
        if e.mitre_tactic:
            tactic_counts[e.mitre_tactic] = tactic_counts.get(e.mitre_tactic, 0) + 1
    return {
        "total": len(events),
        "by_severity": severity_counts,
        "by_source": source_counts,
        "by_tactic": tactic_counts,
        "flagged": sum(1 for e in events if e.is_flagged)
    }

@router.post("/case/{case_id}/build")
def build_timeline(
    case_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    """Build timeline from all collected artifacts in a case."""
    from services.timeline_service import TimelineBuilder
    builder = TimelineBuilder(db)
    count = builder.build_from_case(case_id)
    return {"status": "built", "events_created": count}
