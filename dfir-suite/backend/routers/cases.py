from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
import random, string
from database import get_db
from auth import get_current_user, require_investigator
import models, schemas

router = APIRouter(prefix="/api/cases", tags=["Cases"])

def generate_case_number():
    year = datetime.now().year
    rand = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"DFIR-{year}-{rand}"

@router.get("/", response_model=List[schemas.CaseOut])
def list_cases(
    status: Optional[str] = None,
    skip: int = 0, limit: int = 100,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    query = db.query(models.Case)
    if status:
        query = query.filter(models.Case.status == status)
    cases = query.order_by(models.Case.created_at.desc()).offset(skip).limit(limit).all()
    result = []
    for c in cases:
        evidence_count = db.query(models.Evidence).filter(models.Evidence.case_id == c.id).count()
        ioc_count = db.query(models.IOC).filter(models.IOC.case_id == c.id).count()
        case_dict = {**c.__dict__}
        case_dict["evidence_count"] = evidence_count
        case_dict["ioc_count"] = ioc_count
        result.append(schemas.CaseOut(**case_dict))
    return result

@router.post("/", response_model=schemas.CaseOut, status_code=201)
def create_case(
    payload: schemas.CaseCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    case = models.Case(
        case_number=generate_case_number(),
        title=payload.title,
        description=payload.description,
        priority=payload.priority,
        tags=payload.tags or [],
        affected_systems=payload.affected_systems or [],
        investigator_id=payload.investigator_id or current_user.id,
        mitre_techniques=[]
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    log = models.AuditLog(user_id=current_user.id, action="create_case",
                          resource_type="case", resource_id=case.id,
                          details={"case_number": case.case_number})
    db.add(log)
    db.commit()
    return schemas.CaseOut(**{**case.__dict__, "evidence_count": 0, "ioc_count": 0})

@router.get("/{case_id}", response_model=schemas.CaseOut)
def get_case(
    case_id: int, db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    case = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    evidence_count = db.query(models.Evidence).filter(models.Evidence.case_id == case_id).count()
    ioc_count = db.query(models.IOC).filter(models.IOC.case_id == case_id).count()
    return schemas.CaseOut(**{**case.__dict__, "evidence_count": evidence_count, "ioc_count": ioc_count})

@router.put("/{case_id}", response_model=schemas.CaseOut)
def update_case(
    case_id: int, payload: schemas.CaseUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    case = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    for field, value in payload.dict(exclude_none=True).items():
        setattr(case, field, value)
    if payload.status == schemas.CaseStatus.closed:
        case.closed_at = datetime.utcnow()
    db.commit()
    db.refresh(case)
    evidence_count = db.query(models.Evidence).filter(models.Evidence.case_id == case_id).count()
    ioc_count = db.query(models.IOC).filter(models.IOC.case_id == case_id).count()
    return schemas.CaseOut(**{**case.__dict__, "evidence_count": evidence_count, "ioc_count": ioc_count})

@router.delete("/{case_id}", status_code=204)
def delete_case(
    case_id: int, db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    case = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    db.delete(case)
    db.commit()

@router.get("/{case_id}/summary")
def case_summary(
    case_id: int, db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    case = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    artifacts = db.query(models.Artifact).filter(models.Artifact.case_id == case_id).all()
    iocs = db.query(models.IOC).filter(models.IOC.case_id == case_id).all()
    events = db.query(models.TimelineEvent).filter(models.TimelineEvent.case_id == case_id).all()
    scans = db.query(models.ScanResult).filter(models.ScanResult.case_id == case_id).all()
    suspicious = [a for a in artifacts if a.is_suspicious]
    critical_iocs = [i for i in iocs if i.severity == models.SeverityLevel.critical]
    return {
        "case_id": case_id,
        "case_number": case.case_number,
        "title": case.title,
        "status": case.status,
        "priority": case.priority,
        "total_artifacts": len(artifacts),
        "suspicious_artifacts": len(suspicious),
        "total_iocs": len(iocs),
        "critical_iocs": len(critical_iocs),
        "timeline_events": len(events),
        "scan_hits": len(scans),
        "mitre_techniques": case.mitre_techniques or [],
        "affected_systems": case.affected_systems or [],
        "tags": case.tags or []
    }

@router.post("/{case_id}/notes", response_model=schemas.NoteOut, status_code=201)
def add_note(
    case_id: int, payload: schemas.NoteCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    note = models.InvestigatorNote(
        case_id=case_id,
        author_id=current_user.id,
        title=payload.title,
        content=payload.content,
        is_pinned=payload.is_pinned
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note

@router.get("/{case_id}/notes", response_model=List[schemas.NoteOut])
def get_notes(
    case_id: int, db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    return db.query(models.InvestigatorNote).filter(
        models.InvestigatorNote.case_id == case_id
    ).order_by(models.InvestigatorNote.is_pinned.desc(), models.InvestigatorNote.created_at.desc()).all()
