from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from database import get_db
from auth import get_current_user, require_investigator
import models, schemas

router = APIRouter(prefix="/api/iocs", tags=["IOCs"])

@router.get("/case/{case_id}", response_model=List[schemas.IOCOut])
def list_iocs(
    case_id: int,
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    query = db.query(models.IOC).filter(models.IOC.case_id == case_id)
    if ioc_type:
        query = query.filter(models.IOC.ioc_type == ioc_type)
    if severity:
        query = query.filter(models.IOC.severity == severity)
    return query.order_by(models.IOC.severity.desc()).all()

@router.post("/", response_model=schemas.IOCOut, status_code=201)
def create_ioc(
    payload: schemas.IOCCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    ioc = models.IOC(**payload.dict())
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc

@router.post("/bulk")
def bulk_import_iocs(
    case_id: int,
    iocs: List[schemas.IOCCreate],
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    created = 0
    for ioc_data in iocs:
        ioc_data.case_id = case_id
        existing = db.query(models.IOC).filter(
            models.IOC.case_id == case_id,
            models.IOC.value == ioc_data.value
        ).first()
        if not existing:
            ioc = models.IOC(**ioc_data.dict())
            db.add(ioc)
            created += 1
    db.commit()
    return {"created": created, "total_submitted": len(iocs)}

@router.delete("/{ioc_id}", status_code=204)
def delete_ioc(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    ioc = db.query(models.IOC).filter(models.IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(404, "IOC not found")
    db.delete(ioc)
    db.commit()

@router.get("/case/{case_id}/export")
def export_iocs(
    case_id: int,
    format: str = "json",
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    iocs = db.query(models.IOC).filter(models.IOC.case_id == case_id).all()
    if format == "csv":
        lines = ["type,value,severity,confidence,source"]
        for ioc in iocs:
            lines.append(f"{ioc.ioc_type},{ioc.value},{ioc.severity.value},{ioc.confidence},{ioc.source or ''}")
        return {"format": "csv", "data": "\n".join(lines)}
    return {"format": "json", "data": [{"type": i.ioc_type, "value": i.value, "severity": i.severity.value, "confidence": i.confidence} for i in iocs]}
