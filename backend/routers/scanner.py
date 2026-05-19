from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from database import get_db
from auth import get_current_user, require_investigator
import models, schemas

router = APIRouter(prefix="/api/scanner", tags=["Scanner"])

@router.post("/yara/{evidence_id}")
def run_yara_scan(
    evidence_id: int,
    background_tasks: BackgroundTasks,
    rules_dir: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    evidence = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(404, "Evidence not found")
    background_tasks.add_task(_run_yara_bg, evidence_id, rules_dir)
    return {"status": "started", "scanner": "yara", "evidence_id": evidence_id}

def _run_yara_bg(evidence_id: int, rules_dir: Optional[str]):
    from services.scanner_service import YaraScanner
    from database import SessionLocal
    db = SessionLocal()
    try:
        scanner = YaraScanner(db)
        scanner.scan_evidence(evidence_id, rules_dir)
    finally:
        db.close()

@router.post("/sigma/{case_id}")
def run_sigma_scan(
    case_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    case = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    background_tasks.add_task(_run_sigma_bg, case_id)
    return {"status": "started", "scanner": "sigma", "case_id": case_id}

def _run_sigma_bg(case_id: int):
    from services.scanner_service import SigmaScanner
    from database import SessionLocal
    db = SessionLocal()
    try:
        scanner = SigmaScanner(db)
        scanner.scan_case(case_id)
    finally:
        db.close()

@router.post("/ioc/{case_id}")
def run_ioc_scan(
    case_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    background_tasks.add_task(_run_ioc_scan_bg, case_id)
    return {"status": "started", "scanner": "ioc", "case_id": case_id}

def _run_ioc_scan_bg(case_id: int):
    from services.scanner_service import IOCScanner
    from database import SessionLocal
    db = SessionLocal()
    try:
        scanner = IOCScanner(db)
        scanner.scan_case(case_id)
    finally:
        db.close()

@router.get("/results/case/{case_id}", response_model=List[schemas.ScanResultOut])
def get_scan_results(
    case_id: int,
    scanner_type: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    query = db.query(models.ScanResult).filter(models.ScanResult.case_id == case_id)
    if scanner_type:
        query = query.filter(models.ScanResult.scanner_type == scanner_type)
    if severity:
        query = query.filter(models.ScanResult.severity == severity)
    return query.order_by(models.ScanResult.scan_timestamp.desc()).all()

@router.get("/rules/yara")
def list_yara_rules(current_user: models.User = Depends(get_current_user)):
    import os
    rules_dir = os.path.join(os.path.dirname(__file__), "..", "yara_rules")
    rules = []
    if os.path.exists(rules_dir):
        for f in os.listdir(rules_dir):
            if f.endswith(".yar") or f.endswith(".yara"):
                rules.append({"name": f, "path": os.path.join(rules_dir, f)})
    return {"rules": rules, "count": len(rules)}
