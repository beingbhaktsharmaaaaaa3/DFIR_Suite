from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from database import get_db
from auth import get_current_user, require_investigator, require_admin
import models, schemas

# ─── Dashboard ───
dashboard_router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@dashboard_router.get("/stats", response_model=schemas.DashboardStats)
def get_stats(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    from sqlalchemy import func
    total_cases = db.query(func.count(models.Case.id)).scalar()
    open_cases = db.query(func.count(models.Case.id)).filter(models.Case.status == "open").scalar()
    active_cases = db.query(func.count(models.Case.id)).filter(models.Case.status == "active").scalar()
    total_evidence = db.query(func.count(models.Evidence.id)).scalar()
    total_iocs = db.query(func.count(models.IOC.id)).scalar()
    critical_iocs = db.query(func.count(models.IOC.id)).filter(models.IOC.severity == "critical").scalar()
    total_artifacts = db.query(func.count(models.Artifact.id)).scalar()
    suspicious_artifacts = db.query(func.count(models.Artifact.id)).filter(models.Artifact.is_suspicious == True).scalar()
    scan_results = db.query(func.count(models.ScanResult.id)).scalar()
    recent_cases = db.query(models.Case).order_by(models.Case.created_at.desc()).limit(5).all()
    sev_rows = db.query(models.Case.priority, func.count(models.Case.id)).group_by(models.Case.priority).all()
    art_rows = db.query(models.Artifact.artifact_type, func.count(models.Artifact.id)).group_by(models.Artifact.artifact_type).all()
    return schemas.DashboardStats(
        total_cases=total_cases or 0, open_cases=open_cases or 0, active_cases=active_cases or 0,
        total_evidence=total_evidence or 0, total_iocs=total_iocs or 0, critical_iocs=critical_iocs or 0,
        total_artifacts=total_artifacts or 0, suspicious_artifacts=suspicious_artifacts or 0, scan_results=scan_results or 0,
        recent_cases=[{"id": c.id, "case_number": c.case_number, "title": c.title, "status": c.status.value, "priority": c.priority.value} for c in recent_cases],
        severity_breakdown={r[0].value if r[0] else "unknown": r[1] for r in sev_rows},
        artifact_types={r[0]: r[1] for r in art_rows}
    )

# ─── Users ───
users_router = APIRouter(prefix="/api/users", tags=["Users"])

@users_router.get("/", response_model=List[schemas.UserOut])
def list_users(db: Session = Depends(get_db), current_user: models.User = Depends(require_admin)):
    return db.query(models.User).all()

@users_router.post("/", response_model=schemas.UserOut, status_code=201)
def create_user(payload: schemas.UserCreate, db: Session = Depends(get_db), current_user: models.User = Depends(require_admin)):
    from auth import hash_password
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(400, "Username already exists")
    user = models.User(
        username=payload.username, email=payload.email,
        full_name=payload.full_name, role=payload.role,
        hashed_password=hash_password(payload.password)
    )
    db.add(user); db.commit(); db.refresh(user)
    return user

@users_router.put("/{user_id}", response_model=schemas.UserOut)
def update_user(user_id: int, payload: schemas.UserUpdate, db: Session = Depends(get_db), current_user: models.User = Depends(require_admin)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user: raise HTTPException(404, "User not found")
    for f, v in payload.dict(exclude_none=True).items(): setattr(user, f, v)
    db.commit(); db.refresh(user)
    return user

@users_router.delete("/{user_id}", status_code=204)
def delete_user(user_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(require_admin)):
    if user_id == current_user.id: raise HTTPException(400, "Cannot delete yourself")
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user: raise HTTPException(404, "User not found")
    db.delete(user); db.commit()

@users_router.get("/me", response_model=schemas.UserOut)
def get_me(current_user: models.User = Depends(get_current_user)):
    return current_user

# ─── Network ───
network_router = APIRouter(prefix="/api/network", tags=["Network"])

@network_router.post("/collect/{case_id}")
def collect_network(case_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(require_investigator)):
    from services.network_service import NetworkCollector
    collector = NetworkCollector(db)
    count = collector.collect_live(case_id)
    return {"status": "collected", "case_id": case_id, "items_collected": count}

@network_router.get("/case/{case_id}")
def get_network_artifacts(case_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    items = db.query(models.NetworkArtifact).filter(models.NetworkArtifact.case_id == case_id).all()
    return [{"id": i.id, "type": i.artifact_type, "local": f"{i.local_address}:{i.local_port}", "remote": f"{i.remote_address}:{i.remote_port}", "protocol": i.protocol, "state": i.state, "process": i.process_name, "pid": i.pid, "suspicious": i.is_suspicious} for i in items]

# ─── Persistence ───
persistence_router = APIRouter(prefix="/api/persistence", tags=["Persistence"])

@persistence_router.post("/scan/{case_id}")
def scan_persistence(case_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(require_investigator)):
    from services.persistence_service import PersistenceDetector
    detector = PersistenceDetector(db)
    count = detector.scan(case_id)
    return {"status": "scanned", "case_id": case_id, "items_found": count}

@persistence_router.get("/case/{case_id}")
def get_persistence(case_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    items = db.query(models.PersistenceItem).filter(models.PersistenceItem.case_id == case_id).order_by(models.PersistenceItem.severity.desc()).all()
    return [{"id": i.id, "type": i.persistence_type, "location": i.location, "name": i.value_name, "data": i.value_data, "severity": i.severity.value, "mitre": i.mitre_technique, "suspicious": i.is_suspicious} for i in items]

# ─── Reports ───
reports_router = APIRouter(prefix="/api/reports", tags=["Reports"])

@reports_router.post("/generate", status_code=201)
def generate_report(payload: schemas.ReportCreate, db: Session = Depends(get_db), current_user: models.User = Depends(require_investigator)):
    from services.report_service import ReportGenerator
    gen = ReportGenerator(db)
    report = gen.generate(payload, current_user.id)
    return {"status": "generated", "report_id": report.id, "file_path": report.file_path, "title": report.title}

@reports_router.get("/case/{case_id}")
def list_reports(case_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    reports = db.query(models.Report).filter(models.Report.case_id == case_id).order_by(models.Report.generated_at.desc()).all()
    return [{"id": r.id, "title": r.title, "type": r.report_type, "format": r.format, "generated_at": r.generated_at, "file_path": r.file_path} for r in reports]

@reports_router.get("/download/{report_id}")
def download_report(report_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    from fastapi.responses import FileResponse
    import os
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report: raise HTTPException(404, "Report not found")
    if not os.path.exists(report.file_path): raise HTTPException(404, "Report file not found")
    return FileResponse(report.file_path, filename=os.path.basename(report.file_path))

# ─── Auth ───
auth_router = APIRouter(prefix="/api/auth", tags=["Auth"])

@auth_router.post("/login", response_model=schemas.Token)
def login(payload: schemas.LoginRequest, db: Session = Depends(get_db)):
    from auth import authenticate_user, create_access_token
    from datetime import timedelta, datetime
    user = authenticate_user(db, payload.username, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    user.last_login = datetime.utcnow()
    db.commit()
    token = create_access_token(data={"sub": user.username})
    return schemas.Token(
        access_token=token, token_type="bearer",
        user={"id": user.id, "username": user.username, "role": user.role.value, "full_name": user.full_name}
    )

@auth_router.post("/logout")
def logout(current_user: models.User = Depends(get_current_user)):
    return {"message": "Logged out successfully"}
