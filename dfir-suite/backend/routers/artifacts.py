from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from database import get_db
from auth import get_current_user, require_investigator
import models, schemas

router = APIRouter(prefix="/api/artifacts", tags=["Artifacts"])

@router.get("/case/{case_id}", response_model=List[schemas.ArtifactOut])
def list_artifacts(
    case_id: int,
    artifact_type: Optional[str] = None,
    is_suspicious: Optional[bool] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    query = db.query(models.Artifact).filter(models.Artifact.case_id == case_id)
    if artifact_type:
        query = query.filter(models.Artifact.artifact_type == artifact_type)
    if is_suspicious is not None:
        query = query.filter(models.Artifact.is_suspicious == is_suspicious)
    return query.order_by(models.Artifact.timestamp.desc().nullslast()).all()

@router.get("/case/{case_id}/types")
def get_artifact_types(
    case_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    from sqlalchemy import func, distinct
    results = db.query(
        models.Artifact.artifact_type,
        func.count(models.Artifact.id).label("count")
    ).filter(models.Artifact.case_id == case_id).group_by(models.Artifact.artifact_type).all()
    return [{"type": r[0], "count": r[1]} for r in results]

@router.get("/case/{case_id}/suspicious")
def get_suspicious_artifacts(
    case_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    artifacts = db.query(models.Artifact).filter(
        models.Artifact.case_id == case_id,
        models.Artifact.is_suspicious == True
    ).order_by(models.Artifact.timestamp.desc().nullslast()).all()
    return artifacts

@router.post("/collect/{evidence_id}")
def collect_artifacts(
    evidence_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    evidence = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(404, "Evidence not found")
    background_tasks.add_task(run_artifact_collection, evidence_id, db)
    return {"status": "started", "evidence_id": evidence_id, "message": "Artifact collection started in background"}

def run_artifact_collection(evidence_id: int, db: Session):
    from services.artifact_service import ArtifactCollector
    from database import SessionLocal
    db2 = SessionLocal()
    try:
        evidence = db2.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
        if not evidence:
            return
        collector = ArtifactCollector(db2)
        collector.collect(evidence)
        evidence.is_processed = True
        db2.commit()
    finally:
        db2.close()

@router.get("/{artifact_id}", response_model=schemas.ArtifactOut)
def get_artifact(
    artifact_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    artifact = db.query(models.Artifact).filter(models.Artifact.id == artifact_id).first()
    if not artifact:
        raise HTTPException(404, "Artifact not found")
    return artifact

@router.delete("/{artifact_id}", status_code=204)
def delete_artifact(
    artifact_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    artifact = db.query(models.Artifact).filter(models.Artifact.id == artifact_id).first()
    if not artifact:
        raise HTTPException(404, "Artifact not found")
    db.delete(artifact)
    db.commit()
