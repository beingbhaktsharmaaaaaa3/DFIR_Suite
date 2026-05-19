from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session
from typing import List, Optional
import os, shutil, hashlib, aiofiles
from database import get_db
from auth import get_current_user, require_investigator
import models, schemas

router = APIRouter(prefix="/api/evidence", tags=["Evidence"])

EVIDENCE_STORE = os.path.join(os.path.dirname(__file__), "..", "..", "evidence_store")
os.makedirs(EVIDENCE_STORE, exist_ok=True)

def compute_hashes(file_path: str):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

@router.post("/upload", response_model=schemas.EvidenceOut, status_code=201)
async def upload_evidence(
    case_id: int = Form(...),
    name: str = Form(...),
    evidence_type: str = Form(...),
    source_system: str = Form(None),
    acquired_by: str = Form(None),
    notes: str = Form(None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    case = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    case_dir = os.path.join(EVIDENCE_STORE, f"case_{case_id}")
    os.makedirs(case_dir, exist_ok=True)
    file_path = os.path.join(case_dir, file.filename)
    async with aiofiles.open(file_path, "wb") as out:
        content = await file.read()
        await out.write(content)
    file_size = os.path.getsize(file_path) / (1024 * 1024)
    md5, sha1, sha256 = compute_hashes(file_path)
    custody_entry = {
        "action": "acquired",
        "by": acquired_by or current_user.username,
        "timestamp": str(models.func.now() if False else __import__('datetime').datetime.utcnow()),
        "hash_verified": True
    }
    evidence = models.Evidence(
        case_id=case_id,
        name=name,
        evidence_type=evidence_type,
        file_path=file_path,
        original_path=file.filename,
        file_size=file_size,
        md5_hash=md5,
        sha1_hash=sha1,
        sha256_hash=sha256,
        source_system=source_system,
        acquired_by=acquired_by or current_user.username,
        chain_of_custody=[custody_entry],
        notes=notes
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence

@router.get("/case/{case_id}", response_model=List[schemas.EvidenceOut])
def list_case_evidence(
    case_id: int, db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    return db.query(models.Evidence).filter(models.Evidence.case_id == case_id).all()

@router.get("/{evidence_id}", response_model=schemas.EvidenceOut)
def get_evidence(
    evidence_id: int, db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    ev = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    if not ev:
        raise HTTPException(404, "Evidence not found")
    return ev

@router.delete("/{evidence_id}", status_code=204)
def delete_evidence(
    evidence_id: int, db: Session = Depends(get_db),
    current_user: models.User = Depends(require_investigator)
):
    ev = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    if not ev:
        raise HTTPException(404, "Evidence not found")
    if ev.file_path and os.path.exists(ev.file_path):
        os.remove(ev.file_path)
    db.delete(ev)
    db.commit()

@router.get("/{evidence_id}/verify")
def verify_integrity(
    evidence_id: int, db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    ev = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    if not ev:
        raise HTTPException(404, "Evidence not found")
    if not ev.file_path or not os.path.exists(ev.file_path):
        return {"verified": False, "error": "File not found on disk"}
    md5, sha1, sha256 = compute_hashes(ev.file_path)
    return {
        "verified": sha256 == ev.sha256_hash,
        "stored_sha256": ev.sha256_hash,
        "current_sha256": sha256,
        "stored_md5": ev.md5_hash,
        "current_md5": md5
    }
