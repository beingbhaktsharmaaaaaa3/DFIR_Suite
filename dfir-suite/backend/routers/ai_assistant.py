from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from auth import get_current_user
import models, schemas
import httpx, json

router = APIRouter(prefix="/api/ai", tags=["AI Assistant"])
OLLAMA_URL = "http://localhost:11434"

def ollama_available():
    try:
        r = httpx.get(f"{OLLAMA_URL}/api/tags", timeout=3)
        return r.status_code == 200
    except:
        return False

def query_ollama(prompt: str, model: str = "mistral", system: str = "") -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }
    if system:
        payload["system"] = system
    try:
        r = httpx.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=120)
        if r.status_code == 200:
            return r.json().get("response", "No response from model.")
        return f"Ollama error: {r.status_code}"
    except Exception as e:
        return f"Ollama connection failed: {str(e)}. Make sure Ollama is running."

@router.get("/status")
def ai_status():
    available = ollama_available()
    models_list = []
    if available:
        try:
            r = httpx.get(f"{OLLAMA_URL}/api/tags", timeout=5)
            models_list = [m["name"] for m in r.json().get("models", [])]
        except:
            pass
    return {"available": available, "url": OLLAMA_URL, "models": models_list}

@router.post("/query", response_model=schemas.AIQueryResponse)
def ai_query(
    payload: schemas.AIQueryRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    system_prompt = """You are DFIR-AI, an expert digital forensics and incident response assistant.
You help investigators analyze evidence, identify threats, explain attack techniques, and generate insights.
Always provide structured, actionable forensic analysis. Reference MITRE ATT&CK techniques when relevant.
Keep responses focused and professional."""
    context = payload.context or ""
    if payload.case_id:
        case = db.query(models.Case).filter(models.Case.id == payload.case_id).first()
        if case:
            artifacts = db.query(models.Artifact).filter(
                models.Artifact.case_id == payload.case_id,
                models.Artifact.is_suspicious == True
            ).limit(20).all()
            iocs = db.query(models.IOC).filter(models.IOC.case_id == payload.case_id).limit(20).all()
            context += f"\nCase: {case.case_number} - {case.title}\nStatus: {case.status}\n"
            if artifacts:
                context += f"\nSuspicious artifacts ({len(artifacts)}): " + ", ".join([a.name[:50] for a in artifacts[:5]])
            if iocs:
                context += f"\nIOCs ({len(iocs)}): " + ", ".join([f"{i.ioc_type}:{i.value[:30]}" for i in iocs[:5]])
    full_prompt = f"{context}\n\nQuestion: {payload.query}" if context else payload.query
    response = query_ollama(full_prompt, payload.model, system_prompt)
    return schemas.AIQueryResponse(response=response, model=payload.model)

@router.post("/summarize/{case_id}")
def summarize_case(
    case_id: int,
    model: str = "mistral",
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    case = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    artifacts = db.query(models.Artifact).filter(models.Artifact.case_id == case_id).all()
    iocs = db.query(models.IOC).filter(models.IOC.case_id == case_id).all()
    scans = db.query(models.ScanResult).filter(models.ScanResult.case_id == case_id).all()
    persistence = db.query(models.PersistenceItem).filter(models.PersistenceItem.case_id == case_id).all()
    suspicious_artifacts = [a for a in artifacts if a.is_suspicious]
    critical_scans = [s for s in scans if s.severity.value in ["critical", "high"]]
    prompt = f"""Generate a professional DFIR investigation summary for:

Case: {case.case_number} | {case.title}
Status: {case.status} | Priority: {case.priority}
Affected systems: {', '.join(case.affected_systems or []) or 'Unknown'}

Evidence Summary:
- Total artifacts collected: {len(artifacts)}
- Suspicious artifacts: {len(suspicious_artifacts)}
- IOCs identified: {len(iocs)}
- Scan hits: {len(scans)} ({len(critical_scans)} critical/high)
- Persistence mechanisms found: {len(persistence)}

MITRE ATT&CK techniques observed: {', '.join(case.mitre_techniques or []) or 'None mapped yet'}

Suspicious artifacts (top 10):
{chr(10).join([f'- [{a.artifact_type}] {a.name}: {a.raw_value or ""}' for a in suspicious_artifacts[:10]])}

IOCs (top 10):
{chr(10).join([f'- [{i.ioc_type}] {i.value} (confidence: {i.confidence})' for i in iocs[:10]])}

Generate: 1) Executive Summary 2) Key Findings 3) Attack Timeline Assessment 4) Recommendations"""
    summary = query_ollama(prompt, model, "You are a senior DFIR analyst generating professional investigation reports.")
    return {"case_id": case_id, "summary": summary, "model": model}

@router.post("/explain/artifact/{artifact_id}")
def explain_artifact(
    artifact_id: int,
    model: str = "mistral",
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    artifact = db.query(models.Artifact).filter(models.Artifact.id == artifact_id).first()
    if not artifact:
        raise HTTPException(404, "Artifact not found")
    prompt = f"""Explain this digital forensic artifact from a DFIR perspective:

Type: {artifact.artifact_type}
Name: {artifact.name}
Path: {artifact.path or 'N/A'}
Value: {artifact.raw_value or str(artifact.data or {})}
Timestamp: {artifact.timestamp}
Suspicious: {artifact.is_suspicious}
MITRE: {artifact.mitre_technique or 'Not mapped'}

Explain: 1) What this artifact is 2) Why it may be suspicious 3) What attacker activity it suggests 4) Related MITRE ATT&CK techniques 5) Investigation recommendations"""
    explanation = query_ollama(prompt, model)
    return {"artifact_id": artifact_id, "explanation": explanation, "model": model}

@router.post("/explain/ioc/{ioc_id}")
def explain_ioc(
    ioc_id: int,
    model: str = "mistral",
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    ioc = db.query(models.IOC).filter(models.IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(404, "IOC not found")
    prompt = f"""Analyze this Indicator of Compromise (IOC):

Type: {ioc.ioc_type}
Value: {ioc.value}
Severity: {ioc.severity}
Confidence: {ioc.confidence}
Source: {ioc.source or 'Unknown'}

Provide: 1) IOC analysis 2) Threat context 3) Attack techniques associated 4) Containment recommendations"""
    explanation = query_ollama(prompt, model)
    return {"ioc_id": ioc_id, "explanation": explanation, "model": model}

@router.post("/attack-chain/{case_id}")
def explain_attack_chain(
    case_id: int,
    model: str = "mistral",
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    case = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    events = db.query(models.TimelineEvent).filter(
        models.TimelineEvent.case_id == case_id
    ).order_by(models.TimelineEvent.timestamp.asc()).limit(50).all()
    persistence = db.query(models.PersistenceItem).filter(
        models.PersistenceItem.case_id == case_id,
        models.PersistenceItem.is_suspicious == True
    ).all()
    prompt = f"""Reconstruct the attack chain for DFIR case {case.case_number}:

Case: {case.title}
MITRE techniques found: {', '.join(case.mitre_techniques or []) or 'Unknown'}

Timeline events ({len(events)} total, showing chronological):
{chr(10).join([f'[{e.timestamp}] [{e.source}] {e.description}' for e in events[:30]])}

Suspicious persistence ({len(persistence)}):
{chr(10).join([f'- {p.persistence_type}: {p.location} = {p.value_data or ""}' for p in persistence[:10]])}

Reconstruct: 1) Initial Access 2) Execution 3) Persistence 4) Privilege Escalation 5) Lateral Movement 6) Collection 7) Exfiltration/Impact
Map each phase to MITRE ATT&CK and evidence found."""
    chain = query_ollama(prompt, model)
    return {"case_id": case_id, "attack_chain": chain, "model": model}
