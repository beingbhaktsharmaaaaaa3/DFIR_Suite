from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class UserRole(str, Enum):
    admin = "admin"
    investigator = "investigator"
    viewer = "viewer"

class CaseStatus(str, Enum):
    open = "open"
    active = "active"
    closed = "closed"
    archived = "archived"

class SeverityLevel(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class EvidenceType(str, Enum):
    disk_image = "disk_image"
    memory_dump = "memory_dump"
    file = "file"
    live_response = "live_response"
    network_capture = "network_capture"

# ─── Auth ───
class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict

class LoginRequest(BaseModel):
    username: str
    password: str

# ─── Users ───
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: Optional[str] = None
    password: str = Field(..., min_length=8)
    role: UserRole = UserRole.investigator

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    class Config:
        from_attributes = True

# ─── Cases ───
class CaseCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    description: Optional[str] = None
    priority: SeverityLevel = SeverityLevel.medium
    tags: Optional[List[str]] = []
    affected_systems: Optional[List[str]] = []
    investigator_id: Optional[int] = None

class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[CaseStatus] = None
    priority: Optional[SeverityLevel] = None
    tags: Optional[List[str]] = None
    affected_systems: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    investigator_id: Optional[int] = None

class CaseOut(BaseModel):
    id: int
    case_number: str
    title: str
    description: Optional[str]
    status: CaseStatus
    priority: SeverityLevel
    investigator_id: Optional[int]
    created_at: datetime
    updated_at: Optional[datetime]
    tags: Optional[List[str]]
    mitre_techniques: Optional[List[str]]
    affected_systems: Optional[List[str]]
    evidence_count: Optional[int] = 0
    ioc_count: Optional[int] = 0
    class Config:
        from_attributes = True

# ─── Evidence ───
class EvidenceCreate(BaseModel):
    case_id: int
    name: str
    evidence_type: EvidenceType
    original_path: Optional[str] = None
    source_system: Optional[str] = None
    acquired_by: Optional[str] = None
    notes: Optional[str] = None

class EvidenceOut(BaseModel):
    id: int
    case_id: int
    name: str
    evidence_type: EvidenceType
    file_path: Optional[str]
    file_size: Optional[float]
    md5_hash: Optional[str]
    sha256_hash: Optional[str]
    sha1_hash: Optional[str]
    source_system: Optional[str]
    acquisition_date: datetime
    acquired_by: Optional[str]
    is_processed: bool
    notes: Optional[str]
    class Config:
        from_attributes = True

# ─── Artifacts ───
class ArtifactOut(BaseModel):
    id: int
    evidence_id: int
    case_id: int
    artifact_type: str
    name: str
    path: Optional[str]
    timestamp: Optional[datetime]
    data: Optional[Dict]
    raw_value: Optional[str]
    severity: SeverityLevel
    is_suspicious: bool
    mitre_technique: Optional[str]
    created_at: datetime
    class Config:
        from_attributes = True

# ─── Timeline ───
class TimelineEventCreate(BaseModel):
    case_id: int
    evidence_id: Optional[int] = None
    timestamp: datetime
    event_type: str
    source: Optional[str] = None
    description: str
    details: Optional[Dict] = {}
    severity: SeverityLevel = SeverityLevel.info
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None

class TimelineEventOut(BaseModel):
    id: int
    case_id: int
    evidence_id: Optional[int]
    timestamp: datetime
    event_type: str
    source: Optional[str]
    description: str
    details: Optional[Dict]
    severity: SeverityLevel
    mitre_technique: Optional[str]
    mitre_tactic: Optional[str]
    is_flagged: bool
    class Config:
        from_attributes = True

# ─── IOC ───
class IOCCreate(BaseModel):
    case_id: int
    ioc_type: str
    value: str
    description: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.medium
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    source: Optional[str] = None

class IOCOut(BaseModel):
    id: int
    case_id: int
    ioc_type: str
    value: str
    description: Optional[str]
    severity: SeverityLevel
    confidence: float
    source: Optional[str]
    is_active: bool
    first_seen: datetime
    class Config:
        from_attributes = True

# ─── Scan ───
class ScanResultOut(BaseModel):
    id: int
    evidence_id: int
    case_id: int
    scanner_type: str
    rule_name: Optional[str]
    severity: SeverityLevel
    file_path: Optional[str]
    description: Optional[str]
    mitre_technique: Optional[str]
    scan_timestamp: datetime
    matched_strings: Optional[List]
    class Config:
        from_attributes = True

# ─── Notes ───
class NoteCreate(BaseModel):
    case_id: int
    title: Optional[str] = None
    content: str
    is_pinned: bool = False

class NoteOut(BaseModel):
    id: int
    case_id: int
    title: Optional[str]
    content: str
    is_pinned: bool
    created_at: datetime
    class Config:
        from_attributes = True

# ─── AI ───
class AIQueryRequest(BaseModel):
    case_id: Optional[int] = None
    query: str
    context: Optional[str] = None
    model: str = "mistral"

class AIQueryResponse(BaseModel):
    response: str
    model: str
    tokens_used: Optional[int] = None

# ─── Network ───
class NetworkArtifactOut(BaseModel):
    id: int
    case_id: int
    artifact_type: Optional[str]
    local_address: Optional[str]
    local_port: Optional[int]
    remote_address: Optional[str]
    remote_port: Optional[int]
    protocol: Optional[str]
    state: Optional[str]
    process_name: Optional[str]
    pid: Optional[int]
    is_suspicious: bool
    collected_at: datetime
    class Config:
        from_attributes = True

# ─── Persistence ───
class PersistenceItemOut(BaseModel):
    id: int
    case_id: int
    persistence_type: str
    location: Optional[str]
    value_name: Optional[str]
    value_data: Optional[str]
    description: Optional[str]
    severity: SeverityLevel
    mitre_technique: Optional[str]
    is_suspicious: bool
    collected_at: datetime
    class Config:
        from_attributes = True

# ─── Dashboard ───
class DashboardStats(BaseModel):
    total_cases: int
    open_cases: int
    active_cases: int
    total_evidence: int
    total_iocs: int
    critical_iocs: int
    total_artifacts: int
    suspicious_artifacts: int
    scan_results: int
    recent_cases: List[Dict]
    severity_breakdown: Dict
    artifact_types: Dict

# ─── Report ───
class ReportCreate(BaseModel):
    case_id: int
    title: str
    report_type: str = "full"
    format: str = "pdf"
    includes_ai_summary: bool = False
