from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Float, ForeignKey, JSON, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base
import enum

class UserRole(str, enum.Enum):
    admin = "admin"
    investigator = "investigator"
    viewer = "viewer"

class CaseStatus(str, enum.Enum):
    open = "open"
    active = "active"
    closed = "closed"
    archived = "archived"

class EvidenceType(str, enum.Enum):
    disk_image = "disk_image"
    memory_dump = "memory_dump"
    file = "file"
    live_response = "live_response"
    network_capture = "network_capture"

class SeverityLevel(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100))
    role = Column(Enum(UserRole), default=UserRole.investigator)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    cases = relationship("Case", back_populates="assigned_investigator")
    audit_logs = relationship("AuditLog", back_populates="user")

class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True, index=True)
    case_number = Column(String(50), unique=True, nullable=False, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    status = Column(Enum(CaseStatus), default=CaseStatus.open)
    priority = Column(Enum(SeverityLevel), default=SeverityLevel.medium)
    investigator_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    closed_at = Column(DateTime(timezone=True), nullable=True)
    tags = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    affected_systems = Column(JSON, default=list)
    assigned_investigator = relationship("User", back_populates="cases")
    evidence = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="case", cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="case", cascade="all, delete-orphan")
    notes = relationship("InvestigatorNote", back_populates="case", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="case", cascade="all, delete-orphan")

class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    name = Column(String(200), nullable=False)
    evidence_type = Column(Enum(EvidenceType), nullable=False)
    file_path = Column(String(500))
    original_path = Column(String(500))
    file_size = Column(Float, default=0)
    md5_hash = Column(String(32))
    sha256_hash = Column(String(64))
    sha1_hash = Column(String(40))
    source_system = Column(String(200))
    acquisition_date = Column(DateTime(timezone=True), server_default=func.now())
    acquired_by = Column(String(100))
    chain_of_custody = Column(JSON, default=list)
    metadata_json = Column(JSON, default=dict)
    is_processed = Column(Boolean, default=False)
    notes = Column(Text)
    case = relationship("Case", back_populates="evidence")
    artifacts = relationship("Artifact", back_populates="evidence", cascade="all, delete-orphan")
    scan_results = relationship("ScanResult", back_populates="evidence", cascade="all, delete-orphan")

class Artifact(Base):
    __tablename__ = "artifacts"
    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id"), nullable=False)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    artifact_type = Column(String(50), nullable=False, index=True)
    name = Column(String(500), nullable=False)
    path = Column(String(1000))
    timestamp = Column(DateTime(timezone=True), nullable=True)
    data = Column(JSON, default=dict)
    raw_value = Column(Text)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.info)
    is_suspicious = Column(Boolean, default=False)
    mitre_technique = Column(String(50))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    evidence = relationship("Evidence", back_populates="artifacts")

class TimelineEvent(Base):
    __tablename__ = "timeline_events"
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    evidence_id = Column(Integer, ForeignKey("evidence.id"), nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    event_type = Column(String(100), nullable=False)
    source = Column(String(100))
    description = Column(Text, nullable=False)
    details = Column(JSON, default=dict)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.info)
    mitre_technique = Column(String(50))
    mitre_tactic = Column(String(100))
    is_flagged = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    case = relationship("Case", back_populates="timeline_events")

class IOC(Base):
    __tablename__ = "iocs"
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    ioc_type = Column(String(50), nullable=False)
    value = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.medium)
    confidence = Column(Float, default=0.5)
    source = Column(String(200))
    is_active = Column(Boolean, default=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True))
    metadata_json = Column(JSON, default=dict)
    case = relationship("Case", back_populates="iocs")

class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id"), nullable=False)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    scanner_type = Column(String(50), nullable=False)
    rule_name = Column(String(200))
    rule_file = Column(String(200))
    matched_strings = Column(JSON, default=list)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.medium)
    file_path = Column(String(500))
    description = Column(Text)
    mitre_technique = Column(String(50))
    scan_timestamp = Column(DateTime(timezone=True), server_default=func.now())
    raw_output = Column(Text)
    evidence = relationship("Evidence", back_populates="scan_results")

class NetworkArtifact(Base):
    __tablename__ = "network_artifacts"
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    evidence_id = Column(Integer, ForeignKey("evidence.id"), nullable=True)
    artifact_type = Column(String(50))
    local_address = Column(String(100))
    local_port = Column(Integer)
    remote_address = Column(String(100))
    remote_port = Column(Integer)
    protocol = Column(String(10))
    state = Column(String(50))
    process_name = Column(String(200))
    pid = Column(Integer)
    is_suspicious = Column(Boolean, default=False)
    notes = Column(Text)
    collected_at = Column(DateTime(timezone=True), server_default=func.now())

class PersistenceItem(Base):
    __tablename__ = "persistence_items"
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    evidence_id = Column(Integer, ForeignKey("evidence.id"), nullable=True)
    persistence_type = Column(String(100), nullable=False)
    location = Column(String(500))
    value_name = Column(String(200))
    value_data = Column(Text)
    description = Column(Text)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.medium)
    mitre_technique = Column(String(50))
    is_suspicious = Column(Boolean, default=False)
    collected_at = Column(DateTime(timezone=True), server_default=func.now())

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    title = Column(String(300), nullable=False)
    report_type = Column(String(50), default="full")
    file_path = Column(String(500))
    format = Column(String(10), default="pdf")
    generated_by = Column(Integer, ForeignKey("users.id"))
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    summary = Column(Text)
    includes_ai_summary = Column(Boolean, default=False)
    case = relationship("Case", back_populates="reports")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50))
    resource_id = Column(Integer)
    details = Column(JSON, default=dict)
    ip_address = Column(String(50))
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    user = relationship("User", back_populates="audit_logs")

class InvestigatorNote(Base):
    __tablename__ = "investigator_notes"
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    title = Column(String(200))
    content = Column(Text, nullable=False)
    is_pinned = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    case = relationship("Case", back_populates="notes")
