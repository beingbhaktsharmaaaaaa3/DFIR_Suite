from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Float, JSON, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base
import enum

class SessionType(str, enum.Enum):
    ram_capture  = "ram_capture"
    ram_analysis = "ram_analysis"
    disk_imaging = "disk_imaging"
    disk_analysis= "disk_analysis"
    data_recovery= "data_recovery"
    partition_rec= "partition_recovery"

class AcqStatus(str, enum.Enum):
    pending    = "pending"
    running    = "running"
    completed  = "completed"
    failed     = "failed"
    paused     = "paused"

class Session(Base):
    __tablename__ = "sessions"
    id           = Column(Integer, primary_key=True, index=True)
    name         = Column(String(200), nullable=False)
    session_type = Column(String(50), nullable=False)
    examiner     = Column(String(100))
    notes        = Column(Text)
    created_at   = Column(DateTime(timezone=True), server_default=func.now())
    updated_at   = Column(DateTime(timezone=True), onupdate=func.now())
    metadata_json= Column(JSON, default=dict)
    acquisitions = relationship("Acquisition", back_populates="session", cascade="all, delete-orphan")
    results      = relationship("AnalysisResult", back_populates="session", cascade="all, delete-orphan")
    reports      = relationship("Report", back_populates="session", cascade="all, delete-orphan")

class Acquisition(Base):
    __tablename__ = "acquisitions"
    id           = Column(Integer, primary_key=True, index=True)
    session_id   = Column(Integer, nullable=True)
    name         = Column(String(200), nullable=False)
    acq_type     = Column(String(50), nullable=False)   # ram_dump | disk_image | partition
    source       = Column(String(500))                   # device path / drive
    dest_path    = Column(String(500))                   # output file
    format       = Column(String(20))                    # raw / e01 / dd
    size_bytes   = Column(Float, default=0)
    md5          = Column(String(32))
    sha1         = Column(String(40))
    sha256       = Column(String(64))
    status       = Column(String(20), default="pending")
    progress     = Column(Float, default=0)
    started_at   = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    tool_used    = Column(String(100))
    log          = Column(Text)
    system_info  = Column(JSON, default=dict)
    verified     = Column(Boolean, default=False)
    session      = relationship("Session", back_populates="acquisitions")

class AnalysisResult(Base):
    __tablename__ = "analysis_results"
    id           = Column(Integer, primary_key=True, index=True)
    session_id   = Column(Integer, nullable=True)
    source_file  = Column(String(500))
    analysis_type= Column(String(100))                   # pslist | netscan | malfind | etc
    plugin       = Column(String(100))
    data         = Column(JSON, default=list)
    summary      = Column(Text)
    suspicious_count = Column(Integer, default=0)
    created_at   = Column(DateTime(timezone=True), server_default=func.now())
    session      = relationship("Session", back_populates="results")

class RecoveredFile(Base):
    __tablename__ = "recovered_files"
    id           = Column(Integer, primary_key=True, index=True)
    session_id   = Column(Integer, nullable=True)
    original_name= Column(String(500))
    recovered_path= Column(String(500))
    file_type    = Column(String(50))
    size_bytes   = Column(Float, default=0)
    quality      = Column(String(20))   # good | partial | corrupted | overwritten
    offset       = Column(Float)
    md5          = Column(String(32))
    created_at   = Column(DateTime(timezone=True), server_default=func.now())

class Report(Base):
    __tablename__ = "reports"
    id           = Column(Integer, primary_key=True, index=True)
    session_id   = Column(Integer, nullable=True)
    title        = Column(String(300))
    examiner     = Column(String(100))
    format       = Column(String(10), default="pdf")
    file_path    = Column(String(500))
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    content_json = Column(JSON, default=dict)
    session      = relationship("Session", back_populates="reports")
