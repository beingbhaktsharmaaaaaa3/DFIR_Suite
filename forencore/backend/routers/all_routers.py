from fastapi import APIRouter, HTTPException, BackgroundTasks, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import os, shutil, datetime, platform, psutil

EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)

# ════════════════════════════════════════════════════════════════════
# SYSTEM / DASHBOARD
# ════════════════════════════════════════════════════════════════════
system_router = APIRouter(prefix="/api/system", tags=["System"])

@system_router.get("/info")
def system_info():
    from services.ram_capture import get_system_info
    return get_system_info()

@system_router.get("/dashboard")
def dashboard():
    from services.disk_imaging import list_images
    from services.ram_capture import list_captures
    from services.report_service import list_reports
    try: vm = psutil.virtual_memory()
    except: vm = None
    return {
        "platform": platform.system() + " " + platform.release(),
        "hostname": platform.node(),
        "python": platform.python_version(),
        "ram_gb": round(vm.total/(1024**3), 1) if vm else 0,
        "ram_used_pct": vm.percent if vm else 0,
        "images": list_images(),
        "captures": list_captures(),
        "reports": list_reports(),
        "image_count": len(list_images()),
        "capture_count": len(list_captures()),
        "report_count": len(list_reports()),
    }

# ════════════════════════════════════════════════════════════════════
# RAM CAPTURE
# ════════════════════════════════════════════════════════════════════
ram_capture_router = APIRouter(prefix="/api/ram/capture", tags=["RAM Capture"])

class CaptureRequest(BaseModel):
    output_name: Optional[str] = None
    fmt: str = "raw"
    task_id: Optional[str] = None

@ram_capture_router.post("/start")
def start_capture(req: CaptureRequest):
    from services.ram_capture import start_ram_capture
    return start_ram_capture(req.output_name, req.fmt, req.task_id)

@ram_capture_router.get("/progress/{task_id}")
def capture_progress(task_id: str):
    from services.ram_capture import get_capture_progress
    return get_capture_progress(task_id)

@ram_capture_router.get("/list")
def list_ram_captures():
    from services.ram_capture import list_captures
    return list_captures()

@ram_capture_router.get("/sysinfo")
def sysinfo():
    from services.ram_capture import get_system_info
    return get_system_info()

# ════════════════════════════════════════════════════════════════════
# RAM ANALYSIS
# ════════════════════════════════════════════════════════════════════
ram_analysis_router = APIRouter(prefix="/api/ram/analysis", tags=["RAM Analysis"])

class AnalysisRequest(BaseModel):
    dump_path: str
    task_id: Optional[str] = None

class PluginRequest(BaseModel):
    dump_path: str
    pid: Optional[int] = None

@ram_analysis_router.post("/full")
def run_full(req: AnalysisRequest):
    from services.ram_analysis import run_full_analysis
    return run_full_analysis(req.dump_path, req.task_id)

@ram_analysis_router.get("/progress/{task_id}")
def analysis_progress(task_id: str):
    from services.ram_analysis import get_analysis_progress
    return get_analysis_progress(task_id)

@ram_analysis_router.post("/pslist")
def pslist(req: PluginRequest):
    from services.ram_analysis import analyze_pslist
    return analyze_pslist(req.dump_path)

@ram_analysis_router.post("/netscan")
def netscan(req: PluginRequest):
    from services.ram_analysis import analyze_netscan
    return analyze_netscan(req.dump_path)

@ram_analysis_router.post("/malfind")
def malfind(req: PluginRequest):
    from services.ram_analysis import analyze_malfind
    return analyze_malfind(req.dump_path)

@ram_analysis_router.post("/dlllist")
def dlllist(req: PluginRequest):
    from services.ram_analysis import analyze_dlllist
    return analyze_dlllist(req.dump_path, req.pid)

@ram_analysis_router.post("/cmdline")
def cmdline(req: PluginRequest):
    from services.ram_analysis import analyze_cmdline
    return analyze_cmdline(req.dump_path)

@ram_analysis_router.get("/volatility/status")
def vol_status():
    from services.ram_analysis import find_volatility
    path = find_volatility()
    return {"available": path is not None, "path": path,
            "note": "Install: pip install volatility3 or download from https://github.com/volatilityfoundation/volatility3"}

# ════════════════════════════════════════════════════════════════════
# DISK IMAGING
# ════════════════════════════════════════════════════════════════════
disk_imaging_router = APIRouter(prefix="/api/disk/imaging", tags=["Disk Imaging"])

class ImagingRequest(BaseModel):
    source: str
    output_name: Optional[str] = None
    fmt: str = "raw"
    block_size: int = 4096
    task_id: Optional[str] = None

class VerifyRequest(BaseModel):
    image_path: str
    expected_sha256: str

@disk_imaging_router.get("/drives")
def list_drives():
    from services.disk_imaging import list_drives
    return list_drives()

@disk_imaging_router.post("/start")
def start_imaging(req: ImagingRequest):
    from services.disk_imaging import start_disk_image
    return start_disk_image(req.source, req.output_name, req.fmt, req.block_size, req.task_id)

@disk_imaging_router.get("/progress/{task_id}")
def imaging_progress(task_id: str):
    from services.disk_imaging import get_imaging_progress
    return get_imaging_progress(task_id)

@disk_imaging_router.get("/list")
def list_disk_images():
    from services.disk_imaging import list_images
    return list_images()

@disk_imaging_router.post("/verify")
def verify_image(req: VerifyRequest):
    from services.disk_imaging import verify_image
    return verify_image(req.image_path, req.expected_sha256)

@disk_imaging_router.post("/upload")
async def upload_image(file: UploadFile = File(...)):
    dest = os.path.join(EVIDENCE_DIR, file.filename)
    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)
    size = os.path.getsize(dest)
    return {"name": file.filename, "path": dest,
            "size_bytes": size, "size_gb": round(size/(1024**3), 3)}

# ════════════════════════════════════════════════════════════════════
# DISK ANALYSIS
# ════════════════════════════════════════════════════════════════════
disk_analysis_router = APIRouter(prefix="/api/disk/analysis", tags=["Disk Analysis"])

class DiskAnalysisRequest(BaseModel):
    image_path: str
    task_id: Optional[str] = None

@disk_analysis_router.post("/start")
def start_disk_analysis(req: DiskAnalysisRequest):
    from services.forensic_analysis import analyze_disk_image
    return analyze_disk_image(req.image_path, req.task_id)

@disk_analysis_router.get("/progress/{task_id}")
def disk_analysis_progress(task_id: str):
    from services.forensic_analysis import get_task_progress
    return get_task_progress(task_id)

@disk_analysis_router.post("/strings")
def extract_strings(req: DiskAnalysisRequest):
    from services.forensic_analysis import _extract_strings
    return {"strings": _extract_strings(req.image_path, limit=1000)}

@disk_analysis_router.post("/entropy")
def file_entropy(req: DiskAnalysisRequest):
    from services.forensic_analysis import _compute_entropy
    return _compute_entropy(req.image_path)

@disk_analysis_router.post("/partitions")
def scan_partitions(req: DiskAnalysisRequest):
    from services.forensic_analysis import _scan_partitions
    return {"partitions": _scan_partitions(req.image_path)}

@disk_analysis_router.post("/header")
def read_header(req: DiskAnalysisRequest):
    from services.forensic_analysis import _read_image_header
    return _read_image_header(req.image_path)

# ════════════════════════════════════════════════════════════════════
# DATA RECOVERY
# ════════════════════════════════════════════════════════════════════
recovery_router = APIRouter(prefix="/api/recovery", tags=["Data Recovery"])

class RecoveryRequest(BaseModel):
    source_path: str
    scan_mode: str = "deep"
    file_types: Optional[List[str]] = None
    task_id: Optional[str] = None

@recovery_router.post("/start")
def start_recovery(req: RecoveryRequest):
    from services.forensic_analysis import start_data_recovery
    return start_data_recovery(req.source_path, None, req.scan_mode, req.file_types, req.task_id)

@recovery_router.get("/progress/{task_id}")
def recovery_progress(task_id: str):
    from services.forensic_analysis import get_task_progress
    return get_task_progress(task_id)

@recovery_router.get("/download/{task_id}")
def download_recovered(task_id: str):
    from services.forensic_analysis import get_task_progress
    progress = get_task_progress(task_id)
    recovered = progress.get("recovered", [])
    return {"files": recovered, "count": len(recovered)}

# ════════════════════════════════════════════════════════════════════
# PARTITION RECOVERY
# ════════════════════════════════════════════════════════════════════
partition_router = APIRouter(prefix="/api/partition", tags=["Partition Recovery"])

class PartitionRequest(BaseModel):
    source_path: str
    task_id: Optional[str] = None

@partition_router.post("/scan")
def scan_partitions(req: PartitionRequest):
    from services.forensic_analysis import start_partition_recovery
    return start_partition_recovery(req.source_path, req.task_id)

@partition_router.get("/progress/{task_id}")
def partition_progress(task_id: str):
    from services.forensic_analysis import get_task_progress
    return get_task_progress(task_id)

# ════════════════════════════════════════════════════════════════════
# REPORTS
# ════════════════════════════════════════════════════════════════════
reports_router = APIRouter(prefix="/api/reports", tags=["Reports"])

class ReportRequest(BaseModel):
    title: str
    case_name: Optional[str] = ""
    examiner: Optional[dict] = {}
    acquisitions: Optional[list] = []
    ram_analysis: Optional[dict] = {}
    disk_analysis: Optional[dict] = {}
    recovery: Optional[dict] = {}
    notes: Optional[str] = ""
    fmt: str = "pdf"

@reports_router.post("/generate")
def generate_report(req: ReportRequest):
    from services.report_service import generate_report
    return generate_report(req.dict(exclude={"fmt"}), req.fmt)

@reports_router.get("/list")
def list_reports():
    from services.report_service import list_reports
    return list_reports()

@reports_router.get("/download/{filename}")
def download_report(filename: str):
    from services.report_service import REPORTS_DIR
    path = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Report not found")
    return FileResponse(path, filename=filename)

# ════════════════════════════════════════════════════════════════════
# UTILITIES
# ════════════════════════════════════════════════════════════════════
utils_router = APIRouter(prefix="/api/utils", tags=["Utilities"])

class HashRequest(BaseModel):
    file_path: str

class HexRequest(BaseModel):
    file_path: str
    offset: int = 0
    length: int = 512

@utils_router.post("/hash")
def hash_file(req: HashRequest):
    import hashlib
    if not os.path.exists(req.file_path):
        raise HTTPException(404, "File not found")
    md5=hashlib.md5(); sha1=hashlib.sha1(); sha256=hashlib.sha256()
    size = os.path.getsize(req.file_path)
    with open(req.file_path,"rb") as f:
        while chunk := f.read(8*1024*1024):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    return {"path": req.file_path, "size_bytes": size,
            "md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}

@utils_router.post("/hex")
def hex_view(req: HexRequest):
    if not os.path.exists(req.file_path):
        raise HTTPException(404, "File not found")
    with open(req.file_path,"rb") as f:
        f.seek(req.offset)
        data = f.read(req.length)
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part  = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        ascii_part= "".join(chr(b) if 0x20<=b<=0x7e else "." for b in chunk)
        lines.append({"offset": f"{req.offset+i:08x}", "hex": hex_part, "ascii": ascii_part})
    return {"lines": lines, "offset": req.offset, "length": len(data)}

@utils_router.post("/strings")
def extract_strings_util(req: HashRequest):
    from services.forensic_analysis import _extract_strings
    if not os.path.exists(req.file_path):
        raise HTTPException(404, "File not found")
    return {"strings": _extract_strings(req.file_path, limit=1000), "path": req.file_path}

@utils_router.post("/entropy")
def entropy_util(req: HashRequest):
    from services.forensic_analysis import _compute_entropy
    if not os.path.exists(req.file_path):
        raise HTTPException(404, "File not found")
    return _compute_entropy(req.file_path)

@utils_router.get("/evidence/list")
def list_evidence():
    from services.disk_imaging import list_images
    from services.ram_capture import list_captures
    return {"images": list_images(), "captures": list_captures()}
