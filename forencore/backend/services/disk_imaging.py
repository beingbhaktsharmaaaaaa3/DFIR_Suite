import os, platform, subprocess, hashlib, datetime, uuid, json, re, threading
from pathlib import Path
import psutil

EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)

_imaging_progress = {}  # task_id -> progress dict

def list_drives() -> list:
    """Detect all physical drives with metadata."""
    drives = []
    system = platform.system()
    
    if system == "Windows":
        drives = _list_drives_windows()
    elif system == "Linux":
        drives = _list_drives_linux()
    else:
        drives = _list_drives_psutil()
    
    return drives

def _list_drives_windows() -> list:
    drives = []
    try:
        # Use WMIC
        result = subprocess.run(
            ["wmic", "diskdrive", "get", "DeviceID,Model,Size,SerialNumber,MediaType", "/format:csv"],
            capture_output=True, text=True, timeout=15
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip() and "DeviceID" not in l and l.strip() != ""]
        for line in lines:
            if not line: continue
            parts = line.split(',')
            if len(parts) >= 4:
                try:
                    size = int(parts[3] or 0)
                    drives.append({
                        "device": parts[1] or "",
                        "model": parts[2] or "Unknown",
                        "size_bytes": size,
                        "size_gb": round(size / (1024**3), 2),
                        "serial": parts[4] if len(parts) > 4 else "",
                        "media_type": parts[5] if len(parts) > 5 else "",
                        "partitions": _get_windows_partitions(parts[1] or "")
                    })
                except Exception:
                    pass
    except Exception:
        drives = _list_drives_psutil()
    return drives

def _get_windows_partitions(device: str) -> list:
    parts = []
    try:
        for p in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(p.mountpoint)
                parts.append({
                    "mountpoint": p.mountpoint,
                    "fstype": p.fstype,
                    "total_gb": round(usage.total / (1024**3), 2),
                    "used_gb": round(usage.used / (1024**3), 2),
                    "free_gb": round(usage.free / (1024**3), 2)
                })
            except Exception:
                pass
    except Exception:
        pass
    return parts

def _list_drives_linux() -> list:
    drives = []
    try:
        result = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,SIZE,MODEL,SERIAL,TYPE,MOUNTPOINT,FSTYPE,RM"],
            capture_output=True, text=True, timeout=10
        )
        data = json.loads(result.stdout)
        for dev in data.get("blockdevices", []):
            if dev.get("type") == "disk":
                size_str = dev.get("size", "0")
                size_bytes = _parse_size(size_str)
                partitions = []
                for child in dev.get("children", []):
                    partitions.append({
                        "name": child.get("name", ""),
                        "size": child.get("size", ""),
                        "fstype": child.get("fstype", ""),
                        "mountpoint": child.get("mountpoint", ""),
                        "removable": child.get("rm", False)
                    })
                drives.append({
                    "device": f"/dev/{dev['name']}",
                    "model": dev.get("model", "Unknown"),
                    "size_str": size_str,
                    "size_bytes": size_bytes,
                    "size_gb": round(size_bytes / (1024**3), 2) if size_bytes else 0,
                    "serial": dev.get("serial", ""),
                    "removable": dev.get("rm", False),
                    "partitions": partitions
                })
    except Exception:
        drives = _list_drives_psutil()
    return drives

def _list_drives_psutil() -> list:
    drives = []
    seen = set()
    for part in psutil.disk_partitions(all=False):
        device = part.device
        if device in seen: continue
        seen.add(device)
        try:
            usage = psutil.disk_usage(part.mountpoint)
            drives.append({
                "device": device,
                "model": "Unknown",
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "size_bytes": usage.total,
                "size_gb": round(usage.total / (1024**3), 2),
                "serial": "",
                "partitions": []
            })
        except Exception:
            drives.append({"device": device, "model": "Unknown", "size_gb": 0, "partitions": []})
    return drives

def _parse_size(s: str) -> int:
    s = s.strip().upper()
    mult = {"B":1,"K":1024,"M":1024**2,"G":1024**3,"T":1024**4}
    try:
        for suffix, factor in mult.items():
            if s.endswith(suffix):
                return int(float(s[:-1]) * factor)
        return int(s)
    except:
        return 0

def start_disk_image(source: str, output_name: str = None, fmt: str = "raw",
                     block_size: int = 4096, task_id: str = None) -> dict:
    if not task_id:
        task_id = str(uuid.uuid4())[:8]
    
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = "dd" if fmt == "raw" else fmt
    fname = output_name or f"disk_{ts}.{ext}"
    out_path = os.path.join(EVIDENCE_DIR, fname)
    
    _imaging_progress[task_id] = {
        "status": "starting", "progress": 0,
        "message": "Preparing disk imaging...",
        "source": source, "dest": out_path,
        "task_id": task_id
    }
    
    threading.Thread(
        target=_do_imaging,
        args=(task_id, source, out_path, fmt, block_size),
        daemon=True
    ).start()
    return {"task_id": task_id, "output_path": out_path, "status": "started"}

def _do_imaging(task_id, source, out_path, fmt, block_size):
    def upd(status, pct, msg):
        _imaging_progress[task_id].update({"status": status, "progress": pct, "message": msg})
    
    try:
        upd("running", 5, f"Opening source: {source}")
        
        # SAFETY: never write back to source
        if os.path.abspath(out_path) == os.path.abspath(source):
            raise RuntimeError("Source and destination cannot be the same!")
        
        system = platform.system()
        
        if system == "Windows":
            _image_windows(task_id, source, out_path, fmt, block_size, upd)
        else:
            _image_linux(task_id, source, out_path, fmt, block_size, upd)
        
        if os.path.exists(out_path):
            upd("hashing", 90, "Computing hashes (this may take a while for large images)...")
            hashes = _hash_file(out_path, task_id)
            size = os.path.getsize(out_path)
            _imaging_progress[task_id].update({
                "status": "completed", "progress": 100,
                "message": "Disk image complete.",
                "hashes": hashes,
                "size_bytes": size,
                "size_gb": round(size / (1024**3), 3),
                "completed_at": datetime.datetime.utcnow().isoformat()
            })
        else:
            upd("failed", 0, "Image file not created.")
    
    except Exception as e:
        _imaging_progress[task_id].update({"status": "failed", "progress": 0, "message": str(e)})

def _image_windows(task_id, source, out_path, fmt, block_size, upd):
    # Try dc3dd, then dd (from UnxUtils/Cygwin), then raw Python read
    dc3dd = _find_tool(["dc3dd", "dc3dd.exe"])
    dd    = _find_tool(["dd", "dd.exe"])
    
    if dc3dd:
        upd("running", 10, f"Using dc3dd: {dc3dd}")
        cmd = [dc3dd, f"if={source}", f"of={out_path}", f"bs={block_size}", "hash=sha256", "log=/tmp/dc3dd.log"]
        _run_imaging_cmd(cmd, task_id, upd)
    elif dd:
        upd("running", 10, f"Using dd: {dd}")
        cmd = [dd, f"if={source}", f"of={out_path}", f"bs={block_size}", "conv=noerror,sync"]
        _run_imaging_cmd(cmd, task_id, upd)
    else:
        upd("running", 10, "No dd/dc3dd found — using Python raw read (read-only, safe)...")
        _python_image(source, out_path, task_id, upd)

def _image_linux(task_id, source, out_path, fmt, block_size, upd):
    dc3dd = _find_tool(["dc3dd"])
    dd    = _find_tool(["dd"])
    
    if dc3dd:
        upd("running", 10, f"Using dc3dd: {dc3dd}")
        cmd = [dc3dd, f"if={source}", f"of={out_path}", f"bs={block_size}", "hash=sha256"]
        _run_imaging_cmd(cmd, task_id, upd)
    elif dd:
        upd("running", 10, f"Using dd: {dd}")
        cmd = ["dd", f"if={source}", f"of={out_path}", f"bs={block_size}", "conv=noerror,sync", "status=progress"]
        _run_imaging_cmd(cmd, task_id, upd)
    else:
        _python_image(source, out_path, task_id, upd)

def _run_imaging_cmd(cmd, task_id, upd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    while True:
        line = proc.stderr.readline()
        if not line and proc.poll() is not None: break
        # Parse dd/dc3dd progress
        m = re.search(r'(\d+)\s+bytes', line)
        if m:
            _imaging_progress[task_id]["bytes_written"] = int(m.group(1))
            upd("running", min(85, _imaging_progress[task_id].get("progress", 10) + 1),
                f"Imaging: {round(int(m.group(1))/(1024**3), 2)} GB written")
    if proc.returncode not in [0, None]:
        err = proc.stderr.read()
        raise RuntimeError(f"Imaging failed: {err[:300]}")

def _python_image(source, out_path, task_id, upd):
    """Pure Python disk/file imaging — read-only, safe."""
    chunk = 4 * 1024 * 1024
    written = 0
    try:
        total = os.path.getsize(source) if os.path.isfile(source) else 0
        with open(source, "rb") as fi, open(out_path, "wb") as fo:
            while True:
                data = fi.read(chunk)
                if not data: break
                fo.write(data)
                written += len(data)
                pct = int((written / total) * 75) + 10 if total else 30
                upd("running", min(pct, 85), f"Imaging: {round(written/(1024**2))} MB written")
    except PermissionError:
        upd("failed", 0, "Permission denied — run as Administrator/root for raw drive access.")
        raise

def _hash_file(path: str, task_id: str = None) -> dict:
    md5 = hashlib.md5(); sha1 = hashlib.sha1(); sha256 = hashlib.sha256()
    size = os.path.getsize(path)
    done = 0
    with open(path, "rb") as f:
        while chunk := f.read(8 * 1024 * 1024):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
            done += len(chunk)
            if task_id:
                pct = 90 + int((done / size) * 9)
                _imaging_progress[task_id]["progress"] = min(pct, 99)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}

def _find_tool(names: list) -> str | None:
    for name in names:
        try:
            result = subprocess.run(["which" if platform.system()!="Windows" else "where", name],
                                    capture_output=True, text=True, timeout=3)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().splitlines()[0]
        except: pass
        if platform.system() == "Windows":
            for p in [r"C:\Tools", r"C:\forensics", os.path.join(os.path.dirname(__file__),"..","..","tools")]:
                fp = os.path.join(p, name if "." in name else name+".exe")
                if os.path.exists(fp): return fp
    return None

def get_imaging_progress(task_id: str) -> dict:
    return _imaging_progress.get(task_id, {"status": "unknown", "progress": 0})

def verify_image(image_path: str, expected_sha256: str) -> dict:
    if not os.path.exists(image_path):
        return {"verified": False, "error": "File not found"}
    actual = _hash_file(image_path)
    match = actual["sha256"].lower() == expected_sha256.lower()
    return {"verified": match, "expected": expected_sha256, "actual": actual["sha256"],
            "hashes": actual}

def list_images() -> list:
    files = []
    for ext in ["*.dd", "*.raw", "*.img", "*.e01", "*.mem", "*.dmp"]:
        for f in Path(EVIDENCE_DIR).glob(ext):
            stat = f.stat()
            files.append({
                "name": f.name, "path": str(f),
                "size_gb": round(stat.st_size/(1024**3), 3),
                "size_bytes": stat.st_size,
                "format": f.suffix.lstrip("."),
                "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
    return sorted(files, key=lambda x: x["modified"], reverse=True)
