import os, platform, subprocess, json, datetime, uuid, threading, hashlib, struct, re
from pathlib import Path
from typing import Optional

EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "evidence")
RECOVERY_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "recovered")
os.makedirs(EVIDENCE_DIR, exist_ok=True)
os.makedirs(RECOVERY_DIR, exist_ok=True)

_task_progress = {}

# ── FILE SIGNATURES for carving ──────────────────────────────────────
FILE_SIGNATURES = {
    "jpg":  (b"\xff\xd8\xff", b"\xff\xd9"),
    "png":  (b"\x89PNG\r\n\x1a\n", None),
    "pdf":  (b"%PDF-", b"%%EOF"),
    "zip":  (b"PK\x03\x04", b"PK\x05\x06"),
    "docx": (b"PK\x03\x04", None),
    "exe":  (b"MZ", None),
    "mp4":  (b"\x00\x00\x00\x18ftyp", None),
    "gif":  (b"GIF8", b"\x00;"),
    "bmp":  (b"BM", None),
    "rar":  (b"Rar!\x1a\x07", None),
    "7z":   (b"7z\xbc\xaf\x27\x1c", None),
    "sqlite": (b"SQLite format 3", None),
    "xml":  (b"<?xml", None),
    "html": (b"<!DOCTYPE html", None),
}

# ═══════════════════════════════════════════════════════════════════
# DISK ANALYSIS
# ═══════════════════════════════════════════════════════════════════
def analyze_disk_image(image_path: str, task_id: str = None) -> dict:
    if not task_id:
        task_id = str(uuid.uuid4())[:8]
    _task_progress[task_id] = {"status": "starting", "progress": 0, "results": {}}
    threading.Thread(target=_run_disk_analysis, args=(task_id, image_path), daemon=True).start()
    return {"task_id": task_id, "status": "started"}

def _run_disk_analysis(task_id, image_path):
    def upd(pct, msg): _task_progress[task_id].update({"progress": pct, "message": msg, "status": "running"})
    results = {}
    try:
        upd(5,  "Reading image header...")
        results["header"]     = _read_image_header(image_path)
        upd(20, "Scanning partitions...")
        results["partitions"] = _scan_partitions(image_path)
        upd(40, "Extracting file system info...")
        results["filesystem"] = _get_filesystem_info(image_path)
        upd(60, "Scanning for deleted files...")
        results["deleted"]    = _find_deleted_files(image_path)
        upd(75, "Extracting strings...")
        results["strings"]    = _extract_strings(image_path, limit=500)
        upd(85, "Computing file entropy...")
        results["entropy"]    = _compute_entropy(image_path)
        upd(95, "Building file list...")
        results["files"]      = _list_image_files(image_path)
        _task_progress[task_id].update({
            "status": "completed", "progress": 100,
            "results": results, "message": "Analysis complete",
            "completed_at": datetime.datetime.utcnow().isoformat()
        })
    except Exception as e:
        _task_progress[task_id].update({"status": "failed", "progress": 0, "message": str(e)})

def _read_image_header(path: str) -> dict:
    info = {"path": path, "size_bytes": os.path.getsize(path),
            "size_gb": round(os.path.getsize(path)/(1024**3), 3)}
    try:
        with open(path, "rb") as f:
            header = f.read(512)
        # Check MBR signature
        if len(header) >= 512:
            mbr_sig = header[510:512]
            info["mbr_signature"] = mbr_sig.hex()
            info["has_mbr"] = mbr_sig == b"\x55\xaa"
        # Check common filesystem signatures
        for fs, sig in [("NTFS", b"NTFS    "), ("FAT32", b"FAT32   "), ("FAT16", b"FAT16   ")]:
            if sig in header:
                info["filesystem_hint"] = fs
        info["header_hex"] = header[:64].hex()
    except Exception as e:
        info["error"] = str(e)
    return info

def _scan_partitions(path: str) -> list:
    partitions = []
    # Try pytsk3 first
    try:
        import pytsk3
        img = pytsk3.Img_Info(path)
        vol = pytsk3.Volume_Info(img)
        for part in vol:
            partitions.append({
                "addr": part.addr,
                "start": part.start,
                "length": part.len,
                "desc": part.desc.decode(errors="replace").strip(),
                "size_mb": round((part.len * 512) / (1024**2), 2)
            })
        return partitions
    except Exception:
        pass
    # Manual MBR partition table parse
    try:
        with open(path, "rb") as f:
            mbr = f.read(512)
        if len(mbr) < 512 or mbr[510:512] != b"\x55\xaa":
            return [{"desc": "No valid MBR found", "start": 0, "length": 0}]
        for i in range(4):
            offset = 446 + (i * 16)
            entry = mbr[offset:offset+16]
            if len(entry) < 16: continue
            ptype = entry[4]
            if ptype == 0: continue
            start_lba  = struct.unpack_from("<I", entry, 8)[0]
            size_lba   = struct.unpack_from("<I", entry, 12)[0]
            fs_types = {0x07:"NTFS", 0x0b:"FAT32", 0x0c:"FAT32(LBA)", 0x83:"Linux ext",
                        0x82:"Linux swap", 0x05:"Extended", 0x0f:"Extended(LBA)", 0x27:"WinRE"}
            partitions.append({
                "index": i+1, "type": ptype, "type_name": fs_types.get(ptype, f"0x{ptype:02x}"),
                "start_lba": start_lba, "size_lba": size_lba,
                "start_bytes": start_lba * 512,
                "size_mb": round((size_lba * 512) / (1024**2), 2),
                "bootable": entry[0] == 0x80
            })
    except Exception as e:
        partitions.append({"error": str(e)})
    return partitions

def _get_filesystem_info(path: str) -> dict:
    try:
        import pytsk3
        img = pytsk3.Img_Info(path)
        fs  = pytsk3.FS_Info(img)
        return {
            "type": str(fs.info.ftype),
            "block_size": fs.info.block_size,
            "block_count": fs.info.block_count,
            "root_inum": fs.info.root_inum
        }
    except Exception:
        pass
    return {"note": "Install pytsk3 for full filesystem analysis. pip install pytsk3"}

def _find_deleted_files(path: str) -> list:
    deleted = []
    try:
        import pytsk3
        img = pytsk3.Img_Info(path)
        fs  = pytsk3.FS_Info(img)
        dir_ = fs.open_dir(path="/")
        for entry in dir_:
            if entry.info.meta and entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                name = entry.info.name.name.decode(errors="replace")
                deleted.append({
                    "name": name,
                    "size": entry.info.meta.size,
                    "type": str(entry.info.meta.type),
                    "status": "deleted"
                })
    except Exception:
        pass
    return deleted[:200]

def _extract_strings(path: str, min_len: int = 6, limit: int = 500) -> list:
    strings = []
    try:
        with open(path, "rb") as f:
            data = f.read(min(10 * 1024 * 1024, os.path.getsize(path)))  # first 10MB
        current = []
        for byte in data:
            if 0x20 <= byte <= 0x7e:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    s = "".join(current)
                    if not s.isspace():
                        strings.append(s)
                        if len(strings) >= limit: break
                current = []
    except Exception:
        pass
    return strings

def _compute_entropy(path: str) -> dict:
    """Compute file entropy (high entropy = encrypted/compressed/packed)."""
    import math
    try:
        with open(path, "rb") as f:
            data = f.read(min(5 * 1024 * 1024, os.path.getsize(path)))
        if not data: return {"entropy": 0, "interpretation": "empty"}
        freq = [0] * 256
        for b in data: freq[b] += 1
        length = len(data)
        entropy = -sum((f/length)*math.log2(f/length) for f in freq if f > 0)
        interp = "low (plain text/structured)" if entropy < 4 else \
                 "medium (mixed content)" if entropy < 7 else \
                 "high (encrypted/compressed/packed)"
        return {"entropy": round(entropy, 4), "interpretation": interp, "scale": "0-8 bits"}
    except Exception as e:
        return {"error": str(e)}

def _list_image_files(path: str) -> list:
    files = []
    try:
        import pytsk3
        img = pytsk3.Img_Info(path)
        fs  = pytsk3.FS_Info(img)
        _walk_fs(fs, fs.open_dir(path="/"), "/", files, limit=1000)
    except Exception:
        pass
    return files[:1000]

def _walk_fs(fs, directory, path, results, depth=0, limit=1000):
    if depth > 5 or len(results) >= limit: return
    for entry in directory:
        try:
            name = entry.info.name.name.decode(errors="replace")
            if name in [".", ".."]: continue
            meta = entry.info.meta
            if meta:
                results.append({
                    "name": name,
                    "path": path + name,
                    "size": meta.size,
                    "type": "dir" if str(meta.type) == "TSK_FS_META_TYPE_DIR" else "file",
                    "deleted": bool(meta.flags & 2),
                    "mtime": meta.mtime
                })
                if str(meta.type) == "TSK_FS_META_TYPE_DIR" and not (meta.flags & 2):
                    try:
                        sub = fs.open_dir(inode=meta.addr)
                        _walk_fs(fs, sub, path+name+"/", results, depth+1, limit)
                    except: pass
        except: pass

# ═══════════════════════════════════════════════════════════════════
# DATA RECOVERY (File Carving)
# ═══════════════════════════════════════════════════════════════════
def start_data_recovery(source_path: str, output_dir: str = None,
                         scan_mode: str = "deep", file_types: list = None,
                         task_id: str = None) -> dict:
    if not task_id:
        task_id = str(uuid.uuid4())[:8]
    out_dir = output_dir or os.path.join(RECOVERY_DIR, f"recovery_{task_id}")
    os.makedirs(out_dir, exist_ok=True)
    _task_progress[task_id] = {"status": "starting", "progress": 0, "recovered": [], "task_id": task_id}
    threading.Thread(
        target=_run_recovery,
        args=(task_id, source_path, out_dir, scan_mode, file_types),
        daemon=True
    ).start()
    return {"task_id": task_id, "output_dir": out_dir, "status": "started"}

def _run_recovery(task_id, source_path, out_dir, scan_mode, file_types):
    def upd(pct, msg, count=0):
        _task_progress[task_id].update({"progress": pct, "message": msg, "status": "running",
                                         "recovered_count": count})
    try:
        # Try PhotoRec first
        photorec = _find_photorec()
        if photorec:
            upd(5, f"Using PhotoRec: {photorec}")
            _run_photorec(task_id, source_path, out_dir, photorec, upd)
        else:
            upd(5, "PhotoRec not found — using built-in file carver...")
            _carve_files(task_id, source_path, out_dir, file_types, upd)
        
        # Collect results
        recovered = []
        for root, dirs, files in os.walk(out_dir):
            for f in files:
                fp = os.path.join(root, f)
                size = os.path.getsize(fp)
                recovered.append({
                    "name": f, "path": fp, "size_bytes": size,
                    "size_kb": round(size/1024, 1),
                    "type": Path(f).suffix.lstrip(".").upper() or "UNKNOWN",
                    "quality": "good" if size > 512 else "partial"
                })
        
        _task_progress[task_id].update({
            "status": "completed", "progress": 100,
            "recovered": recovered, "recovered_count": len(recovered),
            "message": f"Recovery complete. Found {len(recovered)} files.",
            "completed_at": datetime.datetime.utcnow().isoformat()
        })
    except Exception as e:
        _task_progress[task_id].update({"status": "failed", "message": str(e)})

def _find_photorec() -> Optional[str]:
    for name in ["photorec", "photorec_static", "photorec.exe"]:
        try:
            r = subprocess.run(["which" if platform.system()!="Windows" else "where", name],
                               capture_output=True, text=True, timeout=3)
            if r.returncode == 0: return r.stdout.strip().splitlines()[0]
        except: pass
        for p in ["/usr/bin", "/usr/local/bin", r"C:\Tools"]:
            fp = os.path.join(p, name)
            if os.path.exists(fp): return fp
    return None

def _run_photorec(task_id, source, out_dir, photorec_path, upd):
    cmd = [photorec_path, "/d", out_dir, "/cmd", source, "fileopt,enable,everything,search"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        upd(30, "PhotoRec scanning...")
        proc.wait(timeout=600)
        upd(90, "PhotoRec scan complete.")
    except Exception as e:
        upd(10, f"PhotoRec failed: {e} — falling back to built-in carver...")
        _carve_files(task_id, source, out_dir, None, upd)

def _carve_files(task_id, source_path, out_dir, file_types, upd):
    """Built-in file signature carver."""
    types_to_carve = {k: v for k, v in FILE_SIGNATURES.items()
                      if not file_types or k in file_types}
    upd(10, f"Scanning for {len(types_to_carve)} file type signatures...")
    
    chunk_size = 4 * 1024 * 1024  # 4MB chunks
    total_size = os.path.getsize(source_path)
    offset = 0
    found = []
    
    with open(source_path, "rb") as f:
        while offset < total_size:
            chunk = f.read(chunk_size)
            if not chunk: break
            
            for ext, (header, footer) in types_to_carve.items():
                pos = 0
                while True:
                    idx = chunk.find(header, pos)
                    if idx == -1: break
                    abs_offset = offset + idx
                    # Extract up to 50MB per file
                    max_size = min(50 * 1024 * 1024, total_size - abs_offset)
                    found.append((abs_offset, ext, max_size))
                    pos = idx + 1
            
            offset += len(chunk)
            pct = int((offset / total_size) * 70) + 10
            upd(pct, f"Scanning: {round(offset/(1024**2))} MB / {round(total_size/(1024**2))} MB — found {len(found)} signatures")
    
    upd(80, f"Extracting {len(found)} files...")
    extracted = 0
    with open(source_path, "rb") as f:
        for abs_offset, ext, max_size in found[:500]:  # limit to 500 files
            f.seek(abs_offset)
            data = f.read(min(max_size, 10 * 1024 * 1024))
            if data:
                out_file = os.path.join(out_dir, f"recovered_{abs_offset:016x}.{ext}")
                with open(out_file, "wb") as of:
                    of.write(data)
                extracted += 1
                upd(80 + int((extracted/max(len(found),1))*15), f"Extracted {extracted} files...", extracted)
    
    upd(97, f"Extracted {extracted} files from carving.")

# ═══════════════════════════════════════════════════════════════════
# PARTITION RECOVERY
# ═══════════════════════════════════════════════════════════════════
def start_partition_recovery(source_path: str, task_id: str = None) -> dict:
    if not task_id:
        task_id = str(uuid.uuid4())[:8]
    _task_progress[task_id] = {"status": "starting", "progress": 0, "task_id": task_id}
    threading.Thread(
        target=_run_partition_scan,
        args=(task_id, source_path),
        daemon=True
    ).start()
    return {"task_id": task_id, "status": "started"}

def _run_partition_scan(task_id, source_path):
    def upd(pct, msg): _task_progress[task_id].update({"progress": pct, "message": msg, "status": "running"})
    try:
        # Try TestDisk
        testdisk = _find_testdisk()
        partitions = []
        
        if testdisk:
            upd(10, f"Using TestDisk: {testdisk}")
            partitions = _run_testdisk(source_path, testdisk, upd)
        
        # Always also do manual scan
        upd(50, "Scanning for partition signatures...")
        manual_parts = _manual_partition_scan(source_path)
        
        # Merge results
        all_parts = partitions + [p for p in manual_parts
                                  if not any(abs(p.get("start_lba",0) - q.get("start_lba",0)) < 100 for q in partitions)]
        
        upd(90, "Analyzing found partitions...")
        for p in all_parts:
            p["status"] = "found"
            if p.get("size_mb", 0) > 0:
                p["recoverable"] = True
        
        _task_progress[task_id].update({
            "status": "completed", "progress": 100,
            "partitions": all_parts, "count": len(all_parts),
            "message": f"Found {len(all_parts)} partition(s).",
            "completed_at": datetime.datetime.utcnow().isoformat()
        })
    except Exception as e:
        _task_progress[task_id].update({"status": "failed", "message": str(e)})

def _find_testdisk() -> Optional[str]:
    for name in ["testdisk", "testdisk_static", "testdisk.exe"]:
        try:
            r = subprocess.run(["which" if platform.system()!="Windows" else "where", name],
                               capture_output=True, text=True, timeout=3)
            if r.returncode == 0: return r.stdout.strip().splitlines()[0]
        except: pass
    return None

def _run_testdisk(source_path, testdisk_path, upd) -> list:
    parts = []
    try:
        cmd = [testdisk_path, "/list", source_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout + result.stderr
        # Parse testdisk output
        for line in output.splitlines():
            m = re.search(r'(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\w+)', line)
            if m:
                parts.append({
                    "start_lba": int(m.group(1)),
                    "end_lba": int(m.group(4)),
                    "size_lba": int(m.group(4)) - int(m.group(1)),
                    "size_mb": round(((int(m.group(4)) - int(m.group(1))) * 512) / (1024**2), 1),
                    "filesystem": m.group(6),
                    "source": "testdisk"
                })
    except Exception:
        pass
    return parts

def _manual_partition_scan(path: str) -> list:
    """Scan for partition boot record signatures."""
    partitions = []
    FS_SIGNATURES = {
        b"NTFS    ": "NTFS",
        b"FAT32   ": "FAT32",
        b"FAT16   ": "FAT16",
        b"\x53\xef": "EXT2/3/4",  # EXT superblock magic at offset 56
    }
    sector_size = 512
    scan_size = min(os.path.getsize(path), 500 * 1024 * 1024)  # first 500MB
    
    try:
        with open(path, "rb") as f:
            sector = 0
            while sector * sector_size < scan_size:
                f.seek(sector * sector_size)
                data = f.read(sector_size)
                if len(data) < 512: break
                for sig, fs_name in FS_SIGNATURES.items():
                    if sig in data[:128]:
                        partitions.append({
                            "start_lba": sector,
                            "start_bytes": sector * sector_size,
                            "filesystem": fs_name,
                            "size_mb": 0,
                            "source": "signature_scan",
                            "sector": sector
                        })
                        break
                sector += 2048  # scan every 2048 sectors (1MB)
    except Exception:
        pass
    
    return partitions

# ═══════════════════════════════════════════════════════════════════
# SHARED
# ═══════════════════════════════════════════════════════════════════
def get_task_progress(task_id: str) -> dict:
    return _task_progress.get(task_id, {"status": "unknown", "progress": 0})
