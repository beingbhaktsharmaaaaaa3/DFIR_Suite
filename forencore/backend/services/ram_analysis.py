import os, subprocess, json, platform, datetime, re, hashlib, uuid, psutil
from pathlib import Path
from typing import Optional

_analysis_progress = {}   # task_id -> result

VOLATILITY_CANDIDATES = [
    "vol", "vol.py", "volatility3", "python3 vol.py",
    os.path.join(os.path.dirname(__file__), "..", "..", "tools", "vol.py"),
    r"C:\Tools\volatility3\vol.py",
    "/opt/volatility3/vol.py",
    "/usr/local/bin/vol",
]

def find_volatility() -> Optional[str]:
    for v in VOLATILITY_CANDIDATES:
        try:
            parts = v.split()
            result = subprocess.run(parts + ["--help"], capture_output=True, timeout=5)
            if result.returncode in [0, 1, 2]:
                return v
        except Exception:
            continue
    return None

def run_vol_plugin(dump_path: str, plugin: str, extra_args: list = None) -> dict:
    """Run a Volatility 3 plugin and return parsed JSON output."""
    vol = find_volatility()
    if not vol:
        return {"error": "volatility3_not_found", "data": [], "fallback": True}
    
    cmd = vol.split() + ["-f", dump_path, plugin, "-r", "json"]
    if extra_args:
        cmd += extra_args
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        stdout = result.stdout.strip()
        
        # Vol3 outputs JSON wrapped in extra info sometimes
        json_start = stdout.find('[')
        if json_start == -1:
            json_start = stdout.find('{')
        if json_start != -1:
            try:
                data = json.loads(stdout[json_start:])
                if isinstance(data, dict) and "rows" in data:
                    return {"data": data["rows"], "columns": data.get("columns", []), "plugin": plugin}
                if isinstance(data, list):
                    return {"data": data, "plugin": plugin}
            except Exception:
                pass
        
        return {"error": result.stderr[:500] if result.stderr else "No output", "data": [], "plugin": plugin}
    except subprocess.TimeoutExpired:
        return {"error": "Plugin timed out (>5 min)", "data": [], "plugin": plugin}
    except Exception as e:
        return {"error": str(e), "data": [], "plugin": plugin}

def analyze_pslist(dump_path: str) -> dict:
    result = run_vol_plugin(dump_path, "windows.pslist.PsList")
    if result.get("fallback"):
        return _live_pslist_fallback()
    
    processes = []
    suspicious = []
    SUSPICIOUS_NAMES = {"lsass.exe":1, "svchost.exe":1, "csrss.exe":1, "winlogon.exe":1, "services.exe":1}
    MALWARE_INDICATORS = ["temp", "appdata\\roaming", "recycle", "tmp", ".$$$"]
    
    for row in result.get("data", []):
        # Vol3 pslist columns: PID, PPID, ImageFileName, Offset, Threads, Handles, SessionId, Wow64, CreateTime, ExitTime
        proc = {}
        if isinstance(row, list):
            cols = result.get("columns", ["PID","PPID","ImageFileName","Offset","Threads","Handles","SessionId","Wow64","CreateTime","ExitTime"])
            proc = dict(zip(cols, row))
        elif isinstance(row, dict):
            proc = row
        
        name = str(proc.get("ImageFileName", proc.get("name", ""))).lower()
        pid  = proc.get("PID", proc.get("pid", 0))
        ppid = proc.get("PPID", proc.get("ppid", 0))
        
        is_suspicious = False
        sus_reasons = []
        if any(ind in name for ind in MALWARE_INDICATORS):
            is_suspicious = True; sus_reasons.append("Suspicious path")
        if name in SUSPICIOUS_NAMES and ppid not in [0, 4]:
            is_suspicious = True; sus_reasons.append("Unexpected parent")
        
        entry = {
            "pid": pid, "ppid": ppid,
            "name": str(proc.get("ImageFileName", proc.get("name", "unknown"))),
            "threads": proc.get("Threads", proc.get("threads", 0)),
            "handles": proc.get("Handles", proc.get("handles", 0)),
            "session": proc.get("SessionId", proc.get("session", 0)),
            "create_time": str(proc.get("CreateTime", proc.get("create_time", ""))),
            "is_suspicious": is_suspicious,
            "suspicious_reasons": sus_reasons
        }
        processes.append(entry)
        if is_suspicious:
            suspicious.append(entry)
    
    return {"processes": processes, "total": len(processes), "suspicious": suspicious, "plugin": "pslist"}

def _live_pslist_fallback() -> dict:
    """Use psutil when Volatility is not available."""
    processes = []
    suspicious = []
    SUSPICIOUS_INDICATORS = ["temp", "tmp", "appdata\\roaming\\", "recycle"]
    
    for proc in psutil.process_iter(['pid','ppid','name','num_threads','create_time','status','exe']):
        try:
            exe = (proc.info.get('exe') or "").lower()
            name = proc.info.get('name', 'unknown')
            is_susp = any(ind in exe for ind in SUSPICIOUS_INDICATORS)
            entry = {
                "pid": proc.info['pid'],
                "ppid": proc.info['ppid'],
                "name": name,
                "threads": proc.info.get('num_threads', 0),
                "handles": 0,
                "session": 0,
                "exe": proc.info.get('exe', ''),
                "create_time": datetime.datetime.fromtimestamp(proc.info['create_time']).isoformat() if proc.info.get('create_time') else '',
                "is_suspicious": is_susp,
                "suspicious_reasons": ["Suspicious path"] if is_susp else [],
                "source": "live_system"
            }
            processes.append(entry)
            if is_susp: suspicious.append(entry)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    return {
        "processes": processes,
        "total": len(processes),
        "suspicious": suspicious,
        "plugin": "pslist_live",
        "note": "Live system data — Volatility 3 not found. Load a memory dump for full analysis."
    }

def analyze_netscan(dump_path: str) -> dict:
    result = run_vol_plugin(dump_path, "windows.netstat.NetStat")
    if result.get("fallback"):
        return _live_netscan_fallback()
    
    connections = []
    SUSPICIOUS_PORTS = {4444, 1337, 8080, 31337, 9001, 6667, 6666, 443, 80}
    
    for row in result.get("data", []):
        conn = row if isinstance(row, dict) else dict(zip(
            result.get("columns", ["Offset","Proto","LocalAddr","LocalPort","ForeignAddr","ForeignPort","State","PID","Owner","Created"]),
            row
        ))
        local_port  = int(conn.get("LocalPort",  0) or 0)
        remote_port = int(conn.get("ForeignPort", 0) or 0)
        is_susp = remote_port in SUSPICIOUS_PORTS or local_port in SUSPICIOUS_PORTS
        entry = {
            "proto": conn.get("Proto", ""),
            "local_addr": str(conn.get("LocalAddr", "")),
            "local_port": local_port,
            "remote_addr": str(conn.get("ForeignAddr", "")),
            "remote_port": remote_port,
            "state": str(conn.get("State", "")),
            "pid": conn.get("PID", 0),
            "owner": str(conn.get("Owner", "")),
            "is_suspicious": is_susp
        }
        connections.append(entry)
    
    return {"connections": connections, "total": len(connections), "plugin": "netscan"}

def _live_netscan_fallback() -> dict:
    connections = []
    SUSPICIOUS_PORTS = {4444, 1337, 8080, 31337, 9001, 6667}
    for conn in psutil.net_connections(kind='all'):
        try:
            laddr = conn.laddr; raddr = conn.raddr
            rport = raddr.port if raddr else 0
            lport = laddr.port if laddr else 0
            proc_name = ""
            if conn.pid:
                try: proc_name = psutil.Process(conn.pid).name()
                except: pass
            entry = {
                "proto": "TCP" if conn.type == 1 else "UDP",
                "local_addr": laddr.ip if laddr else "",
                "local_port": lport,
                "remote_addr": raddr.ip if raddr else "",
                "remote_port": rport,
                "state": conn.status or "NONE",
                "pid": conn.pid or 0,
                "owner": proc_name,
                "is_suspicious": rport in SUSPICIOUS_PORTS,
                "source": "live_system"
            }
            connections.append(entry)
        except Exception:
            pass
    return {"connections": connections, "total": len(connections), "plugin": "netscan_live",
            "note": "Live system data — install Volatility 3 for memory dump analysis."}

def analyze_malfind(dump_path: str) -> dict:
    result = run_vol_plugin(dump_path, "windows.malfind.Malfind")
    if result.get("fallback"):
        return {"findings": [], "total": 0, "plugin": "malfind",
                "note": "Volatility 3 required for malfind. Point to a real memory dump."}
    findings = []
    for row in result.get("data", []):
        entry = row if isinstance(row, dict) else dict(zip(
            result.get("columns", ["PID","Process","Start_VPN","End_VPN","Tag","Protection","CommitCharge","PrivateMemory","File_output","Hexdump","Disasm"]),
            row
        ))
        findings.append({
            "pid": entry.get("PID", 0),
            "process": entry.get("Process", ""),
            "start_vpn": str(entry.get("Start_VPN", "")),
            "end_vpn": str(entry.get("End_VPN", "")),
            "protection": str(entry.get("Protection", "")),
            "hexdump": str(entry.get("Hexdump", ""))[:200],
            "disasm": str(entry.get("Disasm", ""))[:300],
            "severity": "critical"
        })
    return {"findings": findings, "total": len(findings), "plugin": "malfind"}

def analyze_dlllist(dump_path: str, pid: int = None) -> dict:
    extra = ["--pid", str(pid)] if pid else []
    result = run_vol_plugin(dump_path, "windows.dlllist.DllList", extra)
    if result.get("fallback"):
        return {"dlls": [], "total": 0, "plugin": "dlllist",
                "note": "Volatility 3 required for DLL analysis."}
    dlls = []
    SUSPICIOUS_PATHS = ["temp", "tmp", "appdata\\roaming", "recycle", "public"]
    for row in result.get("data", []):
        entry = row if isinstance(row, dict) else dict(zip(
            result.get("columns", ["PID","Process","Base","Size","Name","Path","LoadTime","File_output"]),
            row
        ))
        path = str(entry.get("Path", "")).lower()
        is_susp = any(p in path for p in SUSPICIOUS_PATHS)
        dlls.append({
            "pid": entry.get("PID", 0),
            "process": entry.get("Process", ""),
            "name": entry.get("Name", ""),
            "path": entry.get("Path", ""),
            "base": str(entry.get("Base", "")),
            "size": entry.get("Size", 0),
            "is_suspicious": is_susp
        })
    return {"dlls": dlls, "total": len(dlls), "plugin": "dlllist"}

def analyze_cmdline(dump_path: str) -> dict:
    result = run_vol_plugin(dump_path, "windows.cmdline.CmdLine")
    if result.get("fallback"):
        return _live_cmdline_fallback()
    cmds = []
    SUSPICIOUS_PATTERNS = ["-enc", "-encodedcommand", "bypass", "hidden", "iex", "invoke-expression", "downloadstring", "webclient"]
    for row in result.get("data", []):
        entry = row if isinstance(row, dict) else dict(zip(
            result.get("columns", ["PID","Process","Args"]),
            row
        ))
        args = str(entry.get("Args", "")).lower()
        is_susp = any(p in args for p in SUSPICIOUS_PATTERNS)
        cmds.append({
            "pid": entry.get("PID", 0),
            "process": entry.get("Process", ""),
            "cmdline": str(entry.get("Args", "")),
            "is_suspicious": is_susp
        })
    return {"commands": cmds, "total": len(cmds), "plugin": "cmdline"}

def _live_cmdline_fallback() -> dict:
    cmds = []
    SUSPICIOUS = ["-enc", "bypass", "hidden", "downloadstring", "iex"]
    for proc in psutil.process_iter(['pid','name','cmdline']):
        try:
            cl = " ".join(proc.info.get('cmdline') or [])
            is_susp = any(p in cl.lower() for p in SUSPICIOUS)
            cmds.append({"pid": proc.info['pid'], "process": proc.info['name'],
                         "cmdline": cl, "is_suspicious": is_susp, "source": "live_system"})
        except Exception:
            pass
    return {"commands": cmds, "total": len(cmds), "plugin": "cmdline_live",
            "note": "Live system data."}

def run_full_analysis(dump_path: str, task_id: str = None) -> dict:
    if not task_id:
        task_id = str(uuid.uuid4())[:8]
    _analysis_progress[task_id] = {"status": "running", "progress": 0, "results": {}}
    
    import threading
    def _run():
        steps = [
            ("pslist",   lambda: analyze_pslist(dump_path),   20),
            ("netscan",  lambda: analyze_netscan(dump_path),  40),
            ("malfind",  lambda: analyze_malfind(dump_path),  60),
            ("dlllist",  lambda: analyze_dlllist(dump_path),  80),
            ("cmdline",  lambda: analyze_cmdline(dump_path),  95),
        ]
        results = {}
        for name, fn, pct in steps:
            _analysis_progress[task_id].update({"progress": pct - 15, "message": f"Running {name}..."})
            try:
                results[name] = fn()
            except Exception as e:
                results[name] = {"error": str(e), "data": []}
            _analysis_progress[task_id].update({"progress": pct})
        
        _analysis_progress[task_id].update({
            "status": "completed", "progress": 100,
            "results": results,
            "message": "Analysis complete",
            "completed_at": datetime.datetime.utcnow().isoformat()
        })
    
    threading.Thread(target=_run, daemon=True).start()
    return {"task_id": task_id, "status": "started"}

def get_analysis_progress(task_id: str) -> dict:
    return _analysis_progress.get(task_id, {"status": "unknown"})
