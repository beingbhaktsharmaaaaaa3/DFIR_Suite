import os, json, sqlite3, glob, struct
from datetime import datetime
from typing import List, Dict, Any
from sqlalchemy.orm import Session
import models

SUSPICIOUS_REGISTRY_KEYS = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
]

SUSPICIOUS_EXTENSIONS = [".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta", ".scr", ".com"]

MITRE_MAP = {
    "run_key": "T1547.001", "scheduled_task": "T1053.005", "service": "T1543.003",
    "startup": "T1547.001", "browser_history": "T1217", "powershell": "T1059.001",
    "cmd": "T1059.003", "wscript": "T1059.005", "prefetch": "T1204", "lnk": "T1204"
}

class ArtifactCollector:
    def __init__(self, db: Session):
        self.db = db

    def collect(self, evidence: models.Evidence):
        file_path = evidence.file_path
        if not file_path or not os.path.exists(file_path):
            self._collect_live(evidence)
            return
        ext = os.path.splitext(file_path)[1].lower()
        if ext in [".db", ".sqlite"]:
            self._parse_browser_db(evidence, file_path)
        elif ext in [".evtx"]:
            self._parse_evtx(evidence, file_path)
        else:
            self._collect_live(evidence)

    def _collect_live(self, evidence: models.Evidence):
        self._collect_registry(evidence)
        self._collect_browser_history(evidence)
        self._collect_prefetch(evidence)
        self._collect_recent_files(evidence)
        self._collect_scheduled_tasks(evidence)

    def _collect_registry(self, evidence: models.Evidence):
        try:
            import winreg
            run_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            ]
            for hive, key_path in run_keys:
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, data, _ = winreg.EnumValue(key, i)
                            is_suspicious = any(ext in str(data).lower() for ext in [".ps1", ".bat", ".vbs", "temp", "appdata"])
                            artifact = models.Artifact(
                                evidence_id=evidence.id, case_id=evidence.case_id,
                                artifact_type="registry_run", name=name,
                                path=f"{hive}\\{key_path}", raw_value=str(data),
                                data={"hive": str(hive), "key": key_path, "name": name, "value": str(data)},
                                severity=models.SeverityLevel.high if is_suspicious else models.SeverityLevel.info,
                                is_suspicious=is_suspicious, mitre_technique=MITRE_MAP["run_key"]
                            )
                            self.db.add(artifact)
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except Exception:
                    pass
            self.db.commit()
        except ImportError:
            self._add_demo_registry_artifacts(evidence)

    def _collect_browser_history(self, evidence: models.Evidence):
        browser_paths = {
            "chrome": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History"),
            "firefox": os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles"),
            "edge": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History"),
        }
        for browser, path in browser_paths.items():
            if os.path.exists(path):
                if browser == "firefox":
                    for profile in glob.glob(os.path.join(path, "*.default*", "places.sqlite")):
                        self._parse_firefox_history(evidence, profile, browser)
                else:
                    self._parse_chrome_history(evidence, path, browser)

    def _parse_chrome_history(self, evidence: models.Evidence, db_path: str, browser: str):
        import shutil, tempfile
        tmp = tempfile.mktemp(suffix=".db")
        try:
            shutil.copy2(db_path, tmp)
            conn = sqlite3.connect(tmp)
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500")
            for row in cursor.fetchall():
                url, title, count, ts = row
                is_susp = any(kw in str(url).lower() for kw in ["pastebin", "temp", "ngrok", "raw.github", "transfer.sh"])
                artifact = models.Artifact(
                    evidence_id=evidence.id, case_id=evidence.case_id,
                    artifact_type="browser_history", name=title or url,
                    path=url, raw_value=url,
                    data={"browser": browser, "url": url, "title": title or "", "visit_count": count},
                    severity=models.SeverityLevel.high if is_susp else models.SeverityLevel.info,
                    is_suspicious=is_susp, mitre_technique=MITRE_MAP["browser_history"]
                )
                self.db.add(artifact)
            conn.close()
            self.db.commit()
        except Exception:
            pass
        finally:
            if os.path.exists(tmp): os.remove(tmp)

    def _parse_firefox_history(self, evidence: models.Evidence, db_path: str, browser: str):
        import shutil, tempfile
        tmp = tempfile.mktemp(suffix=".db")
        try:
            shutil.copy2(db_path, tmp)
            conn = sqlite3.connect(tmp)
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 500")
            for row in cursor.fetchall():
                url, title, count, ts = row
                is_susp = any(kw in str(url).lower() for kw in ["pastebin", "temp", "ngrok", "raw.github"])
                artifact = models.Artifact(
                    evidence_id=evidence.id, case_id=evidence.case_id,
                    artifact_type="browser_history", name=title or url,
                    path=url, raw_value=url,
                    data={"browser": browser, "url": url, "title": title or "", "visit_count": count or 0},
                    severity=models.SeverityLevel.high if is_susp else models.SeverityLevel.info,
                    is_suspicious=is_susp, mitre_technique=MITRE_MAP["browser_history"]
                )
                self.db.add(artifact)
            conn.close()
            self.db.commit()
        except Exception:
            pass
        finally:
            if os.path.exists(tmp): os.remove(tmp)

    def _collect_prefetch(self, evidence: models.Evidence):
        prefetch_dir = r"C:\Windows\Prefetch"
        if os.path.exists(prefetch_dir):
            for f in os.listdir(prefetch_dir):
                if f.endswith(".pf"):
                    exe_name = f.split("-")[0] if "-" in f else f.replace(".pf", "")
                    mtime = datetime.fromtimestamp(os.path.getmtime(os.path.join(prefetch_dir, f)))
                    is_susp = any(kw in exe_name.lower() for kw in ["powershell", "cmd", "wscript", "mshta", "regsvr"])
                    artifact = models.Artifact(
                        evidence_id=evidence.id, case_id=evidence.case_id,
                        artifact_type="prefetch", name=exe_name,
                        path=os.path.join(prefetch_dir, f), raw_value=f,
                        data={"filename": f, "exe_name": exe_name},
                        timestamp=mtime,
                        severity=models.SeverityLevel.medium if is_susp else models.SeverityLevel.info,
                        is_suspicious=is_susp, mitre_technique=MITRE_MAP["prefetch"]
                    )
                    self.db.add(artifact)
            self.db.commit()

    def _collect_recent_files(self, evidence: models.Evidence):
        recent_dir = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent")
        if os.path.exists(recent_dir):
            for f in os.listdir(recent_dir):
                if f.endswith(".lnk"):
                    mtime = datetime.fromtimestamp(os.path.getmtime(os.path.join(recent_dir, f)))
                    artifact = models.Artifact(
                        evidence_id=evidence.id, case_id=evidence.case_id,
                        artifact_type="recent_file", name=f.replace(".lnk", ""),
                        path=os.path.join(recent_dir, f), raw_value=f,
                        data={"lnk_file": f}, timestamp=mtime,
                        severity=models.SeverityLevel.info, is_suspicious=False,
                        mitre_technique=MITRE_MAP["lnk"]
                    )
                    self.db.add(artifact)
            self.db.commit()

    def _collect_scheduled_tasks(self, evidence: models.Evidence):
        tasks_dir = r"C:\Windows\System32\Tasks"
        if os.path.exists(tasks_dir):
            for root, _, files in os.walk(tasks_dir):
                for f in files:
                    task_path = os.path.join(root, f)
                    try:
                        with open(task_path, "r", errors="ignore") as tf:
                            content = tf.read()
                        is_susp = any(kw in content.lower() for kw in ["powershell", "cmd /c", "wscript", "mshta", "http://", "https://", "temp"])
                        artifact = models.Artifact(
                            evidence_id=evidence.id, case_id=evidence.case_id,
                            artifact_type="scheduled_task", name=f,
                            path=task_path, raw_value=content[:500],
                            data={"task_name": f, "path": task_path},
                            severity=models.SeverityLevel.high if is_susp else models.SeverityLevel.info,
                            is_suspicious=is_susp, mitre_technique=MITRE_MAP["scheduled_task"]
                        )
                        self.db.add(artifact)
                    except Exception:
                        pass
            self.db.commit()

    def _parse_evtx(self, evidence: models.Evidence, file_path: str):
        try:
            from evtx import PyEvtxParser
            parser = PyEvtxParser(file_path)
            for record in parser.records_json():
                data = json.loads(record["data"])
                event = data.get("Event", {})
                system = event.get("System", {})
                event_data = event.get("EventData", {})
                event_id = system.get("EventID", {})
                if isinstance(event_id, dict):
                    event_id = event_id.get("#text", 0)
                ts_str = system.get("TimeCreated", {}).get("@SystemTime", "")
                ts = None
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    except:
                        pass
                suspicious_events = {4624: "Logon", 4625: "Failed Logon", 4648: "Explicit Cred", 4688: "Process Create", 4698: "Task Created", 4720: "User Created", 7045: "Service Install", 1102: "Log Cleared", 4776: "NTLM Auth", 4732: "Group Add"}
                is_susp = int(event_id) in suspicious_events
                artifact = models.Artifact(
                    evidence_id=evidence.id, case_id=evidence.case_id,
                    artifact_type="event_log", name=f"EventID {event_id}: {suspicious_events.get(int(event_id), 'Event')}",
                    path=file_path, raw_value=json.dumps(event_data)[:500],
                    data={"event_id": event_id, "channel": system.get("Channel", ""), "computer": system.get("Computer", ""), "event_data": event_data},
                    timestamp=ts,
                    severity=models.SeverityLevel.high if is_susp else models.SeverityLevel.info,
                    is_suspicious=is_susp
                )
                self.db.add(artifact)
            self.db.commit()
        except Exception as e:
            pass

    def _parse_browser_db(self, evidence: models.Evidence, db_path: str):
        self._parse_chrome_history(evidence, db_path, "unknown")

    def _add_demo_registry_artifacts(self, evidence: models.Evidence):
        demo_items = [
            ("SecurityHealth", r"C:\Windows\System32\SecurityHealthSystray.exe", False),
            ("OneDrive", r"C:\Users\User\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background", False),
            ("SuspiciousRAT", r"C:\Users\User\AppData\Roaming\Temp\svchost32.exe -connect 192.168.1.100:4444", True),
        ]
        for name, value, susp in demo_items:
            artifact = models.Artifact(
                evidence_id=evidence.id, case_id=evidence.case_id,
                artifact_type="registry_run", name=name,
                path=r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                raw_value=value,
                data={"name": name, "value": value},
                severity=models.SeverityLevel.critical if susp else models.SeverityLevel.info,
                is_suspicious=susp, mitre_technique=MITRE_MAP["run_key"]
            )
            self.db.add(artifact)
        self.db.commit()
