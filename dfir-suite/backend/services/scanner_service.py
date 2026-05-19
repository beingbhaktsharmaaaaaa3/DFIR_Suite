import os, re, hashlib
from datetime import datetime
from sqlalchemy.orm import Session
import models

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "yara_rules")
SIGMA_DIR = os.path.join(os.path.dirname(__file__), "..", "sigma_rules")

class YaraScanner:
    def __init__(self, db: Session):
        self.db = db

    def scan_evidence(self, evidence_id: int, rules_dir: str = None):
        evidence = self.db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
        if not evidence or not evidence.file_path or not os.path.exists(evidence.file_path):
            return 0
        rules_path = rules_dir or RULES_DIR
        if not os.path.exists(rules_path):
            return 0
        hits = 0
        try:
            import yara
            rule_files = [f for f in os.listdir(rules_path) if f.endswith((".yar", ".yara"))]
            for rule_file in rule_files:
                try:
                    rules = yara.compile(filepath=os.path.join(rules_path, rule_file))
                    matches = rules.match(evidence.file_path)
                    for match in matches:
                        severity = self._map_severity(match.meta.get("severity", "medium"))
                        result = models.ScanResult(
                            evidence_id=evidence_id,
                            case_id=evidence.case_id,
                            scanner_type="yara",
                            rule_name=match.rule,
                            rule_file=rule_file,
                            matched_strings=[str(s) for s in match.strings],
                            severity=severity,
                            file_path=evidence.file_path,
                            description=match.meta.get("description", ""),
                            mitre_technique=match.meta.get("mitre_attack", ""),
                            raw_output=str(match)
                        )
                        self.db.add(result)
                        hits += 1
                except Exception:
                    pass
            self.db.commit()
        except ImportError:
            hits = self._demo_yara_scan(evidence)
        return hits

    def _demo_yara_scan(self, evidence: models.Evidence):
        suspicious_patterns = ["mimikatz", "meterpreter", "cobalt strike", "invoke-", "bypass", "shellcode"]
        hits = 0
        try:
            with open(evidence.file_path, "rb") as f:
                content = f.read(1024 * 1024).lower()
            for pattern in suspicious_patterns:
                if pattern.encode() in content:
                    result = models.ScanResult(
                        evidence_id=evidence.id, case_id=evidence.case_id,
                        scanner_type="yara", rule_name=f"demo_{pattern.replace(' ','_')}",
                        rule_file="demo_rules.yar",
                        matched_strings=[pattern],
                        severity=models.SeverityLevel.high,
                        file_path=evidence.file_path,
                        description=f"Pattern '{pattern}' found in file",
                        mitre_technique="T1059"
                    )
                    self.db.add(result)
                    hits += 1
            self.db.commit()
        except Exception:
            pass
        return hits

    def _map_severity(self, sev: str):
        mapping = {"critical": models.SeverityLevel.critical, "high": models.SeverityLevel.high,
                   "medium": models.SeverityLevel.medium, "low": models.SeverityLevel.low}
        return mapping.get(sev.lower(), models.SeverityLevel.medium)


class SigmaScanner:
    SIGMA_RULES = [
        {"name": "Suspicious PowerShell Execution", "pattern": r"powershell.*(-enc|-encodedcommand|-nop|-w hidden)", "severity": "high", "mitre": "T1059.001", "source": "event_log"},
        {"name": "LSASS Memory Access", "pattern": r"lsass\.exe", "severity": "critical", "mitre": "T1003.001", "source": "event_log"},
        {"name": "Scheduled Task Creation", "pattern": r"schtasks.*(/create|/change)", "severity": "high", "mitre": "T1053.005", "source": "event_log"},
        {"name": "Remote Service Installation", "pattern": r"sc.*create", "severity": "high", "mitre": "T1543.003", "source": "event_log"},
        {"name": "Suspicious MSHTA Usage", "pattern": r"mshta\.exe.*(http|https|ftp)", "severity": "critical", "mitre": "T1218.005", "source": "event_log"},
        {"name": "WMI Remote Execution", "pattern": r"wmic.*(process call create|/node:)", "severity": "high", "mitre": "T1047", "source": "event_log"},
        {"name": "Certutil Download", "pattern": r"certutil.*(urlcache|-decode|-encode)", "severity": "high", "mitre": "T1105", "source": "event_log"},
        {"name": "Suspicious Reg Export", "pattern": r"reg.*(export|save).*(sam|system|security)", "severity": "critical", "mitre": "T1003.002", "source": "event_log"},
    ]

    def __init__(self, db: Session):
        self.db = db

    def scan_case(self, case_id: int):
        artifacts = self.db.query(models.Artifact).filter(
            models.Artifact.case_id == case_id,
            models.Artifact.artifact_type.in_(["event_log", "registry_run", "scheduled_task"])
        ).all()
        hits = 0
        for artifact in artifacts:
            value = (artifact.raw_value or "") + str(artifact.data or {})
            for rule in self.SIGMA_RULES:
                if re.search(rule["pattern"], value, re.IGNORECASE):
                    existing = self.db.query(models.ScanResult).filter(
                        models.ScanResult.case_id == case_id,
                        models.ScanResult.rule_name == rule["name"],
                        models.ScanResult.scanner_type == "sigma"
                    ).first()
                    if not existing:
                        result = models.ScanResult(
                            evidence_id=artifact.evidence_id,
                            case_id=case_id,
                            scanner_type="sigma",
                            rule_name=rule["name"],
                            rule_file="builtin_sigma",
                            matched_strings=[artifact.raw_value[:100] if artifact.raw_value else ""],
                            severity=self._sev(rule["severity"]),
                            file_path=artifact.path,
                            description=f"Sigma rule match: {rule['name']}",
                            mitre_technique=rule["mitre"],
                            raw_output=f"Artifact: {artifact.name}"
                        )
                        self.db.add(result)
                        artifact.is_suspicious = True
                        hits += 1
        self.db.commit()
        return hits

    def _sev(self, s):
        m = {"critical": models.SeverityLevel.critical, "high": models.SeverityLevel.high,
             "medium": models.SeverityLevel.medium, "low": models.SeverityLevel.low}
        return m.get(s, models.SeverityLevel.medium)


class IOCScanner:
    def __init__(self, db: Session):
        self.db = db

    def scan_case(self, case_id: int):
        iocs = self.db.query(models.IOC).filter(models.IOC.case_id == case_id, models.IOC.is_active == True).all()
        artifacts = self.db.query(models.Artifact).filter(models.Artifact.case_id == case_id).all()
        network = self.db.query(models.NetworkArtifact).filter(models.NetworkArtifact.case_id == case_id).all()
        hits = 0
        for ioc in iocs:
            for artifact in artifacts:
                searchable = f"{artifact.name} {artifact.raw_value or ''} {str(artifact.data or '')}".lower()
                if ioc.value.lower() in searchable:
                    result = models.ScanResult(
                        evidence_id=artifact.evidence_id, case_id=case_id,
                        scanner_type="ioc", rule_name=f"IOC:{ioc.ioc_type}:{ioc.value[:50]}",
                        rule_file="ioc_database",
                        matched_strings=[ioc.value],
                        severity=ioc.severity,
                        file_path=artifact.path,
                        description=f"IOC match: [{ioc.ioc_type}] {ioc.value}",
                        mitre_technique="",
                        raw_output=f"Artifact: {artifact.name}"
                    )
                    self.db.add(result)
                    artifact.is_suspicious = True
                    hits += 1
            if ioc.ioc_type in ["ip", "domain"]:
                for net in network:
                    if ioc.value in (net.remote_address or ""):
                        net.is_suspicious = True
                        hits += 1
        self.db.commit()
        return hits
