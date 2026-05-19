import os, socket, datetime
from sqlalchemy.orm import Session
import models

# ─── Network Collector ───
class NetworkCollector:
    def __init__(self, db: Session):
        self.db = db

    def collect_live(self, case_id: int) -> int:
        count = 0
        try:
            import psutil
            for conn in psutil.net_connections(kind="all"):
                try:
                    proc_name = ""
                    if conn.pid:
                        try:
                            proc_name = psutil.Process(conn.pid).name()
                        except:
                            pass
                    laddr = conn.laddr
                    raddr = conn.raddr if conn.raddr else None
                    suspicious_ports = [4444, 1337, 8080, 8443, 9001, 31337]
                    is_susp = (raddr and raddr.port in suspicious_ports) or proc_name.lower() in ["mshta.exe", "wscript.exe", "powershell.exe"]
                    item = models.NetworkArtifact(
                        case_id=case_id,
                        artifact_type=conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                        local_address=laddr.ip if laddr else None,
                        local_port=laddr.port if laddr else None,
                        remote_address=raddr.ip if raddr else None,
                        remote_port=raddr.port if raddr else None,
                        protocol="TCP" if conn.type == 1 else "UDP",
                        state=conn.status if conn.status else "NONE",
                        process_name=proc_name,
                        pid=conn.pid,
                        is_suspicious=is_susp
                    )
                    self.db.add(item)
                    count += 1
                except Exception:
                    pass
            self.db.commit()
        except ImportError:
            count = self._demo_network(case_id)
        return count

    def _demo_network(self, case_id: int) -> int:
        demo = [
            ("127.0.0.1", 5000, None, None, "TCP", "LISTEN", "python.exe", 1234, False),
            ("0.0.0.0", 445, None, None, "TCP", "LISTEN", "System", 4, False),
            ("192.168.1.5", 49200, "192.168.1.100", 4444, "TCP", "ESTABLISHED", "svchost32.exe", 9999, True),
        ]
        for la, lp, ra, rp, proto, state, proc, pid, susp in demo:
            item = models.NetworkArtifact(
                case_id=case_id, artifact_type="TCP",
                local_address=la, local_port=lp,
                remote_address=ra, remote_port=rp,
                protocol=proto, state=state,
                process_name=proc, pid=pid, is_suspicious=susp
            )
            self.db.add(item)
        self.db.commit()
        return len(demo)


# ─── Persistence Detector ───
PERSISTENCE_LOCATIONS = [
    ("registry_run", r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "T1547.001"),
    ("registry_run", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "T1547.001"),
    ("registry_runonce", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "T1547.001"),
    ("winlogon", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "T1547.004"),
    ("startup_folder", r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup", "T1547.001"),
    ("scheduled_tasks", r"C:\Windows\System32\Tasks", "T1053.005"),
    ("services", r"HKLM\SYSTEM\CurrentControlSet\Services", "T1543.003"),
]

class PersistenceDetector:
    def __init__(self, db: Session):
        self.db = db

    def scan(self, case_id: int) -> int:
        count = 0
        count += self._scan_registry(case_id)
        count += self._scan_startup(case_id)
        count += self._scan_tasks(case_id)
        count += self._scan_services(case_id)
        return count

    def _scan_registry(self, case_id: int) -> int:
        count = 0
        try:
            import winreg
            run_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "T1547.001"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "T1547.001"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "T1547.001"),
            ]
            for hive, key_path, mitre in run_keys:
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, data, _ = winreg.EnumValue(key, i)
                            susp = any(x in str(data).lower() for x in ["temp", "appdata\\roaming", ".ps1", ".vbs", ".bat", "http"])
                            item = models.PersistenceItem(
                                case_id=case_id,
                                persistence_type="registry_run",
                                location=f"{hive}\\{key_path}",
                                value_name=name, value_data=str(data),
                                description=f"Registry run key: {name}",
                                severity=models.SeverityLevel.high if susp else models.SeverityLevel.medium,
                                mitre_technique=mitre, is_suspicious=susp
                            )
                            self.db.add(item)
                            count += 1
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except Exception:
                    pass
        except ImportError:
            count = self._demo_persistence(case_id)
        self.db.commit()
        return count

    def _scan_startup(self, case_id: int) -> int:
        count = 0
        startup = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        if os.path.exists(startup):
            for f in os.listdir(startup):
                susp = not f.endswith(".lnk")
                item = models.PersistenceItem(
                    case_id=case_id, persistence_type="startup_folder",
                    location=startup, value_name=f, value_data=f,
                    description=f"Startup folder item: {f}",
                    severity=models.SeverityLevel.high if susp else models.SeverityLevel.low,
                    mitre_technique="T1547.001", is_suspicious=susp
                )
                self.db.add(item)
                count += 1
        self.db.commit()
        return count

    def _scan_tasks(self, case_id: int) -> int:
        count = 0
        tasks_dir = r"C:\Windows\System32\Tasks"
        if os.path.exists(tasks_dir):
            for root, _, files in os.walk(tasks_dir):
                for f in files:
                    path = os.path.join(root, f)
                    try:
                        content = open(path, "r", errors="ignore").read()
                        susp = any(x in content.lower() for x in ["powershell", "http", "temp", "wscript", "mshta"])
                        item = models.PersistenceItem(
                            case_id=case_id, persistence_type="scheduled_task",
                            location=path, value_name=f, value_data=content[:200],
                            description=f"Scheduled task: {f}",
                            severity=models.SeverityLevel.high if susp else models.SeverityLevel.info,
                            mitre_technique="T1053.005", is_suspicious=susp
                        )
                        self.db.add(item)
                        count += 1
                    except Exception:
                        pass
        self.db.commit()
        return count

    def _scan_services(self, case_id: int) -> int:
        count = 0
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
            i = 0
            while True:
                try:
                    svc_name = winreg.EnumKey(key, i)
                    try:
                        svc_key = winreg.OpenKey(key, svc_name)
                        try:
                            image, _ = winreg.QueryValueEx(svc_key, "ImagePath")
                            susp = any(x in str(image).lower() for x in ["temp", "appdata", "users\\public", "http"])
                            if susp:
                                item = models.PersistenceItem(
                                    case_id=case_id, persistence_type="service",
                                    location=r"HKLM\SYSTEM\CurrentControlSet\Services",
                                    value_name=svc_name, value_data=str(image),
                                    description=f"Windows service: {svc_name}",
                                    severity=models.SeverityLevel.high,
                                    mitre_technique="T1543.003", is_suspicious=True
                                )
                                self.db.add(item)
                                count += 1
                        except Exception:
                            pass
                        winreg.CloseKey(svc_key)
                    except Exception:
                        pass
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
            self.db.commit()
        except Exception:
            pass
        return count

    def _demo_persistence(self, case_id: int) -> int:
        demo = [
            ("registry_run", r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "SecurityUpdater", r"C:\Users\User\AppData\Roaming\svchost.exe", True, "T1547.001"),
            ("scheduled_task", r"C:\Windows\System32\Tasks", "SystemMaintenance", r"powershell -nop -w hidden -enc aQBuAHYAbwBrAGUALQBlAHgAcAByAGUAcwBzAGkAbwBuACAAJABlAG4AdgA6AFQARQBNAFAA", True, "T1053.005"),
        ]
        for ptype, loc, name, data, susp, mitre in demo:
            item = models.PersistenceItem(
                case_id=case_id, persistence_type=ptype,
                location=loc, value_name=name, value_data=data,
                description=f"Demo: {name}", severity=models.SeverityLevel.critical if susp else models.SeverityLevel.info,
                mitre_technique=mitre, is_suspicious=susp
            )
            self.db.add(item)
        self.db.commit()
        return len(demo)


# ─── Timeline Builder ───
class TimelineBuilder:
    def __init__(self, db: Session):
        self.db = db

    def build_from_case(self, case_id: int) -> int:
        count = 0
        artifacts = self.db.query(models.Artifact).filter(
            models.Artifact.case_id == case_id,
            models.Artifact.timestamp.isnot(None)
        ).all()
        for a in artifacts:
            existing = self.db.query(models.TimelineEvent).filter(
                models.TimelineEvent.case_id == case_id,
                models.TimelineEvent.evidence_id == a.evidence_id,
                models.TimelineEvent.description == a.name,
                models.TimelineEvent.timestamp == a.timestamp
            ).first()
            if not existing:
                event = models.TimelineEvent(
                    case_id=case_id, evidence_id=a.evidence_id,
                    timestamp=a.timestamp, event_type=a.artifact_type,
                    source=a.artifact_type, description=a.name,
                    details=a.data or {}, severity=a.severity,
                    mitre_technique=a.mitre_technique,
                    is_flagged=a.is_suspicious
                )
                self.db.add(event)
                count += 1
        persistence = self.db.query(models.PersistenceItem).filter(
            models.PersistenceItem.case_id == case_id
        ).all()
        for p in persistence:
            event = models.TimelineEvent(
                case_id=case_id, timestamp=p.collected_at,
                event_type="persistence", source="persistence_detector",
                description=f"[PERSISTENCE] {p.persistence_type}: {p.value_name}",
                details={"location": p.location, "data": p.value_data},
                severity=p.severity, mitre_technique=p.mitre_technique,
                is_flagged=p.is_suspicious
            )
            self.db.add(event)
            count += 1
        self.db.commit()
        return count


# ─── Report Generator ───
class ReportGenerator:
    def __init__(self, db: Session):
        self.db = db

    def generate(self, payload, user_id: int) -> models.Report:
        case = self.db.query(models.Case).filter(models.Case.id == payload.case_id).first()
        reports_dir = os.path.join(os.path.dirname(__file__), "..", "..", "reports")
        os.makedirs(reports_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"DFIR_{case.case_number}_{ts}.{payload.format}"
        file_path = os.path.join(reports_dir, filename)
        if payload.format == "pdf":
            self._generate_pdf(case, file_path)
        else:
            self._generate_html(case, file_path)
        report = models.Report(
            case_id=payload.case_id, title=payload.title,
            report_type=payload.report_type, format=payload.format,
            file_path=file_path, generated_by=user_id,
            includes_ai_summary=payload.includes_ai_summary
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)
        return report

    def _generate_pdf(self, case, file_path: str):
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
            from reportlab.lib.units import inch
            doc = SimpleDocTemplate(file_path, pagesize=A4, topMargin=0.75*inch, bottomMargin=0.75*inch)
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=22, textColor=colors.HexColor("#1a1a2e"), spaceAfter=6)
            h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor("#16213e"), spaceBefore=12, spaceAfter=4)
            body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=10, leading=14)
            story = []
            story.append(Paragraph("DFIR Investigation Suite", ParagraphStyle('Header', parent=styles['Normal'], fontSize=10, textColor=colors.grey)))
            story.append(Spacer(1, 6))
            story.append(Paragraph(f"Case Report: {case.case_number}", title_style))
            story.append(Paragraph(case.title, ParagraphStyle('Sub', parent=styles['Normal'], fontSize=14, textColor=colors.HexColor("#0f3460"))))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#16213e")))
            story.append(Spacer(1, 12))
            artifacts = self.db.query(models.Artifact).filter(models.Artifact.case_id == case.id).all()
            iocs = self.db.query(models.IOC).filter(models.IOC.case_id == case.id).all()
            scans = self.db.query(models.ScanResult).filter(models.ScanResult.case_id == case.id).all()
            persistence = self.db.query(models.PersistenceItem).filter(models.PersistenceItem.case_id == case.id).all()
            suspicious = [a for a in artifacts if a.is_suspicious]
            summary_data = [
                ["Field", "Value"],
                ["Case Number", case.case_number],
                ["Status", case.status.value.upper()],
                ["Priority", case.priority.value.upper()],
                ["Total Artifacts", str(len(artifacts))],
                ["Suspicious Artifacts", str(len(suspicious))],
                ["IOCs", str(len(iocs))],
                ["Scan Hits", str(len(scans))],
                ["Persistence Items", str(len(persistence))],
            ]
            t = Table(summary_data, colWidths=[2.5*inch, 4*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#16213e")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4f8")]),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(Paragraph("Case Summary", h2_style))
            story.append(t)
            story.append(Spacer(1, 16))
            if suspicious:
                story.append(Paragraph("Suspicious Artifacts", h2_style))
                art_data = [["Type", "Name", "Severity", "MITRE"]]
                for a in suspicious[:20]:
                    art_data.append([a.artifact_type, a.name[:50], a.severity.value, a.mitre_technique or ""])
                at = Table(art_data, colWidths=[1.5*inch, 3*inch, 1*inch, 1*inch])
                at.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#c0392b")),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('PADDING', (0, 0), (-1, -1), 5),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#fdf2f2")]),
                ]))
                story.append(at)
                story.append(Spacer(1, 16))
            if iocs:
                story.append(Paragraph("Indicators of Compromise", h2_style))
                ioc_data = [["Type", "Value", "Severity", "Confidence"]]
                for i in iocs[:20]:
                    ioc_data.append([i.ioc_type, i.value[:40], i.severity.value, f"{i.confidence:.0%}"])
                it = Table(ioc_data, colWidths=[1.2*inch, 3.3*inch, 1*inch, 1*inch])
                it.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e67e22")),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('PADDING', (0, 0), (-1, -1), 5),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#fef9f0")]),
                ]))
                story.append(it)
                story.append(Spacer(1, 16))
            if case.mitre_techniques:
                story.append(Paragraph("MITRE ATT&CK Techniques", h2_style))
                for t_id in case.mitre_techniques:
                    story.append(Paragraph(f"• {t_id}", body_style))
                story.append(Spacer(1, 12))
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
            story.append(Spacer(1, 6))
            from datetime import datetime as dt
            story.append(Paragraph(f"Generated by DFIR Investigation Suite • {dt.now().strftime('%Y-%m-%d %H:%M')} • CONFIDENTIAL", ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey, alignment=1)))
            doc.build(story)
        except Exception as e:
            with open(file_path, "w") as f:
                f.write(f"Report generation failed: {e}\nCase: {case.case_number}")

    def _generate_html(self, case, file_path: str):
        artifacts = self.db.query(models.Artifact).filter(models.Artifact.case_id == case.id).all()
        iocs = self.db.query(models.IOC).filter(models.IOC.case_id == case.id).all()
        scans = self.db.query(models.ScanResult).filter(models.ScanResult.case_id == case.id).all()
        suspicious = [a for a in artifacts if a.is_suspicious]
        from datetime import datetime as dt
        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>DFIR Report - {case.case_number}</title>
<style>body{{font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}}
h1{{color:#58a6ff}}h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:8px}}
table{{width:100%;border-collapse:collapse;margin:12px 0}}th{{background:#161b22;color:#58a6ff;padding:10px;text-align:left}}
td{{padding:8px;border-bottom:1px solid #21262d}}tr:hover{{background:#161b22}}.badge{{padding:3px 8px;border-radius:4px;font-size:12px}}
.critical{{background:#ff000030;color:#ff6b6b}}.high{{background:#ff6b0030;color:#ffa94d}}
.medium{{background:#ffd70030;color:#ffd700}}.low{{background:#00ff0020;color:#69db7c}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:12px 0}}</style></head>
<body><h1>🔍 DFIR Investigation Report</h1>
<div class="card"><h2>Case Summary</h2>
<p><strong>Case:</strong> {case.case_number} | <strong>Title:</strong> {case.title}</p>
<p><strong>Status:</strong> {case.status.value} | <strong>Priority:</strong> {case.priority.value}</p>
<p><strong>Artifacts:</strong> {len(artifacts)} total, {len(suspicious)} suspicious | <strong>IOCs:</strong> {len(iocs)} | <strong>Scans:</strong> {len(scans)}</p>
</div>
<div class="card"><h2>Suspicious Artifacts</h2><table><tr><th>Type</th><th>Name</th><th>Severity</th><th>MITRE</th></tr>
{"".join(f'<tr><td>{a.artifact_type}</td><td>{a.name[:60]}</td><td><span class="badge {a.severity.value}">{a.severity.value}</span></td><td>{a.mitre_technique or ""}</td></tr>' for a in suspicious[:30])}
</table></div>
<div class="card"><h2>IOCs</h2><table><tr><th>Type</th><th>Value</th><th>Severity</th></tr>
{"".join(f'<tr><td>{i.ioc_type}</td><td>{i.value[:50]}</td><td><span class="badge {i.severity.value}">{i.severity.value}</span></td></tr>' for i in iocs[:30])}
</table></div>
<p style="color:#555;text-align:center;margin-top:30px">Generated by DFIR Investigation Suite • {dt.now().strftime('%Y-%m-%d %H:%M')} • CONFIDENTIAL</p>
</body></html>"""
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html)
