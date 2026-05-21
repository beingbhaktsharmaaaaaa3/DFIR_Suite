import os, datetime, json
from pathlib import Path

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_report(data: dict, fmt: str = "pdf") -> dict:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    title = data.get("title", f"ForenCore Report {ts}")
    safe_title = "".join(c if c.isalnum() or c in "-_" else "_" for c in title)
    fname = f"{safe_title}_{ts}.{fmt}"
    out_path = os.path.join(REPORTS_DIR, fname)

    if fmt == "pdf":
        _gen_pdf(data, out_path, title)
    elif fmt == "html":
        _gen_html(data, out_path, title)
    elif fmt == "json":
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    
    size = os.path.getsize(out_path) if os.path.exists(out_path) else 0
    return {"path": out_path, "filename": fname, "format": fmt,
            "size_bytes": size, "generated_at": datetime.datetime.utcnow().isoformat()}

def _gen_pdf(data: dict, out_path: str, title: str):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
        from reportlab.lib.units import inch, cm

        doc = SimpleDocTemplate(out_path, pagesize=A4,
                                topMargin=0.75*inch, bottomMargin=0.75*inch,
                                leftMargin=inch, rightMargin=inch)
        styles = getSampleStyleSheet()
        
        DARK   = colors.HexColor("#1a1a2e")
        PURPLE = colors.HexColor("#7c3aed")
        GREY   = colors.HexColor("#374151")
        LIGHT  = colors.HexColor("#f9fafb")

        title_s  = ParagraphStyle('TitleS',  parent=styles['Title'],  fontSize=22, textColor=DARK,   spaceAfter=4)
        h2_s     = ParagraphStyle('H2S',     parent=styles['Heading2'],fontSize=13, textColor=PURPLE, spaceBefore=14, spaceAfter=6)
        body_s   = ParagraphStyle('BodyS',   parent=styles['Normal'], fontSize=10, leading=15, textColor=GREY)
        small_s  = ParagraphStyle('SmallS',  parent=styles['Normal'], fontSize=8,  textColor=colors.grey)
        code_s   = ParagraphStyle('CodeS',   parent=styles['Code'],   fontSize=8,  leading=12, textColor=DARK)

        def table(rows, col_widths=None, header_color=PURPLE):
            t = Table(rows, colWidths=col_widths)
            t.setStyle(TableStyle([
                ('BACKGROUND',  (0,0), (-1,0),  header_color),
                ('TEXTCOLOR',   (0,0), (-1,0),  colors.white),
                ('FONTNAME',    (0,0), (-1,0),  'Helvetica-Bold'),
                ('FONTSIZE',    (0,0), (-1,-1), 9),
                ('PADDING',     (0,0), (-1,-1), 6),
                ('GRID',        (0,0), (-1,-1), 0.4, colors.HexColor("#d1d5db")),
                ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white, colors.HexColor("#f3f4f6")]),
                ('VALIGN',      (0,0), (-1,-1), 'TOP'),
            ]))
            return t
        
        story = []
        # ── Header ──────────────────────────────────────────────────
        story.append(Paragraph("🔬 ForenCore Forensic Workstation", small_s))
        story.append(Spacer(1, 4))
        story.append(Paragraph(title, title_s))
        story.append(HRFlowable(width="100%", thickness=2, color=PURPLE))
        story.append(Spacer(1, 8))

        # ── Examiner Info ────────────────────────────────────────────
        examiner = data.get("examiner", {})
        story.append(Paragraph("Examiner Information", h2_s))
        rows = [["Field", "Value"],
                ["Examiner",   examiner.get("name",  "N/A")],
                ["Case Name",  data.get("case_name", "N/A")],
                ["Date",       datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")],
                ["Tool",       "ForenCore v1.0"],
                ["Platform",   __import__('platform').system() + " " + __import__('platform').release()]]
        story.append(table(rows, [2.5*inch, 4*inch]))
        story.append(Spacer(1, 12))

        # ── Acquisitions ─────────────────────────────────────────────
        acqs = data.get("acquisitions", [])
        if acqs:
            story.append(Paragraph("Evidence Acquisitions", h2_s))
            rows = [["Name","Type","Size (GB)","SHA256","Status"]]
            for a in acqs:
                rows.append([
                    str(a.get("name",""))[:30],
                    str(a.get("acq_type","")),
                    str(round(float(a.get("size_bytes",0))/(1024**3), 3)),
                    str(a.get("sha256","N/A"))[:20]+"...",
                    str(a.get("status",""))
                ])
            story.append(table(rows, [2*inch, 1.2*inch, 0.9*inch, 2*inch, 0.9*inch]))
            story.append(Spacer(1, 12))

        # ── RAM Analysis ─────────────────────────────────────────────
        ram = data.get("ram_analysis", {})
        if ram:
            story.append(Paragraph("RAM Analysis Findings", h2_s))
            procs = ram.get("processes", [])
            susp  = [p for p in procs if p.get("is_suspicious")]
            story.append(Paragraph(f"Total processes: {len(procs)} | Suspicious: {len(susp)}", body_s))
            if susp:
                rows = [["PID","Name","PPID","Reason"]]
                for p in susp[:20]:
                    rows.append([str(p.get("pid","")), str(p.get("name",""))[:25],
                                 str(p.get("ppid","")), ", ".join(p.get("suspicious_reasons",[]))[:40]])
                story.append(table(rows, [0.6*inch, 2*inch, 0.6*inch, 3.3*inch]))
            story.append(Spacer(1, 12))

        # ── Disk Analysis ────────────────────────────────────────────
        disk = data.get("disk_analysis", {})
        if disk:
            story.append(Paragraph("Disk Analysis Findings", h2_s))
            partitions = disk.get("partitions", [])
            if partitions:
                story.append(Paragraph(f"Partitions found: {len(partitions)}", body_s))
                rows = [["#","Type","Start LBA","Size (MB)","Bootable"]]
                for i, p in enumerate(partitions[:10]):
                    rows.append([str(i+1), str(p.get("type_name",""))[:15],
                                 str(p.get("start_lba","")), str(p.get("size_mb","")),
                                 "Yes" if p.get("bootable") else "No"])
                story.append(table(rows, [0.4*inch, 1.5*inch, 1.5*inch, 1.2*inch, 0.9*inch]))
            story.append(Spacer(1, 12))

        # ── Recovery ─────────────────────────────────────────────────
        recovery = data.get("recovery", {})
        if recovery:
            story.append(Paragraph("Data Recovery Results", h2_s))
            recovered = recovery.get("recovered", [])
            story.append(Paragraph(f"Files recovered: {len(recovered)}", body_s))
            if recovered:
                rows = [["Filename","Type","Size (KB)","Quality"]]
                for r in recovered[:20]:
                    rows.append([str(r.get("name",""))[:30], str(r.get("type","")),
                                 str(r.get("size_kb","")), str(r.get("quality",""))])
                story.append(table(rows, [2.5*inch, 1*inch, 1.2*inch, 1.8*inch]))
            story.append(Spacer(1, 12))

        # ── Notes ────────────────────────────────────────────────────
        notes = data.get("notes", "")
        if notes:
            story.append(Paragraph("Examiner Notes", h2_s))
            story.append(Paragraph(str(notes), body_s))
            story.append(Spacer(1, 12))

        # ── Footer ───────────────────────────────────────────────────
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            f"Generated by ForenCore v1.0 • {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} • CONFIDENTIAL — FOR LAW ENFORCEMENT / AUTHORIZED USE ONLY",
            ParagraphStyle('Footer', parent=styles['Normal'], fontSize=7, textColor=colors.grey, alignment=1)
        ))
        doc.build(story)

    except Exception as e:
        with open(out_path, "w") as f:
            f.write(f"PDF generation error: {e}\nInstall reportlab: pip install reportlab")

def _gen_html(data: dict, out_path: str, title: str):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    acqs = data.get("acquisitions", [])
    ram  = data.get("ram_analysis", {})
    procs = ram.get("processes", [])
    susp = [p for p in procs if p.get("is_suspicious")]
    disk = data.get("disk_analysis", {})
    recovery = data.get("recovery", {})
    recovered = recovery.get("recovered", [])

    def rows(items, keys):
        return "".join(f"<tr>{''.join(f'<td>{str(item.get(k,chr(8212)))[:80]}</td>' for k in keys)}</tr>" for item in items)

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>{title}</title>
<style>
* {{margin:0;padding:0;box-sizing:border-box}}
body {{font-family:Arial,sans-serif;background:#111827;color:#d1d5db;padding:0}}
.header {{background:linear-gradient(135deg,#1f1b4b,#2d1b69);padding:30px 40px;border-bottom:3px solid #7c3aed}}
.header h1 {{font-size:24px;color:#fff}} .header p {{color:#a78bfa;font-size:13px;margin-top:4px}}
.body {{padding:30px 40px;max-width:1100px;margin:0 auto}}
h2 {{font-size:15px;font-weight:700;color:#a78bfa;margin:24px 0 10px;padding-bottom:6px;border-bottom:1px solid #374151}}
table {{width:100%;border-collapse:collapse;margin:8px 0 16px}}
th {{background:#1f2937;color:#a78bfa;padding:9px 12px;text-align:left;font-size:12px;font-weight:600}}
td {{padding:8px 12px;border-bottom:1px solid #1f2937;font-size:12px}}
tr:hover td {{background:#1f2937}}
.badge {{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}}
.susp {{background:rgba(239,68,68,.2);color:#f87171}}
.ok   {{background:rgba(34,197,94,.2);color:#4ade80}}
.info {{background:rgba(124,58,237,.2);color:#a78bfa}}
.grid2 {{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
.card {{background:#1f2937;border:1px solid #374151;border-radius:8px;padding:16px}}
.stat {{text-align:center}} .stat-n {{font-size:28px;font-weight:700;color:#a78bfa}}
.stat-l {{font-size:12px;color:#9ca3af;margin-top:4px}}
.footer {{text-align:center;color:#4b5563;font-size:11px;padding:20px;margin-top:30px;border-top:1px solid #1f2937}}
</style></head><body>
<div class="header">
  <div style="font-size:11px;color:#7c3aed;margin-bottom:6px">🔬 FORENCORE FORENSIC WORKSTATION</div>
  <h1>{title}</h1>
  <p>Generated: {now} &nbsp;|&nbsp; Case: {data.get('case_name','N/A')} &nbsp;|&nbsp; Examiner: {data.get('examiner',{}).get('name','N/A')}</p>
</div>
<div class="body">
<div class="grid2" style="margin-top:20px">
  <div class="card stat"><div class="stat-n">{len(acqs)}</div><div class="stat-l">Acquisitions</div></div>
  <div class="card stat"><div class="stat-n">{len(susp)}</div><div class="stat-l">Suspicious Processes</div></div>
</div>

<h2>Evidence Acquisitions</h2>
{"<p style='color:#6b7280'>No acquisitions recorded.</p>" if not acqs else f'''
<table><thead><tr><th>Name</th><th>Type</th><th>Size (GB)</th><th>SHA256</th><th>Status</th></tr></thead>
<tbody>{rows(acqs,["name","acq_type","size_bytes","sha256","status"])}</tbody></table>'''}

<h2>RAM Analysis — Suspicious Processes</h2>
{"<p style='color:#6b7280'>No RAM analysis data.</p>" if not susp else f'''
<table><thead><tr><th>PID</th><th>Name</th><th>PPID</th><th>Reason</th></tr></thead>
<tbody>{"".join(f"<tr><td>{p.get('pid','')}</td><td>{p.get('name','')}</td><td>{p.get('ppid','')}</td><td><span class='badge susp'>{', '.join(p.get('suspicious_reasons',[]))}</span></td></tr>" for p in susp[:30])}</tbody></table>'''}

<h2>Disk Analysis — Partitions</h2>
{"<p style='color:#6b7280'>No disk analysis data.</p>" if not disk.get('partitions') else f'''
<table><thead><tr><th>#</th><th>Type</th><th>Start LBA</th><th>Size (MB)</th><th>Bootable</th></tr></thead>
<tbody>{rows(disk.get("partitions",[])[:10],["index","type_name","start_lba","size_mb","bootable"])}</tbody></table>'''}

<h2>Data Recovery Results</h2>
{"<p style='color:#6b7280'>No recovery data.</p>" if not recovered else f'''
<table><thead><tr><th>Filename</th><th>Type</th><th>Size (KB)</th><th>Quality</th></tr></thead>
<tbody>{rows(recovered[:30],["name","type","size_kb","quality"])}</tbody></table>'''}

{f'<h2>Notes</h2><div class="card"><p style="font-size:13px;line-height:1.7">{data.get("notes","")}</p></div>' if data.get("notes") else ''}
</div>
<div class="footer">ForenCore v1.0 &nbsp;|&nbsp; {now} &nbsp;|&nbsp; CONFIDENTIAL — FOR AUTHORIZED FORENSIC USE ONLY</div>
</body></html>"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

def list_reports() -> list:
    files = []
    for ext in ["*.pdf","*.html","*.json"]:
        for f in Path(REPORTS_DIR).glob(ext):
            stat = f.stat()
            files.append({"name": f.name, "path": str(f), "format": f.suffix.lstrip("."),
                           "size_bytes": stat.st_size,
                           "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat()})
    return sorted(files, key=lambda x: x["modified"], reverse=True)
