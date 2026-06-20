from __future__ import annotations

import html
import json
import textwrap
from pathlib import Path
from typing import Any

from .models import CaseReport
from .utils import write_json


RISK_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def risk_counts(report: CaseReport) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in report.findings:
        counts[finding.risk] = counts.get(finding.risk, 0) + 1
    return counts


def executive_summary(report: CaseReport) -> str:
    counts = risk_counts(report)
    total = len(report.findings)
    if total == 0:
        return "No high-confidence suspicious findings were identified by the configured checks. Manual validation is still recommended."
    top = max(report.findings, key=lambda f: RISK_ORDER.get(f.risk, 0)).risk
    return (
        f"The assessment identified {total} finding(s). Highest observed risk is {top}. "
        f"Counts: Critical {counts.get('Critical', 0)}, High {counts.get('High', 0)}, "
        f"Medium {counts.get('Medium', 0)}, Low {counts.get('Low', 0)}."
    )


def format_duration(seconds: Any) -> str:
    try:
        total = int(seconds)
    except Exception:
        total = 0
    minutes, sec = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {sec}s"
    if minutes:
        return f"{minutes}m {sec}s"
    return f"{sec}s"


def write_reports(report: CaseReport, output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in report.case_name).strip("_") or "case"
    paths = {
        "json": output_dir / f"{safe_name}.json",
        "html": output_dir / f"{safe_name}.html",
        "pdf": output_dir / f"{safe_name}.pdf",
    }
    write_json(paths["json"], report.to_dict())
    write_html(report, paths["html"])
    write_pdf(report, paths["pdf"])
    return paths


def flatten_table(rows: list[dict[str, Any]], limit: int = 30) -> str:
    if not rows:
        return "<p>No records collected.</p>"
    keys: list[str] = []
    for row in rows[:limit]:
        for key in row.keys():
            if key not in keys:
                keys.append(key)
            if len(keys) >= 6:
                break
        if len(keys) >= 6:
            break
    head = "".join(f"<th>{html.escape(labelize(k))}</th>" for k in keys)
    body = []
    for row in rows[:limit]:
        cells = "".join(f"<td>{format_cell(k, row.get(k, ''))}</td>" for k in keys)
        body.append(f"<tr>{cells}</tr>")
    more = ""
    if len(rows) > limit:
        more = f"<p>Showing {limit} of {len(rows)} records. Full data is available in the JSON report.</p>"
    return f"<table class='data-table'><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>{more}"


def evidence_cards(rows: list[dict[str, Any]], limit: int = 12) -> str:
    if not rows:
        return "<p>No evidence records attached.</p>"
    cards = []
    priority = ["type", "source", "name", "path", "command", "key", "PathName", "TaskName", "State", "risk", "indicator"]
    for index, row in enumerate(rows[:limit], start=1):
        if not isinstance(row, dict):
            cards.append(f"<div class='card'><h4>Evidence {index}</h4><p>{html.escape(str(row))}</p></div>")
            continue
        ordered = [key for key in priority if key in row]
        ordered.extend([key for key in row.keys() if key not in ordered])
        pairs = []
        for key in ordered[:8]:
            value = row.get(key)
            if value in ("", None, {}, []):
                continue
            pairs.append(
                f"<dt>{html.escape(labelize(key))}</dt><dd>{format_cell(key, value)}</dd>"
            )
        title = row.get("name") or row.get("TaskName") or row.get("source") or row.get("type") or f"Evidence {index}"
        cards.append(
            f"""<div class='card'>
       <h4>{html.escape(str(title))}</h4>
              <dl>{''.join(pairs) if pairs else "<p>No displayable fields.</p>"}</dl>
            </div>"""
        )
    more = ""
    if len(rows) > limit:
        more = f"<p>Showing {limit} of {len(rows)} evidence records. Full evidence is available in the JSON report.</p>"
    return f"{''.join(cards)}{more}"


def labelize(value: Any) -> str:
    return str(value).replace("_", " ").replace("-", " ").title()


def format_cell(key: Any, value: Any) -> str:
    if value is None:
        return "None"
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, default=str)
    else:
        text = str(value)
    text = text.strip()
    if not text:
        return "Empty"
    escaped = html.escape(text[:900])
    key_text = str(key).lower()
    if key_text in {"path", "command", "pathname", "file", "registry_key", "key"} or "\\" in text or "/" in text:
        return f"<code>{escaped}</code>"
    return escaped


def write_html(report: CaseReport, path: Path) -> None:
    counts = risk_counts(report)
    analyst = str(report.metadata.get("analyst", "") or "Not specified")
    notes = str(report.metadata.get("notes", "") or "None")
    duration = format_duration(report.metadata.get("duration_seconds", 0))
    findings = sorted(report.findings, key=lambda f: RISK_ORDER.get(f.risk, 0), reverse=True)
    finding_cards = []
    for finding in findings:
        evidence = evidence_cards(finding.evidence if isinstance(finding.evidence, list) else [], limit=12)
        finding_cards.append(
            f"""<div class='finding'>
            <h3>{html.escape(finding.title)} <span class='risk'>{html.escape(finding.risk)}</span></h3>
            <p>{html.escape(finding.description)}</p>
            <h4>Evidence</h4>
              {evidence}
              <h4>Recommendation</h4>
            <p>{html.escape(finding.recommendation)}</p>
            </div>"""
        )
    inventory_tables = []
    for key in ["installed_software", "processes", "services", "startup_entries", "scheduled_tasks", "user_accounts", "usb_history", "event_logs", "network_connections", "recent_files", "downloads"]:
        value = report.inventory.get(key, [])
        if isinstance(value, list):
            inventory_tables.append(f"<h3>{html.escape(key.replace('_', ' ').title())}</h3>{flatten_table(value, limit=25)}")
    timeline_rows = [
        {
            "timestamp": item.timestamp,
            "source": item.source,
            "type": item.event_type,
            "description": item.description,
        }
        for item in report.timeline[:200]
    ]
    body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>{html.escape(report.case_name)}</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f7fa; color: #17202a; }}
.container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
h1 {{ color: #102033; border-bottom: 3px solid #102033; padding-bottom: 10px; }}
h2 {{ color: #102033; margin-top: 30px; border-left: 4px solid #102033; padding-left: 10px; }}
h3 {{ color: #2c3e50; }}
.meta {{ background: #eef3f7; padding: 15px; border-radius: 5px; margin: 20px 0; }}
.counts {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
.count {{ background: #102033; color: white; padding: 10px 20px; border-radius: 5px; }}
.count b {{ font-size: 1.5em; margin-left: 8px; }}
.finding {{ background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 20px 0; }}
.finding h3 {{ margin-top: 0; }}
.risk {{ display: inline-block; padding: 3px 10px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.85em; }}
.risk.Critical {{ background: #c0392b; }}
.risk.High {{ background: #e74c3c; }}
.risk.Medium {{ background: #f39c12; }}
.risk.Low {{ background: #3498db; }}
.risk.Info {{ background: #95a5a6; }}
table.data-table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 0.9em; }}
table.data-table th {{ background: #102033; color: white; padding: 12px; text-align: left; font-weight: 600; }}
table.data-table td {{ padding: 10px; border-bottom: 1px solid #ddd; vertical-align: top; }}
table.data-table tr:nth-child(even) {{ background: #f8f9fa; }}
table.data-table tr:hover {{ background: #eef3f7; }}
code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Consolas', monospace; font-size: 0.9em; color: #c0392b; }}
.card {{ background: #f8f9fa; border-left: 4px solid #102033; padding: 15px; margin: 10px 0; border-radius: 0 5px 5px 0; }}
.card h4 {{ margin-top: 0; color: #102033; }}
dl {{ margin: 10px 0; }}
dt {{ font-weight: 600; color: #2c3e50; margin-top: 8px; }}
dd {{ margin-left: 20px; margin-bottom: 8px; }}
.recommendations {{ background: #e8f6f3; padding: 20px; border-radius: 5px; }}
.recommendations ul {{ margin: 10px 0; padding-left: 20px; }}
.recommendations li {{ margin: 8px 0; }}
.timeline {{ background: #fef9e7; padding: 20px; border-radius: 5px; }}
</style>
</head>
<body>
<div class='container'>
    <h1>{html.escape(report.case_name)}</h1>
    <div class='meta'>
        <p><b>Host:</b> {html.escape(report.host)} | <b>Analyst:</b> {html.escape(analyst)} | <b>Started:</b> {html.escape(report.started_at)} | <b>Completed:</b> {html.escape(report.completed_at)} | <b>Duration:</b> {html.escape(duration)}</p>
    </div>
    
    <h2>Executive Summary</h2>
    <p>{html.escape(executive_summary(report))}</p>
    <div class='counts'>
        {''.join(f"<span class='count'>{risk}<b>{count}</b></span>" for risk, count in counts.items())}
    </div>
    
    <h2>Case Notes</h2>
    <p>{html.escape(notes)}</p>
    
    <h2>Findings</h2>
    <div class='findings'>
      {''.join(finding_cards) if finding_cards else "<p>No findings generated.</p>"}
    </div>
    
    <h2>Recommendations</h2>
    <div class='recommendations'>
    <ul>{''.join(f"<li>{html.escape(item)}</li>" for item in report.recommendations)}</ul>
    </div>
    
    <h2>Evidence Tables</h2>
    <div class='tables'>
      {''.join(inventory_tables)}
    </div>
    
    <h2>Forensic Timeline</h2>
    <div class='timeline'>
      {flatten_table(timeline_rows, limit=200)}
    </div>
</div>
</body>
</html>"""
    path.write_text(body, encoding="utf-8")


def write_pdf(report: CaseReport, path: Path) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, PageBreak
    except ImportError:
        path.write_bytes(minimal_pdf(pdf_fallback_text(report)))
        return

    styles = getSampleStyleSheet()
    if 'Small' not in styles.byName:
        styles.add(ParagraphStyle(name='Small', fontSize=7, leading=9, fontName='Helvetica'))

    doc = SimpleDocTemplate(
        str(path), 
        pagesize=letter, 
        title=report.case_name,
        leftMargin=0.5*inch,
        rightMargin=0.5*inch,
        topMargin=0.5*inch,
        bottomMargin=0.5*inch
    )
    story = []
    
    # 1. Title & Metadata
    story.append(Paragraph(report.case_name, styles["Title"]))
    story.append(Spacer(1, 12))
    
    analyst = str(report.metadata.get("analyst", "") or "Not specified")
    duration = format_duration(report.metadata.get("duration_seconds", 0))
    meta_text = f"<b>Host:</b> {html.escape(report.host)} | <b>Analyst:</b> {html.escape(analyst)}<br/>" \
                f"<b>Started:</b> {html.escape(report.started_at)} | <b>Completed:</b> {html.escape(report.completed_at)} | <b>Duration:</b> {html.escape(duration)}"
    story.append(Paragraph(meta_text, styles["Normal"]))
    story.append(Spacer(1, 12))
    
    # 2. Executive Summary
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(html.escape(executive_summary(report)), styles["BodyText"]))
    
    counts = risk_counts(report)
    counts_text = " | ".join([f"{k}: {v}" for k, v in counts.items()])
    story.append(Paragraph(f"<b>Risk Counts:</b> {html.escape(counts_text)}", styles["Normal"]))
    story.append(Spacer(1, 12))
    
    # 3. Case Notes
    notes = str(report.metadata.get("notes", "") or "None")
    story.append(Paragraph("Case Notes", styles["Heading2"]))
    story.append(Paragraph(html.escape(notes), styles["BodyText"]))
    story.append(Spacer(1, 12))
    
    # 4. Findings
    story.append(Paragraph("Findings", styles["Heading2"]))
    findings = sorted(report.findings, key=lambda f: RISK_ORDER.get(f.risk, 0), reverse=True)
    if not findings:
        story.append(Paragraph("No findings generated.", styles["BodyText"]))
    else:
        for finding in findings:
            story.append(Paragraph(f"<b>{html.escape(finding.risk)}: {html.escape(finding.title)}</b>", styles["Heading3"]))
            story.append(Paragraph(f"<b>Category:</b> {html.escape(finding.category)}", styles["Normal"]))
            story.append(Paragraph(f"<b>Description:</b> {html.escape(finding.description)}", styles["BodyText"]))
            story.append(Paragraph(f"<b>Recommendation:</b> {html.escape(finding.recommendation)}", styles["BodyText"]))
            
            if finding.evidence:
                story.append(Paragraph("<b>Evidence:</b>", styles["Normal"]))
                evidence_data = [["Key", "Value"]]
                for item in finding.evidence[:20]:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            val_str = str(v)
                            if isinstance(v, (dict, list)):
                                val_str = json.dumps(v, ensure_ascii=False, default=str)
                            if len(val_str) > 250:
                                val_str = val_str[:247] + "..."
                            evidence_data.append([html.escape(labelize(k)), Paragraph(html.escape(val_str), styles["Small"])])
                
                if len(finding.evidence) > 20:
                    evidence_data.append([f"Showing 20 of {len(finding.evidence)} records.", "Full evidence is available in the JSON report."])
                
                if len(evidence_data) > 1:
                    t = Table(evidence_data, colWidths=[1.5*inch, 5.5*inch])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                        ('FONTSIZE', (0, 1), (-1, -1), 7),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    story.append(t)
            story.append(Spacer(1, 12))
            
    story.append(Spacer(1, 12))
    
    # 5. Recommendations
    story.append(Paragraph("Recommendations", styles["Heading2"]))
    if not report.recommendations:
        story.append(Paragraph("No recommendations.", styles["BodyText"]))
    else:
        for item in report.recommendations:
            story.append(Paragraph(f"• {html.escape(item)}", styles["BodyText"]))
    story.append(Spacer(1, 12))
    
    # 6. Evidence Tables (Inventory)
    story.append(PageBreak())
    story.append(Paragraph("Evidence Tables", styles["Heading1"]))
    
    inventory_keys = [
        "installed_software", "processes", "services", "startup_entries", 
        "scheduled_tasks", "user_accounts", "usb_history", "event_logs", 
        "network_connections", "recent_files", "downloads"
    ]
    
    for key in inventory_keys:
        value = report.inventory.get(key, [])
        if isinstance(value, list) and value:
            story.append(Paragraph(html.escape(key.replace('_', ' ').title()), styles["Heading2"]))
            
            keys_to_show = []
            for row in value[:30]:
                if isinstance(row, dict):
                    for k in row.keys():
                        if k not in keys_to_show:
                            keys_to_show.append(k)
                        if len(keys_to_show) >= 6:
                            break
                if len(keys_to_show) >= 6:
                    break
                    
            if not keys_to_show:
                continue
                
            table_data = [[html.escape(labelize(k)) for k in keys_to_show]]
            limit = 25
            for row in value[:limit]:
                if isinstance(row, dict):
                    row_cells = []
                    for k in keys_to_show:
                        val = row.get(k, "")
                        if isinstance(val, (dict, list)):
                            val = json.dumps(val, ensure_ascii=False, default=str)
                        val_str = str(val)
                        if len(val_str) > 100:
                            val_str = val_str[:97] + "..."
                        row_cells.append(Paragraph(html.escape(val_str), styles["Small"]))
                    table_data.append(row_cells)
            
            if len(value) > limit:
                msg = f"Showing {limit} of {len(value)} records. Full data in JSON."
                table_data.append([Paragraph(html.escape(msg), styles["Small"])] + [""] * (len(keys_to_show) - 1))
                
            col_width = 7.0 * inch / len(keys_to_show)
            t = Table(table_data, colWidths=[col_width]*len(keys_to_show), repeatRows=1)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#102033")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('TOPPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")])
            ]))
            story.append(t)
            story.append(Spacer(1, 12))

    # 7. Forensic Timeline
    story.append(PageBreak())
    story.append(Paragraph("Forensic Timeline", styles["Heading1"]))
    timeline_rows = [
        {
            "timestamp": item.timestamp,
            "source": item.source,
            "type": item.event_type,
            "description": item.description,
        }
        for item in report.timeline[:200]
    ]
    
    if timeline_rows:
        keys_to_show = ["timestamp", "source", "type", "description"]
        table_data = [[html.escape(labelize(k)) for k in keys_to_show]]
        for row in timeline_rows:
            row_cells = []
            for k in keys_to_show:
                val = row.get(k, "")
                val_str = str(val)
                if len(val_str) > 150:
                    val_str = val_str[:147] + "..."
                row_cells.append(Paragraph(html.escape(val_str), styles["Small"]))
            table_data.append(row_cells)
            
        t = Table(table_data, colWidths=[1.2*inch, 1.0*inch, 1.0*inch, 3.8*inch], repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#102033")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTSIZE', (0, 1), (-1, -1), 7),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")])
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No timeline events.", styles["BodyText"]))

    try:
        doc.build(story)
    except Exception:
        path.write_bytes(minimal_pdf(pdf_fallback_text(report)))


def pdf_fallback_text(report: CaseReport) -> str:
    lines = [
        report.case_name,
        "",
        f"Host: {report.host}",
        f"Analyst: {report.metadata.get('analyst', '') or 'Not specified'}",
        f"Started: {report.started_at}",
        f"Completed: {report.completed_at}",
        f"Duration: {format_duration(report.metadata.get('duration_seconds', 0))}",
        "",
        "Executive Summary",
        executive_summary(report),
        "",
        "Findings",
    ]
    if report.findings:
        for finding in sorted(report.findings, key=lambda f: RISK_ORDER.get(f.risk, 0), reverse=True)[:12]:
            lines.append(f"- {finding.risk}: {finding.title}")
            lines.append(f"  {finding.description}")
    else:
        lines.append("- No findings generated.")
    lines.extend(["", "Recommendations"])
    lines.extend(f"- {item}" for item in report.recommendations[:8])
    return "\n".join(lines)


def minimal_pdf(text: str) -> bytes:
    lines = []
    for raw_line in text.splitlines() or [text]:
        lines.extend(textwrap.wrap(raw_line, width=82) or [""])
    lines = lines[:42]
    commands = ["BT /F1 11 Tf 72 730 Td 14 TL"]
    for index, line in enumerate(lines):
        escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        if index == 0:
            commands.append(f"({escaped}) Tj")
        else:
            commands.append(f"T* ({escaped}) Tj")
    commands.append("ET")
    stream = "\n".join(commands)
    objects = [
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj",
        "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
        f"5 0 obj << /Length {len(stream)} >> stream\n{stream}\nendstream endobj",
    ]
    pdf = "%PDF-1.4\n"
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf.encode("latin-1")))
        pdf += obj + "\n"
    xref = len(pdf.encode("latin-1"))
    pdf += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"
    for offset in offsets[1:]:
        pdf += f"{offset:010d} 00000 n \n"
    pdf += f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF"
    return pdf.encode("latin-1", errors="replace")