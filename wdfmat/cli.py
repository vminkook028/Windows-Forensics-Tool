from __future__ import annotations

import argparse
import os
from pathlib import Path
from datetime import datetime

from .analyzers import Analyzer
from .collectors import EmailCollector, WindowsCollector
from .models import CaseReport, utc_now
from .reporters import write_reports
from .utils import hostname


def run_case(
    case_name: str,
    output: Path,
    iocs: Path,
    rules: Path,
    virustotal: bool = False,
    vt_api_key: str = "",
    analyst: str = "",
    notes: str = "",
) -> dict[str, Path]:
    started = utc_now()
    report = CaseReport(case_name=case_name, host=hostname(), started_at=started)
    report.inventory = WindowsCollector().collect_all()
    report.email_artifacts = EmailCollector().collect_all()
    analyzer = Analyzer(ioc_path=iocs, rules_dir=rules, vt_api_key=vt_api_key or os.environ.get("VT_API_KEY", ""), vt_enabled=virustotal)
    report.findings, report.timeline, report.recommendations = analyzer.analyze(report.inventory, report.email_artifacts)
    report.completed_at = utc_now()
    report.metadata = {
        "tool": "Windows Digital Forensics and Malware Assessment Tool",
        "version": "0.1.0",
        "analyst": analyst,
        "notes": notes,
        "duration_seconds": duration_seconds(started, report.completed_at),
    }
    return write_reports(report, output)


def duration_seconds(started_at: str, completed_at: str) -> int:
    try:
        started = datetime.fromisoformat(started_at)
        completed = datetime.fromisoformat(completed_at)
        return max(0, int((completed - started).total_seconds()))
    except Exception:
        return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Windows Digital Forensics and Malware Assessment Tool")
    parser.add_argument("--case-name", default="forensic_case", help="Case name used in reports")
    parser.add_argument("--output", default="outputs", help="Output directory")
    parser.add_argument("--iocs", default="data/iocs.json", help="IOC JSON path")
    parser.add_argument("--rules", default="rules", help="YARA rules directory")
    parser.add_argument("--virustotal", action="store_true", help="Enable optional VirusTotal hash lookups")
    parser.add_argument("--vt-api-key", default="", help="VirusTotal API key, defaults to VT_API_KEY environment variable")
    parser.add_argument("--analyst", default="", help="Analyst name for report metadata")
    parser.add_argument("--notes", default="", help="Case notes for report metadata")
    args = parser.parse_args()
    paths = run_case(args.case_name, Path(args.output), Path(args.iocs), Path(args.rules), args.virustotal, args.vt_api_key, args.analyst, args.notes)
    for report_type, path in paths.items():
        print(f"{report_type}: {path}")
