from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from .models import Finding, TimelineEvent
from .utils import EXECUTABLE_EXTENSIONS, file_metadata, load_json, normalize_text, ps_json

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

try:
    import yara
except Exception:  # pragma: no cover
    yara = None


SUSPICIOUS_DIRS = ["\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\", "\\downloads\\"]
SUSPICIOUS_NAMES = ["update", "svchost", "chrome", "invoice", "payload", "loader", "rat", "miner"]


class Analyzer:
    def __init__(self, ioc_path: Path, rules_dir: Path, vt_api_key: str = "", vt_enabled: bool = False) -> None:
        self.iocs = load_json(ioc_path, {"hashes": [], "domains": [], "ips": [], "filenames": []})
        self.rules_dir = rules_dir
        self.vt_api_key = vt_api_key
        self.vt_enabled = vt_enabled

    def analyze(self, inventory: dict[str, Any], email: dict[str, Any]) -> tuple[list[Finding], list[TimelineEvent], list[str]]:
        findings: list[Finding] = []
        timeline: list[TimelineEvent] = []
        findings.extend(self.suspicious_executables(inventory, email))
        findings.extend(self.unsigned_binaries(inventory))
        findings.extend(self.persistence(inventory))
        findings.extend(self.ioc_matches(inventory, email))
        findings.extend(self.yara_matches(inventory, email))
        findings.extend(self.network_findings(inventory))
        findings.extend(self.email_findings(email))
        if self.vt_enabled and self.vt_api_key:
            findings.extend(self.virustotal_findings(inventory, email))
        timeline.extend(self.timeline(inventory, email, findings))
        recommendations = self.recommendations(findings)
        return findings, timeline, recommendations

    def executable_artifacts(self, inventory: dict[str, Any], email: dict[str, Any]) -> list[dict[str, Any]]:
        artifacts: list[dict[str, Any]] = []
        for proc in inventory.get("processes", []):
            path = proc.get("exe") or proc.get("Path") or proc.get("path")
            if path:
                meta = proc.get("file") or file_metadata(path, hash_content=False)
                meta["source"] = "process"
                meta["pid"] = proc.get("pid") or proc.get("Id")
                artifacts.append(meta)
        for item in inventory.get("downloads", []) + email.get("suspicious_attachments", []):
            if str(item.get("suffix", "")).lower() in EXECUTABLE_EXTENSIONS:
                artifacts.append({**item, "source": "file_artifact"})
        return artifacts

    def suspicious_executables(self, inventory: dict[str, Any], email: dict[str, Any]) -> list[Finding]:
        evidence = []
        for item in self.executable_artifacts(inventory, email):
            path = normalize_text(item.get("path"))
            name = normalize_text(item.get("name"))
            if any(d in path for d in SUSPICIOUS_DIRS) and any(n in name for n in SUSPICIOUS_NAMES):
                evidence.append(item)
        if not evidence:
            return []
        return [
            Finding(
                title="Suspicious executable placement or naming",
                risk="High",
                category="Malware Assessment",
                description="Executable artifacts were observed in user-writable locations with names commonly abused for masquerading or delivery.",
                evidence=evidence[:50],
                recommendation="Validate file reputation, isolate affected endpoints if active execution is confirmed, and preserve copies for malware analysis.",
            )
        ]

    def unsigned_binaries(self, inventory: dict[str, Any]) -> list[Finding]:
        paths = []
        for proc in inventory.get("processes", []):
            path = proc.get("exe") or proc.get("Path")
            if path and str(path).lower().endswith(tuple(EXECUTABLE_EXTENSIONS)):
                paths.append(path)
        if not paths:
            return []
        quoted = ",".join("'" + str(p).replace("'", "''") + "'" for p in paths[:80])
        results = ps_json(f"{quoted}.Split(',') | ForEach-Object {{ Get-AuthenticodeSignature $_ | Select-Object Path,Status,SignerCertificate }}", timeout=90)
        evidence = [row for row in results if str(row.get("Status", "")).lower() not in {"valid"}]
        if not evidence:
            return []
        return [
            Finding(
                title="Unsigned or invalid-signature binaries",
                risk="Medium",
                category="Executable Trust",
                description="One or more executable files lack a valid Authenticode signature.",
                evidence=evidence[:50],
                recommendation="Prioritize unsigned binaries running from user-writable paths for containment and reverse-engineering triage.",
            )
        ]

    def persistence(self, inventory: dict[str, Any]) -> list[Finding]:
        evidence = []
        evidence.extend(inventory.get("startup_entries", []))
        for svc in inventory.get("services", []):
            path = normalize_text(svc.get("PathName"))
            if any(d in path for d in SUSPICIOUS_DIRS):
                evidence.append({"type": "service", **svc})
        for task in inventory.get("scheduled_tasks", []):
            text = normalize_text(task)
            if any(d.replace("\\", "") in text for d in SUSPICIOUS_DIRS):
                evidence.append({"type": "scheduled_task", **task})
        if not evidence:
            return []
        risk = "High" if any("appdata" in normalize_text(x) or "temp" in normalize_text(x) for x in evidence) else "Medium"
        return [
            Finding(
                title="Persistence mechanisms identified",
                risk=risk,
                category="Persistence",
                description="Autorun, service, or scheduled task persistence artifacts were found.",
                evidence=evidence[:75],
                recommendation="Review each autorun entry, verify business justification, and disable malicious persistence after evidence preservation.",
            )
        ]

    def ioc_matches(self, inventory: dict[str, Any], email: dict[str, Any]) -> list[Finding]:
        evidence = []
        hashes = {normalize_text(x) for x in self.iocs.get("hashes", [])}
        filenames = {normalize_text(x) for x in self.iocs.get("filenames", [])}
        ips = {normalize_text(x) for x in self.iocs.get("ips", [])}
        for collection in [inventory.get("downloads", []), email.get("suspicious_attachments", [])]:
            for item in collection:
                if normalize_text(item.get("name")) in filenames or normalize_text(item.get("md5")) in hashes or normalize_text(item.get("sha256")) in hashes:
                    evidence.append(item)
        for conn in inventory.get("network_connections", []):
            if any(ip in normalize_text(conn) for ip in ips):
                evidence.append({"type": "network_ioc", **conn})
        if not evidence:
            return []
        return [
            Finding(
                title="IOC match detected",
                risk="Critical",
                category="IOC Matching",
                description="Collected artifacts matched configured indicators of compromise.",
                evidence=evidence[:100],
                recommendation="Treat matched indicators as incident evidence, scope laterally, and preserve original files/logs.",
            )
        ]

    def yara_matches(self, inventory: dict[str, Any], email: dict[str, Any]) -> list[Finding]:
        if not yara or not self.rules_dir.exists():
            return []
        rule_files = list(self.rules_dir.glob("*.yar")) + list(self.rules_dir.glob("*.yara"))
        if not rule_files:
            return []
        try:
            rules = yara.compile(filepaths={p.stem: str(p) for p in rule_files})
        except Exception:
            return []
        evidence = []
        for item in self.executable_artifacts(inventory, email)[:300]:
            path = item.get("path")
            if path and Path(path).exists():
                try:
                    matches = rules.match(str(path), timeout=10)
                    if matches:
                        evidence.append({"path": path, "matches": [str(m) for m in matches], "source": item.get("source")})
                except Exception:
                    continue
        if not evidence:
            return []
        return [
            Finding(
                title="YARA rule match",
                risk="High",
                category="Malware Assessment",
                description="One or more files matched local YARA detection rules.",
                evidence=evidence,
                recommendation="Quarantine only after forensic capture; submit matched samples to malware analysis workflow.",
            )
        ]

    def network_findings(self, inventory: dict[str, Any]) -> list[Finding]:
        evidence = []
        for conn in inventory.get("network_connections", []):
            remote = normalize_text(conn.get("remote") or f"{conn.get('RemoteAddress')}:{conn.get('RemotePort')}")
            if remote and not remote.startswith(("127.", "::1", "0.0.0.0")) and any(port in remote for port in [":4444", ":5555", ":6667", ":1337"]):
                evidence.append(conn)
        if not evidence:
            return []
        return [
            Finding(
                title="Suspicious network connection",
                risk="Medium",
                category="Network",
                description="Connections were observed to ports often associated with remote shells, IRC, or malware tooling.",
                evidence=evidence[:50],
                recommendation="Correlate remote endpoints with firewall, proxy, DNS, and EDR telemetry.",
            )
        ]

    def email_findings(self, email: dict[str, Any]) -> list[Finding]:
        evidence = list(email.get("phishing_indicators", []))
        for item in email.get("suspicious_attachments", []):
            if str(item.get("suffix", "")).lower() in {".docm", ".xlsm", ".iso", ".img", ".scr", ".js", ".vbs"}:
                evidence.append({"indicator": "risky attachment type", "artifact": item})
        if not evidence:
            return []
        return [
            Finding(
                title="Suspicious email or attachment artifacts",
                risk="High",
                category="Email Artifact Analysis",
                description="Mail-adjacent artifacts include risky attachment types or social-engineering filename patterns.",
                evidence=evidence[:100],
                recommendation="Correlate with mailbox audit logs, headers, URL rewrites, and user-reporting data.",
            )
        ]

    def virustotal_findings(self, inventory: dict[str, Any], email: dict[str, Any]) -> list[Finding]:
        if not requests:
            return []
        evidence = []
        headers = {"x-apikey": self.vt_api_key}
        for item in self.executable_artifacts(inventory, email)[:25]:
            sha256 = item.get("sha256")
            if not sha256:
                path = item.get("path")
                if path and Path(path).exists():
                    sha256 = file_metadata(path).get("sha256")
            if not sha256:
                continue
            try:
                response = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=headers, timeout=20)
                if response.status_code == 200:
                    stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    if stats.get("malicious", 0) or stats.get("suspicious", 0):
                        evidence.append({"sha256": sha256, "vt_stats": stats, "path": item.get("path")})
            except Exception:
                continue
        if not evidence:
            return []
        return [
            Finding(
                title="VirusTotal detections",
                risk="High",
                category="Reputation",
                description="VirusTotal reported malicious or suspicious detections for submitted hashes.",
                evidence=evidence,
                recommendation="Use reputation data as supporting evidence, not sole proof; preserve and analyze matched samples.",
            )
        ]

    def timeline(self, inventory: dict[str, Any], email: dict[str, Any], findings: list[Finding]) -> list[TimelineEvent]:
        events: list[TimelineEvent] = []
        for item in inventory.get("downloads", []) + inventory.get("recent_files", []) + email.get("suspicious_attachments", []):
            modified = item.get("modified")
            if modified:
                events.append(TimelineEvent(str(modified), item.get("source", "filesystem"), "file_modified", item.get("path", ""), item))
        for evt in inventory.get("event_logs", []):
            ts = evt.get("TimeCreated")
            if ts:
                events.append(TimelineEvent(str(ts), evt.get("LogName", "eventlog"), str(evt.get("Id", "")), str(evt.get("Message", ""))[:300], evt))
        for finding in findings:
            events.append(TimelineEvent("", "analysis", finding.category, finding.title, {"risk": finding.risk}))
        return sorted(events, key=lambda x: x.timestamp or "9999")

    def recommendations(self, findings: list[Finding]) -> list[str]:
        base = [
            "Preserve original evidence and maintain a clear chain of custody.",
            "Run collection from an administrator PowerShell session for complete registry, event log, service, and USB coverage.",
            "Correlate host artifacts with EDR, SIEM, DNS, proxy, and firewall telemetry.",
        ]
        if any(f.risk in {"Critical", "High"} for f in findings):
            base.insert(0, "Contain affected hosts before remediation when high-confidence malicious activity is confirmed.")
        return base
