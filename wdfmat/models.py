from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class EvidenceItem:
    category: str
    name: str
    path: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now)


@dataclass
class Finding:
    title: str
    risk: str
    category: str
    description: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class TimelineEvent:
    timestamp: str
    source: str
    event_type: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class CaseReport:
    case_name: str
    host: str
    started_at: str
    completed_at: str = ""
    inventory: dict[str, Any] = field(default_factory=dict)
    email_artifacts: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
