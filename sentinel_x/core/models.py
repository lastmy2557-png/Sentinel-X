"""
Core domain models and enumerations for Sentinel-X.
Covers NormalizedSecurityEvent, MitreReference, DetectionRule, Alert, Incident,
IncidentNote, and TimelineEntry with strict validation.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from sentinel_x.core.exceptions import ValidationError

MITRE_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def normalize_timestamp(ts: Optional[str | datetime]) -> str:
    """Normalize a timestamp string or datetime object into UTC ISO-8601 format."""
    if ts is None:
        return utc_now_iso()
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        else:
            ts = ts.astimezone(timezone.utc)
        return ts.isoformat()

    raw = str(ts).strip()
    if not raw:
        return utc_now_iso()

    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat()
    except ValueError:
        pass

    # Common syslog / web log formats
    common_formats = [
        "%Y-%m-%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%b %d %H:%M:%S",
    ]
    for fmt in common_formats:
        try:
            dt = datetime.strptime(raw, fmt)
            if fmt == "%b %d %H:%M:%S":
                dt = dt.replace(year=datetime.now(timezone.utc).year, tzinfo=timezone.utc)
            elif dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue

    raise ValidationError(f"Unrecognized timestamp format: {ts!r}")


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def weight(self) -> int:
        weights = {
            Severity.INFO: 10,
            Severity.LOW: 20,
            Severity.MEDIUM: 30,
            Severity.HIGH: 40,
            Severity.CRITICAL: 50,
        }
        return weights[self]

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        try:
            return cls(value.strip().upper())
        except (ValueError, AttributeError) as exc:
            raise ValidationError(f"Invalid severity '{value}'.") from exc


class EventCategory(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    NETWORK = "NETWORK"
    PROCESS = "PROCESS"
    FILE = "FILE"
    WEB = "WEB"
    SYSTEM = "SYSTEM"
    SECURITY_ALERT = "SECURITY_ALERT"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, value: str) -> "EventCategory":
        try:
            return cls(value.strip().upper())
        except (ValueError, AttributeError) as exc:
            raise ValidationError(f"Invalid event category '{value}'.") from exc


class AlertStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

    @classmethod
    def from_str(cls, value: str) -> "AlertStatus":
        try:
            return cls(value.strip().upper())
        except (ValueError, AttributeError) as exc:
            raise ValidationError(f"Invalid alert status '{value}'.") from exc


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"

    @classmethod
    def from_str(cls, value: str) -> "IncidentStatus":
        try:
            return cls(value.strip().upper())
        except (ValueError, AttributeError) as exc:
            raise ValidationError(f"Invalid incident status '{value}'.") from exc


@dataclass(frozen=True)
class MitreReference:
    """Official MITRE ATT&CK Technique & Tactic mapping."""

    technique_id: str
    technique_name: str
    tactic: str
    url: str = ""

    def __post_init__(self) -> None:
        if not MITRE_TECHNIQUE_ID_RE.match(self.technique_id):
            raise ValidationError(
                f"Invalid MITRE ATT&CK Technique ID '{self.technique_id}'. "
                "Expected format Txxxx or Txxxx.xxx."
            )
        if not self.technique_name.strip() or not self.tactic.strip():
            raise ValidationError("MITRE technique_name and tactic cannot be empty.")

    def to_dict(self) -> Dict[str, str]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "url": self.url
            or f"https://attack.mitre.org/techniques/{self.technique_id.replace('.', '/')}/",
        }


@dataclass
class NormalizedSecurityEvent:
    """Normalized security telemetry event stored and analyzed by Sentinel-X."""

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=utc_now_iso)
    source_type: str = "generic"
    source_host: str = "unknown"
    source_ip: str = ""
    destination_ip: str = ""
    user: str = ""
    action: str = "event"
    outcome: str = "unknown"
    category: EventCategory = EventCategory.UNKNOWN
    severity: Severity = Severity.INFO
    message: str = ""
    raw_log: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_sample: bool = False

    def __post_init__(self) -> None:
        self.timestamp = normalize_timestamp(self.timestamp)
        if isinstance(self.category, str):
            self.category = EventCategory.from_str(self.category)
        if isinstance(self.severity, str):
            self.severity = Severity.from_str(self.severity)
        if not self.event_id or not self.event_id.strip():
            raise ValidationError("event_id cannot be empty.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source_type": self.source_type,
            "source_host": self.source_host,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "user": self.user,
            "action": self.action,
            "outcome": self.outcome,
            "category": self.category.value,
            "severity": self.severity.value,
            "message": self.message,
            "raw_log": self.raw_log,
            "metadata": self.metadata,
            "is_sample": bool(self.is_sample),
        }


@dataclass
class DetectionRule:
    """Configurable rule for rule-based and correlation threat detection."""

    rule_id: str
    name: str
    description: str
    severity: Severity
    mitre: MitreReference
    conditions: Dict[str, Any]
    explanation_template: str
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.rule_id or not self.rule_id.strip():
            raise ValidationError("rule_id cannot be empty.")
        if not self.name or not self.name.strip():
            raise ValidationError("Detection rule name cannot be empty.")
        if isinstance(self.severity, str):
            self.severity = Severity.from_str(self.severity)
        if not isinstance(self.conditions, dict) or not self.conditions:
            raise ValidationError(f"DetectionRule '{self.rule_id}' must define conditions.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "enabled": self.enabled,
            "mitre": self.mitre.to_dict(),
            "conditions": self.conditions,
            "explanation_template": self.explanation_template,
        }


@dataclass
class Alert:
    """Security alert generated by the Threat Detection Engine."""

    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    rule_name: str = ""
    severity: Severity = Severity.MEDIUM
    status: AlertStatus = AlertStatus.NEW
    created_at: str = field(default_factory=utc_now_iso)
    title: str = ""
    explanation: str = ""
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    mitre_tactic: str = ""
    evidence_event_ids: List[str] = field(default_factory=list)
    evidence_summary: Dict[str, Any] = field(default_factory=dict)
    incident_id: Optional[str] = None
    is_sample: bool = False

    def __post_init__(self) -> None:
        self.created_at = normalize_timestamp(self.created_at)
        if isinstance(self.severity, str):
            self.severity = Severity.from_str(self.severity)
        if isinstance(self.status, str):
            self.status = AlertStatus.from_str(self.status)
        if self.mitre_technique_id and not MITRE_TECHNIQUE_ID_RE.match(self.mitre_technique_id):
            raise ValidationError(f"Invalid MITRE technique ID '{self.mitre_technique_id}'.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "status": self.status.value,
            "created_at": self.created_at,
            "title": self.title,
            "explanation": self.explanation,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "mitre_tactic": self.mitre_tactic,
            "evidence_event_ids": list(self.evidence_event_ids),
            "evidence_summary": self.evidence_summary,
            "incident_id": self.incident_id,
            "is_sample": bool(self.is_sample),
        }


@dataclass
class IncidentNote:
    """Analyst investigation note attached to an Incident."""

    note_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    author: str = "soc_analyst"
    content: str = ""
    created_at: str = field(default_factory=utc_now_iso)

    def __post_init__(self) -> None:
        self.created_at = normalize_timestamp(self.created_at)
        if not self.content or not self.content.strip():
            raise ValidationError("Incident note content cannot be empty.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "note_id": self.note_id,
            "incident_id": self.incident_id,
            "author": self.author,
            "content": self.content,
            "created_at": self.created_at,
        }


@dataclass
class TimelineEntry:
    """Chronological timeline entry for an Incident."""

    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    timestamp: str = field(default_factory=utc_now_iso)
    entry_type: str = "STATUS_CHANGE"
    actor: str = "system"
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.timestamp = normalize_timestamp(self.timestamp)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "incident_id": self.incident_id,
            "timestamp": self.timestamp,
            "entry_type": self.entry_type,
            "actor": self.actor,
            "description": self.description,
            "metadata": self.metadata,
        }


@dataclass
class Incident:
    """Security Incident aggregating alerts, events, investigation notes, and timeline."""

    incident_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: Severity = Severity.HIGH
    status: IncidentStatus = IncidentStatus.OPEN
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    resolved_at: Optional[str] = None
    resolution_summary: str = ""
    assigned_to: str = "unassigned"
    linked_event_ids: List[str] = field(default_factory=list)
    linked_alert_ids: List[str] = field(default_factory=list)
    notes: List[IncidentNote] = field(default_factory=list)
    timeline: List[TimelineEntry] = field(default_factory=list)
    is_sample: bool = False

    def __post_init__(self) -> None:
        if not self.title or not self.title.strip():
            raise ValidationError("Incident title cannot be empty.")
        self.created_at = normalize_timestamp(self.created_at)
        self.updated_at = normalize_timestamp(self.updated_at)
        if self.resolved_at:
            self.resolved_at = normalize_timestamp(self.resolved_at)
        if isinstance(self.severity, str):
            self.severity = Severity.from_str(self.severity)
        if isinstance(self.status, str):
            self.status = IncidentStatus.from_str(self.status)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "resolved_at": self.resolved_at,
            "resolution_summary": self.resolution_summary,
            "assigned_to": self.assigned_to,
            "linked_event_ids": list(self.linked_event_ids),
            "linked_alert_ids": list(self.linked_alert_ids),
            "notes": [n.to_dict() for n in self.notes],
            "timeline": [t.to_dict() for t in self.timeline],
            "is_sample": bool(self.is_sample),
        }
