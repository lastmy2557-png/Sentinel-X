"""
Pluggable Log Parsers and Normalizer for Sentinel-X (Section 4.1).
Supports JSON logs, Linux Auth/SSH Syslog, Web Access logs (Common/Combined),
and Key-Value logs. Designed with a registry so new log formats can be added
without modifying existing code.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

from sentinel_x.core.exceptions import IngestionError
from sentinel_x.core.models import (
    EventCategory,
    NormalizedSecurityEvent,
    Severity,
    normalize_timestamp,
)

# Regex patterns for standard log formats
SYSLOG_AUTH_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[^\s]+)\s+"
    r"(?P<host>[^\s]+)\s+(?P<process>[a-zA-Z0-9_.\-/]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SSH_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>[^\s]+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>[^\s]+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
)
SUDO_CMD_RE = re.compile(
    r"(?P<user>[^\s]+)\s*:\s*TTY=[^\s]+\s*;\s*PWD=[^\s]+\s*;\s*USER=(?P<target_user>[^\s]+)\s*;\s*COMMAND=(?P<cmd>.+)$"
)
WEB_ACCESS_RE = re.compile(
    r'^(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9:]+)\s+-\s+(?P<user>[^\s]+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>[^\s]+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


class BaseLogParser(ABC):
    """Abstract base class for pluggable log format parsers."""

    format_name: str = "base"

    @abstractmethod
    def can_parse(self, raw_line: str) -> bool:
        """Return True if this parser recognizes the raw log line."""

    @abstractmethod
    def parse(self, raw_line: str, is_sample: bool = False) -> NormalizedSecurityEvent:
        """Parse and normalize a raw log line into a NormalizedSecurityEvent."""


class JsonLogParser(BaseLogParser):
    """Parses structured JSON log lines."""

    format_name = "json"

    def can_parse(self, raw_line: str) -> bool:
        stripped = raw_line.strip()
        return stripped.startswith("{") and stripped.endswith("}")

    def parse(self, raw_line: str, is_sample: bool = False) -> NormalizedSecurityEvent:
        try:
            data = json.loads(raw_line.strip())
            if not isinstance(data, dict):
                raise IngestionError("JSON log entry must be a JSON object.")
        except json.JSONDecodeError as exc:
            raise IngestionError(f"Malformed JSON log line: {exc}") from exc

        category_str = str(data.get("category", "")).upper()
        action = str(data.get("action", data.get("event_type", "event")))
        outcome = str(data.get("outcome", data.get("status", "unknown"))).lower()

        if not category_str:
            category = classify_event_category(action, str(data.get("message", "")))
        else:
            try:
                category = EventCategory.from_str(category_str)
            except Exception:
                category = EventCategory.UNKNOWN

        sev_str = str(data.get("severity", "")).upper()
        if not sev_str:
            severity = classify_event_severity(category, action, outcome, str(data.get("message", "")))
        else:
            try:
                severity = Severity.from_str(sev_str)
            except Exception:
                severity = Severity.INFO

        reserved_keys = {
            "event_id",
            "timestamp",
            "source_type",
            "source_host",
            "source_ip",
            "destination_ip",
            "user",
            "action",
            "outcome",
            "category",
            "severity",
            "message",
            "is_sample",
        }
        extra_meta = {k: v for k, v in data.items() if k not in reserved_keys}
        if isinstance(data.get("metadata"), dict):
            extra_meta.update(data["metadata"])

        kwargs: Dict[str, Any] = {
            "timestamp": normalize_timestamp(data.get("timestamp")),
            "source_type": str(data.get("source_type", "json")),
            "source_host": str(data.get("source_host", data.get("host", "unknown"))),
            "source_ip": str(data.get("source_ip", data.get("src_ip", ""))),
            "destination_ip": str(data.get("destination_ip", data.get("dst_ip", ""))),
            "user": str(data.get("user", data.get("username", ""))),
            "action": action,
            "outcome": outcome,
            "category": category,
            "severity": severity,
            "message": str(data.get("message", raw_line.strip())),
            "raw_log": raw_line.strip(),
            "metadata": extra_meta,
            "is_sample": bool(data.get("is_sample", is_sample)),
        }
        if data.get("event_id"):
            kwargs["event_id"] = str(data["event_id"])
        return NormalizedSecurityEvent(**kwargs)


class WebAccessLogParser(BaseLogParser):
    """Parses Apache/Nginx Common and Combined Web Access logs."""

    format_name = "web_access"

    def can_parse(self, raw_line: str) -> bool:
        return bool(WEB_ACCESS_RE.match(raw_line.strip()))

    def parse(self, raw_line: str, is_sample: bool = False) -> NormalizedSecurityEvent:
        from urllib.parse import unquote_plus

        match = WEB_ACCESS_RE.match(raw_line.strip())
        if not match:
            raise IngestionError("Line does not match web access log format.")
        gd = match.groupdict()
        status_code = int(gd["status"])
        raw_path = gd["path"]
        decoded_path = unquote_plus(raw_path)
        method = gd["method"]
        user = "" if gd["user"] == "-" else gd["user"]
        outcome = "failure" if status_code >= 400 else "success"

        severity = classify_event_severity(
            EventCategory.WEB, f"http_{method.lower()}", outcome, decoded_path, status_code=status_code
        )
        return NormalizedSecurityEvent(
            timestamp=normalize_timestamp(gd["timestamp"]),
            source_type="web_access",
            source_host="web-server",
            source_ip=gd["ip"],
            user=user,
            action=f"http_{method.lower()}",
            outcome=outcome,
            category=EventCategory.WEB,
            severity=severity,
            message=f"{method} {decoded_path} -> HTTP {status_code}",
            raw_log=raw_line.strip(),
            metadata={
                "http_method": method,
                "http_path": raw_path,
                "http_path_decoded": decoded_path,
                "http_status": status_code,
                "user_agent": gd.get("ua") or "",
                "referer": gd.get("referer") or "",
            },
            is_sample=is_sample,
        )


class SyslogAuthParser(BaseLogParser):
    """Parses RFC3164/ISO Syslog & Linux Auth/SSH/Sudo logs."""

    format_name = "syslog"

    def can_parse(self, raw_line: str) -> bool:
        return bool(SYSLOG_AUTH_RE.match(raw_line.strip()))

    def parse(self, raw_line: str, is_sample: bool = False) -> NormalizedSecurityEvent:
        match = SYSLOG_AUTH_RE.match(raw_line.strip())
        if not match:
            raise IngestionError("Line does not match syslog format.")
        gd = match.groupdict()
        host = gd["host"]
        process = gd["process"]
        msg = gd["message"]

        user = ""
        source_ip = ""
        action = process.lower()
        outcome = "unknown"
        category = EventCategory.SYSTEM
        metadata: Dict[str, Any] = {"process": process, "pid": gd.get("pid") or ""}

        ssh_fail = SSH_FAILED_RE.search(msg)
        ssh_ok = SSH_ACCEPTED_RE.search(msg)
        sudo_match = SUDO_CMD_RE.search(msg)

        if ssh_fail:
            user = ssh_fail.group("user")
            source_ip = ssh_fail.group("ip")
            action = "ssh_login"
            outcome = "failure"
            category = EventCategory.AUTHENTICATION
        elif ssh_ok:
            user = ssh_ok.group("user")
            source_ip = ssh_ok.group("ip")
            action = "ssh_login"
            outcome = "success"
            category = EventCategory.AUTHENTICATION
        elif sudo_match or process.lower() == "sudo":
            category = EventCategory.PROCESS
            action = "privilege_escalation_sudo"
            outcome = "failure" if "incorrect password" in msg.lower() or "not in sudoers" in msg.lower() else "success"
            if sudo_match:
                user = sudo_match.group("user")
                metadata["target_user"] = sudo_match.group("target_user")
                metadata["command"] = sudo_match.group("cmd").strip()
        else:
            ip_match = IPV4_RE.search(msg)
            if ip_match:
                source_ip = ip_match.group(0)
            category = classify_event_category(action, msg)
            if "fail" in msg.lower() or "denied" in msg.lower() or "error" in msg.lower():
                outcome = "failure"
            elif "accept" in msg.lower() or "success" in msg.lower():
                outcome = "success"

        severity = classify_event_severity(category, action, outcome, msg)
        return NormalizedSecurityEvent(
            timestamp=normalize_timestamp(gd["timestamp"]),
            source_type="syslog",
            source_host=host,
            source_ip=source_ip,
            user=user,
            action=action,
            outcome=outcome,
            category=category,
            severity=severity,
            message=msg,
            raw_log=raw_line.strip(),
            metadata=metadata,
            is_sample=is_sample,
        )


def classify_event_category(action: str, message: str) -> EventCategory:
    """Heuristically classify an event into a standard EventCategory."""
    combined = f"{action} {message}".lower()
    if any(k in combined for k in ("login", "auth", "sshd", "password", "session")):
        return EventCategory.AUTHENTICATION
    if any(k in combined for k in ("http", "GET ", "POST ", "uri", "web")):
        return EventCategory.WEB
    if any(k in combined for k in ("sudo", "exec", "command", "process", "bash", "powershell", "cmd")):
        return EventCategory.PROCESS
    if any(k in combined for k in ("firewall", "ufw", "iptables", "port", "connection", "network")):
        return EventCategory.NETWORK
    if any(k in combined for k in ("file", "chmod", "chown", "/etc/shadow", "/etc/passwd")):
        return EventCategory.FILE
    return EventCategory.SYSTEM


def classify_event_severity(
    category: EventCategory,
    action: str,
    outcome: str,
    message: str,
    status_code: int = 0,
) -> Severity:
    """Classify baseline severity of a normalized event."""
    msg_lower = message.lower()
    if any(
        indicator in msg_lower
        for indicator in (
            "/etc/shadow",
            "union select",
            "../",
            "cmd.exe",
            "/bin/sh",
            "reverse shell",
            "not in sudoers",
            " ransomware",
        )
    ):
        return Severity.HIGH
    if category == EventCategory.AUTHENTICATION and outcome == "failure":
        return Severity.MEDIUM
    if status_code in (401, 403, 500, 502, 503):
        return Severity.MEDIUM
    return Severity.LOW if outcome == "success" else Severity.INFO


class LogParserRegistry:
    """Extensible registry of log parsers."""

    def __init__(self) -> None:
        self._parsers: List[BaseLogParser] = [
            JsonLogParser(),
            WebAccessLogParser(),
            SyslogAuthParser(),
        ]

    def register(self, parser: BaseLogParser, prepend: bool = True) -> None:
        """Register a new log parser without modifying existing parsers."""
        if prepend:
            self._parsers.insert(0, parser)
        else:
            self._parsers.append(parser)

    def parse_line(self, raw_line: str, is_sample: bool = False) -> NormalizedSecurityEvent:
        """Parse a single log line using the first matching parser, or fallback to generic."""
        stripped = raw_line.strip()
        if not stripped:
            raise IngestionError("Cannot parse empty log line.")

        for parser in self._parsers:
            if parser.can_parse(stripped):
                return parser.parse(stripped, is_sample=is_sample)

        # Fallback generic normalization
        category = classify_event_category("generic", stripped)
        outcome = "failure" if ("fail" in stripped.lower() or "error" in stripped.lower()) else "unknown"
        severity = classify_event_severity(category, "generic", outcome, stripped)
        ip_match = IPV4_RE.search(stripped)
        return NormalizedSecurityEvent(
            source_type="generic",
            source_ip=ip_match.group(0) if ip_match else "",
            action="generic_log",
            outcome=outcome,
            category=category,
            severity=severity,
            message=stripped,
            raw_log=stripped,
            is_sample=is_sample,
        )
