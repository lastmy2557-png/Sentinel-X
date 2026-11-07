"""
Threat Detection Engine and Rule Management for Sentinel-X (Sections 4.2 & 4.3).
Supports configurable single-event rules and time-window correlation rules,
attaches official MITRE ATT&CK references, explains detections with event evidence,
and allows dry-run testing of rules.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from sentinel_x.core.audit import AuditLogger
from sentinel_x.core.database import DatabaseManager
from sentinel_x.core.exceptions import DetectionError
from sentinel_x.core.models import (
    Alert,
    AlertStatus,
    DetectionRule,
    NormalizedSecurityEvent,
    Severity,
)
from sentinel_x.detection.mitre import get_mitre_reference, resolve_mitre_reference


def build_default_rules() -> List[DetectionRule]:
    """Return built-in baseline detection rules mapped to official MITRE ATT&CK techniques."""
    return [
        DetectionRule(
            rule_id="SX-DET-001",
            name="SSH Password Brute Force (Correlation)",
            description=(
                "Detects multiple failed SSH authentication attempts from the same source IP "
                "within a short time window. Scope limitation: Detects volumetric password guessing "
                "on SSH; does not detect distributed low-and-slow attacks across many IPs."
            ),
            severity=Severity.HIGH,
            mitre=get_mitre_reference("T1110.001"),
            conditions={
                "category": "AUTHENTICATION",
                "action": "ssh_login",
                "outcome": "failure",
                "correlation": {
                    "group_by": "source_ip",
                    "threshold": 3,
                    "window_seconds": 300,
                },
            },
            explanation_template=(
                "Detected {match_count} failed SSH login attempts from source IP '{source_ip}' "
                "targeting host '{source_host}' (last user '{user}') within 300 seconds."
            ),
            enabled=True,
        ),
        DetectionRule(
            rule_id="SX-DET-002",
            name="Web Application SQL Injection / Path Traversal Probe",
            description=(
                "Detects common SQL injection or directory traversal payloads in HTTP requests. "
                "Scope limitation: Pattern-based detection on URI/message; encoded or encrypted "
                "body payloads require deeper inspection."
            ),
            severity=Severity.HIGH,
            mitre=get_mitre_reference("T1190"),
            conditions={
                "category": "WEB",
                "message_regex": r"(?i)(union\s+select|\.\./\.\./|/etc/passwd|information_schema|sleep\(\d+\))",
            },
            explanation_template=(
                "Suspicious web exploit pattern detected from '{source_ip}' on host '{source_host}': {message}"
            ),
            enabled=True,
        ),
        DetectionRule(
            rule_id="SX-DET-003",
            name="Unauthorized Sudo Privilege Escalation Attempt",
            description=(
                "Detects failed sudo invocations or attempts by unauthorized users to run commands as root. "
                "Scope limitation: Covers standard sudo log telemetry."
            ),
            severity=Severity.HIGH,
            mitre=get_mitre_reference("T1548.003"),
            conditions={
                "action": "privilege_escalation_sudo",
                "outcome": "failure",
            },
            explanation_template=(
                "Unauthorized or failed sudo privilege escalation by user '{user}' on '{source_host}': {message}"
            ),
            enabled=True,
        ),
        DetectionRule(
            rule_id="SX-DET-004",
            name="Credential File Access (/etc/shadow or /etc/passwd)",
            description=(
                "Detects commands or file events accessing sensitive OS credential files (/etc/shadow). "
                "Scope limitation: Relies on process/command or file telemetry visibility."
            ),
            severity=Severity.CRITICAL,
            mitre=get_mitre_reference("T1003.008"),
            conditions={
                "message_regex": r"(?i)(/etc/shadow|/etc/gshadow)",
            },
            explanation_template=(
                "Critical access attempt to OS credential store on '{source_host}' by user '{user}': {message}"
            ),
            enabled=True,
        ),
        DetectionRule(
            rule_id="SX-DET-005",
            name="Suspicious Reverse Shell / Shell Execution Pattern",
            description=(
                "Detects common Unix reverse shell one-liners (bash -i, /dev/tcp/, nc -e). "
                "Scope limitation: Detects known command patterns; obfuscated scripts may evade regex."
            ),
            severity=Severity.CRITICAL,
            mitre=get_mitre_reference("T1059.004"),
            conditions={
                "message_regex": r"(?i)(bash\s+-i|/dev/tcp/|nc\s+-e\s+/bin/(?:ba)?sh|mkfifo\s+/tmp/)",
            },
            explanation_template=(
                "Suspicious Unix shell execution indicator on '{source_host}' (user '{user}'): {message}"
            ),
            enabled=True,
        ),
    ]


class ThreatDetectionEngine:
    """Evaluates normalized security events against configurable detection rules."""

    def __init__(
        self,
        db: DatabaseManager,
        audit_logger: Optional[AuditLogger] = None,
        on_alert_generated: Optional[Callable[[Alert], None]] = None,
        load_defaults: bool = True,
    ) -> None:
        self.db = db
        self.audit_logger = audit_logger
        self.on_alert_generated = on_alert_generated
        if load_defaults and not self.db.list_rules(enabled_only=False):
            for rule in build_default_rules():
                self.db.save_rule(rule)

    def register_rule(self, rule: DetectionRule) -> None:
        """Add or update a detection rule in persistent storage."""
        self.db.save_rule(rule)
        if self.audit_logger:
            self.audit_logger.record(
                action="DETECTION_RULE_REGISTERED",
                target=rule.rule_id,
                details={"name": rule.name, "severity": rule.severity.value, "enabled": rule.enabled},
            )

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> DetectionRule:
        """Enable or disable an existing detection rule."""
        rule = self.db.get_rule(rule_id)
        if not rule:
            raise DetectionError(f"Detection rule '{rule_id}' not found.")
        rule.enabled = bool(enabled)
        self.db.save_rule(rule)
        if self.audit_logger:
            self.audit_logger.record(
                action="DETECTION_RULE_STATUS_UPDATED",
                target=rule_id,
                details={"enabled": rule.enabled},
            )
        return rule

    def load_rules_from_json(self, json_path: Path) -> List[DetectionRule]:
        """Load and validate detection rules from a JSON configuration file."""
        if not json_path.is_file():
            raise DetectionError(f"Rules file not found: {json_path}")
        try:
            raw_list = json.loads(json_path.read_text(encoding="utf-8"))
            if not isinstance(raw_list, list):
                raise DetectionError("Rules JSON file must contain a top-level array of rules.")
        except json.JSONDecodeError as exc:
            raise DetectionError(f"Invalid JSON in rules file: {exc}") from exc

        loaded: List[DetectionRule] = []
        for item in raw_list:
            mitre_info = item.get("mitre", {})
            mitre_ref = resolve_mitre_reference(
                technique_id=mitre_info.get("technique_id", ""),
                technique_name=mitre_info.get("technique_name"),
                tactic=mitre_info.get("tactic"),
            )
            rule = DetectionRule(
                rule_id=item["rule_id"],
                name=item["name"],
                description=item.get("description", ""),
                severity=Severity.from_str(item.get("severity", "MEDIUM")),
                mitre=mitre_ref,
                conditions=item["conditions"],
                explanation_template=item.get(
                    "explanation_template", "Rule {rule_name} matched event {event_id}"
                ),
                enabled=bool(item.get("enabled", True)),
            )
            self.register_rule(rule)
            loaded.append(rule)
        return loaded

    def load_sigma_rule(self, yaml_path: Path | str) -> DetectionRule:
        """Load, validate, and register a Sigma YAML rule file."""
        from sentinel_x.detection.sigma import load_sigma_rule_file

        rule = load_sigma_rule_file(yaml_path)
        self.register_rule(rule)
        return rule

    def evaluate_event(self, event: NormalizedSecurityEvent) -> List[Alert]:
        """Evaluate a newly ingested event against all enabled detection rules."""
        rules = self.db.list_rules(enabled_only=True)
        generated_alerts: List[Alert] = []

        for rule in rules:
            if not self._matches_base_conditions(event, rule.conditions):
                continue

            correlation_cfg = rule.conditions.get("correlation")
            if isinstance(correlation_cfg, dict):
                alert = self._evaluate_correlation(event, rule, correlation_cfg, persist=True)
                if alert is not None:
                    generated_alerts.append(alert)
            else:
                alert = self._build_alert(
                    rule=rule,
                    trigger_event=event,
                    evidence_events=[event],
                )
                self.db.save_alert(alert)
                if self.on_alert_generated:
                    self.on_alert_generated(alert)
                generated_alerts.append(alert)

        return generated_alerts

    def test_rule(
        self, rule: DetectionRule, sample_events: List[NormalizedSecurityEvent]
    ) -> List[Alert]:
        """
        Dry-run a detection rule against a list of in-memory events without writing alerts to DB.
        Allows SOC engineers to test and tune detection rules safely.
        """
        matched_events = [
            ev for ev in sample_events if self._matches_base_conditions(ev, rule.conditions)
        ]
        if not matched_events:
            return []

        correlation_cfg = rule.conditions.get("correlation")
        if isinstance(correlation_cfg, dict):
            group_by = str(correlation_cfg.get("group_by", "source_ip"))
            threshold = int(correlation_cfg.get("threshold", 3))
            groups: Dict[str, List[NormalizedSecurityEvent]] = {}
            for ev in matched_events:
                key = str(getattr(ev, group_by, ""))
                if key:
                    groups.setdefault(key, []).append(ev)
            alerts: List[Alert] = []
            for _, group_evs in groups.items():
                if len(group_evs) >= threshold:
                    alerts.append(
                        self._build_alert(
                            rule=rule,
                            trigger_event=group_evs[-1],
                            evidence_events=group_evs,
                        )
                    )
            return alerts

        return [
            self._build_alert(rule=rule, trigger_event=ev, evidence_events=[ev])
            for ev in matched_events
        ]

    @staticmethod
    def _matches_base_conditions(
        event: NormalizedSecurityEvent, conditions: Dict[str, Any]
    ) -> bool:
        if "category" in conditions:
            if event.category.value != str(conditions["category"]).upper():
                return False
        if "action" in conditions:
            if event.action.lower() != str(conditions["action"]).lower():
                return False
        if "outcome" in conditions:
            if event.outcome.lower() != str(conditions["outcome"]).lower():
                return False
        if "source_ip" in conditions:
            if event.source_ip != str(conditions["source_ip"]):
                return False
        if "user" in conditions:
            if event.user != str(conditions["user"]):
                return False
        if "message_contains" in conditions:
            needle = str(conditions["message_contains"]).lower()
            if needle not in event.message.lower() and needle not in event.raw_log.lower():
                return False
        if "message_regex" in conditions:
            pattern = str(conditions["message_regex"])
            if not (re.search(pattern, event.message) or re.search(pattern, event.raw_log)):
                return False
        return True

    def _evaluate_correlation(
        self,
        event: NormalizedSecurityEvent,
        rule: DetectionRule,
        correlation_cfg: Dict[str, Any],
        persist: bool = True,
    ) -> Optional[Alert]:
        group_by = str(correlation_cfg.get("group_by", "source_ip"))
        threshold = int(correlation_cfg.get("threshold", 3))
        window_seconds = int(correlation_cfg.get("window_seconds", 300))

        entity_val = getattr(event, group_by, "")
        if not entity_val:
            return None

        # Fetch recent events matching the entity
        recent_events = self.db.query_events(
            include_samples=event.is_sample,
            only_samples=event.is_sample,
            limit=500,
        )
        event_dt = datetime.fromisoformat(event.timestamp)
        matching_window_events: List[NormalizedSecurityEvent] = []
        for candidate in recent_events:
            if getattr(candidate, group_by, "") != entity_val:
                continue
            if not self._matches_base_conditions(candidate, rule.conditions):
                continue
            cand_dt = datetime.fromisoformat(candidate.timestamp)
            delta = abs((event_dt - cand_dt).total_seconds())
            if delta <= window_seconds:
                matching_window_events.append(candidate)

        if len(matching_window_events) < threshold:
            return None

        matching_window_events.sort(key=lambda e: e.timestamp)
        alert = self._build_alert(
            rule=rule,
            trigger_event=event,
            evidence_events=matching_window_events,
        )
        if persist:
            self.db.save_alert(alert)
            if self.on_alert_generated:
                self.on_alert_generated(alert)
        return alert

    @staticmethod
    def _build_alert(
        rule: DetectionRule,
        trigger_event: NormalizedSecurityEvent,
        evidence_events: List[NormalizedSecurityEvent],
    ) -> Alert:
        context = {
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "event_id": trigger_event.event_id,
            "source_host": trigger_event.source_host,
            "source_ip": trigger_event.source_ip or "N/A",
            "user": trigger_event.user or "N/A",
            "action": trigger_event.action,
            "outcome": trigger_event.outcome,
            "message": trigger_event.message,
            "match_count": len(evidence_events),
        }
        try:
            explanation = rule.explanation_template.format(**context)
        except KeyError:
            explanation = f"{rule.name}: matched {len(evidence_events)} event(s) on {trigger_event.source_host}."

        evidence_summary = {
            "trigger_event_id": trigger_event.event_id,
            "source_host": trigger_event.source_host,
            "source_ip": trigger_event.source_ip,
            "user": trigger_event.user,
            "matched_event_count": len(evidence_events),
            "first_timestamp": evidence_events[0].timestamp,
            "last_timestamp": evidence_events[-1].timestamp,
            "sample_messages": [e.message for e in evidence_events[:5]],
        }
        return Alert(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            severity=rule.severity,
            status=AlertStatus.NEW,
            title=f"[{rule.mitre.technique_id}] {rule.name}",
            explanation=explanation,
            mitre_technique_id=rule.mitre.technique_id,
            mitre_technique_name=rule.mitre.technique_name,
            mitre_tactic=rule.mitre.tactic,
            evidence_event_ids=[e.event_id for e in evidence_events],
            evidence_summary=evidence_summary,
            is_sample=any(e.is_sample for e in evidence_events),
        )
