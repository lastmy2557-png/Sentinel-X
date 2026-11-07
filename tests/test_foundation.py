"""
Unit tests for Phase 2 — Foundation (sentinel_x.core).
Tests configuration validation, secret masking, audit log injection defense,
domain models, MITRE validation, and SQLite parameterized storage (SQLi defense).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sentinel_x.core import (
    Alert,
    AlertStatus,
    AuditLogger,
    ConfigurationError,
    DatabaseManager,
    DetectionRule,
    EventCategory,
    Incident,
    IncidentNotFoundError,
    IncidentNote,
    IncidentStatus,
    MitreReference,
    NormalizedSecurityEvent,
    SentinelConfig,
    Severity,
    TimelineEntry,
    ValidationError,
)


class TestFoundation(unittest.TestCase):
    def test_config_validation_and_secret_masking(self) -> None:
        cfg = SentinelConfig.from_env(
            environ={
                "SENTINEL_ENV": "development",
                "SENTINEL_PORT": "9090",
                "SENTINEL_API_TOKEN": "super_secret_real_token_123",
                "SENTINEL_SIEM_API_KEY": "CHANGE_ME_PLACEHOLDER",
            }
        )
        self.assertEqual(cfg.port, 9090)
        self.assertEqual(cfg.api_token, "super_secret_real_token_123")
        # Placeholder should be treated as unconfigured
        self.assertEqual(cfg.siem_api_key, "")

        safe_dict = cfg.to_safe_dict()
        self.assertTrue(safe_dict["api_token_configured"])
        self.assertFalse(safe_dict["siem_configured"])
        self.assertNotIn("super_secret_real_token_123", repr(cfg))

        with self.assertRaises(ConfigurationError):
            SentinelConfig(env="invalid_env")

        with self.assertRaises(ConfigurationError):
            SentinelConfig(port=70000)

    def test_audit_logger_sanitizes_log_injection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            logger = AuditLogger(log_path)
            entry = logger.record(
                action="LOGIN_ATTEMPT\r\nFAKE_ADMIN_SUCCESS",
                actor="user1\nmalicious",
                target="/api/v1/incidents",
                status="FAILURE",
                details={"ip": "10.0.0.5"},
            )
            self.assertNotIn("\n", entry["action"])
            self.assertNotIn("\r", entry["action"])
            self.assertNotIn("\n", entry["actor"])

            lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            parsed = json.loads(lines[0])
            self.assertEqual(parsed["status"], "FAILURE")

    def test_models_and_mitre_validation(self) -> None:
        mitre = MitreReference(
            technique_id="T1110.001",
            technique_name="Brute Force: Password Guessing",
            tactic="Credential Access",
        )
        self.assertIn("T1110/001", mitre.to_dict()["url"])

        with self.assertRaises(ValidationError):
            MitreReference(
                technique_id="FAKE-9999",
                technique_name="Invalid",
                tactic="Initial Access",
            )

        ev = NormalizedSecurityEvent(
            timestamp="2026-11-06T12:00:00Z",
            source_type="auth",
            source_host="bastion-01",
            source_ip="192.0.2.50",
            user="root",
            action="ssh_login",
            outcome="failure",
            category="AUTHENTICATION",
            severity="HIGH",
            message="Failed password for root",
        )
        self.assertEqual(ev.category, EventCategory.AUTHENTICATION)
        self.assertEqual(ev.severity, Severity.HIGH)
        self.assertTrue(ev.timestamp.endswith("+00:00"))

    def test_database_crud_and_sqli_protection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DatabaseManager(Path(tmpdir) / "test.db")

            real_ev = NormalizedSecurityEvent(
                event_id="evt-real-1",
                source_host="prod-web-01",
                source_ip="198.51.100.10",
                user="admin",
                action="login",
                outcome="failure",
                category=EventCategory.AUTHENTICATION,
                severity=Severity.HIGH,
                message="Failed login for admin",
                is_sample=False,
            )
            sample_ev = NormalizedSecurityEvent(
                event_id="evt-sample-1",
                source_host="demo-host",
                source_ip="203.0.113.5",
                user="guest",
                action="ping",
                outcome="success",
                category=EventCategory.NETWORK,
                severity=Severity.LOW,
                message="Sample network ping",
                is_sample=True,
            )
            db.save_event(real_ev)
            db.save_event(sample_ev)

            # Verify SQL Injection attempt in search_query does not bypass filter or corrupt table
            sqli_payload = "' OR '1'='1'; DROP TABLE security_events; --"
            sqli_results = db.query_events(search_query=sqli_payload)
            self.assertEqual(len(sqli_results), 0)

            # Verify table still intact and sample filtering works
            real_only = db.query_events(include_samples=False)
            self.assertEqual(len(real_only), 1)
            self.assertEqual(real_only[0].event_id, "evt-real-1")

            all_events = db.query_events(include_samples=True)
            self.assertEqual(len(all_events), 2)

            # Verify Rule, Alert, and Incident persistence
            rule = DetectionRule(
                rule_id="SX-RULE-001",
                name="SSH Brute Force",
                description="Detects repeated SSH failures",
                severity=Severity.HIGH,
                mitre=MitreReference("T1110", "Brute Force", "Credential Access"),
                conditions={"action": "login", "outcome": "failure"},
                explanation_template="SSH failure detected on {source_host}",
            )
            db.save_rule(rule)
            self.assertEqual(len(db.list_rules(enabled_only=True)), 1)

            alert = Alert(
                alert_id="alt-001",
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=Severity.HIGH,
                status=AlertStatus.NEW,
                title="SSH Brute Force Alert",
                explanation="5 failures from 198.51.100.10",
                mitre_technique_id="T1110",
                mitre_technique_name="Brute Force",
                mitre_tactic="Credential Access",
                evidence_event_ids=["evt-real-1"],
                is_sample=False,
            )
            db.save_alert(alert)
            self.assertEqual(len(db.list_alerts(include_samples=False)), 1)

            inc = Incident(
                incident_id="inc-001",
                title="Production SSH Intrusion Attempt",
                description="Investigating brute force from 198.51.100.10",
                severity=Severity.HIGH,
                status=IncidentStatus.INVESTIGATING,
                linked_event_ids=["evt-real-1"],
                linked_alert_ids=["alt-001"],
                notes=[
                    IncidentNote(
                        incident_id="inc-001",
                        author="analyst_a",
                        content="Blocked IP at perimeter firewall.",
                    )
                ],
                timeline=[
                    TimelineEntry(
                        incident_id="inc-001",
                        entry_type="CREATED",
                        actor="analyst_a",
                        description="Incident opened from alert alt-001",
                    )
                ],
            )
            db.save_incident(inc)
            loaded_inc = db.get_incident("inc-001")
            self.assertEqual(loaded_inc.title, "Production SSH Intrusion Attempt")
            self.assertEqual(len(loaded_inc.notes), 1)
            self.assertEqual(len(loaded_inc.timeline), 1)

            with self.assertRaises(IncidentNotFoundError):
                db.get_incident("non-existent-id")

            stats = db.get_dashboard_statistics(include_samples=False)
            self.assertEqual(stats["total_events"], 1)
            self.assertEqual(stats["real_telemetry_events"], 1)
            self.assertEqual(stats["sample_telemetry_events"], 1)
            self.assertFalse(stats["includes_sample_data"])


if __name__ == "__main__":
    unittest.main()
