"""
End-to-End and Unit Tests for Phase 3 — Core SOC:
- Log Ingestion, Parsing, Normalization, Search, Correlation, Path Traversal & Size Guards
- Threat Detection Engine (Single-event & Correlation) + Official MITRE ATT&CK Integration
- Incident Management & Report Exporting (JSON, Markdown, XSS-safe HTML)
- External Integrations Interface (Honest configuration status)
- Security Dashboard Service & HTTP Server (Real vs Sample telemetry separation)
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import urlopen

from sentinel_x.core import (
    ConfigurationError,
    DatabaseManager,
    DetectionRule,
    EventCategory,
    IncidentStatus,
    SecurityBoundaryError,
    SentinelConfig,
    Severity,
    ValidationError,
)
from sentinel_x.dashboard import DashboardService, create_dashboard_http_server
from sentinel_x.detection import (
    ThreatDetectionEngine,
    get_mitre_reference,
)
from sentinel_x.incidents import IncidentManagementService
from sentinel_x.ingestion import BaseLogParser, LogIngestionService, LogParserRegistry
from sentinel_x.integrations import IntegrationRegistry, SIEMPlatformConnector
from sentinel_x.reporting import IncidentReportExporter


class TestSOCCore(unittest.TestCase):
    def test_ingestion_parsers_and_custom_parser_extension(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DatabaseManager(Path(tmpdir) / "soc.db")
            registry = LogParserRegistry()
            ingestion = LogIngestionService(db=db, parser_registry=registry)

            # 1. Syslog SSH failed login
            ev1 = ingestion.ingest_line(
                "2026-11-06T10:00:01Z bastion-01 sshd[123]: Failed password for root from 203.0.113.9 port 44111 ssh2"
            )
            self.assertEqual(ev1.category, EventCategory.AUTHENTICATION)
            self.assertEqual(ev1.action, "ssh_login")
            self.assertEqual(ev1.outcome, "failure")
            self.assertEqual(ev1.source_ip, "203.0.113.9")
            self.assertEqual(ev1.user, "root")

            # 2. Web Access log
            ev2 = ingestion.ingest_line(
                '198.51.100.22 - alice [06/Nov/2026:10:05:00 +0000] "GET /admin/../../etc/passwd HTTP/1.1" 403 128 "-" "curl/8.0"'
            )
            self.assertEqual(ev2.category, EventCategory.WEB)
            self.assertEqual(ev2.source_ip, "198.51.100.22")
            self.assertEqual(ev2.user, "alice")
            self.assertEqual(ev2.severity, Severity.HIGH)

            # 3. JSON log
            ev3 = ingestion.ingest_line(
                json.dumps(
                    {
                        "timestamp": "2026-11-06T10:06:00Z",
                        "source_host": "db-01",
                        "source_ip": "10.0.0.12",
                        "user": "postgres",
                        "action": "query_exec",
                        "outcome": "success",
                        "category": "SYSTEM",
                        "message": "Database backup completed",
                    }
                )
            )
            self.assertEqual(ev3.source_host, "db-01")
            self.assertEqual(ev3.user, "postgres")

            # 4. Custom parser registration without modifying existing parsers
            class CustomPipeParser(BaseLogParser):
                format_name = "pipe_custom"

                def can_parse(self, raw_line: str) -> bool:
                    return raw_line.startswith("PIPE|")

                def parse(self, raw_line: str, is_sample: bool = False):
                    parts = raw_line.split("|")
                    from sentinel_x.core.models import NormalizedSecurityEvent

                    return NormalizedSecurityEvent(
                        source_type="pipe_custom",
                        source_host=parts[1],
                        action=parts[2],
                        message=parts[3],
                        raw_log=raw_line,
                        is_sample=is_sample,
                    )

            registry.register(CustomPipeParser())
            ev4 = ingestion.ingest_line("PIPE|fw-01|packet_drop|Blocked port scan")
            self.assertEqual(ev4.source_type, "pipe_custom")
            self.assertEqual(ev4.source_host, "fw-01")

    def test_ingestion_security_boundaries_and_correlation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir) / "allowed"
            base_dir.mkdir(parents=True)
            outside_file = Path(tmpdir) / "outside_secret.log"
            outside_file.write_text("secret log line\n", encoding="utf-8")

            valid_file = base_dir / "app.log"
            valid_file.write_text(
                "2026-11-06T10:00:01Z host1 sshd[1]: Failed password for root from 192.0.2.99 port 1\n"
                "2026-11-06T10:00:02Z host1 sshd[2]: Failed password for admin from 192.0.2.99 port 2\n",
                encoding="utf-8",
            )

            db = DatabaseManager(Path(tmpdir) / "soc.db")
            ingestion = LogIngestionService(
                db=db,
                allowed_base_dir=base_dir,
                max_file_bytes=1024,
            )

            # Path traversal outside allowed_base_dir must raise SecurityBoundaryError
            with self.assertRaises(SecurityBoundaryError):
                ingestion.ingest_file(base_dir / ".." / "outside_secret.log")

            # File exceeding max_file_bytes must raise SecurityBoundaryError
            oversized = base_dir / "huge.log"
            oversized.write_text("A" * 2048, encoding="utf-8")
            with self.assertRaises(SecurityBoundaryError):
                ingestion.ingest_file(oversized)

            # Valid file ingestion and correlation
            ingested = ingestion.ingest_file(valid_file)
            self.assertEqual(len(ingested), 2)

            correlations = ingestion.correlate_events(group_by="source_ip", min_events=2)
            self.assertEqual(len(correlations), 1)
            self.assertEqual(correlations[0]["entity"], "192.0.2.99")
            self.assertEqual(correlations[0]["failure_count"], 2)

    def test_end_to_end_detection_mitre_incidents_reporting_and_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DatabaseManager(Path(tmpdir) / "soc_e2e.db")
            engine = ThreatDetectionEngine(db=db, load_defaults=True)
            ingestion = LogIngestionService(
                db=db,
                on_event_ingested=lambda ev: engine.evaluate_event(ev),
            )

            # Verify fabricated MITRE Technique ID is rejected
            with self.assertRaises(ValidationError):
                get_mitre_reference("T9999.999")

            # Ingest 3 SSH brute-force events from 203.0.113.50 (triggers correlation rule SX-DET-001)
            for sec in (1, 5, 9):
                ingestion.ingest_line(
                    f"2026-11-06T11:00:0{sec}Z bastion-01 sshd[10{sec}]: "
                    f"Failed password for root from 203.0.113.50 port 5000{sec} ssh2",
                    is_sample=False,
                )

            # Ingest 1 SQL injection web probe (triggers SX-DET-002)
            ingestion.ingest_line(
                '198.51.100.88 - - [06/Nov/2026:11:01:00 +0000] '
                '"GET /login?user=admin%27%20UNION%20SELECT%201,2-- HTTP/1.1" 500 200 "-" "sqlmap"',
                is_sample=False,
            )

            # Ingest 1 sample event (tagged is_sample=True)
            ingestion.ingest_line(
                '{"timestamp": "2026-11-06T11:02:00Z", "source_host": "lab-01", "action": "test", "message": "cat /etc/shadow"}',
                is_sample=True,
            )

            real_alerts = db.list_alerts(include_samples=False)
            self.assertEqual(len(real_alerts), 2)
            rule_ids = {a.rule_id for a in real_alerts}
            self.assertIn("SX-DET-001", rule_ids)
            self.assertIn("SX-DET-002", rule_ids)

            brute_alert = next(a for a in real_alerts if a.rule_id == "SX-DET-001")
            self.assertEqual(brute_alert.mitre_technique_id, "T1110.001")
            self.assertEqual(brute_alert.mitre_tactic, "Credential Access")
            self.assertEqual(len(brute_alert.evidence_event_ids), 3)

            # Test dry-run rule evaluation
            test_rule = DetectionRule(
                rule_id="SX-TEST-DRY",
                name="Dry Run Test Rule",
                description="Test rule",
                severity=Severity.LOW,
                mitre=get_mitre_reference("T1046"),
                conditions={"message_contains": "UNION SELECT"},
                explanation_template="Dry run matched {event_id}",
            )
            dry_alerts = engine.test_rule(test_rule, db.query_events(include_samples=False))
            self.assertEqual(len(dry_alerts), 1)

            # Incident Management workflow
            incidents_svc = IncidentManagementService(db=db)
            inc = incidents_svc.create_incident(
                title="SSH Brute Force & Web Probe <script>alert(1)</script>",
                description="Coordinated attack against perimeter hosts",
                severity=Severity.HIGH,
                assigned_to="blue_team_lead",
                alert_ids=[a.alert_id for a in real_alerts],
            )
            self.assertEqual(inc.status, IncidentStatus.OPEN)
            self.assertGreaterEqual(len(inc.linked_event_ids), 4)

            inc = incidents_svc.add_note(
                inc.incident_id,
                content="Isolated source IP 203.0.113.50 at firewall.",
                author="analyst_01",
            )
            inc = incidents_svc.update_status(
                inc.incident_id,
                IncidentStatus.RESOLVED,
                actor="analyst_01",
                resolution_summary="Blocked offending IPs and rotated credentials.",
            )
            self.assertEqual(inc.status, IncidentStatus.RESOLVED)
            self.assertIsNotNone(inc.resolved_at)
            self.assertEqual(len(inc.timeline), 3)

            # Export reports (JSON, Markdown, HTML with XSS escaping)
            exporter = IncidentReportExporter(db=db)
            md_report = exporter.export_markdown(inc.incident_id)
            self.assertIn("T1110.001", md_report)
            self.assertIn("REAL TELEMETRY", md_report)

            html_report = exporter.export_html(inc.incident_id)
            self.assertNotIn("<script>alert(1)</script>", html_report)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_report)

            # External Integrations honest status check
            integrations = IntegrationRegistry(SentinelConfig())
            statuses = integrations.list_statuses()
            self.assertTrue(all(not s["configured"] for s in statuses))
            self.assertTrue(all(s["status"] == "NOT_CONFIGURED" for s in statuses))

            unconfigured_siem = SIEMPlatformConnector()
            with self.assertRaises(ConfigurationError):
                unconfigured_siem.build_alert_payload(brute_alert)

            configured_siem = SIEMPlatformConnector(
                endpoint_url="https://siem.internal.example/ingest",
                api_key="real_production_api_key_998877",
            )
            self.assertTrue(configured_siem.is_configured())

            # Dashboard Service & live HTTP server verification
            dashboard_svc = DashboardService(db=db, integrations=integrations)
            snap_real = dashboard_svc.get_dashboard_snapshot(include_samples=False)
            self.assertEqual(snap_real["statistics"]["total_events"], 4)
            self.assertEqual(snap_real["statistics"]["real_telemetry_events"], 4)
            self.assertEqual(snap_real["statistics"]["sample_telemetry_events"], 1)
            self.assertFalse(snap_real["statistics"]["includes_sample_data"])

            from urllib.request import ProxyHandler, build_opener

            server = create_dashboard_http_server(
                dashboard_svc, SentinelConfig(host="127.0.0.1", port=18981)
            )
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            opener = build_opener(ProxyHandler({}))
            try:
                with opener.open(f"http://127.0.0.1:{port}/api/v1/summary?include_samples=0") as resp:
                    self.assertEqual(resp.status, 200)
                    api_data = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(api_data["statistics"]["total_alerts"], 2)

                with opener.open(f"http://127.0.0.1:{port}/?include_samples=0") as resp:
                    self.assertEqual(resp.status, 200)
                    page_html = resp.read().decode("utf-8")
                    self.assertIn("REAL_TELEMETRY_ONLY", page_html)
                    self.assertNotIn("<script>alert(1)</script>", page_html)
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
