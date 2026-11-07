"""
Integration Tests for Phase 5 — Integration (tests/test_integration.py).
Tests:
1. Unified SentinelXPlatform orchestration & CLI end-to-end execution
2. Module interactions (Ingest -> Detect -> Alert -> Incident -> Report -> Audit Log)
3. Self-Audit of the real Sentinel-X workspace using Anti-REA Release Protection Scanner
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from sentinel_x.cli import main as soc_cli_main
from sentinel_x.security.release_protection import generate_security_audit_report


class TestPlatformIntegration(unittest.TestCase):
    def test_cli_and_platform_end_to_end_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            db_path = base / "integrated.db"
            sample_log = Path(__file__).resolve().parent.parent / "data" / "samples" / "sample_security.log"

            # 1. Ingest sample log via CLI with --sample flag
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = soc_cli_main(["--db", str(db_path), "ingest", "--file", str(sample_log), "--sample"])
            self.assertEqual(rc, 0)
            ingest_out = json.loads(buf.getvalue())
            self.assertEqual(ingest_out["events_ingested"], 5)
            self.assertGreaterEqual(ingest_out["alerts_generated"], 3)
            self.assertTrue(ingest_out["is_sample"])
            alert_ids = ingest_out["alert_ids"]

            # 2. Verify summary with --exclude-samples shows 0 real events and 5 sample events
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = soc_cli_main(["--db", str(db_path), "summary", "--exclude-samples"])
            self.assertEqual(rc, 0)
            sum_real = json.loads(buf.getvalue())
            self.assertEqual(sum_real["statistics"]["total_events"], 0)
            self.assertEqual(sum_real["statistics"]["sample_telemetry_events"], 5)

            # 3. Create incident from generated alerts via CLI
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = soc_cli_main(
                    [
                        "--db",
                        str(db_path),
                        "incident",
                        "create",
                        "--title",
                        "Sample Lab Multi-Stage Intrusion",
                        "--severity",
                        "CRITICAL",
                        "--alert-ids",
                        *alert_ids,
                    ]
                )
            self.assertEqual(rc, 0)
            inc_data = json.loads(buf.getvalue())
            inc_id = inc_data["incident_id"]
            self.assertTrue(inc_data["is_sample"])

            # 4. Export Markdown report via CLI
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = soc_cli_main(
                    ["--db", str(db_path), "incident", "report", "--id", inc_id, "--format", "markdown"]
                )
            self.assertEqual(rc, 0)
            report_md = buf.getvalue()
            self.assertIn("SAMPLE / TEST DATA", report_md)
            self.assertIn("T1110.001", report_md)
            self.assertIn("T1003.008", report_md)

    def test_self_audit_of_sentinel_x_workspace_passes_cleanly(self) -> None:
        """
        Run the Anti-REA Release Security Scanner against the actual Sentinel-X project root
        to verify zero leaked secrets, zero exposed keys, and hardened build configuration.
        """
        workspace_root = Path(__file__).resolve().parent.parent
        report = generate_security_audit_report(workspace_root, include_tests_in_scan=False)
        self.assertEqual(
            report["overall_status"],
            "PASSED",
            f"Workspace self-audit failed with findings: {report['findings']}",
        )
        self.assertEqual(report["finding_summary"]["total_findings"], 0)


if __name__ == "__main__":
    unittest.main()
