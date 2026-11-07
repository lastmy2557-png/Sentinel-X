"""
Unit and Integration Tests for Phase 7 Extensions:
- Real-time UDP Syslog Receiver (SyslogUDPReceiver)
- Sigma YAML Detection Rule Importer (parse_sigma_yaml_to_rule / load_sigma_rule_file)
"""

from __future__ import annotations

import socket
import tempfile
import time
import unittest
from pathlib import Path

from sentinel_x.core import SentinelConfig, ValidationError
from sentinel_x.detection import parse_sigma_yaml_to_rule
from sentinel_x.ingestion import SyslogUDPReceiver
from sentinel_x.platform import SentinelXPlatform


class TestPhase7Extensions(unittest.TestCase):
    def test_realtime_udp_syslog_receiver_and_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = SentinelConfig(
                db_path=Path(tmpdir) / "syslog_rt.db",
                audit_log_path=Path(tmpdir) / "audit.log",
            )
            platform = SentinelXPlatform(config=cfg)
            receiver = SyslogUDPReceiver(
                ingestion_service=platform.ingestion,
                host="127.0.0.1",
                port=0,
            )
            receiver.start_background()
            try:
                udp_port = receiver.bound_port
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    # Send 3 RFC3164 SSH failure datagrams with <38> priority header
                    for idx in (1, 2, 3):
                        msg = (
                            f"<38>2026-11-07T03:00:0{idx}Z edge-gw sshd[20{idx}]: "
                            f"Failed password for root from 198.51.100.200 port 4000{idx} ssh2"
                        )
                        sock.sendto(msg.encode("utf-8"), ("127.0.0.1", udp_port))
                finally:
                    sock.close()

                # Wait briefly for background UDP handler to process all 3 packets
                deadline = time.time() + 3.0
                while receiver.received_count < 3 and time.time() < deadline:
                    time.sleep(0.02)

                self.assertEqual(receiver.received_count, 3)
                alerts = platform.db.list_alerts()
                self.assertEqual(len(alerts), 1)
                self.assertEqual(alerts[0].rule_id, "SX-DET-001")
                self.assertEqual(alerts[0].mitre_technique_id, "T1110.001")
            finally:
                receiver.stop()

    def test_sigma_yaml_rule_importer_and_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = SentinelConfig(
                db_path=Path(tmpdir) / "sigma.db",
                audit_log_path=Path(tmpdir) / "audit.log",
            )
            platform = SentinelXPlatform(config=cfg)
            sigma_file = (
                Path(__file__).resolve().parent.parent
                / "config"
                / "rules"
                / "sample_sigma_rule.yml"
            )
            rule = platform.detection.load_sigma_rule(sigma_file)
            self.assertEqual(rule.rule_id, "SX-SIGMA-001")
            self.assertEqual(rule.mitre.technique_id, "T1505.003")
            self.assertEqual(rule.mitre.tactic, "Persistence")

            # Ingest web access log matching the imported Sigma rule (c99.php?cmd=whoami)
            platform.ingestion.ingest_line(
                '203.0.113.77 - - [07/Nov/2026:03:10:00 +0000] '
                '"GET /uploads/c99.php?cmd=whoami HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
            )
            alerts = platform.pop_generated_alerts()
            self.assertTrue(any(a.rule_id == "SX-SIGMA-001" for a in alerts))

            # Verify Sigma rule with unverified/fabricated MITRE tag is rejected
            bad_yaml = """
title: Bad MITRE Rule
id: SX-BAD-001
level: high
tags:
  - attack.t9999.999
detection:
  selection:
    category: WEB
"""
            with self.assertRaises(ValidationError):
                parse_sigma_yaml_to_rule(bad_yaml)


if __name__ == "__main__":
    unittest.main()
