"""
Unit & Integration Tests for Phase 9:
1. External API Integration Settings UI (/settings) & REST API (/api/v1/settings/connectors)
   - Secret masking (never exposing raw API keys in GET/POST responses or HTML)
   - SQLite persistence across platform restarts
   - Input validation (rejecting invalid URLs and placeholder secrets)
   - Live connection testing (/api/v1/settings/connectors/test)
   - Audit logging of configuration changes without leaking secrets
2. Release & Distribution Package Builder (scripts/build_release_package.py)
   - PEP 427 Wheel (.whl), Source Tarball (.tar.gz), Release Bundle (.zip),
     Release Manifest (release_manifest.json), and SHA256SUMS.txt generation.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from scripts.build_exe import build_windows_pe_zipapp_exe
from scripts.build_release_package import PROJECT_ROOT, build_all_release_packages
from scripts.release_patch import bump_semver, parse_semver, update_version_files
from sentinel_x.core import AuditLogger, DatabaseManager, SentinelConfig
from sentinel_x.dashboard import DashboardService, create_dashboard_http_server
from sentinel_x.integrations import IntegrationRegistry


class TestAPISettingsAndReleasePackages(unittest.TestCase):
    def test_api_settings_ui_persistence_masking_and_connection_test(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            db_path = base / "settings_test.db"
            audit_path = base / "audit_settings.log"

            db = DatabaseManager(db_path)
            audit = AuditLogger(audit_path)
            integrations = IntegrationRegistry(db=db, audit_logger=audit)
            dashboard_svc = DashboardService(db=db, integrations=integrations)

            server = create_dashboard_http_server(
                dashboard_svc, SentinelConfig(host="127.0.0.1", port=18982)
            )
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            opener = build_opener(ProxyHandler({}))

            raw_secret = "sx_prod_secret_token_987654"
            try:
                # 1. GET /settings renders HTML page with all 5 connector cards and non-overlapping nav layout
                with opener.open(f"http://127.0.0.1:{port}/settings") as resp:
                    self.assertEqual(resp.status, 200)
                    html_text = resp.read().decode("utf-8")
                    self.assertIn("siem_forwarder", html_text)
                    self.assertIn("edr_controller", html_text)
                    self.assertIn("threat_intel_feed", html_text)
                    self.assertIn("webhook_notifier", html_text)
                    self.assertIn("external_security_tool", html_text)
                    self.assertIn(".nav a { display: inline-flex; align-items: center; white-space: nowrap;", html_text)
                    self.assertIn(".topbar { display: flex; flex-wrap: wrap;", html_text)

                # 2. POST /api/v1/settings/connectors to configure SIEM connector
                post_payload = json.dumps(
                    {
                        "connector_id": "siem_forwarder",
                        "provider_name": "Splunk Enterprise HEC",
                        "endpoint_url": f"http://127.0.0.1:{port}/api/v1/summary",
                        "api_key": raw_secret,
                        "enabled": True,
                    }
                ).encode("utf-8")
                req = Request(
                    f"http://127.0.0.1:{port}/api/v1/settings/connectors",
                    data=post_payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with opener.open(req) as resp:
                    self.assertEqual(resp.status, 200)
                    res_data = json.loads(resp.read().decode("utf-8"))
                    conn_info = res_data["connector"]
                    self.assertEqual(conn_info["status"], "CONFIGURED_READY")
                    self.assertTrue(conn_info["api_key_configured"])
                    # Ensure raw secret is masked and never returned in plaintext
                    self.assertNotIn(raw_secret, json.dumps(res_data))
                    self.assertTrue(conn_info["api_key_masked"].endswith("7654"))

                # 3. Verify updating provider_name with blank api_key preserves saved secret
                update_provider_payload = json.dumps(
                    {
                        "connector_id": "siem_forwarder",
                        "provider_name": "Elastic SIEM Cloud",
                        "api_key": "",
                    }
                ).encode("utf-8")
                req_upd = Request(
                    f"http://127.0.0.1:{port}/api/v1/settings/connectors",
                    data=update_provider_payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with opener.open(req_upd) as resp:
                    res_upd = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(res_upd["connector"]["provider_name"], "Elastic SIEM Cloud")
                    self.assertTrue(res_upd["connector"]["api_key_configured"])

                # 4. Test real HTTP connection via POST /api/v1/settings/connectors/test
                test_payload = json.dumps({"connector_id": "siem_forwarder"}).encode("utf-8")
                req_test = Request(
                    f"http://127.0.0.1:{port}/api/v1/settings/connectors/test",
                    data=test_payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with opener.open(req_test) as resp:
                    self.assertEqual(resp.status, 200)
                    test_out = json.loads(resp.read().decode("utf-8"))
                    self.assertTrue(test_out["result"]["success"])
                    self.assertEqual(test_out["result"]["status"], "REACHABLE_HTTP_200")

                # 5. Test unconfigured connector honestly reports NOT_CONFIGURED
                unconf_payload = json.dumps({"connector_id": "edr_controller"}).encode("utf-8")
                req_unconf = Request(
                    f"http://127.0.0.1:{port}/api/v1/settings/connectors/test",
                    data=unconf_payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with opener.open(req_unconf) as resp:
                    unconf_out = json.loads(resp.read().decode("utf-8"))
                    self.assertFalse(unconf_out["result"]["success"])
                    self.assertEqual(unconf_out["result"]["status"], "NOT_CONFIGURED")

                # 6. Verify invalid URL scheme (javascript:) is rejected with HTTP 400
                bad_url_payload = json.dumps(
                    {
                        "connector_id": "webhook_notifier",
                        "endpoint_url": "javascript:alert(1)",
                    }
                ).encode("utf-8")
                req_bad = Request(
                    f"http://127.0.0.1:{port}/api/v1/settings/connectors",
                    data=bad_url_payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(HTTPError) as ctx:
                    opener.open(req_bad)
                self.assertEqual(ctx.exception.code, 400)
                ctx.exception.close()

                # 7. Verify SQLite persistence across fresh IntegrationRegistry instantiation
                reloaded_registry = IntegrationRegistry(db=db)
                reloaded_siem = reloaded_registry.get("siem_forwarder")
                self.assertIsNotNone(reloaded_siem)
                assert reloaded_siem is not None
                self.assertTrue(reloaded_siem.is_configured())
                self.assertEqual(reloaded_siem.provider_name, "Elastic SIEM Cloud")

                # 8. Verify audit log recorded changes without leaking raw secret
                audit_content = audit_path.read_text(encoding="utf-8")
                self.assertIn("CONNECTOR_CONFIG_UPDATED", audit_content)
                self.assertIn("CONNECTOR_CONNECTION_TESTED", audit_content)
                self.assertNotIn(raw_secret, audit_content)
            finally:
                server.shutdown()
                server.server_close()

    def test_build_release_packages_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dist = Path(tmpdir) / "dist"
            res = build_all_release_packages(
                project_root=PROJECT_ROOT,
                dist_dir=out_dist,
                version="0.1.0",
            )
            self.assertEqual(res["status"], "RELEASE_PACKAGES_BUILT")
            self.assertEqual(res["audit_status"], "PASSED")

            expected_files = [
                "sentinel_x-0.1.0-py3-none-any.whl",
                "sentinel_x-0.1.0.tar.gz",
                "sentinel-x-0.1.0-release-bundle.zip",
                "release_manifest.json",
                "SHA256SUMS.txt",
            ]
            for fname in expected_files:
                fpath = out_dist / fname
                self.assertTrue(fpath.is_file(), f"Missing expected release artifact: {fname}")
                self.assertGreater(fpath.stat().st_size, 0)

    def test_patch_generator_and_windows_pe_zipapp_compiler(self) -> None:
        self.assertEqual(parse_semver("0.1.0"), (0, 1, 0))
        self.assertEqual(bump_semver("0.1.0", "patch"), "0.1.1")
        self.assertEqual(bump_semver("0.1.1", "minor"), "0.2.0")
        self.assertEqual(bump_semver("0.2.0", "major"), "1.0.0")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            mock_root = tmp_path / "proj"
            (mock_root / "sentinel_x").mkdir(parents=True, exist_ok=True)
            (mock_root / "sentinel_x" / "__init__.py").write_text('__version__ = "0.1.0"\n', encoding="utf-8")
            (mock_root / "pyproject.toml").write_text('[project]\nname = "sentinel-x"\nversion = "0.1.0"\n', encoding="utf-8")

            changed = update_version_files(mock_root, "0.1.1")
            self.assertEqual(len(changed), 2)
            self.assertIn('__version__ = "0.1.1"', (mock_root / "sentinel_x" / "__init__.py").read_text(encoding="utf-8"))
            self.assertIn('version = "0.1.1"', (mock_root / "pyproject.toml").read_text(encoding="utf-8"))

            exe_out = build_windows_pe_zipapp_exe(
                project_root=PROJECT_ROOT,
                dist_dir=tmp_path / "dist",
                work_dir=tmp_path / "work",
                exe_name="sentinel-x",
            )
            self.assertTrue(exe_out.is_file())
            raw_bytes = exe_out.read_bytes()
            self.assertEqual(raw_bytes[:2], b"MZ")
            self.assertIn(b"PE\x00\x00", raw_bytes[:512])

        # Ensure scripts/apply_patch_windows.bat has zero multi-line parenthesized blocks
        bat_text = (PROJECT_ROOT / "scripts" / "apply_patch_windows.bat").read_text(encoding="utf-8")
        for raw_line in bat_text.splitlines():
            line = raw_line.strip()
            if not line or line.upper().startswith("REM"):
                continue
            self.assertFalse(line.endswith("("), f"Found parenthesized block in apply_patch_windows.bat: {line}")

    def test_vercel_official_website_assets_and_config(self) -> None:
        vercel_cfg_path = PROJECT_ROOT / "vercel.json"
        self.assertTrue(vercel_cfg_path.is_file())
        vercel_cfg = json.loads(vercel_cfg_path.read_text(encoding="utf-8"))
        self.assertEqual(vercel_cfg["outputDirectory"], "public")

        for rel_file in ("public/index.html", "public/styles.css", "public/app.js", "public/version.json"):
            fp = PROJECT_ROOT / rel_file
            self.assertTrue(fp.is_file(), f"Missing official website file: {rel_file}")
            self.assertGreater(fp.stat().st_size, 0)

        index_html = (PROJECT_ROOT / "public" / "index.html").read_text(encoding="utf-8")
        self.assertEqual(index_html.count("<h1"), 1)
        for tab_key in ("all", "dashboard", "simulator", "capabilities", "integrations", "anti-rea", "releases"):
            self.assertIn(f'data-tab-target="{tab_key}"', index_html)
        for console_id in (
            "soc-ingest-textarea",
            "soc-alerts-tbody",
            "soc-incidents-tbody",
            "sigma-yaml-input",
            "interactive-connectors-container",
            "antirea-scan-input",
            "ed25519-manifest-output",
            "sha256-file-input",
        ):
            self.assertIn(f'id="{console_id}"', index_html)


if __name__ == "__main__":
    unittest.main()
