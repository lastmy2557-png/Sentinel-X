"""
Unit & Integration Tests for Phase 8 (Standalone Executable Entrypoint & Build Pipeline):
- sentinel_x.__main__.run_entrypoint CLI routing
- scripts.build_exe.build_pyinstaller_command safe argument generation
- scripts.build_exe.write_build_integrity_artifacts SHA-256 checksum & manifest generation
- scripts.build_exe.run_build dry-run and pre-build Anti-REA security audit enforcement
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts.build_exe import (
    PROJECT_ROOT,
    build_pyinstaller_command,
    main as build_exe_main,
    run_build,
    write_build_integrity_artifacts,
)
from sentinel_x.__main__ import run_entrypoint


class BuildExePipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_entrypoint_routes_soc_and_release_protection_commands(self) -> None:
        db_file = self.base_path / "entrypoint_test.db"
        audit_file = self.base_path / "entrypoint_audit.log"

        with patch.dict(
            os.environ,
            {
                "SENTINEL_DB_PATH": str(db_file),
                "SENTINEL_AUDIT_LOG_PATH": str(audit_file),
            },
            clear=False,
        ):
            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                rc = run_entrypoint(["summary"])
            self.assertEqual(rc, 0)
            payload = json.loads(stdout_buf.getvalue())
            self.assertIn("statistics", payload)
            self.assertIn("total_events", payload["statistics"])

            # Test routing to release-protection sub-CLI
            rp_buf = io.StringIO()
            with redirect_stdout(rp_buf):
                rc_rp = run_entrypoint(
                    ["release-protection", "inventory", "--root", str(self.base_path)]
                )
            self.assertEqual(rc_rp, 0)
            rp_payload = json.loads(rp_buf.getvalue())
            self.assertIn("file_count", rp_payload)

    def test_build_pyinstaller_command_structure(self) -> None:
        dist_dir = self.base_path / "dist"
        work_dir = self.base_path / "build"
        cmd = build_pyinstaller_command(
            project_root=PROJECT_ROOT,
            dist_dir=dist_dir,
            work_dir=work_dir,
            exe_name="sentinel-x",
        )
        self.assertIn("PyInstaller", cmd)
        self.assertIn("--onefile", cmd)
        self.assertIn("--clean", cmd)
        self.assertIn("sentinel-x", cmd)
        self.assertTrue(cmd[-1].endswith("sentinel_x/__main__.py") or cmd[-1].endswith("sentinel_x\\__main__.py"))

    def test_write_build_integrity_artifacts(self) -> None:
        dist_dir = self.base_path / "dist"
        dist_dir.mkdir(parents=True, exist_ok=True)
        dummy_exe = dist_dir / "sentinel-x.exe"
        dummy_exe.write_bytes(b"MZ_DUMMY_BINARY_CONTENT_FOR_HASH_TEST")

        manifest = write_build_integrity_artifacts(dummy_exe, dist_dir)
        self.assertEqual(manifest["executable_name"], "sentinel-x.exe")
        self.assertEqual(len(manifest["sha256"]), 64)

        checksum_file = dist_dir / "sentinel-x.exe.sha256"
        manifest_file = dist_dir / "build_manifest.json"
        self.assertTrue(checksum_file.is_file())
        self.assertTrue(manifest_file.is_file())
        self.assertIn(manifest["sha256"], checksum_file.read_text(encoding="utf-8"))

    def test_run_build_dry_run_and_cli(self) -> None:
        result = run_build(
            project_root=PROJECT_ROOT,
            dist_dir=self.base_path / "dist",
            work_dir=self.base_path / "build",
            dry_run=True,
        )
        self.assertEqual(result["status"], "DRY_RUN")
        self.assertTrue(result["audit_passed"])

        cli_buf = io.StringIO()
        with redirect_stdout(cli_buf):
            rc = build_exe_main(["--dry-run", "--dist-dir", str(self.base_path / "dist")])
        self.assertEqual(rc, 0)
        cli_output = json.loads(cli_buf.getvalue())
        self.assertEqual(cli_output["status"], "DRY_RUN")

    def test_pre_build_audit_blocks_compromised_workspace(self) -> None:
        compromised_root = self.base_path / "compromised_project"
        compromised_root.mkdir(parents=True, exist_ok=True)
        # Plant a forbidden private key file inside workspace
        leaked_key = compromised_root / "leaked_private.key"
        leaked_key.write_text("-----BEGIN PRIVATE KEY-----\nFAKE\n", encoding="utf-8")

        with self.assertRaises(RuntimeError):
            run_build(project_root=compromised_root, dry_run=True)


if __name__ == "__main__":
    unittest.main()
