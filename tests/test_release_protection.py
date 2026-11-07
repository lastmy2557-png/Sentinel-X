"""
Unit and Integration Tests for Phase 4 — Anti-REA / Release Protection
(sentinel_x.security.release_protection).
Tested independently from SOC Core.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sentinel_x.security.release_protection import (
    ReleaseSecurityScanner,
    create_release_manifest,
    format_audit_report_markdown,
    generate_ed25519_keypair,
    generate_security_audit_report,
    verify_release_manifest,
)
from sentinel_x.security.release_protection.cli import main as release_cli_main


class TestReleaseProtection(unittest.TestCase):
    def test_ed25519_signed_manifest_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            rel_dir = base / "release_pkg"
            rel_dir.mkdir()
            (rel_dir / ".gitignore").write_text(".env\n*.key\n*.pem\n", encoding="utf-8")
            (rel_dir / "app.py").write_text("def run():\n    return 'ok'\n", encoding="utf-8")
            (rel_dir / "README.md").write_text("# Release Pkg\n", encoding="utf-8")

            key_dir = base / "external_keys"
            priv_a = key_dir / "publisher_a.key"
            pub_a = key_dir / "publisher_a_public.pem"
            priv_b = key_dir / "publisher_b.key"
            pub_b = key_dir / "publisher_b_public.pem"

            generate_ed25519_keypair(priv_a, pub_a)
            generate_ed25519_keypair(priv_b, pub_b)

            manifest_path = base / "release_manifest.json"
            create_release_manifest(
                root_dir=rel_dir,
                version="1.0.0",
                publisher="Sentinel-X Security Team",
                private_key_path=priv_a,
                output_path=manifest_path,
            )

            # 1. Valid signature and untampered files -> verified=True
            res_ok = verify_release_manifest(
                root_dir=rel_dir,
                manifest_data_or_path=manifest_path,
                public_key_path=pub_a,
                require_signature=True,
            )
            self.assertTrue(res_ok.verified)
            self.assertTrue(res_ok.signature_verified)
            self.assertTrue(res_ok.integrity_verified)

            # 2. Wrong public key -> signature_verified=False, verified=False
            res_wrong_key = verify_release_manifest(
                root_dir=rel_dir,
                manifest_data_or_path=manifest_path,
                public_key_path=pub_b,
                require_signature=True,
            )
            self.assertFalse(res_wrong_key.verified)
            self.assertFalse(res_wrong_key.signature_verified)

            # 3. Hash-only (unsigned) manifest must NOT pass when require_signature=True
            unsigned_manifest = create_release_manifest(
                root_dir=rel_dir,
                version="1.0.0",
                private_key_path=None,
            )
            res_unsigned = verify_release_manifest(
                root_dir=rel_dir,
                manifest_data_or_path=unsigned_manifest,
                public_key_path=pub_a,
                require_signature=True,
            )
            self.assertFalse(res_unsigned.verified)
            self.assertFalse(res_unsigned.signature_verified)

            # 4. Tamper with app.py, delete README.md, and inject backdoor.py
            (rel_dir / "app.py").write_text("def run():\n    return 'tampered'\n", encoding="utf-8")
            (rel_dir / "README.md").unlink()
            (rel_dir / "injected.py").write_text("print('unauthorized')\n", encoding="utf-8")

            res_tampered = verify_release_manifest(
                root_dir=rel_dir,
                manifest_data_or_path=manifest_path,
                public_key_path=pub_a,
                require_signature=True,
            )
            self.assertFalse(res_tampered.verified)
            self.assertTrue(res_tampered.signature_verified)
            self.assertFalse(res_tampered.integrity_verified)
            self.assertIn("app.py", res_tampered.modified_files)
            self.assertIn("README.md", res_tampered.missing_files)
            self.assertIn("injected.py", res_tampered.unexpected_files)

    def test_scanner_detects_secrets_sensitive_files_debug_sourcemaps_and_build_risks(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            # Deliberately weak .gitignore (missing *.pem)
            (root / ".gitignore").write_text(".env\n*.key\n", encoding="utf-8")
            # Safe template should be allowed
            (root / ".env.example").write_text("API_KEY=CHANGE_ME_PLACEHOLDER\n", encoding="utf-8")
            # Exposed .env file
            (root / ".env").write_text("ENV=prod\n", encoding="utf-8")
            # Exposed debug artifact
            (root / "crash.pdb").write_text("pdb dump", encoding="utf-8")
            # Exposed source map
            (root / "app.js.map").write_text("{}", encoding="utf-8")

            # Construct synthetic secret token at runtime so test source file stays clean
            fake_aws = "AKIA" + "1234567890ABCDEF"
            (root / "bad_code.py").write_text(
                f'aws_id = "{fake_aws}"\n'
                "breakpoint()\n"
                "import subprocess\n"
                "subprocess.run('ls', shell=True)\n",
                encoding="utf-8",
            )

            scanner = ReleaseSecurityScanner(include_tests=True)
            findings = scanner.scan_workspace(root)
            rule_ids = {f.rule_id for f in findings}

            self.assertIn("CFG-WEAK-GITIGNORE", rule_ids)
            self.assertIn("FILE-SENSITIVE-EXPOSURE", rule_ids)
            self.assertIn("DBG-ARTIFACT-FILE", rule_ids)
            self.assertIn("MAP-FILE-EXPOSURE", rule_ids)
            self.assertIn("SEC-AWS-AKIA", rule_ids)
            self.assertIn("DBG-BREAKPOINT-CODE", rule_ids)
            self.assertIn("CFG-UNSAFE-SHELL-TRUE", rule_ids)

            # Ensure raw secret value is redacted in evidence
            secret_finding = next(f for f in findings if f.rule_id == "SEC-AWS-AKIA")
            self.assertNotIn(fake_aws, secret_finding.redacted_evidence)
            self.assertIn("REDACTED", secret_finding.redacted_evidence)

            report = generate_security_audit_report(root, include_tests_in_scan=True)
            self.assertEqual(report["overall_status"], "FAILED")
            md = format_audit_report_markdown(report)
            self.assertIn("Tamper Detection", md)
            self.assertIn("No software can guarantee 100% prevention against reverse engineering", md)

    def test_release_verification_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            pkg = base / "clean_pkg"
            pkg.mkdir()
            (pkg / ".gitignore").write_text(".env\n*.key\n*.pem\n", encoding="utf-8")
            (pkg / "module.py").write_text("x = 42\n", encoding="utf-8")

            keys = base / "keys"
            priv = keys / "rel.key"
            pub = keys / "rel_public.pem"
            manifest = base / "manifest.json"

            self.assertEqual(
                release_cli_main(["keygen", "--private-key", str(priv), "--public-key", str(pub)]),
                0,
            )
            self.assertEqual(
                release_cli_main(
                    [
                        "sign",
                        "--root",
                        str(pkg),
                        "--private-key",
                        str(priv),
                        "--output",
                        str(manifest),
                    ]
                ),
                0,
            )
            self.assertEqual(
                release_cli_main(
                    [
                        "verify",
                        "--root",
                        str(pkg),
                        "--manifest",
                        str(manifest),
                        "--public-key",
                        str(pub),
                    ]
                ),
                0,
            )
            self.assertEqual(
                release_cli_main(["audit", "--root", str(pkg), "--format", "markdown"]),
                0,
            )


if __name__ == "__main__":
    unittest.main()
