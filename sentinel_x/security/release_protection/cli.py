"""
Release Verification & Anti-REA CLI for Sentinel-X (Section 5.1).
Provides standalone commands:
- keygen    : Generate external Ed25519 keypair outside the repository
- inventory : Output SHA-256 file inventory
- sign      : Create and digitally sign a release manifest using an external Ed25519 private key
- verify    : Verify Ed25519 digital signature and SHA-256 file integrity (Tamper Detection)
- audit     : Run secret scan, sensitive file detection, debug/sourcemap checks, and build audit
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from sentinel_x.security.release_protection.inventory import build_file_inventory
from sentinel_x.security.release_protection.manifest import (
    create_release_manifest,
    generate_ed25519_keypair,
    verify_release_manifest,
)
from sentinel_x.security.release_protection.report import (
    format_audit_report_markdown,
    generate_security_audit_report,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel-x-release-protection",
        description="Sentinel-X Release Protection (Anti-REA): Tamper Detection, Signed Manifests, and Security Audit CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_keygen = sub.add_parser("keygen", help="Generate external Ed25519 signing keypair")
    p_keygen.add_argument("--private-key", required=True, help="Output path for private key (store outside repo)")
    p_keygen.add_argument("--public-key", required=True, help="Output path for public key")

    p_inv = sub.add_parser("inventory", help="Generate SHA-256 file inventory")
    p_inv.add_argument("--root", default=".", help="Target release directory")

    p_sign = sub.add_parser("sign", help="Create and sign release manifest")
    p_sign.add_argument("--root", default=".", help="Target release directory")
    p_sign.add_argument("--version", default="0.1.0", help="Release version string")
    p_sign.add_argument("--publisher", default="Sentinel-X Release Engineering", help="Publisher name")
    p_sign.add_argument(
        "--private-key",
        default=os.environ.get("SENTINEL_RELEASE_PRIVATE_KEY_PATH", ""),
        help="Path to external Ed25519 private key",
    )
    p_sign.add_argument("--output", default="release_manifest.json", help="Output manifest file path")

    p_verify = sub.add_parser("verify", help="Verify signed release manifest and detect file tampering")
    p_verify.add_argument("--root", default=".", help="Target release directory")
    p_verify.add_argument("--manifest", default="release_manifest.json", help="Manifest file path")
    p_verify.add_argument(
        "--public-key",
        default=os.environ.get("SENTINEL_RELEASE_PUBLIC_KEY_PATH", ""),
        help="Path to Ed25519 public key",
    )
    p_verify.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="Check SHA-256 hashes only without publisher signature authentication",
    )

    p_audit = sub.add_parser("audit", help="Run Anti-REA security audit (secrets, artifacts, build config)")
    p_audit.add_argument("--root", default=".", help="Target directory to audit")
    p_audit.add_argument("--format", choices=["json", "markdown"], default="json", help="Output format")
    p_audit.add_argument("--output", default="", help="Optional output file path")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "keygen":
        priv = Path(args.private_key)
        pub = Path(args.public_key)
        generate_ed25519_keypair(priv, pub)
        print(json.dumps({"status": "OK", "private_key": str(priv), "public_key": str(pub)}))
        return 0

    if args.command == "inventory":
        entries = build_file_inventory(Path(args.root))
        print(
            json.dumps(
                {"file_count": len(entries), "files": [e.to_dict() for e in entries]},
                indent=2,
            )
        )
        return 0

    if args.command == "sign":
        priv_path = Path(args.private_key) if args.private_key else None
        if priv_path is None:
            print(
                "Error: --private-key or SENTINEL_RELEASE_PRIVATE_KEY_PATH is required to sign a release manifest.",
                file=sys.stderr,
            )
            return 2
        manifest = create_release_manifest(
            root_dir=Path(args.root),
            version=args.version,
            publisher=args.publisher,
            private_key_path=priv_path,
            output_path=Path(args.output),
        )
        print(
            json.dumps(
                {
                    "status": "SIGNED",
                    "output": args.output,
                    "file_count": manifest["manifest"]["file_count"],
                    "inventory_sha256": manifest["signature_info"]["inventory_sha256"],
                },
                indent=2,
            )
        )
        return 0

    if args.command == "verify":
        pub_path = Path(args.public_key) if args.public_key else None
        result = verify_release_manifest(
            root_dir=Path(args.root),
            manifest_data_or_path=Path(args.manifest),
            public_key_path=pub_path,
            require_signature=not args.allow_unsigned,
        )
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.verified else 1

    if args.command == "audit":
        report = generate_security_audit_report(Path(args.root))
        output_text = (
            format_audit_report_markdown(report)
            if args.format == "markdown"
            else json.dumps(report, indent=2, ensure_ascii=False)
        )
        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(output_text, encoding="utf-8")
        print(output_text)
        return 0 if report["overall_status"] == "PASSED" else 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
