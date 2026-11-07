"""
Sentinel-X Release & Distribution Package Builder (`scripts/build_release_package.py`).
Builds standard distribution artifacts for GitHub Releases and GitHub Packages:
1. PEP 427 Python Wheel (`dist/sentinel_x-<version>-py3-none-any.whl`)
2. Source Distribution Tarball (`dist/sentinel_x-<version>.tar.gz`)
3. Portable Release Bundle (`dist/sentinel-x-<version>-release-bundle.zip`)
4. Anti-REA Release Manifest (`dist/release_manifest.json`)
5. Master SHA-256 Checksum File (`dist/SHA256SUMS.txt`)

Runs Anti-REA Security Audit BEFORE building any package and uses only Python 3.11+
standard library modules for deterministic, supply-chain-safe packaging.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sentinel_x import __version__
from sentinel_x.security.release_protection.inventory import (
    build_file_inventory,
    compute_file_sha256,
)
from sentinel_x.security.release_protection.manifest import create_release_manifest
from sentinel_x.security.release_protection.report import generate_security_audit_report


def _urlsafe_b64_nopad(digest: bytes) -> str:
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def build_pep427_wheel(project_root: Path, dist_dir: Path, version: str = __version__) -> Path:
    """Build a standards-compliant PEP 427 pure-Python wheel (.whl) with SHA-256 RECORD."""
    dist_dir.mkdir(parents=True, exist_ok=True)
    dist_info = f"sentinel_x-{version}.dist-info"
    wheel_name = f"sentinel_x-{version}-py3-none-any.whl"
    wheel_path = dist_dir / wheel_name

    pkg_dir = project_root / "sentinel_x"
    py_files = sorted(
        p for p in pkg_dir.rglob("*.py") if "__pycache__" not in p.parts
    )

    records: List[str] = []

    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as whl:
        for file_path in py_files:
            rel_posix = file_path.relative_to(project_root).as_posix()
            raw = file_path.read_bytes()
            whl.writestr(rel_posix, raw)
            sha_b64 = _urlsafe_b64_nopad(hashlib.sha256(raw).digest())
            records.append(f"{rel_posix},sha256={sha_b64},{len(raw)}")

        metadata_text = (
            "Metadata-Version: 2.1\n"
            "Name: sentinel-x\n"
            f"Version: {version}\n"
            "Summary: Sentinel-X Cybersecurity, SOC, Threat Detection & Release Protection Platform\n"
            "Author: Sentinel-X Engineering Team\n"
            "License: MIT\n"
            "Requires-Python: >=3.11\n\n"
            "Sentinel-X Local-first Cybersecurity & SOC Platform.\n"
        ).encode("utf-8")

        wheel_meta_text = (
            "Wheel-Version: 1.0\n"
            "Generator: sentinel-x-release-builder\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode("utf-8")

        entry_points_text = (
            "[console_scripts]\n"
            "sentinel-x = sentinel_x.cli:main\n"
            "sentinel-x-release = sentinel_x.security.release_protection.cli:main\n"
        ).encode("utf-8")

        for meta_name, meta_bytes in (
            (f"{dist_info}/METADATA", metadata_text),
            (f"{dist_info}/WHEEL", wheel_meta_text),
            (f"{dist_info}/entry_points.txt", entry_points_text),
        ):
            whl.writestr(meta_name, meta_bytes)
            sha_b64 = _urlsafe_b64_nopad(hashlib.sha256(meta_bytes).digest())
            records.append(f"{meta_name},sha256={sha_b64},{len(meta_bytes)}")

        record_path = f"{dist_info}/RECORD"
        records.append(f"{record_path},,")
        record_bytes = ("\n".join(records) + "\n").encode("utf-8")
        whl.writestr(record_path, record_bytes)

    return wheel_path


def build_source_tarball(project_root: Path, dist_dir: Path, version: str = __version__) -> Path:
    """Build a source distribution tarball (.tar.gz) containing all inventoried release files."""
    dist_dir.mkdir(parents=True, exist_ok=True)
    tar_name = f"sentinel_x-{version}.tar.gz"
    tar_path = dist_dir / tar_name
    prefix = f"sentinel_x-{version}"

    entries = build_file_inventory(project_root)
    with tarfile.open(tar_path, "w:gz") as tf:
        for entry in entries:
            full_path = project_root / entry.relative_path
            tf.add(full_path, arcname=f"{prefix}/{entry.relative_path}")
    return tar_path


def build_release_bundle_zip(project_root: Path, dist_dir: Path, version: str = __version__) -> Path:
    """Build a portable cross-platform release bundle (.zip) ready for GitHub Releases."""
    dist_dir.mkdir(parents=True, exist_ok=True)
    zip_name = f"sentinel-x-{version}-release-bundle.zip"
    zip_path = dist_dir / zip_name
    prefix = f"Sentinel-X-{version}"

    entries = build_file_inventory(project_root)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for entry in entries:
            full_path = project_root / entry.relative_path
            zf.write(full_path, arcname=f"{prefix}/{entry.relative_path}")
    return zip_path


def write_sha256_sums(artifact_paths: Iterable[Path], dist_dir: Path) -> Path:
    """Write a standard SHA256SUMS.txt file for all generated release artifacts."""
    lines: List[str] = []
    for path in sorted(artifact_paths, key=lambda p: p.name):
        if path.is_file() and path.name != "SHA256SUMS.txt":
            digest = compute_file_sha256(path)
            lines.append(f"{digest}  {path.name}")
    sums_path = dist_dir / "SHA256SUMS.txt"
    sums_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return sums_path


def build_all_release_packages(
    project_root: Path = PROJECT_ROOT,
    dist_dir: Optional[Path] = None,
    version: str = __version__,
    private_key_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run Anti-REA security audit and build all GitHub Release & Package artifacts."""
    root = project_root.resolve()
    out_dir = (dist_dir or (root / "dist")).resolve()

    audit_report = generate_security_audit_report(root, include_tests_in_scan=False)
    if audit_report["overall_status"] != "PASSED":
        raise RuntimeError(
            f"Pre-release Anti-REA Security Audit FAILED with "
            f"{audit_report['finding_summary']['total_findings']} finding(s)."
        )

    out_dir.mkdir(parents=True, exist_ok=True)

    wheel_path = build_pep427_wheel(root, out_dir, version=version)
    sdist_path = build_source_tarball(root, out_dir, version=version)
    bundle_path = build_release_bundle_zip(root, out_dir, version=version)

    manifest_path = out_dir / "release_manifest.json"
    create_release_manifest(
        root_dir=root,
        version=version,
        publisher="Sentinel-X Release Engineering",
        private_key_path=private_key_path,
        output_path=manifest_path,
    )

    all_artifacts = [wheel_path, sdist_path, bundle_path, manifest_path]
    exe_candidate = out_dir / "sentinel-x.exe"
    if exe_candidate.is_file():
        all_artifacts.append(exe_candidate)

    sums_path = write_sha256_sums(all_artifacts, out_dir)

    return {
        "status": "RELEASE_PACKAGES_BUILT",
        "version": version,
        "audit_status": audit_report["overall_status"],
        "output_dir": str(out_dir),
        "artifacts": [
            {
                "name": p.name,
                "path": str(p),
                "size_bytes": p.stat().st_size,
                "sha256": compute_file_sha256(p),
            }
            for p in [*all_artifacts, sums_path]
        ],
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build_release_package",
        description="Build Sentinel-X GitHub Release & Python/Bundle packages with Anti-REA verification",
    )
    parser.add_argument("--dist-dir", default="", help="Output directory (default: ./dist)")
    parser.add_argument("--version", default=__version__, help="Release version string")
    parser.add_argument("--private-key", default="", help="Optional external Ed25519 private key path for signing")
    args = parser.parse_args(argv)

    try:
        res = build_all_release_packages(
            project_root=PROJECT_ROOT,
            dist_dir=Path(args.dist_dir) if args.dist_dir else None,
            version=args.version,
            private_key_path=Path(args.private_key) if args.private_key else None,
        )
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
