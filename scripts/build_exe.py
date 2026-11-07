"""
Sentinel-X Standalone Executable Builder (`scripts/build_exe.py`).
Compiles Sentinel-X into a single-file executable (`dist/sentinel-x.exe` on Windows)
using PyInstaller, with pre-build Anti-REA security auditing and post-build SHA-256
integrity manifest generation.

Security guarantees:
- Runs Anti-REA Secret & Sensitive File Audit BEFORE building; aborts if findings exist.
- Invokes PyInstaller with shell=False to prevent command injection.
- Generates a SHA-256 checksum file and build manifest for Tamper Detection.
"""

from __future__ import annotations

import argparse
import json
import os
import platform as py_platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is on sys.path when running python scripts/build_exe.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sentinel_x import __version__
from sentinel_x.security.release_protection.inventory import compute_file_sha256
from sentinel_x.security.release_protection.report import generate_security_audit_report


def build_pyinstaller_command(
    project_root: Path,
    dist_dir: Path,
    work_dir: Path,
    exe_name: str = "sentinel-x",
) -> List[str]:
    """Construct safe argument list for PyInstaller (shell=False)."""
    entrypoint = project_root / "sentinel_x" / "__main__.py"
    data_sep = ";" if os.name == "nt" else ":"
    rules_src = project_root / "config" / "rules"
    samples_src = project_root / "data" / "samples"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        exe_name,
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(work_dir),
        "--specpath",
        str(work_dir),
    ]
    if rules_src.is_dir():
        cmd.extend(["--add-data", f"{rules_src}{data_sep}config/rules"])
    if samples_src.is_dir():
        cmd.extend(["--add-data", f"{samples_src}{data_sep}data/samples"])

    cmd.append(str(entrypoint))
    return cmd


def write_build_integrity_artifacts(exe_path: Path, dist_dir: Path) -> Dict[str, Any]:
    """Compute SHA-256 digest of the compiled executable and write integrity metadata."""
    sha256_hex = compute_file_sha256(exe_path)
    size_bytes = exe_path.stat().st_size

    checksum_file = dist_dir / f"{exe_path.name}.sha256"
    checksum_file.write_text(f"{sha256_hex}  {exe_path.name}\n", encoding="utf-8")

    build_manifest = {
        "schema": "sentinel_x.executable_build.v1",
        "version": __version__,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "target_os": py_platform.system(),
        "target_arch": py_platform.machine(),
        "executable_name": exe_path.name,
        "size_bytes": size_bytes,
        "sha256": sha256_hex,
        "checksum_file": checksum_file.name,
    }
    manifest_file = dist_dir / "build_manifest.json"
    manifest_file.write_text(
        json.dumps(build_manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return build_manifest


def run_build(
    project_root: Path = PROJECT_ROOT,
    dist_dir: Optional[Path] = None,
    work_dir: Optional[Path] = None,
    exe_name: str = "sentinel-x",
    dry_run: bool = False,
    skip_audit: bool = False,
) -> Dict[str, Any]:
    """Execute pre-build Anti-REA audit, PyInstaller compilation, and SHA-256 hashing."""
    root = project_root.resolve()
    out_dist = (dist_dir or (root / "dist")).resolve()
    out_work = (work_dir or (root / "build" / "pyinstaller")).resolve()

    if not skip_audit:
        audit_report = generate_security_audit_report(root, include_tests_in_scan=False)
        if audit_report["overall_status"] != "PASSED":
            raise RuntimeError(
                f"Pre-build Anti-REA Security Audit FAILED with "
                f"{audit_report['finding_summary']['total_findings']} finding(s). "
                "Resolve security findings before compiling an executable."
            )

    pyinstaller_cmd = build_pyinstaller_command(
        project_root=root,
        dist_dir=out_dist,
        work_dir=out_work,
        exe_name=exe_name,
    )

    if dry_run:
        return {
            "status": "DRY_RUN",
            "audit_passed": not skip_audit,
            "command": pyinstaller_cmd,
            "dist_dir": str(out_dist),
        }

    # Check if PyInstaller is installed in current Python environment
    check_proc = subprocess.run(
        [sys.executable, "-c", "import PyInstaller"],
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    if check_proc.returncode != 0:
        raise RuntimeError(
            "PyInstaller is not installed in the current Python environment. "
            "Install it first with: pip install pyinstaller pyyaml"
        )

    out_dist.mkdir(parents=True, exist_ok=True)
    out_work.mkdir(parents=True, exist_ok=True)

    proc = subprocess.run(
        pyinstaller_cmd,
        cwd=str(root),
        check=False,
        shell=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"PyInstaller build failed with exit code {proc.returncode}.")

    expected_filename = f"{exe_name}.exe" if os.name == "nt" else exe_name
    exe_path = out_dist / expected_filename
    if not exe_path.is_file():
        raise RuntimeError(f"Expected compiled binary not found at: {exe_path}")

    build_manifest = write_build_integrity_artifacts(exe_path, out_dist)
    return {
        "status": "BUILT",
        "executable_path": str(exe_path),
        "build_manifest": build_manifest,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build_exe",
        description="Build Sentinel-X standalone executable (.exe on Windows) with Anti-REA verification",
    )
    parser.add_argument("--dist-dir", default="", help="Output directory (default: ./dist)")
    parser.add_argument("--work-dir", default="", help="Temporary build directory (default: ./build/pyinstaller)")
    parser.add_argument("--name", default="sentinel-x", help="Executable base name (default: sentinel-x)")
    parser.add_argument("--dry-run", action="store_true", help="Run Anti-REA audit and print PyInstaller command without compiling")
    args = parser.parse_args(argv)

    try:
        result = run_build(
            project_root=PROJECT_ROOT,
            dist_dir=Path(args.dist_dir) if args.dist_dir else None,
            work_dir=Path(args.work_dir) if args.work_dir else None,
            exe_name=args.name,
            dry_run=args.dry_run,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
