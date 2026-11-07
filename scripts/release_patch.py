"""
Sentinel-X Automated Patch Generator, Executable Compiler & GitHub Version Updater
(`scripts/release_patch.py`).

Whenever files are updated in Sentinel-X, this pipeline automates:
1. Semantic Version Bumping (`patch`, `minor`, `major`, or explicit `--version`) across
   `sentinel_x/__init__.py` and `pyproject.toml`.
2. Pre-release Anti-REA Security Audit (blocks release if any secret or sensitive file is found).
3. Unified Git Patch Generation (`patches/v<version>.patch`, `patches/latest.patch`, and
   `patches/PATCH_MANIFEST.json` with SHA-256 integrity digest).
4. Complete Standalone Executable Compilation (`dist/sentinel-x.exe`, `dist/sentinel-x.exe.sha256`,
   `dist/build_manifest.json`) + Release Packages (`.whl`, `.tar.gz`, `.zip`, `SHA256SUMS.txt`).
5. Optional Git Commit, Annotated Tagging (`v<version>`), and Push to GitHub (`origin/main` + tag).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.build_exe import _read_current_version, run_build
from scripts.build_release_package import build_all_release_packages
from sentinel_x.security.release_protection.report import generate_security_audit_report

SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def parse_semver(version_str: str) -> Tuple[int, int, int]:
    """Parse a strict X.Y.Z semantic version string."""
    cleaned = version_str.strip().lstrip("v")
    match = SEMVER_RE.match(cleaned)
    if not match:
        raise ValueError(f"Invalid semantic version '{version_str}'. Expected format: X.Y.Z")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def bump_semver(current_version: str, bump_type: str = "patch") -> str:
    """Increment patch, minor, or major version number."""
    major, minor, patch = parse_semver(current_version)
    if bump_type == "patch":
        return f"{major}.{minor}.{patch + 1}"
    if bump_type == "minor":
        return f"{major}.{minor + 1}.0"
    if bump_type == "major":
        return f"{major + 1}.0.0"
    raise ValueError(f"Unsupported bump_type '{bump_type}'. Must be patch, minor, or major.")


def update_version_files(project_root: Path, new_version: str) -> List[str]:
    """Update version string in sentinel_x/__init__.py and pyproject.toml."""
    parse_semver(new_version)
    updated_files: List[str] = []

    init_path = project_root / "sentinel_x" / "__init__.py"
    if init_path.is_file():
        old_init = init_path.read_text(encoding="utf-8")
        new_init = re.sub(
            r'__version__\s*=\s*["\'][^"\']+["\']',
            f'__version__ = "{new_version}"',
            old_init,
        )
        init_path.write_text(new_init, encoding="utf-8")
        updated_files.append("sentinel_x/__init__.py")

    pyproject_path = project_root / "pyproject.toml"
    if pyproject_path.is_file():
        old_toml = pyproject_path.read_text(encoding="utf-8")
        new_toml = re.sub(
            r'(?m)^version\s*=\s*["\'][^"\']+["\']',
            f'version = "{new_version}"',
            old_toml,
        )
        pyproject_path.write_text(new_toml, encoding="utf-8")
        updated_files.append("pyproject.toml")

    return updated_files


def generate_git_patch(
    project_root: Path,
    patches_dir: Path,
    from_version: str,
    to_version: str,
    summary: str = "Automated patch & executable update",
    base_ref: str = "",
) -> Dict[str, Any]:
    """
    Generate a clean unified diff .patch file (`patches/v<to_version>.patch` and `patches/latest.patch`)
    plus `patches/PATCH_MANIFEST.json`.
    """
    patches_dir.mkdir(parents=True, exist_ok=True)
    patch_filename = f"v{to_version}.patch"
    patch_path = patches_dir / patch_filename
    latest_patch_path = patches_dir / "latest.patch"
    manifest_path = patches_dir / "PATCH_MANIFEST.json"

    ref_to_diff = base_ref.strip()
    if not ref_to_diff:
        # Check if tag v<from_version> exists in git; otherwise diff against HEAD~1 or HEAD
        tag_candidate = f"v{from_version}"
        tag_check = subprocess.run(
            ["git", "rev-parse", "--verify", tag_candidate],
            cwd=str(project_root),
            check=False,
            capture_output=True,
            text=True,
            shell=False,
        )
        if tag_check.returncode == 0:
            ref_to_diff = tag_candidate
        else:
            head_prev = subprocess.run(
                ["git", "rev-parse", "--verify", "HEAD~1"],
                cwd=str(project_root),
                check=False,
                capture_output=True,
                text=True,
                shell=False,
            )
            ref_to_diff = "HEAD~1" if head_prev.returncode == 0 else "HEAD"

    diff_cmd = [
        "git",
        "diff",
        ref_to_diff,
        "--",
        ".",
        ":(exclude)dist",
        ":(exclude)patches",
    ]
    diff_proc = subprocess.run(
        diff_cmd,
        cwd=str(project_root),
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    diff_body = diff_proc.stdout if diff_proc.returncode == 0 else ""

    header_comment = (
        f"# Sentinel-X Official Patch File\n"
        f"# From Version : v{from_version}\n"
        f"# To Version   : v{to_version}\n"
        f"# Summary      : {summary}\n"
        f"# Generated At : {datetime.now(timezone.utc).isoformat()}\n"
        f"# Apply Command: git apply patches/{patch_filename}\n\n"
    )
    full_patch_text = header_comment + diff_body
    patch_path.write_text(full_patch_text, encoding="utf-8")
    latest_patch_path.write_text(full_patch_text, encoding="utf-8")

    patch_sha256 = hashlib.sha256(patch_path.read_bytes()).hexdigest()

    # Load existing patch history if present
    history: List[Dict[str, Any]] = []
    if manifest_path.is_file():
        try:
            old_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if isinstance(old_manifest.get("history"), list):
                history = [
                    item
                    for item in old_manifest["history"]
                    if item.get("to_version") != to_version
                ]
        except Exception:
            history = []

    entry = {
        "from_version": from_version,
        "to_version": to_version,
        "tag": f"v{to_version}",
        "patch_file": f"patches/{patch_filename}",
        "patch_sha256": patch_sha256,
        "patch_size_bytes": patch_path.stat().st_size,
        "summary": summary,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    history.insert(0, entry)

    manifest_data = {
        "schema": "sentinel_x.patch_manifest.v1",
        "latest_version": to_version,
        "latest_tag": f"v{to_version}",
        "latest_patch": entry,
        "history": history[:25],
    }
    manifest_path.write_text(
        json.dumps(manifest_data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return entry


def execute_patch_release(
    project_root: Path = PROJECT_ROOT,
    bump_type: str = "patch",
    target_version: str = "",
    summary: str = "Update files, generate patch, and recompile standalone executable",
    dist_dir: Optional[Path] = None,
    patches_dir: Optional[Path] = None,
    commit_and_push: bool = False,
) -> Dict[str, Any]:
    """
    Execute the complete Patch + Compile + Version Bump (+ optional GitHub Push) workflow.
    """
    root = project_root.resolve()
    out_dist = (dist_dir or (root / "dist")).resolve()
    out_patches = (patches_dir or (root / "patches")).resolve()

    old_version = _read_current_version(root)
    new_version = target_version.strip().lstrip("v") if target_version.strip() else bump_semver(old_version, bump_type)
    parse_semver(new_version)

    # 1. Update version in source files
    updated_version_files = update_version_files(root, new_version)

    # 2. Run Anti-REA Security Audit
    audit_report = generate_security_audit_report(root, include_tests_in_scan=False)
    if audit_report["overall_status"] != "PASSED":
        raise RuntimeError(
            f"Anti-REA Security Audit FAILED with "
            f"{audit_report['finding_summary']['total_findings']} finding(s)."
        )

    # 3. Generate .patch file and PATCH_MANIFEST.json
    patch_entry = generate_git_patch(
        project_root=root,
        patches_dir=out_patches,
        from_version=old_version,
        to_version=new_version,
        summary=summary,
    )

    # 4. Compile standalone Windows executable (dist/sentinel-x.exe) + SHA-256 + build_manifest.json
    exe_build_result = run_build(
        project_root=root,
        dist_dir=out_dist,
        exe_name="sentinel-x",
        dry_run=False,
        skip_audit=True,
    )

    # 5. Build release distribution packages (.whl, .tar.gz, .zip, release_manifest.json, SHA256SUMS.txt)
    pkg_build_result = build_all_release_packages(
        project_root=root,
        dist_dir=out_dist,
        version=new_version,
    )

    # 6. Synchronize Vercel Official Website metadata (public/version.json & public/index.html)
    public_dir = root / "public"
    if public_dir.is_dir():
        exe_meta = exe_build_result.get("build_manifest", {})
        version_json_path = public_dir / "version.json"
        version_payload = {
            "platform": "Sentinel-X Cybersecurity & SOC Platform",
            "version": new_version,
            "tag": f"v{new_version}",
            "exe_name": exe_meta.get("executable_name", "sentinel-x.exe"),
            "exe_size_bytes": exe_meta.get("size_bytes", 0),
            "exe_sha256": exe_meta.get("sha256", ""),
            "patch_file": patch_entry.get("patch_file", f"patches/v{new_version}.patch"),
            "patch_sha256": patch_entry.get("patch_sha256", ""),
            "github_repo": "https://github.com/lastmy2557-png/Sentinel-X",
            "github_release_url": f"https://github.com/lastmy2557-png/Sentinel-X/releases/tag/v{new_version}",
            "ghcr_image": "ghcr.io/lastmy2557-png/sentinel-x:latest",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        version_json_path.write_text(
            json.dumps(version_payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        updated_version_files.append("public/version.json")

        index_html_path = public_dir / "index.html"
        if index_html_path.is_file():
            html_content = index_html_path.read_text(encoding="utf-8")
            html_content = re.sub(
                r'(<[^>]+data-live-version[^>]*>)v[0-9]+\.[0-9]+\.[0-9]+(<)',
                rf'\g<1>v{new_version}\2',
                html_content,
            )
            index_html_path.write_text(html_content, encoding="utf-8")
            updated_version_files.append("public/index.html")

    git_status_info: Dict[str, Any] = {"committed": False, "pushed": False, "tag": f"v{new_version}"}
    if commit_and_push:
        subprocess.run(["git", "add", "-A"], cwd=str(root), check=True, shell=False)
        commit_msg = f"release(v{new_version}): {summary}"
        subprocess.run(
            ["git", "commit", "-m", commit_msg],
            cwd=str(root),
            check=True,
            shell=False,
        )
        tag_name = f"v{new_version}"
        subprocess.run(
            ["git", "tag", "-f", "-a", tag_name, "-m", f"Sentinel-X {tag_name} — {summary}"],
            cwd=str(root),
            check=True,
            shell=False,
        )
        subprocess.run(["git", "push", "origin", "main"], cwd=str(root), check=True, shell=False)
        subprocess.run(["git", "push", "-f", "origin", tag_name], cwd=str(root), check=True, shell=False)
        git_status_info["committed"] = True
        git_status_info["pushed"] = True

    return {
        "status": "PATCH_RELEASE_COMPLETED",
        "from_version": old_version,
        "to_version": new_version,
        "updated_version_files": updated_version_files,
        "patch": patch_entry,
        "executable": exe_build_result,
        "release_packages": pkg_build_result,
        "git": git_status_info,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="release_patch",
        description="Bump version, generate .patch file, compile sentinel-x.exe, and update GitHub release tag",
    )
    parser.add_argument(
        "--bump",
        choices=["patch", "minor", "major"],
        default="patch",
        help="Semantic version part to increment (default: patch)",
    )
    parser.add_argument("--version", default="", help="Explicit target version (e.g. 0.1.1)")
    parser.add_argument(
        "--summary",
        default="Update files, generate patch, and recompile standalone executable",
        help="Short summary of the patch changes",
    )
    parser.add_argument(
        "--commit-and-push",
        action="store_true",
        help="Commit all artifacts, create annotated tag v<version>, and push to GitHub origin",
    )
    args = parser.parse_args(argv)

    try:
        res = execute_patch_release(
            project_root=PROJECT_ROOT,
            bump_type=args.bump,
            target_version=args.version,
            summary=args.summary,
            commit_and_push=args.commit_and_push,
        )
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
