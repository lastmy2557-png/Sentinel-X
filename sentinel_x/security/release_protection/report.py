"""
Security Audit Report Generator for Sentinel-X Anti-REA / Release Protection (Sections 5.1 & 5.4).
Produces structured JSON and Markdown audit reports covering:
- Tamper Detection & Release Integrity Verification
- Secret Scanning
- Sensitive File Exposure
- Debug Artifact & Source Map Exposure
- Build Configuration Hardening
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sentinel_x.security.release_protection.inventory import build_file_inventory
from sentinel_x.security.release_protection.manifest import (
    ANTI_REA_SCOPE_STATEMENT,
    VerificationResult,
)
from sentinel_x.security.release_protection.scanner import (
    AuditFinding,
    ReleaseSecurityScanner,
)


def generate_security_audit_report(
    root_dir: Path | str,
    verification_result: Optional[VerificationResult] = None,
    include_tests_in_scan: bool = False,
) -> Dict[str, Any]:
    """Run Anti-REA security checks on root_dir and return a structured audit report."""
    root = Path(root_dir).resolve()
    scanner = ReleaseSecurityScanner(include_tests=include_tests_in_scan)
    findings: List[AuditFinding] = scanner.scan_workspace(root)
    inventory = build_file_inventory(root)

    severity_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    category_counts: Dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    has_blocking_findings = (
        severity_counts.get("CRITICAL", 0) > 0 or severity_counts.get("HIGH", 0) > 0
    )
    manifest_ok = verification_result.verified if verification_result is not None else True
    overall_passed = (not has_blocking_findings) and manifest_ok

    return {
        "report_type": "SENTINEL_X_ANTI_REA_AUDIT_REPORT",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_directory": str(root),
        "overall_status": "PASSED" if overall_passed else "FAILED",
        "security_capabilities": [
            "Tamper Detection",
            "Release Integrity Verification",
            "Build Hardening",
            "Sensitive Artifact Exposure Reduction",
            "Unauthorized Modification Detection",
        ],
        "security_scope_and_limitations": ANTI_REA_SCOPE_STATEMENT,
        "inventory_summary": {
            "total_release_files": len(inventory),
            "total_bytes": sum(e.size_bytes for e in inventory),
        },
        "manifest_verification": (
            verification_result.to_dict() if verification_result is not None else None
        ),
        "finding_summary": {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "by_category": category_counts,
        },
        "findings": [f.to_dict() for f in findings],
    }


def format_audit_report_markdown(report: Dict[str, Any]) -> str:
    """Format a structured Anti-REA audit report dictionary into Markdown."""
    lines = [
        "# Sentinel-X Release Protection (Anti-REA) Security Audit Report",
        "",
        f"- **Generated At (UTC):** `{report['generated_at']}`",
        f"- **Overall Audit Status:** **`{report['overall_status']}`**",
        f"- **Total Release Files Inventoried:** `{report['inventory_summary']['total_release_files']}`",
        f"- **Total Findings:** `{report['finding_summary']['total_findings']}`",
        "",
        "## Security Scope & Honest Limitations",
        f"> {report['security_scope_and_limitations']}",
        "",
        "## Findings by Severity",
    ]
    for sev, cnt in report["finding_summary"]["by_severity"].items():
        lines.append(f"- **{sev}:** {cnt}")

    if report.get("manifest_verification"):
        mv = report["manifest_verification"]
        lines.extend(
            [
                "",
                "## Release Manifest & Tamper Detection",
                f"- **Verified:** `{mv['verified']}`",
                f"- **Digital Signature Verified:** `{mv['signature_verified']}` (`{mv['signature_algorithm']}`)",
                f"- **File Integrity Verified:** `{mv['integrity_verified']}`",
                f"- **Summary:** {mv['summary']}",
            ]
        )

    lines.extend(["", "## Detailed Security Findings"])
    if not report["findings"]:
        lines.append("- No secrets, sensitive files, debug artifacts, or build misconfigurations detected.")
    else:
        for item in report["findings"]:
            lines.append(
                f"- **[{item['severity']}] `{item['rule_id']}` ({item['category']})** — "
                f"`{item['file_path']}` (line {item['line_number']}): {item['description']}"
            )
            if item.get("redacted_evidence"):
                lines.append(f"  - Evidence (Redacted): `{item['redacted_evidence']}`")

    return "\n".join(lines) + "\n"
