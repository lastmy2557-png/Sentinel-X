"""
Anti-REA / Release Protection independent module for Sentinel-X (Section 5).
Provides:
- SHA-256 File Inventory
- Ed25519 Signed Release Manifest & Tamper Detection
- Secret Scanning & Sensitive File / Debug / Source Map / Build Config Checks
- Security Audit Reports & Release Verification CLI
"""

from sentinel_x.security.release_protection.inventory import (
    FileInventoryEntry,
    build_file_inventory,
    compute_file_sha256,
)
from sentinel_x.security.release_protection.manifest import (
    ANTI_REA_SCOPE_STATEMENT,
    VerificationResult,
    create_release_manifest,
    generate_ed25519_keypair,
    sign_payload_ed25519,
    verify_payload_ed25519,
    verify_release_manifest,
)
from sentinel_x.security.release_protection.report import (
    format_audit_report_markdown,
    generate_security_audit_report,
)
from sentinel_x.security.release_protection.scanner import (
    AuditFinding,
    ReleaseSecurityScanner,
    redact_sensitive_text,
)

__all__ = [
    "ANTI_REA_SCOPE_STATEMENT",
    "AuditFinding",
    "FileInventoryEntry",
    "ReleaseSecurityScanner",
    "VerificationResult",
    "build_file_inventory",
    "compute_file_sha256",
    "create_release_manifest",
    "format_audit_report_markdown",
    "generate_ed25519_keypair",
    "generate_security_audit_report",
    "redact_sensitive_text",
    "sign_payload_ed25519",
    "verify_payload_ed25519",
    "verify_release_manifest",
]
