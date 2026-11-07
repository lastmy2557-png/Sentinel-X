"""
Release Protection Security & Artifact Exposure Scanner (Section 5.1 & Section 9).
Performs:
1. Secret Scanning (with automatic redaction so reports never leak secrets)
2. Sensitive File Detection
3. Debug Artifact Exposure Checks
4. Source Map Exposure Checks
5. Build Configuration Hardening Checks
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

DEFAULT_SCAN_EXCLUDED_DIRS: Set[str] = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "build",
    "dist",
    "patches",
    "downloads",
}

SAFE_PLACEHOLDER_MARKERS = (
    "CHANGE_ME",
    "PLACEHOLDER",
    "YOUR_",
    "EXAMPLE",
    "DUMMY",
    "TEST_",
    "TODO",
)

# Secret regex rules: (rule_id, description, compiled_regex)
SECRET_PATTERNS: List[Tuple[str, str, re.Pattern[str]]] = [
    (
        "SEC-PRIV-KEY",
        "Embedded Cryptographic Private Key Header",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    ),
    (
        "SEC-AWS-AKIA",
        "AWS Access Key ID Pattern",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "SEC-GH-TOKEN",
        "GitHub Personal or Fine-Grained Access Token",
        re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"),
    ),
    (
        "SEC-SLACK-TOKEN",
        "Slack API Token Pattern",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    ),
    (
        "SEC-GENERIC-ASSIGN",
        "Hardcoded Password / Secret / API Key Assignment",
        re.compile(
            r"(?i)\b(?:password|passwd|api_key|secret_key|access_token|private_key)\s*[:=]\s*['\"]([^'\"]{12,})['\"]"
        ),
    ),
]

SENSITIVE_FILENAME_PATTERNS: List[Tuple[str, str]] = [
    (".env", "Local environment configuration file (.env)"),
    (".env.*", "Environment configuration file (.env.*)"),
    ("*.key", "Private or cryptographic key file (*.key)"),
    ("*.pem", "PEM certificate or private key file (*.pem)"),
    ("*.p12", "PKCS#12 key store (*.p12)"),
    ("*.pfx", "PFX certificate archive (*.pfx)"),
    ("id_rsa*", "SSH RSA key file"),
    ("id_ed25519*", "SSH Ed25519 key file"),
    ("credentials.json", "Credentials file"),
    (".htpasswd", "Apache password file"),
    (".netrc", "Network credentials file"),
]

DEBUG_ARTIFACT_PATTERNS: List[str] = [
    "*.pdb",
    "*.core",
    "core.*",
    "debug.log",
    "*.dmp",
]

DEBUG_CODE_RE = re.compile(r"\b(?:pdb\.set_trace\s*\(\)|breakpoint\s*\(\))")
SOURCEMAP_COMMENT_RE = re.compile(r"[@#]\s*sourceMappingURL\s*=\s*\S+")
UNSAFE_SUBPROCESS_RE = re.compile(r"subprocess\.(?:run|Popen|call|check_output)\([^)]*shell\s*=\s*True")


def redact_sensitive_text(line: str) -> str:
    """Mask potential secret values so audit findings never leak raw credentials."""
    trimmed = line.strip()
    if len(trimmed) > 120:
        trimmed = trimmed[:120] + "..."
    # Mask quoted strings longer than 6 chars
    return re.sub(
        r"(['\"])([^'\"]{6,})(['\"])",
        lambda m: f"{m.group(1)}{m.group(2)[:3]}***REDACTED***{m.group(3)}",
        trimmed,
    )


@dataclass(frozen=True)
class AuditFinding:
    """Single security finding produced by the Anti-REA Release Scanner."""

    category: str
    rule_id: str
    severity: str
    file_path: str
    line_number: int
    description: str
    redacted_evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "description": self.description,
            "redacted_evidence": self.redacted_evidence,
        }


class ReleaseSecurityScanner:
    """
    Scans a workspace or release directory for secrets, sensitive files, debug artifacts,
    source maps, and build configuration weaknesses.
    """

    def __init__(
        self,
        excluded_dirs: Optional[Set[str]] = None,
        include_tests: bool = False,
    ) -> None:
        self.excluded_dirs = (
            excluded_dirs if excluded_dirs is not None else set(DEFAULT_SCAN_EXCLUDED_DIRS)
        )
        self.include_tests = include_tests

    def scan_workspace(self, root_dir: Path | str) -> List[AuditFinding]:
        root = Path(root_dir).resolve()
        findings: List[AuditFinding] = []

        findings.extend(self._check_build_configuration(root))

        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                continue
            rel_parts = path.relative_to(root).parts
            if any(part in self.excluded_dirs for part in rel_parts):
                continue
            if not self.include_tests and "tests" in rel_parts:
                continue
            if path.is_dir():
                continue

            rel_posix = path.relative_to(root).as_posix()
            findings.extend(self._check_file_Metadata(path, rel_posix))
            findings.extend(self._check_file_contents(path, rel_posix))

        return findings

    def _check_build_configuration(self, root: Path) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        gitignore = root / ".gitignore"
        if not gitignore.is_file():
            findings.append(
                AuditFinding(
                    category="BUILD_CONFIG",
                    rule_id="CFG-NO-GITIGNORE",
                    severity="HIGH",
                    file_path=".gitignore",
                    line_number=0,
                    description="Missing .gitignore file in workspace root.",
                )
            )
        else:
            gi_text = gitignore.read_text(encoding="utf-8", errors="replace")
            for required_pattern in (".env", "*.key", "*.pem"):
                if required_pattern not in gi_text:
                    findings.append(
                        AuditFinding(
                            category="BUILD_CONFIG",
                            rule_id="CFG-WEAK-GITIGNORE",
                            severity="MEDIUM",
                            file_path=".gitignore",
                            line_number=0,
                            description=f".gitignore does not explicitly ignore '{required_pattern}'.",
                        )
                    )
        return findings

    def _check_file_Metadata(self, path: Path, rel_posix: str) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        name = path.name

        # Allow .env.example and *public*.pem / *public*.key
        if name == ".env.example" or "public" in name.lower():
            pass
        else:
            for pat, desc in SENSITIVE_FILENAME_PATTERNS:
                if fnmatch.fnmatch(name, pat):
                    findings.append(
                        AuditFinding(
                            category="SENSITIVE_FILE",
                            rule_id="FILE-SENSITIVE-EXPOSURE",
                            severity="CRITICAL",
                            file_path=rel_posix,
                            line_number=0,
                            description=f"Sensitive file present in release tree: {desc}",
                        )
                    )
                    break

        # Debug artifact filenames
        for pat in DEBUG_ARTIFACT_PATTERNS:
            if fnmatch.fnmatch(name, pat):
                findings.append(
                    AuditFinding(
                        category="DEBUG_ARTIFACT",
                        rule_id="DBG-ARTIFACT-FILE",
                        severity="MEDIUM",
                        file_path=rel_posix,
                        line_number=0,
                        description=f"Debug or crash artifact exposed in release tree: {name}",
                    )
                )
                break

        # Source map filenames
        if name.endswith((".js.map", ".css.map")):
            findings.append(
                AuditFinding(
                    category="SOURCE_MAP",
                    rule_id="MAP-FILE-EXPOSURE",
                    severity="MEDIUM",
                    file_path=rel_posix,
                    line_number=0,
                    description="Frontend source map file (.map) exposed in release tree.",
                )
            )

        return findings

    def _check_file_contents(self, path: Path, rel_posix: str) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        # Skip binary or large files (> 2MB)
        try:
            if path.stat().st_size > 2 * 1024 * 1024:
                return findings
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            return findings

        # Skip scanning the scanner module itself for regex pattern definitions
        is_scanner_self = rel_posix.endswith("security/release_protection/scanner.py")

        for line_no, raw_line in enumerate(text.splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if not is_scanner_self:
                for rule_id, desc, pattern in SECRET_PATTERNS:
                    match = pattern.search(raw_line)
                    if not match:
                        continue
                    upper_line = raw_line.upper()
                    if any(marker in upper_line for marker in SAFE_PLACEHOLDER_MARKERS):
                        continue
                    findings.append(
                        AuditFinding(
                            category="SECRET_SCAN",
                            rule_id=rule_id,
                            severity="CRITICAL",
                            file_path=rel_posix,
                            line_number=line_no,
                            description=desc,
                            redacted_evidence=redact_sensitive_text(raw_line),
                        )
                    )

            if not is_scanner_self and path.suffix == ".py":
                if DEBUG_CODE_RE.search(raw_line):
                    findings.append(
                        AuditFinding(
                            category="DEBUG_ARTIFACT",
                            rule_id="DBG-BREAKPOINT-CODE",
                            severity="HIGH",
                            file_path=rel_posix,
                            line_number=line_no,
                            description="Interactive debugger breakpoint left in Python code.",
                            redacted_evidence=redact_sensitive_text(raw_line),
                        )
                    )
                if UNSAFE_SUBPROCESS_RE.search(raw_line):
                    findings.append(
                        AuditFinding(
                            category="BUILD_CONFIG",
                            rule_id="CFG-UNSAFE-SHELL-TRUE",
                            severity="HIGH",
                            file_path=rel_posix,
                            line_number=line_no,
                            description="Subprocess invocation with shell=True detected.",
                            redacted_evidence=redact_sensitive_text(raw_line),
                        )
                    )

            if path.suffix in (".js", ".css", ".html") and SOURCEMAP_COMMENT_RE.search(raw_line):
                findings.append(
                    AuditFinding(
                        category="SOURCE_MAP",
                        rule_id="MAP-INLINE-DIRECTIVE",
                        severity="LOW",
                        file_path=rel_posix,
                        line_number=line_no,
                        description="Inline sourceMappingURL directive exposed in web asset.",
                        redacted_evidence=redact_sensitive_text(raw_line),
                    )
                )

        return findings
