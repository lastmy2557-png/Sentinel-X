"""
Structured Security Audit Logging for Sentinel-X.
Sanitizes control characters to prevent log injection and writes JSON-Lines audit records.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def sanitize_log_field(value: str) -> str:
    """Strip CR/LF and non-printable control characters to prevent log injection."""
    if not isinstance(value, str):
        value = str(value)
    return "".join(ch if (ch >= " " or ch == "\t") else " " for ch in value).strip()


class AuditLogger:
    """Writes immutable-style JSONL audit records for security-sensitive operations."""

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path

    def record(
        self,
        action: str,
        actor: str = "system",
        target: str = "",
        status: str = "SUCCESS",
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record a security audit entry to the JSONL audit file and return the record."""
        entry = {
            "audit_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": sanitize_log_field(actor),
            "action": sanitize_log_field(action),
            "target": sanitize_log_field(target),
            "status": sanitize_log_field(status),
            "details": details or {},
        }
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry
