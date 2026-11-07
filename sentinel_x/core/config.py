"""
Configuration management for Sentinel-X.
Loads settings from environment variables or a local .env file with strict validation
and automatic masking of sensitive fields.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from sentinel_x.core.exceptions import ConfigurationError

VALID_ENVIRONMENTS = {"development", "testing", "production"}
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
PLACEHOLDER_MARKERS = {"CHANGE_ME", "PLACEHOLDER", "YOUR_API_KEY", "TODO"}


def parse_dotenv_file(dotenv_path: Path) -> Dict[str, str]:
    """Safely parse a KEY=VALUE .env file without executing shell commands."""
    result: Dict[str, str] = {}
    if not dotenv_path.is_file():
        return result

    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            result[key] = value
    return result


def _is_real_secret(value: Optional[str]) -> bool:
    """Return True only if value is non-empty and not a template placeholder."""
    if not value or not value.strip():
        return False
    upper_val = value.strip().upper()
    return not any(marker in upper_val for marker in PLACEHOLDER_MARKERS)


@dataclass(frozen=True)
class SentinelConfig:
    """Validated runtime configuration for Sentinel-X."""

    env: str = "development"
    db_path: Path = Path("data/runtime/sentinel_x.db")
    log_level: str = "INFO"
    audit_log_path: Path = Path("logs/audit.log")
    max_ingest_file_bytes: int = 10 * 1024 * 1024  # 10 MB default limit
    allowed_ingest_dir: Path = Path("data/samples")
    host: str = "127.0.0.1"
    port: int = 8080
    api_token: str = ""
    siem_endpoint: str = ""
    siem_api_key: str = ""
    webhook_url: str = ""
    threat_intel_api_key: str = ""
    release_private_key_path: Optional[Path] = None
    release_public_key_path: Optional[Path] = None

    def __post_init__(self) -> None:
        if self.env not in VALID_ENVIRONMENTS:
            raise ConfigurationError(
                f"Invalid SENTINEL_ENV '{self.env}'. Must be one of {sorted(VALID_ENVIRONMENTS)}."
            )
        if self.log_level.upper() not in VALID_LOG_LEVELS:
            raise ConfigurationError(
                f"Invalid SENTINEL_LOG_LEVEL '{self.log_level}'. Must be one of {sorted(VALID_LOG_LEVELS)}."
            )
        if not (1 <= self.port <= 65535):
            raise ConfigurationError(
                f"Invalid SENTINEL_PORT '{self.port}'. Must be between 1 and 65535."
            )
        if self.max_ingest_file_bytes <= 0 or self.max_ingest_file_bytes > 500 * 1024 * 1024:
            raise ConfigurationError(
                f"Invalid SENTINEL_MAX_INGEST_FILE_BYTES '{self.max_ingest_file_bytes}'. "
                "Must be between 1 byte and 500 MB."
            )
        if not self.host or not self.host.strip():
            raise ConfigurationError("SENTINEL_HOST cannot be empty.")

    @classmethod
    def from_env(
        cls,
        environ: Optional[Mapping[str, str]] = None,
        dotenv_path: Optional[Path] = None,
    ) -> "SentinelConfig":
        """Load and validate configuration from environment variables and optional .env file."""
        merged: Dict[str, str] = {}
        if dotenv_path is not None:
            merged.update(parse_dotenv_file(dotenv_path))
        source_env = environ if environ is not None else os.environ
        merged.update(source_env)

        try:
            port = int(merged.get("SENTINEL_PORT", "8080"))
        except ValueError as exc:
            raise ConfigurationError("SENTINEL_PORT must be a valid integer.") from exc

        try:
            max_bytes = int(merged.get("SENTINEL_MAX_INGEST_FILE_BYTES", str(10 * 1024 * 1024)))
        except ValueError as exc:
            raise ConfigurationError(
                "SENTINEL_MAX_INGEST_FILE_BYTES must be a valid integer."
            ) from exc

        priv_key_raw = merged.get("SENTINEL_RELEASE_PRIVATE_KEY_PATH", "").strip()
        pub_key_raw = merged.get("SENTINEL_RELEASE_PUBLIC_KEY_PATH", "").strip()

        raw_token = merged.get("SENTINEL_API_TOKEN", "").strip()
        api_token = raw_token if _is_real_secret(raw_token) else ""

        raw_siem_key = merged.get("SENTINEL_SIEM_API_KEY", "").strip()
        siem_api_key = raw_siem_key if _is_real_secret(raw_siem_key) else ""

        raw_ti_key = merged.get("SENTINEL_THREAT_INTEL_API_KEY", "").strip()
        ti_api_key = raw_ti_key if _is_real_secret(raw_ti_key) else ""

        return cls(
            env=merged.get("SENTINEL_ENV", "development").strip().lower(),
            db_path=Path(merged.get("SENTINEL_DB_PATH", "data/runtime/sentinel_x.db").strip()),
            log_level=merged.get("SENTINEL_LOG_LEVEL", "INFO").strip().upper(),
            audit_log_path=Path(merged.get("SENTINEL_AUDIT_LOG_PATH", "logs/audit.log").strip()),
            max_ingest_file_bytes=max_bytes,
            allowed_ingest_dir=Path(
                merged.get("SENTINEL_ALLOWED_INGEST_DIR", "data/samples").strip()
            ),
            host=merged.get("SENTINEL_HOST", "127.0.0.1").strip(),
            port=port,
            api_token=api_token,
            siem_endpoint=merged.get("SENTINEL_SIEM_ENDPOINT", "").strip(),
            siem_api_key=siem_api_key,
            webhook_url=merged.get("SENTINEL_WEBHOOK_URL", "").strip(),
            threat_intel_api_key=ti_api_key,
            release_private_key_path=Path(priv_key_raw) if priv_key_raw else None,
            release_public_key_path=Path(pub_key_raw) if pub_key_raw else None,
        )

    def to_safe_dict(self) -> Dict[str, Any]:
        """Return a dictionary representation with all secrets masked."""
        return {
            "env": self.env,
            "db_path": str(self.db_path),
            "log_level": self.log_level,
            "audit_log_path": str(self.audit_log_path),
            "max_ingest_file_bytes": self.max_ingest_file_bytes,
            "allowed_ingest_dir": str(self.allowed_ingest_dir),
            "host": self.host,
            "port": self.port,
            "api_token_configured": bool(self.api_token),
            "siem_configured": bool(self.siem_endpoint and self.siem_api_key),
            "webhook_configured": bool(self.webhook_url),
            "threat_intel_configured": bool(self.threat_intel_api_key),
            "release_private_key_configured": self.release_private_key_path is not None,
            "release_public_key_configured": self.release_public_key_path is not None,
        }

    def __repr__(self) -> str:
        safe = self.to_safe_dict()
        items = ", ".join(f"{k}={v!r}" for k, v in safe.items())
        return f"SentinelConfig({items})"
