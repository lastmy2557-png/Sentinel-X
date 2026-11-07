"""Core foundation components for Sentinel-X."""

from sentinel_x.core.audit import AuditLogger, sanitize_log_field
from sentinel_x.core.config import SentinelConfig
from sentinel_x.core.database import DatabaseManager
from sentinel_x.core.exceptions import (
    ConfigurationError,
    DetectionError,
    IncidentNotFoundError,
    IngestionError,
    ReleaseProtectionError,
    SecurityBoundaryError,
    SentinelXError,
    SignatureVerificationError,
    StorageError,
    ValidationError,
)
from sentinel_x.core.models import (
    Alert,
    AlertStatus,
    DetectionRule,
    EventCategory,
    Incident,
    IncidentNote,
    IncidentStatus,
    MitreReference,
    NormalizedSecurityEvent,
    Severity,
    TimelineEntry,
)

__all__ = [
    "Alert",
    "AlertStatus",
    "AuditLogger",
    "ConfigurationError",
    "DatabaseManager",
    "DetectionError",
    "DetectionRule",
    "EventCategory",
    "Incident",
    "IncidentNotFoundError",
    "IncidentNote",
    "IncidentStatus",
    "IngestionError",
    "MitreReference",
    "NormalizedSecurityEvent",
    "ReleaseProtectionError",
    "SecurityBoundaryError",
    "SentinelConfig",
    "SentinelXError",
    "Severity",
    "SignatureVerificationError",
    "StorageError",
    "TimelineEntry",
    "ValidationError",
    "sanitize_log_field",
]
