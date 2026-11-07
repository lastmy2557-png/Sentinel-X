"""
Custom exception hierarchy for Sentinel-X.
Ensures consistent, secure error handling across all modules without leaking sensitive internals.
"""


class SentinelXError(Exception):
    """Base exception for all Sentinel-X errors."""


class ConfigurationError(SentinelXError):
    """Raised when configuration values are missing, invalid, or insecure."""


class ValidationError(SentinelXError):
    """Raised when external input or domain data fails validation."""


class SecurityBoundaryError(SentinelXError):
    """Raised when an operation violates a security boundary (e.g., path traversal, file size limit)."""


class StorageError(SentinelXError):
    """Raised when local database operations fail."""


class IngestionError(SentinelXError):
    """Raised when log ingestion or parsing fails."""


class DetectionError(SentinelXError):
    """Raised when detection rule loading or evaluation fails."""


class IncidentNotFoundError(SentinelXError):
    """Raised when a requested incident ID does not exist."""


class ReleaseProtectionError(SentinelXError):
    """Raised when Anti-REA release protection operations fail."""


class SignatureVerificationError(ReleaseProtectionError):
    """Raised when digital signature or release manifest verification fails."""
