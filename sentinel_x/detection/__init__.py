"""Threat Detection and MITRE ATT&CK Integration package."""

from sentinel_x.detection.engine import ThreatDetectionEngine, build_default_rules
from sentinel_x.detection.mitre import (
    OFFICIAL_MITRE_CATALOG,
    get_mitre_reference,
    resolve_mitre_reference,
)

__all__ = [
    "OFFICIAL_MITRE_CATALOG",
    "ThreatDetectionEngine",
    "build_default_rules",
    "get_mitre_reference",
    "resolve_mitre_reference",
]
