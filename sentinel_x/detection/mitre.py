"""
Official MITRE ATT&CK Enterprise Reference Catalog for Sentinel-X (Section 4.3).
Uses strictly verified official MITRE ATT&CK Technique IDs, Technique Names, and Tactics.
"""

from __future__ import annotations

from typing import Dict, Optional

from sentinel_x.core.exceptions import ValidationError
from sentinel_x.core.models import MitreReference

# Official MITRE ATT&CK Enterprise Techniques used by Sentinel-X detections
OFFICIAL_MITRE_CATALOG: Dict[str, MitreReference] = {
    "T1110": MitreReference(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1110/",
    ),
    "T1110.001": MitreReference(
        technique_id="T1110.001",
        technique_name="Brute Force: Password Guessing",
        tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1110/001/",
    ),
    "T1078": MitreReference(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="Initial Access",
        url="https://attack.mitre.org/techniques/T1078/",
    ),
    "T1059": MitreReference(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1059/",
    ),
    "T1059.004": MitreReference(
        technique_id="T1059.004",
        technique_name="Command and Scripting Interpreter: Unix Shell",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1059/004/",
    ),
    "T1190": MitreReference(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        url="https://attack.mitre.org/techniques/T1190/",
    ),
    "T1548.003": MitreReference(
        technique_id="T1548.003",
        technique_name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        tactic="Privilege Escalation",
        url="https://attack.mitre.org/techniques/T1548/003/",
    ),
    "T1003.008": MitreReference(
        technique_id="T1003.008",
        technique_name="OS Credential Dumping: /etc/passwd and /etc/shadow",
        tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1003/008/",
    ),
    "T1505.003": MitreReference(
        technique_id="T1505.003",
        technique_name="Server Software Component: Web Shell",
        tactic="Persistence",
        url="https://attack.mitre.org/techniques/T1505/003/",
    ),
    "T1046": MitreReference(
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="Discovery",
        url="https://attack.mitre.org/techniques/T1046/",
    ),
}


def get_mitre_reference(technique_id: str) -> MitreReference:
    """Return official MitreReference by ID or raise ValidationError if unknown."""
    norm_id = technique_id.strip().upper()
    if norm_id not in OFFICIAL_MITRE_CATALOG:
        raise ValidationError(
            f"MITRE Technique ID '{technique_id}' is not in the verified official MITRE ATT&CK catalog."
        )
    return OFFICIAL_MITRE_CATALOG[norm_id]


def resolve_mitre_reference(
    technique_id: str,
    technique_name: Optional[str] = None,
    tactic: Optional[str] = None,
) -> MitreReference:
    """
    Resolve against the official catalog first; if a known official ID is used,
    enforce its official name and tactic to prevent fabricated mappings.
    """
    norm_id = technique_id.strip().upper()
    if norm_id in OFFICIAL_MITRE_CATALOG:
        return OFFICIAL_MITRE_CATALOG[norm_id]
    if not technique_name or not tactic:
        raise ValidationError(
            f"MITRE Technique '{technique_id}' requires official technique_name and tactic."
        )
    return MitreReference(
        technique_id=norm_id,
        technique_name=technique_name.strip(),
        tactic=tactic.strip(),
    )
