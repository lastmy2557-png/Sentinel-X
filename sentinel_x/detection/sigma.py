"""
YAML & Sigma-Compatible Detection Rule Importer for Sentinel-X (Phase 7 Extension).
Converts standard Sigma-style YAML rules into validated Sentinel-X DetectionRule objects,
mapping MITRE ATT&CK tags (e.g. attack.t1110.001, attack.t1059.004) against the
official MITRE ATT&CK catalog.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

import yaml

from sentinel_x.core.exceptions import DetectionError, ValidationError
from sentinel_x.core.models import DetectionRule, MitreReference, Severity
from sentinel_x.detection.mitre import OFFICIAL_MITRE_CATALOG, get_mitre_reference

SIGMA_LEVEL_TO_SEVERITY: Dict[str, Severity] = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

MITRE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def _extract_mitre_from_tags(tags: List[str]) -> MitreReference:
    """Extract and verify an official MITRE ATT&CK Technique ID from Sigma rule tags."""
    for tag in tags:
        m = MITRE_TAG_RE.match(str(tag).strip())
        if m:
            tech_id = m.group(1).upper()
            if tech_id in OFFICIAL_MITRE_CATALOG:
                return get_mitre_reference(tech_id)
            raise ValidationError(
                f"Sigma tag MITRE Technique ID '{tech_id}' is not in the verified official catalog."
            )
    raise ValidationError(
        "Sigma rule must include a verified official MITRE ATT&CK tag (e.g. 'attack.t1059.004')."
    )


def parse_sigma_yaml_to_rule(yaml_content: str) -> DetectionRule:
    """
    Safely parse a Sigma-style YAML rule string (using yaml.safe_load)
    into a Sentinel-X DetectionRule.
    """
    try:
        doc = yaml.safe_load(yaml_content)
    except yaml.YAMLError as exc:
        raise DetectionError(f"Invalid YAML syntax in Sigma rule: {exc}") from exc

    if not isinstance(doc, dict):
        raise DetectionError("Sigma YAML document must be a mapping/dictionary.")

    rule_id = str(doc.get("id") or doc.get("rule_id") or "").strip()
    title = str(doc.get("title") or doc.get("name") or "").strip()
    description = str(doc.get("description") or "").strip()
    if not rule_id or not title:
        raise DetectionError("Sigma rule must specify 'id' and 'title'.")

    level_str = str(doc.get("level", "medium")).strip().lower()
    severity = SIGMA_LEVEL_TO_SEVERITY.get(level_str)
    if severity is None:
        severity = Severity.from_str(level_str)

    tags = doc.get("tags") or []
    if not isinstance(tags, list):
        raise DetectionError("Sigma 'tags' field must be a list.")
    mitre_ref = _extract_mitre_from_tags([str(t) for t in tags])

    detection_block = doc.get("detection")
    if not isinstance(detection_block, dict):
        raise DetectionError(f"Sigma rule '{rule_id}' is missing 'detection' block.")

    selection = detection_block.get("selection")
    if not isinstance(selection, dict) or not selection:
        raise DetectionError(f"Sigma rule '{rule_id}' must define a 'detection.selection' mapping.")

    conditions: Dict[str, Any] = {}
    regex_parts: List[str] = []

    for key, val in selection.items():
        if key in ("category", "action", "outcome", "user", "source_ip"):
            conditions[key] = str(val)
        elif key.endswith("|contains"):
            if isinstance(val, list):
                escaped = [re.escape(str(v)) for v in val]
                regex_parts.append("(?i)(?:" + "|".join(escaped) + ")")
            else:
                conditions["message_contains"] = str(val)
        elif key.endswith("|re"):
            regex_parts.append(str(val))
        elif key == "keywords":
            if isinstance(val, list):
                escaped = [re.escape(str(v)) for v in val]
                regex_parts.append("(?i)(?:" + "|".join(escaped) + ")")
            else:
                conditions["message_contains"] = str(val)

    if regex_parts:
        conditions["message_regex"] = "|".join(regex_parts)

    if not conditions:
        raise DetectionError(
            f"Sigma rule '{rule_id}' selection did not produce any supported detection conditions."
        )

    explanation_template = str(
        doc.get(
            "explanation_template",
            f"Sigma rule '{title}' ({mitre_ref.technique_id}) matched on host '{{source_host}}': {{message}}",
        )
    )
    enabled = str(doc.get("status", "active")).lower() not in ("disabled", "deprecated")

    return DetectionRule(
        rule_id=rule_id,
        name=title,
        description=description or f"Imported Sigma rule: {title}",
        severity=severity,
        mitre=mitre_ref,
        conditions=conditions,
        explanation_template=explanation_template,
        enabled=enabled,
    )


def load_sigma_rule_file(file_path: Path | str) -> DetectionRule:
    """Load a Sigma YAML rule file from disk and convert to DetectionRule."""
    path = Path(file_path)
    if not path.is_file():
        raise DetectionError(f"Sigma rule file not found: {file_path}")
    return parse_sigma_yaml_to_rule(path.read_text(encoding="utf-8"))
