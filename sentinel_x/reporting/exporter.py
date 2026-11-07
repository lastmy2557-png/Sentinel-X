"""
Incident & SOC Report Exporter for Sentinel-X (Section 4.4).
Exports Incident investigation reports in JSON, Markdown, and XSS-safe HTML formats.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict, List

from sentinel_x.core.database import DatabaseManager
from sentinel_x.core.models import Alert, Incident, NormalizedSecurityEvent


class IncidentReportExporter:
    """Generates structured Incident Investigation Reports with linked alerts and event evidence."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def build_report_payload(self, incident_id: str) -> Dict[str, Any]:
        """Collect complete incident details, linked alerts, and linked events."""
        incident: Incident = self.db.get_incident(incident_id)
        linked_alerts: List[Alert] = []
        for aid in incident.linked_alert_ids:
            alert = self.db.get_alert(aid)
            if alert:
                linked_alerts.append(alert)

        linked_events: List[NormalizedSecurityEvent] = []
        for eid in incident.linked_event_ids:
            ev = self.db.get_event(eid)
            if ev:
                linked_events.append(ev)

        return {
            "report_type": "SENTINEL_X_INCIDENT_REPORT",
            "is_sample_telemetry": incident.is_sample,
            "incident": incident.to_dict(),
            "linked_alerts": [a.to_dict() for a in linked_alerts],
            "linked_events": [e.to_dict() for e in linked_events],
        }

    def export_json(self, incident_id: str, output_path: Path | None = None) -> str:
        payload = self.build_report_payload(incident_id)
        content = json.dumps(payload, indent=2, ensure_ascii=False)
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(content, encoding="utf-8")
        return content

    def export_markdown(self, incident_id: str, output_path: Path | None = None) -> str:
        payload = self.build_report_payload(incident_id)
        inc = payload["incident"]
        lines = [
            f"# Sentinel-X Incident Report: {inc['title']}",
            "",
            f"- **Incident ID:** `{inc['incident_id']}`",
            f"- **Status:** `{inc['status']}`",
            f"- **Severity:** `{inc['severity']}`",
            f"- **Assigned To:** `{inc['assigned_to']}`",
            f"- **Created At (UTC):** `{inc['created_at']}`",
            f"- **Updated At (UTC):** `{inc['updated_at']}`",
            f"- **Resolved At (UTC):** `{inc['resolved_at'] or 'N/A'}`",
            f"- **Telemetry Classification:** `{'SAMPLE / TEST DATA' if payload['is_sample_telemetry'] else 'REAL TELEMETRY'}`",
            "",
            "## Description",
            inc["description"] or "_No description provided._",
            "",
            "## Resolution Summary",
            inc["resolution_summary"] or "_Pending resolution._",
            "",
            "## Linked Alerts & MITRE ATT&CK Mapping",
        ]
        if not payload["linked_alerts"]:
            lines.append("- _No linked alerts._")
        else:
            for al in payload["linked_alerts"]:
                lines.append(
                    f"- **[{al['severity']}] {al['title']}** (`{al['alert_id']}`)\n"
                    f"  - MITRE ATT&CK: `{al['mitre_technique_id']}` — {al['mitre_technique_name']} ({al['mitre_tactic']})\n"
                    f"  - Explanation: {al['explanation']}"
                )

        lines.extend(["", "## Investigation Notes"])
        if not inc["notes"]:
            lines.append("- _No investigation notes recorded._")
        else:
            for note in inc["notes"]:
                lines.append(f"- **[{note['created_at']}] {note['author']}:** {note['content']}")

        lines.extend(["", "## Incident Timeline"])
        for item in inc["timeline"]:
            lines.append(
                f"- `{item['timestamp']}` | **{item['entry_type']}** ({item['actor']}): {item['description']}"
            )

        lines.extend(["", "## Linked Event Evidence"])
        if not payload["linked_events"]:
            lines.append("- _No linked events._")
        else:
            for ev in payload["linked_events"]:
                lines.append(
                    f"- `{ev['timestamp']}` | `{ev['source_host']}` | IP: `{ev['source_ip']}` | "
                    f"Action: `{ev['action']}` (`{ev['outcome']}`) | {ev['message']}"
                )

        content = "\n".join(lines) + "\n"
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(content, encoding="utf-8")
        return content

    def export_html(self, incident_id: str, output_path: Path | None = None) -> str:
        """Export an HTML report with strict HTML output encoding to prevent XSS."""
        payload = self.build_report_payload(incident_id)
        inc = payload["incident"]
        esc = html.escape

        notes_html = "".join(
            f"<li><strong>[{esc(str(n['created_at']))}] {esc(str(n['author']))}:</strong> {esc(str(n['content']))}</li>"
            for n in inc["notes"]
        ) or "<li><em>No investigation notes.</em></li>"

        timeline_html = "".join(
            f"<li><code>{esc(str(t['timestamp']))}</code> <strong>{esc(str(t['entry_type']))}</strong> "
            f"({esc(str(t['actor']))}): {esc(str(t['description']))}</li>"
            for t in inc["timeline"]
        )

        alerts_html = "".join(
            f"<li><strong>[{esc(str(a['severity']))}] {esc(str(a['title']))}</strong> — "
            f"MITRE: <code>{esc(str(a['mitre_technique_id']))}</code> ({esc(str(a['mitre_technique_name']))} / {esc(str(a['mitre_tactic']))})<br>"
            f"{esc(str(a['explanation']))}</li>"
            for a in payload["linked_alerts"]
        ) or "<li><em>No linked alerts.</em></li>"

        content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sentinel-X Incident Report - {esc(str(inc['incident_id']))}</title>
<style>
body {{ font-family: sans-serif; margin: 2rem; color: #111; line-height: 1.5; }}
code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }}
.badge {{ padding: 3px 8px; border-radius: 4px; background: #222; color: #fff; font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>Sentinel-X Incident Report: {esc(str(inc['title']))}</h1>
<p>
  <span class="badge">Status: {esc(str(inc['status']))}</span>
  <span class="badge">Severity: {esc(str(inc['severity']))}</span>
  <span class="badge">Telemetry: {'SAMPLE DATA' if payload['is_sample_telemetry'] else 'REAL TELEMETRY'}</span>
</p>
<p><strong>Incident ID:</strong> <code>{esc(str(inc['incident_id']))}</code></p>
<p><strong>Description:</strong> {esc(str(inc['description']))}</p>
<p><strong>Resolution Summary:</strong> {esc(str(inc['resolution_summary'] or 'Pending'))}</p>
<h2>Linked Alerts &amp; MITRE ATT&amp;CK</h2>
<ul>{alerts_html}</ul>
<h2>Investigation Notes</h2>
<ul>{notes_html}</ul>
<h2>Timeline</h2>
<ul>{timeline_html}</ul>
</body>
</html>
"""
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(content, encoding="utf-8")
        return content
