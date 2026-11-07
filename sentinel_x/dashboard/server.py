"""
Security Dashboard & Local-First REST API Server for Sentinel-X (Section 4.5).
Displays real security telemetry from SQLite:
- Security Events
- Alerts & MITRE ATT&CK Mappings
- Severity Distribution
- Detection Statistics
- Incident Status
- Recent Activity
- External Connector Status

Explicitly distinguishes real telemetry vs sample data (`is_sample`) and escapes all HTML output.
"""

from __future__ import annotations

import html
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from sentinel_x.core.config import SentinelConfig
from sentinel_x.core.database import DatabaseManager
from sentinel_x.integrations.connectors import IntegrationRegistry


class DashboardService:
    """Aggregates real platform telemetry for the Security Dashboard and REST API."""

    def __init__(
        self,
        db: DatabaseManager,
        integrations: Optional[IntegrationRegistry] = None,
    ) -> None:
        self.db = db
        self.integrations = integrations or IntegrationRegistry()

    def get_dashboard_snapshot(
        self, include_samples: bool = True, recent_limit: int = 20
    ) -> Dict[str, Any]:
        """Return a complete dashboard snapshot sourced strictly from actual database records."""
        stats = self.db.get_dashboard_statistics(include_samples=include_samples)
        recent_events = [
            e.to_dict()
            for e in self.db.query_events(include_samples=include_samples, limit=recent_limit)
        ]
        recent_alerts = [
            a.to_dict()
            for a in self.db.list_alerts(include_samples=include_samples, limit=recent_limit)
        ]
        incidents = [
            i.to_dict() for i in self.db.list_incidents(include_samples=include_samples)
        ]
        connectors = self.integrations.list_statuses()

        if stats["total_events"] == 0:
            data_origin_notice = "NO_TELEMETRY_LOADED: Database currently contains 0 events."
        elif stats["includes_sample_data"]:
            data_origin_notice = (
                f"MIXED_OR_SAMPLE_TELEMETRY: Showing {stats['real_telemetry_events']} real event(s) "
                f"and {stats['sample_telemetry_events']} explicitly tagged sample event(s)."
            )
        else:
            data_origin_notice = (
                f"REAL_TELEMETRY_ONLY: Showing {stats['real_telemetry_events']} real event(s). "
                "Sample data is excluded."
            )

        return {
            "platform": "Sentinel-X SOC Platform",
            "data_origin_notice": data_origin_notice,
            "statistics": stats,
            "recent_events": recent_events,
            "recent_alerts": recent_alerts,
            "incidents": incidents,
            "connectors": connectors,
        }

    def render_dashboard_html(self, include_samples: bool = True) -> str:
        """Render an XSS-safe HTML view of the current dashboard state."""
        snap = self.get_dashboard_snapshot(include_samples=include_samples)
        stats = snap["statistics"]
        esc = html.escape

        alert_rows = "".join(
            f"<tr>"
            f"<td><code>{esc(str(a['created_at']))}</code></td>"
            f"<td><strong>{esc(str(a['severity']))}</strong></td>"
            f"<td>{esc(str(a['title']))}</td>"
            f"<td><code>{esc(str(a['mitre_technique_id']))}</code> ({esc(str(a['mitre_tactic']))})</td>"
            f"<td>{esc(str(a['explanation']))}</td>"
            f"<td>{'SAMPLE' if a['is_sample'] else 'REAL'}</td>"
            f"</tr>"
            for a in snap["recent_alerts"]
        ) or "<tr><td colspan='6'><em>No alerts recorded in database.</em></td></tr>"

        incident_rows = "".join(
            f"<tr>"
            f"<td><code>{esc(str(inc['incident_id']))}</code></td>"
            f"<td><strong>{esc(str(inc['status']))}</strong></td>"
            f"<td>{esc(str(inc['severity']))}</td>"
            f"<td>{esc(str(inc['title']))}</td>"
            f"<td>{esc(str(inc['assigned_to']))}</td>"
            f"<td>{'SAMPLE' if inc['is_sample'] else 'REAL'}</td>"
            f"</tr>"
            for inc in snap["incidents"]
        ) or "<tr><td colspan='6'><em>No incidents recorded in database.</em></td></tr>"

        event_rows = "".join(
            f"<tr>"
            f"<td><code>{esc(str(e['timestamp']))}</code></td>"
            f"<td>{esc(str(e['category']))}</td>"
            f"<td>{esc(str(e['severity']))}</td>"
            f"<td><code>{esc(str(e['source_ip'] or '-'))}</code></td>"
            f"<td>{esc(str(e['action']))} ({esc(str(e['outcome']))})</td>"
            f"<td>{esc(str(e['message']))}</td>"
            f"<td>{'SAMPLE' if e['is_sample'] else 'REAL'}</td>"
            f"</tr>"
            for e in snap["recent_events"]
        ) or "<tr><td colspan='7'><em>No security events recorded in database.</em></td></tr>"

        connector_rows = "".join(
            f"<li><strong>{esc(str(c['display_name']))}</strong>: "
            f"<code>{esc(str(c['status']))}</code> — {esc(str(c['message']))}</li>"
            for c in snap["connectors"]
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sentinel-X Security Operations Dashboard</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 1.5rem 2rem; background: #0f172a; color: #f8fafc; }}
.notice {{ padding: 0.75rem 1rem; border-radius: 6px; background: #1e293b; border-left: 4px solid #38bdf8; margin-bottom: 1.5rem; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
.card {{ background: #1e293b; padding: 1rem; border-radius: 6px; border: 1px solid #334155; }}
.card h3 {{ margin: 0 0 0.5rem 0; font-size: 0.9rem; color: #94a3b8; }}
.card .val {{ font-size: 1.6rem; font-weight: bold; color: #f8fafc; }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 1.5rem; background: #1e293b; }}
th, td {{ text-align: left; padding: 0.6rem 0.75rem; border-bottom: 1px solid #334155; font-size: 0.9rem; }}
th {{ background: #0f172a; color: #94a3b8; }}
code {{ color: #38bdf8; }}
</style>
</head>
<body>
<h1>Sentinel-X — Security Operations Dashboard</h1>
<div class="notice"><strong>Telemetry Status:</strong> {esc(snap['data_origin_notice'])}</div>
<div class="grid">
  <div class="card"><h3>Total Events</h3><div class="val">{stats['total_events']}</div></div>
  <div class="card"><h3>Real Events</h3><div class="val">{stats['real_telemetry_events']}</div></div>
  <div class="card"><h3>Sample Events</h3><div class="val">{stats['sample_telemetry_events']}</div></div>
  <div class="card"><h3>Total Alerts</h3><div class="val">{stats['total_alerts']}</div></div>
  <div class="card"><h3>Incidents</h3><div class="val">{stats['total_incidents']}</div></div>
  <div class="card"><h3>Active Rules</h3><div class="val">{stats['enabled_detection_rules']}</div></div>
</div>
<h2>Security Alerts (MITRE ATT&amp;CK Mapped)</h2>
<table>
  <thead><tr><th>Timestamp</th><th>Severity</th><th>Title</th><th>MITRE ATT&amp;CK</th><th>Explanation</th><th>Origin</th></tr></thead>
  <tbody>{alert_rows}</tbody>
</table>
<h2>Incident Status</h2>
<table>
  <thead><tr><th>Incident ID</th><th>Status</th><th>Severity</th><th>Title</th><th>Assigned To</th><th>Origin</th></tr></thead>
  <tbody>{incident_rows}</tbody>
</table>
<h2>Recent Security Events</h2>
<table>
  <thead><tr><th>Timestamp</th><th>Category</th><th>Severity</th><th>Source IP</th><th>Action</th><th>Message</th><th>Origin</th></tr></thead>
  <tbody>{event_rows}</tbody>
</table>
<h2>External Integration Connectors</h2>
<ul>{connector_rows}</ul>
</body>
</html>
"""


def create_dashboard_http_server(
    dashboard_service: DashboardService,
    config: Optional[SentinelConfig] = None,
) -> HTTPServer:
    """Create a local-first HTTP server exposing the Security Dashboard and JSON API."""
    cfg = config or SentinelConfig()

    class DashboardRequestHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            # Suppress noisy stdout access logs during tests
            return

        def _send_json(self, payload: Any, status: int = HTTPStatus.OK) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html_text: str, status: int = HTTPStatus.OK) -> None:
            body = html_text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            include_samples = qs.get("include_samples", ["1"])[0].lower() not in ("0", "false", "no")

            if parsed.path == "/":
                self._send_html(dashboard_service.render_dashboard_html(include_samples=include_samples))
            elif parsed.path == "/api/v1/summary":
                self._send_json(dashboard_service.get_dashboard_snapshot(include_samples=include_samples))
            elif parsed.path == "/api/v1/events":
                events = dashboard_service.db.query_events(include_samples=include_samples, limit=100)
                self._send_json({"events": [e.to_dict() for e in events]})
            elif parsed.path == "/api/v1/alerts":
                alerts = dashboard_service.db.list_alerts(include_samples=include_samples, limit=100)
                self._send_json({"alerts": [a.to_dict() for a in alerts]})
            elif parsed.path == "/api/v1/incidents":
                incidents = dashboard_service.db.list_incidents(include_samples=include_samples)
                self._send_json({"incidents": [i.to_dict() for i in incidents]})
            elif parsed.path == "/api/v1/connectors":
                self._send_json({"connectors": dashboard_service.integrations.list_statuses()})
            else:
                self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    return HTTPServer((cfg.host, cfg.port), DashboardRequestHandler)
