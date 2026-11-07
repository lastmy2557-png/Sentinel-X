"""
Security Dashboard, External API Integration Settings UI, & Local-First REST API Server
for Sentinel-X (Section 4.5 & Phase 9).
Displays real security telemetry from SQLite:
- Security Events
- Alerts & MITRE ATT&CK Mappings
- Severity Distribution
- Detection Statistics
- Incident Status
- Recent Activity
- External Connector Status & Customer API Settings Management (/settings)

Explicitly distinguishes real telemetry vs sample data (`is_sample`), masks all secrets in
API/UI responses, and escapes all HTML output to prevent XSS.
"""

from __future__ import annotations

import hmac
import html
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from sentinel_x import __version__
from sentinel_x.core.config import SentinelConfig
from sentinel_x.core.database import DatabaseManager
from sentinel_x.core.exceptions import SentinelXError, ValidationError
from sentinel_x.integrations.connectors import IntegrationRegistry

MAX_JSON_BODY_BYTES = 65536


class DashboardService:
    """Aggregates real platform telemetry and manages External API Integration Settings for the UI/API."""

    def __init__(
        self,
        db: DatabaseManager,
        integrations: Optional[IntegrationRegistry] = None,
    ) -> None:
        self.db = db
        self.integrations = integrations or IntegrationRegistry(db=db)

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
            "version": __version__,
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
            f"<li><strong>{esc(str(c['display_name']))}</strong> ({esc(str(c.get('provider_name', '')))}): "
            f"<code>{esc(str(c['status']))}</code> — {esc(str(c['message']))}</li>"
            for c in snap["connectors"]
        )

        return f"""<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="utf-8">
<title>Sentinel-X v{esc(__version__)} — Security Operations Dashboard</title>
<style>
*, *::before, *::after {{ box-sizing: border-box; }}
body {{ font-family: system-ui, sans-serif; margin: 1.5rem 2rem; background: #0f172a; color: #f8fafc; }}
.topbar {{ display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 1rem; margin-bottom: 1.25rem; border-bottom: 1px solid #334155; padding-bottom: 0.85rem; }}
.topbar h1 {{ margin: 0; font-size: 1.45rem; line-height: 1.35; flex: 1 1 320px; display: flex; flex-wrap: wrap; align-items: center; gap: 0.6rem; }}
.ver-pill {{ font-size: 0.8rem; background: #1e293b; border: 1px solid #38bdf8; color: #38bdf8; padding: 0.15rem 0.55rem; border-radius: 999px; font-weight: 700; white-space: nowrap; }}
.nav {{ display: flex; flex-wrap: wrap; align-items: center; gap: 0.65rem; flex-shrink: 0; }}
.nav a {{ display: inline-flex; align-items: center; white-space: nowrap; color: #38bdf8; text-decoration: none; padding: 0.5rem 0.95rem; border-radius: 6px; border: 1px solid #334155; background: #1e293b; font-weight: 600; font-size: 0.92rem; line-height: 1.2; }}
.nav a.active {{ background: #0284c7; color: #ffffff; border-color: #38bdf8; }}
.notice {{ padding: 0.75rem 1rem; border-radius: 6px; background: #1e293b; border-left: 4px solid #38bdf8; margin-bottom: 1.5rem; line-height: 1.5; }}
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
<div class="topbar">
  <h1>Sentinel-X — Security Operations Dashboard <span class="ver-pill">v{esc(__version__)}</span></h1>
  <div class="nav">
    <a href="/" class="active">SOC Dashboard</a>
    <a href="/settings">ตั้งค่า API บริการภายนอก (API Settings)</a>
  </div>
</div>
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
<h2>External Integration Connectors (<a href="/settings" style="color:#38bdf8;">ตั้งค่า API คลิกที่นี่</a>)</h2>
<ul>{connector_rows}</ul>
</body>
</html>
"""

    def render_settings_html(self) -> str:
        """Render an XSS-safe, interactive API & External Services Configuration page (/settings)."""
        esc = html.escape
        connectors = self.integrations.list_settings()

        cards_html = []
        for c in connectors:
            cid = esc(str(c["connector_id"]))
            status = str(c["status"])
            badge_color = (
                "#16a34a"
                if status == "CONFIGURED_READY"
                else ("#d97706" if status == "DISABLED" else "#64748b")
            )
            key_badge = (
                f"ตั้งค่าแล้ว ({esc(str(c['api_key_masked']))})"
                if c["api_key_configured"]
                else "ยังไม่ได้ตั้งค่า (Not Configured)"
            )
            checked_attr = "checked" if c["enabled"] else ""
            req_ep = " (จำเป็น / Required)" if c["requires_endpoint"] else " (ทางเลือก / Optional)"
            req_key = " (จำเป็น / Required)" if c["requires_api_key"] else " (ทางเลือก / Optional)"

            cards_html.append(
                f"""
<div class="conn-card" id="card-{cid}">
  <div class="conn-header">
    <div class="conn-title-group">
      <h2>{esc(str(c['display_name']))}</h2>
      <div class="desc">{esc(str(c['description_th']))}</div>
      <div class="examples"><strong>บริการที่รองรับ:</strong> {esc(str(c['supported_examples']))}</div>
    </div>
    <span class="badge" id="badge-{cid}" style="background:{badge_color};">{esc(status)}</span>
  </div>

  <form onsubmit="return saveConnector(event, '{cid}')" autocomplete="off">
    <div class="form-grid">
      <div class="field">
        <label for="provider-{cid}">ชื่อผู้ให้บริการ / ระบบที่ใช้งาน (Provider Name)</label>
        <input type="text" id="provider-{cid}" value="{esc(str(c['provider_name']))}" placeholder="เช่น Splunk, CrowdStrike, VirusTotal, Slack">
      </div>
      <div class="field">
        <label for="endpoint-{cid}">API Endpoint / Webhook URL{req_ep}</label>
        <input type="url" id="endpoint-{cid}" value="{esc(str(c['endpoint_url']))}" placeholder="https://api.example.com/v1/ingest">
      </div>
      <div class="field">
        <label for="apikey-{cid}">API Key / Secret Token{req_key} — <span class="key-state" id="keystate-{cid}">{key_badge}</span></label>
        <input type="password" id="apikey-{cid}" value="" placeholder="เว้นว่างไว้หากใช้ค่าเดิม หรือกรอกใหม่เพื่ออัปเดต API Key">
      </div>
      <div class="field checkbox-row">
        <label><input type="checkbox" id="enabled-{cid}" {checked_attr}> เปิดใช้งานการเชื่อมต่อนี้ (Enable Integration)</label>
        <label><input type="checkbox" id="clear-{cid}"> ล้างค่า API Key เดิมที่บันทึกไว้ (Clear Saved Secret)</label>
      </div>
    </div>
    <div class="btn-row">
      <button type="submit" class="btn-save">บันทึกการตั้งค่า (Save Settings)</button>
      <button type="button" class="btn-test" onclick="testConnector('{cid}')">ทดสอบการเชื่อมต่อจริง (Test Connection)</button>
    </div>
    <div class="result-box" id="result-{cid}" style="display:none;"></div>
  </form>
</div>
"""
            )

        joined_cards = "\n".join(cards_html)
        return f"""<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="utf-8">
<title>Sentinel-X v{esc(__version__)} — ตั้งค่าการเชื่อมต่อ API บริการภายนอก</title>
<style>
*, *::before, *::after {{ box-sizing: border-box; }}
body {{ font-family: system-ui, sans-serif; margin: 1.5rem 2rem; background: #0f172a; color: #f8fafc; }}
.topbar {{ display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 1rem; margin-bottom: 1.25rem; border-bottom: 1px solid #334155; padding-bottom: 0.85rem; }}
.topbar h1 {{ margin: 0; font-size: 1.45rem; line-height: 1.35; flex: 1 1 320px; display: flex; flex-wrap: wrap; align-items: center; gap: 0.6rem; }}
.ver-pill {{ font-size: 0.8rem; background: #1e293b; border: 1px solid #38bdf8; color: #38bdf8; padding: 0.15rem 0.55rem; border-radius: 999px; font-weight: 700; white-space: nowrap; }}
.nav {{ display: flex; flex-wrap: wrap; align-items: center; gap: 0.65rem; flex-shrink: 0; }}
.nav a {{ display: inline-flex; align-items: center; white-space: nowrap; color: #38bdf8; text-decoration: none; padding: 0.5rem 0.95rem; border-radius: 6px; border: 1px solid #334155; background: #1e293b; font-weight: 600; font-size: 0.92rem; line-height: 1.2; }}
.nav a.active {{ background: #0284c7; color: #ffffff; border-color: #38bdf8; }}
.notice {{ padding: 0.85rem 1rem; border-radius: 6px; background: #1e293b; border-left: 4px solid #38bdf8; margin-bottom: 1.5rem; line-height: 1.5; }}
.conn-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.25rem; }}
.conn-header {{ display: flex; flex-wrap: wrap; justify-content: space-between; align-items: flex-start; gap: 0.75rem; margin-bottom: 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.75rem; }}
.conn-title-group {{ flex: 1 1 280px; min-width: 0; }}
.conn-header h2 {{ margin: 0 0 0.35rem 0; font-size: 1.15rem; color: #f8fafc; line-height: 1.35; }}
.desc {{ color: #cbd5e1; font-size: 0.92rem; margin-bottom: 0.25rem; line-height: 1.45; }}
.examples {{ color: #94a3b8; font-size: 0.85rem; line-height: 1.4; }}
.badge {{ display: inline-flex; align-items: center; white-space: nowrap; flex-shrink: 0; padding: 0.35rem 0.75rem; border-radius: 999px; font-size: 0.8rem; font-weight: bold; color: #ffffff; }}
.form-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; margin-bottom: 1rem; }}
.field {{ display: flex; flex-direction: column; min-width: 0; }}
.field label {{ font-size: 0.85rem; color: #cbd5e1; margin-bottom: 0.4rem; font-weight: 600; line-height: 1.4; word-break: break-word; }}
.field input[type="text"], .field input[type="url"], .field input[type="password"] {{
  width: 100%; padding: 0.55rem 0.75rem; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; font-size: 0.9rem;
}}
.checkbox-row {{ flex-direction: row; flex-wrap: wrap; align-items: center; gap: 0.75rem 1.5rem; grid-column: 1 / -1; padding-top: 0.25rem; }}
.checkbox-row label {{ display: inline-flex; align-items: center; gap: 0.45rem; margin-bottom: 0; cursor: pointer; }}
.key-state {{ color: #38bdf8; font-family: monospace; }}
.btn-row {{ display: flex; flex-wrap: wrap; gap: 0.75rem; }}
button {{ padding: 0.55rem 1.1rem; border-radius: 6px; border: none; font-weight: 600; cursor: pointer; font-size: 0.9rem; }}
.btn-save {{ background: #0284c7; color: #ffffff; }}
.btn-save:hover {{ background: #0369a1; }}
.btn-test {{ background: #334155; color: #f8fafc; border: 1px solid #475569; }}
.btn-test:hover {{ background: #475569; }}
.result-box {{ margin-top: 0.85rem; padding: 0.65rem 0.85rem; border-radius: 6px; font-size: 0.9rem; background: #0f172a; border-left: 4px solid #38bdf8; line-height: 1.45; word-break: break-word; }}
</style>
</head>
<body>
<div class="topbar">
  <h1>Sentinel-X — ตั้งค่าการเชื่อมต่อ API บริการภายนอก (External API Settings) <span class="ver-pill">v{esc(__version__)}</span></h1>
  <div class="nav">
    <a href="/">SOC Dashboard</a>
    <a href="/settings" class="active">ตั้งค่า API บริการภายนอก (API Settings)</a>
  </div>
</div>

<div class="notice">
  <strong>มาตรฐานความปลอดภัย (Security by Design):</strong>
  ค่า API Key และ Secret Token ทุกตัวจะถูกบันทึกในฐานข้อมูลท้องถิ่น (Local-first SQLite) และจะถูก<strong>ปิดบังค่า (Masked เช่น ••••••••1234)</strong> เสมอเมื่อแสดงผลบนหน้าเว็บหรือส่งกลับผ่าน API เพื่อป้องกันการรั่วไหลของข้อมูลสำคัญ
</div>

{joined_cards}

<script>
function setResultBox(cid, text, isOk) {{
  const box = document.getElementById('result-' + cid);
  box.style.display = 'block';
  box.style.borderLeftColor = isOk ? '#16a34a' : '#ef4444';
  box.textContent = text;
}}

async function saveConnector(ev, cid) {{
  ev.preventDefault();
  const payload = {{
    connector_id: cid,
    provider_name: document.getElementById('provider-' + cid).value,
    endpoint_url: document.getElementById('endpoint-' + cid).value,
    api_key: document.getElementById('apikey-' + cid).value,
    enabled: document.getElementById('enabled-' + cid).checked,
    clear_secret: document.getElementById('clear-' + cid).checked
  }};
  try {{
    const resp = await fetch('/api/v1/settings/connectors', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(payload)
    }});
    const data = await resp.json();
    if (!resp.ok) {{
      setResultBox(cid, '[บันทึกไม่สำเร็จ] ' + (data.error || 'เกิดข้อผิดพลาด'), false);
      return false;
    }}
    const s = data.connector;
    document.getElementById('apikey-' + cid).value = '';
    document.getElementById('clear-' + cid).checked = false;
    document.getElementById('badge-' + cid).textContent = s.status;
    document.getElementById('badge-' + cid).style.background =
      s.status === 'CONFIGURED_READY' ? '#16a34a' : (s.status === 'DISABLED' ? '#d97706' : '#64748b');
    document.getElementById('keystate-' + cid).textContent =
      s.api_key_configured ? ('ตั้งค่าแล้ว (' + s.api_key_masked + ')') : 'ยังไม่ได้ตั้งค่า (Not Configured)';
    setResultBox(cid, '[บันทึกสำเร็จ] สถานะปัจจุบัน: ' + s.status + ' — ' + s.message, true);
  }} catch (err) {{
    setResultBox(cid, '[ข้อผิดพลาดเครือข่าย] ' + err, false);
  }}
  return false;
}}

async function testConnector(cid) {{
  setResultBox(cid, 'กำลังตรวจสอบการตั้งค่าและทดสอบการเชื่อมต่อ...', true);
  try {{
    const resp = await fetch('/api/v1/settings/connectors/test', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ connector_id: cid }})
    }});
    const data = await resp.json();
    if (!resp.ok) {{
      setResultBox(cid, '[ทดสอบไม่สำเร็จ] ' + (data.error || 'เกิดข้อผิดพลาด'), false);
      return;
    }}
    const r = data.result;
    setResultBox(cid, '[' + r.status + '] ' + r.message, Boolean(r.success));
  }} catch (err) {{
    setResultBox(cid, '[ข้อผิดพลาดเครือข่าย] ' + err, false);
  }}
}}
</script>
</body>
</html>
"""


def create_dashboard_http_server(
    dashboard_service: DashboardService,
    config: Optional[SentinelConfig] = None,
    allow_port_fallback: bool = True,
) -> HTTPServer:
    """Create a local-first HTTP server exposing the Security Dashboard, API Settings UI, and REST API."""
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

        def _check_api_auth(self) -> bool:
            """If SENTINEL_API_TOKEN is configured, enforce constant-time token verification on POST."""
            if not cfg.api_token:
                return True
            auth_header = self.headers.get("Authorization", "")
            token_header = self.headers.get("X-Sentinel-Token", "")
            provided = ""
            if auth_header.startswith("Bearer "):
                provided = auth_header[7:].strip()
            elif token_header:
                provided = token_header.strip()
            if not provided:
                return False
            return hmac.compare_digest(provided.encode("utf-8"), cfg.api_token.encode("utf-8"))

        def _read_json_body(self) -> Dict[str, Any]:
            length_str = self.headers.get("Content-Length", "0")
            try:
                length = int(length_str)
            except ValueError as exc:
                raise ValidationError("Invalid Content-Length header.") from exc
            if length <= 0 or length > MAX_JSON_BODY_BYTES:
                raise ValidationError(f"Request body must be between 1 and {MAX_JSON_BODY_BYTES} bytes.")
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValidationError(f"Malformed JSON request body: {exc}") from exc
            if not isinstance(data, dict):
                raise ValidationError("JSON request body must be an object.")
            return data

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            include_samples = qs.get("include_samples", ["1"])[0].lower() not in ("0", "false", "no")

            if parsed.path == "/":
                self._send_html(dashboard_service.render_dashboard_html(include_samples=include_samples))
            elif parsed.path == "/settings":
                self._send_html(dashboard_service.render_settings_html())
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
            elif parsed.path == "/api/v1/settings/connectors":
                self._send_json({"connectors": dashboard_service.integrations.list_settings()})
            else:
                self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if not self._check_api_auth():
                self._send_json(
                    {"error": "Unauthorized: valid API token required."},
                    status=HTTPStatus.UNAUTHORIZED,
                )
                return

            try:
                body = self._read_json_body()
                if parsed.path == "/api/v1/settings/connectors":
                    cid = str(body.get("connector_id", "")).strip()
                    updated = dashboard_service.integrations.update_connector_settings(
                        connector_id=cid,
                        provider_name=str(body["provider_name"]) if "provider_name" in body else None,
                        endpoint_url=str(body["endpoint_url"]) if "endpoint_url" in body else None,
                        api_key=str(body["api_key"]) if "api_key" in body else None,
                        enabled=bool(body["enabled"]) if "enabled" in body else None,
                        clear_secret=bool(body.get("clear_secret", False)),
                    )
                    self._send_json({"status": "UPDATED", "connector": updated}, status=HTTPStatus.OK)
                elif parsed.path == "/api/v1/settings/connectors/test":
                    cid = str(body.get("connector_id", "")).strip()
                    test_res = dashboard_service.integrations.test_connector_connection(connector_id=cid)
                    self._send_json({"status": "TESTED", "result": test_res}, status=HTTPStatus.OK)
                else:
                    self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
            except SentinelXError as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    try:
        return ThreadingHTTPServer((cfg.host, cfg.port), DashboardRequestHandler)
    except OSError as primary_exc:
        if not allow_port_fallback or cfg.port <= 0:
            raise
        candidate_ports = [cfg.port + offset for offset in range(1, 11)] + [
            8081,
            8088,
            8888,
            9000,
            9080,
            9090,
            5000,
            0,
        ]
        seen = {cfg.port}
        for candidate in candidate_ports:
            if candidate in seen or candidate < 0 or candidate > 65535:
                continue
            seen.add(candidate)
            try:
                srv = ThreadingHTTPServer((cfg.host, candidate), DashboardRequestHandler)
                cfg.port = int(srv.server_address[1])
                return srv
            except OSError:
                continue
        raise primary_exc

