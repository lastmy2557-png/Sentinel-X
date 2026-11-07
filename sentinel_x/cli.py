"""
Main Command-Line Interface for Sentinel-X SOC Platform (Phase 5 — Integration).
Supports:
- summary   : Print platform statistics, alerts, incidents, and connector states
- ingest    : Ingest a log file (real or explicitly tagged --sample)
- events    : Search, filter, or correlate security events
- alerts    : List security alerts with MITRE ATT&CK details
- incident  : Create, update, note, or export an incident report
- serve     : Start the local-first Security Dashboard HTTP server
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from sentinel_x.core.config import SentinelConfig
from sentinel_x.dashboard.server import create_dashboard_http_server
from sentinel_x.platform import SentinelXPlatform


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel-x",
        description="Sentinel-X Cybersecurity & SOC Platform CLI",
    )
    parser.add_argument(
        "--db",
        default="",
        help="Optional override for SQLite database path",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_sum = sub.add_parser("summary", help="Show SOC dashboard summary")
    p_sum.add_argument(
        "--exclude-samples",
        action="store_true",
        help="Exclude sample telemetry from statistics",
    )

    p_ing = sub.add_parser("ingest", help="Ingest a log file and evaluate detection rules")
    p_ing.add_argument("--file", required=True, help="Path to log file")
    p_ing.add_argument(
        "--sample",
        action="store_true",
        help="Explicitly mark ingested events as sample/test telemetry",
    )

    p_ev = sub.add_parser("events", help="Search or correlate normalized security events")
    p_ev.add_argument("--category", default="", help="Filter by category")
    p_ev.add_argument("--severity", default="", help="Filter by severity")
    p_ev.add_argument("--search", default="", help="Search query string")
    p_ev.add_argument("--correlate-by", default="", help="Group events by source_ip, user, or source_host")
    p_ev.add_argument("--exclude-samples", action="store_true", help="Exclude sample telemetry")

    p_al = sub.add_parser("alerts", help="List generated security alerts")
    p_al.add_argument("--severity", default="", help="Filter by severity")
    p_al.add_argument("--exclude-samples", action="store_true", help="Exclude sample alerts")

    p_inc = sub.add_parser("incident", help="Manage incidents and export reports")
    p_inc_sub = p_inc.add_subparsers(dest="incident_action", required=True)

    p_inc_create = p_inc_sub.add_parser("create", help="Create a new incident")
    p_inc_create.add_argument("--title", required=True, help="Incident title")
    p_inc_create.add_argument("--description", default="", help="Incident description")
    p_inc_create.add_argument("--severity", default="HIGH", help="Severity (LOW, MEDIUM, HIGH, CRITICAL)")
    p_inc_create.add_argument("--alert-ids", nargs="*", default=[], help="Linked alert IDs")

    p_inc_report = p_inc_sub.add_parser("report", help="Export incident report")
    p_inc_report.add_argument("--id", required=True, help="Incident ID")
    p_inc_report.add_argument("--format", choices=["json", "markdown", "html"], default="markdown")
    p_inc_report.add_argument("--output", default="", help="Optional output file path")

    p_srv = sub.add_parser("serve", help="Run local-first Security Dashboard HTTP server")
    p_srv.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    p_srv.add_argument("--port", type=int, default=8080, help="Bind port (default 8080)")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_cli_parser()
    args = parser.parse_args(argv)

    env_overrides = {}
    if args.db:
        env_overrides["SENTINEL_DB_PATH"] = args.db
    config = SentinelConfig.from_env(environ=env_overrides if env_overrides else None)
    platform = SentinelXPlatform(config=config)

    if args.command == "summary":
        snap = platform.dashboard.get_dashboard_snapshot(
            include_samples=not args.exclude_samples
        )
        print(json.dumps(snap, indent=2, ensure_ascii=False))
        return 0

    if args.command == "ingest":
        events = platform.ingestion.ingest_file(Path(args.file), is_sample=args.sample)
        alerts = platform.pop_generated_alerts()
        print(
            json.dumps(
                {
                    "status": "INGESTED",
                    "events_ingested": len(events),
                    "alerts_generated": len(alerts),
                    "is_sample": bool(args.sample),
                    "alert_ids": [a.alert_id for a in alerts],
                },
                indent=2,
            )
        )
        return 0

    if args.command == "events":
        if args.correlate_by:
            corr = platform.ingestion.correlate_events(
                group_by=args.correlate_by,
                include_samples=not args.exclude_samples,
            )
            print(json.dumps({"correlations": corr}, indent=2))
            return 0
        evs = platform.ingestion.search_events(
            category=args.category or None,
            severity=args.severity or None,
            search_query=args.search or None,
            include_samples=not args.exclude_samples,
        )
        print(json.dumps({"count": len(evs), "events": [e.to_dict() for e in evs]}, indent=2))
        return 0

    if args.command == "alerts":
        alerts = platform.db.list_alerts(
            severity=args.severity or None,
            include_samples=not args.exclude_samples,
        )
        print(json.dumps({"count": len(alerts), "alerts": [a.to_dict() for a in alerts]}, indent=2))
        return 0

    if args.command == "incident":
        if args.incident_action == "create":
            inc = platform.incidents.create_incident(
                title=args.title,
                description=args.description,
                severity=args.severity,
                alert_ids=args.alert_ids,
            )
            print(json.dumps(inc.to_dict(), indent=2, ensure_ascii=False))
            return 0
        if args.incident_action == "report":
            out_path = Path(args.output) if args.output else None
            if args.format == "json":
                text = platform.reporting.export_json(args.id, out_path)
            elif args.format == "html":
                text = platform.reporting.export_html(args.id, out_path)
            else:
                text = platform.reporting.export_markdown(args.id, out_path)
            print(text)
            return 0

    if args.command == "serve":
        srv_cfg = SentinelConfig(host=args.host, port=args.port, db_path=config.db_path)
        server = create_dashboard_http_server(platform.dashboard, srv_cfg)
        print(f"Sentinel-X Security Dashboard listening on http://{args.host}:{args.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
