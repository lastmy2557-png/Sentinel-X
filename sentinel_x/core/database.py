"""
Local-first SQLite Storage Layer for Sentinel-X.
Enforces WAL mode, foreign keys, and 100% parameterized SQL queries to prevent SQL injection.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from sentinel_x.core.exceptions import IncidentNotFoundError, StorageError
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


class DatabaseManager:
    """Manages SQLite persistence for events, detection rules, alerts, and incidents."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            if str(self.db_path) != ":memory:":
                conn.execute("PRAGMA journal_mode = WAL;")
            yield conn
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise StorageError(f"Database operation failed: {exc}") from exc
        finally:
            conn.close()

    def _init_schema(self) -> None:
        schema_sql = """
        CREATE TABLE IF NOT EXISTS security_events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_host TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            user TEXT NOT NULL,
            action TEXT NOT NULL,
            outcome TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            raw_log TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            is_sample INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_category ON security_events(category);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_source_ip ON security_events(source_ip);

        CREATE TABLE IF NOT EXISTS detection_rules (
            rule_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            mitre_technique_id TEXT NOT NULL,
            mitre_technique_name TEXT NOT NULL,
            mitre_tactic TEXT NOT NULL,
            mitre_url TEXT NOT NULL,
            conditions_json TEXT NOT NULL,
            explanation_template TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            title TEXT NOT NULL,
            explanation TEXT NOT NULL,
            mitre_technique_id TEXT NOT NULL,
            mitre_technique_name TEXT NOT NULL,
            mitre_tactic TEXT NOT NULL,
            evidence_event_ids_json TEXT NOT NULL,
            evidence_summary_json TEXT NOT NULL,
            incident_id TEXT,
            is_sample INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            resolved_at TEXT,
            resolution_summary TEXT NOT NULL,
            assigned_to TEXT NOT NULL,
            linked_event_ids_json TEXT NOT NULL,
            linked_alert_ids_json TEXT NOT NULL,
            is_sample INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS incident_notes (
            note_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            author TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS incident_timeline (
            entry_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            entry_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            description TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
        );
        """
        with self.connection() as conn:
            conn.executescript(schema_sql)

    # ------------------------------------------------------------------
    # Security Events
    # ------------------------------------------------------------------
    def save_event(self, event: NormalizedSecurityEvent) -> None:
        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO security_events (
                    event_id, timestamp, source_type, source_host, source_ip,
                    destination_ip, user, action, outcome, category, severity,
                    message, raw_log, metadata_json, is_sample
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.timestamp,
                    event.source_type,
                    event.source_host,
                    event.source_ip,
                    event.destination_ip,
                    event.user,
                    event.action,
                    event.outcome,
                    event.category.value,
                    event.severity.value,
                    event.message,
                    event.raw_log,
                    json.dumps(event.metadata, ensure_ascii=False),
                    1 if event.is_sample else 0,
                ),
            )

    def get_event(self, event_id: str) -> Optional[NormalizedSecurityEvent]:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM security_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            return self._row_to_event(row) if row else None

    def query_events(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        user: Optional[str] = None,
        action: Optional[str] = None,
        outcome: Optional[str] = None,
        search_query: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        include_samples: bool = True,
        only_samples: bool = False,
        limit: int = 200,
    ) -> List[NormalizedSecurityEvent]:
        clauses: List[str] = []
        params: List[Any] = []

        if category:
            clauses.append("category = ?")
            params.append(category.upper())
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)
        if user:
            clauses.append("user = ?")
            params.append(user)
        if action:
            clauses.append("action = ?")
            params.append(action)
        if outcome:
            clauses.append("outcome = ?")
            params.append(outcome)
        if start_time:
            clauses.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            clauses.append("timestamp <= ?")
            params.append(end_time)
        if only_samples:
            clauses.append("is_sample = 1")
        elif not include_samples:
            clauses.append("is_sample = 0")
        if search_query:
            clauses.append("(message LIKE ? OR raw_log LIKE ? OR source_host LIKE ? OR user LIKE ?)")
            pattern = f"%{search_query}%"
            params.extend([pattern, pattern, pattern, pattern])

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        safe_limit = max(1, min(int(limit), 5000))
        params.append(safe_limit)

        sql = f"SELECT * FROM security_events {where_sql} ORDER BY timestamp DESC LIMIT ?"
        with self.connection() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [self._row_to_event(r) for r in rows]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> NormalizedSecurityEvent:
        return NormalizedSecurityEvent(
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            source_type=row["source_type"],
            source_host=row["source_host"],
            source_ip=row["source_ip"],
            destination_ip=row["destination_ip"],
            user=row["user"],
            action=row["action"],
            outcome=row["outcome"],
            category=EventCategory.from_str(row["category"]),
            severity=Severity.from_str(row["severity"]),
            message=row["message"],
            raw_log=row["raw_log"],
            metadata=json.loads(row["metadata_json"] or "{}"),
            is_sample=bool(row["is_sample"]),
        )

    # ------------------------------------------------------------------
    # Detection Rules
    # ------------------------------------------------------------------
    def save_rule(self, rule: DetectionRule) -> None:
        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO detection_rules (
                    rule_id, name, description, severity, enabled,
                    mitre_technique_id, mitre_technique_name, mitre_tactic, mitre_url,
                    conditions_json, explanation_template
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule.rule_id,
                    rule.name,
                    rule.description,
                    rule.severity.value,
                    1 if rule.enabled else 0,
                    rule.mitre.technique_id,
                    rule.mitre.technique_name,
                    rule.mitre.tactic,
                    rule.mitre.to_dict()["url"],
                    json.dumps(rule.conditions, ensure_ascii=False),
                    rule.explanation_template,
                ),
            )

    def list_rules(self, enabled_only: bool = False) -> List[DetectionRule]:
        sql = "SELECT * FROM detection_rules"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY rule_id ASC"
        with self.connection() as conn:
            rows = conn.execute(sql).fetchall()
            return [self._row_to_rule(r) for r in rows]

    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM detection_rules WHERE rule_id = ?", (rule_id,)
            ).fetchone()
            return self._row_to_rule(row) if row else None

    @staticmethod
    def _row_to_rule(row: sqlite3.Row) -> DetectionRule:
        return DetectionRule(
            rule_id=row["rule_id"],
            name=row["name"],
            description=row["description"],
            severity=Severity.from_str(row["severity"]),
            enabled=bool(row["enabled"]),
            mitre=MitreReference(
                technique_id=row["mitre_technique_id"],
                technique_name=row["mitre_technique_name"],
                tactic=row["mitre_tactic"],
                url=row["mitre_url"],
            ),
            conditions=json.loads(row["conditions_json"] or "{}"),
            explanation_template=row["explanation_template"],
        )

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------
    def save_alert(self, alert: Alert) -> None:
        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id, rule_id, rule_name, severity, status, created_at,
                    title, explanation, mitre_technique_id, mitre_technique_name,
                    mitre_tactic, evidence_event_ids_json, evidence_summary_json,
                    incident_id, is_sample
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.rule_id,
                    alert.rule_name,
                    alert.severity.value,
                    alert.status.value,
                    alert.created_at,
                    alert.title,
                    alert.explanation,
                    alert.mitre_technique_id,
                    alert.mitre_technique_name,
                    alert.mitre_tactic,
                    json.dumps(alert.evidence_event_ids),
                    json.dumps(alert.evidence_summary, ensure_ascii=False),
                    alert.incident_id,
                    1 if alert.is_sample else 0,
                ),
            )

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            return self._row_to_alert(row) if row else None

    def list_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        include_samples: bool = True,
        limit: int = 200,
    ) -> List[Alert]:
        clauses: List[str] = []
        params: List[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if status:
            clauses.append("status = ?")
            params.append(status.upper())
        if not include_samples:
            clauses.append("is_sample = 0")

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(int(limit), 5000)))
        sql = f"SELECT * FROM alerts {where_sql} ORDER BY created_at DESC LIMIT ?"
        with self.connection() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [self._row_to_alert(r) for r in rows]

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> Alert:
        return Alert(
            alert_id=row["alert_id"],
            rule_id=row["rule_id"],
            rule_name=row["rule_name"],
            severity=Severity.from_str(row["severity"]),
            status=AlertStatus.from_str(row["status"]),
            created_at=row["created_at"],
            title=row["title"],
            explanation=row["explanation"],
            mitre_technique_id=row["mitre_technique_id"],
            mitre_technique_name=row["mitre_technique_name"],
            mitre_tactic=row["mitre_tactic"],
            evidence_event_ids=json.loads(row["evidence_event_ids_json"] or "[]"),
            evidence_summary=json.loads(row["evidence_summary_json"] or "{}"),
            incident_id=row["incident_id"],
            is_sample=bool(row["is_sample"]),
        )

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------
    def save_incident(self, incident: Incident) -> None:
        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    incident_id, title, description, severity, status,
                    created_at, updated_at, resolved_at, resolution_summary,
                    assigned_to, linked_event_ids_json, linked_alert_ids_json, is_sample
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.incident_id,
                    incident.title,
                    incident.description,
                    incident.severity.value,
                    incident.status.value,
                    incident.created_at,
                    incident.updated_at,
                    incident.resolved_at,
                    incident.resolution_summary,
                    incident.assigned_to,
                    json.dumps(incident.linked_event_ids),
                    json.dumps(incident.linked_alert_ids),
                    1 if incident.is_sample else 0,
                ),
            )
            for note in incident.notes:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO incident_notes (
                        note_id, incident_id, author, content, created_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        note.note_id,
                        incident.incident_id,
                        note.author,
                        note.content,
                        note.created_at,
                    ),
                )
            for entry in incident.timeline:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO incident_timeline (
                        entry_id, incident_id, timestamp, entry_type,
                        actor, description, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.entry_id,
                        incident.incident_id,
                        entry.timestamp,
                        entry.entry_type,
                        entry.actor,
                        entry.description,
                        json.dumps(entry.metadata, ensure_ascii=False),
                    ),
                )

    def get_incident(self, incident_id: str) -> Incident:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if not row:
                raise IncidentNotFoundError(f"Incident '{incident_id}' not found.")
            return self._row_to_incident(conn, row)

    def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        include_samples: bool = True,
    ) -> List[Incident]:
        clauses: List[str] = []
        params: List[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status.upper())
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if not include_samples:
            clauses.append("is_sample = 0")

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM incidents {where_sql} ORDER BY updated_at DESC"
        with self.connection() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [self._row_to_incident(conn, r) for r in rows]

    @staticmethod
    def _row_to_incident(conn: sqlite3.Connection, row: sqlite3.Row) -> Incident:
        incident_id = row["incident_id"]
        note_rows = conn.execute(
            "SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at ASC",
            (incident_id,),
        ).fetchall()
        timeline_rows = conn.execute(
            "SELECT * FROM incident_timeline WHERE incident_id = ? ORDER BY timestamp ASC",
            (incident_id,),
        ).fetchall()

        notes = [
            IncidentNote(
                note_id=nr["note_id"],
                incident_id=nr["incident_id"],
                author=nr["author"],
                content=nr["content"],
                created_at=nr["created_at"],
            )
            for nr in note_rows
        ]
        timeline = [
            TimelineEntry(
                entry_id=tr["entry_id"],
                incident_id=tr["incident_id"],
                timestamp=tr["timestamp"],
                entry_type=tr["entry_type"],
                actor=tr["actor"],
                description=tr["description"],
                metadata=json.loads(tr["metadata_json"] or "{}"),
            )
            for tr in timeline_rows
        ]
        return Incident(
            incident_id=incident_id,
            title=row["title"],
            description=row["description"],
            severity=Severity.from_str(row["severity"]),
            status=IncidentStatus.from_str(row["status"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            resolved_at=row["resolved_at"],
            resolution_summary=row["resolution_summary"],
            assigned_to=row["assigned_to"],
            linked_event_ids=json.loads(row["linked_event_ids_json"] or "[]"),
            linked_alert_ids=json.loads(row["linked_alert_ids_json"] or "[]"),
            notes=notes,
            timeline=timeline,
            is_sample=bool(row["is_sample"]),
        )

    # ------------------------------------------------------------------
    # Dashboard & Platform Statistics
    # ------------------------------------------------------------------
    def get_dashboard_statistics(self, include_samples: bool = True) -> Dict[str, Any]:
        sample_filter = "" if include_samples else "WHERE is_sample = 0"
        with self.connection() as conn:
            total_events = conn.execute(
                f"SELECT COUNT(*) FROM security_events {sample_filter}"
            ).fetchone()[0]
            sample_events = conn.execute(
                "SELECT COUNT(*) FROM security_events WHERE is_sample = 1"
            ).fetchone()[0]
            real_events = conn.execute(
                "SELECT COUNT(*) FROM security_events WHERE is_sample = 0"
            ).fetchone()[0]

            total_alerts = conn.execute(
                f"SELECT COUNT(*) FROM alerts {sample_filter}"
            ).fetchone()[0]
            total_incidents = conn.execute(
                f"SELECT COUNT(*) FROM incidents {sample_filter}"
            ).fetchone()[0]
            enabled_rules = conn.execute(
                "SELECT COUNT(*) FROM detection_rules WHERE enabled = 1"
            ).fetchone()[0]

            event_sev_rows = conn.execute(
                f"SELECT severity, COUNT(*) AS cnt FROM security_events {sample_filter} GROUP BY severity"
            ).fetchall()
            alert_sev_rows = conn.execute(
                f"SELECT severity, COUNT(*) AS cnt FROM alerts {sample_filter} GROUP BY severity"
            ).fetchall()
            inc_status_rows = conn.execute(
                f"SELECT status, COUNT(*) AS cnt FROM incidents {sample_filter} GROUP BY status"
            ).fetchall()
            rule_hit_rows = conn.execute(
                f"SELECT rule_id, rule_name, COUNT(*) AS cnt FROM alerts {sample_filter} GROUP BY rule_id, rule_name ORDER BY cnt DESC"
            ).fetchall()

        return {
            "total_events": total_events,
            "real_telemetry_events": real_events,
            "sample_telemetry_events": sample_events,
            "total_alerts": total_alerts,
            "total_incidents": total_incidents,
            "enabled_detection_rules": enabled_rules,
            "event_severity_distribution": {r["severity"]: r["cnt"] for r in event_sev_rows},
            "alert_severity_distribution": {r["severity"]: r["cnt"] for r in alert_sev_rows},
            "incident_status_distribution": {r["status"]: r["cnt"] for r in inc_status_rows},
            "detection_statistics": [
                {"rule_id": r["rule_id"], "rule_name": r["rule_name"], "alert_count": r["cnt"]}
                for r in rule_hit_rows
            ],
            "includes_sample_data": include_samples and sample_events > 0,
        }
