"""
Security Log Ingestion, Search, Investigation, and Correlation Service (Section 4.1).
Enforces path traversal boundaries, file size limits, and provides event correlation.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from sentinel_x.core.audit import AuditLogger
from sentinel_x.core.database import DatabaseManager
from sentinel_x.core.exceptions import IngestionError, SecurityBoundaryError
from sentinel_x.core.models import NormalizedSecurityEvent
from sentinel_x.ingestion.parsers import LogParserRegistry


class LogIngestionService:
    """Manages log ingestion, normalization, searching, investigation, and correlation."""

    def __init__(
        self,
        db: DatabaseManager,
        parser_registry: Optional[LogParserRegistry] = None,
        audit_logger: Optional[AuditLogger] = None,
        allowed_base_dir: Optional[Path] = None,
        max_file_bytes: int = 10 * 1024 * 1024,
        on_event_ingested: Optional[Callable[[NormalizedSecurityEvent], None]] = None,
    ) -> None:
        self.db = db
        self.registry = parser_registry or LogParserRegistry()
        self.audit_logger = audit_logger
        self.allowed_base_dir = allowed_base_dir.resolve() if allowed_base_dir else None
        self.max_file_bytes = max_file_bytes
        self.on_event_ingested = on_event_ingested

    def ingest_line(self, raw_line: str, is_sample: bool = False) -> NormalizedSecurityEvent:
        """Parse, normalize, persist, and forward a single log line."""
        event = self.registry.parse_line(raw_line, is_sample=is_sample)
        self.db.save_event(event)
        if self.on_event_ingested is not None:
            self.on_event_ingested(event)
        return event

    def ingest_lines(
        self, lines: Iterable[str], is_sample: bool = False
    ) -> List[NormalizedSecurityEvent]:
        """Ingest multiple log lines, skipping blank lines."""
        ingested: List[NormalizedSecurityEvent] = []
        for raw in lines:
            if not raw or not raw.strip():
                continue
            ingested.append(self.ingest_line(raw, is_sample=is_sample))
        return ingested

    def ingest_file(
        self, file_path: Path | str, is_sample: bool = False
    ) -> List[NormalizedSecurityEvent]:
        """
        Safely ingest a log file after verifying path traversal boundaries and size limits.
        """
        candidate = Path(file_path)
        if candidate.is_symlink():
            raise SecurityBoundaryError(f"Refusing to ingest symlink file: {file_path}")

        resolved = candidate.resolve()
        if self.allowed_base_dir is not None:
            try:
                resolved.relative_to(self.allowed_base_dir)
            except ValueError as exc:
                if self.audit_logger:
                    self.audit_logger.record(
                        action="INGEST_FILE_BLOCKED_PATH_TRAVERSAL",
                        target=str(file_path),
                        status="DENIED",
                    )
                raise SecurityBoundaryError(
                    f"Path '{file_path}' is outside the allowed ingestion directory '{self.allowed_base_dir}'."
                ) from exc

        if not resolved.is_file():
            raise IngestionError(f"Log file does not exist: {file_path}")

        size_bytes = resolved.stat().st_size
        if size_bytes > self.max_file_bytes:
            raise SecurityBoundaryError(
                f"File size ({size_bytes} bytes) exceeds maximum allowed ({self.max_file_bytes} bytes)."
            )

        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
        events = self.ingest_lines(lines, is_sample=is_sample)
        if self.audit_logger:
            self.audit_logger.record(
                action="INGEST_FILE",
                target=str(resolved),
                status="SUCCESS",
                details={"events_ingested": len(events), "is_sample": is_sample},
            )
        return events

    def search_events(
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
        limit: int = 200,
    ) -> List[NormalizedSecurityEvent]:
        """Filter and search normalized security events."""
        return self.db.query_events(
            category=category,
            severity=severity,
            source_ip=source_ip,
            user=user,
            action=action,
            outcome=outcome,
            search_query=search_query,
            start_time=start_time,
            end_time=end_time,
            include_samples=include_samples,
            limit=limit,
        )

    def correlate_events(
        self,
        group_by: str = "source_ip",
        min_events: int = 2,
        include_samples: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Correlate security events grouped by an entity key (source_ip, user, source_host)
        to assist security event investigation.
        """
        valid_group_fields = {"source_ip", "user", "source_host", "action"}
        if group_by not in valid_group_fields:
            raise IngestionError(
                f"Unsupported correlation group_by '{group_by}'. Must be one of {sorted(valid_group_fields)}."
            )

        events = self.db.query_events(include_samples=include_samples, limit=2000)
        groups: Dict[str, List[NormalizedSecurityEvent]] = defaultdict(list)
        for ev in events:
            key_val = getattr(ev, group_by, "")
            if key_val:
                groups[str(key_val)].append(ev)

        correlations: List[Dict[str, Any]] = []
        for entity, ev_list in groups.items():
            if len(ev_list) < min_events:
                continue
            sorted_evs = sorted(ev_list, key=lambda e: e.timestamp)
            categories = sorted({e.category.value for e in sorted_evs})
            actions = sorted({e.action for e in sorted_evs})
            severities = sorted({e.severity.value for e in sorted_evs})
            failure_count = sum(1 for e in sorted_evs if e.outcome == "failure")
            correlations.append(
                {
                    "group_by": group_by,
                    "entity": entity,
                    "event_count": len(sorted_evs),
                    "failure_count": failure_count,
                    "first_seen": sorted_evs[0].timestamp,
                    "last_seen": sorted_evs[-1].timestamp,
                    "categories": categories,
                    "actions": actions,
                    "severities": severities,
                    "event_ids": [e.event_id for e in sorted_evs],
                }
            )
        correlations.sort(key=lambda c: c["event_count"], reverse=True)
        return correlations
