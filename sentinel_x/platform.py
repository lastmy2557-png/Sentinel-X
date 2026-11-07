"""
Unified Sentinel-X Platform Orchestrator (Phase 5 — Integration).
Connects Core Storage, Audit Logger, Log Ingestion, Threat Detection Engine,
Incident Management, Reporting Exporter, External Integrations, and Security Dashboard
through clean interfaces.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from sentinel_x.core.audit import AuditLogger
from sentinel_x.core.config import SentinelConfig
from sentinel_x.core.database import DatabaseManager
from sentinel_x.core.models import Alert, NormalizedSecurityEvent
from sentinel_x.dashboard.server import DashboardService
from sentinel_x.detection.engine import ThreatDetectionEngine
from sentinel_x.incidents.service import IncidentManagementService
from sentinel_x.ingestion.service import LogIngestionService
from sentinel_x.integrations.connectors import IntegrationRegistry
from sentinel_x.reporting.exporter import IncidentReportExporter


class SentinelXPlatform:
    """Integrated facade wiring all SOC modules together."""

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        allowed_ingest_base_dir: Optional[Path] = None,
    ) -> None:
        self.config = config or SentinelConfig.from_env()
        self.db = DatabaseManager(self.config.db_path)
        self.audit = AuditLogger(self.config.audit_log_path)
        self.integrations = IntegrationRegistry(
            self.config,
            db=self.db,
            audit_logger=self.audit,
        )
        self.detection = ThreatDetectionEngine(
            db=self.db,
            audit_logger=self.audit,
            load_defaults=True,
        )
        self.ingestion = LogIngestionService(
            db=self.db,
            audit_logger=self.audit,
            allowed_base_dir=allowed_ingest_base_dir,
            max_file_bytes=self.config.max_ingest_file_bytes,
            on_event_ingested=self._handle_ingested_event,
        )
        self.incidents = IncidentManagementService(
            db=self.db,
            audit_logger=self.audit,
        )
        self.reporting = IncidentReportExporter(db=self.db)
        self.dashboard = DashboardService(
            db=self.db,
            integrations=self.integrations,
        )
        self._last_generated_alerts: List[Alert] = []

    def _handle_ingested_event(self, event: NormalizedSecurityEvent) -> None:
        alerts = self.detection.evaluate_event(event)
        if alerts:
            self._last_generated_alerts.extend(alerts)

    def pop_generated_alerts(self) -> List[Alert]:
        alerts = list(self._last_generated_alerts)
        self._last_generated_alerts.clear()
        return alerts
