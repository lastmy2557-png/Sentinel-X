"""
Real-time Local-First UDP Syslog Receiver for Sentinel-X (Phase 7 Extension).
Listens for RFC3164/RFC5424 Syslog datagrams over UDP (bound to 127.0.0.1 by default),
strips RFC priority prefixes (<PRI>), enforces payload size limits, and forwards
events into LogIngestionService and ThreatDetectionEngine.
"""

from __future__ import annotations

import re
import socketserver
import threading
from typing import Optional

from sentinel_x.ingestion.service import LogIngestionService

SYSLOG_PRI_PREFIX_RE = re.compile(r"^<\d{1,3}>(?:1\s+)?")
MAX_SYSLOG_DATAGRAM_BYTES = 8192


class _SyslogUDPHandler(socketserver.BaseRequestHandler):
    """Handles individual UDP syslog datagrams safely."""

    def handle(self) -> None:
        raw_bytes: bytes = self.request[0]
        if not raw_bytes:
            return
        if len(raw_bytes) > MAX_SYSLOG_DATAGRAM_BYTES:
            raw_bytes = raw_bytes[:MAX_SYSLOG_DATAGRAM_BYTES]

        text = raw_bytes.decode("utf-8", errors="replace").strip()
        if not text:
            return

        # Strip optional <PRI> header before passing to parser registry
        cleaned = SYSLOG_PRI_PREFIX_RE.sub("", text).strip()
        if not cleaned:
            return

        server: "SyslogUDPReceiver" = self.server  # type: ignore[assignment]
        try:
            server.ingestion_service.ingest_line(cleaned, is_sample=False)
            server.received_count += 1
        except Exception:
            server.error_count += 1


class SyslogUDPReceiver(socketserver.ThreadingUDPServer):
    """Threaded UDP Syslog Server integrated with LogIngestionService."""

    allow_reuse_address = True

    def __init__(
        self,
        ingestion_service: LogIngestionService,
        host: str = "127.0.0.1",
        port: int = 5514,
    ) -> None:
        if not (0 <= port <= 65535):
            raise ValueError(f"Invalid UDP port: {port}")
        self.ingestion_service = ingestion_service
        self.received_count = 0
        self.error_count = 0
        self._bg_thread: Optional[threading.Thread] = None
        super().__init__((host, port), _SyslogUDPHandler)

    @property
    def bound_port(self) -> int:
        return int(self.server_address[1])

    def start_background(self) -> None:
        """Start serving UDP syslog packets in a daemon thread."""
        if self._bg_thread and self._bg_thread.is_alive():
            return
        self._bg_thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._bg_thread.start()

    def stop(self) -> None:
        """Stop the UDP syslog receiver cleanly."""
        self.shutdown()
        self.server_close()
        if self._bg_thread and self._bg_thread.is_alive():
            self._bg_thread.join(timeout=2.0)
