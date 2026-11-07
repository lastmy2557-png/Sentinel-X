"""
Incident Management Service for Sentinel-X (Section 4.4).
Supports creating incidents, updating status and severity, recording investigation notes,
linking events and alerts, maintaining an immutable-style incident timeline,
and tracking incident resolution.
"""

from __future__ import annotations

from typing import List, Optional

from sentinel_x.core.audit import AuditLogger
from sentinel_x.core.database import DatabaseManager
from sentinel_x.core.exceptions import ValidationError
from sentinel_x.core.models import (
    AlertStatus,
    Incident,
    IncidentNote,
    IncidentStatus,
    Severity,
    TimelineEntry,
    utc_now_iso,
)


class IncidentManagementService:
    """Manages the complete SOC incident lifecycle."""

    def __init__(
        self,
        db: DatabaseManager,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self.db = db
        self.audit_logger = audit_logger

    def create_incident(
        self,
        title: str,
        description: str = "",
        severity: Severity | str = Severity.HIGH,
        assigned_to: str = "unassigned",
        actor: str = "soc_analyst",
        event_ids: Optional[List[str]] = None,
        alert_ids: Optional[List[str]] = None,
        is_sample: bool = False,
    ) -> Incident:
        """Create a new security incident and record its initial timeline entry."""
        sev = Severity.from_str(severity) if isinstance(severity, str) else severity
        linked_events = list(dict.fromkeys(event_ids or []))
        linked_alerts = list(dict.fromkeys(alert_ids or []))

        # Automatically pull evidence event IDs from linked alerts
        for aid in linked_alerts:
            alert = self.db.get_alert(aid)
            if alert:
                if alert.is_sample:
                    is_sample = True
                for eid in alert.evidence_event_ids:
                    if eid not in linked_events:
                        linked_events.append(eid)

        now = utc_now_iso()
        incident = Incident(
            title=title.strip(),
            description=description.strip(),
            severity=sev,
            status=IncidentStatus.OPEN,
            created_at=now,
            updated_at=now,
            assigned_to=assigned_to.strip() or "unassigned",
            linked_event_ids=linked_events,
            linked_alert_ids=linked_alerts,
            is_sample=is_sample,
        )
        incident.timeline.append(
            TimelineEntry(
                incident_id=incident.incident_id,
                timestamp=now,
                entry_type="INCIDENT_CREATED",
                actor=actor,
                description=f"Incident created with severity {sev.value} and status OPEN.",
                metadata={
                    "linked_alerts": len(linked_alerts),
                    "linked_events": len(linked_events),
                },
            )
        )
        self.db.save_incident(incident)

        # Link alerts back to this incident
        for aid in linked_alerts:
            alert = self.db.get_alert(aid)
            if alert:
                alert.incident_id = incident.incident_id
                if alert.status == AlertStatus.NEW:
                    alert.status = AlertStatus.IN_PROGRESS
                self.db.save_alert(alert)

        if self.audit_logger:
            self.audit_logger.record(
                action="INCIDENT_CREATED",
                actor=actor,
                target=incident.incident_id,
                details={"title": incident.title, "severity": incident.severity.value},
            )
        return incident

    def update_status(
        self,
        incident_id: str,
        new_status: IncidentStatus | str,
        actor: str = "soc_analyst",
        resolution_summary: str = "",
    ) -> Incident:
        """Update incident status, tracking resolution timestamp if RESOLVED or CLOSED."""
        incident = self.db.get_incident(incident_id)
        target_status = (
            IncidentStatus.from_str(new_status)
            if isinstance(new_status, str)
            else new_status
        )
        old_status = incident.status
        now = utc_now_iso()
        incident.status = target_status
        incident.updated_at = now

        if target_status in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
            incident.resolved_at = incident.resolved_at or now
            if resolution_summary.strip():
                incident.resolution_summary = resolution_summary.strip()
            for aid in incident.linked_alert_ids:
                alert = self.db.get_alert(aid)
                if alert:
                    alert.status = AlertStatus.RESOLVED
                    self.db.save_alert(alert)

        incident.timeline.append(
            TimelineEntry(
                incident_id=incident.incident_id,
                timestamp=now,
                entry_type="STATUS_CHANGED",
                actor=actor,
                description=(
                    f"Status changed from {old_status.value} to {target_status.value}."
                    + (f" Resolution: {incident.resolution_summary}" if incident.resolution_summary else "")
                ),
                metadata={"old_status": old_status.value, "new_status": target_status.value},
            )
        )
        self.db.save_incident(incident)
        if self.audit_logger:
            self.audit_logger.record(
                action="INCIDENT_STATUS_UPDATED",
                actor=actor,
                target=incident_id,
                details={"old_status": old_status.value, "new_status": target_status.value},
            )
        return incident

    def update_severity(
        self,
        incident_id: str,
        new_severity: Severity | str,
        actor: str = "soc_analyst",
        reason: str = "",
    ) -> Incident:
        """Update incident severity and log to timeline."""
        incident = self.db.get_incident(incident_id)
        target_sev = (
            Severity.from_str(new_severity)
            if isinstance(new_severity, str)
            else new_severity
        )
        old_sev = incident.severity
        now = utc_now_iso()
        incident.severity = target_sev
        incident.updated_at = now
        incident.timeline.append(
            TimelineEntry(
                incident_id=incident.incident_id,
                timestamp=now,
                entry_type="SEVERITY_CHANGED",
                actor=actor,
                description=(
                    f"Severity changed from {old_sev.value} to {target_sev.value}."
                    + (f" Reason: {reason.strip()}" if reason.strip() else "")
                ),
                metadata={"old_severity": old_sev.value, "new_severity": target_sev.value},
            )
        )
        self.db.save_incident(incident)
        return incident

    def add_note(
        self,
        incident_id: str,
        content: str,
        author: str = "soc_analyst",
    ) -> Incident:
        """Add an investigation note to an incident and record on the timeline."""
        if not content or not content.strip():
            raise ValidationError("Investigation note content cannot be empty.")
        incident = self.db.get_incident(incident_id)
        now = utc_now_iso()
        note = IncidentNote(
            incident_id=incident_id,
            author=author.strip() or "soc_analyst",
            content=content.strip(),
            created_at=now,
        )
        incident.notes.append(note)
        incident.updated_at = now
        incident.timeline.append(
            TimelineEntry(
                incident_id=incident_id,
                timestamp=now,
                entry_type="NOTE_ADDED",
                actor=note.author,
                description=f"Investigation note added by {note.author}.",
                metadata={"note_id": note.note_id},
            )
        )
        self.db.save_incident(incident)
        return incident

    def link_events(
        self,
        incident_id: str,
        event_ids: List[str],
        actor: str = "soc_analyst",
    ) -> Incident:
        """Associate additional security events with an existing incident."""
        incident = self.db.get_incident(incident_id)
        added: List[str] = []
        for eid in event_ids:
            if eid and eid not in incident.linked_event_ids:
                incident.linked_event_ids.append(eid)
                added.append(eid)

        if added:
            now = utc_now_iso()
            incident.updated_at = now
            incident.timeline.append(
                TimelineEntry(
                    incident_id=incident_id,
                    timestamp=now,
                    entry_type="EVENTS_LINKED",
                    actor=actor,
                    description=f"Linked {len(added)} security event(s) to incident.",
                    metadata={"added_event_ids": added},
                )
            )
            self.db.save_incident(incident)
        return incident
