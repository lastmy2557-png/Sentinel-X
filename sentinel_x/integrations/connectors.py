"""
External Security Integrations and Connector Interfaces for Sentinel-X (Section 4.6).
Provides standardized interfaces for:
- SIEM Platforms
- Endpoint Security Products (EDR)
- Threat Intelligence Sources
- Notification Systems
- External Security Tools

Strictly reports NOT_CONFIGURED when credentials or endpoints are absent or placeholders.
Never fakes or simulates an active external connection.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from sentinel_x.core.config import SentinelConfig, _is_real_secret
from sentinel_x.core.exceptions import ConfigurationError
from sentinel_x.core.models import Alert


class BaseSecurityConnector(ABC):
    """Abstract base interface for all external security connectors."""

    connector_id: str = "base"
    connector_type: str = "generic"
    display_name: str = "Base Security Connector"

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True only if all required endpoints and non-placeholder credentials are set."""

    def get_status(self) -> Dict[str, Any]:
        """Return honest configuration and readiness status."""
        configured = self.is_configured()
        return {
            "connector_id": self.connector_id,
            "connector_type": self.connector_type,
            "display_name": self.display_name,
            "configured": configured,
            "status": "CONFIGURED_READY" if configured else "NOT_CONFIGURED",
            "message": (
                "Required credentials and endpoint are configured."
                if configured
                else "Not connected: required credentials or endpoint URL are not configured."
            ),
        }

    def require_configured(self) -> None:
        if not self.is_configured():
            raise ConfigurationError(
                f"Connector '{self.display_name}' ({self.connector_id}) cannot execute because "
                "required credentials or endpoints are not configured."
            )


class SIEMPlatformConnector(BaseSecurityConnector):
    """Interface for forwarding alerts and normalized events to external SIEM platforms."""

    connector_id = "siem_forwarder"
    connector_type = "SIEM_PLATFORM"
    display_name = "External SIEM Platform Forwarder"

    def __init__(self, endpoint_url: str = "", api_key: str = "") -> None:
        self.endpoint_url = endpoint_url.strip()
        self.api_key = api_key.strip() if _is_real_secret(api_key) else ""

    def is_configured(self) -> bool:
        return bool(self.endpoint_url.startswith(("http://", "https://")) and self.api_key)

    def build_alert_payload(self, alert: Alert) -> Dict[str, Any]:
        self.require_configured()
        return {
            "destination": self.endpoint_url,
            "schema": "sentinel_x.siem.v1",
            "alert": alert.to_dict(),
        }


class EndpointSecurityConnector(BaseSecurityConnector):
    """Interface for querying host status or requesting host isolation via EDR."""

    connector_id = "edr_controller"
    connector_type = "ENDPOINT_SECURITY"
    display_name = "Endpoint Detection & Response (EDR) Interface"

    def __init__(self, api_url: str = "", api_token: str = "") -> None:
        self.api_url = api_url.strip()
        self.api_token = api_token.strip() if _is_real_secret(api_token) else ""

    def is_configured(self) -> bool:
        return bool(self.api_url.startswith(("http://", "https://")) and self.api_token)


class ThreatIntelligenceConnector(BaseSecurityConnector):
    """Interface for enriching IPs, domains, and file hashes against Threat Intelligence feeds."""

    connector_id = "threat_intel_feed"
    connector_type = "THREAT_INTELLIGENCE"
    display_name = "Threat Intelligence Enrichment Provider"

    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key.strip() if _is_real_secret(api_key) else ""

    def is_configured(self) -> bool:
        return bool(self.api_key)


class WebhookNotificationConnector(BaseSecurityConnector):
    """Interface for dispatching high-severity alert notifications to SOC webhooks."""

    connector_id = "webhook_notifier"
    connector_type = "NOTIFICATION_SYSTEM"
    display_name = "SOC Alert Webhook Notification Connector"

    def __init__(self, webhook_url: str = "") -> None:
        self.webhook_url = (
            webhook_url.strip()
            if _is_real_secret(webhook_url) and webhook_url.strip().startswith(("http://", "https://"))
            else ""
        )

    def is_configured(self) -> bool:
        return bool(self.webhook_url)


class ExternalSecurityToolConnector(BaseSecurityConnector):
    """Interface for integrating external security scanners or packet analysis tools."""

    connector_id = "external_security_tool"
    connector_type = "EXTERNAL_SECURITY_TOOL"
    display_name = "External Security Tool Adapter"

    def __init__(self, tool_name: str = "custom_tool", configured: bool = False) -> None:
        self.tool_name = tool_name
        self._configured = bool(configured)

    def is_configured(self) -> bool:
        return self._configured


class IntegrationRegistry:
    """Registry managing all external security connectors and reporting their real states."""

    def __init__(self, config: Optional[SentinelConfig] = None) -> None:
        cfg = config or SentinelConfig()
        self._connectors: Dict[str, BaseSecurityConnector] = {}
        self.register(SIEMPlatformConnector(cfg.siem_endpoint, cfg.siem_api_key))
        self.register(EndpointSecurityConnector())
        self.register(ThreatIntelligenceConnector(cfg.threat_intel_api_key))
        self.register(WebhookNotificationConnector(cfg.webhook_url))
        self.register(ExternalSecurityToolConnector())

    def register(self, connector: BaseSecurityConnector) -> None:
        self._connectors[connector.connector_id] = connector

    def get(self, connector_id: str) -> Optional[BaseSecurityConnector]:
        return self._connectors.get(connector_id)

    def list_statuses(self) -> List[Dict[str, Any]]:
        return [c.get_status() for c in self._connectors.values()]
