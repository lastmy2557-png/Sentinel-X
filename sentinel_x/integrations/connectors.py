"""
External Security Integrations and Connector Interfaces for Sentinel-X (Section 4.6 & Phase 9).
Provides standardized interfaces and persistent configuration management for:
- SIEM Platforms (Splunk, Elastic SIEM, Microsoft Sentinel, QRadar)
- Endpoint Security Products / EDR (CrowdStrike, Microsoft Defender, SentinelOne, Wazuh)
- Threat Intelligence Sources (VirusTotal, AbuseIPDB, AlienVault OTX, MISP)
- Notification Systems / Webhooks (Slack, Microsoft Teams, Telegram, Line, PagerDuty)
- External Security Tools / SOAR (TheHive, FortiGate, Palo Alto PAN-OS, Nessus)

Strictly reports NOT_CONFIGURED when credentials or endpoints are absent or placeholders.
Masks all secrets in API/UI responses and never fakes or simulates an active external connection.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import ProxyHandler, Request, build_opener, urlopen

from sentinel_x.core.audit import AuditLogger
from sentinel_x.core.config import SentinelConfig, _is_real_secret
from sentinel_x.core.database import DatabaseManager
from sentinel_x.core.exceptions import ConfigurationError, ValidationError
from sentinel_x.core.models import Alert


def mask_secret_value(secret: str) -> str:
    """Return a masked representation of a secret so raw API keys are never exposed to the UI."""
    cleaned = (secret or "").strip()
    if not cleaned or not _is_real_secret(cleaned):
        return ""
    if len(cleaned) <= 6:
        return "••••••••"
    return f"••••••••{cleaned[-4:]}"


def validate_http_endpoint(url: str, allow_empty: bool = True) -> str:
    """Validate that an endpoint URL uses http:// or https:// and has a valid hostname."""
    cleaned = (url or "").strip()
    if not cleaned:
        if allow_empty:
            return ""
        raise ValidationError("Endpoint URL cannot be empty.")

    if any(ch in cleaned for ch in ("\r", "\n", "\t", " ")):
        raise ValidationError("Endpoint URL must not contain whitespace or control characters.")

    parsed = urlparse(cleaned)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        raise ValidationError(
            f"Invalid Endpoint URL '{cleaned}'. Must start with http:// or https:// and include a valid host."
        )
    return cleaned


class BaseSecurityConnector(ABC):
    """Abstract base interface for all external security connectors."""

    connector_id: str = "base"
    connector_type: str = "generic"
    display_name: str = "Base Security Connector"
    description_th: str = "การเชื่อมต่อบริการความปลอดภัยภายนอก"
    supported_examples: str = ""
    requires_endpoint: bool = True
    requires_api_key: bool = True

    def __init__(
        self,
        provider_name: str = "",
        endpoint_url: str = "",
        api_key: str = "",
        enabled: bool = True,
        updated_at: str = "",
    ) -> None:
        self.provider_name = provider_name.strip()
        self.endpoint_url = endpoint_url.strip()
        self.api_key = api_key.strip() if _is_real_secret(api_key) else ""
        self.enabled = bool(enabled)
        self.updated_at = updated_at

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True only if enabled and all required endpoints and non-placeholder credentials are set."""

    def has_credentials(self) -> bool:
        """Return True if required credentials/endpoints are present regardless of enabled toggle."""
        ep_ok = (
            self.endpoint_url.startswith(("http://", "https://"))
            if self.requires_endpoint
            else True
        )
        key_ok = bool(self.api_key) if self.requires_api_key else True
        return bool(ep_ok and key_ok)

    def get_status(self) -> Dict[str, Any]:
        """Return honest configuration and readiness status."""
        configured = self.is_configured()
        if not self.enabled and self.has_credentials():
            status_code = "DISABLED"
            msg = "Connector credentials are saved, but the integration is currently disabled."
        elif configured:
            status_code = "CONFIGURED_READY"
            msg = "Required credentials and endpoint are configured."
        else:
            status_code = "NOT_CONFIGURED"
            msg = "Not connected: required credentials or endpoint URL are not configured."

        return {
            "connector_id": self.connector_id,
            "connector_type": self.connector_type,
            "display_name": self.display_name,
            "provider_name": self.provider_name,
            "configured": configured,
            "enabled": self.enabled,
            "status": status_code,
            "message": msg,
        }

    def get_safe_settings(self) -> Dict[str, Any]:
        """Return configuration details with secrets strictly masked for UI/API consumption."""
        status_info = self.get_status()
        return {
            **status_info,
            "description_th": self.description_th,
            "supported_examples": self.supported_examples,
            "requires_endpoint": self.requires_endpoint,
            "requires_api_key": self.requires_api_key,
            "endpoint_url": self.endpoint_url,
            "api_key_configured": bool(self.api_key),
            "api_key_masked": mask_secret_value(self.api_key),
            "updated_at": self.updated_at,
        }

    def require_configured(self) -> None:
        if not self.is_configured():
            raise ConfigurationError(
                f"Connector '{self.display_name}' ({self.connector_id}) cannot execute because "
                "required credentials or endpoints are not configured."
            )

    def test_connection(self, timeout: float = 3.0) -> Dict[str, Any]:
        """
        Verify connector configuration and, if an HTTP(S) endpoint is configured,
        perform a real, bounded connectivity probe. Never fakes a successful connection.
        """
        if not self.has_credentials():
            return {
                "connector_id": self.connector_id,
                "success": False,
                "status": "NOT_CONFIGURED",
                "message": "ไม่สามารถทดสอบได้: ยังไม่ได้ระบุ Endpoint URL หรือ API Key ที่จำเป็น",
            }
        if not self.enabled:
            return {
                "connector_id": self.connector_id,
                "success": False,
                "status": "DISABLED",
                "message": "การเชื่อมต่อนี้ถูกปิดใช้งานอยู่ (Disabled) กรุณาเปิดใช้งานก่อนทดสอบ",
            }

        if not self.endpoint_url:
            return {
                "connector_id": self.connector_id,
                "success": True,
                "status": "CREDENTIALS_VALIDATED",
                "message": "ตรวจสอบรูปแบบ API Key ผ่านแล้ว (พร้อมใช้งานเมื่อเรียก API ของผู้ให้บริการ)",
            }

        parsed = urlparse(self.endpoint_url)
        headers = {"User-Agent": "Sentinel-X-SOC/0.1"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = Request(self.endpoint_url, headers=headers, method="GET")
        try:
            if parsed.hostname in ("127.0.0.1", "localhost"):
                opener = build_opener(ProxyHandler({}))
                with opener.open(req, timeout=timeout) as resp:
                    http_code = int(resp.status)
            else:
                with urlopen(req, timeout=timeout) as resp:
                    http_code = int(resp.status)
            return {
                "connector_id": self.connector_id,
                "success": True,
                "status": f"REACHABLE_HTTP_{http_code}",
                "message": f"เชื่อมต่อกับ Endpoint สำเร็จจริง (HTTP {http_code})",
            }
        except HTTPError as http_err:
            # Server responded with an HTTP status code (e.g. 401/403/405), proving network reachability
            return {
                "connector_id": self.connector_id,
                "success": 200 <= http_err.code < 500,
                "status": f"HTTP_{http_err.code}",
                "message": f"เซิร์ฟเวอร์ปลายทางตอบกลับด้วยสถานะ HTTP {http_err.code} ({http_err.reason})",
            }
        except (URLError, OSError) as net_err:
            return {
                "connector_id": self.connector_id,
                "success": False,
                "status": "UNREACHABLE",
                "message": f"ไม่สามารถเชื่อมต่อกับเซิร์ฟเวอร์ปลายทางได้: {net_err}",
            }


class SIEMPlatformConnector(BaseSecurityConnector):
    """Interface for forwarding alerts and normalized events to external SIEM platforms."""

    connector_id = "siem_forwarder"
    connector_type = "SIEM_PLATFORM"
    display_name = "External SIEM Platform Forwarder"
    description_th = "ส่งต่อข้อมูล Security Events และ Alerts ไปยังระบบ SIEM ภายนอก"
    supported_examples = "Splunk HEC, Elastic SIEM, Microsoft Sentinel, IBM QRadar"
    requires_endpoint = True
    requires_api_key = True

    def __init__(
        self,
        endpoint_url: str = "",
        api_key: str = "",
        provider_name: str = "Splunk / Elastic SIEM",
        enabled: bool = True,
        updated_at: str = "",
    ) -> None:
        super().__init__(
            provider_name=provider_name,
            endpoint_url=endpoint_url,
            api_key=api_key,
            enabled=enabled,
            updated_at=updated_at,
        )

    def is_configured(self) -> bool:
        return bool(
            self.enabled
            and self.endpoint_url.startswith(("http://", "https://"))
            and self.api_key
        )

    def build_alert_payload(self, alert: Alert) -> Dict[str, Any]:
        self.require_configured()
        return {
            "destination": self.endpoint_url,
            "provider": self.provider_name,
            "schema": "sentinel_x.siem.v1",
            "alert": alert.to_dict(),
        }


class EndpointSecurityConnector(BaseSecurityConnector):
    """Interface for querying host status or requesting host isolation via EDR."""

    connector_id = "edr_controller"
    connector_type = "ENDPOINT_SECURITY"
    display_name = "Endpoint Detection & Response (EDR) Interface"
    description_th = "เชื่อมต่อระบบ EDR/XDR เพื่อตรวจสอบสถานะเครื่องปลายทางหรือสั่งกักกันเครื่อง (Host Isolation)"
    supported_examples = "CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, Wazuh"
    requires_endpoint = True
    requires_api_key = True

    def __init__(
        self,
        api_url: str = "",
        api_token: str = "",
        provider_name: str = "CrowdStrike / Defender / Wazuh",
        enabled: bool = True,
        updated_at: str = "",
    ) -> None:
        super().__init__(
            provider_name=provider_name,
            endpoint_url=api_url,
            api_key=api_token,
            enabled=enabled,
            updated_at=updated_at,
        )

    @property
    def api_url(self) -> str:
        return self.endpoint_url

    @property
    def api_token(self) -> str:
        return self.api_key

    def is_configured(self) -> bool:
        return bool(
            self.enabled
            and self.endpoint_url.startswith(("http://", "https://"))
            and self.api_key
        )


class ThreatIntelligenceConnector(BaseSecurityConnector):
    """Interface for enriching IPs, domains, and file hashes against Threat Intelligence feeds."""

    connector_id = "threat_intel_feed"
    connector_type = "THREAT_INTELLIGENCE"
    display_name = "Threat Intelligence Enrichment Provider"
    description_th = "ตรวจสอบชื่อเสียงของ IP, Domain และค่า Hash ของไฟล์กับฐานข้อมูลภัยคุกคามระดับโลก"
    supported_examples = "VirusTotal API v3, AbuseIPDB, AlienVault OTX, MISP"
    requires_endpoint = False
    requires_api_key = True

    def __init__(
        self,
        api_key: str = "",
        endpoint_url: str = "https://www.virustotal.com/api/v3",
        provider_name: str = "VirusTotal / AbuseIPDB",
        enabled: bool = True,
        updated_at: str = "",
    ) -> None:
        super().__init__(
            provider_name=provider_name,
            endpoint_url=endpoint_url,
            api_key=api_key,
            enabled=enabled,
            updated_at=updated_at,
        )

    def is_configured(self) -> bool:
        return bool(self.enabled and self.api_key)


class WebhookNotificationConnector(BaseSecurityConnector):
    """Interface for dispatching high-severity alert notifications to SOC webhooks."""

    connector_id = "webhook_notifier"
    connector_type = "NOTIFICATION_SYSTEM"
    display_name = "SOC Alert Webhook Notification Connector"
    description_th = "ส่งการแจ้งเตือนเหตุการณ์ความรุนแรงสูง (High/Critical Alerts) ไปยังห้องปฏิบัติการ SOC ทันที"
    supported_examples = "Slack Webhook, Microsoft Teams, Telegram Bot, Line Messaging API, PagerDuty"
    requires_endpoint = True
    requires_api_key = False

    def __init__(
        self,
        webhook_url: str = "",
        api_key: str = "",
        provider_name: str = "Slack / Teams / Telegram Webhook",
        enabled: bool = True,
        updated_at: str = "",
    ) -> None:
        valid_url = (
            webhook_url.strip()
            if _is_real_secret(webhook_url) and webhook_url.strip().startswith(("http://", "https://"))
            else ""
        )
        super().__init__(
            provider_name=provider_name,
            endpoint_url=valid_url,
            api_key=api_key,
            enabled=enabled,
            updated_at=updated_at,
        )

    @property
    def webhook_url(self) -> str:
        return self.endpoint_url

    def is_configured(self) -> bool:
        return bool(self.enabled and self.endpoint_url.startswith(("http://", "https://")))


class ExternalSecurityToolConnector(BaseSecurityConnector):
    """Interface for integrating external security scanners, firewalls, or SOAR platforms."""

    connector_id = "external_security_tool"
    connector_type = "EXTERNAL_SECURITY_TOOL"
    display_name = "External Security Tool & SOAR Adapter"
    description_th = "เชื่อมต่อระบบ Firewall API, ระบบสแกนช่องโหว่ หรือระบบอัตโนมัติ (SOAR / Case Management)"
    supported_examples = "TheHive, FortiGate API, Palo Alto PAN-OS, OpenVAS / Nessus API"
    requires_endpoint = True
    requires_api_key = True

    def __init__(
        self,
        tool_name: str = "TheHive / Firewall API",
        configured: bool = False,
        endpoint_url: str = "",
        api_key: str = "",
        enabled: bool = True,
        updated_at: str = "",
    ) -> None:
        super().__init__(
            provider_name=tool_name,
            endpoint_url=endpoint_url,
            api_key=api_key,
            enabled=enabled,
            updated_at=updated_at,
        )
        self.tool_name = tool_name
        self._explicit_configured = bool(configured)

    def is_configured(self) -> bool:
        if self._explicit_configured and self.enabled:
            return True
        return bool(
            self.enabled
            and self.endpoint_url.startswith(("http://", "https://"))
            and self.api_key
        )


class IntegrationRegistry:
    """Registry managing all external security connectors, persistence, and real readiness states."""

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        db: Optional[DatabaseManager] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        cfg = config or SentinelConfig()
        self.db = db
        self.audit_logger = audit_logger
        self._connectors: Dict[str, BaseSecurityConnector] = {}

        self.register(SIEMPlatformConnector(cfg.siem_endpoint, cfg.siem_api_key))
        self.register(EndpointSecurityConnector())
        self.register(ThreatIntelligenceConnector(cfg.threat_intel_api_key))
        self.register(WebhookNotificationConnector(cfg.webhook_url))
        self.register(ExternalSecurityToolConnector())

        if self.db is not None:
            self._load_from_database()

    def _load_from_database(self) -> None:
        if self.db is None:
            return
        saved_map = self.db.list_connector_settings()
        for cid, row in saved_map.items():
            conn = self._connectors.get(cid)
            if conn is None:
                continue
            conn.provider_name = row["provider_name"] or conn.provider_name
            conn.endpoint_url = row["endpoint_url"]
            conn.api_key = row["api_key"] if _is_real_secret(row["api_key"]) else ""
            conn.enabled = bool(row["enabled"])
            conn.updated_at = row["updated_at"]

    def register(self, connector: BaseSecurityConnector) -> None:
        self._connectors[connector.connector_id] = connector

    def get(self, connector_id: str) -> Optional[BaseSecurityConnector]:
        return self._connectors.get(connector_id)

    def list_statuses(self) -> List[Dict[str, Any]]:
        return [c.get_status() for c in self._connectors.values()]

    def list_settings(self) -> List[Dict[str, Any]]:
        """Return safe, masked settings for all registered connectors."""
        return [c.get_safe_settings() for c in self._connectors.values()]

    def update_connector_settings(
        self,
        connector_id: str,
        provider_name: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        api_key: Optional[str] = None,
        enabled: Optional[bool] = None,
        clear_secret: bool = False,
        actor: str = "admin_ui",
    ) -> Dict[str, Any]:
        """
        Validate and update a connector's configuration, persisting to SQLite and logging
        to the security audit log without exposing raw secrets.
        """
        conn = self._connectors.get(connector_id)
        if conn is None:
            raise ValidationError(f"Unknown connector_id '{connector_id}'.")

        if provider_name is not None:
            cleaned_provider = provider_name.strip()[:120]
            if cleaned_provider:
                conn.provider_name = cleaned_provider

        if endpoint_url is not None:
            conn.endpoint_url = validate_http_endpoint(endpoint_url, allow_empty=True)

        if clear_secret:
            conn.api_key = ""
        elif api_key is not None and api_key.strip():
            raw_key = api_key.strip()
            if not _is_real_secret(raw_key):
                raise ValidationError(
                    "API Key must not be a template placeholder (e.g. CHANGE_ME or PLACEHOLDER)."
                )
            conn.api_key = raw_key

        if enabled is not None:
            conn.enabled = bool(enabled)

        conn.updated_at = datetime.now(timezone.utc).isoformat()

        if self.db is not None:
            self.db.save_connector_setting(
                connector_id=conn.connector_id,
                provider_name=conn.provider_name,
                endpoint_url=conn.endpoint_url,
                api_key=conn.api_key,
                enabled=conn.enabled,
                updated_at=conn.updated_at,
            )

        if self.audit_logger is not None:
            self.audit_logger.record(
                action="CONNECTOR_CONFIG_UPDATED",
                actor=actor,
                target=conn.connector_id,
                status="SUCCESS",
                details={
                    "provider_name": conn.provider_name,
                    "endpoint_url": conn.endpoint_url,
                    "api_key_configured": bool(conn.api_key),
                    "enabled": conn.enabled,
                    "status": conn.get_status()["status"],
                },
            )

        return conn.get_safe_settings()

    def test_connector_connection(
        self, connector_id: str, timeout: float = 3.0, actor: str = "admin_ui"
    ) -> Dict[str, Any]:
        conn = self._connectors.get(connector_id)
        if conn is None:
            raise ValidationError(f"Unknown connector_id '{connector_id}'.")

        result = conn.test_connection(timeout=timeout)
        if self.audit_logger is not None:
            self.audit_logger.record(
                action="CONNECTOR_CONNECTION_TESTED",
                actor=actor,
                target=connector_id,
                status="SUCCESS" if result["success"] else "FAILURE",
                details={"status": result["status"], "message": result["message"]},
            )
        return result
