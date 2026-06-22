"""
Notifier Base & Implementations
=================================

Notification subsystem with dashboard, email, and webhook
delivery channels. Supports rate limiting and grouping.
"""

import asyncio
import json
import logging
import smtplib
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

logger = logging.getLogger("nakul.notifiers")


class BaseNotifier(ABC):
    """Abstract base notifier."""

    def __init__(self, name: str, config: Dict[str, Any] = None):
        self.name = name
        self.config = config or {}
        self.enabled = True
        self.logger = logging.getLogger(f"nakul.notifiers.{name}")
        self._rate_counter: Dict[str, List[float]] = defaultdict(list)
        self.rate_limit_per_minute = config.get("rate_limit_per_minute", 10) if config else 10

    @abstractmethod
    async def send(self, alert: Dict[str, Any]) -> bool:
        """Send a notification. Returns True on success."""
        pass

    def check_rate_limit(self, key: str = "global") -> bool:
        """Check if rate limit allows sending."""
        now = time.time()
        window = now - 60  # 1-minute window

        self._rate_counter[key] = [
            t for t in self._rate_counter[key] if t > window
        ]

        if len(self._rate_counter[key]) >= self.rate_limit_per_minute:
            return False

        self._rate_counter[key].append(now)
        return True


class DashboardNotifier(BaseNotifier):
    """Stores alerts for dashboard display and SSE push."""

    def __init__(self, db=None, config: Dict[str, Any] = None):
        super().__init__("dashboard", config)
        self.db = db
        # In-memory queue for SSE
        self._pending_alerts: List[Dict[str, Any]] = []
        self._max_pending = 100

    async def send(self, alert: Dict[str, Any]) -> bool:
        """Store alert for dashboard display."""
        if not self.check_rate_limit():
            self.logger.debug("Dashboard notification rate-limited")
            return False

        # Add to in-memory queue for SSE
        self._pending_alerts.append(alert)
        if len(self._pending_alerts) > self._max_pending:
            self._pending_alerts = self._pending_alerts[-self._max_pending:]

        # Persist to database
        if self.db:
            try:
                await self.db.insert_alert(alert)
            except Exception as e:
                self.logger.error(f"Failed to persist alert: {e}")
                return False

        return True

    def get_pending_alerts(self, clear: bool = True) -> List[Dict[str, Any]]:
        """Get pending alerts for SSE push."""
        alerts = list(self._pending_alerts)
        if clear:
            self._pending_alerts.clear()
        return alerts


class EmailNotifier(BaseNotifier):
    """Sends alert notifications via email."""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("email", config)
        self.smtp_host = config.get("email_smtp_host", "") if config else ""
        self.smtp_port = config.get("email_smtp_port", 587) if config else 587
        self.smtp_user = config.get("email_smtp_user", "") if config else ""
        self.smtp_password = config.get("email_smtp_password", "") if config else ""
        self.from_addr = config.get("email_from", "") if config else ""
        self.to_addrs = config.get("email_to", []) if config else []

    async def send(self, alert: Dict[str, Any]) -> bool:
        """Send alert via email."""
        if not self.smtp_host or not self.to_addrs:
            self.logger.debug("Email not configured — skipping")
            return False

        if not self.check_rate_limit():
            self.logger.debug("Email notification rate-limited")
            return False

        try:
            severity = alert.get("severity", "info").upper()
            title = alert.get("title", "Nakul Alert")
            message = alert.get("message", "")
            evidence = alert.get("evidence", [])
            action = alert.get("recommended_action", "")

            subject = f"[Nakul {severity}] {title}"
            body = self._build_email_body(alert)

            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(self.to_addrs)
            msg.attach(MIMEText(body, "html"))

            # Send in a thread to avoid blocking
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._send_smtp, msg)

            self.logger.info(f"Email notification sent: {subject}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to send email: {e}")
            return False

    def _send_smtp(self, msg: MIMEMultipart) -> None:
        """Send email via SMTP (blocking, run in executor)."""
        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
            server.ehlo()
            if self.smtp_port == 587:
                server.starttls()
            if self.smtp_user and self.smtp_password:
                server.login(self.smtp_user, self.smtp_password)
            server.sendmail(
                self.from_addr, self.to_addrs, msg.as_string()
            )

    @staticmethod
    def _build_email_body(alert: Dict[str, Any]) -> str:
        """Build HTML email body."""
        severity = alert.get("severity", "info")
        color_map = {"critical": "#ef4444", "warning": "#f59e0b", "info": "#3b82f6"}
        color = color_map.get(severity, "#6b7280")

        evidence_html = ""
        for e in alert.get("evidence", [])[:5]:
            evidence_html += f"<pre style='background:#1e293b;color:#e2e8f0;padding:8px;border-radius:4px;font-size:12px;overflow-x:auto;'>{e}</pre>"

        return f"""
        <div style="font-family:Inter,system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0f172a;color:#e2e8f0;border-radius:12px;overflow:hidden;">
            <div style="background:{color};padding:16px 24px;">
                <h2 style="margin:0;color:white;font-size:18px;">⚡ {alert.get('title', 'Alert')}</h2>
                <p style="margin:4px 0 0;color:rgba(255,255,255,0.85);font-size:13px;">{severity.upper()} — {alert.get('timestamp', '')[:19]}</p>
            </div>
            <div style="padding:24px;">
                <p style="margin:0 0 16px;line-height:1.6;">{alert.get('message', '')}</p>
                {f'<h3 style="color:#94a3b8;font-size:13px;text-transform:uppercase;">Evidence</h3>{evidence_html}' if evidence_html else ''}
                {f'<h3 style="color:#94a3b8;font-size:13px;text-transform:uppercase;">Recommended Action</h3><p style="line-height:1.6;">{alert.get("recommended_action", "")}</p>' if alert.get("recommended_action") else ''}
                {f'<p style="color:#94a3b8;font-size:12px;margin-top:16px;">Affected: {alert.get("affected_entity", "N/A")}</p>' if alert.get("affected_entity") else ''}
            </div>
            <div style="background:#1e293b;padding:12px 24px;text-align:center;">
                <p style="margin:0;color:#64748b;font-size:11px;">Nakul Server Intelligence Platform</p>
            </div>
        </div>
        """


class WebhookNotifier(BaseNotifier):
    """Sends alert notifications via webhook (HTTP POST)."""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("webhook", config)
        self.url = config.get("webhook_url", "") if config else ""
        self.headers = config.get("webhook_headers", {}) if config else {}
        self.retry_count = config.get("webhook_retry_count", 3) if config else 3

    async def send(self, alert: Dict[str, Any]) -> bool:
        """Send alert via webhook."""
        if not self.url:
            return False

        if not self.check_rate_limit():
            self.logger.debug("Webhook notification rate-limited")
            return False

        try:
            import httpx

            headers = {"Content-Type": "application/json"}
            headers.update(self.headers)

            payload = {
                "timestamp": alert.get("timestamp", ""),
                "severity": alert.get("severity", "info"),
                "title": alert.get("title", ""),
                "message": alert.get("message", ""),
                "affected_entity": alert.get("affected_entity", ""),
                "recommended_action": alert.get("recommended_action", ""),
                "evidence": alert.get("evidence", [])[:5],
                "source": "nakul",
            }

            async with httpx.AsyncClient(timeout=10) as client:
                for attempt in range(self.retry_count):
                    try:
                        response = await client.post(
                            self.url, json=payload, headers=headers
                        )
                        if response.status_code < 300:
                            self.logger.info(f"Webhook delivered to {self.url}")
                            return True
                        self.logger.warning(
                            f"Webhook attempt {attempt+1} failed: HTTP {response.status_code}"
                        )
                    except Exception as e:
                        self.logger.warning(f"Webhook attempt {attempt+1} error: {e}")

                    if attempt < self.retry_count - 1:
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff

            self.logger.error(f"Webhook delivery failed after {self.retry_count} attempts")
            return False

        except ImportError:
            self.logger.error("httpx not installed — webhook notifications unavailable")
            return False
        except Exception as e:
            self.logger.error(f"Webhook error: {e}")
            return False


class NotificationManager:
    """Manages all notification channels."""

    def __init__(self, db=None, config: Dict[str, Any] = None):
        self.config = config or {}
        self.channels: Dict[str, BaseNotifier] = {}
        self.logger = logging.getLogger("nakul.notifiers.manager")

        # Initialize channels based on config
        if config.get("dashboard_enabled", True) if config else True:
            self.channels["dashboard"] = DashboardNotifier(db=db, config=config)

        if config.get("email_enabled", False) if config else False:
            self.channels["email"] = EmailNotifier(config=config)

        if config.get("webhook_enabled", False) if config else False:
            self.channels["webhook"] = WebhookNotifier(config=config)

    async def notify(self, incident: Dict[str, Any]) -> Dict[str, bool]:
        """
        Send notifications for an incident across all enabled channels.
        Returns {channel_name: success} dict.
        """
        alert = self._incident_to_alert(incident)
        results = {}

        for name, channel in self.channels.items():
            if channel.enabled:
                try:
                    success = await channel.send(alert)
                    results[name] = success
                except Exception as e:
                    self.logger.error(f"Notification error on {name}: {e}")
                    results[name] = False

        return results

    def get_dashboard_notifier(self) -> Optional[DashboardNotifier]:
        """Get the dashboard notifier for SSE access."""
        return self.channels.get("dashboard")

    @staticmethod
    def _incident_to_alert(incident: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an incident to an alert for notifications."""
        return {
            "id": str(uuid.uuid4()),
            "timestamp": incident.get("timestamp", datetime.utcnow().isoformat()),
            "incident_id": incident.get("id"),
            "severity": incident.get("severity", "warning"),
            "category": incident.get("category", "system"),
            "title": incident.get("summary", ""),
            "message": incident.get("explanation", ""),
            "evidence": incident.get("source_evidence", []),
            "affected_entity": (
                incident.get("affected_account") or
                incident.get("affected_ip") or
                incident.get("affected_service") or
                "unknown"
            ),
            "recommended_action": incident.get("suggested_remediation", ""),
            "acknowledged": False,
            "suppressed": False,
            "notification_sent": True,
        }
