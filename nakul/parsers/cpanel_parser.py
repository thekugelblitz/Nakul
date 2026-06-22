"""
cPanel Log Parser
==================

Parses cPanel/WHM logs for account-related events,
login activity, and administrative actions.
"""

import re
from datetime import datetime
from typing import Any, Dict, Optional

from nakul.parsers.base import BaseParser


# cPanel access log
CPANEL_ACCESS_PATTERN = re.compile(
    r'^(?P<ip>[\d.]+)\s+.*\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<size>\d+)'
)

# WHM login log
WHM_LOGIN_PATTERN = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<status>\S+)\s+'
    r'(?:user=(?P<user>\S+))?\s*'
    r'(?:ip=(?P<ip>[\d.]+))?'
)

# cPanel error patterns
CPANEL_ERROR_PATTERN = re.compile(
    r'\[(?P<time>[^\]]+)\]\s+(?P<level>\w+)\s+(?P<message>.*)', re.IGNORECASE
)


class CpanelParser(BaseParser):
    """Parses cPanel/WHM log files."""

    def __init__(self):
        super().__init__("cpanel", "cpanel")

    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse a cPanel/WHM log line."""
        if not raw_line:
            return None

        # Try WHM login format
        event = self._parse_login_line(raw_line)
        if event:
            return event

        # Try cPanel access format
        event = self._parse_access_line(raw_line)
        if event:
            return event

        # Try error format
        event = self._parse_error_line(raw_line)
        if event:
            return event

        return None

    def _parse_login_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse WHM login log lines."""
        match = WHM_LOGIN_PATTERN.match(raw_line)
        if not match:
            return None

        data = match.groupdict()
        status = data.get("status", "").lower()
        user = data.get("user", "unknown")
        ip = data.get("ip", "")

        if "fail" in status:
            severity = "warning"
            message = f"WHM login failed for '{user}' from {ip}"
        elif "success" in status or "ok" in status:
            severity = "info"
            message = f"WHM login successful for '{user}' from {ip}"
        else:
            return None

        timestamp = data.get("time", "")
        if timestamp:
            try:
                dt = datetime.strptime(timestamp.strip(), "%Y-%m-%d %H:%M:%S")
                timestamp = dt.isoformat()
            except ValueError:
                timestamp = datetime.utcnow().isoformat()

        return self._make_event(
            message=message,
            severity=severity,
            category="auth",
            timestamp=timestamp,
            raw_line=raw_line,
            ip_address=ip,
            account=user,
            metadata={"type": "whm_login", "result": status},
        )

    def _parse_access_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse cPanel access log for errors."""
        match = CPANEL_ACCESS_PATTERN.match(raw_line)
        if not match:
            return None

        data = match.groupdict()
        status = int(data.get("status", 200))

        if status < 400:
            return None

        ip = data.get("ip", "")
        path = data.get("path", "")

        severity = "warning" if status >= 500 else "info"
        message = f"cPanel HTTP {status}: {data.get('method', 'GET')} {path}"

        return self._make_event(
            message=message,
            severity=severity,
            category="web",
            raw_line=raw_line,
            ip_address=ip,
            metadata={"status_code": status, "path": path},
        )

    def _parse_error_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse cPanel error log lines."""
        match = CPANEL_ERROR_PATTERN.match(raw_line)
        if not match:
            return None

        data = match.groupdict()
        level = data.get("level", "").lower()
        message = data.get("message", raw_line)

        if level in ("error", "crit", "alert", "emerg"):
            severity = "warning" if level == "error" else "critical"
        elif level == "warn":
            severity = "info"
        else:
            return None

        return self._make_event(
            message=f"cPanel: {message[:300]}",
            severity=severity,
            category="system",
            raw_line=raw_line,
            metadata={"level": level},
        )
