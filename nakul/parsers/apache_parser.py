"""
Apache / LiteSpeed Log Parser
===============================

Parses Apache and LiteSpeed access and error logs
into structured events with IP, domain, status code,
and request details.
"""

import re
from datetime import datetime
from typing import Any, Dict, Optional

from nakul.parsers.base import BaseParser


# Common Log Format / Combined Log Format regex
# Example: 192.168.1.1 - user [22/Jun/2025:10:00:00 +0000] "GET /path HTTP/1.1" 200 1234 "referer" "user-agent"
ACCESS_LOG_PATTERN = re.compile(
    r'^(?P<ip>[\d.:a-fA-F]+)\s+'      # IP address
    r'(?P<ident>\S+)\s+'               # Identity
    r'(?P<user>\S+)\s+'                # User
    r'\[(?P<time>[^\]]+)\]\s+'         # Timestamp
    r'"(?P<method>\S+)\s+'             # HTTP method
    r'(?P<path>\S+)\s+'                # Request path
    r'(?P<protocol>[^"]+)"\s+'         # Protocol
    r'(?P<status>\d{3})\s+'            # Status code
    r'(?P<size>\d+|-)'                 # Response size
    r'(?:\s+"(?P<referer>[^"]*)"\s+'   # Referer (optional)
    r'"(?P<user_agent>[^"]*)")?'       # User-Agent (optional)
)

# Apache/LiteSpeed error log pattern
# Example: [Sat Jun 22 10:00:00 2025] [error] [client 192.168.1.1] Error message
ERROR_LOG_PATTERN = re.compile(
    r'^\[(?P<time>[^\]]+)\]\s+'
    r'\[(?:(?P<module>\S+):)?(?P<level>\S+)\]\s+'
    r'(?:\[(?:client|pid)\s+(?P<client>[^\]]+)\]\s+)?'
    r'(?P<message>.*)'
)

# LiteSpeed-specific error pattern
LSWS_ERROR_PATTERN = re.compile(
    r'^(?P<time>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'(?:\[(?P<module>[^\]]*)\]\s+)?'
    r'(?P<message>.*)'
)

# Domain extraction from error log
DOMAIN_PATTERN = re.compile(r'(?:(?:server|host|domain)[:\s]+)?(\S+\.(?:com|net|org|io|co|info|biz|us|uk|ca|au|de|fr|in|ru|jp|br|mx|za|xyz|dev|app|site|online|store|tech)\b)', re.IGNORECASE)


class ApacheParser(BaseParser):
    """Parses Apache/LiteSpeed access and error logs."""

    def __init__(self):
        super().__init__("apache", "web")

    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse an Apache/LiteSpeed log line."""
        if not raw_line or raw_line.startswith("#"):
            return None

        # Try access log format first
        event = self._parse_access_line(raw_line)
        if event:
            return event

        # Try error log format
        event = self._parse_error_line(raw_line)
        if event:
            return event

        return None

    def _parse_access_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse an access log line."""
        match = ACCESS_LOG_PATTERN.match(raw_line)
        if not match:
            return None

        data = match.groupdict()
        status = int(data.get("status", 0))
        ip = data.get("ip", "")
        path = data.get("path", "")
        method = data.get("method", "")

        # Determine severity based on status code
        if status >= 500:
            severity = "critical" if status == 503 else "warning"
            message = f"HTTP {status} error: {method} {path}"
        elif status == 403 or status == 401:
            severity = "info"
            message = f"HTTP {status}: {method} {path}"
        else:
            # Skip normal 2xx/3xx for event generation (too noisy)
            # But still count them for metrics
            return None

        # Parse timestamp
        timestamp = self._parse_access_timestamp(data.get("time", ""))

        # Detect suspicious patterns
        category = "web"
        suspicious_paths = [
            "wp-login.php", "xmlrpc.php", "wp-admin",
            "/admin", "/phpmyadmin", "/.env",
            "/config", "/backup", "shell",
            "/cgi-bin", "eval(", "base64",
        ]
        if any(sp in path.lower() for sp in suspicious_paths):
            category = "security"
            severity = "warning"
            message = f"Suspicious request: {method} {path} from {ip}"

        size_str = data.get("size", "0")
        size = int(size_str) if size_str and size_str != "-" else 0

        return self._make_event(
            message=message,
            severity=severity,
            category=category,
            timestamp=timestamp,
            raw_line=raw_line,
            ip_address=ip,
            metadata={
                "method": method,
                "path": path,
                "status_code": status,
                "size": size,
                "user_agent": data.get("user_agent", ""),
                "referer": data.get("referer", ""),
                "user": data.get("user", "-"),
            },
        )

    def _parse_error_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse an error log line."""
        # Try standard Apache error format
        match = ERROR_LOG_PATTERN.match(raw_line)
        if not match:
            # Try LiteSpeed format
            match = LSWS_ERROR_PATTERN.match(raw_line)

        if not match:
            return None

        data = match.groupdict()
        level = data.get("level", "error").lower()
        message = data.get("message", raw_line)
        client = data.get("client", "")

        # Map Apache log levels to our severity
        severity_map = {
            "emerg": "critical",
            "alert": "critical",
            "crit": "critical",
            "error": "warning",
            "warn": "warning",
            "notice": "info",
            "info": "info",
            "debug": "info",
        }
        severity = severity_map.get(level, "info")

        # Extract IP from client field
        ip = ""
        if client:
            ip_match = re.search(r'([\d.]+)', client)
            if ip_match:
                ip = ip_match.group(1)

        # Extract domain if mentioned
        domain = None
        domain_match = DOMAIN_PATTERN.search(message)
        if domain_match:
            domain = domain_match.group(1).lower()

        timestamp = self._parse_error_timestamp(data.get("time", ""))

        return self._make_event(
            message=message[:500],
            severity=severity,
            category="web",
            timestamp=timestamp,
            raw_line=raw_line,
            ip_address=ip,
            domain=domain,
            metadata={
                "level": level,
                "module": data.get("module", ""),
            },
        )

    @staticmethod
    def _parse_access_timestamp(time_str: str) -> str:
        """Parse Apache access log timestamp format: 22/Jun/2025:10:00:00 +0000"""
        try:
            dt = datetime.strptime(time_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            return dt.isoformat()
        except (ValueError, IndexError):
            return datetime.utcnow().isoformat()

    @staticmethod
    def _parse_error_timestamp(time_str: str) -> str:
        """Parse various error log timestamp formats."""
        formats = [
            "%a %b %d %H:%M:%S.%f %Y",  # Apache: Sat Jun 22 10:00:00.123456 2025
            "%a %b %d %H:%M:%S %Y",      # Apache: Sat Jun 22 10:00:00 2025
            "%Y-%m-%d %H:%M:%S.%f",       # LiteSpeed: 2025-06-22 10:00:00.123
            "%Y-%m-%d %H:%M:%S",          # ISO-ish
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(time_str.strip(), fmt)
                return dt.isoformat()
            except ValueError:
                continue
        return datetime.utcnow().isoformat()
