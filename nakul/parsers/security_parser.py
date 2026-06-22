"""
Security Log Parser
====================

Parses Imunify360, CSF/LFD, and auth/secure logs
for security-related events.
"""

import re
from datetime import datetime
from typing import Any, Dict, Optional

from nakul.parsers.base import BaseParser


# CSF/LFD log patterns
CSF_BLOCK_PATTERN = re.compile(
    r'(?P<time>\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+'
    r'(?P<message>.*)'
)
CSF_IP_PATTERN = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
CSF_BLOCKED = re.compile(r'(?:Blocked|Denied|dropped|rejected)', re.IGNORECASE)
CSF_BRUTE = re.compile(r'(?:brute.?force|login.?failure|authentication.?fail)', re.IGNORECASE)

# Auth/secure log patterns
# Example: Jun 22 10:00:00 server sshd[12345]: Failed password for user from 192.168.1.1 port 22
AUTH_PATTERN = re.compile(
    r'^(?P<time>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s+'
    r'(?P<message>.*)'
)
AUTH_FAILED = re.compile(r'(?:Failed password|authentication failure|FAILED LOGIN|invalid user)', re.IGNORECASE)
AUTH_SUCCESS = re.compile(r'(?:Accepted password|session opened|Successful login)', re.IGNORECASE)
AUTH_IP = re.compile(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
AUTH_USER = re.compile(r'(?:for|user[= ])[\s]?(\S+)')

# Imunify360 patterns
IMUNIFY_PATTERN = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?:\[(?P<level>\w+)\]\s+)?'
    r'(?P<message>.*)'
)
IMUNIFY_MALWARE = re.compile(r'(?:malware|virus|trojan|infected|malicious)', re.IGNORECASE)
IMUNIFY_BLOCKED = re.compile(r'(?:blocked|denied|quarantined|cleaned)', re.IGNORECASE)


class SecurityParser(BaseParser):
    """Parses security-related logs (CSF, Imunify360, auth)."""

    def __init__(self, log_type: str = "auth"):
        self.log_type = log_type
        super().__init__(f"security_{log_type}", "security")

    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Route parsing based on log type."""
        if not raw_line:
            return None

        if self.log_type == "csf":
            return self._parse_csf_line(raw_line)
        elif self.log_type == "imunify":
            return self._parse_imunify_line(raw_line)
        else:
            return self._parse_auth_line(raw_line)

    def _parse_auth_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse auth/secure log line."""
        match = AUTH_PATTERN.match(raw_line)
        if not match:
            return None

        data = match.groupdict()
        message = data.get("message", "")
        service = data.get("service", "")

        # Only care about authentication events
        is_failed = AUTH_FAILED.search(message)
        is_success = AUTH_SUCCESS.search(message)

        if not is_failed and not is_success:
            return None

        # Extract IP
        ip = ""
        ip_match = AUTH_IP.search(message)
        if ip_match:
            ip = ip_match.group(1)

        # Extract username
        user = ""
        user_match = AUTH_USER.search(message)
        if user_match:
            user = user_match.group(1)

        severity = "warning" if is_failed else "info"
        category = "auth"

        if is_failed:
            msg = f"Failed login attempt for '{user}' from {ip} via {service}"
        else:
            msg = f"Successful login for '{user}' from {ip} via {service}"

        pid = None
        if data.get("pid"):
            try:
                pid = int(data["pid"])
            except ValueError:
                pass

        timestamp = self._parse_syslog_timestamp(data.get("time", ""))

        return self._make_event(
            message=msg,
            severity=severity,
            category=category,
            timestamp=timestamp,
            raw_line=raw_line,
            ip_address=ip,
            hostname=data.get("hostname", ""),
            account=user if user else None,
            pid=pid,
            metadata={
                "service": service,
                "auth_result": "failed" if is_failed else "success",
                "username": user,
            },
        )

    def _parse_csf_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse CSF/LFD log line."""
        if not CSF_BLOCKED.search(raw_line) and not CSF_BRUTE.search(raw_line):
            return None

        # Extract IP
        ip = ""
        ip_match = CSF_IP_PATTERN.search(raw_line)
        if ip_match:
            ip = ip_match.group(1)

        severity = "warning"
        category = "security"

        if CSF_BRUTE.search(raw_line):
            message = f"CSF: Brute-force attack detected from {ip}"
            severity = "critical"
        elif CSF_BLOCKED.search(raw_line):
            message = f"CSF: IP blocked — {ip}"
        else:
            message = f"CSF event: {raw_line[:200]}"

        return self._make_event(
            message=message,
            severity=severity,
            category=category,
            raw_line=raw_line,
            ip_address=ip,
            metadata={"type": "csf_block"},
        )

    def _parse_imunify_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse Imunify360 log line."""
        match = IMUNIFY_PATTERN.match(raw_line)
        if not match:
            return None

        data = match.groupdict()
        message = data.get("message", raw_line)

        is_malware = IMUNIFY_MALWARE.search(message)
        is_blocked = IMUNIFY_BLOCKED.search(message)

        if not is_malware and not is_blocked:
            return None

        severity = "critical" if is_malware else "warning"
        category = "malware" if is_malware else "security"

        ip = ""
        ip_match = CSF_IP_PATTERN.search(message)
        if ip_match:
            ip = ip_match.group(1)

        timestamp = data.get("time", "")
        if timestamp:
            try:
                dt = datetime.strptime(timestamp.strip(), "%Y-%m-%d %H:%M:%S")
                timestamp = dt.isoformat()
            except ValueError:
                timestamp = datetime.utcnow().isoformat()

        return self._make_event(
            message=f"Imunify360: {message[:300]}",
            severity=severity,
            category=category,
            timestamp=timestamp,
            raw_line=raw_line,
            ip_address=ip,
            metadata={
                "type": "malware_detection" if is_malware else "security_block",
                "level": data.get("level", ""),
            },
        )

    @staticmethod
    def _parse_syslog_timestamp(time_str: str) -> str:
        """Parse syslog timestamp: Jun 22 10:00:00"""
        try:
            # Add current year since syslog doesn't include it
            year = datetime.utcnow().year
            dt = datetime.strptime(f"{year} {time_str.strip()}", "%Y %b %d %H:%M:%S")
            return dt.isoformat()
        except ValueError:
            return datetime.utcnow().isoformat()
