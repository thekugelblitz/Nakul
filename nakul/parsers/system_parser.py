"""
System Log Parser
==================

Parses syslog, kernel, and journal logs for system-level events.
"""

import re
from datetime import datetime
from typing import Any, Dict, Optional

from nakul.parsers.base import BaseParser


SYSLOG_PATTERN = re.compile(
    r'^(?P<time>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s+'
    r'(?P<message>.*)'
)

KERNEL_PATTERN = re.compile(
    r'^(?:\[[\s\d.]+\]\s+)?(?P<message>.*)'
)

# Critical system events
OOM_PATTERN = re.compile(r'(?:Out of memory|oom-killer|oom_kill|Killed process)', re.IGNORECASE)
SEGFAULT_PATTERN = re.compile(r'(?:segfault|segmentation fault|general protection fault)', re.IGNORECASE)
DISK_ERROR = re.compile(r'(?:I/O error|disk error|EXT4-fs error|XFS error|read-only)', re.IGNORECASE)
SERVICE_RESTART = re.compile(r'(?:Started|Stopped|Restarting|reloading|systemd.*(?:start|stop|restart))', re.IGNORECASE)
KERNEL_PANIC = re.compile(r'(?:kernel panic|BUG:|WARNING:|OOPS)', re.IGNORECASE)


class SystemParser(BaseParser):
    """Parses system logs (syslog, kernel, journal)."""

    def __init__(self):
        super().__init__("system", "system")

    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse a system log line."""
        if not raw_line:
            return None

        match = SYSLOG_PATTERN.match(raw_line)
        if not match:
            return self._parse_kernel_line(raw_line)

        data = match.groupdict()
        message = data.get("message", "")
        service = data.get("service", "")

        # Detect critical events
        severity, category, event_type = self._classify_message(message)

        if severity is None:
            return None  # Not interesting enough

        pid = None
        if data.get("pid"):
            try:
                pid = int(data["pid"])
            except ValueError:
                pass

        timestamp = self._parse_syslog_timestamp(data.get("time", ""))

        return self._make_event(
            message=f"{service}: {message[:400]}",
            severity=severity,
            category=category,
            timestamp=timestamp,
            raw_line=raw_line,
            hostname=data.get("hostname", ""),
            process=service,
            pid=pid,
            metadata={"type": event_type, "service": service},
        )

    def _parse_kernel_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse kernel log lines."""
        severity, category, event_type = self._classify_message(raw_line)
        if severity is None:
            return None

        return self._make_event(
            message=f"Kernel: {raw_line[:400]}",
            severity=severity,
            category=category,
            raw_line=raw_line,
            metadata={"type": event_type},
        )

    @staticmethod
    def _classify_message(message: str):
        """Classify a log message into severity and category. Returns (severity, category, type) or (None, None, None)."""
        if OOM_PATTERN.search(message):
            return "critical", "resource", "oom_kill"
        if KERNEL_PANIC.search(message):
            return "critical", "system", "kernel_panic"
        if SEGFAULT_PATTERN.search(message):
            return "critical", "system", "segfault"
        if DISK_ERROR.search(message):
            return "critical", "system", "disk_error"
        if SERVICE_RESTART.search(message):
            return "info", "service", "service_change"
        return None, None, None

    @staticmethod
    def _parse_syslog_timestamp(time_str: str) -> str:
        """Parse syslog timestamp."""
        try:
            year = datetime.utcnow().year
            dt = datetime.strptime(f"{year} {time_str.strip()}", "%Y %b %d %H:%M:%S")
            return dt.isoformat()
        except ValueError:
            return datetime.utcnow().isoformat()
