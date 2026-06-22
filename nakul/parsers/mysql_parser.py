"""
MySQL / MariaDB Log Parser
============================

Parses MySQL/MariaDB error logs, slow query logs,
and general logs for database-related events.
"""

import re
from datetime import datetime
from typing import Any, Dict, Optional

from nakul.parsers.base import BaseParser


# MySQL error log pattern
# Example: 2025-06-22T10:00:00.123456Z 0 [ERROR] [MY-000001] Message
MYSQL_ERROR_PATTERN = re.compile(
    r'^(?P<time>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+'
    r'(?P<thread>\d+)\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'(?:\[(?P<code>[^\]]*)\]\s+)?'
    r'(?P<message>.*)'
)

# MariaDB error log pattern
# Example: 250622 10:00:00 [ERROR] mysqld: message
MARIADB_ERROR_PATTERN = re.compile(
    r'^(?P<time>\d{6}\s+\d{1,2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'(?P<message>.*)'
)

# Slow query log patterns
SLOW_QUERY_TIME = re.compile(r'# Query_time:\s+(?P<query_time>[\d.]+)\s+Lock_time:\s+(?P<lock_time>[\d.]+)\s+Rows_sent:\s+(?P<rows_sent>\d+)\s+Rows_examined:\s+(?P<rows_examined>\d+)')
SLOW_QUERY_USER = re.compile(r'# User@Host:\s+(?P<user>\S+?)(?:\[\S*\])?\s+@\s+(?P<host>\S*)\s+\[(?P<ip>[^\]]*)\]')

# Connection and access patterns
CONNECTION_REFUSED = re.compile(r"(?:Too many connections|max_connections|Connection refused|Can't connect)", re.IGNORECASE)
ACCESS_DENIED = re.compile(r"Access denied for user '(?P<user>[^']+)'@'(?P<host>[^']+)'", re.IGNORECASE)
CRASH_PATTERN = re.compile(r"(?:crash|segfault|assertion|fatal|aborting|shutting down)", re.IGNORECASE)


class MysqlParser(BaseParser):
    """Parses MySQL/MariaDB log files."""

    def __init__(self):
        super().__init__("mysql", "database")
        self._slow_query_buffer: Dict[str, Any] = {}

    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse a MySQL/MariaDB log line."""
        if not raw_line or raw_line.startswith("#") and "Query_time" not in raw_line and "User@Host" not in raw_line:
            return None

        # Check for slow query metadata
        slow_event = self._parse_slow_query_line(raw_line)
        if slow_event:
            return slow_event

        # Try MySQL error format
        event = self._parse_error_line(raw_line)
        if event:
            return event

        return None

    def _parse_error_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse a MySQL/MariaDB error log line."""
        match = MYSQL_ERROR_PATTERN.match(raw_line)
        if not match:
            match = MARIADB_ERROR_PATTERN.match(raw_line)

        if not match:
            return None

        data = match.groupdict()
        level = data.get("level", "").lower()
        message = data.get("message", raw_line)

        severity_map = {
            "error": "warning",
            "warning": "info",
            "note": "info",
            "system": "info",
        }
        severity = severity_map.get(level, "info")

        # Detect critical patterns
        if CRASH_PATTERN.search(message):
            severity = "critical"
        elif CONNECTION_REFUSED.search(message):
            severity = "critical"

        # Detect access denied
        access_match = ACCESS_DENIED.search(message)
        metadata = {"level": level, "code": data.get("code", "")}

        if access_match:
            severity = "warning"
            metadata["mysql_user"] = access_match.group("user")
            metadata["mysql_host"] = access_match.group("host")
            message = f"MySQL access denied for '{access_match.group('user')}'@'{access_match.group('host')}'"

        timestamp = self._parse_mysql_timestamp(data.get("time", ""))

        return self._make_event(
            message=message[:500],
            severity=severity,
            category="database",
            timestamp=timestamp,
            raw_line=raw_line,
            metadata=metadata,
        )

    def _parse_slow_query_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse slow query log metadata lines."""
        # Parse user/host line
        user_match = SLOW_QUERY_USER.match(raw_line)
        if user_match:
            self._slow_query_buffer = {
                "user": user_match.group("user"),
                "host": user_match.group("host"),
                "ip": user_match.group("ip"),
            }
            return None

        # Parse query time line
        time_match = SLOW_QUERY_TIME.match(raw_line)
        if time_match:
            query_time = float(time_match.group("query_time"))
            lock_time = float(time_match.group("lock_time"))
            rows_sent = int(time_match.group("rows_sent"))
            rows_examined = int(time_match.group("rows_examined"))

            severity = "info"
            if query_time > 30:
                severity = "critical"
            elif query_time > 10:
                severity = "warning"

            user = self._slow_query_buffer.get("user", "unknown")
            ip = self._slow_query_buffer.get("ip", "")

            message = (
                f"Slow query ({query_time:.1f}s) by user '{user}': "
                f"examined {rows_examined} rows, sent {rows_sent}"
            )

            return self._make_event(
                message=message,
                severity=severity,
                category="database",
                raw_line=raw_line,
                ip_address=ip,
                metadata={
                    "query_time": query_time,
                    "lock_time": lock_time,
                    "rows_sent": rows_sent,
                    "rows_examined": rows_examined,
                    "mysql_user": user,
                    "host": self._slow_query_buffer.get("host", ""),
                    "type": "slow_query",
                },
            )

        return None

    @staticmethod
    def _parse_mysql_timestamp(time_str: str) -> str:
        """Parse MySQL timestamp formats."""
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]
        # MariaDB short format: 250622 10:00:00
        if len(time_str) < 16 and " " in time_str:
            try:
                dt = datetime.strptime(time_str.strip(), "%y%m%d %H:%M:%S")
                return dt.isoformat()
            except ValueError:
                pass

        for fmt in formats:
            try:
                dt = datetime.strptime(time_str.strip(), fmt)
                return dt.isoformat()
            except ValueError:
                continue
        return datetime.utcnow().isoformat()
