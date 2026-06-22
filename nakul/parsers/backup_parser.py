"""
Backup Log Parser
==================

Parses Backuply and general backup log files
for backup job status, failures, and warnings.
"""

import re
from datetime import datetime
from typing import Any, Dict, Optional

from nakul.parsers.base import BaseParser


BACKUP_FAIL = re.compile(r'(?:failed|error|abort|cannot|unable|permission denied|disk full|no space)', re.IGNORECASE)
BACKUP_SUCCESS = re.compile(r'(?:completed|success|finished|done)', re.IGNORECASE)
BACKUP_WARNING = re.compile(r'(?:warning|skipped|partial|incomplete|retry)', re.IGNORECASE)
BACKUP_TIMESTAMP = re.compile(r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})')


class BackupParser(BaseParser):
    """Parses backup-related log files."""

    def __init__(self):
        super().__init__("backup", "backup")

    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse a backup log line."""
        if not raw_line:
            return None

        is_fail = BACKUP_FAIL.search(raw_line)
        is_success = BACKUP_SUCCESS.search(raw_line)
        is_warning = BACKUP_WARNING.search(raw_line)

        if not (is_fail or is_success or is_warning):
            return None

        if is_fail:
            severity = "critical"
            message = f"Backup failure: {raw_line[:300]}"
        elif is_warning:
            severity = "warning"
            message = f"Backup warning: {raw_line[:300]}"
        else:
            severity = "info"
            message = f"Backup completed: {raw_line[:300]}"

        timestamp = datetime.utcnow().isoformat()
        ts_match = BACKUP_TIMESTAMP.search(raw_line)
        if ts_match:
            try:
                dt = datetime.strptime(ts_match.group(1), "%Y-%m-%d %H:%M:%S")
                timestamp = dt.isoformat()
            except ValueError:
                pass

        return self._make_event(
            message=message,
            severity=severity,
            category="backup",
            timestamp=timestamp,
            raw_line=raw_line,
            metadata={
                "type": "backup_failure" if is_fail else ("backup_warning" if is_warning else "backup_success"),
            },
        )
