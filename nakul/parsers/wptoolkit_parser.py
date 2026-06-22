"""
WP Toolkit Log Parser
======================

Parses WP Toolkit logs for WordPress-related events.
"""

import re
from datetime import datetime
from typing import Any, Dict, Optional

from nakul.parsers.base import BaseParser


WP_ERROR = re.compile(r'(?:error|failed|fatal|exception|critical)', re.IGNORECASE)
WP_WARNING = re.compile(r'(?:warning|deprecated|notice)', re.IGNORECASE)
WP_UPDATE = re.compile(r'(?:updated|update|upgrade|installed|activated)', re.IGNORECASE)
WP_SECURITY = re.compile(r'(?:vulnerability|exploit|malware|infected|suspicious)', re.IGNORECASE)


class WpToolkitParser(BaseParser):
    """Parses WP Toolkit log files."""

    def __init__(self):
        super().__init__("wptoolkit", "wptoolkit")

    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parse a WP Toolkit log line."""
        if not raw_line:
            return None

        is_security = WP_SECURITY.search(raw_line)
        is_error = WP_ERROR.search(raw_line)
        is_warning = WP_WARNING.search(raw_line)
        is_update = WP_UPDATE.search(raw_line)

        if not (is_security or is_error or is_warning or is_update):
            return None

        if is_security:
            severity = "critical"
            category = "security"
            message = f"WP Toolkit security: {raw_line[:300]}"
        elif is_error:
            severity = "warning"
            category = "web"
            message = f"WP Toolkit error: {raw_line[:300]}"
        elif is_warning:
            severity = "info"
            category = "web"
            message = f"WP Toolkit warning: {raw_line[:300]}"
        else:
            severity = "info"
            category = "system"
            message = f"WP Toolkit: {raw_line[:300]}"

        return self._make_event(
            message=message,
            severity=severity,
            category=category,
            raw_line=raw_line,
            metadata={"type": "wptoolkit"},
        )
