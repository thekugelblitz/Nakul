"""
Base Parser
============

Abstract base class for all log parsers.
Provides common interface for transforming raw log lines into structured events.
"""

import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional


class BaseParser(ABC):
    """Abstract base class for all log parsers."""

    def __init__(self, name: str, source: str):
        self.name = name
        self.source = source
        self.logger = logging.getLogger(f"nakul.parsers.{name}")
        self.parse_count: int = 0
        self.error_count: int = 0

    @abstractmethod
    def parse_line(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single raw log line into a structured event dict.
        Returns None if the line cannot be parsed or is not relevant.
        """
        pass

    def parse_batch(self, raw_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse a batch of raw collected items into structured events.
        Each item has at least 'raw_line', 'source', 'file_path'.
        """
        events = []
        for item in raw_items:
            raw_line = item.get("raw_line", "")
            if not raw_line:
                continue

            try:
                event = self.parse_line(raw_line)
                if event:
                    # Enrich with collection metadata
                    event.setdefault("id", str(uuid.uuid4()))
                    event.setdefault("source", self.source)
                    event.setdefault("log_file", item.get("file_path", ""))
                    self.parse_count += 1
                    events.append(event)
            except Exception as e:
                self.error_count += 1
                if self.error_count <= 10:  # Only log first 10 errors
                    self.logger.debug(f"Parse error: {e} — line: {raw_line[:200]}")

        return events

    def _make_event(
        self,
        message: str,
        severity: str = "info",
        category: str = "system",
        timestamp: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Helper to create a standardized event dict."""
        event = {
            "id": str(uuid.uuid4()),
            "timestamp": timestamp or datetime.utcnow().isoformat(),
            "source": self.source,
            "category": category,
            "severity": severity,
            "message": message,
            "metadata": {},
        }
        event.update(kwargs)
        return event

    def get_status(self) -> Dict[str, Any]:
        """Return parser status."""
        return {
            "name": self.name,
            "source": self.source,
            "parse_count": self.parse_count,
            "error_count": self.error_count,
        }
