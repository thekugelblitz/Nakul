"""
Base Collector
===============

Abstract base class for all data collectors.
Provides common interface, error handling, and availability checking.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional


class BaseCollector(ABC):
    """Abstract base class for all collectors."""

    def __init__(self, name: str, config: Dict[str, Any] = None):
        self.name = name
        self.config = config or {}
        self.logger = logging.getLogger(f"nakul.collectors.{name}")
        self.last_collection: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self._available: Optional[bool] = None
        self.collection_count: int = 0

    @abstractmethod
    async def collect(self) -> List[Dict[str, Any]]:
        """
        Perform data collection. Returns a list of raw data items.
        Must handle errors gracefully and never crash.
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if this collector can operate (dependencies exist, paths accessible).
        Returns False if the data source is missing or inaccessible.
        """
        pass

    def get_status(self) -> Dict[str, Any]:
        """Return current collector status."""
        return {
            "name": self.name,
            "available": self._available if self._available is not None else self.is_available(),
            "last_collection": self.last_collection.isoformat() if self.last_collection else None,
            "last_error": self.last_error,
            "collection_count": self.collection_count,
        }

    async def safe_collect(self) -> List[Dict[str, Any]]:
        """
        Wrapper around collect() that catches all exceptions.
        Ensures the collector never crashes the agent.
        """
        if not self.is_available():
            self._available = False
            return []

        self._available = True
        try:
            results = await self.collect()
            self.last_collection = datetime.utcnow()
            self.last_error = None
            self.collection_count += 1
            return results
        except Exception as e:
            self.last_error = str(e)
            self.logger.error(f"Collection failed: {e}", exc_info=True)
            return []
