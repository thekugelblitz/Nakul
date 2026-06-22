"""
Deduplication Manager
======================

Prevents duplicate incidents using fingerprinting,
configurable cooldowns, and occurrence counting.
"""

import hashlib
import logging
import time
from typing import Dict, Optional

logger = logging.getLogger("nakul.incidents.dedup")


class DedupManager:
    """
    Manages incident deduplication using fingerprints.
    Prevents creating duplicate incidents within a cooldown period.
    """

    def __init__(self, cooldown_seconds: int = 300):
        self.cooldown_seconds = cooldown_seconds
        # {fingerprint: last_creation_timestamp}
        self._cooldowns: Dict[str, float] = {}

    @staticmethod
    def build_fingerprint(
        rule_id: str,
        account: str = "",
        ip: str = "",
        category: str = "",
        extra: str = "",
    ) -> str:
        """
        Create a fingerprint for deduplication.
        Same rule + same entity = same fingerprint.
        """
        key = f"{rule_id}:{account}:{ip}:{category}:{extra}"
        return hashlib.md5(key.encode()).hexdigest()

    def should_create(self, fingerprint: str) -> bool:
        """
        Check if a new incident should be created for this fingerprint.
        Returns False if within cooldown period.
        """
        self._cleanup()

        if fingerprint in self._cooldowns:
            elapsed = time.time() - self._cooldowns[fingerprint]
            if elapsed < self.cooldown_seconds:
                logger.debug(
                    f"Incident suppressed (cooldown): {fingerprint[:8]}... "
                    f"({int(self.cooldown_seconds - elapsed)}s remaining)"
                )
                return False

        return True

    def record_creation(self, fingerprint: str) -> None:
        """Record that an incident was created for this fingerprint."""
        self._cooldowns[fingerprint] = time.time()

    def reset(self, fingerprint: Optional[str] = None) -> None:
        """Reset cooldown for a specific fingerprint or all."""
        if fingerprint:
            self._cooldowns.pop(fingerprint, None)
        else:
            self._cooldowns.clear()

    def _cleanup(self) -> None:
        """Remove expired cooldowns."""
        now = time.time()
        expired = [
            fp for fp, ts in self._cooldowns.items()
            if now - ts > self.cooldown_seconds * 2
        ]
        for fp in expired:
            del self._cooldowns[fp]

    @property
    def active_cooldowns(self) -> int:
        """Number of active cooldown entries."""
        return len(self._cooldowns)
