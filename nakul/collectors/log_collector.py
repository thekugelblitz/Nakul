"""
Log Collector
==============

Incremental log file tailing with offset persistence.
Handles log rotation, missing files, permission errors,
and very large files efficiently.
"""

import os
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from nakul.collectors.base import BaseCollector

logger = logging.getLogger("nakul.collectors.log")


class LogCollector(BaseCollector):
    """
    Reads new lines from log files since last read position.
    Tracks file offsets and inodes to handle rotation.
    """

    def __init__(
        self,
        name: str,
        file_path: str,
        source_name: str,
        db=None,
        batch_size: int = 1000,
        max_line_length: int = 4096,
        config: Dict[str, Any] = None,
    ):
        super().__init__(name, config)
        self.file_path = file_path
        self.source_name = source_name
        self.db = db
        self.batch_size = batch_size
        self.max_line_length = max_line_length

        # In-memory offset tracking (persisted to DB)
        self._offset: int = 0
        self._inode: int = 0
        self._initialized: bool = False

    def is_available(self) -> bool:
        """Check if the log file exists and is readable."""
        if not os.path.exists(self.file_path):
            return False
        try:
            return os.access(self.file_path, os.R_OK)
        except OSError:
            return False

    async def _load_offset(self) -> None:
        """Load the last read offset from database."""
        if self._initialized or self.db is None:
            return

        try:
            offset_data = await self.db.get_log_offset(self.file_path)
            if offset_data:
                self._offset = offset_data.get("offset", 0)
                self._inode = offset_data.get("inode", 0)
            self._initialized = True
        except Exception as e:
            self.logger.warning(f"Failed to load offset for {self.file_path}: {e}")
            self._initialized = True

    async def _save_offset(self, offset: int, inode: int, file_size: int) -> None:
        """Persist current offset to database."""
        if self.db is None:
            return
        try:
            await self.db.update_log_offset(self.file_path, offset, inode, file_size)
        except Exception as e:
            self.logger.warning(f"Failed to save offset for {self.file_path}: {e}")

    def _detect_rotation(self, current_inode: int, current_size: int) -> bool:
        """
        Detect if the log file has been rotated.
        Rotation is detected by inode change or file size shrinking.
        """
        if self._inode != 0 and self._inode != current_inode:
            self.logger.info(f"Log rotation detected (inode change): {self.file_path}")
            return True
        if current_size < self._offset:
            self.logger.info(f"Log rotation detected (file shrink): {self.file_path}")
            return True
        return False

    async def collect(self) -> List[Dict[str, Any]]:
        """
        Read new lines from the log file since last offset.
        Returns list of raw line dicts with metadata.
        """
        if not os.path.exists(self.file_path):
            return []

        await self._load_offset()

        try:
            stat = os.stat(self.file_path)
            current_inode = stat.st_ino
            current_size = stat.st_size
        except OSError as e:
            self.logger.error(f"Cannot stat {self.file_path}: {e}")
            return []

        # Detect rotation and reset offset
        if self._detect_rotation(current_inode, current_size):
            self._offset = 0
            self._inode = current_inode

        # Nothing new to read
        if current_size <= self._offset:
            return []

        lines = []
        new_offset = self._offset

        try:
            with open(self.file_path, "r", errors="replace") as f:
                f.seek(self._offset)
                
                lines_read = 0
                while lines_read < self.batch_size:
                    line = f.readline()
                    if not line:
                        break  # EOF

                    line = line.rstrip("\n\r")
                    if not line:
                        continue

                    # Truncate extremely long lines
                    if len(line) > self.max_line_length:
                        line = line[:self.max_line_length] + "...[truncated]"

                    lines.append({
                        "raw_line": line,
                        "source": self.source_name,
                        "file_path": self.file_path,
                        "timestamp": datetime.utcnow().isoformat(),
                    })
                    lines_read += 1

                new_offset = f.tell()

        except PermissionError:
            self.logger.error(f"Permission denied reading {self.file_path}")
            self.last_error = f"Permission denied: {self.file_path}"
            return []
        except IOError as e:
            self.logger.error(f"IO error reading {self.file_path}: {e}")
            self.last_error = str(e)
            return []

        # Save new offset
        self._offset = new_offset
        self._inode = current_inode
        await self._save_offset(new_offset, current_inode, current_size)

        if lines:
            self.logger.debug(
                f"Read {len(lines)} lines from {self.file_path} "
                f"(offset {self._offset - (new_offset - self._offset)} → {new_offset})"
            )

        return lines

    def reset_offset(self) -> None:
        """Reset offset to re-read the entire file."""
        self._offset = 0
        self._inode = 0
        self._initialized = False
        self.logger.info(f"Offset reset for {self.file_path}")


class MultiLogCollector:
    """
    Manages multiple LogCollector instances for different log sources.
    Provides a unified collection interface.
    """

    def __init__(self, db=None, batch_size: int = 1000, max_line_length: int = 4096):
        self.db = db
        self.batch_size = batch_size
        self.max_line_length = max_line_length
        self.collectors: Dict[str, LogCollector] = {}
        self.logger = logging.getLogger("nakul.collectors.multi_log")

    def add_log_source(self, name: str, file_path: str, source_name: str) -> None:
        """Register a log file for monitoring."""
        collector = LogCollector(
            name=name,
            file_path=file_path,
            source_name=source_name,
            db=self.db,
            batch_size=self.batch_size,
            max_line_length=self.max_line_length,
        )
        self.collectors[name] = collector
        self.logger.debug(f"Added log source: {name} → {file_path}")

    async def collect_all(self) -> List[Dict[str, Any]]:
        """Collect new lines from all registered log sources."""
        all_lines = []
        for name, collector in self.collectors.items():
            try:
                lines = await collector.safe_collect()
                all_lines.extend(lines)
            except Exception as e:
                self.logger.error(f"Error collecting from {name}: {e}")
        return all_lines

    def get_status(self) -> Dict[str, Any]:
        """Get status of all log collectors."""
        return {
            name: collector.get_status()
            for name, collector in self.collectors.items()
        }
