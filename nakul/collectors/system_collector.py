"""
System Metrics Collector
=========================

Collects CPU, memory, disk, network, load, and process data
using psutil. Works on any Linux system.
"""

import os
import time
import logging
from datetime import datetime
from typing import Any, Dict, List

from nakul.collectors.base import BaseCollector

logger = logging.getLogger("nakul.collectors.system")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not available — system metrics collection disabled")


class SystemCollector(BaseCollector):
    """Collects system resource metrics using psutil."""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("system", config)

    def is_available(self) -> bool:
        """psutil must be available."""
        return PSUTIL_AVAILABLE

    async def collect(self) -> List[Dict[str, Any]]:
        """Collect a full system snapshot."""
        if not PSUTIL_AVAILABLE:
            return []

        snapshot = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "system_snapshot",
        }

        try:
            # CPU
            snapshot["cpu_percent"] = psutil.cpu_percent(interval=1)
            snapshot["cpu_count"] = psutil.cpu_count() or 1

            # Memory
            mem = psutil.virtual_memory()
            snapshot["memory_total_mb"] = round(mem.total / (1024 * 1024), 1)
            snapshot["memory_used_mb"] = round(mem.used / (1024 * 1024), 1)
            snapshot["memory_percent"] = mem.percent

            # Swap
            swap = psutil.swap_memory()
            snapshot["swap_total_mb"] = round(swap.total / (1024 * 1024), 1)
            snapshot["swap_used_mb"] = round(swap.used / (1024 * 1024), 1)
            snapshot["swap_percent"] = swap.percent

            # Disk (root partition)
            try:
                disk = psutil.disk_usage("/")
                snapshot["disk_total_gb"] = round(disk.total / (1024 ** 3), 2)
                snapshot["disk_used_gb"] = round(disk.used / (1024 ** 3), 2)
                snapshot["disk_percent"] = disk.percent
            except OSError:
                snapshot["disk_total_gb"] = 0
                snapshot["disk_used_gb"] = 0
                snapshot["disk_percent"] = 0

            # Inode usage (Linux specific)
            snapshot["disk_inodes_used_percent"] = self._get_inode_usage()

            # Load average
            try:
                load = os.getloadavg()
                snapshot["load_1"] = round(load[0], 2)
                snapshot["load_5"] = round(load[1], 2)
                snapshot["load_15"] = round(load[2], 2)
            except (OSError, AttributeError):
                # os.getloadavg() not available on Windows
                snapshot["load_1"] = 0
                snapshot["load_5"] = 0
                snapshot["load_15"] = 0

            # Network connections
            try:
                snapshot["network_connections"] = len(psutil.net_connections())
            except (psutil.AccessDenied, OSError):
                snapshot["network_connections"] = 0

            # Process count
            snapshot["process_count"] = len(psutil.pids())

            # Uptime
            snapshot["uptime_seconds"] = int(time.time() - psutil.boot_time())

            # Top processes by CPU
            snapshot["top_cpu_processes"] = self._get_top_processes("cpu")
            snapshot["top_memory_processes"] = self._get_top_processes("memory")

        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}", exc_info=True)

        return [snapshot]

    @staticmethod
    def _get_inode_usage() -> float:
        """Get inode usage percentage for the root filesystem."""
        try:
            stat = os.statvfs("/")
            if stat.f_files > 0:
                used = stat.f_files - stat.f_ffree
                return round((used / stat.f_files) * 100, 1)
        except (OSError, AttributeError):
            pass
        return 0.0

    @staticmethod
    def _get_top_processes(sort_by: str = "cpu", limit: int = 10) -> List[Dict[str, Any]]:
        """Get top processes by CPU or memory usage."""
        processes = []
        try:
            for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "cmdline"]):
                try:
                    info = proc.info
                    processes.append({
                        "pid": info["pid"],
                        "name": info["name"] or "unknown",
                        "user": info.get("username", "unknown"),
                        "cpu_percent": info.get("cpu_percent", 0) or 0,
                        "memory_percent": round(info.get("memory_percent", 0) or 0, 1),
                        "cmdline": " ".join(info.get("cmdline") or [])[:200],
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            key = "cpu_percent" if sort_by == "cpu" else "memory_percent"
            processes.sort(key=lambda p: p[key], reverse=True)
            return processes[:limit]

        except Exception:
            return []
