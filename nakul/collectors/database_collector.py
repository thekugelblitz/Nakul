"""
Database Collector
===================

Collects MySQL/MariaDB performance metrics and identifies abusers.
Leverages root socket access (cPanel standard) to avoid requiring passwords.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List

from nakul.collectors.base import BaseCollector

logger = logging.getLogger("nakul.collectors.database")


class DatabaseCollector(BaseCollector):
    """Monitors MySQL/MariaDB for performance and abusers."""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("database", config)
        self._mysql_cmd = "mysql -N -B -e"

    def is_available(self) -> bool:
        """Check if mysql command is available."""
        import shutil
        return shutil.which("mysql") is not None

    async def _run_mysql_query(self, query: str) -> str:
        """Run a query via mysql CLI and return stdout."""
        try:
            proc = await asyncio.create_subprocess_shell(
                f"{self._mysql_cmd} \"{query}\"",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                self.logger.debug(f"MySQL query failed: {stderr.decode()}")
                return ""
            return stdout.decode().strip()
        except Exception as e:
            self.logger.error(f"Error running MySQL query: {e}")
            return ""

    async def collect(self) -> List[Dict[str, Any]]:
        """Collect database metrics."""
        db_metrics = {
            "db_queries_sec": 0.0,
            "db_connections": 0,
            "top_db_abusers": []
        }

        # 1. Fetch Global Status
        status_query = "SHOW GLOBAL STATUS WHERE Variable_name IN ('Questions', 'Threads_connected');"
        status_out = await self._run_mysql_query(status_query)
        
        status_dict = {}
        for line in status_out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                status_dict[parts[0]] = parts[1]

        # Calculate queries/sec
        # Note: 'Questions' is total questions since uptime. To get QPS precisely, 
        # we'd need delta between runs, but for simplicity we can just track Connections for now 
        # or calculate QPS if we store previous.
        db_metrics["db_connections"] = int(status_dict.get("Threads_connected", 0))

        # 2. Find Abusers (Long-running queries)
        # Exclude 'Sleep' and system users
        processlist_query = """
        SELECT User, db, Time, State, Info 
        FROM information_schema.processlist 
        WHERE Command != 'Sleep' AND User NOT IN ('system user', 'root', 'event_scheduler') 
        ORDER BY Time DESC LIMIT 10;
        """
        processlist_out = await self._run_mysql_query(processlist_query)
        
        abusers = []
        for line in processlist_out.splitlines():
            parts = line.split('\t')
            if len(parts) >= 5:
                user = parts[0]
                db = parts[1] if parts[1] != 'NULL' else ''
                time_sec = int(parts[2]) if parts[2].isdigit() else 0
                state = parts[3] if parts[3] != 'NULL' else ''
                info = parts[4][:100] if parts[4] != 'NULL' else ''
                
                abusers.append({
                    "user": user,
                    "db": db,
                    "time": time_sec,
                    "state": state,
                    "query": info
                })

        db_metrics["top_db_abusers"] = abusers

        return [db_metrics]
