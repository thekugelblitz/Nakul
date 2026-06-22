"""
Nakul Database Layer
=====================

SQLite async database with schema versioning, migrations,
WAL mode for resilience, and data retention management.
"""

import os
import json
import logging
import aiosqlite
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("nakul.database")

SCHEMA_VERSION = 1

SCHEMA_SQL = """
-- Events table: normalized events from all sources
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'system',
    severity TEXT NOT NULL DEFAULT 'info',
    message TEXT NOT NULL DEFAULT '',
    raw_line TEXT DEFAULT '',
    hostname TEXT DEFAULT '',
    account TEXT,
    domain TEXT,
    ip_address TEXT,
    process TEXT,
    pid INTEGER,
    log_file TEXT,
    metadata TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
CREATE INDEX IF NOT EXISTS idx_events_account ON events(account);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip_address);

-- Incidents table: correlated, scored incidents
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'warning',
    category TEXT NOT NULL DEFAULT 'system',
    state TEXT NOT NULL DEFAULT 'new',
    rule_id TEXT DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    explanation TEXT DEFAULT '',
    affected_account TEXT,
    affected_service TEXT,
    affected_domain TEXT,
    affected_ip TEXT,
    source_evidence TEXT DEFAULT '[]',
    event_ids TEXT DEFAULT '[]',
    confidence_score REAL DEFAULT 0.0,
    suggested_remediation TEXT DEFAULT '',
    logs_consulted TEXT DEFAULT '[]',
    resolution_notes TEXT DEFAULT '',
    fingerprint TEXT DEFAULT '',
    occurrence_count INTEGER DEFAULT 1,
    metadata TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_state ON incidents(state);
CREATE INDEX IF NOT EXISTS idx_incidents_category ON incidents(category);
CREATE INDEX IF NOT EXISTS idx_incidents_fingerprint ON incidents(fingerprint);

-- Alerts table: notifications derived from incidents
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    incident_id TEXT,
    severity TEXT NOT NULL DEFAULT 'warning',
    category TEXT NOT NULL DEFAULT 'system',
    title TEXT NOT NULL DEFAULT '',
    message TEXT DEFAULT '',
    evidence TEXT DEFAULT '[]',
    affected_entity TEXT,
    recommended_action TEXT DEFAULT '',
    acknowledged INTEGER DEFAULT 0,
    acknowledged_by TEXT,
    acknowledged_at TEXT,
    suppressed INTEGER DEFAULT 0,
    notification_sent INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);

-- Services table: current service status
CREATE TABLE IF NOT EXISTS services (
    name TEXT PRIMARY KEY,
    display_name TEXT DEFAULT '',
    installed INTEGER DEFAULT 0,
    running INTEGER DEFAULT 0,
    health TEXT DEFAULT 'unknown',
    version TEXT,
    pid INTEGER,
    uptime_seconds INTEGER,
    last_check TEXT,
    last_error TEXT,
    recent_events TEXT DEFAULT '[]',
    config_path TEXT,
    log_path TEXT,
    metadata TEXT DEFAULT '{}'
);

-- System snapshots: periodic resource usage snapshots
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    cpu_percent REAL DEFAULT 0,
    cpu_count INTEGER DEFAULT 1,
    memory_total_mb REAL DEFAULT 0,
    memory_used_mb REAL DEFAULT 0,
    memory_percent REAL DEFAULT 0,
    swap_total_mb REAL DEFAULT 0,
    swap_used_mb REAL DEFAULT 0,
    swap_percent REAL DEFAULT 0,
    disk_total_gb REAL DEFAULT 0,
    disk_used_gb REAL DEFAULT 0,
    disk_percent REAL DEFAULT 0,
    disk_inodes_used_percent REAL DEFAULT 0,
    load_1 REAL DEFAULT 0,
    load_5 REAL DEFAULT 0,
    load_15 REAL DEFAULT 0,
    network_connections INTEGER DEFAULT 0,
    process_count INTEGER DEFAULT 0,
    uptime_seconds INTEGER DEFAULT 0,
    top_cpu_processes TEXT DEFAULT '[]',
    top_memory_processes TEXT DEFAULT '[]',
    db_queries_sec REAL DEFAULT 0,
    db_connections INTEGER DEFAULT 0,
    top_db_abusers TEXT DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON snapshots(timestamp);

-- Log offsets: track file read positions for incremental tailing
CREATE TABLE IF NOT EXISTS log_offsets (
    file_path TEXT PRIMARY KEY,
    offset INTEGER DEFAULT 0,
    inode INTEGER DEFAULT 0,
    last_read TEXT,
    file_size INTEGER DEFAULT 0
);

-- Audit log: operator action trail
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    user TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    target_type TEXT DEFAULT '',
    target_id TEXT,
    details TEXT DEFAULT '{}',
    ip_address TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

-- Notification log: track sent notifications for rate limiting
CREATE TABLE IF NOT EXISTS notification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    channel TEXT NOT NULL DEFAULT '',
    alert_id TEXT,
    incident_id TEXT,
    status TEXT DEFAULT 'sent',
    error TEXT
);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

-- Settings key-value store for runtime config
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
"""


class Database:
    """Async SQLite database manager with migrations and resilience."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.db: Optional[aiosqlite.Connection] = None

    async def initialize(self) -> None:
        """Initialize database connection, create schema, run migrations."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        self.db = await aiosqlite.connect(self.db_path)
        self.db.row_factory = aiosqlite.Row

        # Enable WAL mode for better concurrent access and crash resilience
        await self.db.execute("PRAGMA journal_mode=WAL")
        await self.db.execute("PRAGMA synchronous=NORMAL")
        await self.db.execute("PRAGMA cache_size=-64000")  # 64MB cache
        await self.db.execute("PRAGMA foreign_keys=ON")
        await self.db.execute("PRAGMA busy_timeout=5000")

        # Create schema
        await self.db.executescript(SCHEMA_SQL)

        # Record schema version
        await self.db.execute(
            "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
            (SCHEMA_VERSION, datetime.utcnow().isoformat())
        )

        # Ensure dynamic schema migrations (add missing columns)
        try:
            await self.db.execute("ALTER TABLE snapshots ADD COLUMN db_queries_sec REAL DEFAULT 0;")
            await self.db.execute("ALTER TABLE snapshots ADD COLUMN db_connections INTEGER DEFAULT 0;")
            await self.db.execute("ALTER TABLE snapshots ADD COLUMN top_db_abusers TEXT DEFAULT '[]';")
        except aiosqlite.OperationalError:
            pass # Columns already exist

        await self.db.commit()
        logger.info(f"Database initialized at {self.db_path}")

    async def close(self) -> None:
        """Close database connection."""
        if self.db:
            await self.db.close()
            logger.info("Database connection closed")

    # =========================================================================
    # Events
    # =========================================================================

    async def insert_event(self, event: Dict[str, Any]) -> None:
        """Insert a single event."""
        await self.db.execute(
            """INSERT OR IGNORE INTO events
            (id, timestamp, source, category, severity, message, raw_line,
             hostname, account, domain, ip_address, process, pid, log_file, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.get("id", ""),
                event.get("timestamp", datetime.utcnow().isoformat()),
                event.get("source", ""),
                event.get("category", "system"),
                event.get("severity", "info"),
                event.get("message", ""),
                event.get("raw_line", ""),
                event.get("hostname", ""),
                event.get("account"),
                event.get("domain"),
                event.get("ip_address"),
                event.get("process"),
                event.get("pid"),
                event.get("log_file"),
                json.dumps(event.get("metadata", {})),
            )
        )
        await self.db.commit()

    async def insert_events_batch(self, events: List[Dict[str, Any]]) -> int:
        """Insert multiple events in a batch. Returns count inserted."""
        if not events:
            return 0
        await self.db.executemany(
            """INSERT OR IGNORE INTO events
            (id, timestamp, source, category, severity, message, raw_line,
             hostname, account, domain, ip_address, process, pid, log_file, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    e.get("id", ""),
                    e.get("timestamp", datetime.utcnow().isoformat()),
                    e.get("source", ""),
                    e.get("category", "system"),
                    e.get("severity", "info"),
                    e.get("message", ""),
                    e.get("raw_line", ""),
                    e.get("hostname", ""),
                    e.get("account"),
                    e.get("domain"),
                    e.get("ip_address"),
                    e.get("process"),
                    e.get("pid"),
                    e.get("log_file"),
                    json.dumps(e.get("metadata", {})),
                )
                for e in events
            ]
        )
        await self.db.commit()
        return len(events)

    async def get_events(
        self,
        source: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        account: Optional[str] = None,
        ip_address: Optional[str] = None,
        domain: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Query events with filtering. Returns (events, total_count)."""
        conditions = []
        params = []

        if source:
            conditions.append("source = ?")
            params.append(source)
        if category:
            conditions.append("category = ?")
            params.append(category)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if account:
            conditions.append("account = ?")
            params.append(account)
        if ip_address:
            conditions.append("ip_address = ?")
            params.append(ip_address)
        if domain:
            conditions.append("domain = ?")
            params.append(domain)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)
        if until:
            conditions.append("timestamp <= ?")
            params.append(until)

        where = " WHERE " + " AND ".join(conditions) if conditions else ""

        # Get total count
        count_row = await self.db.execute_fetchall(
            f"SELECT COUNT(*) as cnt FROM events{where}", params
        )
        total = count_row[0][0] if count_row else 0

        # Get paginated results
        rows = await self.db.execute_fetchall(
            f"SELECT * FROM events{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        )

        events = [dict(row) for row in rows]
        for e in events:
            if e.get("metadata"):
                try:
                    e["metadata"] = json.loads(e["metadata"])
                except (json.JSONDecodeError, TypeError):
                    e["metadata"] = {}

        return events, total

    async def get_events_since(self, since: str, source: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get events since a timestamp, optionally filtered by source."""
        if source:
            rows = await self.db.execute_fetchall(
                "SELECT * FROM events WHERE timestamp >= ? AND source = ? ORDER BY timestamp DESC",
                (since, source)
            )
        else:
            rows = await self.db.execute_fetchall(
                "SELECT * FROM events WHERE timestamp >= ? ORDER BY timestamp DESC",
                (since,)
            )
        return [dict(row) for row in rows]

    # =========================================================================
    # Incidents
    # =========================================================================

    async def insert_incident(self, incident: Dict[str, Any]) -> None:
        """Insert or update an incident."""
        await self.db.execute(
            """INSERT OR REPLACE INTO incidents
            (id, timestamp, updated_at, severity, category, state, rule_id,
             summary, explanation, affected_account, affected_service,
             affected_domain, affected_ip, source_evidence, event_ids,
             confidence_score, suggested_remediation, logs_consulted,
             resolution_notes, fingerprint, occurrence_count, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                incident.get("id", ""),
                incident.get("timestamp", datetime.utcnow().isoformat()),
                incident.get("updated_at", datetime.utcnow().isoformat()),
                incident.get("severity", "warning"),
                incident.get("category", "system"),
                incident.get("state", "new"),
                incident.get("rule_id", ""),
                incident.get("summary", ""),
                incident.get("explanation", ""),
                incident.get("affected_account"),
                incident.get("affected_service"),
                incident.get("affected_domain"),
                incident.get("affected_ip"),
                json.dumps(incident.get("source_evidence", [])),
                json.dumps(incident.get("event_ids", [])),
                incident.get("confidence_score", 0.0),
                incident.get("suggested_remediation", ""),
                json.dumps(incident.get("logs_consulted", [])),
                incident.get("resolution_notes", ""),
                incident.get("fingerprint", ""),
                incident.get("occurrence_count", 1),
                json.dumps(incident.get("metadata", {})),
            )
        )
        await self.db.commit()

    async def get_incidents(
        self,
        state: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Query incidents with filtering."""
        conditions = []
        params = []

        if state:
            conditions.append("state = ?")
            params.append(state)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if category:
            conditions.append("category = ?")
            params.append(category)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)

        where = " WHERE " + " AND ".join(conditions) if conditions else ""

        count_row = await self.db.execute_fetchall(
            f"SELECT COUNT(*) FROM incidents{where}", params
        )
        total = count_row[0][0] if count_row else 0

        rows = await self.db.execute_fetchall(
            f"SELECT * FROM incidents{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        )

        incidents = []
        for row in rows:
            inc = dict(row)
            for field in ("source_evidence", "event_ids", "logs_consulted"):
                if inc.get(field):
                    try:
                        inc[field] = json.loads(inc[field])
                    except (json.JSONDecodeError, TypeError):
                        inc[field] = []
            if inc.get("metadata"):
                try:
                    inc["metadata"] = json.loads(inc["metadata"])
                except (json.JSONDecodeError, TypeError):
                    inc["metadata"] = {}
            incidents.append(inc)

        return incidents, total

    async def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get a single incident by ID."""
        rows = await self.db.execute_fetchall(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        )
        if not rows:
            return None
        inc = dict(rows[0])
        for field in ("source_evidence", "event_ids", "logs_consulted"):
            if inc.get(field):
                try:
                    inc[field] = json.loads(inc[field])
                except (json.JSONDecodeError, TypeError):
                    inc[field] = []
        if inc.get("metadata"):
            try:
                inc["metadata"] = json.loads(inc["metadata"])
            except (json.JSONDecodeError, TypeError):
                inc["metadata"] = {}
        return inc

    async def update_incident_state(
        self, incident_id: str, state: str, notes: str = "", user: str = ""
    ) -> bool:
        """Update incident state (acknowledge, resolve, suppress, etc.)."""
        cursor = await self.db.execute(
            """UPDATE incidents SET state = ?, resolution_notes = ?,
               updated_at = ? WHERE id = ?""",
            (state, notes, datetime.utcnow().isoformat(), incident_id)
        )
        await self.db.commit()
        return cursor.rowcount > 0

    async def get_incident_by_fingerprint(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        """Find an active incident by fingerprint for deduplication."""
        rows = await self.db.execute_fetchall(
            """SELECT * FROM incidents WHERE fingerprint = ?
               AND state IN ('new', 'acknowledged', 'investigating')
               ORDER BY timestamp DESC LIMIT 1""",
            (fingerprint,)
        )
        if not rows:
            return None
        return dict(rows[0])

    async def increment_incident_count(self, incident_id: str) -> None:
        """Increment occurrence count for a deduplicated incident."""
        await self.db.execute(
            """UPDATE incidents SET occurrence_count = occurrence_count + 1,
               updated_at = ? WHERE id = ?""",
            (datetime.utcnow().isoformat(), incident_id)
        )
        await self.db.commit()

    # =========================================================================
    # Alerts
    # =========================================================================

    async def insert_alert(self, alert: Dict[str, Any]) -> None:
        """Insert an alert."""
        await self.db.execute(
            """INSERT OR IGNORE INTO alerts
            (id, timestamp, incident_id, severity, category, title, message,
             evidence, affected_entity, recommended_action, acknowledged,
             acknowledged_by, acknowledged_at, suppressed, notification_sent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.get("id", ""),
                alert.get("timestamp", datetime.utcnow().isoformat()),
                alert.get("incident_id"),
                alert.get("severity", "warning"),
                alert.get("category", "system"),
                alert.get("title", ""),
                alert.get("message", ""),
                json.dumps(alert.get("evidence", [])),
                alert.get("affected_entity"),
                alert.get("recommended_action", ""),
                1 if alert.get("acknowledged") else 0,
                alert.get("acknowledged_by"),
                alert.get("acknowledged_at"),
                1 if alert.get("suppressed") else 0,
                1 if alert.get("notification_sent") else 0,
            )
        )
        await self.db.commit()

    async def get_alerts(
        self,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Query alerts with filtering."""
        conditions = []
        params = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if acknowledged is not None:
            conditions.append("acknowledged = ?")
            params.append(1 if acknowledged else 0)

        conditions.append("suppressed = 0")
        where = " WHERE " + " AND ".join(conditions)

        count_row = await self.db.execute_fetchall(
            f"SELECT COUNT(*) FROM alerts{where}", params
        )
        total = count_row[0][0] if count_row else 0

        rows = await self.db.execute_fetchall(
            f"SELECT * FROM alerts{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        )

        alerts = []
        for row in rows:
            a = dict(row)
            if a.get("evidence"):
                try:
                    a["evidence"] = json.loads(a["evidence"])
                except (json.JSONDecodeError, TypeError):
                    a["evidence"] = []
            a["acknowledged"] = bool(a.get("acknowledged"))
            a["suppressed"] = bool(a.get("suppressed"))
            a["notification_sent"] = bool(a.get("notification_sent"))
            alerts.append(a)

        return alerts, total

    async def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """Acknowledge an alert."""
        cursor = await self.db.execute(
            """UPDATE alerts SET acknowledged = 1, acknowledged_by = ?,
               acknowledged_at = ? WHERE id = ?""",
            (user, datetime.utcnow().isoformat(), alert_id)
        )
        await self.db.commit()
        return cursor.rowcount > 0

    # =========================================================================
    # Services
    # =========================================================================

    async def upsert_service(self, service: Dict[str, Any]) -> None:
        """Insert or update a service status."""
        await self.db.execute(
            """INSERT OR REPLACE INTO services
            (name, display_name, installed, running, health, version,
             pid, uptime_seconds, last_check, last_error, recent_events,
             config_path, log_path, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                service.get("name", ""),
                service.get("display_name", ""),
                1 if service.get("installed") else 0,
                1 if service.get("running") else 0,
                service.get("health", "unknown"),
                service.get("version"),
                service.get("pid"),
                service.get("uptime_seconds"),
                service.get("last_check", datetime.utcnow().isoformat()),
                service.get("last_error"),
                json.dumps(service.get("recent_events", [])),
                service.get("config_path"),
                service.get("log_path"),
                json.dumps(service.get("metadata", {})),
            )
        )
        await self.db.commit()

    async def get_services(self) -> List[Dict[str, Any]]:
        """Get all service statuses."""
        rows = await self.db.execute_fetchall("SELECT * FROM services ORDER BY name")
        services = []
        for row in rows:
            s = dict(row)
            s["installed"] = bool(s.get("installed"))
            s["running"] = bool(s.get("running"))
            if s.get("recent_events"):
                try:
                    s["recent_events"] = json.loads(s["recent_events"])
                except (json.JSONDecodeError, TypeError):
                    s["recent_events"] = []
            if s.get("metadata"):
                try:
                    s["metadata"] = json.loads(s["metadata"])
                except (json.JSONDecodeError, TypeError):
                    s["metadata"] = {}
            services.append(s)
        return services

    # =========================================================================
    # Snapshots
    # =========================================================================

    async def insert_snapshot(self, snapshot: Dict[str, Any]) -> None:
        """Insert a system snapshot."""
        await self.db.execute(
            """INSERT INTO snapshots
            (timestamp, cpu_percent, cpu_count, memory_total_mb, memory_used_mb,
             memory_percent, swap_total_mb, swap_used_mb, swap_percent,
             disk_total_gb, disk_used_gb, disk_percent, disk_inodes_used_percent,
             load_1, load_5, load_15, network_connections, process_count,
             uptime_seconds, top_cpu_processes, top_memory_processes,
             db_queries_sec, db_connections, top_db_abusers)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                snapshot.get("timestamp", datetime.utcnow().isoformat()),
                snapshot.get("cpu_percent", 0),
                snapshot.get("cpu_count", 1),
                snapshot.get("memory_total_mb", 0),
                snapshot.get("memory_used_mb", 0),
                snapshot.get("memory_percent", 0),
                snapshot.get("swap_total_mb", 0),
                snapshot.get("swap_used_mb", 0),
                snapshot.get("swap_percent", 0),
                snapshot.get("disk_total_gb", 0),
                snapshot.get("disk_used_gb", 0),
                snapshot.get("disk_percent", 0),
                snapshot.get("disk_inodes_used_percent", 0),
                snapshot.get("load_1", 0),
                snapshot.get("load_5", 0),
                snapshot.get("load_15", 0),
                snapshot.get("network_connections", 0),
                snapshot.get("process_count", 0),
                snapshot.get("uptime_seconds", 0),
                json.dumps(snapshot.get("top_cpu_processes", [])),
                json.dumps(snapshot.get("top_memory_processes", [])),
                snapshot.get("db_queries_sec", 0),
                snapshot.get("db_connections", 0),
                json.dumps(snapshot.get("top_db_abusers", [])),
            )
        )
        await self.db.commit()

    async def get_snapshots(self, since: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get system snapshots, optionally since a timestamp."""
        if since:
            rows = await self.db.execute_fetchall(
                "SELECT * FROM snapshots WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?",
                (since, limit)
            )
        else:
            rows = await self.db.execute_fetchall(
                "SELECT * FROM snapshots ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )

        snapshots = []
        for row in rows:
            s = dict(row)
            for field in ("top_cpu_processes", "top_memory_processes"):
                if s.get(field):
                    try:
                        s[field] = json.loads(s[field])
                    except (json.JSONDecodeError, TypeError):
                        s[field] = []
            snapshots.append(s)
        return snapshots

    async def get_latest_snapshot(self) -> Optional[Dict[str, Any]]:
        """Get the most recent system snapshot."""
        rows = await self.db.execute_fetchall(
            "SELECT * FROM snapshots ORDER BY timestamp DESC LIMIT 1"
        )
        if not rows:
            return None
        s = dict(rows[0])
        for field in ("top_cpu_processes", "top_memory_processes"):
            if s.get(field):
                try:
                    s[field] = json.loads(s[field])
                except (json.JSONDecodeError, TypeError):
                    s[field] = []
        return s

    async def get_downsampled_snapshots(self, hours: int) -> List[Dict[str, Any]]:
        """Get downsampled snapshots over a given time range."""
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        
        # Decide grouping interval based on hours
        if hours <= 1:
            grouping = "%Y-%m-%d %H:%M:%S" # No grouping essentially, but we can do per minute if too many
            grouping = "%Y-%m-%d %H:%M" # 1 min grouping
        elif hours <= 24:
            # 5-minute grouping (trick: minute / 5)
            # SQLite strftime doesn't have math natively in string formatting easily, 
            # so we just use 5 min boundaries by substringing or math
            grouping = "strftime('%Y-%m-%d %H:', timestamp) || printf('%02d', (CAST(strftime('%M', timestamp) AS INTEGER) / 5) * 5)"
        elif hours <= 168:
            # 1-hour grouping
            grouping = "strftime('%Y-%m-%d %H:00:00', timestamp)"
        else:
            # 6-hour grouping
            grouping = "strftime('%Y-%m-%d ', timestamp) || printf('%02d:00:00', (CAST(strftime('%H', timestamp) AS INTEGER) / 6) * 6)"

        # Use grouping variable directly if it's a function call, otherwise strftime
        if grouping.startswith("strftime") or grouping.startswith("CAST"):
            group_sql = grouping
        else:
            group_sql = f"strftime('{grouping}', timestamp)"

        query = f"""
            SELECT 
                {group_sql} as timestamp,
                AVG(cpu_percent) as cpu_percent,
                AVG(memory_percent) as memory_percent,
                AVG(disk_percent) as disk_percent,
                AVG(load_1) as load_1,
                AVG(db_connections) as db_connections
            FROM snapshots
            WHERE timestamp >= ?
            GROUP BY {group_sql}
            ORDER BY timestamp ASC
        """
        rows = await self.db.execute_fetchall(query, (since,))
        return [dict(row) for row in rows]

    async def cleanup_old_data(self) -> None:
        """Prune old data to prevent database from hogging disk space."""
        try:
            # Keep snapshots for 30 days
            await self.db.execute("DELETE FROM snapshots WHERE timestamp < ?", 
                                 ((datetime.utcnow() - timedelta(days=30)).isoformat(),))
            
            # Keep raw events for 7 days
            await self.db.execute("DELETE FROM events WHERE timestamp < ?", 
                                 ((datetime.utcnow() - timedelta(days=7)).isoformat(),))
            
            # Keep incidents for 30 days
            await self.db.execute("DELETE FROM incidents WHERE timestamp < ?", 
                                 ((datetime.utcnow() - timedelta(days=30)).isoformat(),))
            
            # Keep audit logs for 90 days
            await self.db.execute("DELETE FROM audit_log WHERE timestamp < ?", 
                                 ((datetime.utcnow() - timedelta(days=90)).isoformat(),))
                                 
            await self.db.commit()
            
            # Vacuum occasionally (e.g. 1 in 20 chance)
            import random
            if random.random() < 0.05:
                await self.db.execute("VACUUM")
                
        except Exception as e:
            logger.error(f"Error during data cleanup: {e}")

    # =========================================================================
    # Log Offsets
    # =========================================================================

    async def get_log_offset(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Get the last read offset for a log file."""
        rows = await self.db.execute_fetchall(
            "SELECT * FROM log_offsets WHERE file_path = ?", (file_path,)
        )
        if not rows:
            return None
        return dict(rows[0])

    async def update_log_offset(
        self, file_path: str, offset: int, inode: int, file_size: int
    ) -> None:
        """Update log file read offset."""
        await self.db.execute(
            """INSERT OR REPLACE INTO log_offsets
            (file_path, offset, inode, last_read, file_size)
            VALUES (?, ?, ?, ?, ?)""",
            (file_path, offset, inode, datetime.utcnow().isoformat(), file_size)
        )
        await self.db.commit()

    # =========================================================================
    # Audit Log
    # =========================================================================

    async def insert_audit(self, audit: Dict[str, Any]) -> None:
        """Insert an audit log entry."""
        await self.db.execute(
            """INSERT INTO audit_log
            (id, timestamp, user, action, target_type, target_id, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                audit.get("id", ""),
                audit.get("timestamp", datetime.utcnow().isoformat()),
                audit.get("user", ""),
                audit.get("action", ""),
                audit.get("target_type", ""),
                audit.get("target_id"),
                json.dumps(audit.get("details", {})),
                audit.get("ip_address"),
            )
        )
        await self.db.commit()

    async def get_audit_log(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get audit log entries."""
        rows = await self.db.execute_fetchall(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
        entries = []
        for row in rows:
            a = dict(row)
            if a.get("details"):
                try:
                    a["details"] = json.loads(a["details"])
                except (json.JSONDecodeError, TypeError):
                    a["details"] = {}
            entries.append(a)
        return entries

    # =========================================================================
    # Settings
    # =========================================================================

    async def get_setting(self, key: str) -> Optional[str]:
        """Get a setting value."""
        rows = await self.db.execute_fetchall(
            "SELECT value FROM settings WHERE key = ?", (key,)
        )
        if not rows:
            return None
        return rows[0][0]

    async def set_setting(self, key: str, value: str) -> None:
        """Set a setting value."""
        await self.db.execute(
            """INSERT OR REPLACE INTO settings (key, value, updated_at)
            VALUES (?, ?, ?)""",
            (key, value, datetime.utcnow().isoformat())
        )
        await self.db.commit()

    # =========================================================================
    # Statistics
    # =========================================================================

    async def get_stats(self) -> Dict[str, Any]:
        """Get database statistics for the dashboard."""
        stats = {}

        # Count by severity
        for table, key_prefix in [("events", "events"), ("incidents", "incidents"), ("alerts", "alerts")]:
            for sev in ("info", "warning", "critical"):
                rows = await self.db.execute_fetchall(
                    f"SELECT COUNT(*) FROM {table} WHERE severity = ?", (sev,)
                )
                stats[f"{key_prefix}_{sev}"] = rows[0][0] if rows else 0

        # Active incidents
        rows = await self.db.execute_fetchall(
            "SELECT COUNT(*) FROM incidents WHERE state IN ('new', 'acknowledged', 'investigating')"
        )
        stats["active_incidents"] = rows[0][0] if rows else 0

        # Unacknowledged alerts
        rows = await self.db.execute_fetchall(
            "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0 AND suppressed = 0"
        )
        stats["unack_alerts"] = rows[0][0] if rows else 0

        # Events last hour
        one_hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        rows = await self.db.execute_fetchall(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (one_hour_ago,)
        )
        stats["events_last_hour"] = rows[0][0] if rows else 0

        return stats

    # =========================================================================
    # Maintenance
    # =========================================================================

    async def cleanup_old_data(self, retention_days: int = 30) -> Dict[str, int]:
        """Remove data older than retention period."""
        cutoff = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()
        deleted = {}

        for table in ("events", "snapshots", "notification_log"):
            cursor = await self.db.execute(
                f"DELETE FROM {table} WHERE timestamp < ?", (cutoff,)
            )
            deleted[table] = cursor.rowcount

        # Keep resolved/suppressed incidents longer but still clean up
        cursor = await self.db.execute(
            """DELETE FROM incidents WHERE timestamp < ?
               AND state IN ('resolved', 'suppressed', 'false_positive')""",
            (cutoff,)
        )
        deleted["incidents"] = cursor.rowcount

        await self.db.commit()
        logger.info(f"Data cleanup complete: {deleted}")
        return deleted

    async def checkpoint(self) -> None:
        """Force a WAL checkpoint."""
        await self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        logger.debug("WAL checkpoint completed")
