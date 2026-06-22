"""
Nakul Main Application
========================

Entry point for the Nakul server intelligence agent.
Manages the monitoring loop, scheduler, and web server.
"""

import asyncio
import argparse
import logging
import os
import signal
import sys
from datetime import datetime, timedelta

import uvicorn

from nakul import __version__
from nakul.config import load_config, NakulConfig
from nakul.database import Database
from nakul.auth import AuthManager, generate_initial_password
from nakul.api.router import create_app

# Collectors
from nakul.collectors.log_collector import MultiLogCollector
from nakul.collectors.system_collector import SystemCollector
from nakul.collectors.service_collector import ServiceCollector
from nakul.collectors.cpanel_collector import CpanelCollector

# Parsers
from nakul.parsers.apache_parser import ApacheParser
from nakul.parsers.mysql_parser import MysqlParser
from nakul.parsers.security_parser import SecurityParser
from nakul.parsers.cpanel_parser import CpanelParser
from nakul.parsers.backup_parser import BackupParser
from nakul.parsers.system_parser import SystemParser
from nakul.parsers.wptoolkit_parser import WpToolkitParser

# Correlation & Incidents
from nakul.correlation.engine import CorrelationEngine
from nakul.correlation.account_mapper import AccountMapper
from nakul.incidents.engine import IncidentEngine

# Notifiers
from nakul.notifiers.base import NotificationManager

# Plugins
from nakul.plugins.base import PluginManager

logger = logging.getLogger("nakul")


class NakulAgent:
    """Main monitoring agent that orchestrates all layers."""

    def __init__(self, config: NakulConfig):
        self.config = config
        self.db: Database = None
        self.auth: AuthManager = None
        self.running = False

        # Layer 1: Collectors
        self.log_collector: MultiLogCollector = None
        self.system_collector: SystemCollector = None
        self.service_collector: ServiceCollector = None
        self.cpanel_collector: CpanelCollector = None

        # Layer 2: Parsers
        self.parsers = {}

        # Layer 3: Correlation
        self.account_mapper: AccountMapper = None
        self.correlation_engine: CorrelationEngine = None

        # Layer 4: Incidents
        self.incident_engine: IncidentEngine = None

        # Layer 5: Notifiers
        self.notification_manager: NotificationManager = None

        # Plugins
        self.plugin_manager: PluginManager = None

    async def initialize(self) -> None:
        """Initialize all components."""
        logger.info(f"Nakul v{__version__} initializing...")

        # Database
        self.db = Database(self.config.database.path)
        await self.db.initialize()

        # Auth
        self.auth = AuthManager(
            secret_key=self.config.auth.secret_key,
            algorithm=self.config.auth.algorithm,
            access_token_expire_minutes=self.config.auth.access_token_expire_minutes,
            rate_limit_attempts=self.config.auth.rate_limit_attempts,
            rate_limit_window_seconds=self.config.auth.rate_limit_window_seconds,
            ip_allowlist=self.config.server.ip_allowlist,
        )

        # Plugins — discover what's installed
        log_paths_dict = self.config.log_paths.model_dump()
        self.plugin_manager = PluginManager(
            plugin_config=self.config.plugins.model_dump(),
            log_paths=log_paths_dict,
        )
        self.plugin_manager.discover_and_load()

        # Log Collectors
        self.log_collector = MultiLogCollector(
            db=self.db,
            batch_size=self.config.collector.log_batch_size,
            max_line_length=self.config.collector.max_log_line_length,
        )
        self._setup_log_sources()

        # System collector
        self.system_collector = SystemCollector()

        # Service collector
        self.service_collector = ServiceCollector()

        # cPanel collector
        self.cpanel_collector = CpanelCollector()

        # Parsers
        self._setup_parsers()

        # Account mapper
        self.account_mapper = AccountMapper()

        # Correlation engine
        self.correlation_engine = CorrelationEngine(
            window_seconds=self.config.alerts.aggregation_window_seconds,
            account_mapper=self.account_mapper,
        )

        # Incident engine
        self.incident_engine = IncidentEngine(
            db=self.db,
            config=self.config.alerts.model_dump(),
        )

        # Notification manager
        self.notification_manager = NotificationManager(
            db=self.db,
            config=self.config.notifications.model_dump(),
        )

        logger.info("All components initialized")

    def _setup_log_sources(self) -> None:
        """Register all log sources from config and plugins."""
        lp = self.config.log_paths

        # Core log sources (always try)
        core_sources = [
            ("apache_access", lp.apache_access, "web"),
            ("apache_error", lp.apache_error, "web"),
            ("mysql_error", lp.mysql_error, "database"),
            ("mysql_slow", lp.mysql_slow, "database"),
            ("auth_log", lp.auth_log, "security"),
            ("syslog", lp.syslog, "system"),
            ("cpanel_access", lp.cpanel_access, "cpanel"),
            ("cpanel_error", lp.cpanel_error, "cpanel"),
        ]

        for name, path, source in core_sources:
            self.log_collector.add_log_source(name, path, source)

        # Plugin log sources
        for source_def in self.plugin_manager.get_all_log_sources():
            self.log_collector.add_log_source(
                source_def["name"], source_def["path"], source_def["source"]
            )

        logger.info(f"Registered {len(self.log_collector.collectors)} log sources")

    def _setup_parsers(self) -> None:
        """Initialize all parsers."""
        self.parsers = {
            "web": ApacheParser(),
            "database": MysqlParser(),
            "security": SecurityParser(log_type="auth"),
            "security_csf": SecurityParser(log_type="csf"),
            "security_imunify": SecurityParser(log_type="imunify"),
            "cpanel": CpanelParser(),
            "backup": BackupParser(),
            "system": SystemParser(),
            "wptoolkit": WpToolkitParser(),
        }
        logger.info(f"Initialized {len(self.parsers)} parsers")

    async def run_cycle(self) -> None:
        """Run a single monitoring cycle."""
        try:
            # 1. Collect system metrics
            system_data = await self.system_collector.safe_collect()
            if system_data:
                snapshot = system_data[0]
                await self.db.insert_snapshot(snapshot)

                # Generate resource alerts
                await self._check_resource_thresholds(snapshot)

            # 2. Collect service statuses
            service_statuses = await self.service_collector.safe_collect()
            for svc in service_statuses:
                await self.db.upsert_service(svc)

            # 3. Collect cPanel data
            cpanel_data = await self.cpanel_collector.safe_collect()
            if cpanel_data:
                self.account_mapper.update_from_cpanel_data(cpanel_data[0])

            # 4. Collect and parse logs
            raw_lines = await self.log_collector.collect_all()
            if raw_lines:
                events = self._parse_all(raw_lines)

                # 5. Store events
                if events:
                    event_dicts = [e for e in events]
                    await self.db.insert_events_batch(event_dicts)

                    # 6. Correlate events
                    correlations = self.correlation_engine.process_events(events)

                    # 7. Generate incidents from events
                    event_incidents = await self.incident_engine.process_events(events)

                    # 8. Generate incidents from correlations
                    corr_incidents = await self.incident_engine.process_correlations(correlations)

                    # 9. Store and notify for all incidents
                    all_incidents = event_incidents + corr_incidents
                    for incident in all_incidents:
                        # Check if dedup should increment existing
                        existing = await self.db.get_incident_by_fingerprint(
                            incident.get("fingerprint", "")
                        )
                        if existing:
                            await self.db.increment_incident_count(existing["id"])
                        else:
                            await self.db.insert_incident(incident)
                            await self.notification_manager.notify(incident)

                    if all_incidents:
                        logger.info(
                            f"Cycle complete: {len(events)} events, "
                            f"{len(correlations)} correlations, "
                            f"{len(all_incidents)} incidents"
                        )

        except Exception as e:
            logger.error(f"Monitoring cycle error: {e}", exc_info=True)

    def _parse_all(self, raw_lines: list) -> list:
        """Parse raw log lines using appropriate parsers."""
        all_events = []

        # Group lines by source
        by_source = {}
        for line in raw_lines:
            source = line.get("source", "system")
            if source not in by_source:
                by_source[source] = []
            by_source[source].append(line)

        # Parse each group with the matching parser
        for source, lines in by_source.items():
            parser = self.parsers.get(source)
            if parser:
                events = parser.parse_batch(lines)
                all_events.extend(events)
            else:
                # Try system parser as fallback
                fallback = self.parsers.get("system")
                if fallback:
                    events = fallback.parse_batch(lines)
                    all_events.extend(events)

        return all_events

    async def _check_resource_thresholds(self, snapshot: dict) -> None:
        """Check system metrics against configured thresholds."""
        alerts_config = self.config.alerts
        events = []

        # CPU
        cpu = snapshot.get("cpu_percent", 0)
        if cpu >= alerts_config.cpu_critical_percent:
            events.append(self._resource_event("critical", "resource",
                f"CPU usage critical: {cpu:.1f}% (threshold: {alerts_config.cpu_critical_percent}%)",
                {"metric": "cpu", "value": cpu}))
        elif cpu >= alerts_config.cpu_warning_percent:
            events.append(self._resource_event("warning", "resource",
                f"CPU usage high: {cpu:.1f}% (threshold: {alerts_config.cpu_warning_percent}%)",
                {"metric": "cpu", "value": cpu}))

        # Memory
        mem = snapshot.get("memory_percent", 0)
        if mem >= alerts_config.memory_critical_percent:
            events.append(self._resource_event("critical", "resource",
                f"Memory usage critical: {mem:.1f}% (threshold: {alerts_config.memory_critical_percent}%)",
                {"metric": "memory", "value": mem}))
        elif mem >= alerts_config.memory_warning_percent:
            events.append(self._resource_event("warning", "resource",
                f"Memory usage high: {mem:.1f}% (threshold: {alerts_config.memory_warning_percent}%)",
                {"metric": "memory", "value": mem}))

        # Disk
        disk = snapshot.get("disk_percent", 0)
        if disk >= alerts_config.disk_critical_percent:
            events.append(self._resource_event("critical", "resource",
                f"Disk space critical: {disk:.1f}% used (threshold: {alerts_config.disk_critical_percent}%)",
                {"metric": "disk", "value": disk}))
        elif disk >= alerts_config.disk_warning_percent:
            events.append(self._resource_event("warning", "resource",
                f"Disk space low: {disk:.1f}% used (threshold: {alerts_config.disk_warning_percent}%)",
                {"metric": "disk", "value": disk}))

        # Load
        load = snapshot.get("load_1", 0)
        cpu_count = snapshot.get("cpu_count", 1)
        if load >= alerts_config.load_critical_multiplier * cpu_count:
            events.append(self._resource_event("critical", "resource",
                f"Load average critical: {load:.2f} ({alerts_config.load_critical_multiplier}x {cpu_count} cores)",
                {"metric": "load", "value": load}))
        elif load >= alerts_config.load_warning_multiplier * cpu_count:
            events.append(self._resource_event("warning", "resource",
                f"Load average high: {load:.2f} ({alerts_config.load_warning_multiplier}x {cpu_count} cores)",
                {"metric": "load", "value": load}))

        # Process events through incident engine
        if events:
            await self.db.insert_events_batch(events)
            incidents = await self.incident_engine.process_events(events)
            for incident in incidents:
                await self.db.insert_incident(incident)
                await self.notification_manager.notify(incident)

    @staticmethod
    def _resource_event(severity: str, category: str, message: str, metadata: dict) -> dict:
        """Create a resource monitoring event."""
        import uuid
        return {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "source": "system",
            "category": category,
            "severity": severity,
            "message": message,
            "raw_line": "",
            "hostname": "",
            "metadata": metadata,
        }

    async def start_monitoring(self) -> None:
        """Start the monitoring loop."""
        self.running = True
        interval = self.config.collector.scan_interval_seconds
        logger.info(f"Starting monitoring loop (interval: {interval}s)")

        while self.running:
            await self.run_cycle()
            await asyncio.sleep(interval)

    async def stop(self) -> None:
        """Stop the agent gracefully."""
        self.running = False
        logger.info("Stopping Nakul agent...")

        # Cleanup
        await self.db.checkpoint()
        await self.db.cleanup_old_data(self.config.database.retention_days)
        await self.db.close()

        logger.info("Nakul agent stopped")


def setup_logging(level: str = "info") -> None:
    """Configure logging."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Nakul Server Intelligence Platform")
    parser.add_argument("--config", "-c", default=None, help="Path to config file")
    parser.add_argument("--port", "-p", type=int, default=None, help="Override port")
    parser.add_argument("--host", default=None, help="Override host")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--dry-run", action="store_true", help="Validate config and exit")
    parser.add_argument("--version", "-v", action="store_true", help="Show version")
    parser.add_argument("--generate-password", action="store_true", help="Generate admin password")

    args = parser.parse_args()

    if args.version:
        print(f"Nakul v{__version__}")
        sys.exit(0)

    if args.generate_password:
        password, password_hash = generate_initial_password()
        print(f"Generated admin password: {password}")
        print(f"Password hash: {password_hash}")
        print(f"\nAdd to nakul.yaml under auth.admin_password_hash")
        sys.exit(0)

    # Load config
    config = load_config(args.config)

    # Apply CLI overrides
    if args.port:
        config.server.port = args.port
    if args.host:
        config.server.host = args.host
    if args.debug:
        config.server.debug = True
        config.server.log_level = "debug"

    # Setup logging
    setup_logging(config.server.log_level)

    if args.dry_run:
        logger.info("Configuration valid:")
        logger.info(f"  Server: {config.server.host}:{config.server.port}")
        logger.info(f"  Database: {config.database.path}")
        logger.info(f"  Scan interval: {config.collector.scan_interval_seconds}s")
        logger.info(f"  Plugins: {config.plugins.model_dump()}")
        sys.exit(0)

    logger.info(f"Nakul v{__version__} starting on {config.server.host}:{config.server.port}")

    # Create agent and app
    agent = NakulAgent(config)

    async def startup():
        await agent.initialize()
        # Start monitoring in background
        asyncio.create_task(agent.start_monitoring())

    async def shutdown():
        await agent.stop()

    # Create FastAPI app
    app = create_app(
        db=agent.db,
        auth_manager=agent.auth,
        config=config,
        agent=agent,
    )

    app.add_event_handler("startup", startup)
    app.add_event_handler("shutdown", shutdown)

    # Run with uvicorn
    uvicorn.run(
        app,
        host=config.server.host,
        port=config.server.port,
        log_level=config.server.log_level,
        access_log=config.server.debug,
    )


if __name__ == "__main__":
    main()
