"""
Correlation Engine
===================

Groups events by account, IP, domain within configurable time windows.
Links events across sources to identify patterns and compound incidents.
"""

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("nakul.correlation")


class CorrelationEngine:
    """
    Correlates events across multiple sources to identify
    patterns, compound incidents, and related activity.
    """

    def __init__(self, window_seconds: int = 300, account_mapper=None):
        self.window_seconds = window_seconds
        self.account_mapper = account_mapper

        # Sliding window buffers keyed by entity
        self._ip_events: Dict[str, List[Dict]] = defaultdict(list)
        self._account_events: Dict[str, List[Dict]] = defaultdict(list)
        self._domain_events: Dict[str, List[Dict]] = defaultdict(list)
        self._category_events: Dict[str, List[Dict]] = defaultdict(list)

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process a batch of events, correlate them, and return
        correlated event groups that may warrant incidents.
        """
        self._cleanup_windows()

        for event in events:
            self._index_event(event)

        # Find correlations
        correlated_groups = []

        # Check for IP-based patterns (DDoS, brute force)
        for ip, ip_events in self._ip_events.items():
            if len(ip_events) >= 5:
                group = self._analyze_ip_group(ip, ip_events)
                if group:
                    correlated_groups.append(group)

        # Check for account-based patterns (resource abuse)
        for account, acc_events in self._account_events.items():
            if len(acc_events) >= 3:
                group = self._analyze_account_group(account, acc_events)
                if group:
                    correlated_groups.append(group)

        # Check for category spikes
        for category, cat_events in self._category_events.items():
            if len(cat_events) >= 10:
                group = self._analyze_category_spike(category, cat_events)
                if group:
                    correlated_groups.append(group)

        return correlated_groups

    def _index_event(self, event: Dict[str, Any]) -> None:
        """Index an event into correlation buffers."""
        # Enrich with account mapping
        if self.account_mapper:
            self._enrich_event(event)

        ip = event.get("ip_address", "")
        account = event.get("account", "")
        domain = event.get("domain", "")
        category = event.get("category", "")

        if ip:
            self._ip_events[ip].append(event)
        if account:
            self._account_events[account].append(event)
        if domain:
            self._domain_events[domain].append(event)
        if category:
            self._category_events[category].append(event)

    def _enrich_event(self, event: Dict[str, Any]) -> None:
        """Enrich event with account mapping data."""
        if not self.account_mapper:
            return

        # Try to resolve account from domain
        if not event.get("account") and event.get("domain"):
            account = self.account_mapper.get_account_for_domain(event["domain"])
            if account:
                event["account"] = account

        # Try to resolve account from MySQL user
        metadata = event.get("metadata", {})
        if not event.get("account") and metadata.get("mysql_user"):
            account = self.account_mapper.get_account_for_mysql_user(metadata["mysql_user"])
            if account:
                event["account"] = account

    def _analyze_ip_group(self, ip: str, events: List[Dict]) -> Optional[Dict[str, Any]]:
        """Analyze events from a single IP for patterns."""
        window_events = self._get_window_events(events)
        if len(window_events) < 5:
            return None

        # Count by category
        categories = defaultdict(int)
        severities = defaultdict(int)
        for e in window_events:
            categories[e.get("category", "")] += 1
            severities[e.get("severity", "")] += 1

        # Detect patterns
        pattern = None
        confidence = 0.0

        # Brute force: many auth failures
        auth_count = categories.get("auth", 0)
        if auth_count >= 5:
            pattern = "brute_force"
            confidence = min(1.0, auth_count / 10.0)

        # Connection flood: many web events
        web_count = categories.get("web", 0)
        if web_count >= 20:
            pattern = "connection_flood"
            confidence = min(1.0, web_count / 50.0)

        # Security events spike
        security_count = categories.get("security", 0)
        if security_count >= 5:
            pattern = "security_spike"
            confidence = min(1.0, security_count / 10.0)

        if not pattern:
            return None

        return {
            "type": "ip_correlation",
            "pattern": pattern,
            "ip": ip,
            "event_count": len(window_events),
            "confidence": confidence,
            "categories": dict(categories),
            "severities": dict(severities),
            "events": window_events[:20],  # Keep first 20 for evidence
            "evidence": [e.get("raw_line", "")[:200] for e in window_events[:5]],
        }

    def _analyze_account_group(self, account: str, events: List[Dict]) -> Optional[Dict[str, Any]]:
        """Analyze events for a single cPanel account."""
        window_events = self._get_window_events(events)
        if len(window_events) < 3:
            return None

        categories = defaultdict(int)
        for e in window_events:
            categories[e.get("category", "")] += 1

        # Detect resource abuse patterns
        pattern = None
        confidence = 0.0

        resource_count = categories.get("resource", 0)
        database_count = categories.get("database", 0)
        web_count = categories.get("web", 0)
        total_warnings = sum(1 for e in window_events if e.get("severity") in ("warning", "critical"))

        # Multi-source abuse
        active_categories = sum(1 for c in categories.values() if c >= 2)
        if active_categories >= 2 and total_warnings >= 3:
            pattern = "multi_source_abuse"
            confidence = min(1.0, total_warnings / 10.0)

        # Database abuse
        if database_count >= 5:
            pattern = "database_abuse"
            confidence = min(1.0, database_count / 10.0)

        if not pattern:
            return None

        return {
            "type": "account_correlation",
            "pattern": pattern,
            "account": account,
            "event_count": len(window_events),
            "confidence": confidence,
            "categories": dict(categories),
            "events": window_events[:20],
            "evidence": [e.get("raw_line", "")[:200] for e in window_events[:5]],
        }

    def _analyze_category_spike(self, category: str, events: List[Dict]) -> Optional[Dict[str, Any]]:
        """Detect unusual spikes in event categories."""
        window_events = self._get_window_events(events)
        if len(window_events) < 10:
            return None

        # Check for warning/critical density
        critical_count = sum(1 for e in window_events if e.get("severity") == "critical")
        warning_count = sum(1 for e in window_events if e.get("severity") == "warning")

        if critical_count < 3 and warning_count < 5:
            return None

        return {
            "type": "category_spike",
            "pattern": f"{category}_spike",
            "category": category,
            "event_count": len(window_events),
            "critical_count": critical_count,
            "warning_count": warning_count,
            "confidence": min(1.0, (critical_count * 2 + warning_count) / 20.0),
            "events": window_events[:20],
            "evidence": [e.get("raw_line", "")[:200] for e in window_events[:5]],
        }

    def _get_window_events(self, events: List[Dict]) -> List[Dict]:
        """Filter events within the correlation time window."""
        cutoff = (datetime.utcnow() - timedelta(seconds=self.window_seconds)).isoformat()
        return [e for e in events if e.get("timestamp", "") >= cutoff]

    def _cleanup_windows(self) -> None:
        """Remove events outside the correlation window."""
        cutoff = (datetime.utcnow() - timedelta(seconds=self.window_seconds * 2)).isoformat()

        for buffer in (self._ip_events, self._account_events, self._domain_events, self._category_events):
            empty_keys = []
            for key, events in buffer.items():
                buffer[key] = [e for e in events if e.get("timestamp", "") >= cutoff]
                if not buffer[key]:
                    empty_keys.append(key)
            for key in empty_keys:
                del buffer[key]
