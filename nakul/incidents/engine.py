"""
Incident Engine
================

Creates, scores, and manages incidents from correlated events
and individual high-severity events. Each incident includes
human-readable context, evidence, and remediation suggestions.
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from nakul.incidents.rules import ALERT_RULES, get_rule
from nakul.incidents.dedup import DedupManager

logger = logging.getLogger("nakul.incidents")


class IncidentEngine:
    """
    Evaluates events and correlation results against rules
    to generate scored, actionable incidents.
    """

    def __init__(self, db=None, config: Dict[str, Any] = None):
        self.db = db
        self.config = config or {}
        self.dedup = DedupManager(
            cooldown_seconds=config.get("cooldown_seconds", 300) if config else 300
        )
        self.rules = dict(ALERT_RULES)  # Copy so we can modify

    def apply_rule_overrides(self, overrides: Dict[str, Any]) -> None:
        """Apply user-configured rule overrides."""
        for rule_id, override in overrides.items():
            if rule_id in self.rules:
                self.rules[rule_id].update(override)
                logger.info(f"Rule override applied: {rule_id}")

    async def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Evaluate individual events against alerting rules.
        Returns list of new incidents.
        """
        incidents = []

        for event in events:
            severity = event.get("severity", "info")
            category = event.get("category", "system")

            # Only process warning/critical events
            if severity not in ("warning", "critical"):
                continue

            # Match against rules
            matching_rules = self._match_rules(event)

            for rule in matching_rules:
                incident = self._create_incident_from_event(event, rule)
                if incident:
                    incidents.append(incident)

        return incidents

    async def process_correlations(self, correlations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Create incidents from correlation engine results.
        """
        incidents = []

        for corr in correlations:
            incident = self._create_incident_from_correlation(corr)
            if incident:
                incidents.append(incident)

        return incidents

    def _match_rules(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find all rules that match an event."""
        matches = []
        category = event.get("category", "")
        severity = event.get("severity", "")
        message = event.get("message", "").lower()
        metadata = event.get("metadata", {})

        for rule_id, rule in self.rules.items():
            if not rule.get("enabled", True):
                continue

            # Check category match
            rule_categories = rule.get("categories", [])
            if rule_categories and category not in rule_categories:
                continue

            # Check severity match
            rule_min_severity = rule.get("min_severity", "info")
            severity_order = {"info": 0, "warning": 1, "critical": 2}
            if severity_order.get(severity, 0) < severity_order.get(rule_min_severity, 0):
                continue

            # Check keyword triggers
            keywords = rule.get("keywords", [])
            if keywords and not any(kw in message for kw in keywords):
                # Also check metadata
                meta_str = str(metadata).lower()
                if not any(kw in meta_str for kw in keywords):
                    continue

            matches.append({"rule_id": rule_id, **rule})

        return matches

    def _create_incident_from_event(
        self, event: Dict[str, Any], rule: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Create an incident from a single event + rule match."""
        rule_id = rule.get("rule_id", "unknown")

        # Build fingerprint for dedup
        fingerprint = self.dedup.build_fingerprint(
            rule_id=rule_id,
            account=event.get("account", ""),
            ip=event.get("ip_address", ""),
            category=event.get("category", ""),
        )

        # Check dedup
        if not self.dedup.should_create(fingerprint):
            return None

        # Generate human-readable content
        summary = rule.get("summary_template", "").format(
            message=event.get("message", ""),
            account=event.get("account", "N/A"),
            ip=event.get("ip_address", "N/A"),
            domain=event.get("domain", "N/A"),
            source=event.get("source", ""),
        ) or event.get("message", "")[:200]

        explanation = rule.get("explanation_template", "").format(
            message=event.get("message", ""),
            account=event.get("account", "N/A"),
            ip=event.get("ip_address", "N/A"),
            domain=event.get("domain", "N/A"),
            source=event.get("source", ""),
            category=event.get("category", ""),
            log_file=event.get("log_file", "N/A"),
        ) or f"Event detected: {event.get('message', '')}"

        incident = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "severity": event.get("severity", rule.get("severity", "warning")),
            "category": event.get("category", "system"),
            "state": "new",
            "rule_id": rule_id,
            "summary": summary[:300],
            "explanation": explanation[:1000],
            "affected_account": event.get("account"),
            "affected_service": event.get("source"),
            "affected_domain": event.get("domain"),
            "affected_ip": event.get("ip_address"),
            "source_evidence": [event.get("raw_line", "")[:500]],
            "event_ids": [event.get("id", "")],
            "confidence_score": rule.get("base_confidence", 0.7),
            "suggested_remediation": rule.get("remediation", "Investigate the event and take appropriate action."),
            "logs_consulted": [event.get("log_file", "")] if event.get("log_file") else [],
            "fingerprint": fingerprint,
            "occurrence_count": 1,
            "metadata": {
                "rule_name": rule.get("name", ""),
                "event_metadata": event.get("metadata", {}),
            },
        }

        self.dedup.record_creation(fingerprint)
        return incident

    def _create_incident_from_correlation(
        self, correlation: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Create an incident from a correlated event group."""
        pattern = correlation.get("pattern", "unknown")
        corr_type = correlation.get("type", "")

        # Build fingerprint
        fingerprint = self.dedup.build_fingerprint(
            rule_id=f"corr_{pattern}",
            account=correlation.get("account", ""),
            ip=correlation.get("ip", ""),
            category=correlation.get("category", ""),
        )

        if not self.dedup.should_create(fingerprint):
            return None

        event_count = correlation.get("event_count", 0)
        confidence = correlation.get("confidence", 0.5)
        events = correlation.get("events", [])
        evidence = correlation.get("evidence", [])

        # Human-readable descriptions by pattern
        pattern_descriptions = {
            "brute_force": {
                "summary": f"Brute-force attack detected: {event_count} failed login attempts from IP {correlation.get('ip', 'unknown')}",
                "explanation": (
                    f"Multiple failed authentication attempts ({event_count}) were detected from IP "
                    f"{correlation.get('ip', 'unknown')} within the correlation window. This pattern "
                    f"is consistent with an automated brute-force attack targeting login services."
                ),
                "remediation": (
                    "1. Block the attacking IP using CSF or iptables\n"
                    "2. Check if any accounts were compromised\n"
                    "3. Review auth logs for successful logins from this IP\n"
                    "4. Consider enabling Imunify360 brute-force protection"
                ),
                "severity": "critical",
            },
            "connection_flood": {
                "summary": f"Connection flood from IP {correlation.get('ip', 'unknown')}: {event_count} requests detected",
                "explanation": (
                    f"An abnormal volume of requests ({event_count}) from IP "
                    f"{correlation.get('ip', 'unknown')} suggests a possible DDoS attack or "
                    f"aggressive crawling behavior."
                ),
                "remediation": (
                    "1. Temporarily block the IP using CSF\n"
                    "2. Check if requests are targeting a specific domain or path\n"
                    "3. Review server load and response times\n"
                    "4. Consider implementing rate limiting"
                ),
                "severity": "critical",
            },
            "database_abuse": {
                "summary": f"Database abuse by account '{correlation.get('account', 'unknown')}': {event_count} issues detected",
                "explanation": (
                    f"Account '{correlation.get('account', 'unknown')}' is generating excessive "
                    f"database events ({event_count}), including slow queries, connection errors, "
                    f"or access denied errors."
                ),
                "remediation": (
                    "1. Check the account's database queries using slow query log\n"
                    "2. Review MySQL process list for long-running queries\n"
                    "3. Consider optimizing the application's database usage\n"
                    "4. Check if the database is under attack"
                ),
                "severity": "warning",
            },
            "multi_source_abuse": {
                "summary": f"Multi-source abuse by account '{correlation.get('account', 'unknown')}': affecting {len(correlation.get('categories', {}))} service areas",
                "explanation": (
                    f"Account '{correlation.get('account', 'unknown')}' is triggering warnings across "
                    f"multiple service categories: {', '.join(correlation.get('categories', {}).keys())}. "
                    f"This suggests the account may be under attack, running malicious code, or has "
                    f"a severely misconfigured application."
                ),
                "remediation": (
                    "1. Immediately investigate the account's resource usage\n"
                    "2. Check for malware or compromised scripts\n"
                    "3. Review running processes owned by this user\n"
                    "4. Consider temporary suspension if abuse continues"
                ),
                "severity": "critical",
            },
            "security_spike": {
                "summary": f"Security event spike: {event_count} events detected from IP {correlation.get('ip', 'unknown')}",
                "explanation": (
                    f"A sudden increase in security-related events ({event_count}) suggests "
                    f"active probing, scanning, or attack activity."
                ),
                "remediation": (
                    "1. Review Imunify360/CSF logs for blocked activity\n"
                    "2. Check for new malware detections\n"
                    "3. Verify firewall rules are up to date\n"
                    "4. Scan affected accounts for compromised files"
                ),
                "severity": "critical",
            },
        }

        desc = pattern_descriptions.get(pattern, {
            "summary": f"Correlated incident: {pattern} ({event_count} events)",
            "explanation": f"A pattern of type '{pattern}' was detected with {event_count} related events.",
            "remediation": "Investigate the related events and take appropriate action.",
            "severity": "warning",
        })

        # Collect log files from events
        log_files = list(set(e.get("log_file", "") for e in events if e.get("log_file")))

        incident = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "severity": desc["severity"],
            "category": correlation.get("category", events[0].get("category", "system") if events else "system"),
            "state": "new",
            "rule_id": f"corr_{pattern}",
            "summary": desc["summary"][:300],
            "explanation": desc["explanation"][:1000],
            "affected_account": correlation.get("account"),
            "affected_service": None,
            "affected_domain": None,
            "affected_ip": correlation.get("ip"),
            "source_evidence": evidence[:10],
            "event_ids": [e.get("id", "") for e in events[:50]],
            "confidence_score": confidence,
            "suggested_remediation": desc["remediation"],
            "logs_consulted": log_files[:10],
            "fingerprint": fingerprint,
            "occurrence_count": event_count,
            "metadata": {
                "pattern": pattern,
                "correlation_type": corr_type,
                "categories": correlation.get("categories", {}),
            },
        }

        self.dedup.record_creation(fingerprint)
        return incident
