"""
Correlation Patterns
=====================

Pattern definitions for event correlation and detection.
"""

from typing import Any, Dict, List

# Pattern definitions for correlation
CORRELATION_PATTERNS = {
    "brute_force": {
        "name": "Brute Force Attack",
        "description": "Multiple failed authentication attempts from a single IP",
        "min_events": 5,
        "time_window_seconds": 300,
        "categories": ["auth"],
        "severity": "critical",
    },
    "connection_flood": {
        "name": "Connection Flood / DDoS",
        "description": "Excessive requests from a single IP indicating potential DDoS",
        "min_events": 20,
        "time_window_seconds": 60,
        "categories": ["web"],
        "severity": "critical",
    },
    "resource_abuse": {
        "name": "Resource Abuse",
        "description": "Account consuming excessive CPU, memory, or I/O",
        "min_events": 3,
        "time_window_seconds": 300,
        "categories": ["resource"],
        "severity": "warning",
    },
    "database_abuse": {
        "name": "Database Abuse",
        "description": "Excessive slow queries, connections, or errors from an account",
        "min_events": 5,
        "time_window_seconds": 300,
        "categories": ["database"],
        "severity": "warning",
    },
    "multi_source_abuse": {
        "name": "Multi-Source Abuse",
        "description": "Account triggering warnings across multiple service types simultaneously",
        "min_events": 3,
        "time_window_seconds": 300,
        "categories": ["resource", "database", "web"],
        "severity": "critical",
    },
    "security_spike": {
        "name": "Security Event Spike",
        "description": "Sudden increase in security-related events",
        "min_events": 5,
        "time_window_seconds": 300,
        "categories": ["security", "malware"],
        "severity": "critical",
    },
    "backup_failure": {
        "name": "Backup Failure Pattern",
        "description": "Repeated backup failures indicating a systemic issue",
        "min_events": 2,
        "time_window_seconds": 3600,
        "categories": ["backup"],
        "severity": "warning",
    },
}
