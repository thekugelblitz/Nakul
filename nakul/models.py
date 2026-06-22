"""
Nakul Data Models
==================

Pydantic models for all data structures used across the platform:
events, incidents, alerts, service status, snapshots, and audit actions.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# =============================================================================
# Enums
# =============================================================================

class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class IncidentState(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    FALSE_POSITIVE = "false_positive"


class ServiceHealth(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"
    NOT_INSTALLED = "not_installed"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class EventCategory(str, Enum):
    RESOURCE = "resource"
    SECURITY = "security"
    WEB = "web"
    DATABASE = "database"
    BACKUP = "backup"
    SERVICE = "service"
    SYSTEM = "system"
    NETWORK = "network"
    MALWARE = "malware"
    AUTH = "auth"


# =============================================================================
# Core Event Model
# =============================================================================

class Event(BaseModel):
    """A normalized event from any data source."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str = ""  # e.g., "apache", "mysql", "csf", "system"
    category: EventCategory = EventCategory.SYSTEM
    severity: Severity = Severity.INFO
    message: str = ""
    raw_line: str = ""
    hostname: str = ""
    account: Optional[str] = None  # cPanel account
    domain: Optional[str] = None
    ip_address: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    log_file: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# Incident Model
# =============================================================================

class Incident(BaseModel):
    """A correlated, scored incident with full context."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    severity: Severity = Severity.WARNING
    category: EventCategory = EventCategory.SYSTEM
    state: IncidentState = IncidentState.NEW
    rule_id: str = ""  # Which rule generated this
    summary: str = ""  # Human-readable short summary
    explanation: str = ""  # Detailed explanation of what happened and why it matters
    affected_account: Optional[str] = None
    affected_service: Optional[str] = None
    affected_domain: Optional[str] = None
    affected_ip: Optional[str] = None
    source_evidence: List[str] = Field(default_factory=list)  # Raw log excerpts
    event_ids: List[str] = Field(default_factory=list)  # Related event IDs
    confidence_score: float = 0.0  # 0.0 to 1.0
    suggested_remediation: str = ""
    logs_consulted: List[str] = Field(default_factory=list)  # Which log files
    resolution_notes: str = ""
    fingerprint: str = ""  # For deduplication
    occurrence_count: int = 1
    metadata: Dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# Alert Model
# =============================================================================

class Alert(BaseModel):
    """An alert generated from an incident for display/notification."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    incident_id: Optional[str] = None
    severity: Severity = Severity.WARNING
    category: EventCategory = EventCategory.SYSTEM
    title: str = ""
    message: str = ""
    evidence: List[str] = Field(default_factory=list)
    affected_entity: Optional[str] = None  # account, IP, service
    recommended_action: str = ""
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    suppressed: bool = False
    notification_sent: bool = False


# =============================================================================
# Service Status Model
# =============================================================================

class ServiceStatus(BaseModel):
    """Status of a monitored service."""
    name: str
    display_name: str = ""
    installed: bool = False
    running: bool = False
    health: ServiceHealth = ServiceHealth.UNKNOWN
    version: Optional[str] = None
    pid: Optional[int] = None
    uptime_seconds: Optional[int] = None
    last_check: datetime = Field(default_factory=datetime.utcnow)
    last_error: Optional[str] = None
    recent_events: List[str] = Field(default_factory=list)  # Recent event summaries
    config_path: Optional[str] = None
    log_path: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# System Snapshot Model
# =============================================================================

class SystemSnapshot(BaseModel):
    """Point-in-time snapshot of system resource usage."""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    cpu_percent: float = 0.0
    cpu_count: int = 1
    memory_total_mb: float = 0.0
    memory_used_mb: float = 0.0
    memory_percent: float = 0.0
    swap_total_mb: float = 0.0
    swap_used_mb: float = 0.0
    swap_percent: float = 0.0
    disk_total_gb: float = 0.0
    disk_used_gb: float = 0.0
    disk_percent: float = 0.0
    disk_inodes_used_percent: float = 0.0
    load_1: float = 0.0
    load_5: float = 0.0
    load_15: float = 0.0
    network_connections: int = 0
    process_count: int = 0
    uptime_seconds: int = 0
    top_cpu_processes: List[Dict[str, Any]] = Field(default_factory=list)
    top_memory_processes: List[Dict[str, Any]] = Field(default_factory=list)


# =============================================================================
# Log Entry Model
# =============================================================================

class LogEntry(BaseModel):
    """A single parsed log line with metadata."""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str = ""
    level: str = ""
    message: str = ""
    raw: str = ""
    file_path: str = ""
    line_number: Optional[int] = None
    hostname: Optional[str] = None
    account: Optional[str] = None
    ip_address: Optional[str] = None
    domain: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# Audit Action Model
# =============================================================================

class AuditAction(BaseModel):
    """Record of an operator action for audit trail."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user: str = ""
    action: str = ""  # e.g., "acknowledge_incident", "suppress_alert", "update_config"
    target_type: str = ""  # e.g., "incident", "alert", "config"
    target_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None


# =============================================================================
# API Response Models
# =============================================================================

class DashboardSummary(BaseModel):
    """Summary data for the dashboard home page."""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    system: SystemSnapshot = Field(default_factory=SystemSnapshot)
    services: List[ServiceStatus] = Field(default_factory=list)
    active_alerts_count: int = 0
    critical_alerts_count: int = 0
    warning_alerts_count: int = 0
    recent_incidents: List[Incident] = Field(default_factory=list)
    top_issues: List[str] = Field(default_factory=list)
    events_last_hour: int = 0
    server_health: ServiceHealth = ServiceHealth.UNKNOWN


class PaginatedResponse(BaseModel):
    """Generic paginated response."""
    items: List[Any] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 50
    total_pages: int = 0
