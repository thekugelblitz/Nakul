"""
Nakul Configuration Loader & Validator
=======================================

Loads configuration from YAML files with environment variable overrides,
validation, and sane defaults for all settings.
"""

import os
import logging
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("nakul.config")

# Default paths
DEFAULT_CONFIG_PATH = "/etc/nakul/nakul.yaml"
DEFAULT_DB_PATH = "/var/lib/nakul/nakul.db"
DEFAULT_LOG_DIR = "/var/log/nakul"


class ServerConfig(BaseModel):
    """Web server configuration."""
    host: str = "0.0.0.0"
    port: int = 8122
    workers: int = 1
    debug: bool = False
    log_level: str = "info"
    cors_origins: List[str] = ["*"]
    ip_allowlist: List[str] = []  # Empty = allow all


class AuthConfig(BaseModel):
    """Authentication configuration."""
    secret_key: str = "change-me-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    session_timeout_minutes: int = 120
    rate_limit_attempts: int = 5
    rate_limit_window_seconds: int = 300
    admin_username: str = "admin"
    admin_password_hash: str = ""  # Generated during install


class DatabaseConfig(BaseModel):
    """Database configuration."""
    path: str = DEFAULT_DB_PATH
    wal_mode: bool = True
    max_events: int = 100000
    max_incidents: int = 50000
    retention_days: int = 30
    checkpoint_interval_seconds: int = 300


class CollectorConfig(BaseModel):
    """Collector layer configuration."""
    scan_interval_seconds: int = 30
    log_batch_size: int = 1000
    max_log_line_length: int = 4096
    system_metrics_interval_seconds: int = 15
    service_check_interval_seconds: int = 60


class LogPaths(BaseModel):
    """Configurable log file paths."""
    # Apache / LiteSpeed
    apache_access: str = "/var/log/apache2/access_log"
    apache_error: str = "/var/log/apache2/error_log"
    litespeed_access: str = "/usr/local/lsws/logs/access.log"
    litespeed_error: str = "/usr/local/lsws/logs/error.log"

    # cPanel / WHM
    cpanel_access: str = "/usr/local/cpanel/logs/access_log"
    cpanel_error: str = "/usr/local/cpanel/logs/error_log"
    whm_access: str = "/usr/local/cpanel/logs/login_log"

    # MySQL / MariaDB
    mysql_error: str = "/var/log/mysql/error.log"
    mysql_slow: str = "/var/log/mysql/slow.log"
    mysql_general: str = "/var/log/mysql/general.log"

    # Security
    imunify360: str = "/var/log/imunify360/console.log"
    csf_deny: str = "/etc/csf/csf.deny"
    csf_log: str = "/var/log/lfd.log"
    auth_log: str = "/var/log/secure"

    # Backups
    backuply: str = "/var/log/backuply.log"

    # System
    syslog: str = "/var/log/messages"
    kernel: str = "/var/log/kern.log"

    # Softaculous
    softaculous: str = "/var/log/softaculous.log"

    # WP Toolkit
    wptoolkit: str = "/var/log/plesk/wt.log"


class AlertConfig(BaseModel):
    """Alert thresholds and settings."""
    # Resource thresholds
    cpu_warning_percent: float = 80.0
    cpu_critical_percent: float = 95.0
    memory_warning_percent: float = 85.0
    memory_critical_percent: float = 95.0
    disk_warning_percent: float = 85.0
    disk_critical_percent: float = 95.0
    inode_warning_percent: float = 85.0
    inode_critical_percent: float = 95.0
    load_warning_multiplier: float = 2.0  # x CPU cores
    load_critical_multiplier: float = 4.0

    # Web thresholds
    error_500_threshold: int = 50  # per 5 minutes
    error_503_threshold: int = 20
    connection_flood_threshold: int = 500
    request_rate_threshold: int = 1000  # per minute per IP

    # Security thresholds
    brute_force_threshold: int = 10  # failed logins per 5 minutes
    csf_block_threshold: int = 20  # blocks per 5 minutes
    imunify_detection_threshold: int = 5

    # Database thresholds
    slow_query_threshold: int = 20  # per 5 minutes
    db_connection_threshold: int = 100
    long_query_seconds: int = 30

    # General
    cooldown_seconds: int = 300
    aggregation_window_seconds: int = 300
    max_alerts_per_hour: int = 100


class NotificationConfig(BaseModel):
    """Notification subsystem configuration."""
    dashboard_enabled: bool = True
    email_enabled: bool = False
    webhook_enabled: bool = False
    email_smtp_host: str = ""
    email_smtp_port: int = 587
    email_smtp_user: str = ""
    email_smtp_password: str = ""
    email_from: str = ""
    email_to: List[str] = []
    webhook_url: str = ""
    webhook_headers: Dict[str, str] = {}
    webhook_retry_count: int = 3
    rate_limit_per_minute: int = 10


class PluginConfig(BaseModel):
    """Plugin enable/disable settings."""
    litespeed_enabled: bool = True
    cloudlinux_enabled: bool = True
    imunify360_enabled: bool = True
    csf_enabled: bool = True
    backuply_enabled: bool = True
    softaculous_enabled: bool = True
    wptoolkit_enabled: bool = True
    auto_detect: bool = True  # Auto-detect and adjust


class NakulConfig(BaseModel):
    """Root configuration model."""
    server: ServerConfig = ServerConfig()
    auth: AuthConfig = AuthConfig()
    database: DatabaseConfig = DatabaseConfig()
    collector: CollectorConfig = CollectorConfig()
    log_paths: LogPaths = LogPaths()
    alerts: AlertConfig = AlertConfig()
    notifications: NotificationConfig = NotificationConfig()
    plugins: PluginConfig = PluginConfig()


def load_config(config_path: Optional[str] = None) -> NakulConfig:
    """
    Load configuration from YAML file with environment variable overrides.

    Priority: ENV vars > YAML file > defaults
    """
    path = config_path or os.environ.get("NAKUL_CONFIG", DEFAULT_CONFIG_PATH)

    config_data: Dict[str, Any] = {}

    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                loaded = yaml.safe_load(f)
                if loaded and isinstance(loaded, dict):
                    config_data = loaded
            logger.info(f"Loaded configuration from {path}")
        except Exception as e:
            logger.warning(f"Failed to load config from {path}: {e}. Using defaults.")
    else:
        logger.info(f"Config file not found at {path}. Using defaults.")

    # Apply environment variable overrides
    _apply_env_overrides(config_data)

    try:
        config = NakulConfig(**config_data)
    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        logger.info("Falling back to default configuration")
        config = NakulConfig()

    return config


def _apply_env_overrides(config_data: Dict[str, Any]) -> None:
    """Apply NAKUL_* environment variables as overrides."""
    env_mappings = {
        "NAKUL_HOST": ("server", "host"),
        "NAKUL_PORT": ("server", "port", int),
        "NAKUL_DEBUG": ("server", "debug", lambda v: v.lower() in ("1", "true", "yes")),
        "NAKUL_LOG_LEVEL": ("server", "log_level"),
        "NAKUL_SECRET_KEY": ("auth", "secret_key"),
        "NAKUL_DB_PATH": ("database", "path"),
        "NAKUL_SCAN_INTERVAL": ("collector", "scan_interval_seconds", int),
        "NAKUL_RETENTION_DAYS": ("database", "retention_days", int),
        "NAKUL_ADMIN_USER": ("auth", "admin_username"),
        "NAKUL_ADMIN_PASS_HASH": ("auth", "admin_password_hash"),
    }

    for env_key, mapping in env_mappings.items():
        value = os.environ.get(env_key)
        if value is not None:
            section = mapping[0]
            key = mapping[1]
            converter = mapping[2] if len(mapping) > 2 else str

            if section not in config_data:
                config_data[section] = {}

            try:
                config_data[section][key] = converter(value)
            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid env override {env_key}={value}: {e}")


def save_config(config: NakulConfig, path: Optional[str] = None) -> None:
    """Save current configuration to YAML file."""
    save_path = path or os.environ.get("NAKUL_CONFIG", DEFAULT_CONFIG_PATH)
    os.makedirs(os.path.dirname(save_path), exist_ok=True)

    data = config.model_dump()
    with open(save_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    logger.info(f"Configuration saved to {save_path}")
