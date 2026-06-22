"""
Alert Rules
============

Default alerting rules with thresholds, severity, descriptions,
and human-readable remediation steps. All rules can be overridden
via configuration.
"""

from typing import Any, Dict, Optional

# Default alert rules
# Each rule specifies matching conditions and response templates
ALERT_RULES: Dict[str, Dict[str, Any]] = {
    # =========================================================================
    # Web / HTTP Rules
    # =========================================================================
    "http_500_spike": {
        "name": "HTTP 500 Error Spike",
        "enabled": True,
        "categories": ["web"],
        "min_severity": "warning",
        "keywords": ["500", "internal server error"],
        "base_confidence": 0.8,
        "severity": "warning",
        "summary_template": "HTTP 500 errors detected on {domain}",
        "explanation_template": (
            "The web server is returning HTTP 500 (Internal Server Error) responses. "
            "This was detected in {log_file}. The affected domain appears to be {domain}, "
            "associated with account {account}. 500 errors typically indicate a server-side "
            "application crash, misconfigured .htaccess, or PHP fatal error."
        ),
        "remediation": (
            "1. Check the PHP error log for the affected domain\n"
            "2. Review recent .htaccess changes\n"
            "3. Check if the account has exceeded PHP memory or process limits\n"
            "4. Verify file permissions on the web root\n"
            "5. Check for broken plugins/themes if WordPress"
        ),
    },

    "http_503_spike": {
        "name": "HTTP 503 Service Unavailable Spike",
        "enabled": True,
        "categories": ["web"],
        "min_severity": "warning",
        "keywords": ["503", "service unavailable"],
        "base_confidence": 0.85,
        "severity": "critical",
        "summary_template": "HTTP 503 errors — service overloaded for {domain}",
        "explanation_template": (
            "HTTP 503 (Service Unavailable) responses indicate the web server cannot handle "
            "requests, typically due to resource exhaustion, backend timeout, or too many "
            "concurrent connections. Domain: {domain}, Account: {account}."
        ),
        "remediation": (
            "1. Check server load average and resource usage\n"
            "2. Review LiteSpeed/Apache max connections settings\n"
            "3. Check PHP process limits (entry processes, max children)\n"
            "4. Look for DDoS indicators in access logs\n"
            "5. Consider temporarily increasing resources or enabling caching"
        ),
    },

    "suspicious_request": {
        "name": "Suspicious Web Request",
        "enabled": True,
        "categories": ["security", "web"],
        "min_severity": "warning",
        "keywords": ["suspicious", "wp-login", "xmlrpc", "phpmyadmin", "eval(", "base64", "shell"],
        "base_confidence": 0.7,
        "severity": "warning",
        "summary_template": "Suspicious request pattern from {ip}",
        "explanation_template": (
            "A suspicious request was detected from IP {ip}: {message}. "
            "This may indicate automated scanning, vulnerability probing, "
            "or an attempted exploit."
        ),
        "remediation": (
            "1. Review the full request details in access logs\n"
            "2. Block the IP if pattern continues\n"
            "3. Ensure WordPress xmlrpc.php is disabled if not needed\n"
            "4. Verify Imunify360 WAF is active\n"
            "5. Check for successful exploits in error logs"
        ),
    },

    # =========================================================================
    # Security Rules
    # =========================================================================
    "brute_force_login": {
        "name": "Brute Force Login Attempt",
        "enabled": True,
        "categories": ["auth"],
        "min_severity": "warning",
        "keywords": ["failed", "login", "authentication", "denied"],
        "base_confidence": 0.75,
        "severity": "warning",
        "summary_template": "Failed login attempt for {account} from {ip}",
        "explanation_template": (
            "A failed authentication attempt was detected: {message}. "
            "Source IP: {ip}. Multiple failed attempts may indicate a "
            "brute-force attack."
        ),
        "remediation": (
            "1. Monitor for additional failed attempts from the same IP\n"
            "2. Block the IP if threshold is exceeded\n"
            "3. Verify the target account has a strong password\n"
            "4. Enable two-factor authentication if available\n"
            "5. Check CSF/LFD brute-force detection settings"
        ),
    },

    "csf_block": {
        "name": "CSF IP Block",
        "enabled": True,
        "categories": ["security"],
        "min_severity": "warning",
        "keywords": ["blocked", "denied", "csf"],
        "base_confidence": 0.8,
        "severity": "warning",
        "summary_template": "CSF blocked IP {ip}",
        "explanation_template": (
            "CSF/LFD has blocked IP {ip}: {message}. This indicates "
            "the firewall has detected and responded to suspicious activity."
        ),
        "remediation": (
            "1. Review the block reason in CSF logs\n"
            "2. Check if the IP is a legitimate user or service\n"
            "3. Whitelist the IP if it's a false positive\n"
            "4. Review CSF trigger thresholds if blocks are excessive"
        ),
    },

    "malware_detection": {
        "name": "Malware Detection",
        "enabled": True,
        "categories": ["malware", "security"],
        "min_severity": "warning",
        "keywords": ["malware", "virus", "trojan", "infected", "malicious", "quarantined"],
        "base_confidence": 0.9,
        "severity": "critical",
        "summary_template": "Malware detected on server",
        "explanation_template": (
            "Imunify360 or security scanner has detected malicious content: {message}. "
            "This requires immediate investigation to prevent further compromise."
        ),
        "remediation": (
            "1. Check Imunify360 dashboard for quarantined files\n"
            "2. Identify the affected account and domain\n"
            "3. Scan the account's files for additional malware\n"
            "4. Check for unauthorized file modifications\n"
            "5. Reset passwords and review access logs\n"
            "6. Clean or restore affected files from backup"
        ),
    },

    # =========================================================================
    # Database Rules
    # =========================================================================
    "slow_query_spike": {
        "name": "Slow Query Spike",
        "enabled": True,
        "categories": ["database"],
        "min_severity": "warning",
        "keywords": ["slow query", "query_time"],
        "base_confidence": 0.7,
        "severity": "warning",
        "summary_template": "Slow MySQL queries detected",
        "explanation_template": (
            "MySQL/MariaDB slow queries detected: {message}. Excessive slow queries "
            "can degrade database performance for all accounts on the server."
        ),
        "remediation": (
            "1. Review the slow query log for offending queries\n"
            "2. Check EXPLAIN plans for the slowest queries\n"
            "3. Add missing indexes if appropriate\n"
            "4. Optimize or rewrite inefficient queries\n"
            "5. Check if the database tables need optimization (OPTIMIZE TABLE)"
        ),
    },

    "mysql_connection_limit": {
        "name": "MySQL Connection Limit",
        "enabled": True,
        "categories": ["database"],
        "min_severity": "critical",
        "keywords": ["too many connections", "max_connections", "connection refused"],
        "base_confidence": 0.9,
        "severity": "critical",
        "summary_template": "MySQL connection limit reached",
        "explanation_template": (
            "MySQL/MariaDB has reached its maximum connection limit: {message}. "
            "This prevents new database connections, causing application errors "
            "and 500 errors across all sites using MySQL."
        ),
        "remediation": (
            "1. Check 'SHOW PROCESSLIST' for stuck connections\n"
            "2. Kill long-running or sleeping connections\n"
            "3. Increase max_connections if server resources allow\n"
            "4. Identify the account/app creating excessive connections\n"
            "5. Implement connection pooling in the application"
        ),
    },

    "mysql_access_denied": {
        "name": "MySQL Access Denied",
        "enabled": True,
        "categories": ["database"],
        "min_severity": "warning",
        "keywords": ["access denied"],
        "base_confidence": 0.6,
        "severity": "warning",
        "summary_template": "MySQL access denied for user",
        "explanation_template": (
            "A MySQL access denied error was detected: {message}. "
            "This may indicate misconfigured database credentials, "
            "a compromised application, or a brute-force attempt."
        ),
        "remediation": (
            "1. Verify the database credentials in the application config\n"
            "2. Check if the database user and grants are correct\n"
            "3. Review if a password was recently changed\n"
            "4. Monitor for repeated access denied errors (may indicate attack)"
        ),
    },

    # =========================================================================
    # Resource Rules
    # =========================================================================
    "high_cpu": {
        "name": "High CPU Usage",
        "enabled": True,
        "categories": ["resource"],
        "min_severity": "warning",
        "keywords": ["cpu"],
        "base_confidence": 0.8,
        "severity": "warning",
        "summary_template": "High CPU usage detected",
        "explanation_template": "Server CPU usage is elevated. This may cause slow response times and service degradation.",
        "remediation": (
            "1. Check top processes consuming CPU\n"
            "2. Identify which cPanel account owns the top processes\n"
            "3. Check for runaway PHP scripts or cron jobs\n"
            "4. Review CloudLinux LVE limits if applicable\n"
            "5. Consider load balancing or upgrading resources"
        ),
    },

    "high_memory": {
        "name": "High Memory Usage",
        "enabled": True,
        "categories": ["resource"],
        "min_severity": "warning",
        "keywords": ["memory", "oom", "out of memory"],
        "base_confidence": 0.85,
        "severity": "warning",
        "summary_template": "High memory usage: server may become unstable",
        "explanation_template": "Server memory usage is critically high. The OOM killer may start terminating processes.",
        "remediation": (
            "1. Check top memory-consuming processes\n"
            "2. Look for memory leaks in long-running processes\n"
            "3. Restart any services with abnormally high memory\n"
            "4. Check swap usage — high swap indicates insufficient RAM\n"
            "5. Consider increasing server memory"
        ),
    },

    "disk_space_warning": {
        "name": "Disk Space Warning",
        "enabled": True,
        "categories": ["resource"],
        "min_severity": "warning",
        "keywords": ["disk", "no space", "disk full"],
        "base_confidence": 0.9,
        "severity": "critical",
        "summary_template": "Disk space critically low",
        "explanation_template": "Server disk space is running low. This can cause service failures, backup failures, and data loss.",
        "remediation": (
            "1. Check disk usage by directory: du -sh /* | sort -rh\n"
            "2. Clear old backups and temporary files\n"
            "3. Check for accounts using excessive disk space\n"
            "4. Rotate or compress large log files\n"
            "5. Check for large database files that can be optimized"
        ),
    },

    # =========================================================================
    # System Rules
    # =========================================================================
    "oom_kill": {
        "name": "OOM Killer Activated",
        "enabled": True,
        "categories": ["system", "resource"],
        "min_severity": "critical",
        "keywords": ["oom", "out of memory", "killed process"],
        "base_confidence": 0.95,
        "severity": "critical",
        "summary_template": "OOM Killer activated — process killed due to memory exhaustion",
        "explanation_template": (
            "The Linux OOM (Out of Memory) killer has terminated a process to free memory: {message}. "
            "This indicates the server has exhausted all available RAM and swap space."
        ),
        "remediation": (
            "1. Check which process was killed and why\n"
            "2. Increase available memory or add swap\n"
            "3. Reduce memory limits for PHP or other services\n"
            "4. Identify and fix memory leaks\n"
            "5. Consider upgrading the server's RAM"
        ),
    },

    "service_crash": {
        "name": "Service Crash",
        "enabled": True,
        "categories": ["system", "service"],
        "min_severity": "critical",
        "keywords": ["segfault", "crash", "core dump", "fatal", "aborting"],
        "base_confidence": 0.9,
        "severity": "critical",
        "summary_template": "Service crashed: {message}",
        "explanation_template": "A critical service has crashed or encountered a fatal error: {message}.",
        "remediation": (
            "1. Check if the service has auto-restarted\n"
            "2. Review service logs for the crash cause\n"
            "3. Check for recent configuration or software changes\n"
            "4. Verify sufficient resources (memory, disk)\n"
            "5. Report the issue if it's a software bug"
        ),
    },

    # =========================================================================
    # Backup Rules
    # =========================================================================
    "backup_failure": {
        "name": "Backup Failure",
        "enabled": True,
        "categories": ["backup"],
        "min_severity": "warning",
        "keywords": ["failed", "error", "abort", "cannot", "permission denied"],
        "base_confidence": 0.85,
        "severity": "critical",
        "summary_template": "Backup job failed",
        "explanation_template": (
            "A backup operation has failed: {message}. Failed backups leave accounts "
            "unprotected against data loss."
        ),
        "remediation": (
            "1. Check the backup log for detailed error messages\n"
            "2. Verify sufficient disk space for backups\n"
            "3. Check file permissions on backup destination\n"
            "4. Verify backup service credentials and configuration\n"
            "5. Re-run the failed backup manually"
        ),
    },
}


def get_rule(rule_id: str) -> Optional[Dict[str, Any]]:
    """Get a rule by ID."""
    return ALERT_RULES.get(rule_id)


def get_all_rules() -> Dict[str, Dict[str, Any]]:
    """Get all rules."""
    return dict(ALERT_RULES)


def get_enabled_rules() -> Dict[str, Dict[str, Any]]:
    """Get only enabled rules."""
    return {k: v for k, v in ALERT_RULES.items() if v.get("enabled", True)}
