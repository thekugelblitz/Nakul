"""
Service Status Collector
=========================

Detects installed services, checks running state, version,
and health. Handles missing services gracefully.
"""

import os
import re
import subprocess
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from nakul.collectors.base import BaseCollector

logger = logging.getLogger("nakul.collectors.service")


# Default service definitions
DEFAULT_SERVICES = {
    "cpanel": {
        "display_name": "cPanel/WHM",
        "check_binary": "/usr/local/cpanel/cpanel",
        "check_file": "/usr/local/cpanel/version",
        "systemd_unit": "cpanel.service",
        "version_cmd": "cat /usr/local/cpanel/version",
        "config_path": "/var/cpanel/cpanel.config",
    },
    "litespeed": {
        "display_name": "LiteSpeed Web Server",
        "check_binary": "/usr/local/lsws/bin/lshttpd",
        "systemd_unit": "lsws.service",
        "version_cmd": "/usr/local/lsws/bin/lshttpd -v 2>&1",
        "config_path": "/usr/local/lsws/conf/httpd_config.xml",
        "log_path": "/usr/local/lsws/logs/error.log",
    },
    "apache": {
        "display_name": "Apache HTTP Server",
        "check_binary": "/usr/sbin/httpd",
        "systemd_unit": "httpd.service",
        "version_cmd": "httpd -v 2>&1",
        "config_path": "/etc/httpd/conf/httpd.conf",
        "log_path": "/var/log/apache2/error_log",
    },
    "mysql": {
        "display_name": "MySQL/MariaDB",
        "check_binary": "/usr/bin/mysql",
        "systemd_unit": "mysqld.service",
        "alt_units": ["mariadb.service", "mysql.service"],
        "version_cmd": "mysql --version 2>&1",
        "config_path": "/etc/my.cnf",
        "log_path": "/var/log/mysql/error.log",
    },
    "imunify360": {
        "display_name": "Imunify360",
        "check_binary": "/usr/bin/imunify360-agent",
        "systemd_unit": "imunify360.service",
        "version_cmd": "imunify360-agent version 2>&1",
        "config_path": "/etc/sysconfig/imunify360/imunify360.config",
        "log_path": "/var/log/imunify360/console.log",
    },
    "csf": {
        "display_name": "CSF Firewall",
        "check_binary": "/usr/sbin/csf",
        "check_file": "/etc/csf/csf.conf",
        "systemd_unit": "csf.service",
        "version_cmd": "csf -v 2>&1",
        "config_path": "/etc/csf/csf.conf",
        "log_path": "/var/log/lfd.log",
    },
    "cloudlinux": {
        "display_name": "CloudLinux OS",
        "check_file": "/etc/cloudlinux-release",
        "check_binary": "/usr/sbin/lvectl",
        "version_cmd": "cat /etc/cloudlinux-release 2>&1",
    },
    "backuply": {
        "display_name": "Backuply",
        "check_binary": "/usr/local/bin/backuply",
        "check_file": "/etc/backuply/backuply.conf",
        "version_cmd": "backuply --version 2>&1",
        "log_path": "/var/log/backuply.log",
    },
    "softaculous": {
        "display_name": "Softaculous",
        "check_file": "/usr/local/cpanel/whostmgr/docroot/cgi/softaculous/index.php",
        "check_dir": "/var/softaculous",
        "version_cmd": "cat /var/softaculous/version.txt 2>&1",
    },
    "wptoolkit": {
        "display_name": "WP Toolkit",
        "check_binary": "/usr/local/bin/wp-toolkit",
        "check_file": "/usr/local/cpanel/whostmgr/docroot/cgi/wpt/index.cgi",
        "version_cmd": "wp-toolkit --version 2>&1",
    },
}


class ServiceCollector(BaseCollector):
    """Detects and monitors service status."""

    def __init__(self, service_definitions: Dict[str, Dict] = None, config: Dict[str, Any] = None):
        super().__init__("service", config)
        self.service_defs = service_definitions or DEFAULT_SERVICES

    def is_available(self) -> bool:
        """Always available — it just reports what it finds."""
        return True

    async def collect(self) -> List[Dict[str, Any]]:
        """Collect status for all defined services."""
        statuses = []

        for svc_name, svc_def in self.service_defs.items():
            try:
                status = self._check_service(svc_name, svc_def)
                statuses.append(status)
            except Exception as e:
                self.logger.error(f"Error checking service {svc_name}: {e}")
                statuses.append({
                    "name": svc_name,
                    "display_name": svc_def.get("display_name", svc_name),
                    "installed": False,
                    "running": False,
                    "health": "unknown",
                    "last_check": datetime.utcnow().isoformat(),
                    "last_error": str(e),
                })

        return statuses

    def _check_service(self, name: str, definition: Dict) -> Dict[str, Any]:
        """Check a single service's installation and running status."""
        status = {
            "name": name,
            "display_name": definition.get("display_name", name),
            "installed": False,
            "running": False,
            "health": "not_installed",
            "version": None,
            "pid": None,
            "uptime_seconds": None,
            "last_check": datetime.utcnow().isoformat(),
            "last_error": None,
            "config_path": definition.get("config_path"),
            "log_path": definition.get("log_path"),
            "metadata": {},
        }

        # Check if installed
        installed = False
        if definition.get("check_binary"):
            installed = os.path.isfile(definition["check_binary"])
        if not installed and definition.get("check_file"):
            installed = os.path.isfile(definition["check_file"])
        if not installed and definition.get("check_dir"):
            installed = os.path.isdir(definition["check_dir"])

        status["installed"] = installed

        if not installed:
            status["health"] = "not_installed"
            return status

        # Get version
        if definition.get("version_cmd"):
            version = self._run_cmd(definition["version_cmd"])
            if version:
                # Extract version number from output
                status["version"] = self._extract_version(version)

        # Check if running via systemd
        running = False
        pid = None
        units_to_check = [definition.get("systemd_unit", "")]
        units_to_check.extend(definition.get("alt_units", []))

        for unit in units_to_check:
            if not unit:
                continue
            is_running, svc_pid = self._check_systemd_unit(unit)
            if is_running:
                running = True
                pid = svc_pid
                break

        status["running"] = running
        status["pid"] = pid

        if running:
            status["health"] = "healthy"
        elif installed:
            status["health"] = "down"

        return status

    @staticmethod
    def _check_systemd_unit(unit_name: str) -> Tuple[bool, Optional[int]]:
        """Check if a systemd unit is active. Returns (is_running, pid)."""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", unit_name],
                capture_output=True, text=True, timeout=5
            )
            is_active = result.stdout.strip() == "active"

            pid = None
            if is_active:
                try:
                    pid_result = subprocess.run(
                        ["systemctl", "show", unit_name, "--property=MainPID"],
                        capture_output=True, text=True, timeout=5
                    )
                    pid_str = pid_result.stdout.strip().replace("MainPID=", "")
                    if pid_str and pid_str != "0":
                        pid = int(pid_str)
                except (subprocess.TimeoutExpired, ValueError):
                    pass

            return is_active, pid

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False, None

    @staticmethod
    def _run_cmd(cmd: str, timeout: int = 5) -> Optional[str]:
        """Run a shell command and return output."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout.strip() or result.stderr.strip()
            return output if output else None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    @staticmethod
    def _extract_version(text: str) -> Optional[str]:
        """Extract a version number from command output."""
        if not text:
            return None
        # Match patterns like 1.2.3, v1.2.3, 110.0.6
        patterns = [
            r'(\d+\.\d+\.\d+(?:\.\d+)?)',
            r'[vV]?(\d+\.\d+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1)
        # If no version pattern found, return first line (truncated)
        first_line = text.split('\n')[0].strip()
        return first_line[:50] if first_line else None
