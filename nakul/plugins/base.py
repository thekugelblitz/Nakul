"""
Plugin System
==============

Base plugin class and plugin registry for optional service integrations.
Each plugin provides detection, collectors, parsers, and rules for a service.
"""

import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type

logger = logging.getLogger("nakul.plugins")


class BasePlugin(ABC):
    """Base class for all service integration plugins."""

    name: str = ""
    display_name: str = ""
    description: str = ""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"nakul.plugins.{self.name}")
        self._detected: Optional[bool] = None

    @abstractmethod
    def detect(self) -> bool:
        """
        Detect if this service is installed on the system.
        Returns True if the service is available.
        """
        pass

    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Get current service status."""
        pass

    def get_log_sources(self) -> List[Dict[str, str]]:
        """Return log sources this plugin monitors. Override in subclass."""
        return []

    def get_parser_name(self) -> Optional[str]:
        """Return the parser type for this plugin's logs. Override in subclass."""
        return None

    def is_available(self) -> bool:
        """Check if plugin is available (cached)."""
        if self._detected is None:
            try:
                self._detected = self.detect()
            except Exception as e:
                self.logger.error(f"Detection failed: {e}")
                self._detected = False
        return self._detected

    def _check_path(self, path: str) -> bool:
        """Check if a file/directory exists."""
        return os.path.exists(path)

    def _check_binary(self, path: str) -> bool:
        """Check if a binary exists and is executable."""
        return os.path.isfile(path) and os.access(path, os.X_OK)


class LiteSpeedPlugin(BasePlugin):
    name = "litespeed"
    display_name = "LiteSpeed Web Server"
    description = "LiteSpeed Web Server monitoring"

    def detect(self) -> bool:
        return self._check_path("/usr/local/lsws/bin/lshttpd")

    def get_status(self) -> Dict[str, Any]:
        return {"name": self.name, "display_name": self.display_name, "installed": self.is_available()}

    def get_log_sources(self) -> List[Dict[str, str]]:
        return [
            {"name": "litespeed_access", "path": self.config.get("litespeed_access", "/usr/local/lsws/logs/access.log"), "source": "web"},
            {"name": "litespeed_error", "path": self.config.get("litespeed_error", "/usr/local/lsws/logs/error.log"), "source": "web"},
        ]

    def get_parser_name(self) -> str:
        return "apache"  # LiteSpeed uses similar format


class CloudLinuxPlugin(BasePlugin):
    name = "cloudlinux"
    display_name = "CloudLinux OS"
    description = "CloudLinux OS and LVE monitoring"

    def detect(self) -> bool:
        return self._check_path("/etc/cloudlinux-release")

    def get_status(self) -> Dict[str, Any]:
        return {"name": self.name, "display_name": self.display_name, "installed": self.is_available()}

    def get_log_sources(self) -> List[Dict[str, str]]:
        return []  # CloudLinux uses system logs

    def get_parser_name(self) -> Optional[str]:
        return "system"


class Imunify360Plugin(BasePlugin):
    name = "imunify360"
    display_name = "Imunify360"
    description = "Imunify360 security monitoring"

    def detect(self) -> bool:
        return self._check_path("/usr/bin/imunify360-agent")

    def get_status(self) -> Dict[str, Any]:
        return {"name": self.name, "display_name": self.display_name, "installed": self.is_available()}

    def get_log_sources(self) -> List[Dict[str, str]]:
        return [
            {"name": "imunify360", "path": self.config.get("imunify360", "/var/log/imunify360/console.log"), "source": "security"},
        ]

    def get_parser_name(self) -> str:
        return "security_imunify"


class CSFPlugin(BasePlugin):
    name = "csf"
    display_name = "CSF Firewall"
    description = "ConfigServer Security & Firewall monitoring"

    def detect(self) -> bool:
        return self._check_path("/etc/csf/csf.conf")

    def get_status(self) -> Dict[str, Any]:
        return {"name": self.name, "display_name": self.display_name, "installed": self.is_available()}

    def get_log_sources(self) -> List[Dict[str, str]]:
        return [
            {"name": "csf_log", "path": self.config.get("csf_log", "/var/log/lfd.log"), "source": "security"},
        ]

    def get_parser_name(self) -> str:
        return "security_csf"


class BackuplyPlugin(BasePlugin):
    name = "backuply"
    display_name = "Backuply"
    description = "Backuply server backup monitoring"

    def detect(self) -> bool:
        return (
            self._check_path("/usr/local/bin/backuply") or
            self._check_path("/etc/backuply/backuply.conf")
        )

    def get_status(self) -> Dict[str, Any]:
        return {"name": self.name, "display_name": self.display_name, "installed": self.is_available()}

    def get_log_sources(self) -> List[Dict[str, str]]:
        return [
            {"name": "backuply", "path": self.config.get("backuply", "/var/log/backuply.log"), "source": "backup"},
        ]

    def get_parser_name(self) -> str:
        return "backup"


class SoftaculousPlugin(BasePlugin):
    name = "softaculous"
    display_name = "Softaculous"
    description = "Softaculous auto-installer monitoring"

    def detect(self) -> bool:
        return self._check_path("/var/softaculous")

    def get_status(self) -> Dict[str, Any]:
        return {"name": self.name, "display_name": self.display_name, "installed": self.is_available()}

    def get_log_sources(self) -> List[Dict[str, str]]:
        return [
            {"name": "softaculous", "path": self.config.get("softaculous", "/var/log/softaculous.log"), "source": "system"},
        ]

    def get_parser_name(self) -> Optional[str]:
        return None


class WPToolkitPlugin(BasePlugin):
    name = "wptoolkit"
    display_name = "WP Toolkit"
    description = "WordPress Toolkit monitoring"

    def detect(self) -> bool:
        return (
            self._check_path("/usr/local/bin/wp-toolkit") or
            self._check_path("/usr/local/cpanel/whostmgr/docroot/cgi/wpt/index.cgi")
        )

    def get_status(self) -> Dict[str, Any]:
        return {"name": self.name, "display_name": self.display_name, "installed": self.is_available()}

    def get_log_sources(self) -> List[Dict[str, str]]:
        return [
            {"name": "wptoolkit", "path": self.config.get("wptoolkit", "/var/log/plesk/wt.log"), "source": "web"},
        ]

    def get_parser_name(self) -> str:
        return "wptoolkit"


# Plugin Registry
ALL_PLUGINS: Dict[str, Type[BasePlugin]] = {
    "litespeed": LiteSpeedPlugin,
    "cloudlinux": CloudLinuxPlugin,
    "imunify360": Imunify360Plugin,
    "csf": CSFPlugin,
    "backuply": BackuplyPlugin,
    "softaculous": SoftaculousPlugin,
    "wptoolkit": WPToolkitPlugin,
}


class PluginManager:
    """Manages plugin lifecycle and discovery."""

    def __init__(self, plugin_config: Dict[str, Any] = None, log_paths: Dict[str, str] = None):
        self.config = plugin_config or {}
        self.log_paths = log_paths or {}
        self.plugins: Dict[str, BasePlugin] = {}
        self.logger = logging.getLogger("nakul.plugins.manager")

    def discover_and_load(self) -> None:
        """Discover and load all plugins, checking availability."""
        auto_detect = self.config.get("auto_detect", True)

        for name, plugin_cls in ALL_PLUGINS.items():
            config_key = f"{name}_enabled"
            enabled = self.config.get(config_key, True)

            if not enabled:
                self.logger.info(f"Plugin {name} disabled by configuration")
                continue

            try:
                plugin = plugin_cls(config=self.log_paths)

                if auto_detect:
                    available = plugin.is_available()
                    if available:
                        self.plugins[name] = plugin
                        self.logger.info(f"Plugin loaded: {plugin.display_name} (detected)")
                    else:
                        self.logger.info(f"Plugin skipped: {plugin.display_name} (not installed)")
                else:
                    self.plugins[name] = plugin
                    self.logger.info(f"Plugin loaded: {plugin.display_name} (auto-detect disabled)")

            except Exception as e:
                self.logger.error(f"Failed to load plugin {name}: {e}")

    def get_all_log_sources(self) -> List[Dict[str, str]]:
        """Get log sources from all active plugins."""
        sources = []
        for plugin in self.plugins.values():
            sources.extend(plugin.get_log_sources())
        return sources

    def get_plugin_statuses(self) -> List[Dict[str, Any]]:
        """Get status of all plugins (loaded and unloaded)."""
        statuses = []
        for name, plugin_cls in ALL_PLUGINS.items():
            if name in self.plugins:
                status = self.plugins[name].get_status()
                status["loaded"] = True
                status["available"] = True
            else:
                config_key = f"{name}_enabled"
                status = {
                    "name": name,
                    "display_name": plugin_cls.display_name,
                    "installed": False,
                    "loaded": False,
                    "available": False,
                    "enabled": self.config.get(config_key, True),
                }
            statuses.append(status)
        return statuses
