"""
cPanel Data Collector
======================

Reads cPanel account data, domain mappings, user information,
and database associations to enable correlation.
"""

import os
import re
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from nakul.collectors.base import BaseCollector

logger = logging.getLogger("nakul.collectors.cpanel")


class CpanelCollector(BaseCollector):
    """
    Collects cPanel account and domain mapping data.
    Maps accounts → domains → MySQL users for correlation.
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("cpanel", config)
        self.trueuserdomains_path = "/etc/trueuserdomains"
        self.userdomains_path = "/etc/userdomains"
        self.cpanel_users_dir = "/var/cpanel/users"
        self.userdata_dir = "/var/cpanel/userdata"
        self.mysql_grants_path = "/var/cpanel/databases/grants.yaml"

        # Cached mappings
        self.account_domains: Dict[str, List[str]] = {}
        self.domain_to_account: Dict[str, str] = {}
        self.ip_to_domains: Dict[str, List[str]] = {}
        self.mysql_user_to_account: Dict[str, str] = {}
        self.accounts: List[Dict[str, Any]] = []

    def is_available(self) -> bool:
        """Check if cPanel data is accessible."""
        return os.path.exists(self.trueuserdomains_path) or os.path.isdir(self.cpanel_users_dir)

    async def collect(self) -> List[Dict[str, Any]]:
        """Collect all cPanel mapping data."""
        self.account_domains.clear()
        self.domain_to_account.clear()
        self.ip_to_domains.clear()
        self.mysql_user_to_account.clear()
        self.accounts.clear()

        # Parse domain mappings
        self._parse_trueuserdomains()
        self._parse_userdomains()
        self._parse_user_files()
        self._parse_mysql_mappings()

        # Return aggregated mapping data as a single item
        return [{
            "type": "cpanel_mapping",
            "timestamp": datetime.utcnow().isoformat(),
            "account_count": len(self.accounts),
            "domain_count": len(self.domain_to_account),
            "accounts": self.accounts,
            "account_domains": self.account_domains,
            "domain_to_account": self.domain_to_account,
            "mysql_user_to_account": self.mysql_user_to_account,
        }]

    def _parse_trueuserdomains(self) -> None:
        """Parse /etc/trueuserdomains for primary domain → user mapping."""
        if not os.path.exists(self.trueuserdomains_path):
            return

        try:
            with open(self.trueuserdomains_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Format: domain.com: username
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        domain = parts[0].strip().lower()
                        user = parts[1].strip()
                        if domain and user:
                            self.domain_to_account[domain] = user
                            if user not in self.account_domains:
                                self.account_domains[user] = []
                            self.account_domains[user].append(domain)
        except (IOError, PermissionError) as e:
            self.logger.warning(f"Cannot read {self.trueuserdomains_path}: {e}")

    def _parse_userdomains(self) -> None:
        """Parse /etc/userdomains for all domain → user mapping (includes addon/sub/parked)."""
        if not os.path.exists(self.userdomains_path):
            return

        try:
            with open(self.userdomains_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        domain = parts[0].strip().lower()
                        user = parts[1].strip()
                        if domain and user and user != "*":
                            self.domain_to_account[domain] = user
                            if user not in self.account_domains:
                                self.account_domains[user] = []
                            if domain not in self.account_domains[user]:
                                self.account_domains[user].append(domain)
        except (IOError, PermissionError) as e:
            self.logger.warning(f"Cannot read {self.userdomains_path}: {e}")

    def _parse_user_files(self) -> None:
        """Parse /var/cpanel/users/ for detailed account info."""
        if not os.path.isdir(self.cpanel_users_dir):
            return

        try:
            for filename in os.listdir(self.cpanel_users_dir):
                filepath = os.path.join(self.cpanel_users_dir, filename)
                if not os.path.isfile(filepath) or filename.startswith("."):
                    continue

                account_info = {
                    "username": filename,
                    "domains": [],
                    "ip": None,
                    "plan": None,
                    "suspended": False,
                }

                try:
                    with open(filepath, "r") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("DNS="):
                                domain = line[4:].strip().lower()
                                if domain:
                                    account_info["domains"].append(domain)
                                    self.domain_to_account[domain] = filename
                            elif line.startswith("IP="):
                                ip = line[3:].strip()
                                account_info["ip"] = ip
                                if ip not in self.ip_to_domains:
                                    self.ip_to_domains[ip] = []
                                self.ip_to_domains[ip].extend(
                                    self.account_domains.get(filename, [])
                                )
                            elif line.startswith("PLAN="):
                                account_info["plan"] = line[5:].strip()
                            elif line.startswith("SUSPENDED="):
                                account_info["suspended"] = line[10:].strip() == "1"

                except (IOError, PermissionError):
                    pass

                self.accounts.append(account_info)

        except (IOError, PermissionError) as e:
            self.logger.warning(f"Cannot read {self.cpanel_users_dir}: {e}")

    def _parse_mysql_mappings(self) -> None:
        """Map MySQL users to cPanel accounts."""
        # cPanel MySQL users follow the pattern: cpaneluser_dbuser
        for account in self.accounts:
            username = account["username"]
            prefix = f"{username}_"
            self.mysql_user_to_account[username] = username
            self.mysql_user_to_account[prefix.rstrip("_")] = username

    def get_account_for_domain(self, domain: str) -> Optional[str]:
        """Look up which cPanel account owns a domain."""
        return self.domain_to_account.get(domain.lower())

    def get_account_for_mysql_user(self, mysql_user: str) -> Optional[str]:
        """Look up which cPanel account owns a MySQL user."""
        if mysql_user in self.mysql_user_to_account:
            return self.mysql_user_to_account[mysql_user]
        # Try prefix matching: cpaneluser_dbname
        if "_" in mysql_user:
            prefix = mysql_user.split("_")[0]
            return self.mysql_user_to_account.get(prefix)
        return None

    def get_domains_for_account(self, account: str) -> List[str]:
        """Get all domains for a cPanel account."""
        return self.account_domains.get(account, [])
