"""
Account Mapper
===============

Maps IPs, domains, MySQL users, and process owners
to cPanel accounts using collected cPanel data.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("nakul.correlation.account_mapper")


class AccountMapper:
    """
    Provides lookup functions to map various entities
    to their owning cPanel accounts.
    """

    def __init__(self):
        self.domain_to_account: Dict[str, str] = {}
        self.account_domains: Dict[str, List[str]] = {}
        self.mysql_user_to_account: Dict[str, str] = {}
        self.ip_to_domains: Dict[str, List[str]] = {}
        self.accounts: List[Dict[str, Any]] = []
        self._loaded = False

    def update_from_cpanel_data(self, cpanel_data: Dict[str, Any]) -> None:
        """Update mappings from cPanel collector output."""
        if not cpanel_data:
            return

        self.domain_to_account = cpanel_data.get("domain_to_account", {})
        self.account_domains = cpanel_data.get("account_domains", {})
        self.mysql_user_to_account = cpanel_data.get("mysql_user_to_account", {})
        self.accounts = cpanel_data.get("accounts", [])
        self._loaded = True

        logger.info(
            f"Account mapper updated: {len(self.domain_to_account)} domains, "
            f"{len(self.accounts)} accounts"
        )

    def get_account_for_domain(self, domain: str) -> Optional[str]:
        """Resolve domain to cPanel account."""
        return self.domain_to_account.get(domain.lower())

    def get_account_for_mysql_user(self, mysql_user: str) -> Optional[str]:
        """Resolve MySQL user to cPanel account."""
        if mysql_user in self.mysql_user_to_account:
            return self.mysql_user_to_account[mysql_user]
        # Try prefix: cpaneluser_dbname
        if "_" in mysql_user:
            prefix = mysql_user.split("_")[0]
            if prefix in self.mysql_user_to_account:
                return self.mysql_user_to_account[prefix]
            # Check if prefix matches an account name
            for acct in self.accounts:
                if acct.get("username") == prefix:
                    return prefix
        return None

    def get_account_for_process_user(self, username: str) -> Optional[str]:
        """Resolve Linux process username to cPanel account."""
        for acct in self.accounts:
            if acct.get("username") == username:
                return username
        return None

    def get_domains_for_account(self, account: str) -> List[str]:
        """Get all domains for a cPanel account."""
        return self.account_domains.get(account, [])

    def is_loaded(self) -> bool:
        """Check if account data has been loaded."""
        return self._loaded
