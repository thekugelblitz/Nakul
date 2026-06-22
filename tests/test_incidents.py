"""Tests for incident engine and deduplication."""

import pytest
from nakul.incidents.dedup import DedupManager
from nakul.incidents.rules import get_all_rules, get_enabled_rules, get_rule


class TestDedupManager:
    """Tests for deduplication manager."""

    def setup_method(self):
        self.dedup = DedupManager(cooldown_seconds=5)

    def test_build_fingerprint(self):
        fp1 = self.dedup.build_fingerprint("rule1", account="user1")
        fp2 = self.dedup.build_fingerprint("rule1", account="user1")
        fp3 = self.dedup.build_fingerprint("rule1", account="user2")

        assert fp1 == fp2  # Same inputs = same fingerprint
        assert fp1 != fp3  # Different account = different fingerprint

    def test_should_create_first_time(self):
        fp = self.dedup.build_fingerprint("rule1", account="user1")
        assert self.dedup.should_create(fp) is True

    def test_should_not_create_in_cooldown(self):
        fp = self.dedup.build_fingerprint("rule1", account="user1")
        self.dedup.record_creation(fp)

        assert self.dedup.should_create(fp) is False

    def test_reset_fingerprint(self):
        fp = self.dedup.build_fingerprint("rule1", account="user1")
        self.dedup.record_creation(fp)
        self.dedup.reset(fp)

        assert self.dedup.should_create(fp) is True

    def test_reset_all(self):
        fp1 = self.dedup.build_fingerprint("rule1", account="user1")
        fp2 = self.dedup.build_fingerprint("rule2", account="user2")
        self.dedup.record_creation(fp1)
        self.dedup.record_creation(fp2)
        self.dedup.reset()

        assert self.dedup.should_create(fp1) is True
        assert self.dedup.should_create(fp2) is True

    def test_active_cooldowns(self):
        assert self.dedup.active_cooldowns == 0
        fp = self.dedup.build_fingerprint("rule1")
        self.dedup.record_creation(fp)
        assert self.dedup.active_cooldowns == 1


class TestAlertRules:
    """Tests for alert rules configuration."""

    def test_rules_exist(self):
        rules = get_all_rules()
        assert len(rules) > 0

    def test_all_rules_have_required_fields(self):
        for rule_id, rule in get_all_rules().items():
            assert "name" in rule, f"Rule {rule_id} missing 'name'"
            assert "enabled" in rule, f"Rule {rule_id} missing 'enabled'"
            assert "categories" in rule, f"Rule {rule_id} missing 'categories'"
            assert "severity" in rule, f"Rule {rule_id} missing 'severity'"
            assert "remediation" in rule, f"Rule {rule_id} missing 'remediation'"

    def test_get_rule_by_id(self):
        rule = get_rule("http_500_spike")
        assert rule is not None
        assert rule["name"] == "HTTP 500 Error Spike"

    def test_get_nonexistent_rule(self):
        rule = get_rule("nonexistent_rule_xyz")
        assert rule is None

    def test_enabled_rules(self):
        enabled = get_enabled_rules()
        for rule_id, rule in enabled.items():
            assert rule.get("enabled", True) is True

    def test_critical_rules_exist(self):
        """Ensure key security rules are defined."""
        rules = get_all_rules()
        critical_rules = [
            "brute_force_login", "malware_detection", "oom_kill",
            "backup_failure", "mysql_connection_limit",
        ]
        for rule_id in critical_rules:
            assert rule_id in rules, f"Critical rule '{rule_id}' is missing"
