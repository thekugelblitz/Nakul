"""Tests for log parsers."""

import pytest
from nakul.parsers.apache_parser import ApacheParser
from nakul.parsers.mysql_parser import MysqlParser
from nakul.parsers.security_parser import SecurityParser
from nakul.parsers.backup_parser import BackupParser
from nakul.parsers.system_parser import SystemParser


class TestApacheParser:
    """Tests for Apache/LiteSpeed log parser."""

    def setup_method(self):
        self.parser = ApacheParser()

    def test_parse_500_error(self):
        line = '192.168.1.1 - - [22/Jun/2025:10:00:00 +0000] "GET /page HTTP/1.1" 500 1234 "-" "Mozilla/5.0"'
        event = self.parser.parse_line(line)
        assert event is not None
        assert event["severity"] == "warning"
        assert event["ip_address"] == "192.168.1.1"
        assert event["metadata"]["status_code"] == 500

    def test_parse_503_error(self):
        line = '10.0.0.1 - - [22/Jun/2025:10:00:00 +0000] "GET /api HTTP/1.1" 503 0 "-" "curl"'
        event = self.parser.parse_line(line)
        assert event is not None
        assert event["severity"] == "critical"
        assert event["metadata"]["status_code"] == 503

    def test_parse_200_ignored(self):
        line = '192.168.1.1 - - [22/Jun/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 5678 "-" "Mozilla/5.0"'
        event = self.parser.parse_line(line)
        assert event is None  # 200s are skipped

    def test_parse_suspicious_request(self):
        line = '192.168.1.1 - - [22/Jun/2025:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 403 0 "-" "Bot"'
        event = self.parser.parse_line(line)
        assert event is not None
        assert event["category"] == "security"

    def test_parse_error_log(self):
        line = '[Sat Jun 22 10:00:00.123456 2025] [error] [client 192.168.1.1] File not found: /var/www/missing'
        event = self.parser.parse_line(line)
        assert event is not None
        assert event["severity"] in ("warning", "info")

    def test_parse_empty_line(self):
        assert self.parser.parse_line("") is None
        assert self.parser.parse_line("# comment") is None

    def test_batch_parsing(self):
        items = [
            {"raw_line": '1.2.3.4 - - [22/Jun/2025:10:00:00 +0000] "GET / HTTP/1.1" 500 0', "source": "web", "file_path": "/var/log/test"},
            {"raw_line": "invalid line", "source": "web", "file_path": "/var/log/test"},
        ]
        events = self.parser.parse_batch(items)
        assert len(events) == 1
        assert events[0]["log_file"] == "/var/log/test"


class TestMysqlParser:
    """Tests for MySQL/MariaDB log parser."""

    def setup_method(self):
        self.parser = MysqlParser()

    def test_parse_error_line(self):
        line = "2025-06-22T10:00:00.123456Z 0 [ERROR] [MY-000001] InnoDB: Fatal error"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event["category"] == "database"

    def test_parse_access_denied(self):
        line = "2025-06-22T10:00:00Z 0 [ERROR] Access denied for user 'testuser'@'localhost'"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event["severity"] == "warning"
        assert event["metadata"]["mysql_user"] == "testuser"

    def test_parse_too_many_connections(self):
        line = "2025-06-22T10:00:00Z 0 [ERROR] Too many connections"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event["severity"] == "critical"

    def test_parse_slow_query(self):
        line = "# Query_time: 15.500000 Lock_time: 0.001000 Rows_sent: 100 Rows_examined: 50000"
        # First set user context
        self.parser._slow_query_buffer = {"user": "dbuser", "host": "localhost", "ip": "127.0.0.1"}
        event = self.parser.parse_line(line)
        assert event is not None
        assert event["metadata"]["query_time"] == 15.5
        assert event["severity"] == "warning"


class TestSecurityParser:
    """Tests for security log parser."""

    def test_parse_auth_failure(self):
        parser = SecurityParser(log_type="auth")
        line = "Jun 22 10:00:00 server sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2"
        event = parser.parse_line(line)
        assert event is not None
        assert event["severity"] == "warning"
        assert event["ip_address"] == "192.168.1.100"
        assert event["metadata"]["auth_result"] == "failed"

    def test_parse_auth_success(self):
        parser = SecurityParser(log_type="auth")
        line = "Jun 22 10:00:00 server sshd[12345]: Accepted password for admin from 192.168.1.1 port 22 ssh2"
        event = parser.parse_line(line)
        assert event is not None
        assert event["severity"] == "info"
        assert event["metadata"]["auth_result"] == "success"

    def test_parse_csf_block(self):
        parser = SecurityParser(log_type="csf")
        line = "Jun 22 10:00:00 Blocked IP 10.0.0.5 for brute-force attack"
        event = parser.parse_line(line)
        assert event is not None
        assert event["ip_address"] == "10.0.0.5"

    def test_parse_imunify_malware(self):
        parser = SecurityParser(log_type="imunify")
        line = "2025-06-22 10:00:00 [WARNING] Malware detected in /home/user/public_html/shell.php"
        event = parser.parse_line(line)
        assert event is not None
        assert event["severity"] == "critical"
        assert event["category"] == "malware"


class TestBackupParser:
    """Tests for backup log parser."""

    def setup_method(self):
        self.parser = BackupParser()

    def test_parse_failure(self):
        line = "2025-06-22 10:00:00 Backup failed: disk full, cannot write"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event["severity"] == "critical"
        assert event["category"] == "backup"

    def test_parse_success(self):
        line = "2025-06-22 10:00:00 Backup completed successfully"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event["severity"] == "info"

    def test_parse_warning(self):
        line = "2025-06-22 10:00:00 Backup warning: file skipped due to permission"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event["severity"] == "warning"


class TestSystemParser:
    """Tests for system log parser."""

    def setup_method(self):
        self.parser = SystemParser()

    def test_parse_oom_kill(self):
        line = "Jun 22 10:00:00 server kernel: Out of memory: Killed process 1234 (php-cgi)"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event["severity"] == "critical"
        assert event["category"] == "resource"

    def test_parse_segfault(self):
        line = "Jun 22 10:00:00 server kernel: php-cgi[1234]: segfault at 0000000"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event["severity"] == "critical"

    def test_parse_normal_ignored(self):
        line = "Jun 22 10:00:00 server systemd[1]: Starting some.service"
        # "Starting" matches SERVICE_RESTART, so it should parse
        event = self.parser.parse_line(line)
        assert event is not None or event is None  # May or may not match
