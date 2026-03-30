"""
Tests for the log ingestion module: syslog parsing and normalization.
"""

import pytest
from app.ingestion.syslog_parser import parse_syslog_line
from app.ingestion.normalizer import normalize_parsed_log, normalize_json_event


# ============================================================
# Syslog Parser Tests
# ============================================================

class TestSyslogParser:
    """Test syslog line parsing."""

    def test_parse_failed_ssh_login(self):
        """Standard SSH failed password log line."""
        line = "Mar 30 14:21:15 server01 sshd[12341]: Failed password for root from 192.168.1.100 port 22 ssh2"
        result = parse_syslog_line(line)

        assert result is not None
        assert result["hostname"] == "server01"
        assert result["service"] == "sshd"
        assert result["action"] == "FAILED_LOGIN"
        assert result["user"] == "root"
        assert result["source_ip"] == "192.168.1.100"
        assert result["destination_port"] == 22

    def test_parse_accepted_ssh_login(self):
        """Successful SSH login."""
        line = "Mar 30 14:20:01 server01 sshd[12340]: Accepted password for admin from 10.0.0.50 port 22 ssh2"
        result = parse_syslog_line(line)

        assert result is not None
        assert result["action"] == "ACCEPTED_LOGIN"
        assert result["user"] == "admin"
        assert result["source_ip"] == "10.0.0.50"

    def test_parse_invalid_user_login(self):
        """SSH failed login with 'invalid user' prefix."""
        line = "Mar 30 14:21:20 server01 sshd[12346]: Failed password for invalid user test from 192.168.1.100 port 22 ssh2"
        result = parse_syslog_line(line)

        assert result is not None
        assert result["action"] == "FAILED_LOGIN"
        assert result["user"] == "test"

    def test_parse_sudo_command(self):
        """Sudo command execution."""
        line = "Mar 30 14:23:00 server01 sudo[12350]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
        result = parse_syslog_line(line)

        assert result is not None
        assert result["action"] == "SUDO_COMMAND"
        assert result["user"] == "deploy"
        assert "/bin/bash" in result["message"]

    def test_parse_firewall_block(self):
        """Iptables-style firewall block entry."""
        line = "Mar 30 10:00:01 firewall01 kernel: BLOCKED IN=eth0 SRC=203.0.113.50 DST=10.0.0.1 DPT=22 PROTO=TCP"
        result = parse_syslog_line(line)

        assert result is not None
        assert result["action"] == "BLOCKED"
        assert result["source_ip"] == "203.0.113.50"
        assert result["destination_port"] == 22

    def test_parse_empty_line(self):
        """Empty lines should return None."""
        assert parse_syslog_line("") is None
        assert parse_syslog_line("   ") is None

    def test_parse_malformed_line(self):
        """Non-syslog content should return None."""
        assert parse_syslog_line("this is not a syslog line") is None
        assert parse_syslog_line("random garbage 12345") is None

    def test_parse_connection_log(self):
        """Generic connection log with port info."""
        line = "Mar 30 10:05:00 webserver01 httpd[5432]: connection from 10.0.0.100 on port 443"
        result = parse_syslog_line(line)

        assert result is not None
        assert result["action"] == "CONNECTION"
        assert result["source_ip"] == "10.0.0.100"
        assert result["destination_port"] == 443

    def test_timestamp_normalization(self):
        """Ensure timestamp is converted to ISO 8601."""
        line = "Mar 30 14:21:15 server01 sshd[12341]: Failed password for root from 192.168.1.100 port 22 ssh2"
        result = parse_syslog_line(line)

        # Should contain ISO format markers
        assert "T" in result["timestamp"]
        assert ":" in result["timestamp"]


# ============================================================
# Normalizer Tests
# ============================================================

class TestNormalizer:
    """Test log normalization."""

    def test_normalize_parsed_log(self):
        """Normalization produces correct schema."""
        parsed = {
            "timestamp": "2026-03-30T14:21:15+00:00",
            "hostname": "server01",
            "service": "sshd",
            "pid": "12341",
            "source_ip": "192.168.1.100",
            "user": "root",
            "action": "FAILED_LOGIN",
            "destination_port": 22,
            "message": "Failed password...",
        }
        raw = "Mar 30 14:21:15 server01 sshd[12341]: Failed password for root from 192.168.1.100 port 22 ssh2"

        event = normalize_parsed_log(parsed, raw)

        assert event is not None
        assert event["action"] == "FAILED_LOGIN"
        assert event["severity"] == "medium"
        assert event["source_ip"] == "192.168.1.100"
        assert event["raw"] == raw
        assert "ingested_at" in event

    def test_normalize_null_parsed(self):
        """None input should return None."""
        assert normalize_parsed_log(None, "raw") is None

    def test_normalize_json_event(self):
        """JSON event normalization."""
        data = {
            "source_ip": "10.0.0.1",
            "action": "failed_login",
            "user": "admin",
            "hostname": "server01",
        }
        event = normalize_json_event(data)

        assert event is not None
        assert event["action"] == "FAILED_LOGIN"  # uppercased
        assert event["source_ip"] == "10.0.0.1"

    def test_severity_assignment(self):
        """Verify severity mapping by action type."""
        cases = {
            "FAILED_LOGIN": "medium",
            "ACCEPTED_LOGIN": "info",
            "SUDO_COMMAND": "high",
            "CONNECTION": "low",
            "BLOCKED": "medium",
            "OTHER": "info",
        }
        for action, expected_severity in cases.items():
            parsed = {"action": action}
            event = normalize_parsed_log(parsed, "test")
            assert event["severity"] == expected_severity, (
                f"Action {action} should have severity {expected_severity}"
            )
