"""
Tests for detection rules: brute force, port scan, privilege escalation.

Each test verifies:
  1. Rule fires on expected attack patterns
  2. Rule stays silent on benign traffic
  3. Edge cases (threshold boundaries, window expiry)
"""

import pytest
from datetime import datetime, timezone, timedelta

from app.detection.rules.brute_force import BruteForceRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.priv_escalation import PrivilegeEscalationRule


def _make_event(action, source_ip, timestamp=None, user=None, port=None, message=None):
    """Helper to create test events."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "hostname": "test-server",
        "service": "sshd",
        "action": action,
        "user": user or "root",
        "destination_port": port,
        "severity": "medium",
        "raw": f"test log line: {action}",
        "message": message,
        "metadata": {},
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }


# ============================================================
# Brute Force Rule Tests
# ============================================================

class TestBruteForceRule:
    """Test brute force detection."""

    def setup_method(self):
        self.rule = BruteForceRule(threshold=5, window_seconds=60)

    def test_fires_on_threshold(self):
        """Should fire alert when failed logins reach threshold."""
        now = datetime.now(timezone.utc)
        alerts = []

        for i in range(5):
            ts = (now + timedelta(seconds=i)).isoformat()
            event = _make_event("FAILED_LOGIN", "192.168.1.100", timestamp=ts)
            alert = self.rule.evaluate(event)
            if alert:
                alerts.append(alert)

        assert len(alerts) == 1
        assert alerts[0]["rule_name"] == "brute_force_ssh"
        assert alerts[0]["severity"] == "high"
        assert alerts[0]["source_ip"] == "192.168.1.100"

    def test_no_fire_below_threshold(self):
        """Should NOT fire with fewer than threshold attempts."""
        now = datetime.now(timezone.utc)

        for i in range(4):  # Only 4, threshold is 5
            ts = (now + timedelta(seconds=i)).isoformat()
            event = _make_event("FAILED_LOGIN", "192.168.1.100", timestamp=ts)
            alert = self.rule.evaluate(event)
            assert alert is None

    def test_ignores_successful_logins(self):
        """Accepted logins should not count toward brute force."""
        now = datetime.now(timezone.utc)
        for i in range(10):
            ts = (now + timedelta(seconds=i)).isoformat()
            event = _make_event("ACCEPTED_LOGIN", "192.168.1.100", timestamp=ts)
            assert self.rule.evaluate(event) is None

    def test_window_expiry(self):
        """Failed logins outside the window should not count."""
        now = datetime.now(timezone.utc)

        # 3 events at time 0 (within window)
        for i in range(3):
            ts = now.isoformat()
            event = _make_event("FAILED_LOGIN", "192.168.1.100", timestamp=ts)
            self.rule.evaluate(event)

        # 2 events 120 seconds later (old events should have expired)
        future = now + timedelta(seconds=120)
        for i in range(2):
            ts = (future + timedelta(seconds=i)).isoformat()
            event = _make_event("FAILED_LOGIN", "192.168.1.100", timestamp=ts)
            alert = self.rule.evaluate(event)
            assert alert is None  # Should not fire (only 2 in window)

    def test_separate_ips_tracked_independently(self):
        """Different source IPs should have separate counters."""
        now = datetime.now(timezone.utc)

        # 3 from IP-A
        for i in range(3):
            ts = (now + timedelta(seconds=i)).isoformat()
            event = _make_event("FAILED_LOGIN", "10.0.0.1", timestamp=ts)
            assert self.rule.evaluate(event) is None

        # 3 from IP-B (different counter)
        for i in range(3):
            ts = (now + timedelta(seconds=i + 10)).isoformat()
            event = _make_event("FAILED_LOGIN", "10.0.0.2", timestamp=ts)
            assert self.rule.evaluate(event) is None

    def test_rearms_after_alert(self):
        """After firing, rule should reset counter and re-arm."""
        now = datetime.now(timezone.utc)

        # First burst: triggers alert
        for i in range(5):
            ts = (now + timedelta(seconds=i)).isoformat()
            event = _make_event("FAILED_LOGIN", "192.168.1.100", timestamp=ts)
            self.rule.evaluate(event)

        # Second burst: should trigger again
        alerts = []
        for i in range(5):
            ts = (now + timedelta(seconds=30 + i)).isoformat()
            event = _make_event("FAILED_LOGIN", "192.168.1.100", timestamp=ts)
            alert = self.rule.evaluate(event)
            if alert:
                alerts.append(alert)

        assert len(alerts) == 1


# ============================================================
# Port Scan Rule Tests
# ============================================================

class TestPortScanRule:
    """Test port scan detection."""

    def setup_method(self):
        self.rule = PortScanRule(threshold=10, window_seconds=30)

    def test_fires_on_threshold(self):
        """Should fire when unique ports exceed threshold."""
        now = datetime.now(timezone.utc)
        ports = [22, 80, 443, 8080, 3306, 5432, 6379, 27017, 21, 25]
        alerts = []

        for i, port in enumerate(ports):
            ts = (now + timedelta(seconds=i)).isoformat()
            event = _make_event("BLOCKED", "203.0.113.50", timestamp=ts, port=port)
            alert = self.rule.evaluate(event)
            if alert:
                alerts.append(alert)

        assert len(alerts) == 1
        assert alerts[0]["rule_name"] == "port_scan"
        assert len(alerts[0]["metadata"]["ports_scanned"]) >= 10

    def test_no_fire_below_threshold(self):
        """Should NOT fire with fewer unique ports."""
        now = datetime.now(timezone.utc)
        ports = [22, 80, 443, 8080, 3306]  # Only 5

        for i, port in enumerate(ports):
            ts = (now + timedelta(seconds=i)).isoformat()
            event = _make_event("BLOCKED", "203.0.113.50", timestamp=ts, port=port)
            assert self.rule.evaluate(event) is None

    def test_duplicate_ports_dont_count(self):
        """Same port scanned multiple times shouldn't inflate count."""
        now = datetime.now(timezone.utc)

        # Same port 15 times
        for i in range(15):
            ts = (now + timedelta(seconds=i)).isoformat()
            event = _make_event("BLOCKED", "203.0.113.50", timestamp=ts, port=22)
            assert self.rule.evaluate(event) is None

    def test_ignores_events_without_port(self):
        """Events without destination_port should be skipped."""
        event = _make_event("FAILED_LOGIN", "203.0.113.50")
        assert self.rule.evaluate(event) is None


# ============================================================
# Privilege Escalation Rule Tests
# ============================================================

class TestPrivilegeEscalationRule:
    """Test privilege escalation detection."""

    def setup_method(self):
        self.rule = PrivilegeEscalationRule(lookback_seconds=300, min_failures=1)

    def test_fires_on_sudo_after_failed_auth(self):
        """Sudo after failed login should trigger alert."""
        now = datetime.now(timezone.utc)

        # Failed login
        fail_event = _make_event(
            "FAILED_LOGIN", "10.0.0.1",
            timestamp=now.isoformat(), user="deploy"
        )
        assert self.rule.evaluate(fail_event) is None

        # Then sudo
        sudo_event = _make_event(
            "SUDO_COMMAND", None,
            timestamp=(now + timedelta(seconds=30)).isoformat(),
            user="deploy", message="/bin/bash"
        )
        alert = self.rule.evaluate(sudo_event)

        assert alert is not None
        assert alert["rule_name"] == "privilege_escalation"
        assert alert["severity"] == "critical"

    def test_no_fire_for_sudo_without_failures(self):
        """Sudo without prior failed auth should NOT trigger."""
        now = datetime.now(timezone.utc)

        sudo_event = _make_event(
            "SUDO_COMMAND", None,
            timestamp=now.isoformat(), user="admin", message="/usr/bin/apt update"
        )
        assert self.rule.evaluate(sudo_event) is None

    def test_no_fire_for_different_user(self):
        """Failed auth for user A, sudo by user B should NOT trigger."""
        now = datetime.now(timezone.utc)

        # Failed login for 'deploy'
        fail_event = _make_event(
            "FAILED_LOGIN", "10.0.0.1",
            timestamp=now.isoformat(), user="deploy"
        )
        self.rule.evaluate(fail_event)

        # Sudo by 'admin' (different user)
        sudo_event = _make_event(
            "SUDO_COMMAND", None,
            timestamp=(now + timedelta(seconds=30)).isoformat(),
            user="admin", message="/bin/bash"
        )
        assert self.rule.evaluate(sudo_event) is None

    def test_window_expiry(self):
        """Failed auth outside lookback window should NOT trigger."""
        now = datetime.now(timezone.utc)

        # Failed login 10 minutes ago (outside 300s window)
        old_fail = _make_event(
            "FAILED_LOGIN", "10.0.0.1",
            timestamp=(now - timedelta(seconds=600)).isoformat(),
            user="deploy"
        )
        self.rule.evaluate(old_fail)

        # Sudo now
        sudo_event = _make_event(
            "SUDO_COMMAND", None,
            timestamp=now.isoformat(),
            user="deploy", message="/bin/bash"
        )
        assert self.rule.evaluate(sudo_event) is None
