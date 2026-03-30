"""
End-to-end pipeline tests: raw log → parse → normalize → detect → alert.

Tests the full flow without MongoDB (detection engine only).
"""

import pytest
from datetime import datetime, timezone, timedelta

from app.ingestion.syslog_parser import parse_syslog_line
from app.ingestion.normalizer import normalize_parsed_log
from app.detection.engine import DetectionEngine


class TestFullPipeline:
    """Test the complete ingestion → detection pipeline."""

    def setup_method(self):
        """Fresh engine per test."""
        self.engine = DetectionEngine({
            "BRUTE_FORCE_THRESHOLD": 5,
            "BRUTE_FORCE_WINDOW_SECONDS": 60,
            "PORT_SCAN_THRESHOLD": 10,
            "PORT_SCAN_WINDOW_SECONDS": 30,
        })

    def _process_log(self, log_line: str) -> list:
        """Helper: push a log line through the entire pipeline."""
        parsed = parse_syslog_line(log_line)
        if parsed is None:
            return []
        event = normalize_parsed_log(parsed, log_line)
        if event is None:
            return []
        return self.engine.evaluate(event)

    def test_brute_force_pipeline(self):
        """Full pipeline: 6 failed SSH logins → brute force alert."""
        now = datetime.now(timezone.utc)
        all_alerts = []

        for i in range(6):
            ts = (now + timedelta(seconds=i)).strftime("%b %d %H:%M:%S")
            line = (
                f"{ts} server01 sshd[{12340 + i}]: "
                f"Failed password for root from 192.168.1.100 port 22 ssh2"
            )
            alerts = self._process_log(line)
            all_alerts.extend(alerts)

        assert len(all_alerts) == 1
        assert all_alerts[0]["rule_name"] == "brute_force_ssh"
        assert all_alerts[0]["source_ip"] == "192.168.1.100"

    def test_port_scan_pipeline(self):
        """Full pipeline: 11 unique ports → port scan alert."""
        now = datetime.now(timezone.utc)
        ports = [22, 80, 443, 8080, 3306, 5432, 6379, 27017, 21, 25, 110]
        all_alerts = []

        for i, port in enumerate(ports):
            ts = (now + timedelta(seconds=i)).strftime("%b %d %H:%M:%S")
            line = (
                f"{ts} firewall01 kernel: "
                f"BLOCKED IN=eth0 SRC=203.0.113.50 "
                f"DST=10.0.0.1 DPT={port} PROTO=TCP"
            )
            alerts = self._process_log(line)
            all_alerts.extend(alerts)

        assert len(all_alerts) == 1
        assert all_alerts[0]["rule_name"] == "port_scan"

    def test_priv_escalation_pipeline(self):
        """Full pipeline: failed login + sudo → priv esc alert."""
        now = datetime.now(timezone.utc)
        all_alerts = []

        # Failed login for 'deploy'
        ts1 = now.strftime("%b %d %H:%M:%S")
        line1 = (
            f"{ts1} server01 sshd[12500]: "
            f"Failed password for deploy from 10.20.30.40 port 22 ssh2"
        )
        all_alerts.extend(self._process_log(line1))

        # Sudo by 'deploy'
        ts2 = (now + timedelta(seconds=30)).strftime("%b %d %H:%M:%S")
        line2 = (
            f"{ts2} server01 sudo[12510]: "
            f"deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; "
            f"COMMAND=/bin/bash"
        )
        all_alerts.extend(self._process_log(line2))

        assert len(all_alerts) == 1
        assert all_alerts[0]["rule_name"] == "privilege_escalation"
        assert all_alerts[0]["severity"] == "critical"

    def test_benign_traffic_no_alerts(self):
        """Normal activity should produce zero alerts."""
        now = datetime.now(timezone.utc)

        benign_lines = [
            f"{now.strftime('%b %d %H:%M:%S')} server01 sshd[9000]: Accepted password for admin from 10.0.0.50 port 22 ssh2",
            f"{now.strftime('%b %d %H:%M:%S')} server01 sshd[9001]: Accepted publickey for devops from 10.0.0.51 port 22 ssh2",
            f"{(now + timedelta(minutes=5)).strftime('%b %d %H:%M:%S')} server01 sshd[9002]: Failed password for root from 10.0.0.52 port 22 ssh2",
        ]

        for line in benign_lines:
            alerts = self._process_log(line)
            assert len(alerts) == 0, f"False positive on: {line}"

    def test_engine_stats(self):
        """Verify engine tracks processing stats."""
        now = datetime.now(timezone.utc)

        for i in range(3):
            ts = (now + timedelta(seconds=i)).strftime("%b %d %H:%M:%S")
            line = (
                f"{ts} server01 sshd[1234{i}]: "
                f"Failed password for root from 10.0.0.1 port 22 ssh2"
            )
            self._process_log(line)

        stats = self.engine.get_stats()
        assert stats["events_processed"] == 3
        assert stats["rules_loaded"] == 3
