"""
Tests for web access-log parsing and the WebAttackRule.
"""

import pytest

from app.detection.rules.web_attack import WebAttackRule
from app.ingestion.access_log_parser import parse_access_log_line
from app.ingestion.normalizer import normalize_access_log


def _event(line):
    parsed = parse_access_log_line(line)
    assert parsed is not None, f"failed to parse: {line}"
    return normalize_access_log(parsed, line)


def test_parse_combined_log():
    line = ('203.0.113.10 - - [04/Jul/2026:09:14:02 +0000] '
            '"GET /path?id=1 HTTP/1.1" 200 5120 "-" "curl/8.0"')
    parsed = parse_access_log_line(line)
    assert parsed["source_ip"] == "203.0.113.10"
    assert parsed["http_method"] == "GET"
    assert parsed["path"] == "/path"
    assert parsed["query"] == "id=1"
    assert parsed["status"] == 200
    assert parsed["user_agent"] == "curl/8.0"


def test_parse_rejects_syslog():
    # A syslog line is not a valid access-log line.
    assert parse_access_log_line(
        "Mar 30 14:21:15 server01 sshd[1]: Failed password for root "
        "from 1.2.3.4 port 22 ssh2"
    ) is None


@pytest.fixture
def rule():
    return WebAttackRule()


def test_detects_sql_injection(rule):
    e = _event('1.2.3.4 - - [04/Jul/2026:09:15:41 +0000] '
               '"GET /p?id=1%20UNION%20SELECT%20pass%20FROM%20users HTTP/1.1" '
               '500 210 "-" "Mozilla/5.0"')
    alert = rule.evaluate(e)
    assert alert is not None
    assert alert["severity"] == "critical"  # SQLi bumps to critical
    assert "SQL Injection" in alert["metadata"]["categories"]


def test_detects_xss(rule):
    e = _event('1.2.3.4 - - [04/Jul/2026:09:15:43 +0000] '
               '"GET /s?q=<script>alert(1)</script> HTTP/1.1" 200 1 "-" "M"')
    alert = rule.evaluate(e)
    assert alert is not None
    assert any("XSS" in c for c in alert["metadata"]["categories"])


def test_detects_path_traversal(rule):
    e = _event('1.2.3.4 - - [04/Jul/2026:09:16:20 +0000] '
               '"GET /../../../../etc/passwd HTTP/1.1" 404 1 "-" "curl/8"')
    alert = rule.evaluate(e)
    assert alert is not None
    assert any("Traversal" in c for c in alert["metadata"]["categories"])


def test_detects_scanner_user_agent(rule):
    e = _event('1.2.3.4 - - [04/Jul/2026:09:17:01 +0000] '
               '"GET /admin HTTP/1.1" 401 1 "-" "Nikto/2.1.6"')
    alert = rule.evaluate(e)
    assert alert is not None
    assert any("Nikto" in c for c in alert["metadata"]["categories"])


def test_benign_request_no_alert(rule):
    e = _event('10.0.0.5 - - [04/Jul/2026:09:18:11 +0000] '
               '"GET /about HTTP/1.1" 200 3312 "-" "Mozilla/5.0"')
    assert rule.evaluate(e) is None


def test_rule_carries_mitre(rule):
    assert rule.mitre["technique"] == "T1190"


def test_url_encoded_payload_decoded(rule):
    # %2e%2e%2f == ../
    e = _event('1.2.3.4 - - [04/Jul/2026:09:16:20 +0000] '
               '"GET /x?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1" 404 1 "-" "M"')
    assert rule.evaluate(e) is not None
