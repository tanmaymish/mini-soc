"""
Tests for the `soc` command-line interface.

The CLI runs the real detection engine offline against log files, so these
tests double as an end-to-end check that scan/ip/demo behave correctly
without any database or server.
"""

import io
import json
from contextlib import redirect_stdout

import pytest

from cli.soc import main


def _run(argv):
    """Run the CLI, capturing stdout and the exit code."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(argv)
    return code, buf.getvalue()


def test_scan_flags_brute_force(tmp_path):
    log = tmp_path / "auth.log"
    lines = [
        f"Mar 30 14:21:1{i} server01 sshd[{12341+i}]: "
        f"Failed password for root from 192.168.1.100 port 22 ssh2"
        for i in range(6)
    ]
    log.write_text("\n".join(lines) + "\n")

    code, out = _run(["scan", str(log), "--quiet"])
    assert code == 1  # threats found → nonzero exit
    assert "THREAT" in out
    assert "brute_force_ssh" in out
    assert "192.168.1.100" in out


def test_scan_clean_log(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Mar 30 14:20:01 server01 sshd[100]: "
        "Accepted password for admin from 10.0.0.50 port 22 ssh2\n"
    )
    code, out = _run(["scan", str(log), "--quiet"])
    assert code == 0  # clean → zero exit
    assert "No threats detected" in out


def test_scan_json_is_valid(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Mar 30 14:20:01 server01 sshd[100]: "
        "Failed password for root from 10.9.9.9 port 22 ssh2\n"
    )
    _, out = _run(["scan", str(log), "--json"])
    doc = json.loads(out)  # raises if not valid JSON
    assert doc["events_parsed"] == 1
    assert "alerts" in doc


def test_scan_missing_file_returns_error():
    code, out = _run(["scan", "/no/such/file.log", "--quiet"])
    assert code == 2
    assert "not found" in out


def test_ip_malicious_lookup():
    code, out = _run(["ip", "185.220.101.1"])
    assert code == 1  # malicious → nonzero
    assert "MALICIOUS" in out
    assert "TOR_EXIT_NODE" in out


def test_ip_clean_lookup_json():
    code, out = _run(["ip", "8.8.8.8", "--json"])
    assert code == 0
    doc = json.loads(out)
    assert doc["ip"] == "8.8.8.8"
    assert doc["reputation_score"] == 0


def test_demo_generates_alerts():
    code, out = _run(["demo", "--quiet"])
    assert code == 0
    assert "alert(s) generated" in out
    assert "threat_intel_match" in out


def test_scan_web_access_log(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(
        '45.1.2.3 - - [04/Jul/2026:09:15:41 +0000] '
        '"GET /p?id=1%20UNION%20SELECT%20x HTTP/1.1" 500 1 "-" "sqlmap/1.7"\n'
    )
    code, out = _run(["scan", str(log), "--quiet"])
    assert code == 1
    assert "web_attack" in out
    assert "T1190" in out  # MITRE technique shown


def test_report_writes_html(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(
        '45.1.2.3 - - [04/Jul/2026:09:15:41 +0000] '
        '"GET /p?id=1%20UNION%20SELECT%20x HTTP/1.1" 500 1 "-" "sqlmap/1.7"\n'
    )
    out_html = tmp_path / "report.html"
    code, _ = _run(["report", str(log), "-o", str(out_html)])
    assert code == 0
    html = out_html.read_text()
    assert html.startswith("<!doctype html>")
    assert "web_attack" in html
    assert "T1190" in html
    # Self-contained: no external resource fetches.
    assert "src=\"http" not in html and "href=\"http" not in html


def test_mitre_stamped_on_alerts(tmp_path):
    log = tmp_path / "auth.log"
    lines = [
        f"Mar 30 14:21:1{i} server01 sshd[{12341+i}]: "
        f"Failed password for root from 192.168.1.100 port 22 ssh2"
        for i in range(6)
    ]
    log.write_text("\n".join(lines) + "\n")
    _, out = _run(["scan", str(log), "--quiet"])
    assert "T1110" in out  # brute force ATT&CK technique
