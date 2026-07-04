"""
Web Access Log Parser (Nginx / Apache "combined" format).

Parses the near-universal combined log format emitted by Nginx and Apache:

  127.0.0.1 - - [10/Oct/2024:13:55:36 +0000] "GET /path?q=1 HTTP/1.1" 200 1234 "-" "curl/8.0"

This unlocks web-attack detection (SQLi, XSS, path traversal, scanners) on top
of the SSH/syslog pipeline — so `soc scan access.log` works out of the box for
anyone running a web server.
"""

import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

# Combined log format. The referer/user-agent quoted fields are optional so we
# also accept the "common" log format (no referer/UA).
COMBINED_LOG = re.compile(
    r'^(?P<source_ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)


def parse_access_log_line(line: str) -> dict | None:
    """
    Parse a single access-log line into a structured dict, or None if the
    line isn't in combined/common format.
    """
    line = line.strip()
    if not line:
        return None

    m = COMBINED_LOG.match(line)
    if not m:
        return None

    split = urlsplit(m.group("url"))

    return {
        "timestamp": _normalize_timestamp(m.group("timestamp")),
        "source_ip": m.group("source_ip"),
        "action": "WEB_REQUEST",
        "http_method": m.group("method"),
        "path": split.path,
        "query": split.query,
        "url": m.group("url"),
        "status": int(m.group("status")),
        "user_agent": m.group("user_agent") or "",
        "referer": m.group("referer") or "",
        # Best-effort port from the protocol; most access logs don't carry it.
        "destination_port": 443 if "https" in (m.group("proto") or "").lower() else 80,
    }


def _normalize_timestamp(raw_ts: str) -> str:
    """Convert an access-log timestamp (10/Oct/2024:13:55:36 +0000) to ISO."""
    try:
        dt = datetime.strptime(raw_ts, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc).isoformat()
    except ValueError:
        try:
            dt = datetime.strptime(raw_ts.split()[0], "%d/%b/%Y:%H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except (ValueError, IndexError):
            return raw_ts
