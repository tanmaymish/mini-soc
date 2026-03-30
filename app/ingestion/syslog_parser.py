"""
Syslog Parser.

Parses standard syslog (RFC 3164) and common auth log formats into
structured dictionaries. In production, tools like Logstash, Fluentd,
or rsyslog handle this at scale. We're implementing the core logic.

Common syslog format:
  Mar 30 14:23:45 server01 sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2

Auth log patterns we handle:
  - SSH failed/accepted login
  - sudo commands
  - Connection events with port info
"""

import re
import logging
from datetime import datetime, timezone

logger = logging.getLogger("mini_soc.ingestion.parser")

# --- Regex patterns for common log formats ---

# Standard syslog header: "Mar 30 14:23:45 hostname service[pid]:"
SYSLOG_HEADER = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

# SSH auth patterns
FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+)\s+"
    r"from\s+(?P<source_ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"port\s+(?P<port>\d+)"
)

ACCEPTED_PASSWORD = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+)\s+"
    r"from\s+(?P<source_ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"port\s+(?P<port>\d+)"
)

# Sudo usage
SUDO_COMMAND = re.compile(
    r"(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*"
    r"USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)"
)

# Generic connection with port
CONNECTION_LOG = re.compile(
    r"(?:connection|Connection)\s+from\s+(?P<source_ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?:on\s+)?port\s+(?P<port>\d+)"
)

# Firewall/iptables-style blocked connection
IPTABLES_BLOCK = re.compile(
    r"(?:BLOCKED|DROP|REJECT)\s+.*SRC=(?P<source_ip>\d+\.\d+\.\d+\.\d+)\s+"
    r".*DPT=(?P<port>\d+)"
)


def parse_syslog_line(line: str) -> dict | None:
    """
    Parse a single syslog line into a structured dictionary.

    Args:
        line: Raw syslog line.

    Returns:
        Parsed dict with fields: timestamp, hostname, service, pid,
        source_ip, user, action, destination_port, message.
        Returns None if the line cannot be parsed.
    """
    line = line.strip()
    if not line:
        return None

    # Match the syslog header first
    header_match = SYSLOG_HEADER.match(line)
    if not header_match:
        logger.debug(f"Unparseable syslog line: {line[:80]}...")
        return None

    parsed = {
        "timestamp": _normalize_timestamp(header_match.group("timestamp")),
        "hostname": header_match.group("hostname"),
        "service": header_match.group("service"),
        "pid": header_match.group("pid"),
        "source_ip": None,
        "user": None,
        "action": None,
        "destination_port": None,
        "message": header_match.group("message"),
    }

    message = header_match.group("message")

    # Try to classify the message by matching against known patterns
    if _try_failed_password(message, parsed):
        pass
    elif _try_accepted_password(message, parsed):
        pass
    elif _try_sudo_command(message, parsed):
        pass
    elif _try_connection_log(message, parsed):
        pass
    elif _try_iptables_block(message, parsed):
        pass
    else:
        # Unknown message type — still store it with generic action
        parsed["action"] = "OTHER"

    return parsed


def _try_failed_password(message: str, parsed: dict) -> bool:
    """Match failed SSH password attempts."""
    match = FAILED_PASSWORD.search(message)
    if match:
        parsed["action"] = "FAILED_LOGIN"
        parsed["user"] = match.group("user")
        parsed["source_ip"] = match.group("source_ip")
        parsed["destination_port"] = int(match.group("port"))
        return True
    return False


def _try_accepted_password(message: str, parsed: dict) -> bool:
    """Match successful SSH logins."""
    match = ACCEPTED_PASSWORD.search(message)
    if match:
        parsed["action"] = "ACCEPTED_LOGIN"
        parsed["user"] = match.group("user")
        parsed["source_ip"] = match.group("source_ip")
        parsed["destination_port"] = int(match.group("port"))
        return True
    return False


def _try_sudo_command(message: str, parsed: dict) -> bool:
    """Match sudo command executions."""
    match = SUDO_COMMAND.search(message)
    if match:
        parsed["action"] = "SUDO_COMMAND"
        parsed["user"] = match.group("user")
        parsed["source_ip"] = None  # sudo is local
        parsed["message"] = match.group("command")
        return True
    return False


def _try_connection_log(message: str, parsed: dict) -> bool:
    """Match generic connection logs with port info."""
    match = CONNECTION_LOG.search(message)
    if match:
        parsed["action"] = "CONNECTION"
        parsed["source_ip"] = match.group("source_ip")
        parsed["destination_port"] = int(match.group("port"))
        return True
    return False


def _try_iptables_block(message: str, parsed: dict) -> bool:
    """Match firewall block/drop entries."""
    match = IPTABLES_BLOCK.search(message)
    if match:
        parsed["action"] = "BLOCKED"
        parsed["source_ip"] = match.group("source_ip")
        parsed["destination_port"] = int(match.group("port"))
        return True
    return False


def _normalize_timestamp(raw_ts: str) -> str:
    """
    Convert syslog timestamp to ISO 8601 format.
    Syslog timestamps lack year, so we assume current year.
    """
    try:
        current_year = datetime.now(timezone.utc).year
        dt = datetime.strptime(f"{current_year} {raw_ts}", "%Y %b %d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        # If parsing fails, return raw timestamp
        return raw_ts
