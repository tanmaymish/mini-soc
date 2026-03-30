"""
Normalized Log Event Schema.

In production SIEMs (Splunk, QRadar), raw logs are normalized into a
Common Event Format (CEF) or OCSF schema. This lets detection rules
work against a consistent structure regardless of the log source.

Our schema is inspired by CEF but simplified for clarity.
"""

from datetime import datetime, timezone


def create_log_event(
    raw_log: str,
    timestamp: str = None,
    source_ip: str = None,
    hostname: str = None,
    service: str = None,
    action: str = None,
    user: str = None,
    destination_port: int = None,
    severity: str = "info",
    metadata: dict = None,
) -> dict:
    """
    Create a normalized log event dictionary.

    Args:
        raw_log: Original log line (preserved for forensics).
        timestamp: ISO 8601 timestamp of the event.
        source_ip: IP address of the source (attacker or client).
        hostname: Hostname that generated the log.
        service: Service name (e.g., sshd, httpd, sudo).
        action: Normalized action (FAILED_LOGIN, ACCEPTED_LOGIN,
                CONNECTION, SUDO_COMMAND, etc.).
        user: Username involved in the event.
        destination_port: Target port (relevant for port scan detection).
        severity: Event severity — info, low, medium, high, critical.
        metadata: Additional key-value pairs for extensibility.

    Returns:
        Normalized event dictionary ready for detection and storage.
    """
    return {
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "hostname": hostname,
        "service": service,
        "action": action,
        "user": user,
        "destination_port": destination_port,
        "severity": severity,
        "raw": raw_log,
        "metadata": metadata or {},
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }
