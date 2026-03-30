"""
Port Scan Detection Rule.

ATTACKER BEHAVIOR:
  Before exploiting a system, attackers run port scans (Nmap, Masscan, Zmap)
  to discover open services. The signature is one IP connecting to many
  different ports on the same host in a short burst. Common scan types:
    - SYN scan: sends SYN packets, checks for SYN-ACK
    - Connect scan: full TCP handshake
    - Service scan: Banner grabbing after connection

DETECTION LOGIC:
  Track unique destination ports per source IP within a sliding window.
  When distinct port count exceeds threshold → fire alert.

REAL-WORLD EQUIVALENT:
  - Snort/Suricata: sfPortscan preprocessor
  - Splunk: `stats dc(dest_port) by src_ip | where dc_dest_port > 10`
  - Zeek (Bro): scan detection script
"""

import logging
from collections import defaultdict, deque
from datetime import datetime, timezone

from app.detection.rules.base_rule import BaseRule
from app.models.alert import create_alert

logger = logging.getLogger("mini_soc.detection.port_scan")


class PortScanRule(BaseRule):
    """
    Detects port scanning by tracking unique destination ports per source IP.

    Uses a sliding window with a set of unique ports per IP.
    When port count crosses threshold → alert.
    """

    def __init__(self, threshold: int = 10, window_seconds: int = 30):
        self._threshold = threshold
        self._window_seconds = window_seconds
        # {source_ip: deque([(timestamp, port, event), ...])}
        self._connections = defaultdict(deque)

    @property
    def name(self) -> str:
        return "port_scan"

    @property
    def description(self) -> str:
        return (
            f"Detects connections to {self._threshold}+ distinct ports "
            f"from the same IP within {self._window_seconds} seconds"
        )

    @property
    def severity(self) -> str:
        return "high"

    def evaluate(self, event: dict) -> dict | None:
        """
        Check if this connection contributes to a port scan pattern.

        Considers events with a destination_port (CONNECTION, BLOCKED,
        FAILED_LOGIN on different ports).
        """
        # Need a destination port to track
        dest_port = event.get("destination_port")
        if dest_port is None:
            return None

        source_ip = event.get("source_ip")
        if not source_ip:
            return None

        event_time = self._parse_timestamp(event.get("timestamp"))
        window = self._connections[source_ip]

        # Add current connection
        window.append((event_time, dest_port, event))

        # Prune events outside the window
        cutoff = event_time.timestamp() - self._window_seconds
        while window and window[0][0].timestamp() < cutoff:
            window.popleft()

        # Count unique ports in the current window
        unique_ports = set(entry[1] for entry in window)

        if len(unique_ports) >= self._threshold:
            logger.warning(
                f"PORT SCAN DETECTED: {source_ip} — "
                f"{len(unique_ports)} unique ports in {self._window_seconds}s"
            )

            evidence = [entry[2] for entry in window]

            # Reset to re-arm
            window.clear()

            return create_alert(
                rule_name=self.name,
                severity=self.severity,
                source_ip=source_ip,
                description=(
                    f"Port scan detected: {source_ip} connected to "
                    f"{len(unique_ports)} unique ports within "
                    f"{self._window_seconds} seconds. "
                    f"Ports: {sorted(unique_ports)}"
                ),
                evidence=evidence,
                metadata={
                    "unique_port_count": len(unique_ports),
                    "ports_scanned": sorted(unique_ports),
                    "window_seconds": self._window_seconds,
                },
            )

        return None

    def reset(self):
        """Clear all tracking state."""
        self._connections.clear()

    @staticmethod
    def _parse_timestamp(ts_str: str) -> datetime:
        """Parse ISO 8601 timestamp string to datetime."""
        try:
            return datetime.fromisoformat(ts_str)
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)
