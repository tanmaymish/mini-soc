"""
Brute Force Detection Rule.

ATTACKER BEHAVIOR:
  Attackers use tools like Hydra, Medusa, or custom scripts to try thousands
  of username/password combos against SSH, RDP, or web logins. The signature
  is many failed login attempts from the same IP in a short window.

DETECTION LOGIC:
  Track failed login counts per source IP using a sliding time window.
  When a single IP exceeds the threshold within the window → fire alert.

REAL-WORLD EQUIVALENT:
  - Fail2ban (Linux): Bans IPs after N failed attempts
  - Splunk: `source=auth.log "Failed password" | stats count by src_ip | where count > 5`
  - Sigma rule: win_security_susp_failed_logons
"""

import logging
from collections import defaultdict, deque
from datetime import datetime, timezone

from app.detection.rules.base_rule import BaseRule
from app.models.alert import create_alert

logger = logging.getLogger("mini_soc.detection.brute_force")


class BruteForceRule(BaseRule):
    """
    Detects brute force login attempts via sliding window counting.

    Uses a deque per source IP to track timestamps of failed logins.
    Expired entries are pruned on each evaluation (lazy cleanup).
    """

    def __init__(self, threshold: int = 5, window_seconds: int = 60):
        self._threshold = threshold
        self._window_seconds = window_seconds
        # {source_ip: deque([(timestamp, event), ...])}
        self._failed_attempts = defaultdict(deque)

    @property
    def name(self) -> str:
        return "brute_force_ssh"

    @property
    def description(self) -> str:
        return (
            f"Detects {self._threshold}+ failed login attempts from the "
            f"same IP within {self._window_seconds} seconds"
        )

    @property
    def severity(self) -> str:
        return "high"

    def evaluate(self, event: dict) -> dict | None:
        """
        Check if this event contributes to a brute force pattern.

        Only considers FAILED_LOGIN events. Tracks per-IP sliding window.
        Fires alert when threshold is crossed, then resets that IP's counter
        to avoid duplicate alerts for the same attack burst.
        """
        # Only care about failed logins
        if event.get("action") != "FAILED_LOGIN":
            return None

        source_ip = event.get("source_ip")
        if not source_ip:
            return None

        # Parse event timestamp
        event_time = self._parse_timestamp(event.get("timestamp"))
        window = self._failed_attempts[source_ip]

        # Add current event
        window.append((event_time, event))

        # Prune events outside the window
        cutoff = event_time.timestamp() - self._window_seconds
        while window and window[0][0].timestamp() < cutoff:
            window.popleft()

        # Check threshold
        if len(window) >= self._threshold:
            logger.warning(
                f"BRUTE FORCE DETECTED: {source_ip} — "
                f"{len(window)} failed logins in {self._window_seconds}s"
            )

            # Collect evidence (the triggering events)
            evidence = [entry[1] for entry in window]

            # Reset to avoid duplicate alerts for same burst
            # (re-arms for next attack wave)
            window.clear()

            return create_alert(
                rule_name=self.name,
                severity=self.severity,
                source_ip=source_ip,
                description=(
                    f"Brute force attack detected: {len(evidence)} failed "
                    f"login attempts from {source_ip} within "
                    f"{self._window_seconds} seconds. "
                    f"Targeted user(s): "
                    f"{', '.join(set(e.get('user', '?') for e in evidence))}"
                ),
                evidence=evidence,
                metadata={
                    "attempt_count": len(evidence),
                    "window_seconds": self._window_seconds,
                    "targeted_users": list(
                        set(e.get("user", "unknown") for e in evidence)
                    ),
                },
            )

        return None

    def reset(self):
        """Clear all tracking state."""
        self._failed_attempts.clear()

    @staticmethod
    def _parse_timestamp(ts_str: str) -> datetime:
        """Parse ISO 8601 timestamp string to datetime."""
        try:
            return datetime.fromisoformat(ts_str)
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)
