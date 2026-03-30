"""
Privilege Escalation Detection Rule.

ATTACKER BEHAVIOR:
  After gaining initial access (often via brute force or phishing),
  attackers try to escalate privileges:
    1. Attempt failed logins to discover accounts
    2. Use compromised credentials to execute sudo commands
    3. Lateral movement with elevated privileges

  The signature: a user who recently had failed auths now runs sudo.
  This pattern catches compromised accounts being used for priv esc.

DETECTION LOGIC:
  Track users with recent FAILED_LOGIN events.
  If a SUDO_COMMAND event occurs for a user who had failed auths
  within the lookback window → fire alert.

REAL-WORLD EQUIVALENT:
  - OSSEC rule 5402: "sudo from unknown user"
  - Wazuh: correlation rule combining auth failures with sudo
  - Sigma: linux_sudo_after_failed_auth
"""

import logging
from collections import defaultdict, deque
from datetime import datetime, timezone

from app.detection.rules.base_rule import BaseRule
from app.models.alert import create_alert

logger = logging.getLogger("mini_soc.detection.priv_escalation")


class PrivilegeEscalationRule(BaseRule):
    """
    Detects potential privilege escalation: sudo after failed authentication.

    Correlates two event types across time:
      1. FAILED_LOGIN events per user → builds "suspicion" state
      2. SUDO_COMMAND from a user in "suspicion" state → alert

    This is a correlation rule — more sophisticated than single-event rules.
    """

    def __init__(self, lookback_seconds: int = 300, min_failures: int = 1):
        self._lookback_seconds = lookback_seconds
        self._min_failures = min_failures
        # {username: deque([(timestamp, event), ...])}
        self._failed_auths = defaultdict(deque)

    @property
    def name(self) -> str:
        return "privilege_escalation"

    @property
    def description(self) -> str:
        return (
            "Detects sudo command execution by users who had "
            "recent authentication failures (potential account compromise)"
        )

    @property
    def severity(self) -> str:
        return "critical"

    def evaluate(self, event: dict) -> dict | None:
        """
        Correlate failed logins with subsequent sudo usage.

        Two-phase logic:
          Phase 1: Track FAILED_LOGIN per user (build suspicion)
          Phase 2: Check SUDO_COMMAND against suspicion window
        """
        action = event.get("action")
        user = event.get("user")

        if not user:
            return None

        event_time = self._parse_timestamp(event.get("timestamp"))

        # Phase 1: Track failed logins per user
        if action == "FAILED_LOGIN":
            self._failed_auths[user].append((event_time, event))
            # Prune old entries
            self._prune_window(user, event_time)
            return None

        # Phase 2: Check sudo commands against suspicion list
        if action == "SUDO_COMMAND":
            self._prune_window(user, event_time)
            failures = self._failed_auths.get(user, deque())

            if len(failures) >= self._min_failures:
                logger.critical(
                    f"PRIVILEGE ESCALATION DETECTED: User '{user}' "
                    f"executed sudo after {len(failures)} failed auth(s)"
                )

                # Collect evidence: failed logins + the sudo event
                failure_events = [entry[1] for entry in failures]
                evidence = failure_events + [event]

                # Clear suspicion for this user (alert fired)
                self._failed_auths[user].clear()

                return create_alert(
                    rule_name=self.name,
                    severity=self.severity,
                    source_ip=event.get("source_ip", "local"),
                    description=(
                        f"Potential privilege escalation: User '{user}' "
                        f"executed sudo command after {len(failure_events)} "
                        f"failed authentication attempt(s) within "
                        f"{self._lookback_seconds}s. "
                        f"Command: {event.get('message', 'unknown')}"
                    ),
                    evidence=evidence,
                    metadata={
                        "user": user,
                        "failed_auth_count": len(failure_events),
                        "sudo_command": event.get("message", "unknown"),
                        "lookback_seconds": self._lookback_seconds,
                    },
                )

        return None

    def _prune_window(self, user: str, current_time: datetime):
        """Remove entries outside the lookback window."""
        window = self._failed_auths.get(user)
        if not window:
            return

        cutoff = current_time.timestamp() - self._lookback_seconds
        while window and window[0][0].timestamp() < cutoff:
            window.popleft()

    def reset(self):
        """Clear all tracking state."""
        self._failed_auths.clear()

    @staticmethod
    def _parse_timestamp(ts_str: str) -> datetime:
        """Parse ISO 8601 timestamp string to datetime."""
        try:
            return datetime.fromisoformat(ts_str)
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)
