"""
Admin Endpoint Abuse Rule.

ATTACKER BEHAVIOR:
  The admin control plane is the crown jewel. Attackers probe `/api/admin/*`
  with stolen or low-privilege tokens (broken access control / IDOR), or
  brute a path hoping for an auth-bypass. Two tells:
    1. Repeated 401/403 on admin routes  → unauthorized access attempts.
    2. A 2xx on an admin route from a non-admin role → privilege escalation /
       broken access control (the request should never have succeeded).

DETECTION LOGIC:
  Stateful per source IP over a short window for the failed-probe case;
  single-event for the successful-but-unauthorized case.

REAL-WORLD EQUIVALENT:
  - OWASP API Security Top 10 — API1 (BOLA) & API5 (BFLA)
  - Datadog "Unauthorized access to admin endpoint" signals
"""

from collections import defaultdict, deque
from datetime import datetime, timezone

from app.detection.rules.base_rule import BaseRule
from app.models.alert import create_alert
from app.detection.api_map import is_admin


class AdminAbuseRule(BaseRule):
    def __init__(self, fail_threshold: int = 3, window_seconds: int = 120):
        self._fail_threshold = fail_threshold
        self._window = window_seconds
        self._fails = defaultdict(deque)  # ip -> deque[(ts, event)]

    @property
    def name(self) -> str:
        return "admin_endpoint_abuse"

    @property
    def description(self) -> str:
        return (
            "Detects abuse of the admin control plane: repeated unauthorized "
            "access attempts, or a successful admin action from a non-admin "
            "role (broken access control / privilege escalation)."
        )

    @property
    def severity(self) -> str:
        return "critical"

    @property
    def mitre(self) -> dict:
        return {
            "technique": "T1548",
            "name": "Abuse Elevation Control Mechanism",
            "tactic": "Privilege Escalation",
        }

    def evaluate(self, event: dict) -> dict | None:
        if event.get("action") != "API_REQUEST" or not is_admin(event.get("path", "")):
            return None

        ip = event.get("source_ip")
        status = event.get("status")
        role = (event.get("role") or "").lower()
        now = self._parse(event.get("timestamp"))

        # Case 1: successful admin action from a non-admin role → BFLA / priv-esc.
        if isinstance(status, int) and 200 <= status < 300 and role and role != "admin":
            return create_alert(
                rule_name=self.name, severity="critical", source_ip=ip,
                description=(
                    f"Broken access control: role '{role}' successfully called "
                    f"admin endpoint {event.get('http_method')} {event.get('path')} "
                    f"(HTTP {status}). Privilege escalation."
                ),
                evidence=[event],
                metadata={"service": "Admin Control Plane", "role": role,
                          "path": event.get("path"), "status": status,
                          "kind": "broken_access_control"},
            )

        # Case 2: repeated 401/403 on admin routes → unauthorized access attempts.
        if status in (401, 403):
            window = self._fails[ip]
            window.append((now, event))
            cutoff = now.timestamp() - self._window
            while window and window[0][0].timestamp() < cutoff:
                window.popleft()

            if len(window) >= self._fail_threshold:
                events = [e for _, e in window]
                window.clear()
                return create_alert(
                    rule_name=self.name, severity="critical", source_ip=ip,
                    description=(
                        f"Unauthorized admin access: {ip} was denied "
                        f"{len(events)} times on the admin control plane within "
                        f"{self._window}s (auth-bypass probing)."
                    ),
                    evidence=events,
                    metadata={"service": "Admin Control Plane",
                              "denied_attempts": len(events),
                              "kind": "unauthorized_admin_access"},
                )
        return None

    def reset(self):
        self._fails.clear()

    @staticmethod
    def _parse(ts):
        try:
            return datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)
