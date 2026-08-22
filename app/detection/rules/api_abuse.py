"""
API Abuse Rule — rate anomalies & endpoint enumeration.

ATTACKER BEHAVIOR:
  Automated tooling hammers APIs far faster than a human ever would (credential
  stuffing, scraping, fuzzing), and maps the surface by walking many distinct
  endpoints — most returning 404 — to find something undocumented.

DETECTION LOGIC:
  Stateful per source IP over a rolling window:
    - > rate_threshold requests in window        → API rate abuse (high)
    - >= enum_threshold distinct paths, or many
      4xx "not found" responses                  → endpoint enumeration (medium)

REAL-WORLD EQUIVALENT:
  - API gateway rate limiting (Kong, Apigee)
  - Cloudflare API Shield anomalous-traffic detection
"""

from collections import defaultdict, deque
from datetime import datetime, timezone

from app.detection.rules.base_rule import BaseRule
from app.models.alert import create_alert


class ApiAbuseRule(BaseRule):
    def __init__(self, rate_threshold: int = 20, enum_threshold: int = 8,
                 window_seconds: int = 30):
        self._rate = rate_threshold
        self._enum = enum_threshold
        self._window = window_seconds
        self._hist = defaultdict(deque)  # ip -> deque[(ts, path, status)]
        self._fired = defaultdict(float)  # ip -> last fire ts (debounce)

    @property
    def name(self) -> str:
        return "api_abuse"

    @property
    def description(self) -> str:
        return (
            "Detects API rate abuse (request floods) and endpoint enumeration "
            "(scanning many distinct paths / 404s) from a single source."
        )

    @property
    def severity(self) -> str:
        return "high"

    @property
    def mitre(self) -> dict:
        return {
            "technique": "T1595",
            "name": "Active Scanning",
            "tactic": "Reconnaissance",
        }

    def evaluate(self, event: dict) -> dict | None:
        if event.get("action") != "API_REQUEST":
            return None

        ip = event.get("source_ip")
        if not ip:
            return None
        now = self._parse(event.get("timestamp"))

        window = self._hist[ip]
        window.append((now, event.get("path", ""), event.get("status")))
        cutoff = now.timestamp() - self._window
        while window and window[0][0].timestamp() < cutoff:
            window.popleft()

        # Debounce so one flood doesn't emit an alert per request.
        if now.timestamp() - self._fired[ip] < self._window:
            return None

        count = len(window)
        distinct_paths = len({p for _, p, _ in window})
        not_found = sum(1 for _, _, s in window if s in (404, 400))

        if count > self._rate:
            self._fired[ip] = now.timestamp()
            return create_alert(
                rule_name=self.name, severity="high", source_ip=ip,
                description=(
                    f"API rate abuse: {ip} made {count} requests in "
                    f"{self._window}s (threshold {self._rate})."
                ),
                evidence=[e for _, e in [(0, event)]],
                metadata={"kind": "rate_abuse", "request_count": count,
                          "window_seconds": self._window},
            )

        # Enumeration is breadth *plus* failure. Breadth alone matched every
        # single-page app on the internet - a dashboard hydrating eleven
        # endpoints on load looked identical to endpoint guessing, and the
        # detection benchmark scored this arm at 66% precision because of it.
        # An attacker guessing at endpoints gets 404s and 401s; a SPA loading
        # its own API does not.
        if not_found >= self._enum:
            self._fired[ip] = now.timestamp()
            return create_alert(
                rule_name=self.name, severity="medium", source_ip=ip,
                description=(
                    f"Endpoint enumeration: {ip} probed {distinct_paths} "
                    f"distinct endpoints ({not_found} not-found) in "
                    f"{self._window}s."
                ),
                evidence=[event],
                metadata={"kind": "enumeration", "distinct_paths": distinct_paths,
                          "not_found": not_found},
            )
        return None

    def reset(self):
        self._hist.clear()
        self._fired.clear()

    @staticmethod
    def _parse(ts):
        try:
            return datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)
