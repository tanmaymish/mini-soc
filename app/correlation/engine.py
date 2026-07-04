"""
Correlation Engine.

A single alert is a data point; an *incident* is a story. Real SOC value comes
from stitching weak, separate signals from the same actor into one narrative:

    port scan  +  brute force  +  admin abuse
        └── Recon ──┴── Credential Access ──┴── Privilege Escalation
        = "Multi-stage intrusion from 203.0.113.50"

This engine keeps a short-lived, per-actor window of recent alerts. Once an
actor trips **two or more distinct rule types** inside the window, it opens
(and then keeps updating) an Incident with a combined severity and a
kill-chain narrative ordered by the ATT&CK-style phases below.

This is the correlation layer that sits between detection (SIEM) and response
(SOAR) — the equivalent of QRadar offenses or Splunk ES notable-event
correlation.
"""

import logging
from collections import defaultdict, deque
from datetime import datetime, timezone

logger = logging.getLogger("mini_soc.correlation")

_SEV_RANK = {"low": 1, "info": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_SEV = {1: "low", 2: "medium", 3: "high", 4: "critical"}

# Map each detection rule to a kill-chain phase (ordered) for the narrative.
_PHASE_ORDER = [
    "Reconnaissance", "Credential Access", "Initial Access",
    "Execution", "Privilege Escalation", "Defense Evasion",
    "Command & Control", "Exfiltration",
]
_RULE_PHASE = {
    "api_abuse": "Reconnaissance",
    "port_scan": "Reconnaissance",
    "graphql_abuse": "Reconnaissance",
    "brute_force_ssh": "Credential Access",
    "token_anomaly": "Credential Access",
    "web_attack": "Initial Access",
    "admin_endpoint_abuse": "Privilege Escalation",
    "privilege_escalation": "Privilege Escalation",
    "ml_behavioral_anomaly": "Defense Evasion",
    "threat_intel_match": "Command & Control",
}


class CorrelationEngine:
    """Groups an actor's alerts into a single evolving incident."""

    def __init__(self, window_seconds: int = 600, min_distinct_rules: int = 2):
        self._window = window_seconds
        self._min_rules = min_distinct_rules
        # actor -> deque[(ts, alert)]
        self._recent = defaultdict(deque)
        # actor -> incident dict (the currently-open incident for that actor)
        self._open = {}

    def correlate(self, alert: dict) -> dict | None:
        """
        Feed one alert in. Returns an Incident dict (new or updated) when the
        actor has crossed the correlation threshold, else None.
        """
        actor = alert.get("source_ip")
        if not actor:
            return None

        now = self._parse(alert.get("created_at") or alert.get("timestamp"))
        window = self._recent[actor]
        window.append((now, alert))
        cutoff = now.timestamp() - self._window
        while window and window[0][0].timestamp() < cutoff:
            window.popleft()

        alerts = [a for _, a in window]
        rules = [a.get("rule_name") for a in alerts]
        distinct = list(dict.fromkeys(rules))  # preserve first-seen order

        if len(distinct) < self._min_rules:
            return None

        incident = self._open.get(actor)
        if incident is None:
            incident = {
                "incident_id": f"INC-{now.strftime('%Y%m%d')}-{actor.replace('.', '')[-6:]}-{int(now.timestamp()) % 10000}",
                "actor": actor,
                "status": "open",
                "created_at": now.isoformat(),
            }
            self._open[actor] = incident
            logger.warning(f"[CORRELATION] New incident {incident['incident_id']} for {actor}")

        phases = self._ordered_phases(distinct)
        max_rank = max(_SEV_RANK.get(a.get("severity", "low"), 1) for a in alerts)
        # Multiple stages escalate severity: chained attacks are worse than the sum.
        if len(distinct) >= 3:
            max_rank = min(4, max_rank + 1)

        incident.update({
            "severity": _RANK_SEV[max_rank],
            "stages": phases,
            "rule_names": distinct,
            "alert_count": len(alerts),
            "mitre": [a.get("mitre") for a in alerts if a.get("mitre")],
            "title": f"Multi-stage attack from {actor}",
            "narrative": self._narrative(actor, phases, distinct),
            "kill_chain": " → ".join(phases),
            "updated_at": now.isoformat(),
            "evidence_alerts": [
                {"rule_name": a.get("rule_name"), "severity": a.get("severity"),
                 "description": a.get("description")}
                for a in alerts
            ],
        })
        return incident

    @staticmethod
    def _ordered_phases(rule_names) -> list:
        seen = {}
        for r in rule_names:
            phase = _RULE_PHASE.get(r, "Execution")
            seen[phase] = True
        return sorted(seen.keys(), key=lambda p: _PHASE_ORDER.index(p) if p in _PHASE_ORDER else 99)

    @staticmethod
    def _narrative(actor, phases, rules) -> str:
        chain = " then ".join(phases).lower()
        return (
            f"Actor {actor} progressed through {len(phases)} kill-chain "
            f"phase(s): {chain}. Correlated {len(rules)} distinct detections "
            f"({', '.join(rules)}). Automated containment engaged."
        )

    def reset(self):
        self._recent.clear()
        self._open.clear()

    @staticmethod
    def _parse(ts):
        try:
            return datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)
