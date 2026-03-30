"""
Detection Engine.

The engine is the orchestrator — it loads all registered rules and runs
each incoming event through every rule. This is how real SIEM correlation
engines work (Splunk's correlation search scheduler, QRadar's CRE).

Architecture:
  Event → Engine.evaluate() → [Rule1, Rule2, Rule3] → [Alert | None]

The engine:
  1. Instantiates rules with config-driven thresholds
  2. Runs events through all rules sequentially
  3. Collects and returns any triggered alerts
  4. Provides stats for monitoring rule performance
"""

import logging
from app.detection.rules.brute_force import BruteForceRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.priv_escalation import PrivilegeEscalationRule
from app.detection.rules.anomaly_rule import MLAnomalyRule
from app.detection.rules.threat_intel_match import ThreatIntelRule

logger = logging.getLogger("mini_soc.detection.engine")

class DetectionEngine:
    """
    Core detection engine. Loads rules and evaluates events.
    """

    def __init__(self, config: dict = None):
        config = config or {}

        # Instantiate rules with configurable thresholds
        self._rules = [
            ThreatIntelRule(config), # Intel rule triggers instantly overrides others
            BruteForceRule(
                threshold=config.get("BRUTE_FORCE_THRESHOLD", 5),
                window_seconds=config.get("BRUTE_FORCE_WINDOW_SECONDS", 60),
            ),
            PortScanRule(
                threshold=config.get("PORT_SCAN_THRESHOLD", 10),
                window_seconds=config.get("PORT_SCAN_WINDOW_SECONDS", 30),
            ),
            PrivilegeEscalationRule(),
            MLAnomalyRule(),
        ]

        # Stats tracking
        self._events_processed = 0
        self._alerts_generated = 0

        rule_names = [r.name for r in self._rules]
        logger.info(f"Detection engine loaded {len(self._rules)} rules: {rule_names}")

    def evaluate(self, event: dict) -> list[dict]:
        """
        Run an event through all detection rules.

        Args:
            event: Normalized log event dictionary.

        Returns:
            List of alert dicts (may be empty if no rules fired).
        """
        self._events_processed += 1
        alerts = []

        for rule in self._rules:
            try:
                alert = rule.evaluate(event)
                if alert is not None:
                    alerts.append(alert)
                    self._alerts_generated += 1
                    logger.info(
                        f"Rule '{rule.name}' FIRED — "
                        f"severity={alert['severity']}, "
                        f"source={alert['source_ip']}"
                    )
            except Exception as e:
                # Never let a buggy rule crash the pipeline
                logger.error(
                    f"Rule '{rule.name}' raised exception: {e}",
                    exc_info=True,
                )

        return alerts

    def get_rules(self) -> list[dict]:
        """Return metadata about loaded rules (for /api/rules endpoint)."""
        return [
            {
                "name": rule.name,
                "description": rule.description,
                "severity": rule.severity,
            }
            for rule in self._rules
        ]

    def get_stats(self) -> dict:
        """Return engine performance stats."""
        return {
            "events_processed": self._events_processed,
            "alerts_generated": self._alerts_generated,
            "rules_loaded": len(self._rules),
            "alert_rate": (
                f"{(self._alerts_generated / self._events_processed * 100):.2f}%"
                if self._events_processed > 0
                else "0%"
            ),
        }

    def reset(self):
        """Reset all rule states and counters. Used in testing."""
        for rule in self._rules:
            rule.reset()
        self._events_processed = 0
        self._alerts_generated = 0
