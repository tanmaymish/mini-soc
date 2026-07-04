"""
Threat Intelligence Match Rule.

ATTACKER BEHAVIOR:
  Known-bad infrastructure (botnets, Tor exit nodes, scanners) is reused
  across campaigns. A single packet from a flagged IP is actionable.

DETECTION LOGIC:
  Enrichment happens at the ingestion layer — the normalizer attaches an
  `intel` object (reputation score + tags) to each event. This rule fires
  a critical alert the moment a high-reputation-score IP appears.

REAL-WORLD EQUIVALENT:
  - Splunk ES Threat Intelligence framework
  - MISP / OpenCTI indicator matching
  - CrowdStrike Falcon Intelligence lookups
"""

from app.detection.rules.base_rule import BaseRule
from app.models.alert import create_alert


class ThreatIntelRule(BaseRule):
    """
    Triggers an immediate critical alert if an incoming log matches an
    IP with a bad reputation on a Threat Intel Platform.
    """

    def __init__(self, config: dict = None):
        config = config or {}
        # Any IP with a score at/over this is considered an active threat
        self.reputation_threshold = config.get("TI_REPUTATION_THRESHOLD", 80)

    @property
    def name(self) -> str:
        return "threat_intel_match"

    @property
    def description(self) -> str:
        return (
            "Flags traffic from IPs with a malicious reputation score on "
            "the Threat Intelligence Platform (botnets, Tor exit nodes, "
            "known scanners)."
        )

    @property
    def severity(self) -> str:
        # One packet from known-bad infrastructure is a critical incident
        return "critical"

    @property
    def mitre(self) -> dict:
        return {
            "technique": "T1071",
            "name": "Application Layer Protocol",
            "tactic": "Command and Control",
        }

    def evaluate(self, event: dict) -> dict | None:
        """
        Enrichment already attached `intel` to the event at ingestion;
        we just inspect the reputation score.
        """
        # The normalizer attaches enrichment under metadata.intel; accept a
        # top-level `intel` too for events submitted pre-enriched via JSON.
        intel = event.get("intel") or (event.get("metadata") or {}).get("intel") or {}
        score = intel.get("reputation_score", 0)

        if score < self.reputation_threshold:
            return None

        tags = ", ".join(intel.get("tags", []))
        source_ip = event.get("source_ip")

        alert = create_alert(
            rule_name=self.name,
            severity=self.severity,
            source_ip=source_ip,
            description=(
                f"Traffic from {source_ip} matches a known threat actor on "
                f"the Threat Intelligence Platform (score {score}/100)."
            ),
            evidence=[event],
            metadata={
                "reputation_score": score,
                "tags": intel.get("tags", []),
                "provider": intel.get("provider", "unknown"),
            },
        )
        # Rendered in the dashboard's "Threat Intel Match" evidence panel
        alert["context"] = (
            f"IP found in Threat Intelligence Platform. "
            f"Reputation Score: {score}. Tags: [{tags}]"
        )
        return alert
