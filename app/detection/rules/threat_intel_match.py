from app.detection.rules.base import BaseRule
from datetime import datetime, timezone
import uuid


class ThreatIntelRule(BaseRule):
    """
    Triggers an immediate Critical alert if an incoming log 
    matches an IP with a bad reputation on a Threat Intel Platform.
    """

    def __init__(self, config: dict = None):
        super().__init__(config)
        # Threshold: any IP with a score over 80 is considered an active threat
        self.reputation_threshold = 80

    @property
    def name(self) -> str:
        return "threat_intel_match"

    def match(self, event: dict) -> dict | None:
        """
        Since data enrichment happened at the ingestion layer,
        we just inspect the 'intel' object attached to the event.
        """
        intel = event.get("intel", {})
        score = intel.get("reputation_score", 0)

        if score >= self.reputation_threshold:
            # We don't need to correlate multiple events. 
            # ONE SINGLE PACKET from a known APT/Botnet is a critical incident.
            
            tags = ", ".join(intel.get("tags", []))
            
            alert = {
                "_id": str(uuid.uuid4()),
                "rule_name": self.name,
                "severity": "critical",
                "source_ip": event.get("source_ip"),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "new",
                "evidence": [event], # The single event that fired this
                "context": f"IP found in Threat Intelligence Platform. Reputation Score: {score}. Tags: [{tags}]"
            }
            return alert

        return None
