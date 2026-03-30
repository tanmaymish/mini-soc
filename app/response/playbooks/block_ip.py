"""
Block IP Playbook.

Simulates writing a firewall rule or WAF block.
When an alert fires, we extract the attacker's IP and mark it
as 'blocked' in our MongoDB mitigations collection.

The Ingestion pipeline will query this active blocklist and
drop subsequent logs from this IP before processing.
"""

import logging
from datetime import datetime, timezone
from app.response.playbooks.base import BasePlaybook
from app.storage.mongo import store_mitigation

logger = logging.getLogger("mini_soc.soar.block_ip")


class BlockIPPlaybook(BasePlaybook):
    """Adds the alert's source IP to the active blocklist."""

    @property
    def name(self) -> str:
        return "block_malicious_ip"

    @property
    def target_alerts(self) -> list[str]:
        # We auto-block anyone caught brute forcing, port scanning,
        # or triggering the ML anomaly rule (if severity is high).
        return [
            "ssh_brute_force",
            "horizontal_port_scan",
            "ml_behavioral_anomaly"
        ]

    def execute(self, alert: dict) -> dict | None:
        source_ip = alert.get("source_ip")
        if not source_ip:
            logger.warning("Block IP Playbook aborted: No source_ip found in alert.")
            return None

        # Determine the reason for the block based on the alert rule
        reason = f"Auto-mitigation due to {alert.get('rule_name')} alert."

        mitigation = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "playbook": self.name,
            "action": "BLOCK_IP",
            "target": source_ip,
            "reason": reason,
            "triggering_alert_id": alert.get("_id"),
            "status": "applied",
            # In a real SOAR, you might add 'expiry' like 24 hours. We keep it permanent for testing.
        }

        # Save to DB to activate the block at the ingestion layer
        mitigation_id = store_mitigation(mitigation)
        if mitigation_id:
            logger.info(f"🛡️  SOAR ACTION APPLIED: Blocked IP {source_ip} via {self.name}.")
            mitigation["_id"] = str(mitigation_id)
            return mitigation
            
        return None
