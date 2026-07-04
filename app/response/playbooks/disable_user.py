"""
Disable User Playbook.

When an internal user account shows signs of compromise
(e.g., privilege escalation from an untrusted IP), we 
simulate disabling their Active Directory/SSO account.
"""

import logging
from datetime import datetime, timezone
from app.response.playbooks.base import BasePlaybook
from app.storage import store_mitigation

logger = logging.getLogger("mini_soc.soar.disable_user")


class DisableUserPlaybook(BasePlaybook):
    """Simulates locking a compromised user account."""

    @property
    def name(self) -> str:
        return "disable_compromised_user"

    @property
    def target_alerts(self) -> list[str]:
        # Only triggered by rules indicating compromised internal access
        return [
            "privilege_escalation"
        ]

    def execute(self, alert: dict) -> dict | None:
        # The detection rule records the compromised account in metadata;
        # fall back to the normalized evidence events if it's absent.
        target_user = (alert.get("metadata") or {}).get("user")

        if not target_user:
            for evt in alert.get("evidence", []):
                if evt.get("user"):
                    target_user = evt["user"]

        if not target_user:
            target_user = "unknown_actor"

        reason = f"Auto-mitigation due to {alert.get('rule_name')} (Compromised Credentials)."

        mitigation = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "playbook": self.name,
            "action": "DISABLE_USER",
            "target": target_user,
            "reason": reason,
            "triggering_alert_id": alert.get("_id"),
            "status": "applied",
        }

        mitigation_id = store_mitigation(mitigation)
        if mitigation_id:
            logger.info(f"🛡️  SOAR ACTION APPLIED: Locked user {target_user} via {self.name}.")
            mitigation["_id"] = str(mitigation_id)
            return mitigation
            
        return None
