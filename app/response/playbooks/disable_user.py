"""
Disable User Playbook.

When an internal user account shows signs of compromise
(e.g., privilege escalation from an untrusted IP), we 
simulate disabling their Active Directory/SSO account.
"""

import logging
from datetime import datetime, timezone
from app.response.playbooks.base import BasePlaybook
from app.storage.mongo import store_mitigation

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
        # We need to extract the username from the raw evidence,
        # since the main alert only stores the IP.
        evidence = alert.get("evidence", [])
        if not evidence:
            return None
            
        # The user attempting sudo
        target_user = None
        for evt in evidence:
            if "SUDO_COMMAND" in evt.get("action", "") or "FAIL" in evt.get("action", ""):
                # Raw syslog has the user in the payload usually, e.g., "sysadmin"
                raw_log = evt.get("raw", "")
                if "for sysadmin" in raw_log or "sysadmin :" in raw_log:
                    target_user = "sysadmin"
                elif "for root" in raw_log or "root :" in raw_log:
                    target_user = "root" # we can't disable root, but we'll flag it

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
