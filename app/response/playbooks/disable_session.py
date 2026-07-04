"""
Disable Session Playbook.

Admin control-plane abuse (unauthorized access attempts, or a non-admin role
succeeding on an admin route) is a critical, act-now event: kill the offending
session/token immediately so no further admin actions are possible.
"""

import logging
from datetime import datetime, timezone
from app.response.playbooks.base import BasePlaybook
from app.storage import store_mitigation

logger = logging.getLogger("mini_soc.soar.disable_session")


class DisableSessionPlaybook(BasePlaybook):
    @property
    def name(self) -> str:
        return "disable_session"

    @property
    def target_alerts(self) -> list[str]:
        return ["admin_endpoint_abuse"]

    def execute(self, alert: dict) -> dict | None:
        # Prefer the concrete session actor (token/user), fall back to IP.
        evidence = alert.get("evidence") or [{}]
        first = evidence[0] if evidence else {}
        target = first.get("token") or first.get("user") or alert.get("source_ip")

        mitigation = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "playbook": self.name,
            "action": "DISABLE_SESSION",
            "target": target,
            "reason": (
                f"Auto-mitigation due to {alert.get('rule_name')} "
                f"(admin control-plane abuse). Session terminated."
            ),
            "triggering_alert_id": alert.get("_id"),
            "status": "applied",
        }
        if store_mitigation(mitigation):
            logger.info(f"🛡️  SOAR ACTION APPLIED: Disabled session {target}.")
            return mitigation
        return None
