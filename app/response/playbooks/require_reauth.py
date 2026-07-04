"""
Require Re-Authentication Playbook.

When a token looks stolen (reuse from a new IP), the safe move is to
invalidate the session and force the user to re-authenticate — cheap,
reversible, and it locks out a hijacker holding the token.
"""

import logging
from datetime import datetime, timezone
from app.response.playbooks.base import BasePlaybook
from app.storage import store_mitigation

logger = logging.getLogger("mini_soc.soar.require_reauth")


class RequireReauthPlaybook(BasePlaybook):
    @property
    def name(self) -> str:
        return "require_reauthentication"

    @property
    def target_alerts(self) -> list[str]:
        return ["token_anomaly"]

    def execute(self, alert: dict) -> dict | None:
        meta = alert.get("metadata") or {}
        target = meta.get("token") or alert.get("source_ip")

        mitigation = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "playbook": self.name,
            "action": "REQUIRE_REAUTH",
            "target": target,
            "reason": (
                f"Auto-mitigation due to {alert.get('rule_name')} "
                f"({meta.get('kind', 'suspicious session')}). Session invalidated."
            ),
            "triggering_alert_id": alert.get("_id"),
            "status": "applied",
        }
        if store_mitigation(mitigation):
            logger.info(f"🛡️  SOAR ACTION APPLIED: Forced re-auth for {target}.")
            return mitigation
        return None
