"""
Rate-Limit Playbook.

For API abuse (request floods) and GraphQL abuse (introspection / deep
queries), the proportionate response isn't a hard block — it's throttling.
We record a rate-limit mitigation the API gateway would enforce.
"""

import logging
from datetime import datetime, timezone
from app.response.playbooks.base import BasePlaybook
from app.storage import store_mitigation

logger = logging.getLogger("mini_soc.soar.rate_limit")


class RateLimitPlaybook(BasePlaybook):
    @property
    def name(self) -> str:
        return "rate_limit_source"

    @property
    def target_alerts(self) -> list[str]:
        return ["api_abuse", "graphql_abuse"]

    def execute(self, alert: dict) -> dict | None:
        source_ip = alert.get("source_ip")
        if not source_ip:
            return None

        mitigation = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "playbook": self.name,
            "action": "RATE_LIMIT",
            "target": source_ip,
            "reason": f"Auto-mitigation due to {alert.get('rule_name')} alert.",
            "triggering_alert_id": alert.get("_id"),
            "status": "applied",
        }
        if store_mitigation(mitigation):
            logger.info(f"🛡️  SOAR ACTION APPLIED: Rate-limited {source_ip}.")
            return mitigation
        return None
