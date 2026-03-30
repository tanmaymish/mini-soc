"""
Webhook Alerter (Slack / Discord / Teams).

Posts a JSON payload summarizing the threat to a configured URL.
This acts as a generic integration layer.
"""

import logging
import requests
from app.alerting.base import BaseAlerter

logger = logging.getLogger("mini_soc.alerting.webhook")


class WebhookAlerter(BaseAlerter):
    """Sends alerts via HTTP POST to a webhook URL."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    @property
    def name(self) -> str:
        return "generic_webhook"

    def send_alert(self, alert: dict) -> bool:
        if not self.webhook_url:
            logger.debug("Webhook requested but no URL configured. Skipping.")
            return False

        # Format payload to look decent in Slack/Discord
        severity_emoji = {
            "low": "ℹ️",
            "medium": "⚠️",
            "high": "🚨",
            "critical": "🔥"
        }.get(alert.get("severity", "low"), "🚨")

        payload = {
            "text": f"{severity_emoji} **MINI SOC ALERT** {severity_emoji}",
            "attachments": [
                {
                    "title": f"Rule Triggered: {alert.get('rule_name')}",
                    "color": "danger" if alert.get("severity") in ["high", "critical"] else "warning",
                    "fields": [
                        {"title": "Severity", "value": alert.get("severity", "unknown").upper(), "short": True},
                        {"title": "Source IP", "value": alert.get("source_ip", "unknown"), "short": True},
                        {"title": "Description", "value": alert.get("description", "No description provided"), "short": False},
                        {"title": "Evidence Count", "value": str(len(alert.get("evidence", []))), "short": True},
                    ]
                }
            ]
        }

        try:
            logger.info(f"Pushing [{alert.get('severity').upper()}] alert to webhook...")
            # Fire and forget with a short timeout so we don't block the ingestion pipeline
            response = requests.post(self.webhook_url, json=payload, timeout=2.0)
            
            if response.status_code in (200, 201, 204):
                logger.debug("Webhook sent successfully.")
                return True
            else:
                logger.error(f"Webhook failed with status {response.status_code}: {response.text}")
                return False

        except requests.exceptions.RequestException as e:
            logger.error(f"Webhook connection error: {e}")
            return False
