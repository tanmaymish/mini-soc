"""
Alert Dispatcher.

Evaluates an alert's severity and routes it to the configured destinations
(like Webhooks). This isolates routing logic from the detection engine.
"""

import logging
from app.alerting.base import BaseAlerter
from app.alerting.webhook import WebhookAlerter

logger = logging.getLogger("mini_soc.alerting.dispatcher")

# Map human-readable severities to integer levels for easy comparison
SEVERITY_LEVELS = {
    "low": 1,
    "info": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class AlertDispatcher:
    """Manages routing alerts to external systems."""

    def __init__(self, config: dict):
        self.config = config
        self.min_severity_str = config.get("ALERT_MIN_SEVERITY", "high").lower()
        self.min_severity_level = SEVERITY_LEVELS.get(self.min_severity_str, 3)
        
        self.destinations: list[BaseAlerter] = []
        self._register_destinations()

    def _register_destinations(self):
        """Set up external alerters based on config."""
        webhook_url = self.config.get("WEBHOOK_URL")
        if webhook_url:
            self.destinations.append(WebhookAlerter(webhook_url=webhook_url))
            logger.info("Alert Dispatcher: Registered Webhook alerter.")
        else:
            logger.info("Alert Dispatcher: No WEBHOOK_URL configured. External alerting disabled.")

    def dispatch(self, alert: dict):
        """
        Evaluate and optionally forward an alert.
        This is called synchronously, but in a real SOC, 
        this would typically push to a Celery/Kafka queue.
        """
        if not self.destinations:
            return  # No destinations configured, do nothing

        severity_str = alert.get("severity", "low").lower()
        severity_level = SEVERITY_LEVELS.get(severity_str, 1)

        if severity_level < self.min_severity_level:
            logger.debug(
                f"Alert Dispatcher: Dropping [{severity_str.upper()}] alert. "
                f"Below minimum threshold ({self.min_severity_str.upper()})."
            )
            return

        logger.info(f"Alert Dispatcher: Routing [{severity_str.upper()}] alert to {len(self.destinations)} destinations...")

        for alerter in self.destinations:
            try:
                alerter.send_alert(alert)
            except Exception as e:
                logger.error(f"Alerter '{alerter.name}' failed: {e}", exc_info=True)
