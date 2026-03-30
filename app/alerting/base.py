"""
Base Alerter Interface.

In a real SOC (like Demisto/Cortex XSOAR or Tines), you have multiple
destinations for alerts: Jira, ServiceNow, Slack, PagerDuty, Email.
They all share a common "send" interface.
"""

from abc import ABC, abstractmethod


class BaseAlerter(ABC):
    """Abstract base class for all alert destinations."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the alerter (e.g., 'slack_webhook')."""
        pass

    @abstractmethod
    def send_alert(self, alert: dict) -> bool:
        """
        Send the alert to the destination.

        Args:
            alert: The generated alert dictionary.

        Returns:
            True if successfully sent, False otherwise.
        """
        pass
