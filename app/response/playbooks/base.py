"""
Base SOAR Playbook.

A Playbook defines an automated remediation or enrichment action
to be executed when a specific alert fires.
"""

from abc import ABC, abstractmethod


class BasePlaybook(ABC):
    """Abstract base class for all SOAR Response Playbooks."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the playbook (e.g., 'block_malicious_ip')."""
        pass

    @property
    @abstractmethod
    def target_alerts(self) -> list[str]:
        """A list of Rule Names this playbook responds to."""
        pass

    @abstractmethod
    def execute(self, alert: dict) -> dict | None:
        """
        Execute the automated response safely.

        Args:
            alert: The dictionary containing the alert data.

        Returns:
            A mitigation record dictionary to be saved in the database, 
            or None if the playbook decided not to act.
        """
        pass
