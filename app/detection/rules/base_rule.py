"""
Base Rule — Abstract base class for all detection rules.

Every detection rule in a SOC follows a common pattern:
  1. Receive an event
  2. Check if conditions are met (with stateful context)
  3. If triggered, produce an alert with evidence

This is similar to how Sigma rules or Splunk correlation searches work:
  - Each rule has a name, description, and severity
  - Each rule evaluates independently
  - The engine orchestrates running all rules against each event
"""

from abc import ABC, abstractmethod


class BaseRule(ABC):
    """
    Abstract base class for detection rules.

    Subclasses must implement:
      - name: str — unique rule identifier
      - description: str — human-readable description
      - severity: str — default alert severity
      - evaluate(event) → Optional[dict] — detection logic
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this rule (e.g., 'brute_force_ssh')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """What this rule detects, in plain English."""
        pass

    @property
    @abstractmethod
    def severity(self) -> str:
        """Default severity: low, medium, high, critical."""
        pass

    @abstractmethod
    def evaluate(self, event: dict) -> dict | None:
        """
        Evaluate an event against this rule.

        Args:
            event: Normalized log event dictionary.

        Returns:
            An alert dict if the rule triggered, None otherwise.
        """
        pass

    def reset(self):
        """
        Reset internal state. Used between test cases
        and when the engine is restarted.
        """
        pass
