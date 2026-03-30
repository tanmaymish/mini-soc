"""
Alert Schema.

When a detection rule fires, it produces an Alert. In real SOCs, alerts
feed into case management (TheHive, ServiceNow) and ticketing systems.
Each alert preserves the evidence chain for investigation.
"""

from datetime import datetime, timezone


# Severity levels aligned with CVSS-style rating
SEVERITY_LEVELS = ["low", "medium", "high", "critical"]

# Alert statuses — mirrors SOC workflow
ALERT_STATUSES = ["new", "investigating", "resolved", "false_positive"]


def create_alert(
    rule_name: str,
    severity: str,
    source_ip: str,
    description: str,
    evidence: list,
    metadata: dict = None,
) -> dict:
    """
    Create an alert dictionary.

    Args:
        rule_name: Name of the detection rule that fired
                   (e.g., 'brute_force_ssh').
        severity: Alert severity — low, medium, high, critical.
        source_ip: Primary source IP involved in the threat.
        description: Human-readable description of what was detected.
        evidence: List of triggering log events (for analyst review).
        metadata: Additional context (port list, user list, etc.).

    Returns:
        Alert dictionary ready for storage and eventual dashboard display.
    """
    return {
        "rule_name": rule_name,
        "severity": severity,
        "source_ip": source_ip,
        "description": description,
        "evidence": evidence,
        "metadata": metadata or {},
        "status": "new",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
