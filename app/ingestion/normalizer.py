"""
Log Normalizer.

Converts parsed log data into the standardized event schema.
This is the bridge between raw parser output and the detection engine.

In production SIEMs, normalization includes:
  - Field mapping (source → standard names)
  - Enrichment (GeoIP lookup, threat intel correlation)
  - Severity classification

We implement field mapping and severity classification here.
Enrichment comes in later phases.
"""

import logging
from app.models.log_event import create_log_event
from app.enrichment.threat_intel import lookup_ip

logger = logging.getLogger("mini_soc.ingestion.normalizer")

# Severity mapping based on action type
# This is how real SOCs prioritize — not all events are equal
ACTION_SEVERITY = {
    "FAILED_LOGIN": "medium",
    "ACCEPTED_LOGIN": "info",
    "SUDO_COMMAND": "high",
    "CONNECTION": "low",
    "BLOCKED": "medium",
    "OTHER": "info",
}


def normalize_parsed_log(parsed: dict, raw_log: str) -> dict:
    """
    Convert a parsed syslog dict into a normalized log event.
    """
    if parsed is None:
        return None

    action = parsed.get("action", "OTHER")
    severity = ACTION_SEVERITY.get(action, "info")
    
    source_ip = parsed.get("source_ip", "")
    intel_data = lookup_ip(source_ip) if source_ip else {"reputation_score": 0, "tags": [], "provider": "mock"}

    event = create_log_event(
        raw_log=raw_log,
        timestamp=parsed.get("timestamp"),
        source_ip=source_ip,
        hostname=parsed.get("hostname"),
        service=parsed.get("service"),
        action=action,
        user=parsed.get("user"),
        destination_port=parsed.get("destination_port"),
        severity=severity,
        metadata={"pid": parsed.get("pid"), "intel": intel_data},
    )

    logger.debug(
        f"Normalized event: {action} from {event['source_ip']} "
        f"({severity})"
    )
    return event


def normalize_json_event(data: dict) -> dict:
    """
    Normalize a JSON-submitted event (from API).
    """
    action = data.get("action", "OTHER").upper()
    severity = ACTION_SEVERITY.get(action, data.get("severity", "info"))
    
    source_ip = data.get("source_ip", "")
    intel_data = lookup_ip(source_ip) if source_ip else {"reputation_score": 0, "tags": [], "provider": "mock"}

    metadata = data.get("metadata", {})
    metadata["intel"] = intel_data

    event = create_log_event(
        raw_log=str(data),
        timestamp=data.get("timestamp"),
        source_ip=source_ip,
        hostname=data.get("hostname"),
        service=data.get("service"),
        action=action,
        user=data.get("user"),
        destination_port=data.get("destination_port"),
        severity=severity,
        metadata=metadata,
    )

    return event
