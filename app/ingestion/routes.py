"""
Ingestion API Routes.

Exposes REST endpoints for log submission. In production, these would
sit behind a load balancer and rate limiter. Log sources (agents,
forwarders, applications) push events here.

Endpoints:
  POST /api/logs       — Submit a single log (raw text or JSON)
  POST /api/logs/bulk  — Submit multiple logs in batch
  GET  /api/alerts     — Retrieve detection alerts
  GET  /api/stats      — Alert statistics summary
"""

import logging
from flask import Blueprint, request, jsonify

from app.ingestion.syslog_parser import parse_syslog_line
from app.ingestion.normalizer import normalize_parsed_log, normalize_json_event, normalize_api_event
from app.detection.engine import DetectionEngine
from app.correlation.engine import CorrelationEngine
from app.alerting.dispatcher import AlertDispatcher
from app.storage import (
    store_event, store_alert, get_alerts, get_alert_stats, count_events,
    is_ip_blocked, upsert_incident,
)
from app.response.engine import SoarEngine

logger = logging.getLogger("mini_soc.ingestion.routes")

ingestion_bp = Blueprint("ingestion", __name__)

# Singletons shared across requests
_engine = None
_dispatcher = None
_soar = None
_correlator = None


def _get_correlator():
    """Lazy-init the correlation engine."""
    global _correlator
    if _correlator is None:
        _correlator = CorrelationEngine()
    return _correlator


def _correlate_and_store(correlator, alert):
    """Feed an alert to correlation; persist any incident it produces."""
    incident = correlator.correlate(alert)
    if incident:
        upsert_incident(incident)
    return incident


def _get_engine():
    """Lazy-init the detection engine."""
    global _engine
    if _engine is None:
        from flask import current_app
        _engine = DetectionEngine(current_app.config)
    return _engine


def _get_dispatcher():
    """Lazy-init the alert dispatcher."""
    global _dispatcher
    if _dispatcher is None:
        from flask import current_app
        _dispatcher = AlertDispatcher(current_app.config)
    return _dispatcher


def _get_soar():
    """Lazy-init the SOAR Engine."""
    global _soar
    if _soar is None:
        _soar = SoarEngine()
    return _soar


@ingestion_bp.route("/logs", methods=["POST"])
def ingest_log():
    """
    Ingest a single log event.

    Accepts:
      - Content-Type: application/json → structured event
      - Content-Type: text/plain → raw syslog line

    Returns:
      201 with event details and any triggered alerts.
    """
    engine = _get_engine()
    content_type = request.content_type or ""

    try:
        if "application/json" in content_type:
            data = request.get_json(force=True)

            # Handle raw log line sent as JSON
            if "raw" in data and isinstance(data["raw"], str):
                parsed = parse_syslog_line(data["raw"])
                event = normalize_parsed_log(parsed, data["raw"])
            elif data.get("type") == "api" or ("method" in data and "path" in data):
                # Structured API request event → API-security domain
                event = normalize_api_event(data)
            else:
                event = normalize_json_event(data)
        else:
            # Plain text — treat as raw syslog
            raw_line = request.get_data(as_text=True).strip()
            if not raw_line:
                return jsonify({"error": "Empty log line"}), 400
            parsed = parse_syslog_line(raw_line)
            event = normalize_parsed_log(parsed, raw_line)

        if event is None:
            return jsonify({"error": "Could not parse log line"}), 400

        # ACTIVE MITIGATION CHECK: Drop the log if the IP is blocked
        source_ip = event.get("source_ip")
        if source_ip and is_ip_blocked(source_ip):
            logger.warning(f"Connection dropped: {source_ip} is actively blocked by SOAR mitigations.")
            return jsonify({"error": "Forbidden: IP actively blocked"}), 403

        # Store the normalized event
        event_id = store_event(event)

        # Run through detection engine
        alerts = engine.evaluate(event)
        dispatcher = _get_dispatcher()
        soar = _get_soar()
        correlator = _get_correlator()

        # Store any triggered alerts and dispatch them
        stored_alerts = []
        incidents = []
        for alert in alerts:
            alert_id = store_alert(alert)
            alert["_id"] = alert_id  # optionally add ID for external context

            # Post-detection Orchestration
            dispatcher.dispatch(alert)
            soar.handle_alert(alert)

            # Correlate multi-step attacks into incidents
            incident = _correlate_and_store(correlator, alert)
            if incident:
                incidents.append({
                    "incident_id": incident["incident_id"],
                    "severity": incident["severity"],
                    "kill_chain": incident["kill_chain"],
                })

            stored_alerts.append({
                "id": alert_id,
                "rule": alert["rule_name"],
                "severity": alert["severity"],
                "service": (alert.get("metadata") or {}).get("service"),
            })

        return jsonify({
            "status": "ingested",
            "event_id": event_id,
            "action": event.get("action"),
            "service": event.get("api_service"),
            "alerts_triggered": len(stored_alerts),
            "alerts": stored_alerts,
            "incidents": incidents,
        }), 201

    except Exception as e:
        logger.error(f"Ingestion error: {e}", exc_info=True)
        return jsonify({"error": "Internal processing error"}), 500


@ingestion_bp.route("/logs/bulk", methods=["POST"])
def ingest_bulk():
    """
    Ingest multiple log lines in a single request.
    """
    engine = _get_engine()
    dispatcher = _get_dispatcher()
    soar = _get_soar()
    correlator = _get_correlator()

    try:
        data = request.get_json(force=True)

        if not data:
            return jsonify({"error": "No data provided"}), 400

        results = {"ingested": 0, "failed": 0, "dropped": 0,
                   "alerts_triggered": 0, "incidents": 0}
        all_alerts = []
        incident_ids = set()

        def process_event(event):
            source_ip = event.get("source_ip")
            if source_ip and is_ip_blocked(source_ip):
                results["dropped"] += 1
                return

            store_event(event)
            alerts = engine.evaluate(event)
            for alert in alerts:
                alert["_id"] = store_alert(alert)
                dispatcher.dispatch(alert)
                soar.handle_alert(alert)
                incident = _correlate_and_store(correlator, alert)
                if incident:
                    incident_ids.add(incident["incident_id"])
                all_alerts.append({
                    "rule": alert["rule_name"],
                    "severity": alert["severity"],
                })
            results["ingested"] += 1

        # Handle raw log lines
        lines = data.get("logs", [])
        for line in lines:
            parsed = parse_syslog_line(line)
            event = normalize_parsed_log(parsed, line)
            if event:
                process_event(event)
            else:
                results["failed"] += 1

        # Handle structured events (API events routed to the API normalizer)
        events = data.get("events", [])
        for evt_data in events:
            if evt_data.get("type") == "api" or ("method" in evt_data and "path" in evt_data):
                event = normalize_api_event(evt_data)
            else:
                event = normalize_json_event(evt_data)
            if event:
                process_event(event)

        results["alerts_triggered"] = len(all_alerts)
        results["alerts"] = all_alerts
        results["incidents"] = len(incident_ids)

        return jsonify(results), 201

    except Exception as e:
        logger.error(f"Bulk ingestion error: {e}", exc_info=True)
        return jsonify({"error": "Internal processing error"}), 500


@ingestion_bp.route("/alerts", methods=["GET"])
def list_alerts():
    """Query stored alerts with optional filters."""
    status = request.args.get("status")
    severity = request.args.get("severity")
    limit = request.args.get("limit", 50, type=int)

    alerts = get_alerts(status=status, severity=severity, limit=limit)
    return jsonify({"count": len(alerts), "alerts": alerts}), 200


@ingestion_bp.route("/stats", methods=["GET"])
def alert_stats():
    """Return alert counts by severity plus total events analyzed."""
    stats = get_alert_stats()
    return jsonify({"stats": stats, "total_events": count_events()}), 200
