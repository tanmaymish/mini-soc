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
from app.ingestion.normalizer import normalize_parsed_log, normalize_json_event
from app.detection.engine import DetectionEngine
from app.alerting.dispatcher import AlertDispatcher
from app.storage.mongo import store_event, store_alert, get_alerts, get_alert_stats, is_ip_blocked
from app.response.engine import SoarEngine

logger = logging.getLogger("mini_soc.ingestion.routes")

ingestion_bp = Blueprint("ingestion", __name__)

# Singletons shared across requests
_engine = None
_dispatcher = None
_soar = None


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

        # Store any triggered alerts and dispatch them
        stored_alerts = []
        for alert in alerts:
            alert_id = store_alert(alert)
            alert["_id"] = alert_id  # optionally add ID for external context
            
            # Post-detection Orchestration
            dispatcher.dispatch(alert)
            soar.handle_alert(alert)
            
            stored_alerts.append({
                "id": alert_id,
                "rule": alert["rule_name"],
                "severity": alert["severity"],
            })

        return jsonify({
            "status": "ingested",
            "event_id": event_id,
            "action": event.get("action"),
            "alerts_triggered": len(stored_alerts),
            "alerts": stored_alerts,
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

    try:
        data = request.get_json(force=True)

        if not data:
            return jsonify({"error": "No data provided"}), 400

        results = {"ingested": 0, "failed": 0, "dropped": 0, "alerts_triggered": 0}
        all_alerts = []

        def process_event(event):
            source_ip = event.get("source_ip")
            if source_ip and is_ip_blocked(source_ip):
                results["dropped"] += 1
                return
                
            store_event(event)
            alerts = engine.evaluate(event)
            for alert in alerts:
                store_alert(alert)
                dispatcher.dispatch(alert)
                soar.handle_alert(alert)
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

        # Handle structured events
        events = data.get("events", [])
        for evt_data in events:
            event = normalize_json_event(evt_data)
            if event:
                process_event(event)

        results["alerts_triggered"] = len(all_alerts)
        results["alerts"] = all_alerts

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
    """Return alert count grouped by severity."""
    stats = get_alert_stats()
    return jsonify({"stats": stats}), 200
