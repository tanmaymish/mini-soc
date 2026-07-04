"""
Alert API Routes.

Read-side API consumed by the React dashboard. Serves stored detection
alerts and severity statistics from MongoDB.

Endpoints (mounted at /api/alerts):
  GET  /            — List alerts (filters: status, severity, limit)
  GET  /stats       — Alert counts grouped by severity
"""

from flask import Blueprint, request, jsonify

from app.storage import get_alerts, get_alert_stats

alert_bp = Blueprint("alerts", __name__)


@alert_bp.route("", methods=["GET"])
@alert_bp.route("/", methods=["GET"])
def list_alerts():
    """Query stored alerts with optional filters."""
    status = request.args.get("status")
    severity = request.args.get("severity")
    limit = request.args.get("limit", 50, type=int)

    alerts = get_alerts(status=status, severity=severity, limit=limit)

    # The dashboard sorts/renders by `timestamp`; alerts persist `created_at`.
    for alert in alerts:
        alert.setdefault("timestamp", alert.get("created_at"))

    return jsonify({"count": len(alerts), "alerts": alerts}), 200


@alert_bp.route("/stats", methods=["GET"])
def alert_stats():
    """Return alert count grouped by severity for dashboard summary tiles."""
    stats = get_alert_stats()
    return jsonify({"stats": stats}), 200
