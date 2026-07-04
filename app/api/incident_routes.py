"""
Incident API Routes.

Serves correlated incidents (multi-stage attacks stitched together by the
correlation engine) to the dashboard.

Endpoints (mounted at /api/incidents):
  GET  /   — List recent incidents, newest first
"""

from flask import Blueprint, jsonify

from app.storage import get_incidents

incident_bp = Blueprint("incidents", __name__)


@incident_bp.route("", methods=["GET"])
@incident_bp.route("/", methods=["GET"])
def list_incidents():
    incidents = get_incidents(limit=50)
    return jsonify(incidents), 200
