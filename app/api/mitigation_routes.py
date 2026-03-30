from flask import Blueprint, jsonify
from app.storage.mongo import get_mitigations

mitigation_bp = Blueprint("mitigations", __name__)

@mitigation_bp.route("/", methods=["GET"])
def get_all_mitigations():
    """Fetch all active SOAR mitigations."""
    mitigations = get_mitigations(limit=100)
    return jsonify(mitigations), 200
