"""
Mini SOC — Flask Application Factory.

This follows the factory pattern so we can create multiple app instances
(e.g., one for testing with a different DB, one for production).
Real SIEM backends use similar patterns to isolate components.
"""

import logging
from flask import Flask
from config.settings import get_config


def create_app(config_class=None):
    """
    Create and configure the Flask application.

    Args:
        config_class: Optional config class override (used in testing).

    Returns:
        Configured Flask app instance.
    """
    app = Flask(__name__)

    # Load configuration
    if config_class is None:
        config_class = get_config()
    app.config.from_object(config_class)

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, app.config.get("LOG_LEVEL", "INFO")),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger = logging.getLogger("mini_soc")
    logger.info("Mini SOC starting up...")

    # Initialize MongoDB connection
    from app.storage.mongo import init_db
    init_db(app)

    # Enable CORS for the React frontend (running on different port)
    from flask_cors import CORS
    CORS(app)

    # Register blueprints
    from app.ingestion.routes import ingestion_bp
    from app.api.alert_routes import alert_bp
    from app.api.mitigation_routes import mitigation_bp

    app.register_blueprint(ingestion_bp, url_prefix="/api/ingestion")
    app.register_blueprint(alert_bp, url_prefix="/api/alerts")
    app.register_blueprint(mitigation_bp, url_prefix="/api/mitigations")

    # Health check endpoint
    @app.route("/health")
    def health():
        return {"status": "ok", "service": "mini-soc"}, 200

    logger.info("Mini SOC ready. Detection engine armed.")
    return app
