"""
Centralized configuration for the Mini SOC.
Reads from environment variables with sensible defaults.
Maps to real SOC tuning — thresholds must balance false positives vs. missed detections.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration."""

    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-prod")
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"

    # MongoDB
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "mini_soc")

    # --- Detection Thresholds ---
    # These mirror real SIEM correlation rule tuning.
    # Too low = alert fatigue (false positives)
    # Too high = missed attacks (false negatives)

    # Brute Force: N failed logins from same IP within W seconds
    BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
    BRUTE_FORCE_WINDOW_SECONDS = int(os.getenv("BRUTE_FORCE_WINDOW_SECONDS", "60"))

    # Port Scan: connections to N+ distinct ports from same IP within W seconds
    PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", "10"))
    PORT_SCAN_WINDOW_SECONDS = int(os.getenv("PORT_SCAN_WINDOW_SECONDS", "30"))

    # --- Alerting & Integrations ---
    # In a real SOC, you filter noise by setting a minimum severity for wake-up alerts
    WEBHOOK_URL = os.getenv("WEBHOOK_URL")
    ALERT_MIN_SEVERITY = os.getenv("ALERT_MIN_SEVERITY", "high").lower()

    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


class TestingConfig(Config):
    TESTING = True
    MONGO_DB_NAME = "mini_soc_test"


# Config selector
config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config():
    """Return config class based on FLASK_ENV."""
    env = os.getenv("FLASK_ENV", "development")
    return config_map.get(env, DevelopmentConfig)
