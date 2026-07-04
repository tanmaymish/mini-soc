"""
Storage Facade — pluggable persistence backends.

The pipeline talks to this module only; the concrete backend is chosen
once at startup:

  - DATABASE_URL set  → PostgreSQL (Neon, Supabase, RDS — serverless-friendly)
  - otherwise         → MongoDB (local docker-compose default)

Both backends expose the same document-oriented API, so detection rules,
playbooks, and routes never know which database is underneath.
"""

import logging

logger = logging.getLogger("mini_soc.storage")

_backend = None


def init_db(app):
    """Select and initialize the storage backend from app config."""
    global _backend

    if app.config.get("DATABASE_URL"):
        from app.storage import postgres as backend
        logger.info("Storage backend: PostgreSQL (DATABASE_URL configured)")
    else:
        from app.storage import mongo as backend
        logger.info("Storage backend: MongoDB")

    _backend = backend
    backend.init_db(app)


def get_db():
    return _backend.get_db() if _backend else None


def store_event(event: dict):
    return _backend.store_event(event)


def store_alert(alert: dict):
    return _backend.store_alert(alert)


def get_alerts(status=None, severity=None, limit=50, skip=0):
    return _backend.get_alerts(status=status, severity=severity, limit=limit, skip=skip)


def get_events(source_ip=None, limit=100):
    return _backend.get_events(source_ip=source_ip, limit=limit)


def count_events() -> int:
    return _backend.count_events()


def get_alert_stats():
    return _backend.get_alert_stats()


def store_mitigation(mitigation: dict):
    return _backend.store_mitigation(mitigation)


def get_mitigations(limit=50):
    return _backend.get_mitigations(limit=limit)


def is_ip_blocked(ip_address: str) -> bool:
    return _backend.is_ip_blocked(ip_address)
