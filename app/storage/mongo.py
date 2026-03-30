"""
MongoDB Storage Module.

Handles connection pooling, event/alert persistence, and queries.
In production, this maps to your SIEM's data store — Elasticsearch in ELK,
IndexedDB in Splunk, or PostgreSQL in some commercial SIEMs.

MongoDB is used here because:
  1. Schema-flexible — log formats vary widely across sources
  2. Good for time-series-like append-heavy workloads
  3. Native JSON — no impedance mismatch with our event format
"""

import logging
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure

logger = logging.getLogger("mini_soc.storage")

# Module-level references (initialized by init_db)
_client = None
_db = None


def init_db(app):
    """
    Initialize MongoDB connection from Flask app config.
    Called once during app startup via the factory.
    """
    global _client, _db

    mongo_uri = app.config["MONGO_URI"]
    db_name = app.config["MONGO_DB_NAME"]

    try:
        _client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        # Force a connection test
        _client.admin.command("ping")
        _db = _client[db_name]

        # Create indexes for efficient querying
        _db.log_events.create_index([("timestamp", DESCENDING)])
        _db.log_events.create_index([("source_ip", 1)])
        _db.log_events.create_index([("action", 1)])
        _db.alerts.create_index([("created_at", DESCENDING)])
        _db.alerts.create_index([("source_ip", 1)])
        _db.alerts.create_index([("status", 1)])

        logger.info(f"Connected to MongoDB: {db_name}")
    except ConnectionFailure as e:
        logger.warning(
            f"MongoDB not available ({e}). "
            "Running in degraded mode — events will not be persisted."
        )
        _db = None


def get_db():
    """Return the database instance. May be None if DB is unavailable."""
    return _db


def store_event(event: dict) -> str | None:
    """
    Persist a normalized log event.

    Returns:
        Inserted document ID as string, or None if DB unavailable.
    """
    db = get_db()
    if db is None:
        logger.debug("DB unavailable, skipping event storage.")
        return None

    result = db.log_events.insert_one(event)
    return str(result.inserted_id)


def store_alert(alert: dict) -> str | None:
    """
    Persist a detection alert.

    Returns:
        Inserted document ID as string, or None if DB unavailable.
    """
    db = get_db()
    if db is None:
        logger.debug("DB unavailable, skipping alert storage.")
        return None

    result = db.alerts.insert_one(alert)
    logger.info(
        f"ALERT STORED: [{alert['severity'].upper()}] "
        f"{alert['rule_name']} from {alert['source_ip']}"
    )
    return str(result.inserted_id)


def get_alerts(
    status: str = None,
    severity: str = None,
    limit: int = 50,
    skip: int = 0,
) -> list:
    """
    Query alerts with optional filters.
    Used by the dashboard API (Phase 5) and for testing.
    """
    db = get_db()
    if db is None:
        return []

    query = {}
    if status:
        query["status"] = status
    if severity:
        query["severity"] = severity

    cursor = (
        db.alerts.find(query, {"_id": 0})
        .sort("created_at", DESCENDING)
        .skip(skip)
        .limit(limit)
    )
    return list(cursor)


def get_events(source_ip: str = None, limit: int = 100) -> list:
    """Query log events, optionally filtered by source IP."""
    db = get_db()
    if db is None:
        return []

    query = {}
    if source_ip:
        query["source_ip"] = source_ip

    cursor = (
        db.log_events.find(query, {"_id": 0})
        .sort("timestamp", DESCENDING)
        .limit(limit)
    )
    return list(cursor)


def get_alert_stats() -> dict:
    """Return alert count grouped by severity. For dashboard summary."""
    db = get_db()
    if db is None:
        return {}

    pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    results = db.alerts.aggregate(pipeline)
    return {doc["_id"]: doc["count"] for doc in results}


def store_mitigation(mitigation: dict) -> str | None:
    """Store a SOAR mitigation action in MongoDB."""
    db = get_db()
    if db is None:
        return None
    try:
        result = db.mitigations.insert_one(mitigation)
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"Failed to store mitigation: {e}")
        return None

def get_mitigations(limit: int = 50) -> list[dict]:
    """Retrieve recent active mitigations."""
    db = get_db()
    if db is None:
        return []
        
    cursor = db.mitigations.find().sort("timestamp", DESCENDING).limit(limit)
    mitigations = list(cursor)
    
    # Convert ObjectIds to strings for JSON serialization
    for m in mitigations:
        if "_id" in m:
            m["_id"] = str(m["_id"])
        
    return mitigations

def is_ip_blocked(ip_address: str) -> bool:
    """Check if an IP is actively blocked by the SOAR engine."""
    db = get_db()
    if db is None:
        return False
        
    blocked = db.mitigations.find_one({
        "action": "BLOCK_IP",
        "target": ip_address,
        "status": "applied"
    })
    
    return bool(blocked)
