"""
PostgreSQL Storage Backend (Neon-compatible).

Drop-in alternative to the MongoDB backend for serverless / free-tier
hosting (Neon, Supabase, RDS). Events, alerts, and mitigations are
stored as JSONB documents, so the rest of the pipeline is completely
storage-agnostic — the same dicts flow in and out of either backend.

Activated when the app config (or environment) defines DATABASE_URL,
e.g. postgresql://user:pass@host/db?sslmode=require
"""

import json
import logging

import psycopg2
import psycopg2.extras

logger = logging.getLogger("mini_soc.storage.postgres")

_dsn = None
_conn = None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS log_events (
    id  BIGSERIAL PRIMARY KEY,
    doc JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts  ON log_events ((doc->>'timestamp'));
CREATE INDEX IF NOT EXISTS idx_events_src ON log_events ((doc->>'source_ip'));

CREATE TABLE IF NOT EXISTS alerts (
    id  BIGSERIAL PRIMARY KEY,
    doc JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts ((doc->>'created_at'));
CREATE INDEX IF NOT EXISTS idx_alerts_status  ON alerts ((doc->>'status'));

CREATE TABLE IF NOT EXISTS mitigations (
    id  BIGSERIAL PRIMARY KEY,
    doc JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mitig_target ON mitigations ((doc->>'target'));
"""


def init_db(app):
    """Connect to PostgreSQL and ensure the schema exists."""
    global _dsn, _conn

    _dsn = app.config["DATABASE_URL"]
    try:
        _conn = _connect()
        logger.info("Connected to PostgreSQL storage backend.")
    except Exception as e:
        logger.warning(
            f"PostgreSQL not available ({e}). "
            "Running in degraded mode — events will not be persisted."
        )
        _conn = None


def _connect():
    conn = psycopg2.connect(_dsn)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(_SCHEMA)
    return conn


def _get_conn():
    """Return a live connection, reconnecting if the server dropped us
    (serverless Postgres like Neon suspends idle connections)."""
    global _conn
    if _conn is None:
        return None
    try:
        with _conn.cursor() as cur:
            cur.execute("SELECT 1")
        return _conn
    except psycopg2.Error:
        try:
            _conn = _connect()
            logger.info("Re-established PostgreSQL connection.")
            return _conn
        except Exception as e:
            logger.error(f"PostgreSQL reconnect failed: {e}")
            return None


def get_db():
    """Return the raw connection (None if storage is unavailable)."""
    return _get_conn()


def _insert(table: str, doc: dict) -> str | None:
    conn = _get_conn()
    if conn is None:
        logger.debug(f"DB unavailable, skipping insert into {table}.")
        return None
    with conn.cursor() as cur:
        cur.execute(
            f"INSERT INTO {table} (doc) VALUES (%s) RETURNING id",
            (json.dumps(doc, default=str),),
        )
        return str(cur.fetchone()[0])


def store_event(event: dict) -> str | None:
    """Persist a normalized log event."""
    return _insert("log_events", event)


def store_alert(alert: dict) -> str | None:
    """Persist a detection alert."""
    alert_id = _insert("alerts", alert)
    if alert_id:
        logger.info(
            f"ALERT STORED: [{alert['severity'].upper()}] "
            f"{alert['rule_name']} from {alert['source_ip']}"
        )
    return alert_id


def get_alerts(
    status: str = None,
    severity: str = None,
    limit: int = 50,
    skip: int = 0,
) -> list:
    """Query alerts with optional filters, newest first."""
    conn = _get_conn()
    if conn is None:
        return []

    clauses, params = [], []
    if status:
        clauses.append("doc->>'status' = %s")
        params.append(status)
    if severity:
        clauses.append("doc->>'severity' = %s")
        params.append(severity)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params += [limit, skip]

    with conn.cursor() as cur:
        cur.execute(
            f"SELECT doc FROM alerts {where} "
            "ORDER BY doc->>'created_at' DESC LIMIT %s OFFSET %s",
            params,
        )
        return [row[0] for row in cur.fetchall()]


def get_events(source_ip: str = None, limit: int = 100) -> list:
    """Query log events, optionally filtered by source IP, newest first."""
    conn = _get_conn()
    if conn is None:
        return []

    where, params = "", []
    if source_ip:
        where = "WHERE doc->>'source_ip' = %s"
        params.append(source_ip)
    params.append(limit)

    with conn.cursor() as cur:
        cur.execute(
            f"SELECT doc FROM log_events {where} "
            "ORDER BY doc->>'timestamp' DESC LIMIT %s",
            params,
        )
        return [row[0] for row in cur.fetchall()]


def count_events() -> int:
    """Total number of ingested events (dashboard telemetry tile)."""
    conn = _get_conn()
    if conn is None:
        return 0
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM log_events")
        return cur.fetchone()[0]


def get_alert_stats() -> dict:
    """Return alert count grouped by severity."""
    conn = _get_conn()
    if conn is None:
        return {}

    with conn.cursor() as cur:
        cur.execute(
            "SELECT doc->>'severity', COUNT(*) FROM alerts "
            "GROUP BY 1 ORDER BY 2 DESC"
        )
        return {row[0]: row[1] for row in cur.fetchall()}


def store_mitigation(mitigation: dict) -> str | None:
    """Store a SOAR mitigation action."""
    try:
        return _insert("mitigations", mitigation)
    except Exception as e:
        logger.error(f"Failed to store mitigation: {e}")
        return None


def get_mitigations(limit: int = 50) -> list[dict]:
    """Retrieve recent active mitigations, newest first."""
    conn = _get_conn()
    if conn is None:
        return []

    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, doc FROM mitigations "
            "ORDER BY doc->>'timestamp' DESC LIMIT %s",
            (limit,),
        )
        results = []
        for row_id, doc in cur.fetchall():
            doc["_id"] = str(row_id)
            results.append(doc)
        return results


def is_ip_blocked(ip_address: str) -> bool:
    """Check if an IP is actively blocked by the SOAR engine."""
    conn = _get_conn()
    if conn is None:
        return False

    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM mitigations "
            "WHERE doc->>'action' = 'BLOCK_IP' "
            "AND doc->>'target' = %s "
            "AND doc->>'status' = 'applied' LIMIT 1",
            (ip_address,),
        )
        return cur.fetchone() is not None
