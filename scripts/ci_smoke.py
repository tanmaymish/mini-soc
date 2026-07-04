#!/usr/bin/env python3
"""
CI smoke test — drives the full pipeline in-process against a real
database (PostgreSQL when DATABASE_URL is set, otherwise MongoDB).

Exercises: ingest -> detect -> SOAR auto-containment -> read APIs.
Exits non-zero if any stage misbehaves, so CI fails loudly.
"""

import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, ".")

from app import create_app

failures = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"  {status}: {name} {detail}")
    if not cond:
        failures.append(name)


def main():
    app = create_app()
    client = app.test_client()
    now = datetime.now(timezone.utc)

    def send(line):
        return client.post("/api/ingestion/logs", json={"raw": line})

    # Health
    r = client.get("/health")
    check("health endpoint", r.status_code == 200)

    # Brute force -> alert + SOAR block
    statuses = []
    for i in range(8):
        ts = (now + timedelta(seconds=i)).strftime("%b %d %H:%M:%S")
        statuses.append(send(
            f"{ts} server01 sshd[{12340+i}]: "
            f"Failed password for root from 192.168.1.100 port 22 ssh2"
        ).status_code)
    check("brute force ingested", 201 in statuses)
    check("SOAR blocks attacker mid-attack (403)", 403 in statuses, str(statuses))

    # Threat intel -> instant critical + block on next packet
    ts = now.strftime("%b %d %H:%M:%S")
    r = send(f"{ts} server01 sshd[1]: Failed password for u from 185.220.101.1 port 22 ssh2")
    check("threat-intel critical alert",
          r.status_code == 201 and r.get_json()["alerts_triggered"] >= 1,
          str(r.get_json()))
    r2 = send(f"{ts} server01 sshd[2]: Failed password for u from 185.220.101.1 port 22 ssh2")
    check("known-bad IP blocked (403)", r2.status_code == 403)

    # Read APIs
    r = client.get("/api/alerts")
    check("GET /api/alerts", r.status_code == 200 and r.get_json()["count"] >= 2)

    r = client.get("/api/mitigations")
    check("GET /api/mitigations", r.status_code == 200 and len(r.get_json()) >= 1)

    r = client.get("/api/ingestion/stats")
    check("GET /api/ingestion/stats", r.status_code == 200 and r.get_json()["total_events"] > 0)

    if failures:
        print(f"\nSMOKE TEST FAILED: {failures}")
        return 1
    print("\nSMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
