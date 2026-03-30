# 🧪 Testing Guide — Mini SOC

This document walks through every testable capability in the platform. Use it to verify each subsystem end-to-end.

---

## 📋 Prerequisites

| Requirement | How to Get It |
| :--- | :--- |
| Docker & Docker Compose | [Install Docker](https://docs.docker.com/get-docker/) |
| MongoDB Atlas Account | [Sign up free](https://www.mongodb.com/cloud/atlas) |
| Node.js 18+ | [Download](https://nodejs.org/) |
| Python 3.10+ | Pre-installed on most Linux/Mac systems |

---

## 🚀 1. Start the Full Stack

```bash
git clone https://github.com/tanmaymish/mini-soc.git
cd mini-soc

# Copy and configure the environment file
cp .env.example .env
# Edit .env with your MONGO_URI, SECRET_KEY, etc.

# Launch all services
docker-compose up --build -d
```

**Expected Result:** Three containers spin up — `mini-soc-api`, `mini-soc-frontend`, and `mini-soc-mongo`.

---

## 🔗 2. Verify MongoDB Connection

```bash
docker exec -it mini-soc-api python scripts/test_db_conn.py
```

**Expected Output:**
```
✅ MongoDB Connection Successful!
✅ Write Test Successful!
✅ Read Test Successful!
```

---

## 🔫 3. Attack Simulations

Open the dashboard at **http://localhost:5173**, then run attack simulations **in a separate terminal**:

### Test A: SSH Brute Force Attack
```bash
docker exec -it mini-soc-api python scripts/simulate_attack.py --mode brute_force
```

| What to Verify | Expected Result |
| :--- | :--- |
| Dashboard → Alert Feed | New `CRITICAL` alert: "SSH Brute Force Detected" |
| Alert Details (click to expand) | Shows 5+ failed SSH login attempts from the same source IP |
| SOAR Mitigations Table | New entry: `BLOCK_IP` action applied to attacker IP |

---

### Test B: Port Scan Detection
```bash
docker exec -it mini-soc-api python scripts/simulate_attack.py --mode port_scan
```

| What to Verify | Expected Result |
| :--- | :--- |
| Dashboard → Alert Feed | New `HIGH` alert: "Port Scan Detected" |
| Alert Details | Shows connections to 10+ distinct ports from one IP |
| SOAR Mitigations Table | New entry: `BLOCK_IP` action |

---

### Test C: Privilege Escalation
```bash
docker exec -it mini-soc-api python scripts/simulate_attack.py --mode priv_escalation
```

| What to Verify | Expected Result |
| :--- | :--- |
| Dashboard → Alert Feed | New `CRITICAL` alert: "Privilege Escalation Attempt" |
| Alert Details | Shows failed login followed by `sudo` from same user |
| SOAR Mitigations Table | New entry: `DISABLE_USER` action |

---

### Test D: ML Anomaly Detection
```bash
# First, train the baseline model on normal traffic
docker exec -it mini-soc-api python scripts/train_model.py

# Then simulate anomalous behavior
docker exec -it mini-soc-api python scripts/simulate_attack.py --mode anomaly
```

| What to Verify | Expected Result |
| :--- | :--- |
| Dashboard → Alert Feed | New `HIGH` alert: "ML Anomaly Detected" |
| Alert Details | Shows unusual traffic pattern (high volume at odd hours) |

---

### Test E: Threat Intelligence Match
```bash
docker exec -it mini-soc-api python scripts/simulate_attack.py --mode threat_intel
```

| What to Verify | Expected Result |
| :--- | :--- |
| Dashboard → Alert Feed | New `CRITICAL` alert: "Threat Intel Match" |
| Alert Details (click to expand) | Shows enriched context: Reputation Score `95`, Tags: `TOR_EXIT_NODE` |
| SOAR Mitigations Table | Instant `BLOCK_IP` — no behavioral window needed |

---

### Test F: Full Assault (All Attacks)
```bash
docker exec -it mini-soc-api python scripts/simulate_attack.py --mode all
```

| What to Verify | Expected Result |
| :--- | :--- |
| Dashboard Stats | Multiple alerts, critical count > 0 |
| Alert Feed | Mixed severity alerts from all detection rules |
| SOAR Mitigations | Multiple `BLOCK_IP` and `DISABLE_USER` entries |

---

## 🛡️ 4. SOAR Auto-Block Verification

After running any attack simulation, verify the SOAR engine is actively blocking follow-up traffic:

```bash
# Try sending another log from the same attacker IP
curl -X POST http://localhost:5000/api/ingest/json \
  -H "Content-Type: application/json" \
  -d '{"source_ip": "10.0.0.57", "action": "login_success", "user": "admin"}'
```

**Expected Result:** The API returns a `403 Forbidden` response — the IP was blocklisted by the SOAR engine.

---

## ✅ 5. Unit Tests

Run the built-in test suite to validate core logic:

```bash
docker exec -it mini-soc-api pytest tests/ -v
```

**Expected Output:**
```
tests/test_ingestion.py::test_normalize_syslog     PASSED
tests/test_rules.py::test_brute_force_detection    PASSED
tests/test_rules.py::test_port_scan_detection      PASSED
tests/test_alerting.py::test_webhook_dispatch       PASSED
tests/test_pipeline.py::test_end_to_end            PASSED
```

---

## 🌐 6. Webhook Notification Test (Optional)

1. Get a free test webhook from [webhook.site](https://webhook.site).
2. Set `WEBHOOK_URL` in your `.env` file.
3. Restart the API: `docker-compose restart soc-api`
4. Run any attack simulation.

**Expected Result:** The webhook endpoint receives a formatted JSON incident card with alert severity, rule name, source IP, and timestamp.

---

## 📊 Results Summary

After running all tests, your dashboard should show:

| Metric | Value |
| :--- | :--- |
| Total Events Analyzed | 50+ |
| Active Alerts | 5+ (one per attack type) |
| Critical / High Threats | 3+ |
| Active SOAR Mitigations | 3+ (BLOCK_IP + DISABLE_USER) |

---

<div align="center">
  <b>All tests passing = Your SOC is production-ready.</b> 🛡️
</div>
