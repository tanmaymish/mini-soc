#!/usr/bin/env python3
"""
Attack Simulator — Generates realistic attack log lines and sends
them to the Mini SOC API for testing detection rules.

Usage:
  python scripts/simulate_attack.py --mode brute_force
  python scripts/simulate_attack.py --mode port_scan
  python scripts/simulate_attack.py --mode priv_escalation
  python scripts/simulate_attack.py --mode anomaly
  python scripts/simulate_attack.py --mode mixed
  python scripts/simulate_attack.py --mode all


Options:
  --target   API base URL (default: http://localhost:5000)
  --mode     Attack type to simulate
"""

import argparse
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta


API_URL = "http://localhost:5000"


def send_log(base_url: str, log_line: str):
    """Send a single log line to the ingestion API."""
    url = f"{base_url}/api/logs"
    data = json.dumps({"raw": log_line}).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read().decode())
            alerts = result.get("alerts_triggered", 0)
            status = f"  → {result.get('action', '?')}"
            if alerts > 0:
                status += f" | 🚨 {alerts} ALERT(S) TRIGGERED!"
            print(status)
            return result
    except urllib.error.URLError as e:
        print(f"  → ERROR: {e}")
        return None


def simulate_brute_force(base_url: str):
    """
    Simulate SSH brute force: 8 rapid failed logins from same IP.
    Should trigger after the 5th attempt.
    """
    print("\n" + "=" * 60)
    print("🔓 SIMULATING BRUTE FORCE ATTACK")
    print("   Attacker: 192.168.1.100 → Target: root@server01")
    print("=" * 60)

    attacker_ip = "192.168.1.100"
    now = datetime.now(timezone.utc)

    for i in range(8):
        ts = (now + timedelta(seconds=i)).strftime("%b %d %H:%M:%S")
        log = (
            f"{ts} server01 sshd[{12340 + i}]: "
            f"Failed password for root from {attacker_ip} port 22 ssh2"
        )
        print(f"[{i + 1}/8] Sending: {log[:70]}...")
        send_log(base_url, log)
        time.sleep(0.2)

    print("\n✅ Brute force simulation complete.")


def simulate_port_scan(base_url: str):
    """
    Simulate port scan: connections to 12 different ports from same IP.
    Should trigger after the 10th unique port.
    """
    print("\n" + "=" * 60)
    print("🔍 SIMULATING PORT SCAN")
    print("   Attacker: 203.0.113.50 → Target: firewall01")
    print("=" * 60)

    attacker_ip = "203.0.113.50"
    ports = [22, 80, 443, 8080, 3306, 5432, 6379, 27017, 21, 25, 110, 8443]
    now = datetime.now(timezone.utc)

    for i, port in enumerate(ports):
        ts = (now + timedelta(seconds=i)).strftime("%b %d %H:%M:%S")
        log = (
            f"{ts} firewall01 kernel: "
            f"BLOCKED IN=eth0 SRC={attacker_ip} "
            f"DST=10.0.0.1 DPT={port} PROTO=TCP"
        )
        print(f"[{i + 1}/{len(ports)}] Scanning port {port}...")
        send_log(base_url, log)
        time.sleep(0.15)

    print("\n✅ Port scan simulation complete.")


def simulate_priv_escalation(base_url: str):
    """
    Simulate privilege escalation: failed logins then sudo.
    Scenario: attacker compromises 'deploy' account after failed attempts.
    """
    print("\n" + "=" * 60)
    print("⬆️  SIMULATING PRIVILEGE ESCALATION")
    print("   Phase 1: Failed SSH as 'deploy'")
    print("   Phase 2: Successful sudo by 'deploy'")
    print("=" * 60)

    now = datetime.now(timezone.utc)

    # Phase 1: Failed login attempts for user 'deploy'
    print("\n--- Phase 1: Failed authentication ---")
    for i in range(3):
        ts = (now + timedelta(seconds=i)).strftime("%b %d %H:%M:%S")
        log = (
            f"{ts} server01 sshd[{12500 + i}]: "
            f"Failed password for deploy from 10.20.30.40 port 22 ssh2"
        )
        print(f"  [{i + 1}/3] {log[:60]}...")
        send_log(base_url, log)
        time.sleep(0.2)

    # Phase 2: Successful sudo by that user
    print("\n--- Phase 2: Sudo command execution ---")
    ts = (now + timedelta(seconds=10)).strftime("%b %d %H:%M:%S")
    log = (
        f"{ts} server01 sudo[12510]: "
        f"deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; "
        f"COMMAND=/bin/bash"
    )
    print(f"  [SUDO] {log[:60]}...")
    send_log(base_url, log)

    print("\n✅ Privilege escalation simulation complete.")


def simulate_normal_traffic(base_url: str):
    """Send some normal (benign) log lines to verify no false positives."""
    print("\n" + "=" * 60)
    print("✅ SENDING NORMAL TRAFFIC (should NOT trigger alerts)")
    print("=" * 60)

    now = datetime.now(timezone.utc)
    normal_logs = [
        f"{now.strftime('%b %d %H:%M:%S')} server01 sshd[9000]: Accepted password for admin from 10.0.0.50 port 22 ssh2",
        f"{now.strftime('%b %d %H:%M:%S')} server01 sshd[9001]: Accepted publickey for devops from 10.0.0.51 port 22 ssh2",
        f"{(now + timedelta(minutes=5)).strftime('%b %d %H:%M:%S')} server01 sshd[9002]: Failed password for root from 10.0.0.52 port 22 ssh2",
    ]

    for i, log in enumerate(normal_logs):
        print(f"  [{i + 1}/{len(normal_logs)}] {log[:60]}...")
        send_log(base_url, log)
        time.sleep(0.2)


def simulate_anomaly_attack(base_url: str):
    """
    Simulate an ML anomaly: High velocity connections at 3 AM.
    This evades the static Brute Force rule (not failures) and
    static Port Scan rule (only 1 port), but the statistical
    model will flag it because of the hour and velocity.
    """
    print("\n" + "=" * 60)
    print("🤖 SIMULATING ML ANOMALY (Data Exfiltration Pattern)")
    print("   Attacker: Compromised internal host at 3 AM")
    print("=" * 60)

    now = datetime.now(timezone.utc)
    # Force time to 3 AM (highly unusual for our baseline)
    odd_hour = now.replace(hour=3)

    # 15 successful connections in rapid succession to the same port
    # Not a brute force, not a port scan, but highly anomalous speed/time
    for i in range(15):
        ts = (odd_hour + timedelta(seconds=i)).strftime("%b %d %H:%M:%S")
        log = (
            f"{ts} server01 sshd[{15000 + i}]: "
            f"Accepted publickey for sysadmin from 10.0.0.99 port 22 ssh2"
        )
        print(f"  [{i + 1}/15] {log[:60]}...")
        send_log(base_url, log)
        time.sleep(0.1)

    print("\n✅ ML Anomaly simulation complete.")


def simulate_threat_intel(base_url: str):
    """
    Simulate a single login attempt from a known malicious IP (Tor Exit Node).
    This immediately triggers the ThreatIntelRule regardless of thresholds.
    """
    print("\n" + "=" * 60)
    print("🌍 SIMULATING THREAT INTEL MATCH")
    print("   Attacker: 185.220.101.1 (Known Tor Exit Node)")
    print("=" * 60)

    now = datetime.now(timezone.utc)
    ts = now.strftime("%b %d %H:%M:%S")
    log = (
        f"{ts} server01 sshd[12345]: "
        f"Failed password for valid_user from 185.220.101.1 port 22 ssh2"
    )
    print(f"  Sending: {log[:70]}...")
    send_log(base_url, log)
    print("\n✅ Threat Intel simulation complete.")


def main():
    parser = argparse.ArgumentParser(description="Mini SOC Attack Simulator")
    parser.add_argument(
        "--mode",
        choices=["brute_force", "port_scan", "priv_escalation", "anomaly", "threat_intel", "mixed", "all"],
        default="mixed",
        help="Attack scenario to simulate",
    )
    parser.add_argument(
        "--target",
        default=API_URL,
        help="SOC API base URL (default: http://localhost:5000)",
    )
    args = parser.parse_args()

    print(f"🎯 Target: {args.target}")
    print(f"🗡️  Mode: {args.mode}")

    if args.mode == "brute_force":
        simulate_brute_force(args.target)
    elif args.mode == "port_scan":
        simulate_port_scan(args.target)
    elif args.mode == "priv_escalation":
        simulate_priv_escalation(args.target)
    elif args.mode == "anomaly":
        simulate_anomaly_attack(args.target)
    elif args.mode == "threat_intel":
        simulate_threat_intel(args.target)
    elif args.mode == "mixed":
        simulate_normal_traffic(args.target)
        simulate_brute_force(args.target)
        simulate_port_scan(args.target)
        simulate_anomaly_attack(args.target)
        simulate_threat_intel(args.target)
    elif args.mode == "all":
        simulate_normal_traffic(args.target)
        simulate_brute_force(args.target)
        simulate_port_scan(args.target)
        simulate_priv_escalation(args.target)
        simulate_anomaly_attack(args.target)
        simulate_threat_intel(args.target)

    # Print final alert summary
    print("\n" + "=" * 60)
    print("📊 CHECKING ALERT SUMMARY")
    print("=" * 60)
    try:
        url = f"{args.target}/api/stats"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            stats = json.loads(resp.read().decode())
            print(f"  Alert stats: {json.dumps(stats, indent=2)}")
    except Exception as e:
        print(f"  Could not fetch stats: {e}")

    try:
        url = f"{args.target}/api/alerts?limit=10"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            print(f"\n  Total alerts: {data.get('count', 0)}")
            for alert in data.get("alerts", []):
                print(
                    f"  🚨 [{alert['severity'].upper()}] "
                    f"{alert['rule_name']}: {alert['description'][:80]}..."
                )
    except Exception as e:
        print(f"  Could not fetch alerts: {e}")


if __name__ == "__main__":
    main()
