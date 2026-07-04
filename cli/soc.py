#!/usr/bin/env python3
"""
soc — Mini SOC command-line threat hunter.

A zero-setup, offline CLI that runs the *exact same* detection engine the
server uses, straight against your own log files. No MongoDB, no Postgres,
no server required — point it at /var/log/auth.log and get an instant
threat report, or live-tail a log and watch detections fire in real time.

Commands
--------
  soc scan  <logfile>     Analyze a log file and print a threat report
  soc watch <logfile>     Live-tail a log file, alerting on new lines
  soc ip    <address>     Look up an IP's threat-intel reputation
  soc demo                Run built-in attack scenarios through the engine

Examples
--------
  python -m cli scan /var/log/auth.log
  python -m cli scan sample_logs/auth.log --json
  sudo python -m cli watch /var/log/auth.log
  python -m cli ip 185.220.101.1
  python -m cli demo
"""

import argparse
import json
import logging
import os
import sys
import time
from collections import Counter

# The CLI presents its own output; silence the engine's internal logging
# so JSON stays clean and the report isn't duplicated by log lines.
logging.getLogger("mini_soc").setLevel(logging.CRITICAL)
logging.disable(logging.WARNING)

# Make `import app...` work whether invoked as `python -m cli` or `soc`
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.detection.engine import DetectionEngine
from app.enrichment.threat_intel import lookup_ip
from app.ingestion.access_log_parser import parse_access_log_line
from app.ingestion.normalizer import normalize_access_log, normalize_parsed_log
from app.ingestion.syslog_parser import parse_syslog_line


# --- Tiny ANSI color helper (no third-party deps) ------------------------

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"
    BG_RED = "\033[41m"


_NO_COLOR = not sys.stdout.isatty() or os.getenv("NO_COLOR")


def c(text, *codes):
    if _NO_COLOR:
        return text
    return "".join(codes) + str(text) + C.RESET


SEVERITY_STYLE = {
    "critical": (C.BOLD, C.RED),
    "high": (C.YELLOW,),
    "medium": (C.BLUE,),
    "low": (C.CYAN,),
    "info": (C.GREY,),
}


def sev_badge(severity):
    style = SEVERITY_STYLE.get(severity.lower(), (C.GREY,))
    return c(f" {severity.upper():^8} ", *style)


BANNER = r"""
   __  ____       _    ____   ___   ____
  |  \/  (_)_ __ (_)  / ___| / _ \ / ___|
  | |\/| | | '_ \| |  \___ \| | | | |
  | |  | | | | | | |   ___) | |_| | |___
  |_|  |_|_|_| |_|_|  |____/ \___/ \____|
    AI-Powered Threat Detection · CLI
"""


def print_banner():
    print(c(BANNER, C.CYAN, C.BOLD))


# --- Core: run a stream of raw lines through the detection engine --------

def _iter_events(lines):
    """
    Yield (raw_line, normalized_event) for each parseable line.

    Auto-detects the format: syslog / auth.log first, then Nginx/Apache
    access logs — so a single scan handles mixed sources.
    """
    for raw in lines:
        raw = raw.rstrip("\n")
        if not raw.strip():
            continue

        parsed = parse_syslog_line(raw)
        if parsed:
            event = normalize_parsed_log(parsed, raw)
            if event:
                yield raw, event
                continue

        web = parse_access_log_line(raw)
        if web:
            event = normalize_access_log(web, raw)
            if event:
                yield raw, event


def _format_alert(alert, verbose=False):
    src = alert.get("source_ip") or "local"
    mitre = alert.get("mitre")
    mitre_tag = c(f" [{mitre['technique']}]", C.CYAN) if mitre else ""
    line = (
        f"{sev_badge(alert['severity'])} "
        f"{c(alert['rule_name'], C.BOLD):<24} "
        f"src={c(src, C.MAGENTA)}{mitre_tag}"
    )
    out = [line]
    if verbose:
        out.append(c(f"      {alert.get('description', '')}", C.DIM))
        if mitre:
            out.append(c(
                f"      ATT&CK: {mitre['technique']} {mitre['name']} "
                f"({mitre['tactic']})", C.CYAN, C.DIM))
    return "\n".join(out)


# --- Command: scan -------------------------------------------------------

def cmd_scan(args):
    if not os.path.exists(args.logfile):
        print(c(f"error: file not found: {args.logfile}", C.RED))
        return 2

    engine = DetectionEngine()

    alerts = []
    total_lines = 0
    parsed_events = 0
    ip_counter = Counter()
    action_counter = Counter()

    with open(args.logfile, "r", errors="replace") as fh:
        lines = fh.readlines()

    total_lines = len(lines)
    for raw, event in _iter_events(lines):
        parsed_events += 1
        if event.get("source_ip"):
            ip_counter[event["source_ip"]] += 1
        if event.get("action"):
            action_counter[event["action"]] += 1
        for alert in engine.evaluate(event):
            alerts.append(alert)

    if args.json:
        print(json.dumps(
            {
                "file": args.logfile,
                "lines": total_lines,
                "events_parsed": parsed_events,
                "alerts": alerts,
            },
            indent=2,
            default=str,
        ))
        return 1 if alerts else 0

    if not args.quiet:
        print_banner()
    print(c(f"  Scanning {args.logfile}", C.BOLD))
    print(c(
        f"  {total_lines} lines · {parsed_events} events parsed · "
        f"{len(ip_counter)} unique source IPs\n",
        C.DIM,
    ))

    # Threat summary
    sev_counts = Counter(a["severity"] for a in alerts)
    if not alerts:
        print(c("  ✓ No threats detected. Logs look clean.\n", C.GREEN, C.BOLD))
    else:
        print(c(f"  ⚠ {len(alerts)} THREAT(S) DETECTED", C.RED, C.BOLD))
        summary = "  ".join(
            f"{sev_badge(s)} x{sev_counts[s]}"
            for s in ("critical", "high", "medium", "low")
            if sev_counts.get(s)
        )
        print("   " + summary + "\n")

        for alert in alerts:
            print("  " + _format_alert(alert, verbose=True))
        print()

    # Top talkers — the IPs an analyst would triage first
    if ip_counter:
        flagged = {a.get("source_ip") for a in alerts}
        print(c("  Top source IPs", C.BOLD))
        for ip, count in ip_counter.most_common(args.top):
            mark = c(" ← flagged", C.RED) if ip in flagged else ""
            print(f"    {c(ip, C.MAGENTA):<28} {count:>5} events{mark}")
        print()

    # Recommended containment — mirrors what the SOAR engine would auto-apply
    block_ips = sorted({
        a["source_ip"] for a in alerts
        if a.get("source_ip") and a["severity"] in ("high", "critical")
    })
    if block_ips:
        print(c("  Recommended containment (iptables)", C.BOLD))
        for ip in block_ips:
            print(c(f"    iptables -A INPUT -s {ip} -j DROP", C.GREEN))
        print()

    return 1 if alerts else 0


# --- Command: watch ------------------------------------------------------

def _tail(path):
    """Generator that yields new lines appended to a file (like tail -f)."""
    with open(path, "r", errors="replace") as fh:
        fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            if not line:
                time.sleep(0.3)
                continue
            yield line


def cmd_watch(args):
    if not os.path.exists(args.logfile):
        print(c(f"error: file not found: {args.logfile}", C.RED))
        return 2

    engine = DetectionEngine()
    if not args.quiet:
        print_banner()
    print(c(f"  Watching {args.logfile} — Ctrl-C to stop\n", C.BOLD))

    seen_alerts = 0
    try:
        for raw in _tail(args.logfile):
            for _, event in _iter_events([raw]):
                for alert in engine.evaluate(event):
                    seen_alerts += 1
                    ts = time.strftime("%H:%M:%S")
                    print(f"  {c(ts, C.GREY)}  " + _format_alert(alert, verbose=True))
    except KeyboardInterrupt:
        print(c(f"\n  Stopped. {seen_alerts} alert(s) during session.", C.DIM))
    return 0


# --- Command: ip ---------------------------------------------------------

def cmd_ip(args):
    intel = lookup_ip(args.address)
    if args.json:
        print(json.dumps({"ip": args.address, **intel}, indent=2))
        return 0

    score = intel.get("reputation_score", 0)
    malicious = intel.get("malicious", False)
    color = C.RED if malicious else C.GREEN
    verdict = "MALICIOUS" if malicious else "CLEAN"

    print()
    print(f"  IP        {c(args.address, C.MAGENTA, C.BOLD)}")
    print(f"  Verdict   {c(verdict, color, C.BOLD)}")
    print(f"  Score     {c(f'{score}/100', color)}")
    tags = intel.get("tags", [])
    if tags:
        print(f"  Tags      {c(', '.join(tags), C.YELLOW)}")
    print(f"  Provider  {c(intel.get('provider', 'unknown'), C.DIM)}")
    print()
    return 1 if malicious else 0


# --- Command: demo -------------------------------------------------------

def cmd_demo(args):
    """Fire built-in attack scenarios at the engine with no server/DB."""
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)

    def ts(offset):
        return (now + timedelta(seconds=offset)).strftime("%b %d %H:%M:%S")

    scenarios = []
    # Brute force
    scenarios += [
        f"{ts(i)} server01 sshd[{12340+i}]: Failed password for root "
        f"from 192.168.1.100 port 22 ssh2"
        for i in range(6)
    ]
    # Port scan
    scenarios += [
        f"{ts(i)} firewall01 kernel: BLOCKED IN=eth0 SRC=203.0.113.50 "
        f"DST=10.0.0.1 DPT={p} PROTO=TCP"
        for i, p in enumerate([22, 80, 443, 8080, 3306, 5432, 6379, 27017, 21, 25, 110])
    ]
    # Threat intel hit
    scenarios.append(
        f"{ts(0)} server01 sshd[999]: Failed password for user "
        f"from 185.220.101.1 port 22 ssh2"
    )

    if not args.quiet:
        print_banner()
    print(c("  Running built-in attack scenarios through the live engine\n", C.BOLD))

    engine = DetectionEngine()
    fired = 0
    for _, event in _iter_events(scenarios):
        for alert in engine.evaluate(event):
            fired += 1
            print("  " + _format_alert(alert, verbose=True))
    print()
    print(c(f"  {fired} alert(s) generated from {len(scenarios)} simulated log lines.", C.CYAN))
    return 0


# --- Command: report -----------------------------------------------------

def _scan_file(path):
    """Run the engine over a file, returning (alerts, stats)."""
    engine = DetectionEngine()
    with open(path, "r", errors="replace") as fh:
        lines = fh.readlines()

    alerts = []
    ip_counter = Counter()
    parsed = 0
    for _, event in _iter_events(lines):
        parsed += 1
        if event.get("source_ip"):
            ip_counter[event["source_ip"]] += 1
        alerts.extend(engine.evaluate(event))

    return alerts, {
        "lines": len(lines),
        "events": parsed,
        "ips": ip_counter,
    }


def _html_escape(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def cmd_report(args):
    if not os.path.exists(args.logfile):
        print(c(f"error: file not found: {args.logfile}", C.RED))
        return 2

    from datetime import datetime, timezone

    alerts, stats = _scan_file(args.logfile)
    sev_counts = Counter(a["severity"] for a in alerts)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sev_colors = {
        "critical": "#ef4444", "high": "#f59e0b",
        "medium": "#eab308", "low": "#3b82f6", "info": "#64748b",
    }

    rows = []
    for a in alerts:
        mitre = a.get("mitre") or {}
        sev = a["severity"]
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{sev_colors.get(sev, '#64748b')}22;
              color:{sev_colors.get(sev, '#64748b')};border:1px solid {sev_colors.get(sev, '#64748b')}55">
              {sev.upper()}</span></td>
          <td class="mono">{_html_escape(a['rule_name'])}</td>
          <td class="mono">{_html_escape(a.get('source_ip') or 'local')}</td>
          <td>{_html_escape(mitre.get('technique', '—'))} {_html_escape(mitre.get('name', ''))}</td>
          <td class="desc">{_html_escape(a.get('description', ''))}</td>
        </tr>""")

    tiles = "".join(
        f"""<div class="tile"><div class="num" style="color:{sev_colors[s]}">{sev_counts.get(s, 0)}</div>
        <div class="lbl">{s.title()}</div></div>"""
        for s in ("critical", "high", "medium", "low")
    )

    top_ips = "".join(
        f"<li><span class='mono'>{_html_escape(ip)}</span> — {n} events</li>"
        for ip, n in stats["ips"].most_common(10)
    )

    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mini SOC Incident Report</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:#0f172a; color:#e2e8f0;
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }}
  .wrap {{ max-width: 1000px; margin: 0 auto; padding: 32px 20px 64px; }}
  h1 {{ font-size: 1.6rem; margin: 0 0 4px; }}
  .sub {{ color:#94a3b8; font-size:.9rem; margin-bottom: 24px; }}
  .tiles {{ display:grid; grid-template-columns: repeat(4, 1fr); gap:14px; margin-bottom:28px; }}
  .tile {{ background:#1e293b; border:1px solid #334155; border-radius:12px; padding:18px; text-align:center; }}
  .tile .num {{ font-size:2rem; font-weight:800; }}
  .tile .lbl {{ color:#94a3b8; font-size:.8rem; text-transform:uppercase; letter-spacing:.05em; }}
  h2 {{ font-size:1.05rem; margin: 26px 0 12px; }}
  table {{ width:100%; border-collapse:collapse; background:#1e293b;
    border:1px solid #334155; border-radius:12px; overflow:hidden; font-size:.86rem; }}
  th {{ text-align:left; padding:12px; background:#0f172a; color:#94a3b8;
    text-transform:uppercase; font-size:.72rem; letter-spacing:.05em; }}
  td {{ padding:12px; border-top:1px solid #334155; vertical-align:top; }}
  .desc {{ color:#cbd5e1; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
  .badge {{ padding:3px 9px; border-radius:99px; font-size:.7rem; font-weight:700; }}
  ul {{ line-height:1.9; }}
  .ok {{ background:#10b98122; border:1px solid #10b98155; color:#34d399;
    padding:18px; border-radius:12px; }}
  footer {{ margin-top:36px; color:#64748b; font-size:.8rem; }}
</style></head><body><div class="wrap">
  <h1>🛡️ Mini SOC — Incident Report</h1>
  <div class="sub">Source: <span class="mono">{_html_escape(args.logfile)}</span>
    · {stats['events']} events analyzed · {len(alerts)} alert(s) · Generated {generated}</div>
  <div class="tiles">{tiles}</div>
  {"<h2>Detections</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>Source IP</th><th>ATT&CK</th><th>Detail</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>" if alerts else '<div class="ok">✓ No threats detected. Logs look clean.</div>'}
  <h2>Top Source IPs</h2><ul>{top_ips or "<li>none</li>"}</ul>
  <footer>Generated by the <b>Mini SOC</b> CLI · github.com/tanmaymish/mini-soc</footer>
</div></body></html>"""

    with open(args.output, "w") as fh:
        fh.write(html)

    print(c(f"  ✓ Report written to {args.output}", C.GREEN, C.BOLD))
    print(c(f"    {len(alerts)} alert(s) · open it in a browser to view/share.", C.DIM))
    return 0


# --- Entry point ---------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="soc",
        description="Mini SOC — offline threat hunter for your log files.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    ps = sub.add_parser("scan", help="Analyze a log file and print a threat report")
    ps.add_argument("logfile", help="Path to a syslog / auth.log file")
    ps.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    ps.add_argument("--quiet", action="store_true", help="Suppress the banner")
    ps.add_argument("--top", type=int, default=5, help="How many top source IPs to show")
    ps.set_defaults(func=cmd_scan)

    pw = sub.add_parser("watch", help="Live-tail a log file, alerting on new lines")
    pw.add_argument("logfile", help="Path to a log file to tail")
    pw.add_argument("--quiet", action="store_true", help="Suppress the banner")
    pw.set_defaults(func=cmd_watch)

    pi = sub.add_parser("ip", help="Look up an IP's threat-intel reputation")
    pi.add_argument("address", help="IPv4 address to look up")
    pi.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    pi.set_defaults(func=cmd_ip)

    pd = sub.add_parser("demo", help="Run built-in attack scenarios through the engine")
    pd.add_argument("--quiet", action="store_true", help="Suppress the banner")
    pd.set_defaults(func=cmd_demo)

    pr = sub.add_parser("report", help="Generate a shareable HTML incident report")
    pr.add_argument("logfile", help="Path to a log file to analyze")
    pr.add_argument("-o", "--output", default="soc-report.html",
                    help="Output HTML path (default: soc-report.html)")
    pr.set_defaults(func=cmd_report)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
