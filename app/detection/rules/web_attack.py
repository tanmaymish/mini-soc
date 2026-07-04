"""
Web Attack Detection Rule.

ATTACKER BEHAVIOR:
  Web servers are the most-probed surface on the internet. Before (or instead
  of) a full exploit, attackers spray payloads at every parameter: SQL
  injection, cross-site scripting, path traversal, command injection — and
  automated scanners (sqlmap, nikto, nuclei) announce themselves in the
  User-Agent.

DETECTION LOGIC:
  Single-event, signature-based. Inspect the decoded request path + query and
  the User-Agent for known attack markers. One malicious request is enough to
  fire — this is a WAF-style detection, not a threshold.

REAL-WORLD EQUIVALENT:
  - ModSecurity / OWASP Core Rule Set
  - Cloudflare WAF managed rules
  - AWS WAF SQLi/XSS rule groups
"""

import re
from urllib.parse import unquote_plus

from app.detection.rules.base_rule import BaseRule
from app.models.alert import create_alert

# Signature groups: (label, compiled regex). Kept deliberately readable — each
# maps to a well-known web attack class.
_SIGNATURES = [
    ("SQL Injection", re.compile(
        r"(\bunion\b\s+\bselect\b|\bor\b\s+1\s*=\s*1|'\s*or\s*'|"
        r"\bsleep\s*\(|\bbenchmark\s*\(|information_schema|"
        r"\bxp_cmdshell\b|--\s|/\*.*\*/|\bconcat\s*\()", re.I)),
    ("Cross-Site Scripting (XSS)", re.compile(
        r"(<script\b|</script>|javascript:|onerror\s*=|onload\s*=|"
        r"<img[^>]+src|document\.cookie|alert\s*\()", re.I)),
    ("Path Traversal / LFI", re.compile(
        r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini|"
        r"win\.ini|/proc/self/environ)", re.I)),
    ("Command Injection", re.compile(
        r"(;\s*(cat|ls|id|whoami|wget|curl)\b|\|\s*(nc|bash|sh)\b|"
        r"\$\([^)]+\)|`[^`]+`|&&\s*(cat|ls|id))", re.I)),
]

# Well-known offensive-security scanners that identify themselves in the UA.
_SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|"
    r"acunetix|nessus|nuclei|feroxbuster|httpx|zgrab|zmap)", re.I)


class WebAttackRule(BaseRule):
    """Flags web requests carrying attack payloads or from known scanners."""

    @property
    def name(self) -> str:
        return "web_attack"

    @property
    def description(self) -> str:
        return (
            "Detects web-layer attacks (SQL injection, XSS, path traversal, "
            "command injection) and automated vulnerability scanners in "
            "Nginx/Apache access logs."
        )

    @property
    def severity(self) -> str:
        return "high"

    @property
    def mitre(self) -> dict:
        return {
            "technique": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
        }

    def evaluate(self, event: dict) -> dict | None:
        if event.get("action") != "WEB_REQUEST":
            return None

        # URL-decode so encoded payloads (%27, %2e%2e) are caught too.
        haystack = unquote_plus(
            f"{event.get('path', '')}?{event.get('query', '')}"
        )
        user_agent = event.get("user_agent", "") or ""
        source_ip = event.get("source_ip")

        findings = [label for label, rx in _SIGNATURES if rx.search(haystack)]

        scanner = _SCANNER_UA.search(user_agent)
        if scanner:
            findings.append(f"Scanner: {scanner.group(0)}")

        if not findings:
            return None

        # SQLi / command injection are the most dangerous — bump to critical.
        severity = "critical" if any(
            f.startswith(("SQL", "Command")) for f in findings
        ) else "high"

        return create_alert(
            rule_name=self.name,
            severity=severity,
            source_ip=source_ip,
            description=(
                f"Web attack from {source_ip}: {', '.join(findings)}. "
                f"{event.get('http_method', '')} {event.get('url', '')}"
            ),
            evidence=[event],
            metadata={
                "categories": findings,
                "http_method": event.get("http_method"),
                "url": event.get("url"),
                "status": event.get("status"),
                "user_agent": user_agent,
            },
        )
