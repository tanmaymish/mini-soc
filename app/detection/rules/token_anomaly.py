"""
Token / Session Anomaly Rule.

ATTACKER BEHAVIOR:
  A stolen bearer token or session cookie is used from the attacker's own
  host — so the same token suddenly appears from a *new IP* (session hijack).
  Worse, a token scoped to one tenant is used to read *another tenant's* data
  (broken tenant isolation / IDOR) — a critical multi-tenant data breach.

DETECTION LOGIC:
  Track, per token, the set of source IPs and tenants seen:
    - token seen from a 2nd distinct IP      → token reuse (high)
    - token/user touching a 2nd distinct
      tenant                                 → multi-tenant access (critical)

REAL-WORLD EQUIVALENT:
  - Okta / Auth0 impossible-travel & token-binding signals
  - OWASP API Security — API1 Broken Object Level Authorization
"""

from collections import defaultdict

from app.detection.rules.base_rule import BaseRule
from app.models.alert import create_alert


class TokenAnomalyRule(BaseRule):
    def __init__(self, ip_threshold: int = 3):
        """
        Args:
            ip_threshold: Distinct source IPs on one token before alerting.

        This used to alert the moment a token appeared from a second address,
        which is what a phone does every time it drops off wifi onto mobile
        data - and what any NAT, VPN or carrier-grade proxy looks like from
        the server side. The detection benchmark scored it at 50% precision.

        Three is a threshold, not a fix. The real discriminator is impossible
        travel: two addresses far enough apart that no one could have moved
        between them in the elapsed time. That needs geo-IP or ASN data this
        project does not have yet, so the count is the stand-in, and it trades
        recall for precision - a stolen token used from exactly one extra
        address is now missed. Multi-tenant access still fires on the first
        occurrence, because one token reading two tenants' data has no
        innocent explanation.
        """
        self._ip_threshold = ip_threshold
        self._token_ips = defaultdict(set)      # token -> {ip}
        self._token_tenants = defaultdict(set)  # token -> {tenant}
        self._alerted = set()                   # (token, kind) already fired

    @property
    def name(self) -> str:
        return "token_anomaly"

    @property
    def description(self) -> str:
        return (
            "Detects stolen-token indicators: the same token used from a new "
            "IP (session hijack) or accessing a second tenant (broken tenant "
            "isolation / multi-tenant data access)."
        )

    @property
    def severity(self) -> str:
        return "high"

    @property
    def mitre(self) -> dict:
        return {
            "technique": "T1539",
            "name": "Steal Web Session Cookie",
            "tactic": "Credential Access",
        }

    def evaluate(self, event: dict) -> dict | None:
        if event.get("action") != "API_REQUEST":
            return None
        token = event.get("token")
        if not token:
            return None

        ip = event.get("source_ip")
        tenant = event.get("tenant")

        self._token_ips[token].add(ip)
        if tenant:
            self._token_tenants[token].add(tenant)

        # Multi-tenant access is the more severe finding — check first.
        if len(self._token_tenants[token]) > 1 and (token, "tenant") not in self._alerted:
            self._alerted.add((token, "tenant"))
            return create_alert(
                rule_name=self.name, severity="critical", source_ip=ip,
                description=(
                    f"Multi-tenant data access: token '{_mask(token)}' touched "
                    f"tenants {sorted(self._token_tenants[token])} "
                    f"(broken tenant isolation / IDOR)."
                ),
                evidence=[event],
                metadata={"kind": "multi_tenant_access", "token": _mask(token),
                          "tenants": sorted(self._token_tenants[token])},
            )

        if len(self._token_ips[token]) >= self._ip_threshold and (token, "ip") not in self._alerted:
            self._alerted.add((token, "ip"))
            return create_alert(
                rule_name=self.name, severity="high", source_ip=ip,
                description=(
                    f"Token reuse from new IP: token '{_mask(token)}' seen from "
                    f"{sorted(self._token_ips[token])} (possible session hijack)."
                ),
                evidence=[event],
                metadata={"kind": "token_reuse", "token": _mask(token),
                          "ips": sorted(self._token_ips[token])},
            )
        return None

    def reset(self):
        self._token_ips.clear()
        self._token_tenants.clear()
        self._alerted.clear()


def _mask(token: str) -> str:
    return token if len(token) <= 6 else f"{token[:4]}…{token[-2:]}"
