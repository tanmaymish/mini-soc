"""
Labelled corpus of benign and malicious traffic.

Every scenario is a short, self-contained slice of activity from one actor,
labelled with the rules that *should* fire on it. A scenario expecting nothing
is a scenario that must stay silent.

The benign half is the important half, and it is written to be realistic rather
than convenient: an admin who fat-fingers a password and then runs sudo, a
single-page dashboard fanning out across a dozen endpoints on load, a phone
that changes IP mid-session when it drops off wifi. Those are the shapes that
generate pager fatigue in a real SOC, so the corpus contains them even where
they are known to fire today. A corpus that only contains traffic the rules
already handle measures nothing.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# A fixed epoch keeps every run byte-identical, so a change in the numbers means
# a change in the rules rather than a change in the wall clock.
BASE = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)

# Reputation scores come from app.enrichment.threat_intel.MOCK_TI_DATABASE.
KNOWN_BAD_IP = "45.33.32.156"
CLEAN_INTEL = {"reputation_score": 0, "tags": [], "provider": "mock_ti", "malicious": False}


def at(seconds: float) -> str:
    """An ISO timestamp `seconds` after the corpus epoch."""
    return (BASE + timedelta(seconds=seconds)).isoformat()


@dataclass
class Scenario:
    """One actor's activity, plus the rules that should fire on it."""

    name: str
    kind: str  # "benign" or "attack"
    events: list
    expect: set = field(default_factory=set)
    note: str = ""


def _syslog(action, second, source_ip="203.0.113.10", user=None, port=None, **extra):
    """A normalized syslog-shaped event, always with clean intel attached."""
    event = {
        "timestamp": at(second),
        "source_ip": source_ip,
        "hostname": "app-01",
        "service": "sshd",
        "action": action,
        "user": user,
        "destination_port": port,
        "severity": "info",
        "raw": f"{action} from {source_ip}",
        "metadata": {"intel": dict(CLEAN_INTEL)},
    }
    event.update(extra)
    return event


def _web(second, path, source_ip="203.0.113.20", query="", ua="Mozilla/5.0", status=200,
         method="GET"):
    return {
        "timestamp": at(second),
        "source_ip": source_ip,
        "action": "WEB_REQUEST",
        "http_method": method,
        "path": path,
        "query": query,
        "url": f"{path}?{query}" if query else path,
        "status": status,
        "user_agent": ua,
        "metadata": {"intel": dict(CLEAN_INTEL)},
    }


def _api(second, path, source_ip="203.0.113.30", status=200, method="GET", role="user",
         token=None, tenant=None, graphql=None):
    event = {
        "timestamp": at(second),
        "source_ip": source_ip,
        "action": "API_REQUEST",
        "http_method": method,
        "path": path,
        "status": status,
        "role": role,
        "metadata": {"intel": dict(CLEAN_INTEL)},
    }
    if token:
        event["token"] = token
    if tenant:
        event["tenant"] = tenant
    if graphql:
        event["graphql"] = graphql
    return event


# ──────────────────────────────────────────────────────────────────────────
# Benign: an ordinary working day
# ──────────────────────────────────────────────────────────────────────────

def _benign() -> list:
    return [
        Scenario(
            name="routine_ssh_logins",
            kind="benign",
            note="Four engineers logging into a jump host over a minute.",
            events=[
                _syslog("ACCEPTED_LOGIN", 0, "203.0.113.11", user="asha", port=22),
                _syslog("ACCEPTED_LOGIN", 12, "203.0.113.12", user="ravi", port=22),
                _syslog("ACCEPTED_LOGIN", 31, "203.0.113.13", user="meera", port=22),
                _syslog("ACCEPTED_LOGIN", 55, "203.0.113.14", user="dev", port=22),
            ],
        ),
        Scenario(
            name="mistyped_password_then_success",
            kind="benign",
            note="Two typos then a successful login. Below the brute-force threshold.",
            events=[
                _syslog("FAILED_LOGIN", 0, "203.0.113.15", user="asha", port=22),
                _syslog("FAILED_LOGIN", 6, "203.0.113.15", user="asha", port=22),
                _syslog("ACCEPTED_LOGIN", 14, "203.0.113.15", user="asha", port=22),
            ],
        ),
        Scenario(
            name="admin_typo_then_sudo",
            kind="benign",
            note=(
                "An administrator mistypes their password once, logs in, and runs "
                "sudo a minute later. This is the single most common shape in any "
                "auth log and it must not page anyone."
            ),
            events=[
                _syslog("FAILED_LOGIN", 0, "203.0.113.16", user="root-ops", port=22),
                _syslog("ACCEPTED_LOGIN", 9, "203.0.113.16", user="root-ops", port=22),
                _syslog("SUDO_COMMAND", 70, "203.0.113.16", user="root-ops",
                        service="sudo", message="systemctl restart nginx"),
            ],
        ),
        Scenario(
            name="routine_sudo_no_failures",
            kind="benign",
            note="An operator with a clean auth history running sudo.",
            events=[
                _syslog("ACCEPTED_LOGIN", 0, "203.0.113.17", user="deploy", port=22),
                _syslog("SUDO_COMMAND", 20, "203.0.113.17", user="deploy",
                        service="sudo", message="journalctl -u api"),
            ],
        ),
        Scenario(
            name="healthy_service_connections",
            kind="benign",
            note="A load balancer health-checking three ports repeatedly.",
            events=[
                _syslog("CONNECTION", s, "203.0.113.18", port=p)
                for s, p in [(0, 80), (2, 443), (4, 8080), (8, 80), (11, 443),
                             (14, 8080), (18, 80), (22, 443), (26, 8080)]
            ],
        ),
        Scenario(
            name="normal_web_browsing",
            kind="benign",
            note="A shopper moving through a storefront.",
            events=[
                _web(0, "/"),
                _web(4, "/products", query="page=2&sort=price"),
                _web(9, "/products/aurora-headphones"),
                _web(15, "/cart", method="POST"),
                _web(21, "/checkout", method="POST", status=302),
            ],
        ),
        Scenario(
            name="search_query_with_quotes",
            kind="benign",
            note=(
                "A shopper searching for a product whose name contains an "
                "apostrophe. Naive SQLi signatures love this one."
            ),
            events=[_web(0, "/search", query="q=childrens%27+books")],
        ),
        Scenario(
            name="dashboard_page_load",
            kind="benign",
            note=(
                "A single-page app hydrating a dashboard: eleven distinct "
                "endpoints in four seconds, which is what every SPA on earth does."
            ),
            events=[
                _api(s, path, source_ip="203.0.113.31", token="tok-spa", tenant="acme")
                for s, path in enumerate([
                    "/api/profile", "/api/users/me", "/api/notifications",
                    "/api/billing/summary", "/api/projects", "/api/projects/1",
                    "/api/projects/1/members", "/api/activity", "/api/settings",
                    "/api/features", "/api/health",
                ])
            ],
        ),
        Scenario(
            name="admin_doing_admin_things",
            kind="benign",
            note="A genuine administrator using the admin control plane.",
            events=[
                _api(0, "/api/admin/users", source_ip="203.0.113.32", role="admin"),
                _api(5, "/api/admin/users/42", source_ip="203.0.113.32", role="admin",
                     method="PATCH"),
                _api(11, "/api/admin/audit", source_ip="203.0.113.32", role="admin"),
            ],
        ),
        Scenario(
            name="normal_graphql_query",
            kind="benign",
            note="An ordinary shallow GraphQL read.",
            events=[
                _api(0, "/api/graphql", source_ip="203.0.113.33", method="POST",
                     graphql="query { viewer { name email } }"),
            ],
        ),
        Scenario(
            name="mobile_client_changes_ip",
            kind="benign",
            note=(
                "A phone drops off wifi onto mobile data mid-session, so the same "
                "token arrives from a second address. Also what any NAT, VPN or "
                "carrier-grade proxy looks like."
            ),
            events=[
                _api(0, "/api/projects", source_ip="203.0.113.34", token="tok-phone",
                     tenant="acme"),
                _api(40, "/api/projects", source_ip="198.51.100.77", token="tok-phone",
                     tenant="acme"),
            ],
        ),
        Scenario(
            name="user_hits_a_few_404s",
            kind="benign",
            note="Stale bookmarks and a deleted project. Three not-founds, not a scan.",
            events=[
                _api(0, "/api/projects/900", source_ip="203.0.113.35", status=404),
                _api(6, "/api/projects/901", source_ip="203.0.113.35", status=404),
                _api(13, "/api/projects/902", source_ip="203.0.113.35", status=404),
            ],
        ),
        Scenario(
            name="one_failed_admin_auth",
            kind="benign",
            note="An expired session hitting an admin route once.",
            events=[
                _api(0, "/api/admin/users", source_ip="203.0.113.36", status=401,
                     role="user"),
            ],
        ),
    ]


# ──────────────────────────────────────────────────────────────────────────
# Attacks: each labelled with the rule that should catch it
# ──────────────────────────────────────────────────────────────────────────

def _attacks() -> list:
    return [
        Scenario(
            name="ssh_brute_force",
            kind="attack",
            expect={"brute_force_ssh"},
            note="Six failed logins from one host inside the 60s window.",
            events=[
                _syslog("FAILED_LOGIN", s, "198.51.100.10", user="root", port=22)
                for s in (0, 3, 6, 9, 12, 15)
            ],
        ),
        Scenario(
            name="slow_brute_force_across_users",
            kind="attack",
            expect={"brute_force_ssh"},
            note="Password spraying: one attempt each against six accounts.",
            events=[
                _syslog("FAILED_LOGIN", s, "198.51.100.11", user=u, port=22)
                for s, u in enumerate(["root", "admin", "oracle", "postgres", "git", "test"])
            ],
        ),
        Scenario(
            name="horizontal_port_scan",
            kind="attack",
            expect={"port_scan"},
            note="Twelve distinct ports touched inside the 30s window.",
            events=[
                _syslog("CONNECTION", s * 2, "198.51.100.12", port=p)
                for s, p in enumerate([21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389])
            ],
        ),
        Scenario(
            name="privilege_escalation_after_brute_force",
            kind="attack",
            expect={"brute_force_ssh", "privilege_escalation"},
            note=(
                "A compromised account: five failures, a success, then sudo. Both "
                "rules are supposed to fire here, so both are declared."
            ),
            events=[
                _syslog("FAILED_LOGIN", 0, "198.51.100.13", user="svc-backup", port=22),
                _syslog("FAILED_LOGIN", 4, "198.51.100.13", user="svc-backup", port=22),
                _syslog("FAILED_LOGIN", 8, "198.51.100.13", user="svc-backup", port=22),
                _syslog("FAILED_LOGIN", 12, "198.51.100.13", user="svc-backup", port=22),
                _syslog("FAILED_LOGIN", 16, "198.51.100.13", user="svc-backup", port=22),
                _syslog("ACCEPTED_LOGIN", 20, "198.51.100.13", user="svc-backup", port=22),
                _syslog("SUDO_COMMAND", 26, "198.51.100.13", user="svc-backup",
                        service="sudo", message="cat /etc/shadow"),
            ],
        ),
        Scenario(
            name="sql_injection",
            kind="attack",
            expect={"web_attack"},
            events=[_web(0, "/products", query="id=1%27+OR+%271%27%3D%271",
                         source_ip="198.51.100.14")],
        ),
        Scenario(
            name="union_select_injection",
            kind="attack",
            expect={"web_attack"},
            events=[_web(0, "/report", query="id=1+UNION+SELECT+username,password+FROM+users",
                         source_ip="198.51.100.15")],
        ),
        Scenario(
            name="reflected_xss",
            kind="attack",
            expect={"web_attack"},
            events=[_web(0, "/search", query="q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                         source_ip="198.51.100.16")],
        ),
        Scenario(
            name="path_traversal",
            kind="attack",
            expect={"web_attack"},
            events=[_web(0, "/download", query="file=..%2f..%2f..%2fetc%2fpasswd",
                         source_ip="198.51.100.17", status=404)],
        ),
        Scenario(
            name="vulnerability_scanner_user_agent",
            kind="attack",
            expect={"web_attack"},
            events=[_web(0, "/admin", source_ip="198.51.100.18",
                         ua="sqlmap/1.7.2#stable (http://sqlmap.org)", status=404)],
        ),
        Scenario(
            name="broken_function_level_authorization",
            kind="attack",
            expect={"admin_endpoint_abuse"},
            note="A plain user successfully calling an admin endpoint.",
            events=[_api(0, "/api/admin/users", source_ip="198.51.100.19", role="user",
                         status=200)],
        ),
        Scenario(
            name="admin_auth_bypass_probing",
            kind="attack",
            expect={"admin_endpoint_abuse"},
            note="Four denials on the admin control plane inside the window.",
            events=[
                _api(s * 10, p, source_ip="198.51.100.20", status=403, role="user")
                for s, p in enumerate(["/api/admin/users", "/api/admin/config",
                                       "/api/admin/keys", "/api/admin/audit"])
            ],
        ),
        Scenario(
            name="graphql_introspection",
            kind="attack",
            expect={"graphql_abuse"},
            note="Schema dumping, the first move against an unfamiliar GraphQL API.",
            events=[_api(0, "/api/graphql", source_ip="198.51.100.21", method="POST",
                         graphql="query { __schema { types { name fields { name } } } }")],
        ),
        Scenario(
            name="graphql_deep_nesting_dos",
            kind="attack",
            expect={"graphql_abuse"},
            note=(
                "Depth 12 against a max_depth of 8. The first draft of this scenario "
                "used a depth-8 query and was scored as a miss - but a query at the "
                "threshold is not over it, so the corpus was wrong, not the rule."
            ),
            events=[_api(0, "/api/graphql", source_ip="198.51.100.22", method="POST",
                         graphql="query { a { b { c { d { e { f { g { h { i { j { k { l "
                                 "} } } } } } } } } } } }")],
        ),
        Scenario(
            name="api_rate_flood",
            kind="attack",
            expect={"api_abuse"},
            note="Thirty requests to one endpoint in half the window.",
            events=[
                _api(s * 0.4, "/api/login", source_ip="198.51.100.23", status=401,
                     method="POST")
                for s in range(30)
            ],
        ),
        Scenario(
            name="endpoint_enumeration",
            kind="attack",
            expect={"api_abuse"},
            note="Guessing at undocumented endpoints; everything comes back 404.",
            events=[
                _api(s, p, source_ip="198.51.100.24", status=404)
                for s, p in enumerate([
                    "/api/v1/secrets", "/api/internal/debug", "/api/admin/backup",
                    "/api/.env", "/api/config.json", "/api/actuator/env",
                    "/api/swagger.json", "/api/graphiql", "/api/console",
                ])
            ],
        ),
        Scenario(
            name="stolen_token_across_tenants",
            kind="attack",
            expect={"token_anomaly"},
            note="One bearer token reading two tenants' data — broken isolation.",
            events=[
                _api(0, "/api/projects", source_ip="198.51.100.25", token="tok-stolen",
                     tenant="acme"),
                _api(20, "/api/projects", source_ip="198.51.100.25", token="tok-stolen",
                     tenant="globex"),
            ],
        ),
        Scenario(
            name="token_used_from_many_addresses",
            kind="attack",
            expect={"token_anomaly"},
            note="One token appearing from three unrelated addresses in a minute.",
            events=[
                _api(0, "/api/projects", source_ip="198.51.100.26", token="tok-spread",
                     tenant="acme"),
                _api(25, "/api/projects", source_ip="203.0.113.90", token="tok-spread",
                     tenant="acme"),
                _api(50, "/api/projects", source_ip="192.0.2.55", token="tok-spread",
                     tenant="acme"),
            ],
        ),
        Scenario(
            name="known_bad_ip_contact",
            kind="attack",
            expect={"threat_intel_match"},
            note="Traffic from an IP the intel platform scores 88/100.",
            events=[{
                "timestamp": at(0),
                "source_ip": KNOWN_BAD_IP,
                "hostname": "app-01",
                "service": "sshd",
                "action": "ACCEPTED_LOGIN",
                "user": "deploy",
                "destination_port": 22,
                "severity": "info",
                "raw": "Accepted password for deploy",
                "metadata": {"intel": {
                    "reputation_score": 88,
                    "tags": ["BRUTE_FORCER", "BOTNET"],
                    "provider": "mock_ti",
                    "malicious": True,
                }},
            }],
        ),
    ]


def load() -> list:
    """The whole corpus, benign first."""
    return _benign() + _attacks()
