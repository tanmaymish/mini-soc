"""
Tests for the API-security detection domain and the correlation engine.
"""

from datetime import datetime, timezone, timedelta

from app.ingestion.normalizer import normalize_api_event
from app.detection.api_map import map_endpoint
from app.detection.rules.api_admin_abuse import AdminAbuseRule
from app.detection.rules.graphql_abuse import GraphQLAbuseRule
from app.detection.rules.api_abuse import ApiAbuseRule
from app.detection.rules.token_anomaly import TokenAnomalyRule
from app.correlation.engine import CorrelationEngine


def api_event(path, method="GET", status=200, ip="1.2.3.4", user=None,
              token=None, tenant=None, role=None, graphql=None, ts=None):
    return normalize_api_event({
        "type": "api", "method": method, "path": path, "status": status,
        "source_ip": ip, "user": user, "token": token, "tenant": tenant,
        "role": role, "graphql": graphql,
        "timestamp": (ts or datetime.now(timezone.utc)).isoformat(),
    })


# --- API mapping ---------------------------------------------------------

def test_endpoint_mapping():
    assert map_endpoint("/api/admin/users")["service"] == "Admin Control Plane"
    assert map_endpoint("/api/admin/users")["risk"] == "high"
    assert map_endpoint("/api/login")["service"] == "Authentication Service"
    assert map_endpoint("/api/graphql")["risk"] == "variable"
    assert map_endpoint("/api/user/data")["service"] == "Identity Service"


# --- Admin abuse ---------------------------------------------------------

def test_admin_broken_access_control():
    rule = AdminAbuseRule()
    # A 'user' role succeeding on an admin route = privilege escalation.
    alert = rule.evaluate(api_event("/api/admin/settings", "POST", 200, role="user"))
    assert alert is not None
    assert alert["severity"] == "critical"
    assert "broken access control" in alert["description"].lower()


def test_admin_repeated_denials():
    rule = AdminAbuseRule(fail_threshold=3)
    alert = None
    for _ in range(3):
        alert = rule.evaluate(api_event("/api/admin/users", "GET", 403, ip="9.9.9.9"))
    assert alert is not None
    assert alert["severity"] == "critical"
    assert alert["metadata"]["kind"] == "unauthorized_admin_access"


def test_admin_rule_ignores_normal_endpoints():
    rule = AdminAbuseRule()
    assert rule.evaluate(api_event("/api/user/data", "GET", 200, role="user")) is None


# --- GraphQL abuse -------------------------------------------------------

def test_graphql_introspection_detected():
    rule = GraphQLAbuseRule()
    alert = rule.evaluate(api_event(
        "/api/graphql", "POST", 200,
        graphql="query { __schema { types { name } } }"))
    assert alert is not None
    assert "Schema introspection" in alert["metadata"]["findings"]


def test_graphql_deep_query_detected():
    rule = GraphQLAbuseRule(max_depth=3)
    deep = "{ a { b { c { d { e } } } } }"
    alert = rule.evaluate(api_event("/api/graphql", "POST", 200, graphql=deep))
    assert alert is not None
    assert any("Deep query" in f for f in alert["metadata"]["findings"])


def test_graphql_benign_query_ok():
    rule = GraphQLAbuseRule()
    assert rule.evaluate(api_event("/api/graphql", "POST", 200,
                                   graphql="{ me { name } }")) is None


# --- API abuse (rate + enumeration) --------------------------------------

def test_api_rate_abuse():
    rule = ApiAbuseRule(rate_threshold=10, window_seconds=30)
    now = datetime.now(timezone.utc)
    alert = None
    for i in range(15):
        alert = rule.evaluate(api_event("/api/user/data", ip="5.5.5.5",
                                        ts=now + timedelta(seconds=i * 0.1))) or alert
    assert alert is not None
    assert alert["metadata"]["kind"] == "rate_abuse"


def test_api_enumeration():
    rule = ApiAbuseRule(rate_threshold=100, enum_threshold=8, window_seconds=30)
    now = datetime.now(timezone.utc)
    alert = None
    for i in range(9):
        alert = rule.evaluate(api_event(f"/api/thing{i}", status=404, ip="6.6.6.6",
                                        ts=now + timedelta(seconds=i * 0.1))) or alert
    assert alert is not None
    assert alert["metadata"]["kind"] == "enumeration"
    assert alert["severity"] == "medium"


# --- Token anomaly -------------------------------------------------------

def test_token_reuse_from_new_ip():
    rule = TokenAnomalyRule()
    rule.evaluate(api_event("/api/user/data", token="tok_abc123", ip="1.1.1.1"))
    alert = rule.evaluate(api_event("/api/user/data", token="tok_abc123", ip="2.2.2.2"))
    assert alert is not None
    assert alert["metadata"]["kind"] == "token_reuse"


def test_multi_tenant_access_is_critical():
    rule = TokenAnomalyRule()
    rule.evaluate(api_event("/api/user/data", token="tok_x", tenant="acme"))
    alert = rule.evaluate(api_event("/api/user/data", token="tok_x", tenant="globex"))
    assert alert is not None
    assert alert["severity"] == "critical"
    assert alert["metadata"]["kind"] == "multi_tenant_access"


# --- Correlation engine --------------------------------------------------

def test_correlation_builds_incident():
    corr = CorrelationEngine(min_distinct_rules=2)
    a1 = {"rule_name": "api_abuse", "severity": "high", "source_ip": "7.7.7.7",
          "created_at": datetime.now(timezone.utc).isoformat()}
    assert corr.correlate(a1) is None  # one signal isn't an incident

    a2 = {"rule_name": "admin_endpoint_abuse", "severity": "critical",
          "source_ip": "7.7.7.7", "created_at": datetime.now(timezone.utc).isoformat()}
    incident = corr.correlate(a2)
    assert incident is not None
    assert incident["actor"] == "7.7.7.7"
    assert incident["severity"] == "critical"
    assert "Reconnaissance" in incident["stages"]
    assert "Privilege Escalation" in incident["stages"]
    assert "→" in incident["kill_chain"]


def test_correlation_escalates_on_three_stages():
    corr = CorrelationEngine(min_distinct_rules=2)
    ip = "8.8.8.8"
    now = datetime.now(timezone.utc)
    for rule, sev in [("api_abuse", "medium"), ("web_attack", "high"),
                      ("brute_force_ssh", "high")]:
        inc = corr.correlate({"rule_name": rule, "severity": sev, "source_ip": ip,
                              "created_at": now.isoformat()})
    # 3 distinct stages → severity bumped above the max member severity.
    assert inc["severity"] == "critical"
    assert len(inc["stages"]) == 3
