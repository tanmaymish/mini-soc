"""
API Mapping Layer.

Maps every incoming API request to a *security domain* (service) and a
base risk level. This is how a real SOC turns raw API telemetry into
security-relevant signals: the same 200 OK means very different things on
`/api/health` vs. `/api/admin/users`.

Downstream, detection rules and the correlation engine use `service` and
`risk` to decide how hard to look and how loudly to alert.
"""

import re

# Ordered most-specific → least-specific; first match wins.
# Each entry: (compiled path regex, service name, base risk).
_ROUTES = [
    (re.compile(r"^/api/admin(/|$)", re.I),            "Admin Control Plane", "high"),
    (re.compile(r"^/api/(login|logout|auth|token|oauth)", re.I), "Authentication Service", "medium"),
    (re.compile(r"^/api/graphql", re.I),               "API Gateway (GraphQL)", "variable"),
    (re.compile(r"^/api/(users?|identity|profile|account)", re.I), "Identity Service", "medium"),
    (re.compile(r"^/api/(payments?|billing|invoices?|checkout)", re.I), "Payment Service", "high"),
    (re.compile(r"^/api/internal(/|$)", re.I),         "Internal Service", "high"),
    (re.compile(r"^/api/", re.I),                      "General API", "low"),
]

_DEFAULT = ("Unmapped Endpoint", "low")


def map_endpoint(path: str) -> dict:
    """
    Resolve an API path to its security domain.

    Returns:
        {"service": str, "risk": "low|medium|high|variable"}
    """
    path = path or ""
    for rx, service, risk in _ROUTES:
        if rx.search(path):
            return {"service": service, "risk": risk}
    service, risk = _DEFAULT
    return {"service": service, "risk": risk}


def is_admin(path: str) -> bool:
    return map_endpoint(path)["service"] == "Admin Control Plane"


def is_graphql(path: str) -> bool:
    return map_endpoint(path)["service"] == "API Gateway (GraphQL)"
