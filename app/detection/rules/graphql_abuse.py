"""
GraphQL Abuse Rule.

ATTACKER BEHAVIOR:
  GraphQL's flexibility is also its attack surface. Recon starts with
  *introspection* (`__schema` / `__type`) to dump the entire API shape.
  Then attackers craft deeply-nested queries to exhaust the backend
  (query-depth DoS), or fire sensitive `mutation`s to change state.

DETECTION LOGIC:
  Single-event, content-based. Inspect the GraphQL document (or the raw
  query string) for introspection markers, excessive nesting depth, and
  mutations.

REAL-WORLD EQUIVALENT:
  - GraphQL Armor / Apollo query-depth limiting
  - Escape / StackHawk GraphQL security scanning
"""

import re

from app.detection.rules.base_rule import BaseRule
from app.models.alert import create_alert
from app.detection.api_map import is_graphql

_INTROSPECTION = re.compile(r"__schema|__type|IntrospectionQuery", re.I)
_MUTATION = re.compile(r"\bmutation\b", re.I)


class GraphQLAbuseRule(BaseRule):
    def __init__(self, max_depth: int = 8):
        self._max_depth = max_depth

    @property
    def name(self) -> str:
        return "graphql_abuse"

    @property
    def description(self) -> str:
        return (
            "Detects GraphQL abuse: schema introspection (recon), excessively "
            "deep queries (query-depth DoS), and sensitive mutations."
        )

    @property
    def severity(self) -> str:
        return "high"

    @property
    def mitre(self) -> dict:
        return {
            "technique": "T1595",
            "name": "Active Scanning",
            "tactic": "Reconnaissance",
        }

    def evaluate(self, event: dict) -> dict | None:
        if event.get("action") != "API_REQUEST" or not is_graphql(event.get("path", "")):
            return None

        doc = event.get("graphql") or event.get("query") or ""
        if not doc:
            return None

        findings = []
        if _INTROSPECTION.search(doc):
            findings.append("Schema introspection")
        if _MUTATION.search(doc):
            findings.append("Mutation")

        depth = self._depth(doc)
        if depth > self._max_depth:
            findings.append(f"Deep query (depth {depth})")

        if not findings:
            return None

        return create_alert(
            rule_name=self.name, severity="high", source_ip=event.get("source_ip"),
            description=(
                f"GraphQL abuse from {event.get('source_ip')}: "
                f"{', '.join(findings)} on {event.get('path')}."
            ),
            evidence=[event],
            metadata={"service": "API Gateway (GraphQL)", "findings": findings,
                      "query_depth": depth},
        )

    @staticmethod
    def _depth(doc: str) -> int:
        """Approximate nesting depth via brace balance."""
        depth = mx = 0
        for ch in doc:
            if ch == "{":
                depth += 1
                mx = max(mx, depth)
            elif ch == "}":
                depth = max(0, depth - 1)
        return mx
