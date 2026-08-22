"""
Replays the labelled corpus through the real DetectionEngine and scores it.

Scoring is per scenario, not per event. A brute-force burst is one attack, and
a rule that fires once on it has caught one attack — counting the six failed
logins separately would flatter the numbers.

Each scenario gets a fresh engine. Every rule in here is stateful, so sharing
one engine would let a previous scenario's window leak into the next and make
results depend on corpus ordering.
"""

from dataclasses import dataclass, field

from app.detection.engine import DetectionEngine
from benchmark import corpus


@dataclass
class RuleScore:
    """Confusion-matrix counts for one rule, in scenarios."""

    name: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    fired_on: list = field(default_factory=list)      # scenarios it fired on wrongly
    missed: list = field(default_factory=list)        # scenarios it should have caught

    @property
    def precision(self) -> float | None:
        fired = self.true_positives + self.false_positives
        return self.true_positives / fired if fired else None

    @property
    def recall(self) -> float | None:
        expected = self.true_positives + self.false_negatives
        return self.true_positives / expected if expected else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return 0.0 if (p is not None and r is not None) else None
        return 2 * p * r / (p + r)


@dataclass
class Result:
    """Everything one benchmark run produced."""

    rules: dict                      # rule name -> RuleScore
    scenarios: list                  # per-scenario outcomes
    ml_rule_active: bool

    @property
    def benign_scenarios(self) -> list:
        return [s for s in self.scenarios if s["kind"] == "benign"]

    @property
    def noisy_benign(self) -> list:
        """Benign scenarios that produced at least one alert."""
        return [s for s in self.benign_scenarios if s["fired"]]

    @property
    def false_positive_rate(self) -> float:
        benign = self.benign_scenarios
        return len(self.noisy_benign) / len(benign) if benign else 0.0

    @property
    def missed_attacks(self) -> list:
        return [s for s in self.scenarios if s["kind"] == "attack" and s["missing"]]

    def summary(self) -> dict:
        """A small, stable dict suitable for a baseline file or CI artifact."""
        return {
            "benign_scenarios": len(self.benign_scenarios),
            "attack_scenarios": len(self.scenarios) - len(self.benign_scenarios),
            "noisy_benign_scenarios": sorted(s["name"] for s in self.noisy_benign),
            "missed_attacks": sorted(s["name"] for s in self.missed_attacks),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "ml_rule_active": self.ml_rule_active,
            "rules": {
                name: {
                    "true_positives": s.true_positives,
                    "false_positives": s.false_positives,
                    "false_negatives": s.false_negatives,
                    "precision": None if s.precision is None else round(s.precision, 4),
                    "recall": None if s.recall is None else round(s.recall, 4),
                }
                for name, s in sorted(self.rules.items())
            },
        }


def run(scenarios: list | None = None) -> Result:
    """Replay the corpus and score it."""
    scenarios = scenarios if scenarios is not None else corpus.load()

    probe = DetectionEngine()
    rule_names = [r["name"] for r in probe.get_rules()]
    ml_rule_active = any(
        getattr(r, "model", "absent") not in (None,)
        for r in probe._rules
        if r.name == "ml_behavioral_anomaly"
    )

    scores = {name: RuleScore(name=name) for name in rule_names}
    outcomes = []

    for scenario in scenarios:
        engine = DetectionEngine()
        fired = set()
        for event in scenario.events:
            for alert in engine.evaluate(event):
                fired.add(alert["rule_name"])

        expected = set(scenario.expect)
        unexpected = fired - expected
        missing = expected - fired

        for name in expected & fired:
            scores[name].true_positives += 1
        for name in missing:
            scores[name].false_negatives += 1
            scores[name].missed.append(scenario.name)
        for name in unexpected:
            scores[name].false_positives += 1
            scores[name].fired_on.append(scenario.name)

        outcomes.append({
            "name": scenario.name,
            "kind": scenario.kind,
            "note": scenario.note,
            "events": len(scenario.events),
            "expected": sorted(expected),
            "fired": sorted(fired),
            "unexpected": sorted(unexpected),
            "missing": sorted(missing),
        })

    return Result(rules=scores, scenarios=outcomes, ml_rule_active=ml_rule_active)


def _pct(value) -> str:
    return "     —" if value is None else f"{value * 100:5.1f}%"


def render(result: Result) -> str:
    """A human-readable report."""
    lines = []
    lines.append("Detection efficacy")
    lines.append("=" * 74)
    lines.append(
        f"{len(result.benign_scenarios)} benign scenarios, "
        f"{len(result.scenarios) - len(result.benign_scenarios)} attack scenarios"
    )
    if not result.ml_rule_active:
        lines.append(
            "ml_behavioral_anomaly has no trained model loaded and is inert in this "
            "run — train it with scripts/train_model.py to include it."
        )
    lines.append("")
    lines.append(f"{'rule':<26}{'TP':>4}{'FP':>4}{'FN':>4}  {'precision':>10} {'recall':>8}")
    lines.append("-" * 74)
    for name, score in sorted(result.rules.items()):
        if not (score.true_positives or score.false_positives or score.false_negatives):
            continue
        lines.append(
            f"{name:<26}{score.true_positives:>4}{score.false_positives:>4}"
            f"{score.false_negatives:>4}  {_pct(score.precision):>10} {_pct(score.recall):>8}"
        )
    lines.append("-" * 74)
    lines.append(
        f"Benign scenarios that alerted: {len(result.noisy_benign)}"
        f"/{len(result.benign_scenarios)}  ({result.false_positive_rate * 100:.1f}%)"
    )

    if result.noisy_benign:
        lines.append("")
        lines.append("False positives on benign traffic")
        lines.append("-" * 74)
        for s in result.noisy_benign:
            lines.append(f"  {s['name']}  →  {', '.join(s['unexpected'])}")
            if s["note"]:
                lines.append(f"      {s['note']}")

    if result.missed_attacks:
        lines.append("")
        lines.append("Attacks not detected")
        lines.append("-" * 74)
        for s in result.missed_attacks:
            lines.append(f"  {s['name']}  →  missed by {', '.join(s['missing'])}")

    return "\n".join(lines)
