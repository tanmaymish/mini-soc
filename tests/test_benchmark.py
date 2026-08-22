"""
Tests for the detection benchmark itself.

A benchmark that silently measures nothing is worse than no benchmark, so these
check that the harness actually scores — that it counts a hit as a hit, a miss
as a miss, and noise as noise — before anyone trusts the numbers it prints.
"""

import pytest

from benchmark import corpus, harness


# ── The corpus ────────────────────────────────────────────────────────────

def test_corpus_has_both_halves():
    scenarios = corpus.load()
    benign = [s for s in scenarios if s.kind == "benign"]
    attacks = [s for s in scenarios if s.kind == "attack"]
    assert benign, "a corpus with no benign traffic cannot measure false positives"
    assert attacks, "a corpus with no attacks cannot measure recall"


def test_benign_scenarios_expect_nothing():
    for scenario in corpus.load():
        if scenario.kind == "benign":
            assert scenario.expect == set(), (
                f"{scenario.name} is labelled benign but expects an alert"
            )


def test_attack_scenarios_declare_what_should_catch_them():
    for scenario in corpus.load():
        if scenario.kind == "attack":
            assert scenario.expect, f"{scenario.name} is an attack with no expected rule"


def test_scenario_names_are_unique():
    names = [s.name for s in corpus.load()]
    assert len(names) == len(set(names))


def test_expected_rules_exist_in_the_engine():
    """A typo in an expected rule name would silently score as a permanent miss."""
    from app.detection.engine import DetectionEngine

    known = {r["name"] for r in DetectionEngine().get_rules()}
    for scenario in corpus.load():
        unknown = scenario.expect - known
        assert not unknown, f"{scenario.name} expects unknown rule(s): {unknown}"


def test_corpus_timestamps_are_deterministic():
    """Two loads must be identical, or the benchmark's numbers drift on their own."""
    first = [e["timestamp"] for s in corpus.load() for e in s.events]
    second = [e["timestamp"] for s in corpus.load() for e in s.events]
    assert first == second


# ── The harness ───────────────────────────────────────────────────────────

def _brute_force_events():
    return [
        {
            "timestamp": corpus.at(s),
            "source_ip": "198.51.100.99",
            "action": "FAILED_LOGIN",
            "user": "root",
            "destination_port": 22,
            "metadata": {"intel": dict(corpus.CLEAN_INTEL)},
        }
        for s in range(6)
    ]


def test_harness_counts_a_hit_as_a_true_positive():
    scenario = corpus.Scenario(
        name="hit", kind="attack", expect={"brute_force_ssh"},
        events=_brute_force_events(),
    )
    result = harness.run([scenario])

    assert result.rules["brute_force_ssh"].true_positives == 1
    assert result.rules["brute_force_ssh"].false_negatives == 0
    assert result.missed_attacks == []


def test_harness_counts_a_miss_as_a_false_negative():
    scenario = corpus.Scenario(
        name="miss", kind="attack", expect={"port_scan"},
        events=_brute_force_events(),  # nothing here touches a port scan
    )
    result = harness.run([scenario])

    assert result.rules["port_scan"].false_negatives == 1
    assert [s["name"] for s in result.missed_attacks] == ["miss"]


def test_harness_counts_noise_on_benign_traffic_as_a_false_positive():
    scenario = corpus.Scenario(
        name="noisy", kind="benign", events=_brute_force_events(),
    )
    result = harness.run([scenario])

    assert result.rules["brute_force_ssh"].false_positives == 1
    assert [s["name"] for s in result.noisy_benign] == ["noisy"]
    assert result.false_positive_rate == 1.0


def test_scenarios_do_not_leak_state_into_each_other():
    """
    Every rule here is stateful. If the harness reused one engine, the first
    scenario's window would still be filled when the second ran, and the
    second would score differently depending on corpus order.
    """
    half = _brute_force_events()[:3]
    scenarios = [
        corpus.Scenario(name="half_a", kind="benign", events=half),
        corpus.Scenario(name="half_b", kind="benign", events=half),
    ]
    result = harness.run(scenarios)

    assert result.noisy_benign == [], "three failed logins twice must not add up to six"


def test_precision_and_recall_are_none_when_undefined():
    """A rule that never fired and was never expected has no score, not a zero."""
    score = harness.RuleScore(name="idle")
    assert score.precision is None
    assert score.recall is None


@pytest.mark.parametrize("tp,fp,fn,precision,recall", [
    (3, 1, 0, 0.75, 1.0),
    (2, 0, 2, 1.0, 0.5),
    (0, 4, 0, 0.0, None),
])
def test_score_arithmetic(tp, fp, fn, precision, recall):
    score = harness.RuleScore(name="r", true_positives=tp,
                              false_positives=fp, false_negatives=fn)
    assert score.precision == precision
    assert score.recall == recall


# ── The gate ──────────────────────────────────────────────────────────────

def test_the_shipped_corpus_is_clean():
    """
    The condition scripts/benchmark_detections.py --check enforces in CI, so a
    rule change that reintroduces noise fails here too rather than only on push.
    """
    result = harness.run()

    assert result.missed_attacks == [], (
        "undetected attacks: "
        + ", ".join(sorted(s["name"] for s in result.missed_attacks))
    )
    assert result.noisy_benign == [], (
        "benign traffic raised alerts: "
        + ", ".join(f"{s['name']} -> {','.join(s['unexpected'])}"
                    for s in result.noisy_benign)
    )


def test_summary_is_json_serializable():
    import json

    json.dumps(harness.run().summary())
