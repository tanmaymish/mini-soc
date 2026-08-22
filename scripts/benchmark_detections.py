#!/usr/bin/env python3
"""
Score the detection rules against the labelled corpus.

    python scripts/benchmark_detections.py            # human-readable report
    python scripts/benchmark_detections.py --json     # machine-readable
    python scripts/benchmark_detections.py --check    # non-zero exit on regression

--check is the CI gate: it fails when an attack in the corpus goes undetected
or when benign traffic raises an alert. Both are regressions worth blocking a
merge over, and both have happened - the first version of this benchmark found
three false positives that had been in the rules from the start.

A caveat that belongs next to the numbers rather than buried: this corpus was
written alongside the rules, so scoring well on it means "no regression against
the traffic shapes we thought of", not "correct in production". Its value is as
a ratchet. Adding a scenario that fails is a contribution, not a bug report.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmark import harness  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument("--check", action="store_true",
                        help="exit non-zero if any attack is missed or benign traffic alerts")
    parser.add_argument("--verbose", action="store_true", help="keep the engine's own logging")
    args = parser.parse_args()

    if not args.verbose:
        # The rules log every firing at WARNING; that is right in production and
        # unreadable here, where a hundred firings are the expected output.
        logging.disable(logging.CRITICAL)

    result = harness.run()

    if args.json:
        print(json.dumps(result.summary(), indent=2))
    else:
        print(harness.render(result))

    if args.check:
        problems = []
        if result.missed_attacks:
            problems.append(
                f"{len(result.missed_attacks)} attack scenario(s) undetected: "
                + ", ".join(sorted(s["name"] for s in result.missed_attacks))
            )
        if result.noisy_benign:
            problems.append(
                f"{len(result.noisy_benign)} benign scenario(s) raised alerts: "
                + ", ".join(sorted(s["name"] for s in result.noisy_benign))
            )
        if problems:
            print("", file=sys.stderr)
            for problem in problems:
                print(f"FAIL: {problem}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
