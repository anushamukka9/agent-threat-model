"""Extended benchmarks for agent-threat-model. Prints measured numbers.

Run: python benchmarks/bench.py [--quick]
Record the output in benchmarks/results.md.

Loads the labeled benchmark cases, checks precision and recall
against the expected threat ids, then times repeated analyses of a
representative spec (the bundled vulnerable support agent).
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_threat_model.benchmark import load_cases, run_cases  # noqa: E402
from agent_threat_model.models import Architecture  # noqa: E402
from agent_threat_model.report import build_threat_model  # noqa: E402


def _time(fn, iterations: int, rounds: int = 5) -> float:
    samples = []
    for _ in range(rounds):
        start = time.perf_counter()
        for _ in range(iterations):
            fn()
        samples.append(iterations / (time.perf_counter() - start))
    return statistics.median(samples)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()

    cases = load_cases()
    precision, recall, problems = run_cases(cases)
    assert not problems, f"benchmark cases drifted: {problems}"
    print(f"cases: {len(cases)}, precision: {precision:.2f}, recall: {recall:.2f}")

    support = next(c for c in cases if c["name"] == "vulnerable-support-bot")
    arch = Architecture.from_dict(support["spec"])
    model = build_threat_model(arch)
    print(f"representative spec: {support['name']}, {len(model.threats)} threats")

    iterations = 200 if args.quick else 2000
    rate = _time(lambda: build_threat_model(arch), iterations)
    print(f"analyze representative spec: {rate:>12,.1f} analyses/sec")
    print(f"  average analysis time:     {1000.0 / rate:>12,.3f} ms")
    print("done")


if __name__ == "__main__":
    main()
