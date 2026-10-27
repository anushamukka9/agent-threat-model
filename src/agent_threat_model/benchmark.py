"""CI smoke benchmark: run the labeled benchmark cases.

Run with: python -m agent_threat_model.benchmark

Loads benchmarks/cases.json, runs the engine on each labeled
architecture, and checks precision and recall against the expected
threat ids. Both must be 1.00. Exits nonzero on any mismatch.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_threat_model.models import Architecture
from agent_threat_model.report import build_threat_model


def find_cases_file() -> Path | None:
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / "benchmarks" / "cases.json",
        Path.cwd() / "benchmarks" / "cases.json",
        here.parent.parent.parent / "benchmarks" / "cases.json",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def load_cases(path: Path | None = None) -> list[dict]:
    path = path or find_cases_file()
    if path is None:
        raise FileNotFoundError("benchmarks/cases.json not found")
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def run_cases(cases: list[dict]) -> tuple[float, float, list[str]]:
    """Return (precision, recall, problem lines)."""
    tp = fp = fn = 0
    problems: list[str] = []
    for case in cases:
        arch = Architecture.from_dict(case["spec"])
        model = build_threat_model(arch)
        got = {t.id for t in model.threats}
        expected = set(case["expected_threat_ids"])
        case_tp = len(got & expected)
        case_fp = len(got - expected)
        case_fn = len(expected - got)
        tp += case_tp
        fp += case_fp
        fn += case_fn
        print(
            f"{case['name']}: expected {len(expected)}, got {len(got)}, "
            f"matched {case_tp}, extra {case_fp}, missing {case_fn}"
        )
        if got != expected:
            problems.append(
                f"{case['name']}: extra {sorted(got - expected)}, missing {sorted(expected - got)}"
            )
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return precision, recall, problems


def bench_cases(iterations: int = 20) -> float:
    """Return benchmark case runs per second, for the packaging smoke test."""
    import time

    cases = load_cases()
    start = time.perf_counter()
    for _ in range(iterations):
        for case in cases:
            build_threat_model(Architecture.from_dict(case["spec"]))
    elapsed = time.perf_counter() - start
    total = iterations * len(cases)
    return total / elapsed if elapsed else 0.0


def main() -> int:
    cases = load_cases()
    precision, recall, problems = run_cases(cases)
    print(f"cases: {len(cases)}")
    print(f"precision: {precision:.2f}")
    print(f"recall: {recall:.2f}")
    for problem in problems:
        print(f"MISMATCH: {problem}", file=sys.stderr)
    if problems or precision != 1.0 or recall != 1.0:
        print("benchmark FAILED", file=sys.stderr)
        return 1
    print("benchmark passed: precision and recall 1.00")
    return 0


if __name__ == "__main__":
    sys.exit(main())
