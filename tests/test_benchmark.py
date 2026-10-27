"""Benchmark cases: labeled architectures at precision/recall 1.00."""

from agent_threat_model.benchmark import bench_cases, load_cases, run_cases


def test_cases_load_at_least_8():
    cases = load_cases()
    assert len(cases) >= 8


def test_cases_precision_recall_perfect():
    precision, recall, problems = run_cases(load_cases())
    assert problems == []
    assert precision == 1.0
    assert recall == 1.0


def test_hardened_case_expects_zero_threats():
    cases = {c["name"]: c for c in load_cases()}
    assert cases["hardened-enterprise-agent"]["expected_threat_ids"] == []


def test_case_names_are_realistic():
    names = {c["name"] for c in load_cases()}
    assert "vulnerable-support-bot" in names
    assert "coding-agent-unsandboxed" in names
    assert "research-agent-web-rag" in names


def test_bench_cases_rate_positive():
    assert bench_cases(iterations=2) > 0
