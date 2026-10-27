"""Packaging tests. No tomllib: version is read with a regex fallback
so this file runs unchanged on Python 3.10."""

import re
from pathlib import Path

import agent_threat_model

ROOT = Path(__file__).resolve().parent.parent


def _pyproject_text() -> str:
    return (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_version_matches_pyproject():
    text = _pyproject_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match is not None, "no version line found in pyproject.toml"
    assert agent_threat_model.__version__ == match.group(1)


def test_console_script_declared():
    text = _pyproject_text()
    assert 'agent-threat-model = "agent_threat_model.cli:main"' in text


def test_requires_python_310():
    text = _pyproject_text()
    assert 'requires-python = ">=3.10"' in text


def test_no_runtime_dependencies():
    text = _pyproject_text()
    assert not re.search(r"^dependencies\s*=", text, re.MULTILINE)


def test_public_exports_importable():
    for name in agent_threat_model.__all__:
        assert getattr(agent_threat_model, name, None) is not None, name


def test_benchmark_smoke():
    from agent_threat_model.benchmark import bench_cases

    assert bench_cases(iterations=2) > 0
