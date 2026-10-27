"""CLI: exit codes and the four subcommands."""

import json
from pathlib import Path

from agent_threat_model.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
SUPPORT = str(EXAMPLES / "support_agent.json")
HARDENED = str(EXAMPLES / "hardened_agent.json")


def _write(tmp_path, spec: dict, name: str = "spec.json") -> str:
    path = tmp_path / name
    path.write_text(json.dumps(spec), encoding="utf-8")
    return str(path)


def test_analyze_vulnerable_exits_1(capsys):
    assert main(["analyze", SUPPORT]) == 1
    assert "ATM-012" in capsys.readouterr().out


def test_analyze_hardened_exits_0(capsys):
    assert main(["analyze", HARDENED]) == 0
    assert "No threats found" in capsys.readouterr().out


def test_analyze_json_format(capsys):
    assert main(["analyze", SUPPORT, "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["architecture"] == "support-agent"


def test_analyze_text_format(capsys):
    assert main(["analyze", SUPPORT, "--format", "text"]) == 1
    assert "Scorecard:" in capsys.readouterr().out


def test_analyze_fail_on_levels(tmp_path, clean_spec, capsys):
    spec = dict(clean_spec)
    spec["controls"] = {**clean_spec["controls"], "kill_switch": False, "inventory_tracked": False}
    path = _write(tmp_path, spec)
    # Only medium (ATM-015) and low (ATM-020) threats in this spec.
    assert main(["analyze", path, "--fail-on", "high"]) == 0
    capsys.readouterr()
    assert main(["analyze", path, "--fail-on", "medium"]) == 1
    capsys.readouterr()
    assert main(["analyze", path, "--fail-on", "low"]) == 1


def test_analyze_bad_spec_exits_2(tmp_path, capsys):
    path = _write(tmp_path, {"name": "x", "outputs": ["telepathy"]})
    assert main(["analyze", path]) == 2


def test_analyze_missing_file_exits_2():
    assert main(["analyze", "/nonexistent/spec.json"]) == 2


def test_catalog(capsys):
    assert main(["catalog"]) == 0
    out = capsys.readouterr().out
    assert "ATM-001" in out
    assert "ATM-023" in out
    assert "23 rules" in out


def test_example_prints_spec(capsys):
    assert main(["example"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["name"].startswith("support-agent")


def test_example_write_then_validate(tmp_path, capsys):
    target = tmp_path / "example.json"
    assert main(["example", "--write", str(target)]) == 0
    capsys.readouterr()
    assert main(["validate", str(target)]) == 0
    assert "OK:" in capsys.readouterr().out


def test_validate_support(capsys):
    assert main(["validate", SUPPORT]) == 0
    assert "OK: support-agent" in capsys.readouterr().out


def test_validate_bad_spec_exits_2(tmp_path):
    path = _write(tmp_path, {"inputs": []})
    assert main(["validate", path]) == 2
