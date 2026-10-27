"""Report: sorting, counts, markdown, and JSON."""

import json
from pathlib import Path

from agent_threat_model import Architecture, build_threat_model

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _support():
    return build_threat_model(Architecture.from_json_file(EXAMPLES / "support_agent.json"))


def test_threats_sorted_by_severity_then_id():
    model = _support()
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    keys = [(ranks[t.severity], t.id) for t in model.threats]
    assert keys == sorted(keys)
    assert model.threats[0].severity == "critical"


def test_counts_by_severity():
    model = _support()
    counts = model.counts_by_severity()
    assert counts == {"critical": 1, "high": 11, "medium": 6, "low": 1}
    assert sum(counts.values()) == len(model.threats) == 19


def test_counts_by_stride():
    model = _support()
    counts = model.counts_by_stride()
    assert counts["Tampering"] >= 1
    assert sum(counts.values()) == len(model.threats)


def test_summary_line_mentions_counts_and_score():
    model = _support()
    line = model.summary_line()
    assert "19 threats" in line
    assert "overall score 6/100" in line


def test_markdown_contains_ids_scorecard_and_mitigations():
    md = _support().to_markdown()
    assert "# Threat model: support-agent" in md
    assert "ATM-012" in md
    assert "## Scorecard" in md
    assert "Mitigations:" in md
    assert "llm-sentinel" in md


def test_json_round_trip():
    model = _support()
    data = json.loads(model.to_json())
    assert data["architecture"] == "support-agent"
    assert len(data["threats"]) == 19
    assert data["scorecard"]["overall"] == 6
    first = data["threats"][0]
    assert first["id"] == "ATM-012"
    assert first["evidence"]
    assert first["companions"]


def test_hardened_report_has_no_threats():
    model = build_threat_model(Architecture.from_json_file(EXAMPLES / "hardened_agent.json"))
    assert model.threats == []
    assert "No threats found" in model.to_markdown()
    assert model.counts_by_severity() == {"critical": 0, "high": 0, "medium": 0, "low": 0}


def test_text_format():
    text = _support().to_text()
    assert "Threat model: support-agent" in text
    assert "ATM-001" in text
