"""Scorecard: dimensions, grades, and explained checks."""

from pathlib import Path

from agent_threat_model import Architecture, score_architecture
from agent_threat_model.scorecard import DIMENSIONS, grade_for

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_hardened_scores_100():
    arch = Architecture.from_json_file(EXAMPLES / "hardened_agent.json")
    card = score_architecture(arch)
    assert card.overall == 100
    assert all(d.score == 100 for d in card.dimensions)


def test_vulnerable_scores_low():
    arch = Architecture.from_json_file(EXAMPLES / "support_agent.json")
    card = score_architecture(arch)
    assert card.overall <= 20
    assert card.dimension("identity").score == 0


def test_five_dimensions_in_order(clean_spec):
    card = score_architecture(Architecture.from_dict(clean_spec))
    assert [d.name for d in card.dimensions] == list(DIMENSIONS)


def test_overall_is_mean_of_dimensions(clean_spec):
    card = score_architecture(Architecture.from_dict(clean_spec))
    mean = round(sum(d.score for d in card.dimensions) / len(card.dimensions))
    assert card.overall == mean


def test_checks_are_explained(clean_spec):
    card = score_architecture(Architecture.from_dict(clean_spec))
    for dim in card.dimensions:
        assert dim.checks, dim.name
        for check in dim.checks:
            assert check.label
            assert isinstance(check.passed, bool)
            assert 0 <= dim.score <= 100


def test_one_missing_control_lowers_one_dimension(make_spec):
    spec = make_spec(lambda s: s["controls"].update(kill_switch=False))
    card = score_architecture(Architecture.from_dict(spec))
    kill = card.dimension("kill_switch")
    assert kill.score == 50
    assert card.dimension("audit").score == 100


def test_grade_bands():
    assert grade_for(100) == "strong"
    assert grade_for(90) == "strong"
    assert grade_for(89) == "fair"
    assert grade_for(70) == "fair"
    assert grade_for(69) == "weak"
    assert grade_for(40) == "weak"
    assert grade_for(39) == "missing"
    assert grade_for(0) == "missing"


def test_scorecard_to_dict_shape(clean_spec):
    card = score_architecture(Architecture.from_dict(clean_spec))
    data = card.to_dict()
    assert data["overall"] == card.overall
    assert len(data["dimensions"]) == 5
    assert "checks" in data["dimensions"][0]
