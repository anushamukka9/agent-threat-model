"""Spec parsing, defaults, and validation."""

import json

import pytest

from agent_threat_model.models import Architecture, SpecError


def test_minimal_spec_defaults():
    arch = Architecture.from_dict({"name": "tiny"})
    assert arch.name == "tiny"
    assert arch.description == ""
    assert arch.inputs == []
    assert arch.tools == []
    assert arch.data == []
    assert arch.memory.type == "none"
    assert arch.outputs == []
    assert arch.credentials.scope == "none"
    assert arch.credentials.stored_in == "none"
    assert arch.agents.count == 1
    assert arch.controls.input_guard is False
    assert arch.controls.kill_switch is False


def test_full_spec_parses(clean_spec):
    arch = Architecture.from_dict(clean_spec)
    assert arch.name == "clean-agent"
    assert arch.inputs[0].source == "user"
    assert arch.tools[1].has("write", "database")
    assert arch.data[0].sensitivity == "internal"
    assert arch.memory.type == "session"
    assert arch.mcp_servers[0].audited is True
    assert arch.agents.count == 2


def test_input_trusted_defaults_false():
    arch = Architecture.from_dict({"name": "x", "inputs": [{"source": "web"}]})
    assert arch.inputs[0].trusted is False


def test_memory_null_and_credentials_null_default():
    arch = Architecture.from_dict({"name": "x", "memory": None, "credentials": None})
    assert arch.memory.type == "none"
    assert arch.credentials.scope == "none"


def test_from_json_round_trip(clean_spec):
    arch = Architecture.from_json(json.dumps(clean_spec))
    assert arch.name == "clean-agent"


def test_from_json_file(tmp_path, clean_spec):
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(clean_spec), encoding="utf-8")
    arch = Architecture.from_json_file(path)
    assert arch.name == "clean-agent"


def test_from_json_file_missing(tmp_path):
    with pytest.raises(SpecError):
        Architecture.from_json_file(tmp_path / "nope.json")


def test_from_json_invalid():
    with pytest.raises(SpecError):
        Architecture.from_json("{not json")


@pytest.mark.parametrize(
    "spec",
    [
        {},
        {"name": ""},
        {"name": 12},
        {"name": "x", "inputs": [{"source": "carrier_pigeon"}]},
        {"name": "x", "inputs": [{"source": "web", "trusted": "yes"}]},
        {"name": "x", "tools": [{"name": "t", "capabilities": ["fly"]}]},
        {"name": "x", "tools": [{"capabilities": ["read"]}]},
        {"name": "x", "data": [{"name": "d", "sensitivity": "secret"}]},
        {"name": "x", "memory": {"type": "forever"}},
        {"name": "x", "outputs": ["telepathy"]},
        {"name": "x", "credentials": {"scope": "everything"}},
        {"name": "x", "credentials": {"stored_in": "sticky_note"}},
        {"name": "x", "mcp_servers": [{"name": "m", "audited": "yes"}]},
        {"name": "x", "agents": {"count": 0}},
        {"name": "x", "agents": {"count": "many"}},
        {"name": "x", "controls": {"input_guard": 1}},
        {"name": "x", "inputs": "web"},
        ["not", "a", "dict"],
    ],
)
def test_bad_specs_raise_spec_error(spec):
    with pytest.raises(SpecError):
        Architecture.from_dict(spec)


def test_spec_error_is_value_error():
    with pytest.raises(ValueError):
        Architecture.from_dict({})
