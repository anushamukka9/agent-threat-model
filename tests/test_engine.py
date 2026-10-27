"""Every rule fires on its triggering spec and stays off the clean one."""

import pytest

from agent_threat_model import Architecture, analyze
from agent_threat_model.engine import RULES


def _ids(spec: dict) -> set[str]:
    return {t.id for t in analyze(Architecture.from_dict(spec))}


def _tool(**kw):
    tool = {
        "name": "extra",
        "capabilities": ["read"],
        "requires_approval": True,
        "sandboxed": True,
        "authenticated": True,
    }
    tool.update(kw)
    return tool


# Each mutator turns the clean spec into one that triggers the rule.
TRIGGERS = {
    "ATM-001": lambda s: s["controls"].update(input_guard=False),
    "ATM-002": lambda s: s["inputs"].append({"source": "tool_output", "trusted": True}),
    "ATM-003": lambda s: s["tools"].append(
        _tool(name="shell", capabilities=["code_exec"], sandboxed=False)
    ),
    "ATM-004": lambda s: (
        s["tools"].append(_tool(name="payer", capabilities=["payment"], requires_approval=False)),
        s["controls"].update(human_approval_for_writes=False),
    ),
    "ATM-005": lambda s: s["credentials"].update(scope="long_lived_broad"),
    "ATM-006": lambda s: s["credentials"].update(stored_in="prompt"),
    "ATM-007": lambda s: (
        s["data"].append({"name": "cust", "sensitivity": "pii", "encrypted": True}),
        s["outputs"].append("email"),
        s["controls"].update(output_validation=False),
    ),
    "ATM-008": lambda s: (
        s["data"].append({"name": "cust", "sensitivity": "pii", "encrypted": True}),
        s["controls"].update(output_validation=False),
    ),
    "ATM-009": lambda s: s["memory"].update(type="persistent", writes_from_untrusted_input=True),
    "ATM-010": lambda s: s["memory"].update(type="persistent", shared_across_users=True),
    "ATM-011": lambda s: s["mcp_servers"].append(
        {"name": "new-mcp", "audited": False, "authenticated": True, "network_exposed": False}
    ),
    "ATM-012": lambda s: s["mcp_servers"].append(
        {"name": "open-mcp", "audited": True, "authenticated": False, "network_exposed": True}
    ),
    "ATM-013": lambda s: s["controls"].update(audit_logging=False),
    "ATM-014": lambda s: (
        s["data"].append({"name": "cust", "sensitivity": "confidential", "encrypted": True}),
        s["controls"].update(audit_log_redaction=False),
    ),
    "ATM-015": lambda s: s["controls"].update(kill_switch=False),
    "ATM-016": lambda s: (
        s["tools"].append(_tool(name="net", capabilities=["network"])),
        s["controls"].update(rate_limits=False),
    ),
    "ATM-017": lambda s: s["agents"].update(count=3, per_agent_identity=False),
    "ATM-018": lambda s: s["agents"].update(subagents_inherit_credentials=True),
    "ATM-019": lambda s: s["controls"].update(policy_enforcement=False),
    "ATM-020": lambda s: s["controls"].update(inventory_tracked=False),
    "ATM-021": lambda s: (
        s["inputs"].append({"source": "documents", "trusted": False}),
        s["data"].append({"name": "files", "sensitivity": "confidential", "encrypted": True}),
        s["controls"].update(output_validation=False),
    ),
    "ATM-022": lambda s: s["tools"].append(
        _tool(name="db", capabilities=["write", "database"], authenticated=False)
    ),
    "ATM-023": lambda s: (
        s["tools"].append(_tool(name="shell", capabilities=["code_exec"], sandboxed=False)),
        s["credentials"].update(scope="long_lived_broad"),
    ),
}


def test_catalog_has_at_least_20_rules():
    assert len(RULES) >= 20
    assert {r.id for r in RULES} == set(TRIGGERS)


def test_clean_spec_has_no_threats(clean_spec):
    assert _ids(clean_spec) == set()


@pytest.mark.parametrize("rule_id", sorted(TRIGGERS))
def test_rule_fires_on_triggering_spec(rule_id, make_spec):
    assert rule_id in _ids(make_spec(TRIGGERS[rule_id]))


@pytest.mark.parametrize("rule_id", sorted(TRIGGERS))
def test_rule_silent_on_clean_spec(rule_id, clean_spec):
    assert rule_id not in _ids(clean_spec)


def test_threat_carries_evidence_and_mitigations(clean_spec):
    threats = analyze(
        Architecture.from_dict(
            {**clean_spec, "controls": {**clean_spec["controls"], "kill_switch": False}}
        )
    )
    threat = next(t for t in threats if t.id == "ATM-015")
    assert "kill_switch=false" in threat.evidence
    assert threat.mitigations
    assert threat.stride == "Denial of Service"
    assert threat.severity == "medium"


def test_critical_combo_rule_is_critical(make_spec):
    threats = analyze(Architecture.from_dict(make_spec(TRIGGERS["ATM-023"])))
    threat = next(t for t in threats if t.id == "ATM-023")
    assert threat.severity == "critical"
    assert "long_lived_broad" in threat.evidence


def test_deterministic(make_spec):
    spec = make_spec(TRIGGERS["ATM-001"])
    first = [t.id for t in analyze(Architecture.from_dict(spec))]
    second = [t.id for t in analyze(Architecture.from_dict(spec))]
    assert first == second
