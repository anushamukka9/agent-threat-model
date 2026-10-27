"""Shared helpers: small spec builders for the tests."""

from __future__ import annotations

import copy

import pytest

CLEAN_SPEC: dict = {
    "name": "clean-agent",
    "description": "A hardened agent used as the mitigated baseline.",
    "inputs": [{"source": "user", "trusted": False}],
    "tools": [
        {
            "name": "lookup",
            "capabilities": ["read"],
            "requires_approval": True,
            "sandboxed": True,
            "authenticated": True,
        },
        {
            "name": "writer",
            "capabilities": ["write", "database"],
            "requires_approval": True,
            "sandboxed": True,
            "authenticated": True,
        },
    ],
    "data": [{"name": "product_docs", "sensitivity": "internal", "encrypted": True}],
    "memory": {
        "type": "session",
        "shared_across_users": False,
        "writes_from_untrusted_input": False,
    },
    "outputs": ["user"],
    "credentials": {"scope": "scoped_short_lived", "stored_in": "vault"},
    "mcp_servers": [
        {"name": "docs-mcp", "audited": True, "authenticated": True, "network_exposed": False}
    ],
    "agents": {"count": 2, "per_agent_identity": True, "subagents_inherit_credentials": False},
    "controls": {
        "input_guard": True,
        "output_validation": True,
        "audit_logging": True,
        "audit_log_redaction": True,
        "policy_enforcement": True,
        "human_approval_for_writes": True,
        "rate_limits": True,
        "kill_switch": True,
        "inventory_tracked": True,
    },
}


@pytest.fixture
def clean_spec() -> dict:
    return copy.deepcopy(CLEAN_SPEC)


@pytest.fixture
def make_spec(clean_spec):
    """Return a function that deep-copies the clean spec and mutates it."""

    def _make(mutator=None) -> dict:
        spec = copy.deepcopy(clean_spec)
        if mutator is not None:
            mutator(spec)
        return spec

    return _make
