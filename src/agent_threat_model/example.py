"""The bundled vulnerable example spec, used by the CLI example command."""

from __future__ import annotations

EXAMPLE_SPEC: dict = {
    "name": "support-agent (bundled example)",
    "description": "A customer support agent with email and web input, a shared "
    "knowledge base, and tools that can refund payments.",
    "inputs": [
        {"source": "user", "trusted": False},
        {"source": "email", "trusted": False},
        {"source": "web", "trusted": False},
        {"source": "tool_output", "trusted": True},
    ],
    "tools": [
        {
            "name": "ticket_db",
            "capabilities": ["read", "write", "database"],
            "requires_approval": False,
            "sandboxed": False,
            "authenticated": False,
        },
        {
            "name": "refund_tool",
            "capabilities": ["payment", "network"],
            "requires_approval": False,
            "sandboxed": False,
            "authenticated": True,
        },
        {
            "name": "send_email",
            "capabilities": ["send_message", "network"],
            "requires_approval": False,
            "sandboxed": False,
            "authenticated": True,
        },
    ],
    "data": [
        {"name": "customer_records", "sensitivity": "pii", "encrypted": False},
        {"name": "billing_data", "sensitivity": "confidential", "encrypted": False},
    ],
    "memory": {
        "type": "persistent",
        "shared_across_users": True,
        "writes_from_untrusted_input": True,
    },
    "outputs": ["user", "email", "api_call"],
    "credentials": {"scope": "long_lived_broad", "stored_in": "prompt"},
    "mcp_servers": [
        {
            "name": "crm-mcp",
            "audited": False,
            "authenticated": False,
            "network_exposed": True,
        }
    ],
    "agents": {"count": 3, "per_agent_identity": False, "subagents_inherit_credentials": True},
    "controls": {
        "input_guard": False,
        "output_validation": False,
        "audit_logging": False,
        "audit_log_redaction": False,
        "policy_enforcement": False,
        "human_approval_for_writes": False,
        "rate_limits": False,
        "kill_switch": False,
        "inventory_tracked": False,
    },
}
