"""The rule catalog and the engine that applies it.

Every rule is deterministic: the same spec always produces the same
threats, in the same order. Each threat carries the evidence that
triggered it, meaning the actual spec values, so a reader can check
the finding against the spec without trusting the engine.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from agent_threat_model.models import Architecture

SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}
STRIDE_CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)

UNTRUSTED_SOURCES = ("web", "documents", "tool_output", "email", "user")
WRITE_CAPS = ("write", "delete", "payment", "database")


@dataclass
class Companion:
    repo: str
    helps: str

    def to_dict(self) -> dict[str, str]:
        return {"repo": self.repo, "helps": self.helps}


@dataclass
class Threat:
    id: str
    title: str
    stride: str
    severity: str
    description: str
    evidence: str
    mitigations: list[str] = field(default_factory=list)
    companions: list[Companion] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "stride": self.stride,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "mitigations": list(self.mitigations),
            "companions": [c.to_dict() for c in self.companions],
        }


@dataclass
class Rule:
    id: str
    title: str
    stride: str
    severity: str
    description: str
    mitigations: list[str]
    companions: list[Companion]
    check: Callable[[Architecture], str | None]


def _names(items, attr: str = "name") -> str:
    return ", ".join(getattr(i, attr) for i in items)


# --- Rule checks: return an evidence string, or None when clean. ---


def _c001(a: Architecture) -> str | None:
    bad = [i for i in a.inputs if i.source in UNTRUSTED_SOURCES and not i.trusted]
    if bad and not a.controls.input_guard:
        srcs = ", ".join(sorted({i.source for i in bad}))
        return f"untrusted inputs ({srcs}) with controls.input_guard=false"
    return None


def _c002(a: Architecture) -> str | None:
    bad = [i for i in a.inputs if i.source in ("tool_output", "mcp_server") and i.trusted]
    if bad:
        srcs = ", ".join(sorted({i.source for i in bad}))
        return f"inputs from {srcs} are marked trusted=true"
    return None


def _c003(a: Architecture) -> str | None:
    bad = [t for t in a.tools_with("code_exec") if not t.sandboxed]
    if bad:
        return f"code_exec tools not sandboxed: {_names(bad)}"
    return None


def _c004(a: Architecture) -> str | None:
    if a.controls.human_approval_for_writes:
        return None
    bad = [t for t in a.tools if t.has("write", "delete", "payment") and not t.requires_approval]
    if bad:
        return (
            f"tools with write/delete/payment and requires_approval=false: {_names(bad)}; "
            "controls.human_approval_for_writes=false"
        )
    return None


def _c005(a: Architecture) -> str | None:
    if a.credentials.scope == "long_lived_broad":
        return "credentials.scope=long_lived_broad"
    return None


def _c006(a: Architecture) -> str | None:
    if a.credentials.stored_in in ("prompt", "code"):
        return f"credentials.stored_in={a.credentials.stored_in}"
    return None


def _c007(a: Architecture) -> str | None:
    data = [d for d in a.data if d.sensitivity in ("pii", "confidential")]
    ext = [o for o in a.outputs if o in ("email", "api_call")]
    if data and ext and not a.controls.output_validation:
        return (
            f"data ({_names(data)}) with outputs ({', '.join(ext)}) and "
            "controls.output_validation=false"
        )
    return None


def _c008(a: Architecture) -> str | None:
    data = a.sensitive_data(("pii", "credentials"))
    if data and "user" in a.outputs and not a.controls.output_validation:
        return (
            f"sensitive data ({_names(data)}) with outputs including user and "
            "controls.output_validation=false"
        )
    return None


def _c009(a: Architecture) -> str | None:
    if a.memory.type == "persistent" and a.memory.writes_from_untrusted_input:
        return "memory.type=persistent and memory.writes_from_untrusted_input=true"
    return None


def _c010(a: Architecture) -> str | None:
    if a.memory.type == "persistent" and a.memory.shared_across_users:
        return "memory.type=persistent and memory.shared_across_users=true"
    return None


def _c011(a: Architecture) -> str | None:
    bad = [s for s in a.mcp_servers if not s.audited]
    if bad:
        return f"MCP servers with audited=false: {_names(bad)}"
    return None


def _c012(a: Architecture) -> str | None:
    bad = [s for s in a.mcp_servers if s.network_exposed and not s.authenticated]
    if bad:
        return f"MCP servers network_exposed=true and authenticated=false: {_names(bad)}"
    return None


def _c013(a: Architecture) -> str | None:
    if not a.controls.audit_logging:
        return "controls.audit_logging=false"
    return None


def _c014(a: Architecture) -> str | None:
    data = [d for d in a.data if d.sensitivity in ("pii", "confidential", "credentials")]
    if a.controls.audit_logging and not a.controls.audit_log_redaction and data:
        return (
            f"controls.audit_logging=true, controls.audit_log_redaction=false, "
            f"sensitive data present ({_names(data)})"
        )
    return None


def _c015(a: Architecture) -> str | None:
    if not a.controls.kill_switch:
        return "controls.kill_switch=false"
    return None


def _c016(a: Architecture) -> str | None:
    reasons = []
    if a.tools_with("network"):
        reasons.append(f"network tools: {_names(a.tools_with('network'))}")
    if a.tools_with("payment"):
        reasons.append(f"payment tools: {_names(a.tools_with('payment'))}")
    if "api_call" in a.outputs:
        reasons.append("outputs include api_call")
    if reasons and not a.controls.rate_limits:
        return "controls.rate_limits=false and " + "; ".join(reasons)
    return None


def _c017(a: Architecture) -> str | None:
    if a.agents.count > 1 and not a.agents.per_agent_identity:
        return f"agents.count={a.agents.count} and agents.per_agent_identity=false"
    return None


def _c018(a: Architecture) -> str | None:
    if a.agents.subagents_inherit_credentials:
        return "agents.subagents_inherit_credentials=true"
    return None


def _c019(a: Architecture) -> str | None:
    bad = a.tools_with(*WRITE_CAPS)
    if bad and not a.controls.policy_enforcement:
        return (
            f"tools with write/delete/payment/database ({_names(bad)}) and "
            "controls.policy_enforcement=false"
        )
    return None


def _c020(a: Architecture) -> str | None:
    if not a.controls.inventory_tracked:
        return "controls.inventory_tracked=false"
    return None


def _c021(a: Architecture) -> str | None:
    has_docs = any(i.source == "documents" for i in a.inputs)
    data = [d for d in a.data if d.sensitivity in ("confidential", "pii")]
    if has_docs and data and not a.controls.output_validation:
        return (
            f"documents input with sensitive data ({_names(data)}) and "
            "controls.output_validation=false"
        )
    return None


def _c022(a: Architecture) -> str | None:
    bad = [t for t in a.tools if not t.authenticated and t.has("write", "database")]
    if bad:
        return f"tools with authenticated=false and write/database capability: {_names(bad)}"
    return None


def _c023(a: Architecture) -> str | None:
    bad = [t for t in a.tools_with("code_exec") if not t.sandboxed]
    if bad and a.credentials.scope == "long_lived_broad":
        return (
            f"code_exec tools not sandboxed ({_names(bad)}) combined with "
            "credentials.scope=long_lived_broad"
        )
    return None


def _llm() -> Companion:
    return Companion("llm-sentinel", "screens untrusted input before it reaches the model")


def _mcp() -> Companion:
    return Companion("mcp-audit", "audits MCP server surfaces, tools, and permissions")


def _rag() -> Companion:
    return Companion("rag-canary", "plants canaries in retrieval to catch exfiltration")


def _policy() -> Companion:
    return Companion("agent-policy-kit", "enforces a policy gate on tool calls")


def _audit() -> Companion:
    return Companion("agent-audit", "keeps a tamper-evident record of agent actions")


def _contracts() -> Companion:
    return Companion("output-contracts", "validates outputs against a contract before release")


def _scopes() -> Companion:
    return Companion("agent-scopes", "issues short-lived, narrowly scoped credentials")


def _bom() -> Companion:
    return Companion("ai-bom", "inventories models, tools, MCP servers, and data")


RULES: list[Rule] = [
    Rule(
        "ATM-001",
        "Prompt injection through unguarded untrusted input",
        "Tampering",
        "high",
        "Untrusted input reaches the model with no input guard in front of it. "
        "Anyone who controls that input can steer the agent.",
        ["Put an input guard in front of untrusted sources", "Treat input as data, not orders"],
        [_llm()],
        _c001,
    ),
    Rule(
        "ATM-002",
        "Tool output or MCP input trusted implicitly",
        "Tampering",
        "high",
        "Output from a tool or an MCP server is marked trusted. That output is "
        "attacker-controlled in practice, so trusting it turns indirect "
        "injection and tool poisoning into direct instructions.",
        ["Mark tool and MCP output untrusted", "Screen it like any other untrusted input"],
        [_llm(), _mcp()],
        _c002,
    ),
    Rule(
        "ATM-003",
        "Code execution without a sandbox",
        "Elevation of Privilege",
        "high",
        "A tool can run code and is not sandboxed. Injected instructions stop "
        "being text and become commands on the host.",
        ["Run code execution in a sandbox with no ambient credentials", "Drop network by default"],
        [_policy(), _scopes()],
        _c003,
    ),
    Rule(
        "ATM-004",
        "Write, delete, or payment actions without approval",
        "Tampering",
        "high",
        "A tool can write, delete, or pay, and neither the tool nor the global "
        "controls require human approval. One bad instruction changes real state.",
        ["Require approval for write, delete, and payment actions", "Split read and write tools"],
        [_policy()],
        _c004,
    ),
    Rule(
        "ATM-005",
        "Broad long-lived credentials",
        "Elevation of Privilege",
        "high",
        "The agent holds broad, long-lived credentials. Anything that steers "
        "the agent inherits that reach, for as long as the credential lives.",
        ["Move to scoped, short-lived credentials", "Narrow the scope to the task at hand"],
        [_scopes()],
        _c005,
    ),
    Rule(
        "ATM-006",
        "Credentials stored in a prompt or in code",
        "Information Disclosure",
        "high",
        "Credentials in a prompt can be read back out of the model, and "
        "credentials in code travel with every copy of the repo.",
        ["Store credentials in a vault", "Inject them at call time, never into the prompt"],
        [_scopes()],
        _c006,
    ),
    Rule(
        "ATM-007",
        "Sensitive data can leave through external outputs",
        "Information Disclosure",
        "high",
        "Confidential or personal data is in reach, the agent can send email "
        "or call external APIs, and outputs are not validated before they leave.",
        ["Validate outputs before external sends", "Redact sensitive fields at the boundary"],
        [_contracts()],
        _c007,
    ),
    Rule(
        "ATM-008",
        "Sensitive data can be exfiltrated through responses",
        "Information Disclosure",
        "medium",
        "Personal data or credentials are in reach and answers go straight to "
        "the user with no output validation, so a prompt can ask for them.",
        ["Validate and redact user-facing responses", "Keep credentials out of model context"],
        [_contracts(), _llm()],
        _c008,
    ),
    Rule(
        "ATM-009",
        "Persistent memory written from untrusted input",
        "Tampering",
        "high",
        "Long-term memory accepts writes that trace back to untrusted input. "
        "A poisoned note survives the session and steers later sessions.",
        ["Gate memory writes behind review or a guard", "Tag memory with its source"],
        [_llm(), _audit()],
        _c009,
    ),
    Rule(
        "ATM-010",
        "Persistent memory shared across users",
        "Information Disclosure",
        "high",
        "Persistent memory is shared across users, so one user's data can "
        "surface in another user's session.",
        ["Scope memory per user", "Partition shared knowledge from private memory"],
        [_rag()],
        _c010,
    ),
    Rule(
        "ATM-011",
        "Unaudited MCP server in the tool surface",
        "Tampering",
        "medium",
        "An MCP server is connected but has not been audited. Its tools, "
        "prompts, and updates are taken on faith.",
        ["Audit each MCP server before connecting it", "Pin versions and re-audit on change"],
        [_mcp(), _bom()],
        _c011,
    ),
    Rule(
        "ATM-012",
        "Network-exposed MCP server without authentication",
        "Spoofing",
        "critical",
        "An MCP server is reachable on the network and does not authenticate "
        "callers. Anyone who can reach it can use the agent's tools.",
        ["Require authentication on exposed servers", "Bind servers locally where possible"],
        [_mcp()],
        _c012,
    ),
    Rule(
        "ATM-013",
        "No audit logging",
        "Repudiation",
        "medium",
        "Actions are not logged, so after an incident nobody can show what "
        "the agent did, in what order, or why.",
        ["Log tool calls, inputs, and decisions", "Keep the log tamper-evident"],
        [_audit()],
        _c013,
    ),
    Rule(
        "ATM-014",
        "Sensitive data can land in unredacted audit logs",
        "Information Disclosure",
        "medium",
        "Logging is on, redaction is off, and sensitive data is in reach. "
        "The log becomes a second copy of the secrets it was meant to protect.",
        ["Redact secrets and personal data before writing logs", "Test redaction with fixtures"],
        [_audit()],
        _c014,
    ),
    Rule(
        "ATM-015",
        "No kill switch",
        "Denial of Service",
        "medium",
        "There is no way to stop the agent quickly. A looping or compromised "
        "agent keeps acting until someone pulls credentials by hand.",
        ["Add a kill switch that halts tool calls", "Rehearse using it"],
        [_policy()],
        _c015,
    ),
    Rule(
        "ATM-016",
        "No rate limits on costly or external actions",
        "Denial of Service",
        "medium",
        "The agent can call the network, spend money, or call external APIs "
        "with no rate limits, so a loop or an attacker can run up cost and abuse.",
        ["Rate limit tool calls and external outputs", "Cap spend per session"],
        [_policy()],
        _c016,
    ),
    Rule(
        "ATM-017",
        "Multiple agents share one identity",
        "Spoofing",
        "medium",
        "Several agents act under one identity, so actions cannot be "
        "attributed and one agent can be impersonated by another.",
        ["Give each agent its own identity", "Log which agent took each action"],
        [_audit(), _scopes()],
        _c017,
    ),
    Rule(
        "ATM-018",
        "Subagents inherit credentials",
        "Elevation of Privilege",
        "high",
        "Subagents inherit the parent agent's credentials, so delegating a "
        "small task hands over the full reach of the parent.",
        ["Issue subagents their own scoped credentials", "Never pass parent credentials down"],
        [_scopes()],
        _c018,
    ),
    Rule(
        "ATM-019",
        "State-changing tools with no policy gate",
        "Elevation of Privilege",
        "high",
        "Tools can change state or reach a database and no policy enforcement "
        "sits in front of them, so the model's say-so is the only check.",
        ["Put a policy gate in front of state-changing tools", "Default to deny"],
        [_policy()],
        _c019,
    ),
    Rule(
        "ATM-020",
        "Attack surface is not inventoried",
        "Information Disclosure",
        "low",
        "The components of this agent are not tracked in an inventory, so "
        "nobody can say what the attack surface actually is.",
        ["Inventory models, tools, servers, and data", "Refresh the inventory on change"],
        [_bom()],
        _c020,
    ),
    Rule(
        "ATM-021",
        "Retrieved documents can carry sensitive data out",
        "Information Disclosure",
        "high",
        "Documents are retrieved into context, sensitive data is among them, "
        "and outputs are not validated. A crafted document or question can "
        "walk that data out through the answer.",
        ["Validate outputs from retrieval-backed agents", "Watch retrieval with canaries"],
        [_rag(), _contracts()],
        _c021,
    ),
    Rule(
        "ATM-022",
        "Unauthenticated tool can write or reach a database",
        "Spoofing",
        "high",
        "A tool that can write or reach a database does not authenticate its "
        "caller, so anything that can reach the tool can change state as the agent.",
        ["Authenticate every state-changing tool", "Bind tools to the agent identity"],
        [_policy(), _mcp()],
        _c022,
    ),
    Rule(
        "ATM-023",
        "Unsandboxed code execution with broad credentials",
        "Elevation of Privilege",
        "critical",
        "Code runs without a sandbox while the agent holds broad, long-lived "
        "credentials. This is the worst combination in the catalog: injected "
        "instructions become host commands with lasting, wide access.",
        [
            "Sandbox code execution and strip ambient credentials",
            "Replace broad credentials with scoped, short-lived ones",
        ],
        [_policy(), _scopes()],
        _c023,
    ),
]

RULES_BY_ID = {r.id: r for r in RULES}


def analyze(arch: Architecture) -> list[Threat]:
    """Apply every rule to the architecture. Deterministic order: rule id."""
    threats: list[Threat] = []
    for rule in RULES:
        evidence = rule.check(arch)
        if evidence is not None:
            threats.append(
                Threat(
                    id=rule.id,
                    title=rule.title,
                    stride=rule.stride,
                    severity=rule.severity,
                    description=rule.description,
                    evidence=evidence,
                    mitigations=list(rule.mitigations),
                    companions=list(rule.companions),
                )
            )
    return threats
