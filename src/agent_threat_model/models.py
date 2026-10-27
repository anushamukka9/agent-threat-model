"""Spec models: the architecture description the engine reads.

A spec is plain JSON (or a Python dict) describing one agent app:
what goes in, what tools it can call, what data it touches, how it
remembers, where its answers go, what credentials it holds, which
MCP servers it uses, how many agents share the work, and which
controls are in place.

Unknown means absent. If a control is not listed in the spec, the
engine assumes it is not there. That is fail-closed for a threat
model, and it is stated plainly in the limitations doc.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

INPUT_SOURCES = ("user", "web", "documents", "tool_output", "email", "api", "mcp_server")
CAPABILITIES = (
    "read",
    "write",
    "delete",
    "network",
    "code_exec",
    "send_message",
    "payment",
    "database",
    "file_access",
)
SENSITIVITIES = ("public", "internal", "confidential", "pii", "credentials")
MEMORY_TYPES = ("none", "session", "persistent")
OUTPUT_KINDS = (
    "user",
    "email",
    "api_call",
    "code_change",
    "payment",
    "database_write",
    "file_write",
)
CREDENTIAL_SCOPES = ("none", "scoped_short_lived", "long_lived_narrow", "long_lived_broad")
CREDENTIAL_STORES = ("vault", "env", "prompt", "code", "none")


class SpecError(ValueError):
    """Raised when a spec cannot be parsed or fails validation."""


def _check_enum(value: Any, allowed: tuple[str, ...], where: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise SpecError(f"{where}: expected one of {list(allowed)}, got {value!r}")
    return value


def _check_bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise SpecError(f"{where}: expected a boolean, got {value!r}")
    return value


def _require_dict(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SpecError(f"{where}: expected an object, got {type(value).__name__}")
    return value


def _require_list(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise SpecError(f"{where}: expected a list, got {type(value).__name__}")
    return value


@dataclass
class InputSource:
    source: str
    trusted: bool = False

    @classmethod
    def from_dict(cls, data: Any, where: str = "inputs[]") -> InputSource:
        data = _require_dict(data, where)
        source = _check_enum(data.get("source"), INPUT_SOURCES, f"{where}.source")
        trusted = _check_bool(data.get("trusted", False), f"{where}.trusted")
        return cls(source=source, trusted=trusted)


@dataclass
class Tool:
    name: str
    capabilities: list[str] = field(default_factory=list)
    requires_approval: bool = False
    sandboxed: bool = False
    authenticated: bool = False

    @classmethod
    def from_dict(cls, data: Any, where: str = "tools[]") -> Tool:
        data = _require_dict(data, where)
        name = data.get("name")
        if not isinstance(name, str) or not name:
            raise SpecError(f"{where}.name: expected a non-empty string, got {name!r}")
        caps_raw = _require_list(data.get("capabilities", []), f"{where}.capabilities")
        caps = [_check_enum(c, CAPABILITIES, f"{where}.capabilities") for c in caps_raw]
        return cls(
            name=name,
            capabilities=caps,
            requires_approval=_check_bool(
                data.get("requires_approval", False), f"{where}.requires_approval"
            ),
            sandboxed=_check_bool(data.get("sandboxed", False), f"{where}.sandboxed"),
            authenticated=_check_bool(data.get("authenticated", False), f"{where}.authenticated"),
        )

    def has(self, *caps: str) -> bool:
        return any(c in self.capabilities for c in caps)


@dataclass
class DataItem:
    name: str
    sensitivity: str = "internal"
    encrypted: bool = False

    @classmethod
    def from_dict(cls, data: Any, where: str = "data[]") -> DataItem:
        data = _require_dict(data, where)
        name = data.get("name")
        if not isinstance(name, str) or not name:
            raise SpecError(f"{where}.name: expected a non-empty string, got {name!r}")
        return cls(
            name=name,
            sensitivity=_check_enum(
                data.get("sensitivity", "internal"), SENSITIVITIES, f"{where}.sensitivity"
            ),
            encrypted=_check_bool(data.get("encrypted", False), f"{where}.encrypted"),
        )


@dataclass
class Memory:
    type: str = "none"
    shared_across_users: bool = False
    writes_from_untrusted_input: bool = False

    @classmethod
    def from_dict(cls, data: Any, where: str = "memory") -> Memory:
        if data is None:
            return cls()
        data = _require_dict(data, where)
        return cls(
            type=_check_enum(data.get("type", "none"), MEMORY_TYPES, f"{where}.type"),
            shared_across_users=_check_bool(
                data.get("shared_across_users", False), f"{where}.shared_across_users"
            ),
            writes_from_untrusted_input=_check_bool(
                data.get("writes_from_untrusted_input", False),
                f"{where}.writes_from_untrusted_input",
            ),
        )


@dataclass
class Credentials:
    scope: str = "none"
    stored_in: str = "none"

    @classmethod
    def from_dict(cls, data: Any, where: str = "credentials") -> Credentials:
        if data is None:
            return cls()
        data = _require_dict(data, where)
        return cls(
            scope=_check_enum(data.get("scope", "none"), CREDENTIAL_SCOPES, f"{where}.scope"),
            stored_in=_check_enum(
                data.get("stored_in", "none"), CREDENTIAL_STORES, f"{where}.stored_in"
            ),
        )


@dataclass
class McpServer:
    name: str
    audited: bool = False
    authenticated: bool = False
    network_exposed: bool = False

    @classmethod
    def from_dict(cls, data: Any, where: str = "mcp_servers[]") -> McpServer:
        data = _require_dict(data, where)
        name = data.get("name")
        if not isinstance(name, str) or not name:
            raise SpecError(f"{where}.name: expected a non-empty string, got {name!r}")
        return cls(
            name=name,
            audited=_check_bool(data.get("audited", False), f"{where}.audited"),
            authenticated=_check_bool(data.get("authenticated", False), f"{where}.authenticated"),
            network_exposed=_check_bool(
                data.get("network_exposed", False), f"{where}.network_exposed"
            ),
        )


@dataclass
class Agents:
    count: int = 1
    per_agent_identity: bool = False
    subagents_inherit_credentials: bool = False

    @classmethod
    def from_dict(cls, data: Any, where: str = "agents") -> Agents:
        if data is None:
            return cls()
        data = _require_dict(data, where)
        count = data.get("count", 1)
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise SpecError(f"{where}.count: expected an integer >= 1, got {count!r}")
        return cls(
            count=count,
            per_agent_identity=_check_bool(
                data.get("per_agent_identity", False), f"{where}.per_agent_identity"
            ),
            subagents_inherit_credentials=_check_bool(
                data.get("subagents_inherit_credentials", False),
                f"{where}.subagents_inherit_credentials",
            ),
        )


@dataclass
class Controls:
    input_guard: bool = False
    output_validation: bool = False
    audit_logging: bool = False
    audit_log_redaction: bool = False
    policy_enforcement: bool = False
    human_approval_for_writes: bool = False
    rate_limits: bool = False
    kill_switch: bool = False
    inventory_tracked: bool = False

    @classmethod
    def from_dict(cls, data: Any, where: str = "controls") -> Controls:
        if data is None:
            return cls()
        data = _require_dict(data, where)
        names = (
            "input_guard",
            "output_validation",
            "audit_logging",
            "audit_log_redaction",
            "policy_enforcement",
            "human_approval_for_writes",
            "rate_limits",
            "kill_switch",
            "inventory_tracked",
        )
        return cls(**{n: _check_bool(data.get(n, False), f"{where}.{n}") for n in names})


@dataclass
class Architecture:
    name: str
    description: str = ""
    inputs: list[InputSource] = field(default_factory=list)
    tools: list[Tool] = field(default_factory=list)
    data: list[DataItem] = field(default_factory=list)
    memory: Memory = field(default_factory=Memory)
    outputs: list[str] = field(default_factory=list)
    credentials: Credentials = field(default_factory=Credentials)
    mcp_servers: list[McpServer] = field(default_factory=list)
    agents: Agents = field(default_factory=Agents)
    controls: Controls = field(default_factory=Controls)

    @classmethod
    def from_dict(cls, data: Any) -> Architecture:
        data = _require_dict(data, "spec")
        name = data.get("name")
        if not isinstance(name, str) or not name:
            raise SpecError(f"spec.name: expected a non-empty string, got {name!r}")
        description = data.get("description", "")
        if not isinstance(description, str):
            raise SpecError(f"spec.description: expected a string, got {description!r}")
        outputs_raw = _require_list(data.get("outputs", []), "spec.outputs")
        outputs = [_check_enum(o, OUTPUT_KINDS, "spec.outputs") for o in outputs_raw]
        return cls(
            name=name,
            description=description,
            inputs=[
                InputSource.from_dict(item, f"inputs[{i}]")
                for i, item in enumerate(_require_list(data.get("inputs", []), "spec.inputs"))
            ],
            tools=[
                Tool.from_dict(item, f"tools[{i}]")
                for i, item in enumerate(_require_list(data.get("tools", []), "spec.tools"))
            ],
            data=[
                DataItem.from_dict(item, f"data[{i}]")
                for i, item in enumerate(_require_list(data.get("data", []), "spec.data"))
            ],
            memory=Memory.from_dict(data.get("memory")),
            outputs=outputs,
            credentials=Credentials.from_dict(data.get("credentials")),
            mcp_servers=[
                McpServer.from_dict(item, f"mcp_servers[{i}]")
                for i, item in enumerate(
                    _require_list(data.get("mcp_servers", []), "spec.mcp_servers")
                )
            ],
            agents=Agents.from_dict(data.get("agents")),
            controls=Controls.from_dict(data.get("controls")),
        )

    @classmethod
    def from_json(cls, text: str) -> Architecture:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SpecError(f"spec is not valid JSON: {exc}") from exc
        return cls.from_dict(data)

    @classmethod
    def from_json_file(cls, path: str | Path) -> Architecture:
        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise SpecError(f"cannot read spec file {p}: {exc}") from exc
        return cls.from_json(text)

    # Small helpers the engine and scorecard share.

    def sensitive_data(self, levels: tuple[str, ...] = ("pii", "credentials")) -> list[DataItem]:
        return [d for d in self.data if d.sensitivity in levels]

    def tools_with(self, *caps: str) -> list[Tool]:
        return [t for t in self.tools if t.has(*caps)]
