"""Zero-trust scorecard: five dimensions, each explained check by check.

Every check is a plain yes or no over the spec, with a weight. A
dimension score is the weighted share of checks that passed, so a
reader can see exactly why a dimension scored what it scored.
Grades: 90-100 strong, 70-89 fair, 40-69 weak, 0-39 missing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_threat_model.models import Architecture

DIMENSIONS = ("inventory", "identity", "least_privilege", "audit", "kill_switch")


@dataclass
class Check:
    label: str
    passed: bool
    weight: int

    def to_dict(self) -> dict:
        return {"label": self.label, "passed": self.passed, "weight": self.weight}


@dataclass
class DimensionScore:
    name: str
    score: int
    grade: str
    checks: list[Check] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "score": self.score,
            "grade": self.grade,
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class Scorecard:
    dimensions: list[DimensionScore] = field(default_factory=list)
    overall: int = 0

    def dimension(self, name: str) -> DimensionScore:
        for d in self.dimensions:
            if d.name == name:
                return d
        raise KeyError(name)

    def to_dict(self) -> dict:
        return {
            "overall": self.overall,
            "dimensions": [d.to_dict() for d in self.dimensions],
        }


def grade_for(score: int) -> str:
    if score >= 90:
        return "strong"
    if score >= 70:
        return "fair"
    if score >= 40:
        return "weak"
    return "missing"


def _score(name: str, checks: list[Check]) -> DimensionScore:
    total = sum(c.weight for c in checks)
    passed = sum(c.weight for c in checks if c.passed)
    score = round(100 * passed / total) if total else 0
    return DimensionScore(name=name, score=score, grade=grade_for(score), checks=checks)


def score_architecture(a: Architecture) -> Scorecard:
    scoped = a.credentials.scope in ("none", "scoped_short_lived")
    per_agent = a.agents.per_agent_identity or a.agents.count <= 1
    tools_auth = all(t.authenticated for t in a.tools)
    mcp_auth = all(s.authenticated for s in a.mcp_servers)
    mcp_audited = all(s.audited for s in a.mcp_servers)
    approval = a.controls.human_approval_for_writes or all(
        t.requires_approval for t in a.tools if t.has("write", "delete", "payment")
    )
    # Sandboxing check: every tool that exists is sandboxed. With no
    # tools there is nothing to sandbox, so the check passes.
    sandboxed = all(t.sandboxed for t in a.tools) if a.tools else True

    inventory = _score(
        "inventory",
        [
            Check("inventory is tracked", a.controls.inventory_tracked, 40),
            Check("all MCP servers are audited", mcp_audited, 30),
            Check("data holdings are declared", len(a.data) > 0, 15),
            Check("tools are declared", len(a.tools) > 0, 15),
        ],
    )
    identity = _score(
        "identity",
        [
            Check("each agent has its own identity (or there is one agent)", per_agent, 40),
            Check("all tools are authenticated", tools_auth, 30),
            Check("all MCP servers are authenticated", mcp_auth, 30),
        ],
    )
    least = _score(
        "least_privilege",
        [
            Check("credentials are scoped and short-lived (or none)", scoped, 30),
            Check("writes require approval", bool(approval), 25),
            Check("tools run sandboxed", sandboxed, 25),
            Check("policy enforcement is in place", a.controls.policy_enforcement, 20),
        ],
    )
    audit = _score(
        "audit",
        [
            Check("audit logging is on", a.controls.audit_logging, 50),
            Check("audit logs are redacted", a.controls.audit_log_redaction, 30),
            Check("actions can be attributed to an agent", per_agent, 20),
        ],
    )
    kill = _score(
        "kill_switch",
        [
            Check("a kill switch exists", a.controls.kill_switch, 50),
            Check("rate limits are in place", a.controls.rate_limits, 25),
            Check("credentials can be revoked quickly (scoped or none)", scoped, 25),
        ],
    )
    dims = [inventory, identity, least, audit, kill]
    overall = round(sum(d.score for d in dims) / len(dims)) if dims else 0
    return Scorecard(dimensions=dims, overall=overall)
