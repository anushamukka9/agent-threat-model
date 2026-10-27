"""Threat model report: threats, scorecard, and summaries together."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field

from agent_threat_model.engine import SEVERITY_RANK, Threat, analyze
from agent_threat_model.models import Architecture
from agent_threat_model.scorecard import Scorecard, score_architecture


@dataclass
class ThreatModel:
    architecture_name: str
    threats: list[Threat] = field(default_factory=list)
    scorecard: Scorecard = field(default_factory=Scorecard)

    def counts_by_severity(self) -> dict[str, int]:
        counts = Counter(t.severity for t in self.threats)
        return {s: counts.get(s, 0) for s in ("critical", "high", "medium", "low")}

    def counts_by_stride(self) -> dict[str, int]:
        return dict(Counter(t.stride for t in self.threats))

    def summary_line(self) -> str:
        c = self.counts_by_severity()
        return (
            f"{len(self.threats)} threats: {c['critical']} critical, {c['high']} high, "
            f"{c['medium']} medium, {c['low']} low; overall score {self.scorecard.overall}/100"
        )

    def to_dict(self) -> dict:
        return {
            "architecture": self.architecture_name,
            "summary": self.summary_line(),
            "counts_by_severity": self.counts_by_severity(),
            "counts_by_stride": self.counts_by_stride(),
            "scorecard": self.scorecard.to_dict(),
            "threats": [t.to_dict() for t in self.threats],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + "\n"

    def to_markdown(self) -> str:
        lines = [
            f"# Threat model: {self.architecture_name}",
            "",
            self.summary_line(),
            "",
            "## Scorecard",
            "",
            "| Dimension | Score | Grade |",
            "|---|---|---|",
        ]
        for d in self.scorecard.dimensions:
            lines.append(f"| {d.name} | {d.score}/100 | {d.grade} |")
        lines.append(f"| **overall** | **{self.scorecard.overall}/100** |  |")
        lines += ["", "## Threats", ""]
        if not self.threats:
            lines.append("No threats found for this spec.")
            lines.append("")
            return "\n".join(lines)
        lines += [
            "| ID | Severity | STRIDE | Threat | Evidence |",
            "|---|---|---|---|---|",
        ]
        for t in self.threats:
            lines.append(f"| {t.id} | {t.severity} | {t.stride} | {t.title} | {t.evidence} |")
        for t in self.threats:
            lines += ["", f"### {t.id}: {t.title}", ""]
            lines.append(f"Severity: {t.severity}. STRIDE: {t.stride}.")
            lines.append("")
            lines.append(t.description)
            lines.append("")
            lines.append(f"Evidence: {t.evidence}")
            lines.append("")
            lines.append("Mitigations:")
            for m in t.mitigations:
                lines.append(f"- {m}")
            if t.companions:
                lines.append("")
                lines.append("Companion tools:")
                for c in t.companions:
                    lines.append(f"- {c.repo}: {c.helps}")
        lines.append("")
        return "\n".join(lines)

    def to_text(self) -> str:
        lines = [f"Threat model: {self.architecture_name}", self.summary_line(), ""]
        lines.append("Scorecard:")
        for d in self.scorecard.dimensions:
            lines.append(f"  {d.name}: {d.score}/100 ({d.grade})")
        lines.append(f"  overall: {self.scorecard.overall}/100")
        lines.append("")
        if not self.threats:
            lines.append("No threats found.")
        for t in self.threats:
            lines.append(f"{t.id} [{t.severity}] ({t.stride}) {t.title}")
            lines.append(f"  evidence: {t.evidence}")
            for m in t.mitigations:
                lines.append(f"  mitigation: {m}")
        return "\n".join(lines) + "\n"


def build_threat_model(arch: Architecture) -> ThreatModel:
    threats = analyze(arch)
    threats.sort(key=lambda t: (SEVERITY_RANK[t.severity], t.id))
    return ThreatModel(
        architecture_name=arch.name,
        threats=threats,
        scorecard=score_architecture(arch),
    )
