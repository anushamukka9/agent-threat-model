"""Threat model report: threats, scorecard, and summaries together."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_threat_model.engine import SEVERITY_RANK, Threat, analyze
from agent_threat_model.models import Architecture, SpecError
from agent_threat_model.scorecard import Scorecard, score_architecture


@dataclass
class ThreatModel:
    architecture_name: str
    threats: list[Threat] = field(default_factory=list)
    scorecard: Scorecard = field(default_factory=Scorecard)
    # The canonical spec dict this model was built from, when known.
    # It rides along in the JSON export so the canvas (or another
    # engine run) can rebuild the exact same questionnaire state.
    # It is never used to recompute an imported model: an imported
    # model keeps the threats and scorecard it was exported with.
    source_spec: dict[str, Any] | None = None

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
        data: dict[str, Any] = {
            "architecture": self.architecture_name,
            "summary": self.summary_line(),
            "counts_by_severity": self.counts_by_severity(),
            "counts_by_stride": self.counts_by_stride(),
            "scorecard": self.scorecard.to_dict(),
            "threats": [t.to_dict() for t in self.threats],
        }
        if self.source_spec is not None:
            data["spec"] = self.source_spec
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + "\n"

    @classmethod
    def from_dict(cls, data: Any) -> ThreatModel:
        """Rebuild a finished model from its JSON export.

        The imported model keeps the exported threats and scorecard
        exactly as they were. It is not recomputed from the spec, so
        a model exported from the canvas, or edited by hand with
        care, imports as itself. Raises SpecError on a bad export.
        """
        if not isinstance(data, dict):
            raise SpecError(f"model: expected an object, got {type(data).__name__}")
        name = data.get("architecture") or data.get("architecture_name")
        if not isinstance(name, str) or not name:
            raise SpecError(f"model.architecture: expected a non-empty string, got {name!r}")
        threats_raw = data.get("threats")
        if not isinstance(threats_raw, list):
            raise SpecError("model.threats: expected a list")
        scorecard_raw = data.get("scorecard")
        if not isinstance(scorecard_raw, dict):
            raise SpecError("model.scorecard: expected an object")
        try:
            threats = [Threat.from_dict(item) for item in threats_raw]
            scorecard = Scorecard.from_dict(scorecard_raw)
        except (KeyError, TypeError, ValueError) as exc:
            raise SpecError(f"model: cannot parse exported threat or scorecard: {exc}") from exc
        source_spec = None
        spec_raw = data.get("spec")
        if spec_raw is not None:
            # Canonicalize through the spec parser so an imported
            # canvas state matches a Python-built one exactly.
            source_spec = Architecture.from_dict(spec_raw).to_dict()
        return cls(
            architecture_name=name,
            threats=threats,
            scorecard=scorecard,
            source_spec=source_spec,
        )

    @classmethod
    def from_json(cls, text: str) -> ThreatModel:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SpecError(f"model is not valid JSON: {exc}") from exc
        return cls.from_dict(data)

    @classmethod
    def from_json_file(cls, path: str | Path) -> ThreatModel:
        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise SpecError(f"cannot read model file {p}: {exc}") from exc
        return cls.from_json(text)

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
        source_spec=arch.to_dict(),
    )
