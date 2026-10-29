"""agent-threat-model: threat modeling for AI agent apps.

Describe your agent architecture in a JSON or Python spec, and the
engine applies a deterministic STRIDE-style rule catalog to produce
a threat model: threats with severity, the spec evidence that
triggered each one, mitigations, companion tools, and a zero-trust
scorecard across five dimensions.

Quickstart:
    from agent_threat_model import Architecture, build_threat_model

    arch = Architecture.from_json_file("spec.json")
    model = build_threat_model(arch)
    print(model.summary_line())
    print(model.to_markdown())
"""

from agent_threat_model.engine import RULES, Threat, analyze
from agent_threat_model.models import Architecture, SpecError
from agent_threat_model.report import ThreatModel, build_threat_model
from agent_threat_model.scorecard import Scorecard, score_architecture

__version__ = "0.2.0"

__all__ = [
    "RULES",
    "Architecture",
    "Scorecard",
    "SpecError",
    "Threat",
    "ThreatModel",
    "analyze",
    "build_threat_model",
    "score_architecture",
]
