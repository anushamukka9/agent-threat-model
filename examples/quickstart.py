"""Thirty-second demo: analyze the bundled support agent spec.

Run: python examples/quickstart.py

Loads examples/support_agent.json through the library API, prints
the summary line, the scorecard, and the first few threats, then
analyzes the hardened example to show a clean result.
"""

from pathlib import Path

from agent_threat_model import Architecture, build_threat_model

HERE = Path(__file__).resolve().parent

arch = Architecture.from_json_file(HERE / "support_agent.json")
model = build_threat_model(arch)
print(model.summary_line())
print()
print("scorecard:")
for d in model.scorecard.dimensions:
    print(f"  {d.name}: {d.score}/100 ({d.grade})")
print(f"  overall: {model.scorecard.overall}/100")
print()
print("first threats:")
for threat in model.threats[:5]:
    print(f"  {threat.id} [{threat.severity}] {threat.title}")
    print(f"    evidence: {threat.evidence}")

hardened = build_threat_model(Architecture.from_json_file(HERE / "hardened_agent.json"))
print()
print(f"hardened example: {hardened.summary_line()}")
assert len(hardened.threats) == 0
print("done. one spec in, one threat model out.")
