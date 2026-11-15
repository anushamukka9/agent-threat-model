"""Round-trip demo: export a finished model to JSON, import it back.

Run: python examples/roundtrip.py

Builds the threat model for the bundled support agent, exports it
to JSON, imports the JSON back with ThreatModel.from_json, and
checks that the markdown is byte-for-byte identical. The same JSON
loads in the canvas (canvas/index.html, Model JSON box) and with
the CLI import command.
"""

import json
from pathlib import Path

from agent_threat_model import Architecture, ThreatModel, build_threat_model

HERE = Path(__file__).resolve().parent

arch = Architecture.from_json_file(HERE / "support_agent.json")
model = build_threat_model(arch)

exported = model.to_json()
print(f"exported {len(exported)} bytes of JSON for {model.architecture_name}")
print(f"spec sections in the export: {sorted(json.loads(exported)['spec'])}")

imported = ThreatModel.from_json(exported)
assert imported.to_markdown() == model.to_markdown()
assert imported.to_json() == exported
print("imported back: markdown and JSON are byte-for-byte identical")
print(imported.summary_line())

# The spec alone round-trips too.
rebuilt = Architecture.from_json(arch.to_json())
assert build_threat_model(rebuilt).to_markdown() == model.to_markdown()
print("spec round-trip: identical markdown as well")
print("done. one model out as JSON, the same model back in.")
