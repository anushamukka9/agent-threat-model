# JSON export and import

A finished threat model is a document. You should be able to save
it, send it, diff it, and load it back later without rebuilding it
from the spec and hoping nothing changed. That is what the JSON
export is for.

## Export

In Python:

```python
from agent_threat_model import Architecture, build_threat_model

model = build_threat_model(Architecture.from_json_file("spec.json"))
text = model.to_json()          # a string, ready to write to a file
data = model.to_dict()          # the same content as a dict
```

From the command line:

```bash
agent-threat-model export spec.json --output model.json
agent-threat-model export spec.json            # or print it to stdout
```

In the canvas, the **Model JSON** box has **Export model JSON**
(copies the JSON and fills the box) and **Download model JSON**.

The export carries the architecture name, the summary line, the
severity and STRIDE counts, the full scorecard with every check,
every threat with its evidence, mitigations, and companion tools,
and the spec the model was built from, under the `spec` key. The
spec rides along so the canvas can rebuild the exact questionnaire
state that produced the model.

The spec alone round-trips too: `Architecture.to_dict()` and
`Architecture.to_json()` give the canonical spec, and feeding them
back to `Architecture.from_dict` or `Architecture.from_json` builds
a byte-for-byte identical report.

## Import

In Python:

```python
from agent_threat_model import ThreatModel

model = ThreatModel.from_json_file("model.json")
print(model.to_markdown())      # identical to the exported model
```

From the command line:

```bash
agent-threat-model import model.json                    # markdown
agent-threat-model import model.json --format json      # re-export
agent-threat-model import model.json --fail-on medium   # CI exit code
```

In the canvas, paste an exported model into the **Model JSON** box
and use **Load model JSON**. If the export carries a spec, the
questionnaire is rebuilt from it first, then the imported model is
what renders.

## What import promises, and what it does not

- **Imported means imported.** An imported model keeps the threats
  and scorecard it was exported with. Import never recomputes the
  model from the spec, so a model exported from the canvas, or one
  a reviewer annotated by hand, comes back as itself.
- **Byte-for-byte markdown.** For a model this engine exported,
  the imported model's markdown, JSON, and summary line match the
  original exactly. The test suite checks this for both bundled
  examples, in Python, through the CLI, in the canvas engine, and
  across the two engines in both directions.
- **Bad exports fail loudly.** Invalid JSON, a missing threats
  list, or a missing scorecard raises `SpecError` in Python (exit
  code 2 in the CLI) and shows an error in the canvas. Nothing is
  half-imported.
- **Old exports still load.** Exports from before the `spec` key
  existed import fine. They just cannot rebuild a questionnaire
  state, because they never carried one.
