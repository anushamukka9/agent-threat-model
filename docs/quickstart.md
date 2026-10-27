# Quickstart

## Install

```bash
pip install agent-threat-model
```

## The thirty-second version

```bash
agent-threat-model example --write my-agent.json
agent-threat-model analyze my-agent.json
agent-threat-model validate my-agent.json
```

The example spec is a deliberately vulnerable support agent. The
analyze step reads the spec, applies the rule catalog, and prints a
threat model in markdown: the threats it found, the spec evidence
behind each one, what to do about it, and a zero-trust scorecard.
Analyze exits 1 when it finds a threat at or above the fail-on
level (high by default), which is the behavior you want in CI.

In Python, the same thing looks like this:

```python
from agent_threat_model import Architecture, build_threat_model

arch = Architecture.from_json_file("my-agent.json")
model = build_threat_model(arch)
print(model.summary_line())
print(model.to_markdown())
```

## Try it on the bundled examples

```bash
python examples/quickstart.py
agent-threat-model analyze examples/support_agent.json
agent-threat-model analyze examples/hardened_agent.json
```

The support agent produces 19 threats and an overall score of
6/100. The hardened agent produces zero threats and 100/100. Your
own spec will land somewhere between those two, and the report
shows its work either way.

## Write your own spec

A spec is one JSON object describing your agent: inputs, tools,
data, memory, outputs, credentials, MCP servers, agents, and
controls. Every field, every allowed value, and every default is in
[spec-format.md](spec-format.md). Start from the example and change
one section at a time, re-running analyze as you go.

## Next

- [spec-format.md](spec-format.md): every field, enum, and default,
  including the unknown-means-absent rule.
- [threat-catalog.md](threat-catalog.md): all 23 rules, what
  triggers each one, and the mitigations.
- [scorecard.md](scorecard.md): the five dimensions and their checks.
- [cli.md](cli.md): the commands and their exit codes.
- [limitations.md](limitations.md): what this does not do. Read it.
