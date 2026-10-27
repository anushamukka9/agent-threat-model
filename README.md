# agent-threat-model

A threat-model engine for AI agent apps. You describe your agent
architecture in one JSON spec, and it applies a deterministic rule
catalog, STRIDE-style categories adapted for agents, to produce a
threat model: threats with severity, the spec evidence that
triggered each one, mitigations, the companion tools that help,
and a zero-trust scorecard across five dimensions. Know how your
agent can be hurt before someone shows you.

## Quickstart

```bash
pip install agent-threat-model
```

```bash
agent-threat-model example --write my-agent.json
agent-threat-model analyze my-agent.json
```

In Python:

```python
from agent_threat_model import Architecture, build_threat_model

arch = Architecture.from_json_file("my-agent.json")
model = build_threat_model(arch)
print(model.summary_line())
# 19 threats: 1 critical, 11 high, 6 medium, 1 low; overall score 6/100
print(model.to_markdown())
```

That output is real: it is what the bundled example, a vulnerable
support agent, actually scores. Thirty seconds, start to finish.
See [docs/quickstart.md](docs/quickstart.md) and
[examples/quickstart.py](examples/quickstart.py).

## Why this exists

Every agent app I review has the same review problem. The risks do
not live in one file. They live in the combination: untrusted email
coming in, a tool that can issue refunds, credentials that last
forever, memory shared across customers, and no way to stop the
thing when it misbehaves. Each part looks fine on its own. The
combination is the threat model, and nobody had written it down.

Threat modeling has a classic shape for this: describe the system,
walk a category list, write down what can go wrong and what you
will do about it. agent-threat-model makes that a command instead
of a workshop. The spec takes ten minutes to write. The engine is
deterministic, so the same spec gives the same report in review,
in CI, and six months later when someone asks what changed.

It pairs with my other repos in this series: llm-sentinel guards
what goes into the model, mcp-audit audits MCP server surfaces,
rag-canary watches retrieval, agent-policy-kit decides what the
agent may do, agent-scopes keeps its credentials small and short,
ai-bom inventories what the agent is made of, and
agent-threat-model works out how the whole thing can be hurt
before it runs.

## How it works

Three steps, all plain:

1. **Spec.** One JSON object: inputs and whether they are trusted,
   tools with their capabilities, data with its sensitivity,
   memory, outputs, credentials, MCP servers, agent count and
   identity, and which controls are in place. Every field and
   default is in [docs/spec-format.md](docs/spec-format.md). If a
   control is not in the spec, the engine assumes it is absent.
   Unknown means absent, fail-closed, and the limitations doc
   says so.
2. **Rules.** A catalog of 23 deterministic rules (ATM-001 to
   ATM-023), each with a STRIDE category, a severity, an evidence
   string built from your actual spec values, mitigations, and
   the companion repo that helps with that threat. The full
   catalog is in [docs/threat-catalog.md](docs/threat-catalog.md).
3. **Report and scorecard.** Threats sorted by severity, counts by
   severity and by STRIDE category, and a zero-trust scorecard
   across inventory, identity, least_privilege, audit, and
   kill_switch, each 0-100 with its checks shown pass or fail so
   the number is never a mystery. Details in
   [docs/scorecard.md](docs/scorecard.md).

## The STRIDE summary

| Category | What it asks | Example rule |
|---|---|---|
| Spoofing | Who is really acting? | ATM-012: network-exposed MCP server without authentication (critical) |
| Tampering | Can input or state be changed by the wrong party? | ATM-001: prompt injection through unguarded untrusted input |
| Repudiation | Could you prove what happened? | ATM-013: no audit logging |
| Information Disclosure | Can data get out? | ATM-007: sensitive data leaving through external outputs |
| Denial of Service | Can it be run into the ground? | ATM-016: no rate limits on costly actions |
| Elevation of Privilege | Can small access become big access? | ATM-023: unsandboxed code execution with broad credentials (critical) |

## A real result

The bundled support agent (examples/support_agent.json) takes
untrusted user, email, and web input, trusts its tool output,
keeps shared persistent memory, holds broad long-lived credentials
in its prompt, connects an unaudited and network-exposed MCP
server, and has almost no controls on. The engine finds:

```text
19 threats: 1 critical, 11 high, 6 medium, 1 low; overall score 6/100

inventory:        30/100 (missing)
identity:          0/100 (missing)
least_privilege:   0/100 (missing)
audit:             0/100 (missing)
kill_switch:       0/100 (missing)
overall:           6/100
```

The one critical finding is ATM-012: the CRM MCP server is
reachable on the network and does not authenticate callers. The
hardened example (examples/hardened_agent.json), with guarded
input, validated output, scoped credentials, per-agent identity,
audited servers, and a kill switch, produces zero threats and
100/100. Most real agents land between those two, and the report
shows its work either way.

## Benchmarks

Measured on this machine (see [benchmarks/results.md](benchmarks/results.md)
for the setup) against 8 labeled architectures, from a vulnerable
support bot to a hardened enterprise agent:

| Benchmark | Result |
|---|---|
| Labeled cases (8 architectures) | precision 1.00, recall 1.00 |
| Analyze the support agent spec (19 threats) | 0.073 ms average |
| Analysis throughput | 13,612 analyses/sec |

The labeled cases are the point: each one lists the exact threat
ids a careful reader would expect, the hardened case expects zero,
and the engine must match exactly. Timing is a footnote. Analysis
is cheap enough to run on every change, which is where it belongs.

## Honest limitations

- **Static spec analysis only.** This reads a spec you wrote. It
  does not run your agent or read your code, so the report is
  only as honest and complete as the spec.
- **Unknown means absent.** A control missing from the spec is
  treated as a control you do not have. That errs toward more
  findings, on purpose.
- **STRIDE is a lens, not a proof.** Zero findings means this spec
  triggers none of the 23 rules. It does not mean the agent is safe.
- **No runtime behavior.** This flags the architecture that makes
  prompt injection likely and damaging. Whether a guard catches a
  given payload is a runtime question.
- **Severity is triage guidance.** My ranking for a typical
  deployment. Your blast radius may rank them differently, and
  the evidence strings are printed so you can re-rank.

Full list in [docs/limitations.md](docs/limitations.md). Read it
before you rely on this.

## Companions

Part of my agent security series:

- [llm-sentinel](https://github.com/anushamukka9/llm-sentinel) guards prompts going in.
- [mcp-audit](https://github.com/anushamukka9/mcp-audit) audits MCP server surfaces.
- [rag-canary](https://github.com/anushamukka9/rag-canary) watches retrieval for canary leaks.
- [agent-policy-kit](https://github.com/anushamukka9/agent-policy-kit) decides what agents may do.
- [agent-audit](https://github.com/anushamukka9/agent-audit) keeps the tamper-evident record.
- [output-contracts](https://github.com/anushamukka9/output-contracts) guards tool outputs coming out.
- [agent-scopes](https://github.com/anushamukka9/agent-scopes) issues short-lived scoped credentials.
- [agent-redteam](https://github.com/anushamukka9/agent-redteam) runs adversarial checks against agents.
- [ai-bom](https://github.com/anushamukka9/ai-bom) inventories what an agent is made of.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Small and focused stays
small and focused: new rules need a triggering spec and a
mitigated spec as tests, every feature documents what it cannot
do, and there are no em-dashes in this repo.

## License

MIT. See [LICENSE](LICENSE).
