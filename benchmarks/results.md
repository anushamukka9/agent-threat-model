# Benchmark results

Measured on the build machine (this VM, Linux x86_64, Python
3.12.3) with `python benchmarks/bench.py`: median of 5 rounds,
2,000 iterations per round, timing full analyses (rules plus
scorecard plus report build) of the bundled vulnerable support
agent spec, which produces 19 threats.

| Benchmark | Result |
|---|---|
| Labeled cases (8 architectures) | precision 1.00, recall 1.00 |
| Analyze the support agent spec (19 threats) | 0.073 ms average |
| Analysis throughput | 13,612 analyses/sec |

## What this measures, and what it does not

An analysis is pure computation over a small in-memory spec: 23
rule checks, five scorecard dimensions, and a report build. There
is no IO in the timed loop beyond loading the cases once at the
start. At well under a tenth of a millisecond per spec, the honest
takeaway is that threat modeling a spec costs nothing next to
everything else in a pipeline, so there is no performance excuse
for not running it in CI.

The labeled cases are the correctness benchmark. Each case is a
realistic architecture (a support bot, a coding agent, a research
agent with web and retrieval, a data analyst, an MCP-heavy agent,
a multi-agent team, a hardened enterprise agent, and a minimal
chatbot) with the exact threat ids a careful reader would expect,
and the engine must match them exactly. The hardened case expects
zero threats, which holds the rules honest: a genuinely hardened
spec passes clean. Precision and recall are both 1.00 on this
set. That is a statement about these 8 cases, not about every
architecture anyone will ever describe.

The CI smoke test (`python -m agent_threat_model.benchmark`) runs
the same cases and fails on any mismatch. It does not check the
timing numbers.

Safe to reproduce the measurement:

```bash
pip install -e .
python benchmarks/bench.py
```
