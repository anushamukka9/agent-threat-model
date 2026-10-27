# Examples

- `support_agent.json`: a vulnerable support bot spec. It takes
  untrusted email and web input, keeps shared persistent memory,
  holds broad credentials in its prompt, and has almost no controls
  on. Run `agent-threat-model analyze examples/support_agent.json`
  to see what the engine finds.
- `hardened_agent.json`: a hardened enterprise agent spec with
  guarded input, validated output, scoped credentials, per-agent
  identity, and a kill switch. It produces zero threats.
- `quickstart.py`: loads the support agent spec through the library
  API and prints the summary, scorecard, and first threats, then
  checks the hardened example. Run it with
  `python examples/quickstart.py`.
