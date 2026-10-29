# Threat-model canvas

The canvas is a static web page in `canvas/index.html` that runs
the same engine in the browser. I answer a guided questionnaire,
and the threat model, scorecard, and markdown export build live
from my answers. No build step, no framework, no server, and no
data leaves the page unless I share it.

Open it by opening the file, or serve the repo with
`python3 -m http.server` and visit the `canvas/` path. Background
and full instructions are in
[canvas/README.md](../canvas/README.md).

## Questionnaire sections and spec fields

| Canvas section | Spec fields |
|---|---|
| Your agent | `name`, `description` |
| Inputs | `inputs[]` with `source`, plus a trusted toggle per selected source |
| Tools | `tools[]` rows: `name`, `capabilities`, `requires_approval`, `sandboxed`, `authenticated` |
| Data | `data[]` rows: `name`, `sensitivity`, `encrypted` |
| Memory | `memory.type`, `memory.shared_across_users`, `memory.writes_from_untrusted_input` |
| Outputs | `outputs[]` |
| Credentials | `credentials.scope`, `credentials.stored_in` |
| MCP servers | `mcp_servers[]` rows: `name`, `audited`, `authenticated`, `network_exposed` |
| Agents | `agents.count`, `agents.per_agent_identity`, `agents.subagents_inherit_credentials` |
| Controls | The nine `controls` booleans, each with a plain label |

Every field, allowed value, and default is defined in
[spec-format.md](spec-format.md). The canvas uses the same
defaults as the Python models: a section I leave blank is empty,
off, or absent.

## Export and share behavior

- **Export to markdown** downloads the report as a markdown
  file, and **Copy markdown** puts the same text on the
  clipboard. The format matches `report.py`: title, summary
  line, scorecard table, threats table, then one section per
  threat with mitigations and companion tools. A clean spec
  exports the no-threats line instead of the tables of threats.
- **Copy spec JSON** copies the spec the questionnaire built,
  and the spec box also accepts a pasted spec through
  **Load spec JSON**.
- **Share link** encodes the current spec as base64url JSON in
  the URL hash (`#s=...`) and copies the link. On page load, a
  spec in the hash is decoded and loaded. Hash content is not
  sent to a server, so sharing a link shares the spec only with
  the person I send it to, and a very large spec can run into
  browser URL length limits.

Spec errors show in a visible status area at the top of the
results. The page does not crash on a bad spec; it tells me which
field failed and waits for a fix.

## Limitations

- **Static page only.** The canvas is a local tool. There is no
  account, no saved history, and no server-side analysis.
- **Port parity is test-enforced.** The JavaScript engine in
  `canvas/engine.js` is a port of the Python engine. The parity
  test in `tests/test_canvas.py` runs it in Node against the
  labeled benchmark cases and both bundled examples; a drift
  between the engines fails the test suite.
- **Spec honesty bounds the report.** The canvas reads the spec
  I build, not my running agent or my code. A control I forget
  to tick is treated as a control I do not have, on purpose.
  The full list is in [limitations.md](limitations.md).
