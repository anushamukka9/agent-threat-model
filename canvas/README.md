# Threat-model canvas

This is the web version of agent-threat-model. I answer a guided
questionnaire about my agent on the left, and the threat model
builds itself on the right: threats with severity tags and STRIDE
categories, the evidence from my spec that triggered each one,
mitigations, companion tools, and the five-dimension zero-trust
scorecard.

It is one static page. There is no build step, no framework, and
no server. The engine runs in the page, and nothing I type leaves
my browser unless I share it myself.

## How to open it

Open the file directly:

```text
canvas/index.html
```

Or serve the folder, which some browsers prefer for file work:

```bash
python3 -m http.server 8000
# then visit http://127.0.0.1:8000/canvas/
```

## What I can do here

- Build a spec by answering the questionnaire, section by section.
- Load the bundled support agent example (19 threats, score 6/100)
  or the hardened example (0 threats, score 100/100) and change
  answers to watch the model move.
- Copy the spec JSON the questionnaire builds, or paste a spec
  JSON in and load it.
- Export the threat model to markdown, as a download or copied
  to the clipboard. The markdown matches what the Python report
  writes, heading, scorecard table, threats table, and all.
- Share a link. The Share link button encodes the current spec
  as base64url JSON in the URL hash and copies the link. Whoever
  opens that link sees the same spec and the same threat model.
  The hash never reaches a server.

## How the port stays honest

`canvas/engine.js` is a plain JavaScript port of the Python
engine in `src/agent_threat_model/`: all 23 rules, the same
evidence strings, the same scorecard checks and weights, and the
same markdown format. It is not kept honest by good intentions.
`tests/test_canvas.py` runs the JavaScript engine in Node against
all 8 labeled cases in `benchmarks/cases.json` and checks that
the threat ids match exactly, plus the two bundled examples.
If the two engines ever drift, that test fails.

The spec honesty rule still applies here: the report is only as
honest and complete as the spec behind it. Unknown means absent.
