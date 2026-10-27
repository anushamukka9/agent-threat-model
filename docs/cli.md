# CLI

The CLI is a thin shell over the library, for pipelines and for
harnesses that are not Python.

```bash
agent-threat-model analyze spec.json                          # markdown report to stdout
agent-threat-model analyze spec.json --format json            # machine readable
agent-threat-model analyze spec.json --format text            # a compact summary
agent-threat-model analyze spec.json --fail-on critical       # only critical findings fail
agent-threat-model catalog                                    # the 23-rule catalog as a table
agent-threat-model example                                    # the bundled vulnerable spec, as JSON
agent-threat-model example --write spec.json                  # write it to a file instead
agent-threat-model validate spec.json                         # parse check with a short summary
```

Details that matter:

- `analyze` prints the full report to stdout in the format you
  ask for. Markdown is the default because it is the format a
  human reviews. JSON carries the same content for tooling.
- `--fail-on` sets the severity floor for a failing exit code:
  critical, high, medium, or low. The default is high. A run with
  only medium and low findings passes at the default and fails
  with `--fail-on medium`.
- `catalog` prints every rule with its severity and STRIDE
  category. The full text of each rule is in
  [threat-catalog.md](threat-catalog.md).
- `example` prints the bundled vulnerable support agent spec, the
  same spec as `examples/support_agent.json`. It is a starting
  point for writing your own, and a fixture for trying the tool.
- `validate` only parses. It prints an OK line with section counts
  when the spec is valid, and the spec error when it is not.
- Specs are plain JSON. Read them with `jq`, diff them with git,
  or load them with `Architecture.from_json_file`. The CLI is
  never the only way in.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. For analyze, no threat at or above the fail-on level. |
| 1 | A finding: analyze found a threat at or above the fail-on level. |
| 2 | Usage or input error: an unreadable file or an invalid spec. Nothing was analyzed. |

The 1 versus 2 split is deliberate. A CI step can treat 1 as "the
architecture has a problem to review" and 2 as "the pipeline is
wired wrong", and those should never look alike.
