# Spec format

A spec is one JSON object. Only `name` is required. Everything
else has a default, and the defaults are the cautious ones: a
section you leave out is treated as empty, off, or absent.

## The unknown-means-absent rule

If a control is not listed in the spec, the engine assumes it is
not there. Unknown means absent. That is fail-closed for a threat
model: a spec that forgets to mention its input guard gets the
prompt injection finding, which is the nudge to go and check. It
also means the quality of the report is bounded by the honesty and
completeness of the spec. See [limitations.md](limitations.md).

## Top level

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | string | required | The name of the agent app. |
| `description` | string | `""` | Free text. Not used by the rules. |
| `inputs` | list | `[]` | See Inputs. |
| `tools` | list | `[]` | See Tools. |
| `data` | list | `[]` | See Data. |
| `memory` | object or null | type `none` | See Memory. |
| `outputs` | list of strings | `[]` | See Outputs. |
| `credentials` | object or null | scope `none`, stored `none` | See Credentials. |
| `mcp_servers` | list | `[]` | See MCP servers. |
| `agents` | object or null | one agent | See Agents. |
| `controls` | object or null | all false | See Controls. |

## Inputs

Each entry: `source` (required) and `trusted` (bool, default
false).

Allowed `source` values: `user`, `web`, `documents`, `tool_output`,
`email`, `api`, `mcp_server`.

Mark an input trusted only when you control its content end to end.
Tool output and MCP output are essentially never trusted: marking
them trusted is itself a finding (ATM-002).

## Tools

Each entry: `name` (required string), `capabilities` (list,
default empty), `requires_approval` (bool, default false),
`sandboxed` (bool, default false), `authenticated` (bool, default
false).

Allowed `capabilities`: `read`, `write`, `delete`, `network`,
`code_exec`, `send_message`, `payment`, `database`, `file_access`.
Anything outside that list is rejected with a spec error.

## Data

Each entry: `name` (required string), `sensitivity` (default
`internal`), `encrypted` (bool, default false).

Allowed `sensitivity` values: `public`, `internal`, `confidential`,
`pii`, `credentials`.

## Memory

`type`: `none`, `session`, or `persistent` (default `none`).
`shared_across_users` (bool, default false).
`writes_from_untrusted_input` (bool, default false): true when
anything that traces back to an untrusted input can be written
into memory without review.

## Outputs

A list drawn from: `user`, `email`, `api_call`, `code_change`,
`payment`, `database_write`, `file_write`. Default empty.

## Credentials

`scope`: `none`, `scoped_short_lived`, `long_lived_narrow`, or
`long_lived_broad` (default `none`).
`stored_in`: `vault`, `env`, `prompt`, `code`, or `none` (default
`none`).

## MCP servers

Each entry: `name` (required string), `audited` (bool, default
false), `authenticated` (bool, default false), `network_exposed`
(bool, default false).

## Agents

`count` (integer, at least 1, default 1), `per_agent_identity`
(bool, default false), `subagents_inherit_credentials` (bool,
default false).

## Controls

All booleans, all default false:

- `input_guard`: untrusted input is screened before the model.
- `output_validation`: outputs are checked before they leave.
- `audit_logging`: actions are logged.
- `audit_log_redaction`: logs are redacted before writing.
- `policy_enforcement`: a policy gate sits in front of tool calls.
- `human_approval_for_writes`: writes need a human yes.
- `rate_limits`: tool calls and outputs are rate limited.
- `kill_switch`: the agent can be stopped quickly.
- `inventory_tracked`: the components are kept in an inventory.

## Errors

Bad input fails loudly with a `SpecError` that names the field:
an unknown enum value, a capability outside the allowed set, a
missing name, a boolean that is not a boolean. The CLI prints the
error and exits 2. Nothing is analyzed from a spec that does not
parse.
