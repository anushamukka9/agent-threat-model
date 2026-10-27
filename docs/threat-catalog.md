# Threat catalog

The full rule catalog, generated from the rules the engine actually
runs. Every rule is deterministic: the same spec always produces
the same threats. Evidence in a report quotes the spec values that
triggered the rule, so each finding can be checked by hand.

| ID | Severity | STRIDE | Rule |
|---|---|---|---|
| ATM-001 | high | Tampering | Prompt injection through unguarded untrusted input |
| ATM-002 | high | Tampering | Tool output or MCP input trusted implicitly |
| ATM-003 | high | Elevation of Privilege | Code execution without a sandbox |
| ATM-004 | high | Tampering | Write, delete, or payment actions without approval |
| ATM-005 | high | Elevation of Privilege | Broad long-lived credentials |
| ATM-006 | high | Information Disclosure | Credentials stored in a prompt or in code |
| ATM-007 | high | Information Disclosure | Sensitive data can leave through external outputs |
| ATM-008 | medium | Information Disclosure | Sensitive data can be exfiltrated through responses |
| ATM-009 | high | Tampering | Persistent memory written from untrusted input |
| ATM-010 | high | Information Disclosure | Persistent memory shared across users |
| ATM-011 | medium | Tampering | Unaudited MCP server in the tool surface |
| ATM-012 | critical | Spoofing | Network-exposed MCP server without authentication |
| ATM-013 | medium | Repudiation | No audit logging |
| ATM-014 | medium | Information Disclosure | Sensitive data can land in unredacted audit logs |
| ATM-015 | medium | Denial of Service | No kill switch |
| ATM-016 | medium | Denial of Service | No rate limits on costly or external actions |
| ATM-017 | medium | Spoofing | Multiple agents share one identity |
| ATM-018 | high | Elevation of Privilege | Subagents inherit credentials |
| ATM-019 | high | Elevation of Privilege | State-changing tools with no policy gate |
| ATM-020 | low | Information Disclosure | Attack surface is not inventoried |
| ATM-021 | high | Information Disclosure | Retrieved documents can carry sensitive data out |
| ATM-022 | high | Spoofing | Unauthenticated tool can write or reach a database |
| ATM-023 | critical | Elevation of Privilege | Unsandboxed code execution with broad credentials |

## ATM-001: Prompt injection through unguarded untrusted input

Severity: high. STRIDE: Tampering.

Untrusted input reaches the model with no input guard in front of it. Anyone who controls that input can steer the agent.

Mitigations:
- Put an input guard in front of untrusted sources
- Treat input as data, not orders

Companion tools: llm-sentinel (screens untrusted input before it reaches the model)

## ATM-002: Tool output or MCP input trusted implicitly

Severity: high. STRIDE: Tampering.

Output from a tool or an MCP server is marked trusted. That output is attacker-controlled in practice, so trusting it turns indirect injection and tool poisoning into direct instructions.

Mitigations:
- Mark tool and MCP output untrusted
- Screen it like any other untrusted input

Companion tools: llm-sentinel (screens untrusted input before it reaches the model), mcp-audit (audits MCP server surfaces, tools, and permissions)

## ATM-003: Code execution without a sandbox

Severity: high. STRIDE: Elevation of Privilege.

A tool can run code and is not sandboxed. Injected instructions stop being text and become commands on the host.

Mitigations:
- Run code execution in a sandbox with no ambient credentials
- Drop network by default

Companion tools: agent-policy-kit (enforces a policy gate on tool calls), agent-scopes (issues short-lived, narrowly scoped credentials)

## ATM-004: Write, delete, or payment actions without approval

Severity: high. STRIDE: Tampering.

A tool can write, delete, or pay, and neither the tool nor the global controls require human approval. One bad instruction changes real state.

Mitigations:
- Require approval for write, delete, and payment actions
- Split read and write tools

Companion tools: agent-policy-kit (enforces a policy gate on tool calls)

## ATM-005: Broad long-lived credentials

Severity: high. STRIDE: Elevation of Privilege.

The agent holds broad, long-lived credentials. Anything that steers the agent inherits that reach, for as long as the credential lives.

Mitigations:
- Move to scoped, short-lived credentials
- Narrow the scope to the task at hand

Companion tools: agent-scopes (issues short-lived, narrowly scoped credentials)

## ATM-006: Credentials stored in a prompt or in code

Severity: high. STRIDE: Information Disclosure.

Credentials in a prompt can be read back out of the model, and credentials in code travel with every copy of the repo.

Mitigations:
- Store credentials in a vault
- Inject them at call time, never into the prompt

Companion tools: agent-scopes (issues short-lived, narrowly scoped credentials)

## ATM-007: Sensitive data can leave through external outputs

Severity: high. STRIDE: Information Disclosure.

Confidential or personal data is in reach, the agent can send email or call external APIs, and outputs are not validated before they leave.

Mitigations:
- Validate outputs before external sends
- Redact sensitive fields at the boundary

Companion tools: output-contracts (validates outputs against a contract before release)

## ATM-008: Sensitive data can be exfiltrated through responses

Severity: medium. STRIDE: Information Disclosure.

Personal data or credentials are in reach and answers go straight to the user with no output validation, so a prompt can ask for them.

Mitigations:
- Validate and redact user-facing responses
- Keep credentials out of model context

Companion tools: output-contracts (validates outputs against a contract before release), llm-sentinel (screens untrusted input before it reaches the model)

## ATM-009: Persistent memory written from untrusted input

Severity: high. STRIDE: Tampering.

Long-term memory accepts writes that trace back to untrusted input. A poisoned note survives the session and steers later sessions.

Mitigations:
- Gate memory writes behind review or a guard
- Tag memory with its source

Companion tools: llm-sentinel (screens untrusted input before it reaches the model), agent-audit (keeps a tamper-evident record of agent actions)

## ATM-010: Persistent memory shared across users

Severity: high. STRIDE: Information Disclosure.

Persistent memory is shared across users, so one user's data can surface in another user's session.

Mitigations:
- Scope memory per user
- Partition shared knowledge from private memory

Companion tools: rag-canary (plants canaries in retrieval to catch exfiltration)

## ATM-011: Unaudited MCP server in the tool surface

Severity: medium. STRIDE: Tampering.

An MCP server is connected but has not been audited. Its tools, prompts, and updates are taken on faith.

Mitigations:
- Audit each MCP server before connecting it
- Pin versions and re-audit on change

Companion tools: mcp-audit (audits MCP server surfaces, tools, and permissions), ai-bom (inventories models, tools, MCP servers, and data)

## ATM-012: Network-exposed MCP server without authentication

Severity: critical. STRIDE: Spoofing.

An MCP server is reachable on the network and does not authenticate callers. Anyone who can reach it can use the agent's tools.

Mitigations:
- Require authentication on exposed servers
- Bind servers locally where possible

Companion tools: mcp-audit (audits MCP server surfaces, tools, and permissions)

## ATM-013: No audit logging

Severity: medium. STRIDE: Repudiation.

Actions are not logged, so after an incident nobody can show what the agent did, in what order, or why.

Mitigations:
- Log tool calls, inputs, and decisions
- Keep the log tamper-evident

Companion tools: agent-audit (keeps a tamper-evident record of agent actions)

## ATM-014: Sensitive data can land in unredacted audit logs

Severity: medium. STRIDE: Information Disclosure.

Logging is on, redaction is off, and sensitive data is in reach. The log becomes a second copy of the secrets it was meant to protect.

Mitigations:
- Redact secrets and personal data before writing logs
- Test redaction with fixtures

Companion tools: agent-audit (keeps a tamper-evident record of agent actions)

## ATM-015: No kill switch

Severity: medium. STRIDE: Denial of Service.

There is no way to stop the agent quickly. A looping or compromised agent keeps acting until someone pulls credentials by hand.

Mitigations:
- Add a kill switch that halts tool calls
- Rehearse using it

Companion tools: agent-policy-kit (enforces a policy gate on tool calls)

## ATM-016: No rate limits on costly or external actions

Severity: medium. STRIDE: Denial of Service.

The agent can call the network, spend money, or call external APIs with no rate limits, so a loop or an attacker can run up cost and abuse.

Mitigations:
- Rate limit tool calls and external outputs
- Cap spend per session

Companion tools: agent-policy-kit (enforces a policy gate on tool calls)

## ATM-017: Multiple agents share one identity

Severity: medium. STRIDE: Spoofing.

Several agents act under one identity, so actions cannot be attributed and one agent can be impersonated by another.

Mitigations:
- Give each agent its own identity
- Log which agent took each action

Companion tools: agent-audit (keeps a tamper-evident record of agent actions), agent-scopes (issues short-lived, narrowly scoped credentials)

## ATM-018: Subagents inherit credentials

Severity: high. STRIDE: Elevation of Privilege.

Subagents inherit the parent agent's credentials, so delegating a small task hands over the full reach of the parent.

Mitigations:
- Issue subagents their own scoped credentials
- Never pass parent credentials down

Companion tools: agent-scopes (issues short-lived, narrowly scoped credentials)

## ATM-019: State-changing tools with no policy gate

Severity: high. STRIDE: Elevation of Privilege.

Tools can change state or reach a database and no policy enforcement sits in front of them, so the model's say-so is the only check.

Mitigations:
- Put a policy gate in front of state-changing tools
- Default to deny

Companion tools: agent-policy-kit (enforces a policy gate on tool calls)

## ATM-020: Attack surface is not inventoried

Severity: low. STRIDE: Information Disclosure.

The components of this agent are not tracked in an inventory, so nobody can say what the attack surface actually is.

Mitigations:
- Inventory models, tools, servers, and data
- Refresh the inventory on change

Companion tools: ai-bom (inventories models, tools, MCP servers, and data)

## ATM-021: Retrieved documents can carry sensitive data out

Severity: high. STRIDE: Information Disclosure.

Documents are retrieved into context, sensitive data is among them, and outputs are not validated. A crafted document or question can walk that data out through the answer.

Mitigations:
- Validate outputs from retrieval-backed agents
- Watch retrieval with canaries

Companion tools: rag-canary (plants canaries in retrieval to catch exfiltration), output-contracts (validates outputs against a contract before release)

## ATM-022: Unauthenticated tool can write or reach a database

Severity: high. STRIDE: Spoofing.

A tool that can write or reach a database does not authenticate its caller, so anything that can reach the tool can change state as the agent.

Mitigations:
- Authenticate every state-changing tool
- Bind tools to the agent identity

Companion tools: agent-policy-kit (enforces a policy gate on tool calls), mcp-audit (audits MCP server surfaces, tools, and permissions)

## ATM-023: Unsandboxed code execution with broad credentials

Severity: critical. STRIDE: Elevation of Privilege.

Code runs without a sandbox while the agent holds broad, long-lived credentials. This is the worst combination in the catalog: injected instructions become host commands with lasting, wide access.

Mitigations:
- Sandbox code execution and strip ambient credentials
- Replace broad credentials with scoped, short-lived ones

Companion tools: agent-policy-kit (enforces a policy gate on tool calls), agent-scopes (issues short-lived, narrowly scoped credentials)
