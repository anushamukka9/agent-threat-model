"use strict";

// A plain JavaScript port of the Python engine in
// src/agent_threat_model/. Same rules, same evidence strings, same
// scorecard, same markdown. Parity with the Python version is
// checked by tests/test_canvas.py against benchmarks/cases.json.
// Usable in the browser as window.AgentThreatModel and in Node via
// module.exports.

var SEVERITIES = ["critical", "high", "medium", "low"];
var SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
var STRIDE_CATEGORIES = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information Disclosure",
  "Denial of Service",
  "Elevation of Privilege"
];
var UNTRUSTED_SOURCES = ["web", "documents", "tool_output", "email", "user"];
var WRITE_CAPS = ["write", "delete", "payment", "database"];

var INPUT_SOURCES = ["user", "web", "documents", "tool_output", "email", "api", "mcp_server"];
var CAPABILITIES = [
  "read", "write", "delete", "network", "code_exec",
  "send_message", "payment", "database", "file_access"
];
var SENSITIVITIES = ["public", "internal", "confidential", "pii", "credentials"];
var MEMORY_TYPES = ["none", "session", "persistent"];
var OUTPUT_KINDS = [
  "user", "email", "api_call", "code_change", "payment", "database_write", "file_write"
];
var CREDENTIAL_SCOPES = ["none", "scoped_short_lived", "long_lived_narrow", "long_lived_broad"];
var CREDENTIAL_STORES = ["vault", "env", "prompt", "code", "none"];
var CONTROL_NAMES = [
  "input_guard", "output_validation", "audit_logging", "audit_log_redaction",
  "policy_enforcement", "human_approval_for_writes", "rate_limits",
  "kill_switch", "inventory_tracked"
];

function repr(value) {
  if (value === undefined || value === null) return "None";
  if (typeof value === "string") return "'" + value + "'";
  if (typeof value === "boolean") return value ? "True" : "False";
  return String(value);
}

function specError(message) {
  var err = new Error(message);
  err.name = "SpecError";
  return err;
}

function checkEnum(value, allowed, where) {
  if (typeof value !== "string" || allowed.indexOf(value) === -1) {
    throw specError(where + ": expected one of [" + allowed.map(function (v) {
      return "'" + v + "'";
    }).join(", ") + "], got " + repr(value));
  }
  return value;
}

function checkBool(value, where) {
  if (typeof value !== "boolean") {
    throw specError(where + ": expected a boolean, got " + repr(value));
  }
  return value;
}

function boolOr(value, fallback, where) {
  if (value === undefined) return fallback;
  return checkBool(value, where);
}

function requireDict(value, where) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw specError(where + ": expected an object, got " + (value === null ? "NoneType" : typeof value));
  }
  return value;
}

function requireList(value, where) {
  if (!Array.isArray(value)) {
    throw specError(where + ": expected a list, got " + typeof value);
  }
  return value;
}

function listOr(value, fallback, where) {
  if (value === undefined) return fallback;
  return requireList(value, where);
}

function normalizeInput(data, where) {
  data = requireDict(data, where);
  return {
    source: checkEnum(data.source, INPUT_SOURCES, where + ".source"),
    trusted: boolOr(data.trusted, false, where + ".trusted")
  };
}

function normalizeTool(data, where) {
  data = requireDict(data, where);
  if (typeof data.name !== "string" || !data.name) {
    throw specError(where + ".name: expected a non-empty string, got " + repr(data.name));
  }
  var capsRaw = listOr(data.capabilities, [], where + ".capabilities");
  var caps = capsRaw.map(function (c) {
    return checkEnum(c, CAPABILITIES, where + ".capabilities");
  });
  return {
    name: data.name,
    capabilities: caps,
    requires_approval: boolOr(data.requires_approval, false, where + ".requires_approval"),
    sandboxed: boolOr(data.sandboxed, false, where + ".sandboxed"),
    authenticated: boolOr(data.authenticated, false, where + ".authenticated")
  };
}

function normalizeDataItem(data, where) {
  data = requireDict(data, where);
  if (typeof data.name !== "string" || !data.name) {
    throw specError(where + ".name: expected a non-empty string, got " + repr(data.name));
  }
  return {
    name: data.name,
    sensitivity: checkEnum(
      data.sensitivity === undefined ? "internal" : data.sensitivity,
      SENSITIVITIES, where + ".sensitivity"
    ),
    encrypted: boolOr(data.encrypted, false, where + ".encrypted")
  };
}

function normalizeMemory(data) {
  if (data === undefined || data === null) {
    return { type: "none", shared_across_users: false, writes_from_untrusted_input: false };
  }
  data = requireDict(data, "memory");
  return {
    type: checkEnum(data.type === undefined ? "none" : data.type, MEMORY_TYPES, "memory.type"),
    shared_across_users: boolOr(data.shared_across_users, false, "memory.shared_across_users"),
    writes_from_untrusted_input: boolOr(
      data.writes_from_untrusted_input, false, "memory.writes_from_untrusted_input"
    )
  };
}

function normalizeCredentials(data) {
  if (data === undefined || data === null) {
    return { scope: "none", stored_in: "none" };
  }
  data = requireDict(data, "credentials");
  return {
    scope: checkEnum(
      data.scope === undefined ? "none" : data.scope, CREDENTIAL_SCOPES, "credentials.scope"
    ),
    stored_in: checkEnum(
      data.stored_in === undefined ? "none" : data.stored_in,
      CREDENTIAL_STORES, "credentials.stored_in"
    )
  };
}

function normalizeMcpServer(data, where) {
  data = requireDict(data, where);
  if (typeof data.name !== "string" || !data.name) {
    throw specError(where + ".name: expected a non-empty string, got " + repr(data.name));
  }
  return {
    name: data.name,
    audited: boolOr(data.audited, false, where + ".audited"),
    authenticated: boolOr(data.authenticated, false, where + ".authenticated"),
    network_exposed: boolOr(data.network_exposed, false, where + ".network_exposed")
  };
}

function normalizeAgents(data) {
  if (data === undefined || data === null) {
    return { count: 1, per_agent_identity: false, subagents_inherit_credentials: false };
  }
  data = requireDict(data, "agents");
  var count = data.count === undefined ? 1 : data.count;
  if (typeof count !== "number" || !Number.isInteger(count) || count < 1) {
    throw specError("agents.count: expected an integer >= 1, got " + repr(count));
  }
  return {
    count: count,
    per_agent_identity: boolOr(data.per_agent_identity, false, "agents.per_agent_identity"),
    subagents_inherit_credentials: boolOr(
      data.subagents_inherit_credentials, false, "agents.subagents_inherit_credentials"
    )
  };
}

function normalizeControls(data) {
  var out = {};
  CONTROL_NAMES.forEach(function (n) { out[n] = false; });
  if (data === undefined || data === null) return out;
  data = requireDict(data, "controls");
  CONTROL_NAMES.forEach(function (n) {
    out[n] = boolOr(data[n], false, "controls." + n);
  });
  return out;
}

// Spec normalization with the same defaults as models.py.
// Unknown means absent.
function normalizeSpec(data) {
  data = requireDict(data, "spec");
  if (typeof data.name !== "string" || !data.name) {
    throw specError("spec.name: expected a non-empty string, got " + repr(data.name));
  }
  var description = data.description === undefined ? "" : data.description;
  if (typeof description !== "string") {
    throw specError("spec.description: expected a string, got " + repr(description));
  }
  var outputsRaw = listOr(data.outputs, [], "spec.outputs");
  var outputs = outputsRaw.map(function (o) {
    return checkEnum(o, OUTPUT_KINDS, "spec.outputs");
  });
  return {
    name: data.name,
    description: description,
    inputs: listOr(data.inputs, [], "spec.inputs").map(function (item, i) {
      return normalizeInput(item, "inputs[" + i + "]");
    }),
    tools: listOr(data.tools, [], "spec.tools").map(function (item, i) {
      return normalizeTool(item, "tools[" + i + "]");
    }),
    data: listOr(data.data, [], "spec.data").map(function (item, i) {
      return normalizeDataItem(item, "data[" + i + "]");
    }),
    memory: normalizeMemory(data.memory),
    outputs: outputs,
    credentials: normalizeCredentials(data.credentials),
    mcp_servers: listOr(data.mcp_servers, [], "spec.mcp_servers").map(function (item, i) {
      return normalizeMcpServer(item, "mcp_servers[" + i + "]");
    }),
    agents: normalizeAgents(data.agents),
    controls: normalizeControls(data.controls)
  };
}

function toolHas(tool) {
  var caps = Array.prototype.slice.call(arguments, 1);
  return caps.some(function (c) { return tool.capabilities.indexOf(c) !== -1; });
}

function toolsWith(a) {
  var caps = Array.prototype.slice.call(arguments, 1);
  return a.tools.filter(function (t) {
    return caps.some(function (c) { return t.capabilities.indexOf(c) !== -1; });
  });
}

function sensitiveData(a, levels) {
  levels = levels || ["pii", "credentials"];
  return a.data.filter(function (d) { return levels.indexOf(d.sensitivity) !== -1; });
}

function names(items) {
  return items.map(function (i) { return i.name; }).join(", ");
}

function sortedUnique(values) {
  return Array.from(new Set(values)).sort();
}

function companion(repo, helps) { return { repo: repo, helps: helps }; }
function llm() { return companion("llm-sentinel", "screens untrusted input before it reaches the model"); }
function mcp() { return companion("mcp-audit", "audits MCP server surfaces, tools, and permissions"); }
function rag() { return companion("rag-canary", "plants canaries in retrieval to catch exfiltration"); }
function policy() { return companion("agent-policy-kit", "enforces a policy gate on tool calls"); }
function auditC() { return companion("agent-audit", "keeps a tamper-evident record of agent actions"); }
function contracts() { return companion("output-contracts", "validates outputs against a contract before release"); }
function scopes() { return companion("agent-scopes", "issues short-lived, narrowly scoped credentials"); }
function bom() { return companion("ai-bom", "inventories models, tools, MCP servers, and data"); }

function c001(a) {
  var bad = a.inputs.filter(function (i) {
    return UNTRUSTED_SOURCES.indexOf(i.source) !== -1 && !i.trusted;
  });
  if (bad.length && !a.controls.input_guard) {
    var srcs = sortedUnique(bad.map(function (i) { return i.source; })).join(", ");
    return "untrusted inputs (" + srcs + ") with controls.input_guard=false";
  }
  return null;
}
function c002(a) {
  var bad = a.inputs.filter(function (i) {
    return (i.source === "tool_output" || i.source === "mcp_server") && i.trusted;
  });
  if (bad.length) {
    var srcs = sortedUnique(bad.map(function (i) { return i.source; })).join(", ");
    return "inputs from " + srcs + " are marked trusted=true";
  }
  return null;
}
function c003(a) {
  var bad = toolsWith(a, "code_exec").filter(function (t) { return !t.sandboxed; });
  if (bad.length) return "code_exec tools not sandboxed: " + names(bad);
  return null;
}
function c004(a) {
  if (a.controls.human_approval_for_writes) return null;
  var bad = a.tools.filter(function (t) {
    return toolHas(t, "write", "delete", "payment") && !t.requires_approval;
  });
  if (bad.length) {
    return "tools with write/delete/payment and requires_approval=false: " + names(bad) +
      "; controls.human_approval_for_writes=false";
  }
  return null;
}
function c005(a) {
  if (a.credentials.scope === "long_lived_broad") return "credentials.scope=long_lived_broad";
  return null;
}
function c006(a) {
  if (a.credentials.stored_in === "prompt" || a.credentials.stored_in === "code") {
    return "credentials.stored_in=" + a.credentials.stored_in;
  }
  return null;
}
function c007(a) {
  var data = a.data.filter(function (d) {
    return d.sensitivity === "pii" || d.sensitivity === "confidential";
  });
  var ext = a.outputs.filter(function (o) { return o === "email" || o === "api_call"; });
  if (data.length && ext.length && !a.controls.output_validation) {
    return "data (" + names(data) + ") with outputs (" + ext.join(", ") +
      ") and controls.output_validation=false";
  }
  return null;
}
function c008(a) {
  var data = sensitiveData(a, ["pii", "credentials"]);
  if (data.length && a.outputs.indexOf("user") !== -1 && !a.controls.output_validation) {
    return "sensitive data (" + names(data) +
      ") with outputs including user and controls.output_validation=false";
  }
  return null;
}
function c009(a) {
  if (a.memory.type === "persistent" && a.memory.writes_from_untrusted_input) {
    return "memory.type=persistent and memory.writes_from_untrusted_input=true";
  }
  return null;
}
function c010(a) {
  if (a.memory.type === "persistent" && a.memory.shared_across_users) {
    return "memory.type=persistent and memory.shared_across_users=true";
  }
  return null;
}
function c011(a) {
  var bad = a.mcp_servers.filter(function (s) { return !s.audited; });
  if (bad.length) return "MCP servers with audited=false: " + names(bad);
  return null;
}
function c012(a) {
  var bad = a.mcp_servers.filter(function (s) { return s.network_exposed && !s.authenticated; });
  if (bad.length) {
    return "MCP servers network_exposed=true and authenticated=false: " + names(bad);
  }
  return null;
}
function c013(a) {
  if (!a.controls.audit_logging) return "controls.audit_logging=false";
  return null;
}
function c014(a) {
  var data = a.data.filter(function (d) {
    return ["pii", "confidential", "credentials"].indexOf(d.sensitivity) !== -1;
  });
  if (a.controls.audit_logging && !a.controls.audit_log_redaction && data.length) {
    return "controls.audit_logging=true, controls.audit_log_redaction=false, " +
      "sensitive data present (" + names(data) + ")";
  }
  return null;
}
function c015(a) {
  if (!a.controls.kill_switch) return "controls.kill_switch=false";
  return null;
}
function c016(a) {
  var reasons = [];
  var net = toolsWith(a, "network");
  if (net.length) reasons.push("network tools: " + names(net));
  var pay = toolsWith(a, "payment");
  if (pay.length) reasons.push("payment tools: " + names(pay));
  if (a.outputs.indexOf("api_call") !== -1) reasons.push("outputs include api_call");
  if (reasons.length && !a.controls.rate_limits) {
    return "controls.rate_limits=false and " + reasons.join("; ");
  }
  return null;
}
function c017(a) {
  if (a.agents.count > 1 && !a.agents.per_agent_identity) {
    return "agents.count=" + a.agents.count + " and agents.per_agent_identity=false";
  }
  return null;
}
function c018(a) {
  if (a.agents.subagents_inherit_credentials) {
    return "agents.subagents_inherit_credentials=true";
  }
  return null;
}
function c019(a) {
  var bad = toolsWith.apply(null, [a].concat(WRITE_CAPS));
  if (bad.length && !a.controls.policy_enforcement) {
    return "tools with write/delete/payment/database (" + names(bad) +
      ") and controls.policy_enforcement=false";
  }
  return null;
}
function c020(a) {
  if (!a.controls.inventory_tracked) return "controls.inventory_tracked=false";
  return null;
}
function c021(a) {
  var hasDocs = a.inputs.some(function (i) { return i.source === "documents"; });
  var data = a.data.filter(function (d) {
    return d.sensitivity === "confidential" || d.sensitivity === "pii";
  });
  if (hasDocs && data.length && !a.controls.output_validation) {
    return "documents input with sensitive data (" + names(data) +
      ") and controls.output_validation=false";
  }
  return null;
}
function c022(a) {
  var bad = a.tools.filter(function (t) {
    return !t.authenticated && toolHas(t, "write", "database");
  });
  if (bad.length) {
    return "tools with authenticated=false and write/database capability: " + names(bad);
  }
  return null;
}
function c023(a) {
  var bad = toolsWith(a, "code_exec").filter(function (t) { return !t.sandboxed; });
  if (bad.length && a.credentials.scope === "long_lived_broad") {
    return "code_exec tools not sandboxed (" + names(bad) +
      ") combined with credentials.scope=long_lived_broad";
  }
  return null;
}

var RULES = [
  {
    id: "ATM-001",
    title: "Prompt injection through unguarded untrusted input",
    stride: "Tampering",
    severity: "high",
    description: "Untrusted input reaches the model with no input guard in front of it. Anyone who controls that input can steer the agent.",
    mitigations: ["Put an input guard in front of untrusted sources", "Treat input as data, not orders"],
    companions: [llm()],
    check: c001
  },
  {
    id: "ATM-002",
    title: "Tool output or MCP input trusted implicitly",
    stride: "Tampering",
    severity: "high",
    description: "Output from a tool or an MCP server is marked trusted. That output is attacker-controlled in practice, so trusting it turns indirect injection and tool poisoning into direct instructions.",
    mitigations: ["Mark tool and MCP output untrusted", "Screen it like any other untrusted input"],
    companions: [llm(), mcp()],
    check: c002
  },
  {
    id: "ATM-003",
    title: "Code execution without a sandbox",
    stride: "Elevation of Privilege",
    severity: "high",
    description: "A tool can run code and is not sandboxed. Injected instructions stop being text and become commands on the host.",
    mitigations: ["Run code execution in a sandbox with no ambient credentials", "Drop network by default"],
    companions: [policy(), scopes()],
    check: c003
  },
  {
    id: "ATM-004",
    title: "Write, delete, or payment actions without approval",
    stride: "Tampering",
    severity: "high",
    description: "A tool can write, delete, or pay, and neither the tool nor the global controls require human approval. One bad instruction changes real state.",
    mitigations: ["Require approval for write, delete, and payment actions", "Split read and write tools"],
    companions: [policy()],
    check: c004
  },
  {
    id: "ATM-005",
    title: "Broad long-lived credentials",
    stride: "Elevation of Privilege",
    severity: "high",
    description: "The agent holds broad, long-lived credentials. Anything that steers the agent inherits that reach, for as long as the credential lives.",
    mitigations: ["Move to scoped, short-lived credentials", "Narrow the scope to the task at hand"],
    companions: [scopes()],
    check: c005
  },
  {
    id: "ATM-006",
    title: "Credentials stored in a prompt or in code",
    stride: "Information Disclosure",
    severity: "high",
    description: "Credentials in a prompt can be read back out of the model, and credentials in code travel with every copy of the repo.",
    mitigations: ["Store credentials in a vault", "Inject them at call time, never into the prompt"],
    companions: [scopes()],
    check: c006
  },
  {
    id: "ATM-007",
    title: "Sensitive data can leave through external outputs",
    stride: "Information Disclosure",
    severity: "high",
    description: "Confidential or personal data is in reach, the agent can send email or call external APIs, and outputs are not validated before they leave.",
    mitigations: ["Validate outputs before external sends", "Redact sensitive fields at the boundary"],
    companions: [contracts()],
    check: c007
  },
  {
    id: "ATM-008",
    title: "Sensitive data can be exfiltrated through responses",
    stride: "Information Disclosure",
    severity: "medium",
    description: "Personal data or credentials are in reach and answers go straight to the user with no output validation, so a prompt can ask for them.",
    mitigations: ["Validate and redact user-facing responses", "Keep credentials out of model context"],
    companions: [contracts(), llm()],
    check: c008
  },
  {
    id: "ATM-009",
    title: "Persistent memory written from untrusted input",
    stride: "Tampering",
    severity: "high",
    description: "Long-term memory accepts writes that trace back to untrusted input. A poisoned note survives the session and steers later sessions.",
    mitigations: ["Gate memory writes behind review or a guard", "Tag memory with its source"],
    companions: [llm(), auditC()],
    check: c009
  },
  {
    id: "ATM-010",
    title: "Persistent memory shared across users",
    stride: "Information Disclosure",
    severity: "high",
    description: "Persistent memory is shared across users, so one user's data can surface in another user's session.",
    mitigations: ["Scope memory per user", "Partition shared knowledge from private memory"],
    companions: [rag()],
    check: c010
  },
  {
    id: "ATM-011",
    title: "Unaudited MCP server in the tool surface",
    stride: "Tampering",
    severity: "medium",
    description: "An MCP server is connected but has not been audited. Its tools, prompts, and updates are taken on faith.",
    mitigations: ["Audit each MCP server before connecting it", "Pin versions and re-audit on change"],
    companions: [mcp(), bom()],
    check: c011
  },
  {
    id: "ATM-012",
    title: "Network-exposed MCP server without authentication",
    stride: "Spoofing",
    severity: "critical",
    description: "An MCP server is reachable on the network and does not authenticate callers. Anyone who can reach it can use the agent's tools.",
    mitigations: ["Require authentication on exposed servers", "Bind servers locally where possible"],
    companions: [mcp()],
    check: c012
  },
  {
    id: "ATM-013",
    title: "No audit logging",
    stride: "Repudiation",
    severity: "medium",
    description: "Actions are not logged, so after an incident nobody can show what the agent did, in what order, or why.",
    mitigations: ["Log tool calls, inputs, and decisions", "Keep the log tamper-evident"],
    companions: [auditC()],
    check: c013
  },
  {
    id: "ATM-014",
    title: "Sensitive data can land in unredacted audit logs",
    stride: "Information Disclosure",
    severity: "medium",
    description: "Logging is on, redaction is off, and sensitive data is in reach. The log becomes a second copy of the secrets it was meant to protect.",
    mitigations: ["Redact secrets and personal data before writing logs", "Test redaction with fixtures"],
    companions: [auditC()],
    check: c014
  },
  {
    id: "ATM-015",
    title: "No kill switch",
    stride: "Denial of Service",
    severity: "medium",
    description: "There is no way to stop the agent quickly. A looping or compromised agent keeps acting until someone pulls credentials by hand.",
    mitigations: ["Add a kill switch that halts tool calls", "Rehearse using it"],
    companions: [policy()],
    check: c015
  },
  {
    id: "ATM-016",
    title: "No rate limits on costly or external actions",
    stride: "Denial of Service",
    severity: "medium",
    description: "The agent can call the network, spend money, or call external APIs with no rate limits, so a loop or an attacker can run up cost and abuse.",
    mitigations: ["Rate limit tool calls and external outputs", "Cap spend per session"],
    companions: [policy()],
    check: c016
  },
  {
    id: "ATM-017",
    title: "Multiple agents share one identity",
    stride: "Spoofing",
    severity: "medium",
    description: "Several agents act under one identity, so actions cannot be attributed and one agent can be impersonated by another.",
    mitigations: ["Give each agent its own identity", "Log which agent took each action"],
    companions: [auditC(), scopes()],
    check: c017
  },
  {
    id: "ATM-018",
    title: "Subagents inherit credentials",
    stride: "Elevation of Privilege",
    severity: "high",
    description: "Subagents inherit the parent agent's credentials, so delegating a small task hands over the full reach of the parent.",
    mitigations: ["Issue subagents their own scoped credentials", "Never pass parent credentials down"],
    companions: [scopes()],
    check: c018
  },
  {
    id: "ATM-019",
    title: "State-changing tools with no policy gate",
    stride: "Elevation of Privilege",
    severity: "high",
    description: "Tools can change state or reach a database and no policy enforcement sits in front of them, so the model's say-so is the only check.",
    mitigations: ["Put a policy gate in front of state-changing tools", "Default to deny"],
    companions: [policy()],
    check: c019
  },
  {
    id: "ATM-020",
    title: "Attack surface is not inventoried",
    stride: "Information Disclosure",
    severity: "low",
    description: "The components of this agent are not tracked in an inventory, so nobody can say what the attack surface actually is.",
    mitigations: ["Inventory models, tools, servers, and data", "Refresh the inventory on change"],
    companions: [bom()],
    check: c020
  },
  {
    id: "ATM-021",
    title: "Retrieved documents can carry sensitive data out",
    stride: "Information Disclosure",
    severity: "high",
    description: "Documents are retrieved into context, sensitive data is among them, and outputs are not validated. A crafted document or question can walk that data out through the answer.",
    mitigations: ["Validate outputs from retrieval-backed agents", "Watch retrieval with canaries"],
    companions: [rag(), contracts()],
    check: c021
  },
  {
    id: "ATM-022",
    title: "Unauthenticated tool can write or reach a database",
    stride: "Spoofing",
    severity: "high",
    description: "A tool that can write or reach a database does not authenticate its caller, so anything that can reach the tool can change state as the agent.",
    mitigations: ["Authenticate every state-changing tool", "Bind tools to the agent identity"],
    companions: [policy(), mcp()],
    check: c022
  },
  {
    id: "ATM-023",
    title: "Unsandboxed code execution with broad credentials",
    stride: "Elevation of Privilege",
    severity: "critical",
    description: "Code runs without a sandbox while the agent holds broad, long-lived credentials. This is the worst combination in the catalog: injected instructions become host commands with lasting, wide access.",
    mitigations: [
      "Sandbox code execution and strip ambient credentials",
      "Replace broad credentials with scoped, short-lived ones"
    ],
    companions: [policy(), scopes()],
    check: c023
  }
];

function analyze(input) {
  var a = normalizeSpec(input);
  var threats = [];
  RULES.forEach(function (rule) {
    var evidence = rule.check(a);
    if (evidence !== null && evidence !== undefined) {
      threats.push({
        id: rule.id,
        title: rule.title,
        stride: rule.stride,
        severity: rule.severity,
        description: rule.description,
        evidence: evidence,
        mitigations: rule.mitigations.slice(),
        companions: rule.companions.map(function (c) {
          return { repo: c.repo, helps: c.helps };
        })
      });
    }
  });
  return threats;
}

// Python round uses round half to even. Match it so scores agree.
function pyRound(x) {
  var f = Math.floor(x);
  var diff = x - f;
  if (diff < 0.5) return f;
  if (diff > 0.5) return f + 1;
  return f % 2 === 0 ? f : f + 1;
}

function gradeFor(score) {
  if (score >= 90) return "strong";
  if (score >= 70) return "fair";
  if (score >= 40) return "weak";
  return "missing";
}

function scoreDimension(name, checks) {
  var total = checks.reduce(function (s, c) { return s + c.weight; }, 0);
  var passed = checks.reduce(function (s, c) { return s + (c.passed ? c.weight : 0); }, 0);
  var score = total ? pyRound(100 * passed / total) : 0;
  return { name: name, score: score, grade: gradeFor(score), checks: checks };
}

function scoreArchitecture(input) {
  var a = normalizeSpec(input);
  var scoped = a.credentials.scope === "none" || a.credentials.scope === "scoped_short_lived";
  var perAgent = a.agents.per_agent_identity || a.agents.count <= 1;
  var toolsAuth = a.tools.every(function (t) { return t.authenticated; });
  var mcpAuth = a.mcp_servers.every(function (s) { return s.authenticated; });
  var mcpAudited = a.mcp_servers.every(function (s) { return s.audited; });
  var approval = a.controls.human_approval_for_writes || a.tools.filter(function (t) {
    return toolHas(t, "write", "delete", "payment");
  }).every(function (t) { return t.requires_approval; });
  var sandboxed = a.tools.length ? a.tools.every(function (t) { return t.sandboxed; }) : true;

  var inventory = scoreDimension("inventory", [
    { label: "inventory is tracked", passed: a.controls.inventory_tracked, weight: 40 },
    { label: "all MCP servers are audited", passed: mcpAudited, weight: 30 },
    { label: "data holdings are declared", passed: a.data.length > 0, weight: 15 },
    { label: "tools are declared", passed: a.tools.length > 0, weight: 15 }
  ]);
  var identity = scoreDimension("identity", [
    { label: "each agent has its own identity (or there is one agent)", passed: perAgent, weight: 40 },
    { label: "all tools are authenticated", passed: toolsAuth, weight: 30 },
    { label: "all MCP servers are authenticated", passed: mcpAuth, weight: 30 }
  ]);
  var least = scoreDimension("least_privilege", [
    { label: "credentials are scoped and short-lived (or none)", passed: scoped, weight: 30 },
    { label: "writes require approval", passed: Boolean(approval), weight: 25 },
    { label: "tools run sandboxed", passed: sandboxed, weight: 25 },
    { label: "policy enforcement is in place", passed: a.controls.policy_enforcement, weight: 20 }
  ]);
  var auditDim = scoreDimension("audit", [
    { label: "audit logging is on", passed: a.controls.audit_logging, weight: 50 },
    { label: "audit logs are redacted", passed: a.controls.audit_log_redaction, weight: 30 },
    { label: "actions can be attributed to an agent", passed: perAgent, weight: 20 }
  ]);
  var kill = scoreDimension("kill_switch", [
    { label: "a kill switch exists", passed: a.controls.kill_switch, weight: 50 },
    { label: "rate limits are in place", passed: a.controls.rate_limits, weight: 25 },
    { label: "credentials can be revoked quickly (scoped or none)", passed: scoped, weight: 25 }
  ]);
  var dims = [inventory, identity, least, auditDim, kill];
  var overall = dims.length ? pyRound(dims.reduce(function (s, d) {
    return s + d.score;
  }, 0) / dims.length) : 0;
  return { dimensions: dims, overall: overall };
}

function countsBySeverity(threats) {
  var counts = { critical: 0, high: 0, medium: 0, low: 0 };
  threats.forEach(function (t) { counts[t.severity] += 1; });
  return counts;
}

function countsByStride(threats) {
  var counts = {};
  threats.forEach(function (t) { counts[t.stride] = (counts[t.stride] || 0) + 1; });
  return counts;
}

function summaryLineFor(threats, scorecard) {
  var c = countsBySeverity(threats);
  return threats.length + " threats: " + c.critical + " critical, " + c.high + " high, " +
    c.medium + " medium, " + c.low + " low; overall score " + scorecard.overall + "/100";
}

function modelToMarkdown(model) {
  var lines = [
    "# Threat model: " + model.architecture_name,
    "",
    model.summaryLine(),
    "",
    "## Scorecard",
    "",
    "| Dimension | Score | Grade |",
    "|---|---|---|"
  ];
  model.scorecard.dimensions.forEach(function (d) {
    lines.push("| " + d.name + " | " + d.score + "/100 | " + d.grade + " |");
  });
  lines.push("| **overall** | **" + model.scorecard.overall + "/100** |  |");
  lines.push("", "## Threats", "");
  if (!model.threats.length) {
    lines.push("No threats found for this spec.");
    lines.push("");
    return lines.join("\n");
  }
  lines.push("| ID | Severity | STRIDE | Threat | Evidence |");
  lines.push("|---|---|---|---|---|");
  model.threats.forEach(function (t) {
    lines.push("| " + t.id + " | " + t.severity + " | " + t.stride + " | " +
      t.title + " | " + t.evidence + " |");
  });
  model.threats.forEach(function (t) {
    lines.push("", "### " + t.id + ": " + t.title, "");
    lines.push("Severity: " + t.severity + ". STRIDE: " + t.stride + ".");
    lines.push("");
    lines.push(t.description);
    lines.push("");
    lines.push("Evidence: " + t.evidence);
    lines.push("");
    lines.push("Mitigations:");
    t.mitigations.forEach(function (m) { lines.push("- " + m); });
    if (t.companions.length) {
      lines.push("");
      lines.push("Companion tools:");
      t.companions.forEach(function (c) { lines.push("- " + c.repo + ": " + c.helps); });
    }
  });
  lines.push("");
  return lines.join("\n");
}

function buildThreatModel(input) {
  var a = normalizeSpec(input);
  var threats = analyze(a);
  threats.sort(function (x, y) {
    var r = SEVERITY_RANK[x.severity] - SEVERITY_RANK[y.severity];
    if (r !== 0) return r;
    return x.id < y.id ? -1 : (x.id > y.id ? 1 : 0);
  });
  var scorecard = scoreArchitecture(a);
  var model = {
    architecture_name: a.name,
    architectureName: a.name,
    architecture: a.name,
    spec: a,
    threats: threats,
    scorecard: scorecard
  };
  model.countsBySeverity = function () { return countsBySeverity(threats); };
  model.counts_by_severity = model.countsBySeverity;
  model.countsByStride = function () { return countsByStride(threats); };
  model.counts_by_stride = model.countsByStride;
  model.summaryLine = function () { return summaryLineFor(threats, scorecard); };
  model.summary_line = model.summaryLine;
  model.toMarkdown = function () { return modelToMarkdown(model); };
  model.to_markdown = model.toMarkdown;
  model.toDict = function () {
    return {
      architecture: a.name,
      summary: model.summaryLine(),
      counts_by_severity: model.countsBySeverity(),
      counts_by_stride: model.countsByStride(),
      scorecard: {
        overall: scorecard.overall,
        dimensions: scorecard.dimensions
      },
      threats: threats
    };
  };
  model.to_dict = model.toDict;
  return model;
}

function toMarkdown(input) {
  if (input && typeof input === "object" && Array.isArray(input.threats) &&
      input.scorecard && typeof input.summaryLine === "function") {
    return modelToMarkdown(input);
  }
  return buildThreatModel(input).toMarkdown();
}

function summaryLine(input) {
  if (input && typeof input === "object" && typeof input.summaryLine === "function") {
    return input.summaryLine();
  }
  return buildThreatModel(input).summaryLine();
}

var api = {
  SEVERITIES: SEVERITIES,
  SEVERITY_RANK: SEVERITY_RANK,
  STRIDE_CATEGORIES: STRIDE_CATEGORIES,
  INPUT_SOURCES: INPUT_SOURCES,
  CAPABILITIES: CAPABILITIES,
  SENSITIVITIES: SENSITIVITIES,
  MEMORY_TYPES: MEMORY_TYPES,
  OUTPUT_KINDS: OUTPUT_KINDS,
  CREDENTIAL_SCOPES: CREDENTIAL_SCOPES,
  CREDENTIAL_STORES: CREDENTIAL_STORES,
  RULES: RULES,
  normalizeSpec: normalizeSpec,
  parseSpec: normalizeSpec,
  fromDict: normalizeSpec,
  architectureFromDict: normalizeSpec,
  analyze: analyze,
  scoreArchitecture: scoreArchitecture,
  score_architecture: scoreArchitecture,
  gradeFor: gradeFor,
  grade_for: gradeFor,
  buildThreatModel: buildThreatModel,
  build_threat_model: buildThreatModel,
  toMarkdown: toMarkdown,
  summaryLine: summaryLine
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = api;
}
if (typeof window !== "undefined") {
  window.AgentThreatModel = api;
}
