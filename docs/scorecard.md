# Scorecard

The scorecard grades the architecture on five zero-trust
dimensions. Each dimension is a set of named checks over the spec,
each check with a weight. The dimension score is the weighted
share of checks that passed, from 0 to 100. The overall score is
the mean of the five dimensions, rounded.

Grades: 90-100 strong, 70-89 fair, 40-69 weak, 0-39 missing.

Every check is printed with the score, pass or fail, so the number
is never a mystery. A low score always names what is missing.

## inventory

Can you say what the agent is made of?

| Check | Weight |
|---|---|
| inventory is tracked | 40 |
| all MCP servers are audited | 30 |
| data holdings are declared | 15 |
| tools are declared | 15 |

## identity

Can you tell who, or what, is acting?

| Check | Weight |
|---|---|
| each agent has its own identity (or there is one agent) | 40 |
| all tools are authenticated | 30 |
| all MCP servers are authenticated | 30 |

## least_privilege

Is the agent's reach as small as the task allows?

| Check | Weight |
|---|---|
| credentials are scoped and short-lived (or none) | 30 |
| writes require approval | 25 |
| tools run sandboxed | 25 |
| policy enforcement is in place | 20 |

The sandboxing check passes when every declared tool is sandboxed.
With no tools there is nothing to sandbox, so it passes. The
approval check passes when the global human-approval control is on,
or when every write, delete, and payment tool requires approval
itself.

## audit

Could you reconstruct what happened?

| Check | Weight |
|---|---|
| audit logging is on | 50 |
| audit logs are redacted | 30 |
| actions can be attributed to an agent | 20 |

## kill_switch

Can you stop it, and limit the damage while you do?

The dimension is named for its headline check, but it grades
containment as a whole:

| Check | Weight |
|---|---|
| a kill switch exists | 50 |
| rate limits are in place | 25 |
| credentials can be revoked quickly (scoped or none) | 25 |

## What the scorecard does not grade

Input guarding and output validation drive several threat rules
but are not scorecard dimensions in this version. A spec can score
well here and still carry high-severity threats, and the research
agent in the benchmark cases does exactly that. Read the threats
and the scorecard together: the threats say what can go wrong, the
scorecard says how the foundations look.
