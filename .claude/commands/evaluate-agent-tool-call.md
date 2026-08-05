---
description: Evaluate a claimed agent identity's least-privilege eligibility for a proposed tool call, on top of the deterministic Block 8 runtime policy engine, without authenticating anyone or executing anything
argument-hint: "[agent-id] [tool-name] [json-arguments]"
---

# ThreatTrace Evaluate Agent Tool Call Workflow

Invocation: `/evaluate-agent-tool-call <agent-id> <tool-name> <json-arguments>` — exactly one agent-ID token, followed by exactly one tool-name token, followed by exactly one JSON argument object. This command never accepts a JSON envelope, a fourth positional argument, or any caller-supplied role, capability, authentication, decision, or execution field.

`/evaluate-agent-tool-call` is Block 9's Agent Identity and Least-Privilege boundary: it answers *does this specific claimed agent identity have the least-privilege capability to even make this proposed tool call at all?* by consulting the existing, already-committed, deterministic policy engine (`core.agent_identity_policy.evaluate_agent_tool_call`, via `core.agent_identity_policy_cli`) — and nothing else. That engine itself reuses Block 8's own `core.agent_gateway.evaluate_tool_call` unchanged, layering a fixed agent registry, role, and least-privilege capability check on top of it. This command is strictly read-only and strictly advisory:

Claimed agent ID + tool name + arguments → command-level shape validation → pinned UTC evaluation timestamp → `core.agent_identity_policy_cli` → deterministic `allow` / `require_approval` / `deny` identity-aware report

`/evaluate-agent-tool-call` never authenticates or verifies the caller, never executes the tool it evaluates, never calls Supabase or MCP, never executes SQL, never invokes Hayabusa, never creates or consumes an approval, never creates a session, never mutates an investigation, and never applies a migration. It never decides agent registration, agent enablement, role assignment, capability assignment, tool registration, tool enablement, operation class, argument policy, or the final decision itself — every one of those belongs entirely to `core.agent_identity_policy`, reached only through `core.agent_identity_policy_cli`, never reimplemented in this document.

An identity policy report is a **decision about a proposed call by a claimed identity**, never proof of who made it and never proof that anything ran. `allow` means the claimed agent's role and capabilities currently permit the call and it *may* proceed to a wholly separate execution boundary this command never crosses. `require_approval` means the call needs the existing, separate Block 6 approval workflow first — this command never creates that approval itself. `deny` means the call is refused — this command never retries it, substitutes a different agent, aliases it, or falls back to executing it a different way. All three are equally valid, successful evaluation outcomes.

## Claimed Identity Boundary

`agent_id` is a **caller-supplied claimed identifier**, nothing more. It is never authenticated, never verified, never cryptographically proven, and never derived from Supabase Auth, a token, a certificate, or any other identity provider. This command performs no login, no token validation, no session validation, no certificate validation, no cryptographic verification, and no identity-provider lookup of any kind.

`canonical_agent_id` in the output means only that the claimed string the caller typed matched a fixed, in-code registry entry exactly, case-sensitively, after trimming whitespace — nothing more. A match is not authentication. `identity_authenticated` is always `false` in every report this command can ever display, regardless of `final_decision`.

This command must never describe a claimed agent, a registry match, or a resulting report as **authenticated**, **verified**, **trusted**, **proven**, or **securely identified**. Every reference to the claimed agent is labeled explicitly as claimed.

Every successful report ends with a statement equivalent to: **"No agent was authenticated, and no tool, approval workflow, database operation, or external process was executed."**

## Evaluation Input

$ARGUMENTS

## Stage 0 — Command-Level Input Shape Validation

`$ARGUMENTS` must contain exactly three things, in order: a non-empty agent-ID token, a non-empty tool-name token, and exactly one JSON object. Perform every check below, in order, before Stage 1 — before any timestamp is pinned and before any CLI invocation:

1. Trim `$ARGUMENTS` of surrounding whitespace. Reject a blank result (nothing supplied at all).
2. Split at the first whitespace character. The text before it is the **candidate agent ID**. Reject when there is no whitespace at all (an agent ID with no tool name or JSON argument object supplied).
3. Reject a blank candidate agent ID.
4. The text after the first whitespace, trimmed of leading whitespace, is split again at the next whitespace character. The text before this second split is the **candidate tool name**. Reject when there is no further whitespace at all (an agent ID and tool name with no JSON argument object supplied).
5. Reject a blank candidate tool name.
6. The text after the second whitespace, trimmed of leading whitespace, is the **candidate argument text**. Parse it as exactly one JSON value.
7. Reject malformed JSON.
8. Reject trailing non-whitespace content after the one parsed JSON value.
9. Reject a top-level value that is not a JSON object — a top-level array, string, number, boolean, or `null` is never accepted as `arguments`.

This command performs **no local agent-ID check, tool-name check, or argument-content check of any kind** beyond this pure shape validation. It does not decide, at this or any other stage, whether the claimed agent is known, whether it is enabled, which role it has, which capabilities it has, whether the named tool is known, whether it is enabled, what its operation class is, whether the tool is within the claimed agent's allowlist, whether a mutation request is permitted, whether its arguments are individually valid, or what the final decision should be — every one of those is always decided later, entirely by `core.agent_identity_policy.evaluate_agent_tool_call`, reached only through `core.agent_identity_policy_cli`. The candidate agent ID and candidate tool name are never lowercased, casefolded, aliased, fuzzy-matched, rewritten, sanitized, repaired, or substituted, and the candidate arguments object's own field names and values are never transformed, stripped, or repaired — including when a field name happens to look like one of the engine's own reserved policy/control names (`decision`, `role`, `capabilities`, and so on): such a field is passed to the engine completely unchanged, exactly as supplied, so that the engine itself can produce its own deterministic denial from real, trusted input, never from a command-layer guess.

Call the three validated values the **candidate agent ID**, the **candidate tool name**, and the **candidate arguments object**.

## Python Launcher Selection

Use the existing project convention for selecting a Python launcher:

1. Try `py`.
2. Otherwise try `python3`.
3. Otherwise use a `python` executable only after confirming it resolves to Python 3.10 or later.

Before continuing to Stage 1, confirm the selected launcher can import `core.agent_identity_policy_cli`. If no launcher can be selected, or the import check fails, stop and report `AGENT_IDENTITY_POLICY_CLI_UNAVAILABLE`. Do not install any package. Do not modify the environment.

## Safe CLI Transport

Invoke the CLI through **stdin only**, exactly following the safe invocation pattern already established by `/request-case-update`, `/review-approval`, `/apply-case-update`, `/simulate-case-update`, and `/evaluate-tool-call`. Never pass JSON through command-line arguments, never create a temporary JSON file, never interpolate caller content directly into executable shell code, and never write request data to disk.

## Stage 1 — Pin the Evaluation Timestamp

Only after Stage 0 succeeds, obtain exactly one current, timezone-aware UTC timestamp, canonicalized to ISO-8601 `...Z` form. Generate it exactly once for this invocation:

- the caller can never supply or override it;
- it is never regenerated after this stage — the exact same string value is reused through Stage 2;
- the mechanism used to obtain it is never displayed in any output.

`core.agent_identity_policy`, `core.agent_identity_policy_cli`, `core.agent_gateway`, and `core.agent_gateway_cli` never read the system clock themselves — this stage is the sole source of `evaluated_at` anywhere in this workflow.

## Stage 2 — Invoke the Agent Identity Policy CLI

Construct exactly this object, in exactly this key order:

```json
{
  "agent_id": "<the candidate agent ID from Stage 0>",
  "tool_name": "<the candidate tool name from Stage 0>",
  "arguments": "<the candidate arguments object from Stage 0, unchanged>",
  "evaluated_at": "<the pinned timestamp from Stage 1>"
}
```

Never add, remove, rename, normalize, redact, or otherwise transform any field or value. Never substitute a caller-supplied value for any of the four fields. Never call `core.agent_identity_policy` directly, never call `core.agent_gateway` directly, and never reimplement any part of the agent registry, role map, capability map, argument validation, or policy logic in this document.

Send it through **stdin only** to `py -m core.agent_identity_policy_cli` (or the equivalent selected launcher).

### Identity Policy CLI exit handling

- **0**: success — the report is complete regardless of which of `allow`, `require_approval`, or `deny` it contains. Continue to the output validation below.
- **2**: a deterministic identity-policy validation failure — stop and report `AGENT_IDENTITY_POLICY_VALIDATION_FAILED`.
- **1**: an unexpected internal failure — stop and report `AGENT_IDENTITY_POLICY_INTERNAL_FAILURE`.
- **any other code**: stop and report `AGENT_IDENTITY_POLICY_INTERNAL_FAILURE`.

Never automatically retry any of these outcomes, and never fall back to displaying a partially-constructed or hand-assembled report.

### Identity Policy CLI success-output validation

Require stdout to be exactly one JSON object containing exactly the fifteen fields `core.agent_identity_policy.evaluate_agent_tool_call` always returns: `identity_policy_version`, `canonical_agent_id`, `agent_role`, `identity_authenticated`, `canonical_tool_name`, `operation_class`, `gateway_decision`, `final_decision`, `eligible_for_execution`, `requires_approval`, `matched_identity_rules`, `safe_capability_summary`, `required_next_action`, `evaluated_at`, `execution_performed`.

Require `identity_policy_version` to equal exactly `"1"`, `identity_authenticated` to equal exactly `false`, and `execution_performed` to equal exactly `false`. Require `final_decision` to be exactly one of `allow`, `require_approval`, `deny`, and require it to match one of these three fixed, committed combinations exactly:

| `final_decision` | `eligible_for_execution` | `requires_approval` | `required_next_action` |
|---|---|---|---|
| `allow` | `true` | `false` | `proceed_to_separate_execution_boundary` |
| `require_approval` | `false` | `true` | `submit_to_approval_workflow` |
| `deny` | `false` | `false` | `do_not_execute` |

Require `gateway_decision`-to-`final_decision` monotonicity — the identity policy can only narrow a Block 8 decision, never widen it:

- `gateway_decision` of `deny` may only pair with `final_decision` of `deny`;
- `gateway_decision` of `require_approval` may pair with `final_decision` of `require_approval` or `deny`, never `allow`;
- `gateway_decision` of `allow` may pair with `final_decision` of `allow` or `deny`, never `require_approval`;
- `gateway_decision` of `null` (an unknown or disabled claimed agent, meaning Block 8 was never even reached) may only pair with `final_decision` of `deny`.

Require `safe_capability_summary` to contain exactly five fields: `role`, `requested_tool_allowed`, `requested_operation_class_permitted`, `mutation_request_allowed`, `allowed_tool_count`. Never display, reconstruct, or infer a full tool allowlist, a complete capability set, a hidden role map, or any registry entry beyond these five safe fields.

If the report is missing a required field, contains an unrecognized field, has `identity_policy_version` other than `"1"`, has `identity_authenticated` other than `false`, has `execution_performed` other than `false`, has a `final_decision`/`eligible_for_execution`/`requires_approval`/`required_next_action` combination that does not match the table above exactly, violates `gateway_decision`-to-`final_decision` monotonicity, or has a `safe_capability_summary` that does not contain exactly the five fields above: stop, report `AGENT_IDENTITY_POLICY_VALIDATION_FAILED`, and never execute anything. Do not repair, complete, or reinterpret a malformed report by hand.

Call the fully validated result the **identity policy report**.

## Required Output

Produce, only after the identity policy report passes every check above:

- Claimed Agent ID (the candidate agent ID from Stage 0 — displayed only as what the caller typed; when `canonical_agent_id` is `null`, never treat the claimed agent as confirmed or registered)
- Canonical Agent ID (exactly `canonical_agent_id`, or `null`)
- Agent Role (exactly `agent_role`, or `null`)
- **`identity_authenticated: false`**
- Requested Tool Name (the candidate tool name from Stage 0 — displayed only as what the caller typed; when `canonical_tool_name` is `null`, never treat the requested name as confirmed or registered)
- Canonical Tool Name (exactly `canonical_tool_name`, or `null`)
- Operation Class (exactly `operation_class`, or `null`)
- Gateway Decision (exactly `gateway_decision`, or `null`)
- Final Decision (`allow` / `require_approval` / `deny`)
- Eligible For Execution
- Requires Approval
- Matched Identity Rules (each rule's `code`, `severity`, `message`, `affects_decision` — display every rule the report contains)
- Safe Capability Summary (exactly as returned — `role`, `requested_tool_allowed`, `requested_operation_class_permitted`, `mutation_request_allowed`, `allowed_tool_count`)
- Required Next Action (displayed as advisory information only)
- Evaluated At
- **`execution_performed: false`**
- An explicit statement equivalent to: **"No agent was authenticated, and no tool, approval workflow, database operation, or external process was executed."**

### When `final_decision` is `allow`

State clearly that the claimed agent matched a known, enabled registry entry, that the proposed call currently passes both Block 8's policy and this agent's own least-privilege capability check, that this is not authentication, that the tool may proceed only to a separate execution boundary this command never crosses, that this command itself did not execute it, that `identity_authenticated` remains `false`, and that `execution_performed` remains `false`. Never automatically execute the tool, and never imply that evaluation and execution are the same step.

### When `final_decision` is `require_approval`

State clearly that the claimed agent matched a registry entry, that this specific mutation request is within that agent's own request capability, that Block 8 still requires the separate, existing Block 6 approval workflow before it could ever execute, that no authentication occurred, that no approval was created by this command, that no other command was automatically invoked, that no tool was executed, and that `required_next_action` is advisory text only. Never automatically invoke `/request-case-update`, `/review-approval`, or `/apply-case-update`, and never fabricate or display a constructed approval request.

### When `final_decision` is `deny`

State clearly that the proposed call was denied by identity policy, gateway policy, or both, and display the matched identity rules that explain why. State clearly that a registry match, when one occurred, does not authenticate the caller. Never retry the same request, never substitute a different, more privileged agent, never enable a disabled agent, never add a capability, never choose an alias or a different letter case for the agent ID or tool name, never fall back to a different execution path, and never treat a `deny` decision as a command-level (transport) failure — it is a normal, successful evaluation outcome.

Never display:

- the caller's raw `arguments` separately from `safe_capability_summary`;
- a raw unknown or unregistered agent ID presented as if it were a confirmed, registered agent;
- a raw unknown tool name presented as if it were a confirmed, registered tool;
- any UUID or other argument value;
- SQL or migration text;
- filesystem paths;
- authorization phrases;
- identities from Block 6 (`requested_by`, `approved_by`, `rejected_by`, `consumed_by`, or any reviewer identity);
- credentials;
- tokens;
- environment values;
- a full tool allowlist or a complete capability set;
- registry internals beyond the five safe `safe_capability_summary` fields;
- a bridge/MCP descriptor or RPC parameter payload;
- a stack trace, exception class name, or raw internal exception message;
- the internal construction of the CLI command, its raw stdin envelope, or the timestamp-generation mechanism.

## Required Failure Categories

Use only these fixed, non-sensitive failure categories. Never expose a raw exception message, exception class name, traceback, credential, path, SQL, descriptor, or RPC parameter in any of them.

### AGENT_IDENTITY_POLICY_CLI_UNAVAILABLE

The Python launcher or `core.agent_identity_policy_cli` import check failing before any stage below runs.

### INVALID_INPUT

Stage 0 rejecting a missing agent ID, missing tool name, missing arguments object, malformed JSON, non-object top-level JSON, or trailing content after the JSON object.

### AGENT_IDENTITY_POLICY_VALIDATION_FAILED

Stage 2 reporting exit code 2, or the identity policy CLI success-output validation failing (a malformed report, an unrecognized or missing field, `identity_policy_version` other than `"1"`, `identity_authenticated` other than `false`, `execution_performed` other than `false`, a decision/field combination that does not match the fixed table, a `gateway_decision`-to-`final_decision` monotonicity violation, or a `safe_capability_summary` missing one of its five fields).

### AGENT_IDENTITY_POLICY_INTERNAL_FAILURE

Stage 2 reporting exit code 1 or any other unexpected code.

Do not automatically retry any failure in any category above.

## No-Fallback and No-Retry Policy

On any command-level, CLI, parsing, or report-validation failure, or on any `deny` decision:

- stop;
- do not retry automatically;
- do not change the claimed agent ID's letter case;
- do not choose an alias or a near-miss agent ID;
- do not substitute `coordinator_agent`, or any other more privileged registered agent, for the claimed agent the caller supplied;
- do not enable a disabled agent;
- do not change the claimed agent's role;
- do not add a capability the registry does not already grant;
- do not choose an alias, a near-miss name, or a different letter case for the tool name;
- do not remove, rename, or "fix" any argument;
- do not substitute a different, known tool for the one the caller named;
- do not switch to a raw `mcp__supabase__execute_sql` call, a direct database client, or a REST request;
- do not switch to direct or hand-written SQL;
- do not invoke Hayabusa or any other MCP server;
- do not invoke `/request-case-update`, `/review-approval`, or `/apply-case-update`;
- do not execute the requested operation manually, through any path.

The caller may always safely resubmit a corrected command later — this command itself never performs that retry automatically, and never hides it.

## Explicit Execution Prohibitions

This command must never invoke, directly or indirectly:

- `mcp__supabase__execute_sql`;
- `execute_sql`;
- `apply_migration`;
- `run_evtx_analysis`;
- `insert_risk_aware_pending_approval`;
- `apply_multi_review_transition`;
- `apply_approval_consumption` as a real, executed operation;
- `record_approval_review_and_promote_status`;
- `consume_approval_and_update_investigation_state`;
- `/request-case-update`;
- `/review-approval`;
- `/apply-case-update`;
- a login command;
- a token-validation command;
- a session-creation command;
- a certificate-validation command;
- a dynamically imported, caller-selected module or function;
- a shell command constructed from the proposed tool request;
- a subprocess of any kind other than the one selected Python launcher running `core.agent_identity_policy_cli`.

The only process this command ever executes is the one committed, deterministic evaluator: `py -m core.agent_identity_policy_cli` (or the equivalent selected launcher), invoked exactly once per command invocation. This command never executes the tool named by the caller, under any decision, including `allow`.

## Security Boundaries

This command must never:

- accept a caller-supplied `evaluated_at`, `canonical_agent_id`, `agent_role`, `identity_authenticated`, `enabled`, `role`, `capabilities`, `allowed_tools`, `allowed_operation_classes`, `mutation_request_allowed`, `canonical_tool_name`, `operation_class`, `gateway_decision`, `final_decision`, `eligible_for_execution`, `requires_approval`, `matched_identity_rules`, `safe_capability_summary`, `required_next_action`, `execution_performed`, an authentication status, an approval authority, a trust level, a session state, or an `identity_policy_version` as a command-level override;
- accept a caller-supplied SQL descriptor, RPC parameter set, or MCP payload;
- accept more than one agent-ID token, more than one tool-name token, or more than one JSON argument object;
- decide agent registration, agent enablement, role assignment, capability assignment, tool registration, tool enablement, operation class, argument validity, or the final decision itself — every one of those belongs entirely to `core.agent_identity_policy.evaluate_agent_tool_call`;
- lowercase, casefold, alias, fuzzy-match, or otherwise rewrite the caller-supplied agent ID or tool name;
- strip, rename, or repair a caller-supplied argument field, including one that collides with a reserved policy/control field name;
- treat a registry match as proof of identity, authentication, verification, or trust;
- treat `allow` as evidence that execution occurred;
- treat `require_approval` as approval creation;
- treat `deny` as a CLI transport failure;
- automatically follow `required_next_action`;
- execute the proposed tool, under any decision;
- retry any stage automatically, or fall back to a substitute agent, a substitute tool, a direct query, or a different execution path after any failure;
- display any Block 6 identity field, raw argument value, SQL, descriptor, MCP/RPC payload, credential, project reference, environment variable, filesystem path, or stack trace.

## Example Invocation

```
/evaluate-agent-tool-call analyst_agent load_risk_aware_approval_record {"approval_id":"..."}
```

```
/evaluate-agent-tool-call coordinator_agent apply_approval_consumption {"approval_id":"..."}
```

## Safety Rules

- Accept exactly one agent-ID token, exactly one tool-name token, and exactly one JSON argument object. Never accept a fourth positional argument or a JSON envelope wrapper.
- Never accept a caller-supplied `evaluated_at`, role, capability, decision field, or any other engine-owned output field as a command-level override.
- Never generate `evaluated_at` more than once per invocation, and never let the caller supply or override it.
- Never bypass `core.agent_identity_policy_cli`, and never reimplement any agent registry, role map, capability map, validation, or policy rule that `core.agent_identity_policy` or `core.agent_gateway` already owns.
- Never authenticate, verify, or trust the caller's claimed agent ID — a registry match is never proof of identity.
- Never execute the proposed tool, under any decision, including `allow`.
- Never create an approval, create a session, consume an approval, mutate an investigation, or apply a migration, through this command.
- Never call `mcp__supabase__execute_sql`, `execute_sql`, `apply_migration`, `run_evtx_analysis`, or any Block 6 mutation operation.
- Never automatically invoke `/request-case-update`, `/review-approval`, or `/apply-case-update`.
- Never treat `require_approval` or `deny` as a command failure, and never attempt a fallback execution.
- Never substitute a different, more privileged agent, enable a disabled agent, or add a capability the registry does not already grant.
- Never claim a tool was executed or an agent was authenticated — always state plainly that no agent was authenticated and that no tool, approval workflow, database operation, or external process was executed.
- Never retry any stage automatically, and never fall back to a substitute agent, a substitute tool, or a direct execution path after a failure.
- Never expose a raw PostgreSQL error, generated SQL, a credential, a project URL, a project reference, an access token, a stack trace, an exception class name, or an internal owner detail.
