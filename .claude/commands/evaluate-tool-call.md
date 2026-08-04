---
description: Evaluate a proposed AI-agent tool call against the deterministic Block 8 runtime policy engine, without executing it
argument-hint: "[tool-name] [json-arguments]"
---

# ThreatTrace Evaluate Tool Call Workflow

Invocation: `/evaluate-tool-call <tool-name> <json-arguments>` — exactly one tool-name token, followed by exactly one JSON argument object. This command never accepts a JSON envelope, a second positional argument, or any caller-supplied decision, risk, or execution field.

`/evaluate-tool-call` is Block 8's AI Agent Gateway / Runtime Firewall boundary: it answers *may this proposed tool call proceed?* by consulting the existing, already-committed, deterministic policy engine (`core.agent_gateway.evaluate_tool_call`, via `core.agent_gateway_cli`) — and nothing else. This command is strictly read-only and strictly advisory:

Tool name + arguments → command-level shape validation → pinned UTC evaluation timestamp → `core.agent_gateway_cli` → deterministic `allow` / `require_approval` / `deny` report

`/evaluate-tool-call` never executes the tool it evaluates, never calls Supabase or MCP, never executes SQL, never invokes Hayabusa, never creates or consumes an approval, never mutates an investigation, and never applies a migration. It never decides tool registration, enablement, operation class, argument policy, or the final decision itself — every one of those belongs entirely to `core.agent_gateway`, reached only through `core.agent_gateway_cli`, never reimplemented in this document.

A gateway report is a **decision about a proposed call**, never proof that anything ran. `allow` means the call currently passes policy and *may* proceed to a wholly separate execution boundary this command never crosses. `require_approval` means the call needs the existing, separate Block 6 approval workflow first — this command never creates that approval itself. `deny` means the call is refused — this command never retries it, aliases it, or falls back to executing it a different way. All three are equally valid, successful evaluation outcomes.

## Evaluation Input

$ARGUMENTS

## Stage 0 — Command-Level Input Shape Validation

`$ARGUMENTS` must contain exactly two things, in order: a non-empty tool-name token, and exactly one JSON object. Perform every check below, in order, before Stage 1 — before any timestamp is pinned and before any CLI invocation:

1. Trim `$ARGUMENTS` of surrounding whitespace. Reject a blank result (nothing supplied at all).
2. Split at the first whitespace character. The text before it is the **candidate tool name**. Reject when there is no whitespace at all (a tool name with no JSON argument object supplied).
3. Reject a blank candidate tool name.
4. The text after the first whitespace, trimmed of leading whitespace, is the **candidate argument text**. Parse it as exactly one JSON value.
5. Reject malformed JSON.
6. Reject trailing non-whitespace content after the one parsed JSON value.
7. Reject a top-level value that is not a JSON object — a top-level array, string, number, boolean, or `null` is never accepted as `arguments`.

This command performs **no local UUID check, tool-name check, or argument-content check of any kind** beyond this pure shape validation. It does not decide, at this or any other stage, whether the named tool is known, whether it is enabled, what its operation class is, whether its arguments are individually valid, or what the final decision should be — every one of those is always decided later, entirely by `core.agent_gateway.evaluate_tool_call`, reached only through `core.agent_gateway_cli`. The candidate tool name is never lowercased, aliased, fuzzy-matched, or otherwise rewritten, and the candidate arguments object's own field names and values are never transformed, stripped, or repaired — including when a field name happens to look like one of the engine's own reserved policy/control names (`decision`, `risk_level`, `required_approvals`, and so on): such a field is passed to the engine completely unchanged, exactly as supplied, so that the engine itself can produce its own deterministic `PROHIBITED_ARGUMENT` denial from real, trusted input, never from a command-layer guess.

Call the two validated values the **candidate tool name** and the **candidate arguments object**.

## Python Launcher Selection

Use the existing project convention for selecting a Python launcher:

1. Try `py`.
2. Otherwise try `python3`.
3. Otherwise use a `python` executable only after confirming it resolves to Python 3.10 or later.

Before continuing to Stage 1, confirm the selected launcher can import `core.agent_gateway_cli`. If no launcher can be selected, or the import check fails, stop and report `AGENT_GATEWAY_CLI_UNAVAILABLE`. Do not install any package. Do not modify the environment.

## Safe CLI Transport

Invoke the CLI through **stdin only**, exactly following the safe invocation pattern already established by `/request-case-update`, `/review-approval`, `/apply-case-update`, and `/simulate-case-update`. Never pass JSON through command-line arguments, never create a temporary JSON file, never interpolate caller content directly into executable shell code, and never write request data to disk.

## Stage 1 — Pin the Evaluation Timestamp

Only after Stage 0 succeeds, obtain exactly one current, timezone-aware UTC timestamp, canonicalized to ISO-8601 `...Z` form. Generate it exactly once for this invocation:

- the caller can never supply or override it;
- it is never regenerated after this stage — the exact same string value is reused through Stage 2;
- the mechanism used to obtain it is never displayed in any output.

`core.agent_gateway` and `core.agent_gateway_cli` never read the system clock themselves — this stage is the sole source of `evaluated_at` anywhere in this workflow.

## Stage 2 — Invoke the Agent Gateway CLI

Construct exactly this object, in exactly this key order:

```json
{
  "tool_name": "<the candidate tool name from Stage 0>",
  "arguments": "<the candidate arguments object from Stage 0, unchanged>",
  "evaluated_at": "<the pinned timestamp from Stage 1>"
}
```

Never add, remove, rename, normalize, redact, or otherwise transform any field or value. Never substitute a caller-supplied value for any of the three fields. Never call `core.agent_gateway` directly, and never reimplement any part of its registry, argument validation, or policy logic in this document.

Send it through **stdin only** to `py -m core.agent_gateway_cli` (or the equivalent selected launcher).

### Gateway CLI exit handling

- **0**: success — the report is complete regardless of which of `allow`, `require_approval`, or `deny` it contains. Continue to the output validation below.
- **2**: a deterministic gateway validation failure — stop and report `AGENT_GATEWAY_VALIDATION_FAILED`.
- **1**: an unexpected internal failure — stop and report `AGENT_GATEWAY_INTERNAL_FAILURE`.
- **any other code**: stop and report `AGENT_GATEWAY_INTERNAL_FAILURE`.

Never automatically retry any of these outcomes, and never fall back to displaying a partially-constructed or hand-assembled report.

### Gateway CLI success-output validation

Require stdout to be exactly one JSON object containing exactly the twelve fields `core.agent_gateway.evaluate_tool_call` always returns: `gateway_version`, `canonical_tool_name`, `operation_class`, `decision`, `eligible_for_execution`, `requires_approval`, `matched_rules`, `safe_argument_summary`, `blocked_argument_fields`, `required_next_action`, `evaluated_at`, `execution_performed`.

Require `gateway_version` to equal exactly `"1"`, and `execution_performed` to equal exactly `false`. Require `decision` to be exactly one of `allow`, `require_approval`, `deny`, and require it to match one of these three fixed, committed combinations exactly:

| `decision` | `eligible_for_execution` | `requires_approval` | `required_next_action` |
|---|---|---|---|
| `allow` | `true` | `false` | `proceed_to_separate_execution_boundary` |
| `require_approval` | `false` | `true` | `submit_to_approval_workflow` |
| `deny` | `false` | `false` | `do_not_execute` |

If the report is missing a required field, contains an unrecognized field, has `gateway_version` other than `"1"`, has `execution_performed` other than `false`, or has a `decision`/`eligible_for_execution`/`requires_approval`/`required_next_action` combination that does not match the table above exactly: stop, report `AGENT_GATEWAY_VALIDATION_FAILED`, and never execute anything. Do not repair, complete, or reinterpret a malformed report by hand.

Call the fully validated result the **gateway decision report**.

## Required Output

Produce, only after the gateway decision report passes every check above:

- Requested Tool Name (the candidate tool name from Stage 0 — displayed only as what the caller typed; when `canonical_tool_name` is `null`, never treat the requested name as confirmed or registered)
- Canonical Tool Name (exactly `canonical_tool_name`, or `null`)
- Operation Class (exactly `operation_class`, or `null`)
- Decision (`allow` / `require_approval` / `deny`)
- Eligible For Execution
- Requires Approval
- Matched Policy Rules (each rule's `code`, `severity`, `message`, `affects_decision` — display every rule the report contains)
- Safe Argument Summary (exactly as returned — field names mapped only to `present`/`absent`/`redacted`)
- Blocked Argument Fields (exactly as returned)
- Required Next Action (displayed as advisory information only)
- Evaluated At
- **`execution_performed: false`**
- An explicit statement equivalent to: **"No tool, approval workflow, database operation, or external process was executed."**

### When `decision` is `allow`

State clearly that the proposed call currently passes deterministic policy, that it may proceed only to a separate execution boundary this command never crosses, that this command itself did not execute it, and that `execution_performed` remains `false`. Never automatically execute the tool, and never imply that evaluation and execution are the same step.

### When `decision` is `require_approval`

State clearly that the proposed call is recognized but mutates state and therefore requires the separate, existing Block 6 approval workflow before it could ever execute, that no approval was created by this command, and that `required_next_action` is advisory text only. Never automatically invoke `/request-case-update`, and never fabricate or display a constructed approval request.

### When `decision` is `deny`

State clearly that the proposed call is denied by policy, and display the matched policy rules that explain why. Never retry the same request under a different tool name, never fall back to a different execution path, and never treat a `deny` decision as a command-level (transport) failure — it is a normal, successful evaluation outcome.

Never display:

- the caller's raw arguments separately from `safe_argument_summary`;
- a raw unknown tool name presented as if it were a confirmed, registered tool;
- any UUID or other argument value;
- SQL or migration text;
- filesystem paths;
- authorization phrases;
- identities;
- credentials;
- tokens;
- environment values;
- a bridge/MCP descriptor or RPC parameter payload;
- a stack trace, exception class name, or raw internal exception message;
- the internal construction of the CLI command or its raw stdin envelope.

## Required Failure Categories

Use only these fixed, non-sensitive failure categories. Never expose a raw exception message, exception class name, traceback, credential, path, SQL, descriptor, or RPC parameter in any of them.

### AGENT_GATEWAY_CLI_UNAVAILABLE

The Python launcher or `core.agent_gateway_cli` import check failing before any stage below runs.

### INVALID_INPUT

Stage 0 rejecting a missing tool name, missing arguments object, malformed JSON, non-object top-level JSON, or trailing content after the JSON object.

### AGENT_GATEWAY_VALIDATION_FAILED

Stage 2 reporting exit code 2, or the gateway CLI success-output validation failing (a malformed report, an unrecognized or missing field, `gateway_version` other than `"1"`, `execution_performed` other than `false`, or a decision/field combination that does not match the fixed table).

### AGENT_GATEWAY_INTERNAL_FAILURE

Stage 2 reporting exit code 1 or any other unexpected code.

Do not automatically retry any failure in any category above.

## No-Fallback and No-Retry Policy

On any command-level, CLI, parsing, or report-validation failure:

- stop;
- do not retry automatically;
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
- `apply_approval_consumption`;
- `record_approval_review_and_promote_status`;
- `consume_approval_and_update_investigation_state`;
- `/request-case-update`;
- `/apply-case-update`;
- a subprocess of any kind other than the one selected Python launcher running `core.agent_gateway_cli`;
- a dynamically imported, caller-selected module or function;
- a shell command constructed from the proposed tool request.

The only process this command ever executes is the one committed, deterministic evaluator: `py -m core.agent_gateway_cli` (or the equivalent selected launcher), invoked exactly once per command invocation. This command never executes the tool named by the caller, under any decision, including `allow`.

## Security Boundaries

This command must never:

- accept a caller-supplied `evaluated_at`, `canonical_tool_name`, `operation_class`, `decision`, `eligible_for_execution`, `requires_approval`, `matched_rules`, `safe_argument_summary`, `blocked_argument_fields`, `required_next_action`, `execution_performed`, `policy_outcome`, `risk_level`, or `required_approvals` as a command-level override;
- accept a caller-supplied SQL descriptor, RPC parameter set, or MCP payload;
- accept more than one tool-name token or more than one JSON argument object;
- decide tool registration, enablement, operation class, argument validity, or the final decision itself — every one of those belongs entirely to `core.agent_gateway.evaluate_tool_call`;
- lowercase, alias, fuzzy-match, or otherwise rewrite the caller-supplied tool name;
- strip, rename, or repair a caller-supplied argument field, including one that collides with a reserved policy/control field name;
- treat `allow` as evidence that execution occurred;
- treat `require_approval` as approval creation;
- treat `deny` as a CLI transport failure;
- automatically follow `required_next_action`;
- execute the proposed tool, under any decision;
- retry any stage automatically, or fall back to a substitute tool, a direct query, or a different execution path after any failure;
- display any identity field, raw argument value, SQL, descriptor, MCP/RPC payload, credential, project reference, environment variable, filesystem path, or stack trace.

## Example Invocation

```
/evaluate-tool-call load_risk_aware_approval_record {"approval_id":"7d3f0e4a-4c5f-4d0a-9b12-345678901bcd"}
```

```
/evaluate-tool-call apply_approval_consumption {"approval_id":"7d3f0e4a-4c5f-4d0a-9b12-345678901bcd"}
```

## Safety Rules

- Accept exactly one tool-name token and exactly one JSON argument object. Never accept a second positional argument or a JSON envelope wrapper.
- Never accept a caller-supplied `evaluated_at`, decision field, or any other engine-owned output field as a command-level override.
- Never generate `evaluated_at` more than once per invocation, and never let the caller supply or override it.
- Never bypass `core.agent_gateway_cli`, and never reimplement any registry, validation, or policy rule that `core.agent_gateway` already owns.
- Never execute the proposed tool, under any decision, including `allow`.
- Never create an approval, consume an approval, mutate an investigation, or apply a migration, through this command.
- Never call `mcp__supabase__execute_sql`, `execute_sql`, `apply_migration`, `run_evtx_analysis`, or any Block 6 mutation operation.
- Never automatically invoke `/request-case-update`, `/review-approval`, or `/apply-case-update`.
- Never treat `require_approval` or `deny` as a command failure, and never attempt a fallback execution.
- Never claim a tool was executed — always state plainly that no tool, approval workflow, database operation, or external process was executed.
- Never retry any stage automatically, and never fall back to a substitute tool or a direct execution path after a failure.
- Never expose a raw PostgreSQL error, generated SQL, a credential, a project URL, a project reference, an access token, a stack trace, an exception class name, or an internal owner detail.
