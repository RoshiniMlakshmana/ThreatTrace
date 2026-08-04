---
description: Simulate what an approved, risk-aware case-update approval would change, without applying it
argument-hint: "[approval UUID]"
---

# ThreatTrace Simulate Case Update Workflow

Invocation: `/simulate-case-update <approval-id>` — exactly one caller argument, the approval UUID to simulate. This command never accepts caller-provided investigation state or caller-provided proposed state of any kind.

`/simulate-case-update` is Block 7's Shadow Execution ("digital twin") preview: it answers *what would `/apply-case-update` do to this investigation right now?* without ever applying it. This command is strictly read-only:

Approval UUID → trusted approval lookup → trusted investigation-context lookup → pinned simulation timestamp → deterministic pure simulation → shadow-execution report

`/simulate-case-update` never creates, approves, rejects, reviews, or consumes an approval, and it never updates `public.investigations` through any path. The only database interactions this command ever performs are two existing, already-committed **read-only** lookups — `load_risk_aware_approval_record` and `load_investigation_approval_context` — each executed through the same existing two-phase prepare/verify approval bridge (`core.approval_bridge_cli`) and the strict Supabase MCP descriptor adapter (`core.approval_mcp_adapter_cli`) that `/request-case-update`, `/review-approval`, and `/apply-case-update` already use. After both lookups are independently verified, this command hands the two trusted, verified records and one pinned timestamp to the existing pure simulation engine (`core.shadow_execution_cli`, wrapping `core.shadow_execution.simulate_case_update`) and displays its deterministic result unchanged. This command never reimplements eligibility rules, warning rules, rollback classification, or state-diff calculation — every one of those belongs entirely to `core.shadow_execution`, never to this document.

A shadow-execution report is a **preview**, not an authorization decision and not an execution record. `eligible_for_execution: false` in the report is a normal, successful simulation outcome describing why `/apply-case-update` would currently be refused — never a command failure, and never something this command works around, retries, or bypasses. Actually applying an approved change always remains a separate, later, explicit invocation of `/apply-case-update`.

## Simulation Input

$ARGUMENTS

## Stage 0 — Caller Argument Validation

`$ARGUMENTS` must contain exactly one thing: the approval UUID to simulate, and nothing else. Perform every check below, in order, before Stage 1 — before any bridge, adapter, MCP, or Supabase operation of any kind:

1. Trim `$ARGUMENTS` of surrounding whitespace.
2. Reject a blank result (missing argument).
3. Reject a result that splits into more than one whitespace-separated token (more than one argument).
4. Reject a result that begins with `{` or `[` (a JSON object or array is never accepted here — this command takes one bare UUID argument, never an envelope).
5. Reject a result containing any of `;`, `|`, `` ` ``, `$(`, `--`, `/*`, `*/`, `<`, `>`, `://`, or a path separator (`/` or `\`) — none of these characters can ever appear in a structurally valid UUID, so their presence always indicates a SQL fragment, a shell/command substitution attempt, a path, or a URL, never a genuine approval ID.

The single remaining token becomes the **candidate `approval_id`**.

This command performs no local UUID-format (regex) check of its own, and does not implement a second, competing UUID policy — Stage 1's bridge prepare call delegates canonicalization entirely to the same existing persistence-layer UUID validation `/apply-case-update` already relies on for its own `approval_id` field (`core.approval_persistence`, reached through `core.approval_bridge_cli`). A malformed-but-otherwise-plain-looking UUID (e.g. wrong length, wrong character set) is therefore always rejected in Stage 1, still strictly before any MCP or Supabase call — never accepted, and never given a second, hand-written validation path here.

## Python Launcher Selection

Use the existing project convention for selecting a Python launcher:

1. Try `py`.
2. Otherwise try `python3`.
3. Otherwise use a `python` executable only after confirming it resolves to Python 3.10 or later.

Select one launcher and reuse the same launcher for every CLI invocation in this workflow.

Before continuing to any Supabase or MCP operation, confirm the selected launcher can import all three required modules:

- `core.approval_bridge_cli`
- `core.approval_mcp_adapter_cli`
- `core.shadow_execution_cli`

If no launcher can be selected, or the import check fails for any of the three modules, stop and report `SIMULATION_CLI_UNAVAILABLE`. Do not install any package. Do not modify the environment.

## Safe CLI Transport

Invoke all CLIs through **stdin only**, exactly following the safe invocation pattern already established by `/request-case-update`, `/review-approval`, and `/apply-case-update`. Never:

- pass JSON through command-line arguments;
- create a temporary JSON file;
- interpolate caller content directly into executable shell code;
- write request data to disk.

## Stage 1 — Approval Lookup Bridge Prepare

Use the existing two-phase approval bridge, in its prepare phase, to construct the exact `load_risk_aware_approval_record` operation descriptor — bound only to the candidate `approval_id` from Stage 0, never to any other filter. This is the exact same eighteen-field risk-aware lookup `/review-approval` and `/apply-case-update` already use.

Construct exactly this object:

```json
{
  "phase": "prepare",
  "operation": "load_risk_aware_approval_record",
  "input": {
    "approval_id": "<the candidate approval_id from Stage 0>"
  }
}
```

Send it through **stdin only** to:

- Windows: `py -m core.approval_bridge_cli`
- macOS or Linux: `python3 -m core.approval_bridge_cli`
- Only fall back to plain `python -m core.approval_bridge_cli` if it is confirmed to resolve to Python 3.10 or later.

### Approval lookup prepare exit handling

- **0**: potential success — continue to the output checks below.
- **2** (`approval_persistence_error`, `approval_bridge_error` — including a malformed `approval_id`) or **1** (`internal_error`): stop and report `APPROVAL_LOOKUP_PREPARE_FAILED`.
- **any other code**: stop and report `APPROVAL_LOOKUP_PREPARE_FAILED`.

### Approval lookup prepare success-output checks

Reject the output when stderr is nonempty, stdout is empty, stdout is not valid JSON, stdout contains more than one JSON value, or the parsed value is not a JSON object.

Require the parsed object to contain exactly `phase`, `operation`, `descriptor`, with `phase` equal to `"prepare"` and `operation` equal to `"load_risk_aware_approval_record"`. Require the descriptor to match the canonical select-descriptor shape already owned by `core.approval_persistence`: `operation` equal to `"select"`, `table` equal to `"approvals"`, `columns` equal to the full eighteen-field risk-aware approval record contract (the existing sixteen fields plus `risk_level` and `required_approvals`), `filters` containing exactly `id` equal to the canonical approval UUID, and `limit` equal to `2`.

Call this the **prepared approval-lookup descriptor**. Do not display it in any output.

## Stage 2 — Approval Lookup MCP Adapter Prepare Call

Construct exactly this object:

```json
{
  "action": "prepare_call",
  "descriptor": "<the prepared approval-lookup descriptor from Stage 1>"
}
```

Send it through **stdin only** to `core.approval_mcp_adapter_cli`, using the same launcher selected earlier.

### Approval lookup adapter prepare_call exit handling

- **0**: potential success — continue to the output checks below.
- **2** (`approval_mcp_adapter_error`) or **1** (`internal_error`): stop and report `APPROVAL_LOOKUP_PREPARE_FAILED`.
- **any other code**: stop and report `APPROVAL_LOOKUP_PREPARE_FAILED`.

### Approval lookup adapter prepare_call success-output checks

Require the parsed object to contain exactly `tool` and `arguments`, with `tool` equal exactly to `mcp__supabase__execute_sql` and `arguments` containing exactly one field, `query`, a nonblank string. Call this the **approval lookup MCP request**. Do not display it in any output.

## Stage 3 — Execute Through Supabase MCP (Approval Lookup)

Invoke only the tool named in the approval lookup MCP request — `mcp__supabase__execute_sql` — using exactly the `arguments` the adapter returned, and only **once**. Do not rewrite, edit, or independently generate the SQL, append a second statement, use `apply_migration`, use a direct database client or connection string, use a REST request, or retry automatically.

Capture the tool's raw response exactly as returned. Do not parse, inspect, trust, or display the raw MCP result directly anywhere in this command — it is untrusted data and is handed unmodified to Stage 4 next. Call this the **raw approval lookup MCP result**.

If the tool call itself fails to return a result at all, stop and report `APPROVAL_LOOKUP_MCP_CALL_FAILED`.

## Stage 4 — Approval Lookup MCP Adapter Normalize Response

Construct exactly this object:

```json
{
  "action": "normalize_response",
  "operation": "load_risk_aware_approval_record",
  "tool_response": "<the raw approval lookup MCP result from Stage 3, exactly as returned>"
}
```

Send it through **stdin only** to the same `core.approval_mcp_adapter_cli` module used in Stage 2.

### Approval lookup normalize_response exit handling

- **0**: potential success — continue to the output checks below.
- **2** (`approval_mcp_adapter_error`) or **1** (`internal_error`): stop and report `APPROVAL_LOOKUP_NORMALIZATION_FAILED`.
- **any other code**: stop and report `APPROVAL_LOOKUP_NORMALIZATION_FAILED`.

### Approval lookup normalize_response success-output checks

Require the parsed object to be exactly one of the two canonical shapes: `{"kind": "rows", "rows": [...]}` or `{"kind": "transport_error"}`. Call this the **normalized approval lookup response**. A `transport_error` kind is not itself a local command failure at this stage — pass it forward unchanged to Stage 5, exactly as the bridge's own verify phase already expects to receive it. Never reinterpret it as `{"kind": "rows", "rows": []}` or as any kind of success.

## Stage 5 — Approval Lookup Bridge Verify

Construct exactly this object:

```json
{
  "phase": "verify",
  "operation": "load_risk_aware_approval_record",
  "input": "<the exact same input object used in Stage 1>",
  "prepared_descriptor": "<the prepared approval-lookup descriptor from Stage 1>",
  "executor_response": "<the normalized approval lookup response from Stage 4>"
}
```

Send it through **stdin only** to `core.approval_bridge_cli`.

### Approval lookup verify exit handling

Interpret the exit code strictly, and treat every one of these as fatal — never as a partial or provisional success:

- **0**: success — continue to the output checks below.
- **2**, code `approval_not_found`: no approval exists with the supplied ID — stop and report `APPROVAL_NOT_FOUND`.
- **2**, code `approval_response_error`, `approval_persistence_error`, or `approval_bridge_error`: the executor response was malformed, contained more than one row, the returned ID did not match, or a descriptor mismatch occurred — stop and report `APPROVAL_LOOKUP_VERIFICATION_FAILED`.
- **1**, code `approval_transport_error`: the MCP call or its normalization produced a transport failure — stop and report `APPROVAL_LOOKUP_MCP_CALL_FAILED`.
- **1**, code `internal_error`: stop and report `APPROVAL_LOOKUP_VERIFICATION_FAILED`.
- **any other code**: stop and report `APPROVAL_LOOKUP_VERIFICATION_FAILED`.

Never present a result as successful after any nonzero exit code, and never automatically retry any of these outcomes. Do not proceed to Stage 6 for any failure above.

### Approval lookup verify success-output checks

Require the parsed object to contain exactly `phase`, `operation`, `result`, with `phase` equal to `"verify"` and `operation` equal to `"load_risk_aware_approval_record"`. Require `result` to contain exactly the eighteen risk-aware approval-record fields (the existing sixteen fields plus `risk_level` and `required_approvals`), and verify `id` equals the candidate `approval_id` from Stage 0.

Call this the **trusted approval record**. It is used only to (a) supply the investigation ID for Stage 6 below, and (b) be handed, complete and unchanged, to Stage 12's simulation CLI — this command never performs its own local lifecycle eligibility check on it and never decides eligibility itself; `core.shadow_execution.simulate_case_update` alone determines `eligible_for_execution` and every warning. This command never displays the trusted approval record's identity-bearing fields (`requested_by`, `approved_by`, `rejected_by`, `consumed_by`) in any output.

## Stage 6 — Investigation Context Lookup Bridge Prepare

Before any simulation, obtain the referenced investigation's current `status`/`confidence` from the database itself, through the existing trusted lookup operation — never from the caller, and never from any value other than the trusted approval record's own `investigation_id`.

Construct exactly this object:

```json
{
  "phase": "prepare",
  "operation": "load_investigation_approval_context",
  "input": {
    "investigation_id": "<the trusted approval record's own investigation_id from Stage 5>"
  }
}
```

Send it through **stdin only** to `core.approval_bridge_cli`.

### Investigation lookup prepare exit handling

- **0**: potential success — continue to the output checks below.
- **2** (`approval_persistence_error`, `approval_bridge_error`) or **1** (`internal_error`): stop and report `INVESTIGATION_LOOKUP_PREPARE_FAILED`.
- **any other code**: stop and report `INVESTIGATION_LOOKUP_PREPARE_FAILED`.

### Investigation lookup prepare success-output checks

Require the parsed object to contain exactly `phase`, `operation`, `descriptor`, with `phase` equal to `"prepare"` and `operation` equal to `"load_investigation_approval_context"`. Require the descriptor to match the canonical fixed lookup shape already owned by `core.approval_persistence`: `operation` equal to `"select"`, `table` equal to `"investigations"`, `columns` equal exactly to `["investigation_id", "status", "confidence"]`, `filters` containing exactly `id`, and `limit` equal to `1`.

Call this the **prepared investigation-context descriptor**. Do not display it in any output.

## Stage 7 — Investigation Context Lookup MCP Adapter Prepare Call

Construct exactly this object:

```json
{
  "action": "prepare_call",
  "descriptor": "<the prepared investigation-context descriptor from Stage 6>"
}
```

Send it through **stdin only** to `core.approval_mcp_adapter_cli`.

### Investigation lookup adapter prepare_call exit handling

- **0**: potential success — continue to the output checks below.
- **2** (`approval_mcp_adapter_error`) or **1** (`internal_error`): stop and report `INVESTIGATION_LOOKUP_PREPARE_FAILED`.
- **any other code**: stop and report `INVESTIGATION_LOOKUP_PREPARE_FAILED`.

### Investigation lookup adapter prepare_call success-output checks

Require the parsed object to contain exactly `tool` and `arguments`, with `tool` equal exactly to `mcp__supabase__execute_sql` and `arguments` containing exactly one field, `query`, a nonblank string equal to the fixed `SELECT id AS investigation_id, status, confidence FROM public.investigations WHERE id = <encoded uuid> LIMIT 1;` template. Call this the **investigation-context MCP request**. Do not display it in any output.

## Stage 8 — Execute Through Supabase MCP (Investigation Context Lookup)

Invoke only the tool named in the investigation-context MCP request — `mcp__supabase__execute_sql` — using exactly the `arguments` the adapter returned, and only **once**. Do not rewrite, edit, or independently generate the SQL, append a second statement, use `apply_migration`, use a direct database client or connection string, use a REST request, or retry automatically.

Capture the tool's raw response exactly as returned. Do not parse, inspect, trust, or display it directly anywhere in this command — it is untrusted data and is handed unmodified to Stage 9 next. Call this the **raw investigation-context MCP result**.

If the tool call itself fails to return a result at all, stop and report `INVESTIGATION_LOOKUP_MCP_CALL_FAILED`.

## Stage 9 — Investigation Context Lookup MCP Adapter Normalize Response

Construct exactly this object:

```json
{
  "action": "normalize_response",
  "operation": "load_investigation_approval_context",
  "tool_response": "<the raw investigation-context MCP result from Stage 8, exactly as returned>"
}
```

Send it through **stdin only** to the same `core.approval_mcp_adapter_cli` module.

### Investigation lookup normalize_response exit handling

- **0**: potential success — continue to the output checks below.
- **2** (`approval_mcp_adapter_error`) or **1** (`internal_error`): stop and report `INVESTIGATION_LOOKUP_NORMALIZATION_FAILED`.
- **any other code**: stop and report `INVESTIGATION_LOOKUP_NORMALIZATION_FAILED`.

### Investigation lookup normalize_response success-output checks

Require the parsed object to be exactly one of `{"kind": "rows", "rows": [...]}` or `{"kind": "transport_error"}`. A `transport_error` kind is passed forward unchanged to Stage 10, never reinterpreted as a success. Call this the **normalized investigation-context response**.

## Stage 10 — Investigation Context Lookup Bridge Verify

Construct exactly this object:

```json
{
  "phase": "verify",
  "operation": "load_investigation_approval_context",
  "input": "<the exact same input object used in Stage 6>",
  "prepared_descriptor": "<the prepared investigation-context descriptor from Stage 6>",
  "executor_response": "<the normalized investigation-context response from Stage 9>"
}
```

Send it through **stdin only** to `core.approval_bridge_cli`.

### Investigation lookup verify exit handling

Interpret the exit code strictly, and treat every one of these as fatal:

- **0**: success — continue to the output checks below.
- **2**, code `approval_not_found`: the investigation does not exist — stop and report `INVESTIGATION_NOT_FOUND`.
- **2**, code `approval_response_error`, `approval_persistence_error`, or `approval_bridge_error`: a malformed context row, a descriptor mismatch, or another deterministic failure — stop and report `INVESTIGATION_LOOKUP_VERIFICATION_FAILED`.
- **1**, code `approval_transport_error`: stop and report `INVESTIGATION_LOOKUP_MCP_CALL_FAILED`.
- **1**, code `internal_error`: stop and report `INVESTIGATION_LOOKUP_VERIFICATION_FAILED`.
- **any other code**: stop and report `INVESTIGATION_LOOKUP_VERIFICATION_FAILED`.

Never present a result as successful after any nonzero exit code, and never automatically retry any of these outcomes. Do not proceed to Stage 11 for any failure above, and never invoke the simulation CLI without a Stage 10 success.

### Investigation lookup verify success-output checks

Require the parsed object to contain exactly `phase`, `operation`, `result`, with `phase` equal to `"verify"` and `operation` equal to `"load_investigation_approval_context"`. Require `result` to contain exactly `investigation_id`, `status`, `confidence` — no other field. Verify `result.investigation_id` equals the trusted approval record's own `investigation_id` from Stage 5.

Call this the **trusted investigation context**. It is the sole source of the investigation's current `status`/`confidence` anywhere in this workflow — the caller never supplies, and this command never accepts, either value.

## Stage 11 — Pin the Simulation Timestamp

Only after Stage 10 succeeds, obtain exactly one current, timezone-aware UTC timestamp, canonicalized to ISO-8601 `...Z` form. Generate it exactly once for this invocation:

- the caller can never supply or override it;
- it is never regenerated between this stage and Stage 12 — the exact same string value is reused;
- the mechanism used to obtain it is never displayed in any output.

`core.shadow_execution` and `core.shadow_execution_cli` never read the system clock themselves — this stage is the sole source of `simulated_at` anywhere in this workflow.

## Stage 12 — Invoke the Shadow Execution CLI

Construct exactly this object, in exactly this key order:

```json
{
  "approval_record": "<the trusted approval record from Stage 5, unchanged>",
  "investigation_context": "<the trusted investigation context from Stage 10, unchanged>",
  "simulated_at": "<the pinned timestamp from Stage 11>"
}
```

Never add, remove, rename, or transform any field. Never substitute a caller-supplied value for any of the three fields. Never construct a second action payload, a second investigation ID, a risk override, a lifecycle override, a warning override, a rollback override, or any mutation/execution flag.

Send it through **stdin only** to `py -m core.shadow_execution_cli` (or the equivalent selected launcher).

### Simulation CLI exit handling

- **0**: success — the report is complete regardless of its own `eligible_for_execution` value. Continue to Required Output below.
- **2**: a deterministic shadow-execution validation failure — stop and report `SIMULATION_VALIDATION_FAILED`. This can only occur from a genuinely malformed trusted record or context reaching the CLI, since both were already bridge-verified in Stages 5 and 10.
- **1**: an unexpected internal failure — stop and report `SIMULATION_INTERNAL_FAILURE`.
- **any other code**: stop and report `SIMULATION_INTERNAL_FAILURE`.

Never automatically retry any of these outcomes, and never fall back to displaying a partially-constructed or hand-assembled report.

### Simulation CLI success-output checks

Require stdout to be exactly one JSON object containing exactly the fifteen fields `core.shadow_execution.simulate_case_update` always returns: `simulation_version`, `approval_id`, `investigation_id`, `action_type`, `risk_level`, `required_approvals`, `eligible_for_execution`, `current_state`, `proposed_state`, `changed_fields`, `unchanged_fields`, `warnings`, `rollback`, `simulated_at`, `mutation_performed`. Require `mutation_performed` to be exactly `false` — a report where this field is missing, `true`, or any value other than the literal `false` is never displayed as a success; treat it as `SIMULATION_VALIDATION_FAILED` instead. Call this the **shadow-execution report**.

## Required Output

Produce, only after Stage 12 succeeds:

- Approval ID
- Investigation ID
- Action Type
- Risk Level
- Required Approval Count
- Eligible for Execution (`true`/`false`, exactly as reported)
- Current State (`status`, `confidence`)
- Proposed State (`status`, `confidence`)
- Changed Fields (each as `field`, `before`, `after`)
- Unchanged Fields
- Warnings (each as `code`, `severity`, `message`, `blocks_execution`) — display every warning the report contains, including for an ineligible report; never omit a blocking warning
- Rollback (`reversible`, `strategy`, `limitations`)
- Simulated At
- **`mutation_performed: false`**
- An explicit statement equivalent to: **"No approval, review, or investigation record was modified."**

### When `eligible_for_execution` is `true`

State clearly that the action is currently eligible for execution, that this output is only a simulation, that no investigation or approval mutation occurred, and that `/apply-case-update` remains a separate, later, explicit action this command never triggers.

### When `eligible_for_execution` is `false`

Still display the complete, valid report and every blocking warning it contains. State clearly that the simulation itself completed successfully, that the approval is not currently eligible for execution, and that no mutation occurred. Never attempt a fallback execution, never suggest bypassing the blocking condition, and never treat this outcome as a command transport failure — it is a normal, successful simulation result.

Never display:

- `requested_by`, `approved_by`, `rejected_by`, `consumed_by`, or any other identity field;
- the raw stored `action_payload` (only `current_state`/`proposed_state`/`changed_fields`/`unchanged_fields`, as already produced by the report, may ever be shown);
- normalized identities;
- raw SQL;
- bridge descriptors;
- MCP request or tool-call objects;
- database connection or ownership metadata;
- a project URL, project reference, credential, access token, or service-role value;
- an environment variable;
- a filesystem path;
- a stack trace, exception class name, or raw internal exception message.

## Required Failure Categories

Use only these fixed, non-sensitive failure categories. Never expose a raw PostgreSQL error, generated SQL, a credential, a project URL, a project reference, an access token, a stack trace, an exception class name, or an internal owner detail in any of them.

### INVALID_INPUT

Stage 0 rejecting a missing, multi-token, JSON-shaped, or structurally suspicious (SQL/shell/path/URL-fragment-looking) caller argument.

### APPROVAL_LOOKUP_PREPARE_FAILED

Stage 1 or Stage 2, for the approval lookup, reporting a deterministic validation failure (including a malformed `approval_id`) or an unexpected internal failure.

### APPROVAL_LOOKUP_MCP_CALL_FAILED

Stage 3's tool call itself failing to return a result, or Stage 5 classifying the outcome as `approval_transport_error`.

### APPROVAL_LOOKUP_NORMALIZATION_FAILED

Stage 4 reporting a deterministic validation failure or an unexpected internal failure.

### APPROVAL_NOT_FOUND

Stage 5 reporting `approval_not_found` — no approval exists with the supplied ID.

### APPROVAL_LOOKUP_VERIFICATION_FAILED

Stage 5 reporting a malformed, multiple-row, or ID-mismatched response, a descriptor mismatch, or any other deterministic or internal failure not covered above.

### INVESTIGATION_LOOKUP_PREPARE_FAILED

Stage 6 or Stage 7, for the investigation-context lookup, reporting a deterministic validation failure or an unexpected internal failure.

### INVESTIGATION_LOOKUP_MCP_CALL_FAILED

Stage 8's tool call itself failing to return a result, or Stage 10 classifying the outcome as `approval_transport_error`.

### INVESTIGATION_LOOKUP_NORMALIZATION_FAILED

Stage 9 reporting a deterministic validation failure or an unexpected internal failure.

### INVESTIGATION_NOT_FOUND

Stage 10 reporting `approval_not_found` — the trusted approval record's own `investigation_id` no longer resolves to an existing investigation.

### INVESTIGATION_LOOKUP_VERIFICATION_FAILED

Stage 10 reporting a malformed or ID-mismatched response, a descriptor mismatch, or any other deterministic or internal failure not covered above.

### SIMULATION_VALIDATION_FAILED

Stage 12 reporting exit code 2, or a Stage 12 success-output check failing (a malformed report, a wrong field set, or `mutation_performed` not exactly `false`).

### SIMULATION_INTERNAL_FAILURE

Stage 12 reporting exit code 1 or any other unexpected code.

### SIMULATION_CLI_UNAVAILABLE

The Python launcher or module-import check failing before any Stage below runs.

Do not automatically retry any failure in any category above.

## Failure and No-Fallback Policy

For every stage:

- stop on an unambiguous failure and report the matching category above;
- do not silently continue to the next stage;
- do not build a substitute trusted record or trusted context by hand;
- do not manually repair a malformed lookup response;
- do not switch to direct SQL, a direct database client, a REST call, or `apply_migration`;
- do not automatically retry any stage;
- do not invoke `/apply-case-update`, `/review-approval`, or `/request-case-update` from within this command;
- do not consume, approve, reject, or otherwise mutate the approval;
- do not update the investigation.

Because every database interaction this command performs is read-only, a caller may always safely re-run the entire command later — but this command itself never performs that retry automatically, and never hides it.

## Security Boundaries

This command must never:

- accept a caller-supplied `investigation_id`, `status`, `confidence`, `action_type`, `action_payload`, `current_state`, `proposed_state`, `simulated_at`, `risk_level`, or `required_approvals`;
- accept a caller-supplied SQL fragment, bridge descriptor, MCP request object, or RPC parameter;
- accept more than one caller argument;
- derive the investigation ID for Stage 6 from anything other than the trusted approval record's own `investigation_id`;
- construct SQL directly, hand-edit adapter-generated SQL, or interpolate caller-supplied text as a SQL identifier;
- bypass `core.approval_bridge_cli`, `core.approval_mcp_adapter_cli`, or `core.shadow_execution_cli`;
- reimplement eligibility rules, warning rules, rollback classification, or state-diff calculation — every one of those belongs entirely to `core.shadow_execution`;
- call `insert_risk_aware_pending_approval`, `apply_multi_review_transition`, `apply_approval_consumption`, `record_approval_review_and_promote_status`, or `consume_approval_and_update_investigation_state`;
- issue an `INSERT`, `UPDATE`, `DELETE`, `UPSERT`, or `apply_migration` of any kind;
- create, approve, reject, review, or consume an approval;
- update `public.investigations` through any path;
- perform more than the two read-only lookup operations named in this document anywhere in this workflow;
- retry any stage automatically, or fall back to a substitute record, a direct query, or a different mutation path after any failure;
- claim that a simulation was executed, applied, or that any state actually changed;
- display any identity field, raw `action_payload`, SQL, descriptor, MCP request object, credential, project reference, environment variable, filesystem path, or stack trace.

The only permitted database interactions anywhere in this command are the two existing, already-committed, read-only lookup operations — `load_risk_aware_approval_record` and `load_investigation_approval_context` — each executed exactly once per invocation, through the existing bridge and adapter, never more.

## Example Invocation

```
/simulate-case-update 7d3f0e4a-4c5f-4d0a-9b12-345678901bcd
```

## Safety Rules

- Accept exactly one caller argument: the approval UUID. Never accept a JSON envelope, a second argument, or any derived simulation field.
- Never derive the investigation ID from anything other than the trusted approval record's own `investigation_id`.
- Never accept a caller-supplied current state, proposed state, timestamp, risk level, or required-approval count.
- Never generate `simulated_at` more than once per invocation, and never let the caller supply or override it.
- Never bypass `core.approval_bridge_cli`, `core.approval_mcp_adapter_cli`, or `core.shadow_execution_cli`, and never reimplement any rule those modules already own.
- Never create, approve, reject, review, or consume an approval, and never update an investigation, through this command.
- Never call either mutating RPC (`record_approval_review_and_promote_status`, `consume_approval_and_update_investigation_state`) or any `INSERT`/`UPDATE`/`DELETE`/`UPSERT`/`apply_migration`.
- Never treat `eligible_for_execution: false` as a command failure, and never attempt a fallback execution.
- Never claim a preview was executed — always state plainly that no approval, review, or investigation record was modified.
- Never retry any stage automatically, and never fall back to a substitute record or a direct query after a failure.
- Never expose a raw PostgreSQL error, generated SQL, a credential, a project URL, a project reference, an access token, a stack trace, an exception class name, or an internal owner detail.
- `/apply-case-update` remains the only command that ever actually applies a change — `/simulate-case-update` never does, and never claims to.
