---
description: Atomically consume one approved, risk-aware case-update approval and apply its stored change to the investigation
argument-hint: "[approval UUID, consumed_by]"
---

# ThreatTrace Apply Case Update Workflow

`/apply-case-update` consumes exactly one existing **approved** risk-aware approval and applies its stored proposed `status`/`confidence` to the referenced investigation, in a single atomic database operation. This command is only the **consumption** phase of the approval lifecycle:

Load trusted risk-aware approval → local lifecycle eligibility check → validate consumption → call one atomic RPC → approval becomes consumed → investigation is updated

This command never separately updates the approval and the investigation — both changes commit together, or neither does, through the existing atomic PostgreSQL function `public.consume_approval_and_update_investigation_state`, invoked exactly once through the existing two-phase prepare/verify approval bridge (`core.approval_bridge_cli`) and the strict Supabase MCP descriptor adapter (`core.approval_mcp_adapter_cli`) — never a hand-written SQL statement, never a direct database client, never a REST call, and never the legacy direct-update path used by `/update-case`. This is the same atomic function and the same five-parameter, nineteen-column contract `/apply-case-update` already used before Block 6 — it was never renamed, and no second consumption path exists. Its own conditional `UPDATE ... WHERE ...` clause already independently re-verifies, live, whichever authorization path the approval actually requires: the original one-review path for a legacy or low/medium-risk record, or the risk-aware path (sufficient distinct approve reviews, no rejection review, and requester/reviewer exclusion) for a high/medium-required, high/critical-risk record — this command never re-implements, downgrades, or bypasses that check.

A risk-aware approval may require one distinct reviewer (`required_approvals` `1`, low/medium risk) or two distinct reviewers (`required_approvals` `2`, high/critical risk), and only reaches `approved` — the sole consumable status — once every required review has actually been recorded; a `partially_approved` approval (the first of two reviews only) can never be consumed. This command never counts reviews itself and never recalculates risk — `risk_level`/`required_approvals` are always read from the trusted loaded record alone, and the atomic RPC remains the sole final authority over whether enough genuine, distinct reviews actually exist.

## Consumption Input

$ARGUMENTS

## Input Envelope

The input must be exactly one JSON object. Reject anything else — malformed JSON, trailing non-whitespace content after the object, or a top-level JSON value that is not an object.

Allow exactly these fields:

Required:

- `approval_id`
- `consumed_by`

Reject every field this list does not name. In particular, always reject:

- `investigation_id`
- `status`
- `confidence`
- `action_type`
- `action_payload`
- `requested_by`
- `requested_at`
- `reviewed_by`
- `approved_by`
- `approved_at`
- `rejected_by`
- `rejected_at`
- `rejection_reason`
- `consumed_at`
- `created_at`
- `expires_at`
- `approval_status`
- `transition`
- `transition_plan`
- `descriptor`
- `sql`
- `table`
- `function`

None of these twenty-three fields is ever accepted from caller input. `approval_id` alone identifies which record to consume — the caller can never replace `investigation_id`, `status`, `confidence`, `action_type`, `action_payload`, `requested_by`, `requested_at`, `reviewed_by`, `approved_by`, `approved_at`, `rejected_by`, `rejected_at`, `rejection_reason`, or `expires_at`, all of which remain exactly whatever the original request and review already stored. `consumed_at` is never accepted either — the existing transition validator generates it, exactly as it already does for `/review-approval`'s `reviewed_at`. `created_at` is a database-generated field this command never sets. `approval_status`, `transition`, `transition_plan`, and `descriptor` are never accepted — the genuine transition plan and operation descriptor are always generated internally, from the existing public validator, bridge, and adapter, never from caller-supplied text. `sql`, `table`, and `function` name no field this command's request contract has ever defined.

Also always reject every one of these additional Block 6 fields — none of them has ever been part of this command's own request contract, and every one of them names either a value this command must always load or derive itself (never accept from the caller) or a mechanism internal to the atomic RPC's own live re-authorization this command never exposes to caller input:

- `risk_level`
- `required_approvals`
- `current_investigation`
- `current_status`
- `current_confidence`
- `requested_by_normalized`
- `existing_reviews`
- `approval_count`
- `expected_investigation_id`
- `expected_action_type`
- `expected_approval_status`
- `parameters`

`risk_level` and `required_approvals` are never accepted because they were already derived deterministically and stored on the approval when it was requested — this command only ever loads and re-displays them, never recomputes or replaces them. `current_investigation`/`current_status`/`current_confidence` are never accepted because this command never re-evaluates the investigation's current state at all — the atomic RPC applies the stored `action_payload` directly, never a caller's own claim about the investigation. `requested_by_normalized` and `existing_reviews` are never accepted because both are internal artifacts of the request and review workflows this command never reconstructs or re-derives. `approval_count` is never accepted because review counting remains entirely the atomic RPC's own live responsibility, never this command's. `expected_investigation_id`, `expected_action_type`, and `expected_approval_status` are never accepted because every one of them is always derived from the trusted loaded record alone, never from a separate caller-supplied field — accepting them directly would let a caller substitute a different binding than the one actually stored. `parameters` names no field this command's request contract has ever defined — a caller can never supply RPC parameters directly; every parameter is always generated fresh from validated, trusted data.

## Request Validation

Perform every validation step below, in order, before any Supabase operation:

1. Parse `$ARGUMENTS` as exactly one JSON value.
2. Reject malformed JSON.
3. Reject trailing non-whitespace content after the one JSON value.
4. Reject a top-level value that is not a JSON object.
5. Reject any field not listed under Input Envelope.
6. Require `approval_id` to be present.
7. Require `consumed_by` to be present.
8. Reject a blank `consumed_by` (empty after trimming whitespace).
9. Delegate UUID, identity, timestamp, expiry, status, chronology, and transition validation entirely to the existing public validators and CLIs (`core.approval_transition_cli`, wrapping `core.approval_transition.validate_approval_transition`) in Stage 6 below.

Do not implement a separate, competing validator in this document — every structural rule beyond the three local checks above (JSON shape, field presence, blank `consumed_by`) belongs to that existing validator, and this command only ever reuses it.

### `approval_id`

Must be a string the bridge/adapter can canonicalize as a structurally valid UUID. This command performs no local UUID format check of its own — Stage 1 rejects a malformed value.

### `consumed_by`

`consumed_by` is a **caller-supplied claimed consumer identity**. It is never authenticated, never verified, never cryptographically proven, never derived from Supabase Auth or any other identity provider, and it is never the database service role — it is simply whatever the caller typed, trimmed of surrounding whitespace. This command performs no login, no session check, and no identity lookup of any kind. The existing public validator does not require `consumed_by` to differ from the stored `requested_by` or `approved_by` — consumption is execution bookkeeping, not a new authorization decision, exactly as `core.approval_transition`'s own docstring already states. This command does not invent any additional identity-separation rule beyond what that validator already enforces. The stored value is always displayed and described as a **claimed consumer identity**, never as an authenticated or verified one.

## Claimed Identity Boundary

`consumed_by` is a caller-supplied claimed identity, nothing more. This command must never describe it, or the resulting consumption record, as authenticated, verified, trusted, derived from Supabase Auth, cryptographically proven, or the database service role. The final output always labels it explicitly as a **claimed consumer identity**, and the original requester's and reviewer's own stored identities are always labeled a **claimed requester identity** and a **claimed reviewer identity** respectively.

## Risk-Aware Authorization

### One-review approval

A low- or medium-risk request may be consumed only after it reaches `approved` through its required one-review flow: a single distinct reviewer's `/review-approval` approval, from someone other than the original requester, is sufficient. `required_approvals` is `1` for this path.

### Two-review approval

A high- or critical-risk request may be consumed only after:

- the first review moved it to `partially_approved`;
- the second distinct review moved it to `approved`.

`required_approvals` is `2` for this path, and a `partially_approved` request cannot be consumed — Stage 6 below fails it closed before any further stage runs.

This command never counts reviews itself and never trusts a caller-supplied count — the database RPC alone remains responsible for independently re-verifying, from the live `approval_reviews` rows, that every required distinct review actually exists, that none of them is a rejection, and that no counted reviewer is the original requester.

### Legacy compatibility

`public.consume_approval_and_update_investigation_state` retains its own database-controlled legacy compatibility branch for approvals created before Block 6 (`requested_by_normalized IS NULL`, `required_approvals = 1`) — that branch belongs entirely to the RPC's own live `WHERE` clause, and this command neither removes nor redesigns it here. This command also never intentionally downgrades a new risk-aware record into that legacy path, and never chooses between the RPC's two internal authorization branches itself — that choice is always made by the RPC's own live check against the row it is actually consuming, never by this command.

## Python Launcher Selection

Use the existing project convention for selecting a Python launcher:

1. Try `py`.
2. Otherwise try `python3`.
3. Otherwise use a `python` executable only after confirming it resolves to Python 3.10 or later.

Select one launcher and reuse the same launcher for every CLI invocation in this workflow.

Before continuing to any Supabase or MCP operation, confirm the selected launcher can import all three required modules:

- `core.approval_transition_cli`
- `core.approval_bridge_cli`
- `core.approval_mcp_adapter_cli`

If no launcher can be selected, or the import check fails for any of the three modules, stop and report that the approval-consumption Python CLIs are unavailable. Do not install any package. Do not modify the environment.

## Safe CLI Transport

Invoke all CLIs through **stdin only**, exactly following the safe invocation pattern already established by `/add-evidence`, `/prepare-hayabusa-evidence`, `/decision-review`, `/request-case-update`, and `/review-approval`. Never:

- pass JSON through command-line arguments;
- create a temporary JSON file;
- interpolate caller content directly into executable shell code;
- write request data to disk.

## Stage 1 — Lookup Bridge Prepare

Use the existing two-phase approval bridge, in its prepare phase, to construct the exact `load_risk_aware_approval_record` operation descriptor — bound only to the supplied `approval_id`, never to any other filter. This is the same eighteen-field risk-aware lookup `/review-approval` already uses — never the plain Block 5 `load_approval_record`, which does not surface `risk_level`/`required_approvals` at all.

Construct exactly this object:

```json
{
  "phase": "prepare",
  "operation": "load_risk_aware_approval_record",
  "input": {
    "approval_id": "<the canonical approval UUID from the request>"
  }
}
```

Send it through **stdin only** to:

- Windows: `py -m core.approval_bridge_cli`
- macOS or Linux: `python3 -m core.approval_bridge_cli`
- Only fall back to plain `python -m core.approval_bridge_cli` if it is confirmed to resolve to Python 3.10 or later.

### Lookup prepare exit handling

- **0**: potential success — continue to the output checks below.
- **2** (`approval_persistence_error`, `approval_bridge_error`) or **1** (`internal_error`): stop and report `LOOKUP_PREPARE_FAILED`.
- **any other code**: stop and report `LOOKUP_PREPARE_FAILED`.

### Lookup prepare success-output checks

Reject the output when stderr is nonempty, stdout is empty, stdout is not valid JSON, stdout contains more than one JSON value, or the parsed value is not a JSON object.

Require the parsed object to contain exactly `phase`, `operation`, `descriptor`, with `phase` equal to `"prepare"` and `operation` equal to `"load_risk_aware_approval_record"`. Require the descriptor to match the canonical select-descriptor shape already owned by `core.approval_persistence`: `operation` equal to `"select"`, `table` equal to `"approvals"`, `columns` equal to the full eighteen-field risk-aware approval record contract (the existing sixteen fields plus `risk_level` and `required_approvals`), `filters` containing exactly `id` equal to the canonical approval UUID, and `limit` equal to `2`.

Call this the **prepared lookup descriptor**.

## Stage 2 — Lookup MCP Adapter Prepare Call

Construct exactly this object:

```json
{
  "action": "prepare_call",
  "descriptor": "<the prepared lookup descriptor from Stage 1>"
}
```

Send it through **stdin only** to:

- Windows: `py -m core.approval_mcp_adapter_cli`
- macOS or Linux: `python3 -m core.approval_mcp_adapter_cli`
- Only fall back to plain `python -m core.approval_mcp_adapter_cli` if it is confirmed to resolve to Python 3.10 or later.

### Lookup adapter prepare_call exit handling

- **0**: potential success — continue to the output checks below.
- **2** (`approval_mcp_adapter_error`) or **1** (`internal_error`): stop and report `LOOKUP_PREPARE_FAILED`.
- **any other code**: stop and report `LOOKUP_PREPARE_FAILED`.

### Lookup adapter prepare_call success-output checks

Require the parsed object to contain exactly `tool` and `arguments`, with `tool` equal exactly to:

```
mcp__supabase__execute_sql
```

and `arguments` containing exactly one field, `query`, a nonblank string. Call this the **lookup MCP request**.

## Stage 3 — Execute Through Supabase MCP (Lookup)

Invoke only the tool named in the lookup MCP request — `mcp__supabase__execute_sql` — using exactly the `arguments` the adapter returned. Do not rewrite, edit, or independently generate the SQL, append a second statement, use `apply_migration`, use a direct database client or connection string, use a REST request, or retry automatically.

Capture the tool's raw response exactly as returned. Do not parse, inspect, or trust the raw MCP result directly anywhere in this command — it is untrusted data and is handed unmodified to Stage 4 next. Call this the **raw lookup MCP result**.

If the tool call itself fails to return a result at all, stop and report `LOOKUP_MCP_CALL_FAILED`.

## Stage 4 — Lookup MCP Adapter Normalize Response

Construct exactly this object:

```json
{
  "action": "normalize_response",
  "operation": "load_risk_aware_approval_record",
  "tool_response": "<the raw lookup MCP result from Stage 3, exactly as returned>"
}
```

Send it through **stdin only** to the same `core.approval_mcp_adapter_cli` module used in Stage 2.

### Lookup normalize_response exit handling

- **0**: potential success — continue to the output checks below.
- **2** (`approval_mcp_adapter_error`) or **1** (`internal_error`): stop and report `LOOKUP_NORMALIZATION_FAILED`.
- **any other code**: stop and report `LOOKUP_NORMALIZATION_FAILED`.

### Lookup normalize_response success-output checks

Require the parsed object to be exactly one of the two canonical shapes:

```json
{"kind": "rows", "rows": [...]}
```

```json
{"kind": "transport_error"}
```

Call this the **normalized lookup response**. A `transport_error` kind is not itself a local command failure at this stage — pass it forward unchanged to Stage 5, exactly as the bridge's own verify phase already expects to receive it. Never reinterpret it as `{"kind": "rows", "rows": []}` or as any kind of success.

## Stage 5 — Lookup Bridge Verify

Construct exactly this object:

```json
{
  "phase": "verify",
  "operation": "load_risk_aware_approval_record",
  "input": "<the exact same input object used in Stage 1>",
  "prepared_descriptor": "<the prepared lookup descriptor from Stage 1>",
  "executor_response": "<the normalized lookup response from Stage 4>"
}
```

Send it through **stdin only** to `core.approval_bridge_cli`.

### Lookup verify exit handling

Interpret the exit code strictly, and treat every one of these as fatal — never as a partial or provisional success:

- **0**: success — continue to the output checks below.
- **2**, code `approval_not_found`: no approval exists with the supplied ID — stop and report `APPROVAL_NOT_FOUND`.
- **2**, code `approval_response_error`, `approval_persistence_error`, or `approval_bridge_error`: the executor response was malformed, contained more than one row, the returned ID did not match, or a descriptor mismatch occurred — stop and report `LOOKUP_VERIFICATION_FAILED`.
- **1**, code `approval_transport_error`: the MCP call or its normalization produced a transport failure — stop and report `LOOKUP_MCP_CALL_FAILED`.
- **1**, code `internal_error`: stop and report `LOOKUP_VERIFICATION_FAILED`.
- **any other code**: stop and report `LOOKUP_VERIFICATION_FAILED`.

Never present a result as successful after any nonzero exit code, and never automatically retry any of these outcomes.

### Lookup verify success-output checks

Require the parsed object to contain exactly `phase`, `operation`, `result`, with `phase` equal to `"verify"` and `operation` equal to `"load_risk_aware_approval_record"`. Require `result` to contain exactly the eighteen risk-aware approval-record fields (the existing sixteen fields plus `risk_level` and `required_approvals`), and verify `id` equals the canonical `approval_id` from the request.

Call this the **trusted approval record**. It is used only for display, local eligibility checks, and preparation — it is **not final authorization**. The atomic RPC in Stage 10 independently re-checks every relevant condition itself, from the live database row (and, for a risk-aware record, the live `approval_reviews` table), and remains the sole final authority over whether consumption actually succeeds. `risk_level` and `required_approvals` are read from this trusted record alone — this command never recalculates either, and never accepts a caller-supplied replacement for them.

## Stage 6 — Local Lifecycle Eligibility Check

Using only the trusted approval record's own `status`, fail closed before any further stage runs unless `status` is exactly `approved` — the sole consumable status. This local check is a fast, user-friendly denial, never the final authorization decision; every one of these conditions is independently re-verified again, live, by the atomic RPC in Stage 10.

- `status` is `pending`: consumption is not possible yet — stop and report `CONSUMPTION_NOT_ALLOWED`, stating plainly that approval review is required first.
- `status` is `partially_approved`: exactly one of the two required distinct reviews has been recorded — stop and report `CONSUMPTION_NOT_ALLOWED`, stating plainly that another, distinct reviewer is still required, and that `/apply-case-update` cannot be used yet.
- `status` is `rejected`: stop and report `CONSUMPTION_NOT_ALLOWED`, stating plainly that the request cannot be applied.
- `status` is `consumed`: stop and report `CONSUMPTION_NOT_ALLOWED`, stating plainly that it was already applied and that replay is blocked.
- `status` is `approved`: continue to the projection step below.

This command never counts existing reviews and never accepts a caller-supplied review count or approval count to make this decision — the trusted record's own `status` (already promoted only by the atomic multi-review RPC `record_approval_review_and_promote_status` `/review-approval` uses) is the only signal read here.

When `status` is `approved`, build a **projected sixteen-field record**: the trusted approval record's own sixteen base fields (`id`, `investigation_id`, `action_type`, `action_payload`, `requested_by`, `requested_at`, `status`, `approved_by`, `approved_at`, `rejected_by`, `rejected_at`, `rejection_reason`, `expires_at`, `consumed_by`, `consumed_at`, `created_at`), copied byte-for-byte, with exactly `risk_level` and `required_approvals` omitted. This projection changes no value and rebuilds nothing — it exists only because the existing Block 5 transition validator and consumption bridge operation used in Stages 7 and 8 below do not yet accept those two additive fields on their own `current_record` contract. Every later stage reads the investigation binding, action type, and action payload from this projected record alone, never independently reconstructing them.

## Stage 7 — Consumption Eligibility and Transition Validation

Using only the projected sixteen-field record, require, entirely by delegating to the existing public transition validator:

1. its current `status` is `approved` (already confirmed in Stage 6; the validator re-confirms it independently from the projected record);
2. `approved_by` and `approved_at` are present and satisfy the existing approved-record contract, and `rejected_by`, `rejected_at`, `rejection_reason`, `consumed_by`, `consumed_at` are all currently `null`;
3. the generated consumption time is at or after `approved_at`, and strictly before `expires_at` when one is set — equality with `expires_at` fails, exactly as the existing validator already enforces.

Construct the transition request from only the caller's own submitted `consumed_by`, plus the projected record's own frozen bindings — never from `status`, `confidence`, `action_type`, or `action_payload` of any kind, and never with a caller-supplied `consumed_at`:

```json
{
  "current_record": "<the projected sixteen-field record from Stage 6>",
  "transition_request": {
    "transition": "consume",
    "consumed_by": "<the claimed consumer identity, as typed>",
    "expected_investigation_id": "<the projected record's own investigation_id>",
    "expected_action_type": "<the projected record's own action_type>"
  }
}
```

Send it through **stdin only** to `core.approval_transition_cli`.

### Transition CLI exit handling

- **0**: potential success — continue to the output checks below.
- **2**: deterministic transition-validation failure. Inspect the returned message to classify it, without ever printing the raw message to the caller:
  - a message stating the current status must be `'approved'` (the approval is pending, rejected, or already consumed) — stop and report `CONSUMPTION_NOT_ALLOWED`;
  - a message stating `consumed_at` must be strictly before `expires_at` (the approval has expired) — stop and report `CONSUMPTION_NOT_ALLOWED`;
  - any other validation message (a malformed loaded record, a blank identity, an internally inconsistent binding) — stop and report `TRANSITION_VALIDATION_FAILED`.
- **1**: unexpected internal failure — stop and report `TRANSITION_VALIDATION_FAILED`.
- **any other code**: stop and report `TRANSITION_VALIDATION_FAILED`.

Do not manually construct or forge a transition plan under any circumstance, and never manually construct its `set_fields` — only a plan this CLI itself produced from the projected record may ever be used in Stage 8.

### Transition CLI success-output checks

Reject the output when stderr is nonempty, stdout is empty, stdout is not valid JSON, stdout contains more than one JSON value, or the parsed value is not a JSON object.

Require the parsed object to contain exactly `approval_id`, `from_status`, `to_status`, `set_fields`, `expected_investigation_id`, `expected_action_type`. Verify `approval_id` equals the projected record's own `id`, `from_status` equals `"approved"`, `to_status` equals `"consumed"`, `expected_investigation_id` equals the projected record's own `investigation_id`, and `expected_action_type` equals the projected record's own `action_type`.

Call this the **genuine consume transition plan**.

## Stage 8 — Consumption Bridge Prepare

Use the existing two-phase approval bridge, in its prepare phase, to construct the exact `apply_approval_consumption` operation descriptor — never a hand-written descriptor. This is the same existing Block 5 consumption operation — never renamed, and never duplicated into a second consumption path for risk-aware records.

Construct exactly this object:

```json
{
  "phase": "prepare",
  "operation": "apply_approval_consumption",
  "input": {
    "current_record": "<the projected sixteen-field record from Stage 6>",
    "transition_plan": "<the genuine consume transition plan from Stage 7>"
  }
}
```

Send it through **stdin only** to `core.approval_bridge_cli`.

### Consumption prepare exit handling

- **0**: potential success — continue to the output checks below.
- **2** (`approval_persistence_error`, `approval_bridge_error`) or **1** (`internal_error`): stop and report `CONSUMPTION_PREPARE_FAILED`.
- **any other code**: stop and report `CONSUMPTION_PREPARE_FAILED`.

### Consumption prepare success-output checks

Require the parsed object to contain exactly `phase`, `operation`, `descriptor`, with `phase` equal to `"prepare"` and `operation` equal to `"apply_approval_consumption"`.

Require the descriptor to match the canonical RPC-call shape already owned by `core.approval_persistence`: `operation` equal to `"rpc"`, `function` equal to `"consume_approval_and_update_investigation_state"`, and `parameters` containing exactly `approval_id` (equal to the canonical approval ID), `expected_investigation_id` (equal to the projected record's own `investigation_id`), `expected_action_type` (equal to `"update_investigation_state"`), `consumed_by` (equal to the claimed consumer identity), and `consumed_at` (the validator-generated timestamp from Stage 7) — the same five parameters this RPC has always accepted, never a sixth `risk_level`/`required_approvals`/review-count parameter of any kind; the RPC re-derives its own risk-aware authorization entirely from the live `approvals` and `approval_reviews` rows, never from a caller-supplied parameter. The descriptor must never contain `status` or `confidence` — the stored `action_payload` remains the sole source the atomic function itself later reads to derive the investigation update.

Call this the **prepared atomic descriptor**. Do not generate the RPC SQL directly from it — that remains the MCP adapter's exclusive concern, next.

## Stage 9 — Consumption MCP Adapter Prepare Call

Construct exactly this object:

```json
{
  "action": "prepare_call",
  "descriptor": "<the prepared atomic descriptor from Stage 8>"
}
```

Send it through **stdin only** to `core.approval_mcp_adapter_cli`.

### Consumption adapter prepare_call exit handling

- **0**: potential success — continue to the output checks below.
- **2** (`approval_mcp_adapter_error`) or **1** (`internal_error`): stop and report `CONSUMPTION_PREPARE_FAILED`.
- **any other code**: stop and report `CONSUMPTION_PREPARE_FAILED`.

### Consumption adapter prepare_call success-output checks

Require the parsed object to contain exactly `tool` and `arguments`, with `tool` equal exactly to `mcp__supabase__execute_sql` and `arguments` containing exactly one field, `query`, a nonblank string naming a call to the existing atomic function:

```
public.consume_approval_and_update_investigation_state(
    uuid,
    uuid,
    text,
    text,
    timestamptz
)
```

Call this the **atomic MCP request**.

## Stage 10 — Execute Through Supabase MCP (Atomic Consumption)

Invoke only the tool named in the atomic MCP request — `mcp__supabase__execute_sql` — using exactly the `arguments` the adapter returned, and only **once**. Do not:

- generate the RPC SQL directly in this document, or rewrite the generated SQL in any way;
- append or execute a second SQL statement of any kind;
- update `public.approvals` directly;
- update `public.investigations` directly;
- perform the approval consumption and the investigation update as two separate mutations;
- call the atomic function a second time;
- use `apply_migration` in place of, or in addition to, this call;
- use a direct database client, driver, or connection string;
- use a REST request to Supabase;
- retry automatically on any failure;
- perform a fallback mutation after zero rows, a conflict, or a transport failure.

The read-only approval lookup (Stages 1–5), the purely local Stage 6 eligibility check, and this one atomic RPC call are the only database interactions this command ever performs.

Capture the tool's raw response exactly as returned. Do not parse, inspect, or trust it directly. Call this the **raw atomic MCP result**.

If the tool call itself fails to return a result at all, stop and report `CONSUMPTION_MCP_CALL_FAILED`.

## Stage 11 — Consumption MCP Adapter Normalize Response

Construct exactly this object:

```json
{
  "action": "normalize_response",
  "operation": "apply_approval_consumption",
  "tool_response": "<the raw atomic MCP result from Stage 10, exactly as returned>"
}
```

Send it through **stdin only** to the same `core.approval_mcp_adapter_cli` module.

### Consumption normalize_response exit handling

- **0**: potential success — continue to the output checks below.
- **2** (`approval_mcp_adapter_error`) or **1** (`internal_error`): stop and report `CONSUMPTION_NORMALIZATION_FAILED`.
- **any other code**: stop and report `CONSUMPTION_NORMALIZATION_FAILED`.

### Consumption normalize_response success-output checks

Require the parsed object to be exactly one of `{"kind": "rows", "rows": [...]}` or `{"kind": "transport_error"}`. A `transport_error` kind is passed forward unchanged to Stage 12, never reinterpreted as a success or as zero rows. Call this the **normalized atomic response**.

## Stage 12 — Consumption Bridge Verify

Construct exactly this object:

```json
{
  "phase": "verify",
  "operation": "apply_approval_consumption",
  "input": "<the exact same input object used in Stage 8>",
  "prepared_descriptor": "<the prepared atomic descriptor from Stage 8>",
  "executor_response": "<the normalized atomic response from Stage 11>"
}
```

Send it through **stdin only** to `core.approval_bridge_cli`.

### Consumption verify exit handling

- **0**: success — continue to the output checks below.
- **2**, code `approval_conflict`: zero rows matched the atomic function's own conditional filter — the approval was concurrently modified, replayed, no longer approved-and-unconsumed, or (for a risk-aware record) no longer independently satisfies the live sufficient-distinct-reviews/no-rejection/requester-reviewer-exclusion authorization check, between Stage 5's load and Stage 10's call — stop and report `PERSISTENCE_CONFLICT`. Never treat this as success, and never automatically retry it.
- **2**, code `approval_response_error`, `approval_persistence_error`, or `approval_bridge_error`: the response was malformed, contained more than one row, an unknown field was present, a required investigation-result field was missing, the approval portion did not match the expected consumed record (approval ID, investigation ID, action type, action payload, requester identity, reviewer identity, consumer identity, `consumed_at`, or unchanged rejection fields), the investigation `status`/`confidence` did not match the stored `action_payload`, or a descriptor mismatch occurred — stop and report `CONSUMPTION_VERIFICATION_FAILED`.
- **1**, code `approval_transport_error`: stop and report `CONSUMPTION_MCP_CALL_FAILED`.
- **1**, code `internal_error`: stop and report `CONSUMPTION_VERIFICATION_FAILED`.
- **any other code**: stop and report `CONSUMPTION_VERIFICATION_FAILED`.

Do not interpret zero rows as success. Never automatically retry a conflict or any other failure, and never reload the approval and try again automatically.

### Consumption verify success-output checks

Require the parsed object to contain exactly `phase`, `operation`, `result`, with `phase` equal to `"verify"` and `operation` equal to `"apply_approval_consumption"`. Require `result` to contain exactly `transition_plan`, `updated_record`, `investigation_result`.

Require `updated_record` to contain exactly the sixteen approval-record fields, with: `status` equal to `"consumed"`; `consumed_by` equal to the claimed consumer identity; `consumed_at` equal to the validator-generated timestamp from Stage 7; `rejected_by`, `rejected_at`, `rejection_reason` all `null`; and every frozen field (`id`, `investigation_id`, `action_type`, `action_payload`, `requested_by`, `requested_at`, `approved_by`, `approved_at`, `expires_at`, `created_at`) unchanged from the projected record.

Require `investigation_result` to contain exactly `investigation_id`, `status`, `confidence`, `updated_at` — this is the complete existing **nineteen-column atomic RPC return contract** (the sixteen approval fields plus `investigation_status`, `investigation_confidence`, `investigation_updated_at`, surfaced here as `investigation_result`). Never accept a twentieth field anywhere in this result. Verify `investigation_result["investigation_id"]` equals the trusted approval record's own `investigation_id`, and that `status`/`confidence` equal whichever of the stored `action_payload`'s own `status`/`confidence` keys were present (a key absent from `action_payload` means that half of the investigation record must be left exactly as the atomic function itself already determined, never asserted by this command from any other source).

Independently re-confirm, from this verified result alone, every one of the following before proceeding to output — a mismatch on any of these is a `CONSUMPTION_VERIFICATION_FAILED` failure, never a success, even though Stage 12 itself already returned exit code 0:

1. `updated_record.id` equals the requested `approval_id`.
2. `investigation_result.investigation_id` equals the trusted approval record's own `investigation_id`.
3. `updated_record.action_type` equals the trusted approval record's own `action_type`.
4. `updated_record.status` equals `"consumed"`.
5. `updated_record.consumed_at` is present (non-`null`).
6. `updated_record.consumed_by` equals the claimed consumer identity supplied to this command.
7. `investigation_result.status`/`investigation_result.confidence` match the validated action plan (the stored `action_payload`'s own `status`/`confidence`, exactly as already required above).
8. the trusted approval record loaded in Stage 5 was itself `approved` (already required by Stage 6 before any of this ran).
9. no field of `updated_record` other than `status`, `consumed_by`, `consumed_at` differs from the projected record loaded before consumption.

Call this the **verified atomic consumption result**.

## Required Success Output

Only after Stage 12 fully succeeds, display:

- Approval ID
- Investigation ID
- Action Type
- Applied Status (only when present in the stored `action_payload`)
- Applied Confidence (only when present in the stored `action_payload`)
- Final Approval Status: `consumed`
- Risk Level
- Required Approval Count
- Claimed Requester Identity
- Claimed Reviewer Identity
- Claimed Consumer Identity
- Approved At
- Consumed At
- Expires At (display `null` explicitly when absent)
- Final Investigation Status
- Final Investigation Confidence
- Investigation Updated At
- A clear statement that the approved case update was applied atomically
- A clear statement that this approval cannot be consumed again and that replay is now blocked

`Risk Level` and `Required Approval Count` are read only from the trusted approval record loaded in Stage 5 — this command never recalculates either for display.

Never describe `consumed_by`, `requested_by`, or `reviewed_by` as authenticated or verified. Never claim a `status`/`confidence` field was applied when it was not present in the stored `action_payload`. Never print the generated SQL or the raw MCP output.

Never display any of the following anywhere in the success or failure output:

- `requested_by_normalized`;
- any reviewer identity beyond the single claimed reviewer identity already listed above;
- `reviewer_identity_normalized`;
- the raw stored `action_payload` beyond the Applied Status/Applied Confidence summary already listed above;
- the RPC's own parameter values;
- raw SQL;
- an MCP tool-call descriptor or argument object;
- database connection or ownership metadata.

## Required Failure Categories

Use only these fixed, non-sensitive failure categories. Never expose a raw PostgreSQL error, generated SQL, a credential, a project URL, a project reference, an access token, a service-role credential, an MCP untrusted-data delimiter, a stack trace, or an internal owner detail in any of them.

### INVALID_INPUT

Malformed JSON, trailing content, a non-object top-level value, an unknown or Block-6-prohibited field, a missing `approval_id`/`consumed_by`, or a blank `consumed_by`.

### LOOKUP_PREPARE_FAILED

Stage 1 (bridge prepare) or Stage 2 (adapter prepare_call), for the lookup, reporting a deterministic validation failure or an unexpected internal failure.

### LOOKUP_MCP_CALL_FAILED

Stage 3's lookup tool call itself failing to return a result, or Stage 5 classifying the lookup outcome as `approval_transport_error`.

### LOOKUP_NORMALIZATION_FAILED

Stage 4 (adapter normalize_response), for the lookup, reporting a deterministic validation failure or an unexpected internal failure.

### APPROVAL_NOT_FOUND

Stage 5 (lookup bridge verify) reporting `approval_not_found` — no approval exists with the supplied ID.

### LOOKUP_VERIFICATION_FAILED

Stage 5 (lookup bridge verify) reporting a malformed, multiple-row, or ID-mismatched response, a descriptor mismatch, or any other deterministic or internal failure not covered above.

### CONSUMPTION_NOT_ALLOWED

Stage 6 (local lifecycle eligibility check) reporting that the trusted approval record is not currently in a consumable state:

- `pending` — approval review is required first;
- `partially_approved` — one of the two required distinct reviews has been recorded, but another, distinct reviewer is still required; `/apply-case-update` cannot be used yet;
- `rejected` — the request cannot be applied;
- `consumed` — it was already applied, and replay is blocked.

Also reported by Stage 7 when the projected record is malformed as an approved record, or expired according to the existing validator contract.

### TRANSITION_VALIDATION_FAILED

Any other Stage 7 deterministic validation failure (a blank identity, an internally inconsistent binding) or unexpected internal failure.

### CONSUMPTION_PREPARE_FAILED

Stage 8 (bridge prepare) or Stage 9 (adapter prepare_call), for the atomic consumption, reporting a deterministic validation failure or an unexpected internal failure.

### CONSUMPTION_MCP_CALL_FAILED

Stage 10's atomic tool call itself failing to return a result, or Stage 12 classifying the outcome as `approval_transport_error`.

### CONSUMPTION_NORMALIZATION_FAILED

Stage 11 (adapter normalize_response), for the atomic consumption, reporting a deterministic validation failure or an unexpected internal failure.

### CONSUMPTION_VERIFICATION_FAILED

Stage 12 (consumption bridge verify) reporting a malformed, multiple-row, or binding-mismatched response (including an investigation-result mismatch), a descriptor mismatch, or any other deterministic or internal failure not covered above, or a Stage 12 cross-check mismatch.

### PERSISTENCE_CONFLICT

Stage 12 (consumption bridge verify) reporting `approval_conflict` — zero rows matched the atomic function's own conditional filter. This covers every live authorization condition the atomic function itself independently re-checks: the approval was concurrently modified, replayed, was no longer approved-and-unconsumed, had expired, no longer matched its stored investigation/action binding, or (for a risk-aware record) no longer independently satisfied the live sufficient-distinct-reviews, no-rejection-review, or requester/reviewer-exclusion authorization check — between Stage 5's load and Stage 10's call. The user-facing message must explain plainly that the approval changed or that its review authorization could not be independently confirmed, and that the caller must not retry automatically; report an authorization conflict without exposing which specific reviewer identity or internal condition caused it.

Do not automatically retry any failure in any category above.

## TOCTOU and Final-Authority Rule

The approval record loaded in Stage 5 is used only for display, Stage 6's local eligibility check, Stage 7's transition validation, and Stage 8's preparation — it is **never treated as final authorization**. The atomic RPC invoked in Stage 10 is the sole final authority: it independently re-checks, from the live database row (and, for a risk-aware record, the live `approval_reviews` table) inside its own transaction, the approval ID, the approved status, sufficient distinct approve reviews with no rejection review and requester/reviewer exclusion (for the risk-aware path), the unconsumed state, expiry, the stored investigation ID, the stored action type, the stored `action_payload`, and one-time consumption — exactly as `public.consume_approval_and_update_investigation_state`'s own conditional `UPDATE ... WHERE ...` clause already does. If the approval changed between Stage 5's load and Stage 10's call, the atomic function itself returns zero rows, and this command fails closed as `PERSISTENCE_CONFLICT` — it never reloads the approval and retries automatically, and it never falls back to any other mutation path.

## Security Boundaries

This command must never:

- accept caller-supplied `status` or `confidence`;
- accept a caller-supplied `action_payload`;
- accept a caller-supplied `action_type`;
- accept a caller-supplied `investigation_id`;
- accept a caller-supplied `consumed_at`;
- accept a caller-created transition plan or a caller-created operation descriptor;
- accept a caller-supplied `risk_level`, `required_approvals`, `existing_reviews`, or `approval_count`;
- accept caller-supplied `expected_investigation_id`, `expected_action_type`, `expected_approval_status`, or RPC `parameters`;
- recalculate risk or count reviews itself — `risk_level`/`required_approvals` are always read from the trusted loaded record, and sufficiency of distinct reviews is always the atomic RPC's own live decision;
- replace any stored request or review field;
- approve or reject an approval;
- consume a `pending` approval;
- consume a `partially_approved` approval;
- consume a `rejected` approval;
- consume an already-`consumed` approval;
- consume an approval in a way that contradicts the existing validator's own expiry contract;
- downgrade a risk-aware approval into the atomic RPC's own legacy one-review compatibility branch, or otherwise choose which of the RPC's two internal authorization paths applies — that decision belongs entirely to the RPC's own live `requested_by_normalized`/`required_approvals` check on the row itself;
- update `public.approvals` directly;
- update `public.investigations` directly;
- split the atomic operation into more than one mutation;
- call the atomic RPC more than once;
- execute user-supplied SQL, or interpolate any caller-supplied text as a SQL identifier;
- use `apply_migration`;
- bypass `core.approval_transition_cli`, `core.approval_bridge_cli`, or `core.approval_mcp_adapter_cli`;
- use the legacy direct-update path `/update-case` uses;
- treat any typed confirmation phrase as authorization for a mutation beyond the one atomic RPC call this command performs;
- retry or fall back to any other mutation after a failure.

The only permitted mutation anywhere in this command is one adapter-prepared call to the existing atomic approval-consumption RPC, `public.consume_approval_and_update_investigation_state` — never anything else.

## Required Output

Produce:

- Request Validation Result
- Trusted Approval Record (Stage 5)
- Local Lifecycle Eligibility Check and Projected Record (Stage 6)
- Consumption Eligibility and Genuine Transition Plan (Stage 7)
- Prepared Atomic Descriptor (Stage 8)
- Atomic MCP Request (Stage 9)
- Raw Atomic MCP Result Handling (Stage 10)
- Normalized Atomic Response (Stage 11)
- Verified Atomic Consumption Result (Stage 12)
- Applied Case Update
- Recommended Next Action

## Example Request

```json
{
  "approval_id": "7d3f0e4a-4c5f-4d0a-9b12-345678901bcd",
  "consumed_by": "Update Case Operator"
}
```

## Safety Rules

- `consumed_by` is a claimed identity only — never authenticated, verified, trusted, derived from Supabase Auth, cryptographically proven, or the database service role.
- Never accept `investigation_id`, `status`, `confidence`, `action_type`, `action_payload`, `requested_by`, `requested_at`, `reviewed_by`, `approved_by`, `approved_at`, `rejected_by`, `rejected_at`, `rejection_reason`, `consumed_at`, `created_at`, or `expires_at` as input — the caller can never replace stored approval or investigation content.
- Never accept a caller-supplied transition plan or operation descriptor.
- Never accept a caller-supplied `risk_level`, `required_approvals`, `existing_reviews`, `approval_count`, `expected_investigation_id`, `expected_action_type`, `expected_approval_status`, or RPC `parameters` — every one of these is always loaded or derived internally, and review sufficiency is always the atomic RPC's own live decision.
- Never recalculate risk or count reviews in this command — `risk_level`/`required_approvals` are always read from the trusted loaded record alone.
- Never approve or reject an approval.
- Never consume a pending, partially_approved, rejected, or already-consumed approval.
- Never downgrade a risk-aware approval into the atomic RPC's own legacy compatibility branch, and never choose between its two internal authorization paths — that decision belongs entirely to the RPC's own live check.
- Never update `public.approvals` directly.
- Never update `public.investigations` directly.
- Never split the atomic consumption into more than one mutation, and never call the atomic RPC more than once.
- Never generate SQL directly, and never interpolate caller-supplied text as a SQL identifier — only `core.approval_mcp_adapter_cli` ever produces SQL, from an already-verified descriptor.
- Never bypass `core.approval_transition_cli`, `core.approval_bridge_cli`, or `core.approval_mcp_adapter_cli`.
- Never use `apply_migration` in this workflow.
- Never use the legacy direct-update path `/update-case` uses.
- Never retry any failure automatically, and never perform a fallback mutation after a conflict, zero rows, or a transport failure.
- Never expose a raw PostgreSQL error, generated SQL, a credential, a project URL, a project reference, an access token, a service-role credential, an MCP untrusted-data delimiter, a stack trace, or an internal owner detail.
- Never claim a status/confidence field was applied when it was not present in the stored `action_payload`, and never claim this approval can be consumed a second time.
