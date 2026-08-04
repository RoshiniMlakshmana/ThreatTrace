---
description: Record one distinct reviewer's approve or reject decision against one existing risk-aware pending approval, without applying, consuming, or replacing its stored content
argument-hint: "[approval UUID, decision (approve/reject), reviewed_by, rejection_reason if rejecting]"
---

# ThreatTrace Review Approval Workflow

`/review-approval` loads exactly one existing risk-aware approval, loads its complete immutable review history, and atomically records exactly one reviewer decision — approve or reject — against that approval alone. This command is only the **review** phase of the approval lifecycle:

Load risk-aware approval → load immutable reviews → derive the genuine transition plan → atomically record the review and promote status → verify the result

This command never updates `public.investigations`, never consumes the approval, never invokes the atomic case-update RPC (`consume_approval_and_update_investigation_state`), never applies the proposed `status`/`confidence` to anything, and never creates another approval. Every database round trip this command performs — loading the approval, loading its review history, and atomically recording the review — uses exactly the existing two-phase prepare/verify approval bridge (`core.approval_bridge_cli`) and the strict Supabase MCP descriptor adapter (`core.approval_mcp_adapter_cli`) — never a hand-written SQL statement, never a direct database client, never a REST call, and never the legacy direct-update path used by `/update-case`.

Unlike an earlier version of this workflow, this command never performs a single-row conditional `UPDATE` on `approvals` directly. A risk-aware approval may require one or two distinct reviewers (`required_approvals`, derived deterministically at request time and never recalculated here); this command always records the reviewer's decision as one immutable row in `approval_reviews` and atomically promotes the approval's own summary status together, in a single database round trip, through the existing `record_approval_review_and_promote_status` RPC — never a direct `INSERT` into `approval_reviews`, and never a direct `UPDATE` of `approvals`.

## Review Input

$ARGUMENTS

## Input Envelope

The input must be exactly one JSON object. Reject anything else — malformed JSON, trailing non-whitespace content after the object, or a top-level JSON value that is not an object.

Allow exactly these fields:

Required:

- `approval_id`
- `decision`
- `reviewed_by`

Conditionally required:

- `rejection_reason` — required only when `decision` is `reject`; must not be present at all when `decision` is `approve`.

Reject every field this list does not name. In particular, always reject:

- `investigation_id`
- `action_type`
- `action_payload`
- `status`
- `confidence`
- `requested_by`
- `requested_at`
- `approved_by`
- `approved_at`
- `rejected_by`
- `rejected_at`
- `consumed_by`
- `consumed_at`
- `created_at`
- `expires_at`
- `sql`
- `table`
- `function`
- `transition_plan`
- `descriptor`

None of these twenty fields is ever accepted from reviewer input. `approval_id` alone identifies which record to review — the reviewer can never replace `investigation_id`, `action_type`, `action_payload`, `requested_by`, `requested_at`, or `expires_at`, all of which remain exactly whatever the original request already stored. `approved_by`/`approved_at`/`rejected_by`/`rejected_at`/`consumed_by`/`consumed_at`/`created_at` are all outputs of this workflow (or of a later, separate consumption workflow this command never performs), never inputs to it. `sql`, `table`, and `function` name no field this command's request contract has ever defined — no caller-supplied text is ever used to select a table, a function, or a SQL identifier anywhere in this workflow. `transition_plan` and `descriptor` are never accepted from the reviewer either — both are always generated internally, from the existing public validators and bridge, never from caller-supplied text.

Also always reject every one of these additional Block 6 fields — none of them has ever been part of this command's own request contract, and every one of them names either a value this command must always derive or load itself (never accept from the caller) or a mechanism internal to the multi-review validator, bridge, and adapter layers this command never exposes to reviewer input:

- `risk_level`
- `required_approvals`
- `requested_by_normalized`
- `existing_reviews`
- `reviewer_identity_normalized`
- `from_status`
- `to_status`
- `approval_count_before`
- `approval_count_after`
- `review_record`
- `set_fields`

`risk_level` and `required_approvals` are never accepted because they were already derived deterministically and stored on the approval when it was requested — this command only ever loads and re-displays them, never recomputes or replaces them. `requested_by_normalized` and `reviewer_identity_normalized` are never accepted because both are always computed internally (`.strip().casefold()`), never supplied. `existing_reviews` is never accepted because this command always loads the genuine, complete, immutable review history itself, through `load_approval_reviews` — a caller-supplied review history could otherwise be used to forge a duplicate-reviewer or approval-count bypass. `from_status`, `to_status`, `approval_count_before`, `approval_count_after`, `review_record`, and `set_fields` are never accepted because every one of them is always produced by `core.approval_multi_review_cli` from the trusted loaded record and trusted loaded reviews, never assembled or forged by this command or its caller.

## Request Validation

Perform every validation step below, in order, before any Supabase or MCP operation:

1. Parse `$ARGUMENTS` as exactly one JSON value.
2. Reject malformed JSON.
3. Reject trailing non-whitespace content after the one JSON value.
4. Reject a top-level value that is not a JSON object.
5. Reject any field not listed under Input Envelope (including every Block 6 field named above).
6. Require `approval_id`, `decision`, and `reviewed_by` to all be present.
7. Reject a blank `reviewed_by` (empty after trimming whitespace).
8. Require `rejection_reason` when `decision` is `reject`; reject its presence at all when `decision` is `approve`.

Do not implement a separate, competing validator in this document — every structural rule beyond the local checks above (JSON shape, field presence, blank `reviewed_by`, the `rejection_reason` presence/absence rule) belongs to `core.approval_multi_review_cli` (which itself delegates to `core.approval_transition.validate_multi_review_transition`, never duplicated here), and this command only ever reuses it.

### `approval_id`

Must be a string the bridge/adapter can canonicalize as a structurally valid UUID. This command performs no local UUID format check of its own — Stage 1 rejects a malformed value.

### `decision`

Must be exactly one of the two review-transition values the existing multi-review validator supports:

- `approve`
- `reject`

Never `consume` — this command never performs, and never accepts a decision value naming, the separate atomic consumption transition. That is a later, separate workflow this command does not implement.

### `reviewed_by`

`reviewed_by` is a **caller-supplied claimed reviewer identity** — the reviewer's own typed name or handle. It is never authenticated, never verified, never cryptographically proven, and never derived from Supabase Auth or any other identity provider. This command performs no login, no session check, and no identity lookup of any kind. The stored value is exactly what the caller typed, trimmed of surrounding whitespace, and it is always displayed and described as a **claimed reviewer identity**, never as an authenticated or verified one. Its normalized comparison form (`reviewer_identity_normalized`) is always computed internally by `core.approval_multi_review_cli`, never supplied or displayed.

### `rejection_reason`

Required, nonblank after trimming, only when `decision` is `reject`. The existing multi-review validator contract does not allow this field on an approve transition at all — reject its presence there before Stage 3, rather than silently discarding it.

## Claimed Identity Boundary

`reviewed_by` is a caller-supplied claimed identity, nothing more. This command must never describe it, or the resulting approval record, as authenticated, verified, trusted, derived from Supabase Auth, or cryptographically proven. The final output always labels it explicitly as a **claimed reviewer identity**, and the original requester's own stored identity is always labeled a **claimed requester identity**.

## Python Launcher Selection

Use the existing project convention for selecting a Python launcher:

1. Try `py`.
2. Otherwise try `python3`.
3. Otherwise use a `python` executable only after confirming it resolves to Python 3.10 or later.

Select one launcher and reuse the same launcher for every CLI invocation in this workflow.

Before continuing to any Supabase or MCP operation, confirm the selected launcher can import all three required modules:

- `core.approval_bridge_cli`
- `core.approval_mcp_adapter_cli`
- `core.approval_multi_review_cli`

If no launcher can be selected, or the import check fails for any of the three modules, stop and report that the approval-review Python CLIs are unavailable. Do not install any package. Do not modify the environment.

## Safe CLI Transport

Invoke all CLIs through **stdin only**, exactly following the safe invocation pattern already established by `/add-evidence`, `/prepare-hayabusa-evidence`, `/decision-review`, and `/request-case-update`. Never:

- pass JSON through command-line arguments;
- create a temporary JSON file;
- interpolate reviewer content directly into executable shell code;
- write request data to disk.

## Stage 1 — Trusted Approval-Record Lookup

Load the approval's complete, risk-aware, eighteen-field record from the database itself, through the existing trusted lookup operation — never from any caller-supplied lifecycle, requester, risk, or approval-count claim.

### Stage 1a — Approval Bridge Prepare

Use the existing two-phase approval bridge, in its prepare phase, to construct the exact `load_risk_aware_approval_record` operation descriptor — bound only to the supplied `approval_id`, never to any other filter.

Construct exactly this object:

```json
{
  "phase": "prepare",
  "operation": "load_risk_aware_approval_record",
  "input": {
    "approval_id": "<approval_id exactly as supplied by the reviewer, trimmed>"
  }
}
```

Send it through **stdin only** to:

- Windows: `py -m core.approval_bridge_cli`
- macOS or Linux: `python3 -m core.approval_bridge_cli`
- Only fall back to plain `python -m core.approval_bridge_cli` if it is confirmed to resolve to Python 3.10 or later.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2**: deterministic bridge/persistence validation failure (including a malformed `approval_id`) — stop, report `APPROVAL_LOOKUP_FAILED`, and do not continue.
- **1**: unexpected internal failure — stop, report `APPROVAL_LOOKUP_FAILED`, and do not continue.
- **any other code**: unsupported CLI result — stop and report `APPROVAL_LOOKUP_FAILED`.

Reject the output when stderr is nonempty, stdout is empty, stdout is not valid JSON, stdout contains more than one JSON value, or the parsed value is not a JSON object.

Require the parsed object to contain exactly `phase`, `operation`, `descriptor`, with `phase` equal to `"prepare"` and `operation` equal to `"load_risk_aware_approval_record"`.

Require the descriptor to match the canonical select-descriptor shape already owned by `core.approval_persistence`: `operation` equal to `"select"`, `table` equal to `"approvals"`, `columns` equal to the full eighteen-field risk-aware approval record contract (the existing sixteen fields plus `risk_level` and `required_approvals`), `filters` containing exactly `id` equal to the canonical approval UUID, and `limit` equal to `2`.

Call this the **prepared approval-lookup descriptor**. Do not generate SQL directly from it.

### Stage 1b — MCP Adapter Prepare Call

Construct exactly this object:

```json
{
  "action": "prepare_call",
  "descriptor": "<the prepared approval-lookup descriptor from Stage 1a>"
}
```

Send it through **stdin only** to `core.approval_mcp_adapter_cli`, using the same launcher.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2** (`approval_mcp_adapter_error`) or **1** (`internal_error`): stop and report `APPROVAL_LOOKUP_FAILED`.
- **any other code**: stop and report `APPROVAL_LOOKUP_FAILED`.

Require the parsed object to contain exactly `tool` and `arguments`, with `tool` equal exactly to `mcp__supabase__execute_sql` and `arguments` containing exactly one field, `query`, a nonblank string. Call this the **approval-lookup MCP request**.

### Stage 1c — Execute Through Supabase MCP

Invoke only the tool named in the approval-lookup MCP request — `mcp__supabase__execute_sql` — using exactly the `arguments` the adapter returned. Do not rewrite, edit, or append to the generated SQL, execute a second statement, use `apply_migration`, use a direct database client or connection string, use a REST request, or retry automatically.

Capture the tool's raw response exactly as returned. Do not parse, inspect, or trust the raw MCP result directly anywhere in this command — it is untrusted data and is handed unmodified to Stage 1d next. Call this the **raw approval-lookup MCP result**.

If the tool call itself fails to return a result at all, stop and report `MCP_CALL_FAILED`.

### Stage 1d — MCP Adapter Normalize Response

Construct exactly this object:

```json
{
  "action": "normalize_response",
  "operation": "load_risk_aware_approval_record",
  "tool_response": "<the raw approval-lookup MCP result from Stage 1c, exactly as returned>"
}
```

Send it through **stdin only** to the same `core.approval_mcp_adapter_cli` module.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2** (`approval_mcp_adapter_error`) or **1** (`internal_error`): stop and report `RESPONSE_NORMALIZATION_FAILED`.
- **any other code**: stop and report `RESPONSE_NORMALIZATION_FAILED`.

Require the parsed object to be exactly one of `{"kind": "rows", "rows": [...]}` or `{"kind": "transport_error"}`. Call this the **normalized approval-lookup response**. A `transport_error` kind is passed forward unchanged to Stage 1e, never reinterpreted as a success or as zero rows.

### Stage 1e — Approval Bridge Verify

Construct exactly this object:

```json
{
  "phase": "verify",
  "operation": "load_risk_aware_approval_record",
  "input": "<the exact same input object used in Stage 1a>",
  "prepared_descriptor": "<the prepared approval-lookup descriptor from Stage 1a>",
  "executor_response": "<the normalized approval-lookup response from Stage 1d>"
}
```

Send it through **stdin only** to `core.approval_bridge_cli`.

Interpret the exit code strictly, and treat every one of these as fatal — never as a partial or provisional success:

- **0**: success — continue to the output checks below.
- **2**, code `approval_not_found`: no approval exists with the supplied ID — stop and report `APPROVAL_NOT_FOUND`.
- **2**, code `approval_response_error`, `approval_persistence_error`, or `approval_bridge_error`: the executor response was malformed, contained more than one row, the returned ID did not match, or a descriptor mismatch occurred — stop and report `APPROVAL_LOOKUP_FAILED`.
- **1**, code `approval_transport_error`: stop and report `MCP_CALL_FAILED`.
- **1**, code `internal_error`: stop and report `APPROVAL_LOOKUP_FAILED`.
- **any other code**: stop and report `APPROVAL_LOOKUP_FAILED`.

Never present a result as successful after any nonzero exit code, and never automatically retry any of these outcomes.

Require the parsed object to contain exactly `phase`, `operation`, `result`, with `phase` equal to `"verify"` and `operation` equal to `"load_risk_aware_approval_record"`. Require `result` to contain exactly the eighteen risk-aware approval-record fields, and verify `id` equals the canonical `approval_id` from the request.

Call this the **trusted approval record**. Every later stage reads from it, never from the raw reviewer input or the raw MCP result. `risk_level` and `required_approvals` are read from here alone — this command never recalculates either.

## Stage 2 — Trusted Review-History Lookup

Load the approval's complete, ordered, immutable review history from the database itself — never from a caller-supplied list.

### Stage 2a — Approval Bridge Prepare

Construct exactly this object:

```json
{
  "phase": "prepare",
  "operation": "load_approval_reviews",
  "input": {
    "approval_id": "<the canonical approval UUID from the trusted approval record>"
  }
}
```

Send it through **stdin only** to `core.approval_bridge_cli`.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2**: deterministic bridge/persistence validation failure — stop, report `REVIEW_HISTORY_LOOKUP_FAILED`, and do not continue.
- **1**: unexpected internal failure — stop, report `REVIEW_HISTORY_LOOKUP_FAILED`, and do not continue.
- **any other code**: unsupported CLI result — stop and report `REVIEW_HISTORY_LOOKUP_FAILED`.

Require the parsed object to contain exactly `phase`, `operation`, `descriptor`, with `phase` equal to `"prepare"` and `operation` equal to `"load_approval_reviews"`. Require the descriptor to match the canonical ordered review-select shape already owned by `core.approval_persistence`: `operation` equal to `"select"`, `table` equal to `"approval_reviews"`, `columns` equal exactly to `["approval_id", "reviewer_identity", "reviewer_identity_normalized", "decision", "decided_at"]`, `filters` containing exactly `approval_id`, `order_by` equal to `"decided_at"`, and `limit` equal to `10`.

Call this the **prepared review-history descriptor**.

### Stage 2b — MCP Adapter Prepare Call

Construct exactly this object:

```json
{
  "action": "prepare_call",
  "descriptor": "<the prepared review-history descriptor from Stage 2a>"
}
```

Send it through **stdin only** to `core.approval_mcp_adapter_cli`.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2** (`approval_mcp_adapter_error`) or **1** (`internal_error`): stop and report `REVIEW_HISTORY_LOOKUP_FAILED`.
- **any other code**: stop and report `REVIEW_HISTORY_LOOKUP_FAILED`.

Require the parsed object to contain exactly `tool` and `arguments`, with `tool` equal exactly to `mcp__supabase__execute_sql` and `arguments` containing exactly one field, `query`, a nonblank string. Call this the **review-history MCP request**.

### Stage 2c — Execute Through Supabase MCP

Invoke only the tool named in the review-history MCP request — `mcp__supabase__execute_sql` — using exactly the `arguments` the adapter returned. The same restrictions as Stage 1c apply: no rewritten or additional SQL, no `apply_migration`, no direct database client, no REST request, no automatic retry.

Capture the tool's raw response exactly as returned. Do not parse, inspect, or trust it directly. Call this the **raw review-history MCP result**.

If the tool call itself fails to return a result at all, stop and report `MCP_CALL_FAILED`.

### Stage 2d — MCP Adapter Normalize Response

Construct exactly this object:

```json
{
  "action": "normalize_response",
  "operation": "load_approval_reviews",
  "tool_response": "<the raw review-history MCP result from Stage 2c, exactly as returned>"
}
```

Send it through **stdin only** to `core.approval_mcp_adapter_cli`.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2** (`approval_mcp_adapter_error`) or **1** (`internal_error`): stop and report `RESPONSE_NORMALIZATION_FAILED`.
- **any other code**: stop and report `RESPONSE_NORMALIZATION_FAILED`.

Require the parsed object to be exactly one of `{"kind": "rows", "rows": [...]}` or `{"kind": "transport_error"}`. An empty `rows` list is a genuine, valid success — a not-yet-reviewed approval — never an error. Call this the **normalized review-history response**.

### Stage 2e — Approval Bridge Verify

Construct exactly this object:

```json
{
  "phase": "verify",
  "operation": "load_approval_reviews",
  "input": "<the exact same input object used in Stage 2a>",
  "prepared_descriptor": "<the prepared review-history descriptor from Stage 2a>",
  "executor_response": "<the normalized review-history response from Stage 2d>"
}
```

Send it through **stdin only** to `core.approval_bridge_cli`.

Interpret the exit code strictly:

- **0**: success — continue to the output checks below. Unlike every other operation this command uses, `load_approval_reviews` returns a JSON **array**, not an object — the parsed object's own `result` field is therefore always a list, never a mapping.
- **2**, code `approval_response_error`, `approval_persistence_error`, or `approval_bridge_error`: a malformed row, a review whose `approval_id` did not match, or a descriptor mismatch occurred — stop and report `REVIEW_HISTORY_LOOKUP_FAILED`.
- **1**, code `approval_transport_error`: stop and report `MCP_CALL_FAILED`.
- **1**, code `internal_error`: stop and report `REVIEW_HISTORY_LOOKUP_FAILED`.
- **any other code**: stop and report `REVIEW_HISTORY_LOOKUP_FAILED`.

Never automatically retry any of these outcomes.

Require the parsed object to contain exactly `phase`, `operation`, `result`, with `phase` equal to `"verify"` and `operation` equal to `"load_approval_reviews"`, and `result` a JSON array whose every entry contains exactly `approval_id`, `reviewer_identity`, `reviewer_identity_normalized`, `decision`, `decided_at`. Every entry's own `approval_id` already equals the trusted approval record's own `id` — `core.approval_persistence.load_approval_reviews` itself rejects any row that does not match before this stage can ever succeed, so no further cross-check is required here.

Call this the **trusted review history**. Do not alter, deduplicate, reorder, synthesize, or remove any entry in it — pass it to Stage 3 exactly as returned. Duplicate-review and approval-count rules remain entirely the responsibility of the multi-review validator (Stage 3) and the atomic RPC (Stage 4), never this command's own logic.

## Stage 3 — Multi-Review Transition Plan Derivation

Construct exactly this envelope, using only the trusted approval record, the trusted review history, and the reviewer's own legitimate submitted fields — never `status`, `confidence`, `action_type`, `action_payload`, or a caller-supplied `reviewed_at`:

For an approve decision:

```json
{
  "current_record": "<the trusted approval record from Stage 1e>",
  "existing_reviews": "<the trusted review history from Stage 2e>",
  "transition_request": {
    "decision": "approve",
    "reviewed_by": "<the claimed reviewer identity, as typed>"
  }
}
```

For a reject decision:

```json
{
  "current_record": "<the trusted approval record from Stage 1e>",
  "existing_reviews": "<the trusted review history from Stage 2e>",
  "transition_request": {
    "decision": "reject",
    "reviewed_by": "<the claimed reviewer identity, as typed>",
    "rejection_reason": "<the reviewer's stated reason, as typed>"
  }
}
```

`transition_request` never contains `approval_id`, `reviewed_at`, or any other field — `core.approval_transition.validate_multi_review_transition`'s own contract for `transition_request` is exactly `decision`/`reviewed_by` (approve) or `decision`/`reviewed_by`/`rejection_reason` (reject), and this command never adds to it. When `reviewed_at` is not supplied, the validator generates it from the real current UTC time itself — this command never generates or overrides that timestamp.

Send it through **stdin only** to:

- Windows: `py -m core.approval_multi_review_cli`
- macOS or Linux: `python3 -m core.approval_multi_review_cli`
- Only fall back to plain `python -m core.approval_multi_review_cli` if it is confirmed to resolve to Python 3.10 or later.

### Transition CLI exit handling

- **0**: potential success — continue to the output checks below.
- **2**: deterministic transition-validation failure. Inspect the returned message to classify it, without ever printing the raw message to the reviewer:
  - a message stating the current status must be `'pending'` or `'partially_approved'` — stop and report `TRANSITION_NOT_ALLOWED`;
  - a message stating the reviewer must differ from the original requester — stop and report `SELF_REVIEW_FORBIDDEN`;
  - a message stating `reviewed_by` has already reviewed this approval — stop and report `DUPLICATE_REVIEWER_FORBIDDEN`;
  - any other validation message (malformed `current_record`/`existing_reviews`/`transition_request`, blank identity, missing/blank rejection reason, or a chronology/expiry failure) — stop and report `TRANSITION_VALIDATION_FAILED`.
- **1**: unexpected internal failure — stop and report `TRANSITION_VALIDATION_FAILED`.
- **any other code**: stop and report `TRANSITION_VALIDATION_FAILED`.

Do not manually construct or forge a transition plan under any circumstance — only a plan this CLI itself produced from the trusted approval record and trusted review history may ever be used in Stage 4. This command never independently derives `from_status`, `to_status`, `approval_count_before`, `approval_count_after`, `reviewer_identity_normalized`, `review_record`, or `set_fields` — every one of those belongs entirely to `core.approval_transition.validate_multi_review_transition`, called only through this CLI.

### Transition CLI success-output checks

Reject the output when stderr is nonempty, stdout is empty, stdout is not valid JSON, stdout contains more than one JSON value, or the parsed value is not a JSON object.

Require the parsed object to contain exactly `approval_id`, `from_status`, `to_status`, `required_approvals`, `approval_count_before`, `approval_count_after`, `review_record`, `set_fields`. Verify:

- `approval_id` equals the trusted approval record's own `id`;
- `required_approvals` equals the trusted approval record's own `required_approvals`;
- `review_record.reviewer_identity` equals the reviewer's own trimmed `reviewed_by`;
- `review_record.decision` equals the requested `decision`.

Call this the **genuine transition plan**.

## Stage 4 — Atomic Review Application

### Stage 4a — Approval Bridge Prepare

Use the existing two-phase approval bridge, in its prepare phase, to construct the exact `apply_multi_review_transition` operation descriptor — never a hand-written descriptor, and never a caller-built RPC parameter set.

Construct exactly this object:

```json
{
  "phase": "prepare",
  "operation": "apply_multi_review_transition",
  "input": {
    "current_record": "<the trusted approval record from Stage 1e>",
    "existing_reviews": "<the trusted review history from Stage 2e>",
    "transition_plan": "<the genuine transition plan from Stage 3>"
  }
}
```

Send it through **stdin only** to `core.approval_bridge_cli`.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2** (`approval_persistence_error`, `approval_bridge_error`) or **1** (`internal_error`): stop and report `REVIEW_APPLY_PREPARE_FAILED`.
- **any other code**: stop and report `REVIEW_APPLY_PREPARE_FAILED`.

Require the parsed object to contain exactly `phase`, `operation`, `descriptor`, with `phase` equal to `"prepare"` and `operation` equal to `"apply_multi_review_transition"`.

Require the descriptor to match the canonical atomic-RPC shape already owned by `core.approval_persistence`: `operation` equal to `"rpc"`, `function` equal exactly to `record_approval_review_and_promote_status`, and `parameters` containing exactly its ten fields (`approval_id`, `expected_from_status`, `expected_to_status`, `expected_required_approvals`, `expected_approval_count_before`, `reviewer_identity`, `reviewer_identity_normalized`, `decision`, `decided_at`, `rejection_reason`) — every one of which is generated entirely from the genuine transition plan, never rebuilt or hand-edited by this command. This command never constructs an `insert`/`update` descriptor against `approval_reviews` or `approvals` directly for this operation — the atomic RPC is the sole mutation path.

Call this the **prepared review-application descriptor**. Do not generate SQL directly from it.

### Stage 4b — MCP Adapter Prepare Call

Construct exactly this object:

```json
{
  "action": "prepare_call",
  "descriptor": "<the prepared review-application descriptor from Stage 4a>"
}
```

Send it through **stdin only** to `core.approval_mcp_adapter_cli`.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2** (`approval_mcp_adapter_error`) or **1** (`internal_error`): stop and report `REVIEW_APPLY_PREPARE_FAILED`.
- **any other code**: stop and report `REVIEW_APPLY_PREPARE_FAILED`.

Require the parsed object to contain exactly `tool` and `arguments`, with `tool` equal exactly to `mcp__supabase__execute_sql` and `arguments` containing exactly one field, `query`, a nonblank string — always the fixed `SELECT * FROM public.record_approval_review_and_promote_status(...)` template. Call this the **review-application MCP request**.

### Stage 4c — Execute Through Supabase MCP

Invoke only the tool named in the review-application MCP request — `mcp__supabase__execute_sql` — using exactly the `arguments` the adapter returned. Do not rewrite, edit, or append to the generated SQL in any way; do not execute a second SQL statement of any kind; do not use `apply_migration`; do not use a direct database client, driver, or connection string; do not use a REST request to Supabase; do not retry automatically on any failure; do not perform a second review-application attempt after a conflict.

The only permitted database mutation anywhere in this command is this one atomic `record_approval_review_and_promote_status` RPC call.

Capture the tool's raw response exactly as returned. Do not parse, inspect, or trust it directly. Call this the **raw review-application MCP result**.

If the tool call itself fails to return a result at all, stop and report `MCP_CALL_FAILED`.

### Stage 4d — MCP Adapter Normalize Response

Construct exactly this object:

```json
{
  "action": "normalize_response",
  "operation": "apply_multi_review_transition",
  "tool_response": "<the raw review-application MCP result from Stage 4c, exactly as returned>"
}
```

Send it through **stdin only** to `core.approval_mcp_adapter_cli`.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2** (`approval_mcp_adapter_error`) or **1** (`internal_error`): stop and report `RESPONSE_NORMALIZATION_FAILED`.
- **any other code**: stop and report `RESPONSE_NORMALIZATION_FAILED`.

Require the parsed object to be exactly one of `{"kind": "rows", "rows": [...]}` or `{"kind": "transport_error"}`. A `transport_error` kind, and a genuine zero-row `{"kind": "rows", "rows": []}` result, are both passed forward unchanged to Stage 4e, never reinterpreted locally as any kind of success or failure. Call this the **normalized review-application response**.

### Stage 4e — Approval Bridge Verify

Use the same two-phase approval bridge, in its verify phase, to independently regenerate and check the prepared review-application descriptor, then complete the atomic RPC call using the normalized response — reusing every one of `core.approval_persistence.apply_multi_review_transition`'s own existing response-validation rules unchanged, including its complete validation of the underlying twenty-four-field RPC result row (the eighteen risk-aware approval fields plus `review_approval_id`, `reviewer_identity`, `reviewer_identity_normalized`, `review_decision`, `review_decided_at`, `approval_count`). Never parse the raw MCP result or the normalized response directly in this command.

Construct exactly this object:

```json
{
  "phase": "verify",
  "operation": "apply_multi_review_transition",
  "input": "<the exact same input object used in Stage 4a>",
  "prepared_descriptor": "<the prepared review-application descriptor from Stage 4a>",
  "executor_response": "<the normalized review-application response from Stage 4d>"
}
```

Send it through **stdin only** to `core.approval_bridge_cli`.

Interpret the exit code strictly, and treat every one of these as fatal — never as a partial or provisional success:

- **0**: success — continue to Stage 5 below.
- **2**, code `approval_conflict`: the RPC's executor response **contained zero rows** — the approval was concurrently modified (a stale expected status, a stale expected approval count, a concurrently added duplicate-normalized reviewer, or a concurrent rejection) between Stage 1's/Stage 2's load and Stage 4's atomic call — stop and report `PERSISTENCE_CONFLICT`. No review was recorded and no status was promoted.
- **2**, code `approval_response_error`, `approval_persistence_error`, or `approval_bridge_error`: the response was malformed, contained more than one row, or the returned row did not match the genuine plan (updated record, review record, or approval count) — stop and report `REVIEW_VERIFICATION_FAILED`.
- **1**, code `approval_transport_error`: stop and report `MCP_CALL_FAILED`.
- **1**, code `internal_error`: stop and report `REVIEW_VERIFICATION_FAILED`.
- **any other code**: stop and report `REVIEW_VERIFICATION_FAILED`.

Never present a result as successful after any nonzero exit code, and never automatically retry any of these outcomes — including `PERSISTENCE_CONFLICT`, which always requires the reviewer to re-issue `/review-approval` from the beginning against the approval's now-current state, never an automatic re-lookup or re-attempt within this same run.

Require the parsed object to contain exactly `phase`, `operation`, `result`, with `phase` equal to `"verify"` and `operation` equal to `"apply_multi_review_transition"`. Require `result` to contain exactly `updated_record`, `review_record`, `approval_count`.

Call this the **recorded review result**.

## Stage 5 — Cross-Check the Recorded Review

Before producing any success output, independently re-verify the recorded review result against the trusted approval record, the trusted review history, and the genuine transition plan. Every one of these must hold, or the command fails closed (`REVIEW_VERIFICATION_FAILED`) and no review is reported as recorded, even though the database call itself already succeeded:

1. `result.updated_record.id` equals the requested `approval_id`.
2. `result.review_record.approval_id` equals the requested `approval_id`.
3. `result.review_record.decision` equals the requested `decision`.
4. `result.review_record.reviewer_identity` equals the genuine transition plan's own `review_record.reviewer_identity`, and `result.review_record.reviewer_identity_normalized` equals the genuine transition plan's own `review_record.reviewer_identity_normalized`.
5. `result.updated_record.required_approvals` equals both the trusted approval record's own `required_approvals` and the genuine transition plan's own `required_approvals`.
6. `result.approval_count` equals the genuine transition plan's own `approval_count_after`.
7. `result.updated_record.status` equals the genuine transition plan's own `to_status`.
8. `result.updated_record` satisfies the existing eighteen-field risk-aware record contract, and `result.review_record` satisfies the existing five-field review-record contract — both already reused unchanged by the bridge/persistence layer in Stage 4e, re-confirmed here as a final defensive check.

For an approve decision specifically:

- when `required_approvals` is `1`, `to_status`/`result.updated_record.status` must be `approved` and `approval_count` must be `1`;
- when `required_approvals` is `2` and `approval_count_before` was `0`, `to_status`/`result.updated_record.status` must be `partially_approved` and `approval_count` must be `1`;
- when `required_approvals` is `2` and `approval_count_before` was `1`, `to_status`/`result.updated_record.status` must be `approved` and `approval_count` must be `2`.

For a reject decision specifically:

- `to_status`/`result.updated_record.status` must be `rejected`;
- `result.review_record.decision` must be `reject`;
- `result.approval_count` must equal `approval_count_before` exactly — a rejection never increments the approve count.

A mismatch on any of these checks means this command's own independent verification disagrees with what the database reported — stop, report `REVIEW_VERIFICATION_FAILED`, and do not produce success output. Never attempt a repair, a compensating action, a second review, or a retry in response to a mismatch here.

## Required Success Output

Only after Stage 5 fully succeeds, display only this safe operational information:

- Approval ID
- Recorded Decision (`approve` or `reject`)
- Resulting Status (`approved`, `partially_approved`, or `rejected`)
- Risk Level
- Required Approval Count
- Current Approval Count
- Remaining Approvals Needed (when still short of `required_approvals`)
- Claimed Requester Identity
- Claimed Reviewer Identity
- Review Timestamp
- Rejection Reason (only when rejected)
- A clear statement that the investigation has not been updated
- The next required action

Next-action guidance:

- **One-review approval** (`required_approvals` is `1`, resulting status `approved`): state that the approval is now `approved` and can proceed to `/apply-case-update <approval-id>`.
- **First review of a two-review approval** (resulting status `partially_approved`): state that the status is `partially_approved` and that one additional, distinct reviewer is still required. Do not suggest `/apply-case-update` yet.
- **Second review of a two-review approval** (resulting status `approved`): state that the approval is now `approved`, both required distinct reviewers have approved, and it can proceed to `/apply-case-update <approval-id>`.
- **Rejection** (resulting status `rejected`): state plainly that the request is rejected and cannot be applied, and that a new request through `/request-case-update` is required for any different proposed change.

Never claim an approved request has already updated the investigation. Never claim a rejected or `partially_approved` request can be applied.

Never display any of the following anywhere in the success or failure output:

- `requested_by_normalized`;
- `reviewer_identity_normalized`;
- the raw stored `action_payload` beyond the safe Proposed Status/Proposed Confidence summary this command already showed for the original request;
- the RPC's own parameter values;
- raw SQL;
- an MCP tool-call descriptor or argument object;
- a credential, project URL, project reference, or access token;
- database connection or ownership metadata.

## Required Failure Categories

Use only these fixed, non-sensitive failure categories. Never expose a raw PostgreSQL error, generated SQL, a credential, a project URL, a project reference, an access token, an MCP untrusted-data delimiter, a stack trace, or an internal owner detail in any of them.

### INVALID_INPUT

Malformed JSON, trailing content, a non-object top-level value, an unknown or Block-6-prohibited field, a missing `approval_id`/`decision`/`reviewed_by`, a blank `reviewed_by`, a missing `rejection_reason` on a reject decision, or a present `rejection_reason` on an approve decision.

### APPROVAL_LOOKUP_FAILED

Stage 1a, Stage 1b, or Stage 1e reporting a malformed `approval_id`, a malformed or mismatched lookup row, a descriptor mismatch, or any other deterministic or internal failure during the trusted approval-record lookup — excluding a genuine not-found (see `APPROVAL_NOT_FOUND`) and a transport failure (see `MCP_CALL_FAILED`).

### APPROVAL_NOT_FOUND

Stage 1e reporting `approval_not_found` — no approval exists with the supplied ID.

### REVIEW_HISTORY_LOOKUP_FAILED

Stage 2a, Stage 2b, or Stage 2e reporting a malformed or mismatched review row, a descriptor mismatch, or any other deterministic or internal failure during the trusted review-history lookup.

### TRANSITION_NOT_ALLOWED

Stage 3 reporting that the trusted approval record's current status is neither `pending` nor `partially_approved` (already `approved`, `rejected`, or `consumed`) — a terminal approval can never receive another review.

### SELF_REVIEW_FORBIDDEN

Stage 3 reporting that the claimed reviewer identity is the same as the claimed requester identity on an approve decision.

### DUPLICATE_REVIEWER_FORBIDDEN

Stage 3 reporting that the claimed reviewer identity has already recorded an approve review against this approval, detected locally by the multi-review validator against the trusted review history.

### TRANSITION_VALIDATION_FAILED

Any other Stage 3 deterministic validation failure (malformed input, blank identity, missing/blank rejection reason, or a chronology/expiry failure) or unexpected internal failure.

### REVIEW_APPLY_PREPARE_FAILED

Stage 4a or Stage 4b reporting a deterministic validation failure or an unexpected internal failure.

### MCP_CALL_FAILED

Stage 1c, Stage 2c, or Stage 4c's tool call itself failing to return a result, or Stage 1e/Stage 2e/Stage 4e classifying the outcome as `approval_transport_error`.

### RESPONSE_NORMALIZATION_FAILED

Stage 1d, Stage 2d, or Stage 4d (adapter `normalize_response`) reporting a deterministic validation failure or an unexpected internal failure.

### REVIEW_VERIFICATION_FAILED

Stage 4e reporting a malformed, multiple-row, or plan-mismatched response, a descriptor mismatch, or any other deterministic or internal failure not covered above, or a Stage 5 cross-check mismatch.

### PERSISTENCE_CONFLICT

Stage 4e's atomic RPC call reporting `approval_conflict` — its executor response contained zero rows because the approval no longer matched the exact expected status, expected approval count, or was concurrently reviewed by the same normalized reviewer identity, between the trusted lookups (Stage 1/Stage 2) and the atomic application (Stage 4). No review was recorded. The user-facing message must explain plainly that the approval changed concurrently and that the reviewer must re-issue `/review-approval` from the beginning against its current state. Never retried automatically, and never followed by a fallback direct update or insert.

Do not automatically retry any failure in any category above.

## Security Boundaries

This command must never:

- update `public.investigations`, directly or indirectly;
- call `public.consume_approval_and_update_investigation_state` or any other atomic consumption RPC;
- consume an approval;
- apply the proposed `status` or `confidence` to anything;
- replace the stored `action_payload`, `action_type`, `investigation_id`, or `requested_by`;
- allow an approve decision from the same claimed identity as the original requester;
- allow the same normalized reviewer identity to be counted as an approve review twice;
- review an approval whose current status is not `pending` or `partially_approved`;
- review an approval in a way that contradicts the existing validator's own expiry/chronology contract;
- accept a caller-created transition plan, review record, or operation descriptor;
- accept a caller-supplied `existing_reviews` list, `risk_level`, or `required_approvals`;
- recalculate risk during review — `risk_level`/`required_approvals` are always read from the trusted approval record alone;
- execute user-supplied SQL, or interpolate any caller-supplied text as a SQL identifier;
- use `apply_migration`;
- bypass `core.approval_multi_review_cli`, `core.approval_bridge_cli`, or `core.approval_mcp_adapter_cli`;
- use the legacy direct-update path `/update-case` uses;
- fall back to the plain, single-review `apply_approval_review_transition` operation, a direct `UPDATE` of `approvals`, or a direct `INSERT` into `approval_reviews`, for any reason, including a `PERSISTENCE_CONFLICT`;
- retry Stage 1, Stage 2, or Stage 4 automatically after any conflict or failure;
- treat any typed confirmation phrase as authorization for a mutation beyond the one atomic review-application this command performs.

The only permitted database mutation anywhere in this command is the one atomic `record_approval_review_and_promote_status` RPC call, through the existing two-phase prepare/verify bridge and MCP adapter workflow, exactly as described above.

## Required Output

Produce:

- Request Validation Result
- Trusted Approval Record (Stage 1)
- Trusted Review History (Stage 2)
- Genuine Transition Plan (Stage 3)
- Prepared Review-Application Descriptor (Stage 4a)
- Review-Application MCP Request (Stage 4b)
- Raw Review-Application MCP Result Handling (Stage 4c)
- Normalized Review-Application Response (Stage 4d)
- Recorded Review Result (Stage 4e)
- Cross-Check (Stage 5)
- Reviewed Approval
- Recommended Next Action

## Example Requests

### 1. Approve

```json
{
  "approval_id": "6c2f9d3e-3b4f-4c9e-8a11-234567890abc",
  "decision": "approve",
  "reviewed_by": "Security Reviewer"
}
```

### 2. Reject

```json
{
  "approval_id": "6c2f9d3e-3b4f-4c9e-8a11-234567890abc",
  "decision": "reject",
  "reviewed_by": "Security Reviewer",
  "rejection_reason": "Insufficient evidence to support the proposed change."
}
```

## Safety Rules

- `reviewed_by` is a claimed identity only — never authenticated, verified, trusted, derived from Supabase Auth, or cryptographically proven.
- Never accept `investigation_id`, `action_type`, `action_payload`, `requested_by`, `requested_at`, or `expires_at` as input — the reviewer can never replace stored approval content.
- Never accept a caller-supplied transition plan, review record, or operation descriptor.
- Never accept a caller-supplied `existing_reviews` list, `risk_level`, or `required_approvals` — every one of these is always loaded or derived internally.
- Never update `public.investigations`.
- Never call the atomic consumption RPC.
- Never consume an approval.
- Never apply the proposed status or confidence to anything.
- Never allow self-review on an approve decision.
- Never allow the same normalized reviewer identity to count twice toward `required_approvals`.
- Never review an approval that is not currently `pending` or `partially_approved`.
- Never fall back to the plain `apply_approval_review_transition` operation, a direct `UPDATE` of `approvals`, or a direct `INSERT` into `approval_reviews`, for any reason.
- Never generate SQL directly, and never interpolate caller-supplied text as a SQL identifier — only `core.approval_mcp_adapter_cli` ever produces SQL, from an already-verified descriptor.
- Never bypass `core.approval_multi_review_cli`, `core.approval_bridge_cli`, or `core.approval_mcp_adapter_cli`.
- Never use `apply_migration` in this workflow.
- Never use the legacy direct-update path `/update-case` uses.
- Never retry any failure automatically, and never perform a second review-application attempt after a conflict.
- Never expose a raw PostgreSQL error, generated SQL, a credential, a project URL, a project reference, an access token, an MCP untrusted-data delimiter, a stack trace, or an internal owner detail.
- Never claim an approved request has already updated the investigation, and never claim a rejected or still-`partially_approved` request can be applied.
