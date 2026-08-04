---
description: Request a risk-aware pending approval to change an investigation's status and/or confidence, without applying the change
argument-hint: "[investigation UUID, requested_by, proposed status and/or confidence, optional expires_at]"
---

# ThreatTrace Request Case Update Workflow

`/request-case-update` creates exactly one pending, risk-aware approval request for a proposed investigation `status`/`confidence` change. This command is only the **request** phase of the approval lifecycle:

Request → trusted context lookup → deterministic risk classification → context-bound pending approval

This command never approves, rejects, or consumes an approval, and it never updates `public.investigations` directly or through any other path. The only database mutation this command ever performs is the insertion of one validated, pending, risk-aware `approvals` row, executed entirely through the existing two-phase prepare/verify approval bridge (`core.approval_bridge_cli`) and the strict Supabase MCP descriptor adapter (`core.approval_mcp_adapter_cli`) — never a hand-written SQL statement, never a direct database client, never a REST call, and never the legacy direct-update path used by `/update-case`.

Unlike an earlier version of this workflow, the analyst's own claim about the investigation's current `status`/`confidence` is never trusted for risk classification or for the insert itself. This command always performs a **trusted investigation-context lookup** first, classifies risk deterministically from that trusted context, and binds the eventual insert to that exact context — so a concurrent investigation change between lookup and insert is detected and rejected, never silently accepted.

## Request Input

$ARGUMENTS

## Input Envelope

The input must be exactly one JSON object. Reject anything else — malformed JSON, trailing non-whitespace content after the object, or a top-level JSON value that is not an object.

Allow exactly these fields:

Required:

- `investigation_id`
- `requested_by`

At least one of these two must also be present:

- `status`
- `confidence`

Optional:

- `expires_at`

Reject every field this list does not name. In particular, always reject:

- `approval_id`
- `id`
- `action_type`
- `action_payload`
- `approved_by`
- `approved_at`
- `rejected_by`
- `rejected_at`
- `rejection_reason`
- `consumed_by`
- `consumed_at`
- `approval_status`
- `created_at`
- `sql`
- `table`
- `function`

None of these fifteen fields is ever accepted from analyst input. `approval_id`/`id` are never accepted because this command always generates a brand-new approval UUID itself, through the database insert, never from caller-supplied text. `action_type` is never accepted because this command always uses the one existing canonical case-update action type itself — the analyst never supplies or replaces it. `action_payload` is never accepted directly — it is always built by this command from only the analyst's own `status`/`confidence` fields, never from a caller-supplied nested object that could smuggle in an arbitrary key. `approved_by`, `approved_at`, `rejected_by`, `rejected_at`, `rejection_reason`, `consumed_by`, `consumed_at`, `approval_status`, and `created_at` all belong to a later reviewer or consumption decision this command never makes. `sql`, `table`, and `function` name no field this command's request contract has ever defined — no caller-supplied text is ever used to select a table, a function, or a SQL identifier anywhere in this workflow.

Also always reject every one of these additional Block 6 fields — none of them has ever been part of this command's own request contract, and every one of them names either a value this command must always derive itself (never accept from the caller) or a mechanism internal to the bridge/adapter layer this command never exposes to analyst input:

- `current_investigation`
- `current_status`
- `current_confidence`
- `risk_level`
- `required_approvals`
- `requested_by_normalized`
- `expected_current_status`
- `expected_current_confidence`
- `approval_count`
- `reviewer`
- `reviewed_by`
- `descriptor`

`current_investigation`/`current_status`/`current_confidence` are never accepted because the investigation's current context is always obtained from the trusted lookup in Stage 1 below, never from a caller's own claim — a caller-forged current status or confidence could otherwise downgrade the deterministic risk classification. `risk_level` and `required_approvals` are never accepted because they are always derived deterministically by `core.approval_risk.classify_approval_risk` from the trusted context and the proposed change, never chosen by the caller. `requested_by_normalized` is never accepted because it is always computed internally (`requested_by.strip().casefold()`), never supplied. `expected_current_status`/`expected_current_confidence` are never accepted because they are always derived by `core.approval_persistence.insert_risk_aware_pending_approval` from the same trusted lookup result, never from a separate caller-supplied field — accepting them directly would let a caller bypass the live-context guard entirely. `approval_count`, `reviewer`, and `reviewed_by` all belong to a later, separate `/review-approval` decision this command never makes or previews. `descriptor` names no field this command's request contract has ever defined — a caller can never supply a bridge or adapter descriptor directly; every descriptor is always generated fresh from validated data.

## Request Validation

Perform every validation step below, in order, before any Supabase or MCP operation:

1. Parse `$ARGUMENTS` as exactly one JSON value.
2. Reject malformed JSON.
3. Reject trailing non-whitespace content after the one JSON value.
4. Reject a top-level value that is not a JSON object.
5. Reject any field not listed under Input Envelope (including every Block 6 field named above).
6. Require both `investigation_id` and `requested_by` to be present.
7. Require at least one of `status` or `confidence` to be present.
8. Reject an explicit JSON `null` for `status` or `confidence` when that key is present — either field must be entirely omitted or a real value, never `null`.
9. Reject a blank `requested_by` (empty after trimming whitespace).

Every one of these nine checks is a purely local, in-memory check performed before any Stage below ever runs — a prohibited field, a missing required field, or a malformed local shape always fails closed before any Supabase or MCP call is ever attempted.

This command performs no local UUID format check of `investigation_id` and delegates every further structural rule (UUID canonicalization, timestamp generation, vocabulary membership, payload shape) to the existing validators. Unlike an earlier version of this workflow, no standalone `core.approval_request_cli` invocation exists here: `core.approval_risk_request_cli` already delegates to `core.approval_request.validate_approval_request` internally (composed inside `core.approval_request.validate_risk_aware_approval_request`), so a second, separate call would be redundant — risk classification always requires validating the request at the same time, and `core.approval_persistence.insert_risk_aware_pending_approval` independently re-validates the same request a second time during Stage 3's insertion. Do not implement a separate, competing validator in this document — every structural rule beyond the nine local checks above belongs to those existing validators, and this command only ever reuses them.

### `investigation_id`

Must be a string that the trusted lookup's own persistence layer (`core.approval_persistence.load_investigation_approval_context`) can canonicalize as a structurally valid UUID. A malformed value is rejected in Stage 1 below, before any Supabase call is made.

### `requested_by`

`requested_by` is a **caller-supplied claimed identity** — the analyst's own typed name or handle. It is never authenticated, never verified, never cryptographically proven, and never derived from Supabase Auth or any other identity provider. This command performs no login, no session check, and no identity lookup of any kind. The stored value is exactly what the caller typed, trimmed of surrounding whitespace, and it is always displayed and described as a claimed requester identity, never as an authenticated or verified one.

### `status` / `confidence`

At least one must be present. Each, when present, must be one of the existing controlled vocabulary values the validators already enforce (`core.decision_context.INVESTIGATION_STATUSES` for `status`, `core.evidence_normalizer.CONFIDENCE_LEVELS` for `confidence`). This command never defines its own copy of either vocabulary. These are the analyst's *proposed* values — never confused with the investigation's *current* `status`/`confidence`, which this command only ever learns from the trusted lookup in Stage 1.

### `expires_at`

Optional. When omitted, the created approval has no expiry (`expires_at` is `null`) — the existing, already-supported default/null behavior. When supplied, it must be a timestamp the validators accept (an aware ISO-8601 string, canonicalized to UTC `Z` form), strictly after the generated `requested_at`.

## Claimed Identity Boundary

`requested_by` is a caller-supplied claimed identity, nothing more. This command must never describe it, or the resulting approval record, as authenticated, verified, trusted, derived from Supabase Auth, or cryptographically proven. The final output always labels it explicitly as a **claimed requester identity**.

## Python Launcher Selection

Use the existing project convention for selecting a Python launcher:

1. Try `py`.
2. Otherwise try `python3`.
3. Otherwise use a `python` executable only after confirming it resolves to Python 3.10 or later.

Select one launcher and reuse the same launcher for every CLI invocation in this workflow.

Before continuing to any Supabase or MCP operation, confirm the selected launcher can import all three required modules:

- `core.approval_bridge_cli`
- `core.approval_mcp_adapter_cli`
- `core.approval_risk_request_cli`

If no launcher can be selected, or the import check fails for any of the three modules, stop and report that the approval-request Python CLIs are unavailable. Do not install any package. Do not modify the environment.

## Safe CLI Transport

Invoke all three CLIs through **stdin only**, exactly following the safe invocation pattern already established by `/add-evidence`, `/prepare-hayabusa-evidence`, and `/decision-review`. Never:

- pass JSON through command-line arguments;
- create a temporary JSON file;
- interpolate analyst content directly into executable shell code;
- write request data to disk.

## Stage 1 — Trusted Investigation-Context Lookup

Before any risk classification and before any approval insertion, obtain the investigation's current `status`/`confidence` from the database itself, through the existing trusted lookup operation — never from the analyst's own request. This is the only source of current investigation context anywhere in this workflow.

### Stage 1a — Approval Bridge Prepare

Use the existing two-phase approval bridge, in its prepare phase, to construct the exact `load_investigation_approval_context` operation descriptor — never a hand-written descriptor.

Construct exactly this object, in exactly this key order:

```json
{
  "phase": "prepare",
  "operation": "load_investigation_approval_context",
  "input": {
    "investigation_id": "<investigation_id exactly as supplied by the analyst, trimmed>"
  }
}
```

Send it through **stdin only** to:

- Windows: `py -m core.approval_bridge_cli`
- macOS or Linux: `python3 -m core.approval_bridge_cli`
- Only fall back to plain `python -m core.approval_bridge_cli` if it is confirmed to resolve to Python 3.10 or later.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2**: deterministic bridge/persistence validation failure (including a malformed `investigation_id`) — stop, report `CONTEXT_LOOKUP_FAILED`, and do not continue.
- **1**: unexpected internal failure — stop, report `CONTEXT_LOOKUP_FAILED`, and do not continue.
- **any other code**: unsupported CLI result — stop and report `CONTEXT_LOOKUP_FAILED`.

Reject the output when stderr is nonempty, stdout is empty, stdout is not valid JSON, stdout contains more than one JSON value, or the parsed value is not a JSON object.

Require the parsed object to contain exactly `phase`, `operation`, `descriptor`, with `phase` equal to `"prepare"` and `operation` equal to `"load_investigation_approval_context"`.

Require the descriptor to match the canonical fixed lookup shape already owned by `core.approval_persistence`: `operation` equal to `"select"`, `table` equal to `"investigations"`, `columns` equal exactly to `["investigation_id", "status", "confidence"]`, `filters` containing exactly `id`, and `limit` equal to `1`.

Call this the **prepared context descriptor**. Do not generate SQL directly from it — that remains the MCP adapter's exclusive concern, next.

### Stage 1b — MCP Adapter Prepare Call

Construct exactly this object:

```json
{
  "action": "prepare_call",
  "descriptor": "<the prepared context descriptor from Stage 1a>"
}
```

Send it through **stdin only** to:

- Windows: `py -m core.approval_mcp_adapter_cli`
- macOS or Linux: `python3 -m core.approval_mcp_adapter_cli`
- Only fall back to plain `python -m core.approval_mcp_adapter_cli` if it is confirmed to resolve to Python 3.10 or later.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2**: deterministic adapter validation failure (`approval_mcp_adapter_error`) — stop, report `CONTEXT_LOOKUP_FAILED`, and do not continue.
- **1**: unexpected internal failure (`internal_error`) — stop, report `CONTEXT_LOOKUP_FAILED`, and do not continue.
- **any other code**: unsupported CLI result — stop and report `CONTEXT_LOOKUP_FAILED`.

Reject the output when stderr is nonempty, stdout is empty, stdout is not valid JSON, stdout contains more than one JSON value, or the parsed value is not a JSON object.

Require the parsed object to contain exactly `tool` and `arguments`, with `tool` equal exactly to `mcp__supabase__execute_sql` and `arguments` containing exactly one field, `query`, a nonblank string equal to the fixed `SELECT id AS investigation_id, status, confidence FROM public.investigations WHERE id = <encoded uuid> LIMIT 1;` template.

Call this the **context MCP request**. Do not manually construct, edit, or append to this SQL anywhere in this workflow.

### Stage 1c — Execute Through Supabase MCP

Invoke only the tool named in the context MCP request — `mcp__supabase__execute_sql` — using exactly the `arguments` the adapter returned. Do not rewrite, edit, or append to the generated SQL in any way; do not execute a second SQL statement; do not use `apply_migration`; do not use a direct database client, driver, connection string, or REST request; do not retry automatically on any failure.

Capture the tool's raw response exactly as returned. Do not parse, inspect, or trust the raw MCP result directly anywhere in this command — it is untrusted data and is handed unmodified to Stage 1d next. Call this the **raw context MCP result**.

If the tool call itself fails to return a result at all (a transport-level failure distinct from a structured error envelope), stop and report `MCP_CALL_FAILED`.

### Stage 1d — MCP Adapter Normalize Response

Construct exactly this object:

```json
{
  "action": "normalize_response",
  "operation": "load_investigation_approval_context",
  "tool_response": "<the raw context MCP result from Stage 1c, exactly as returned>"
}
```

Send it through **stdin only** to the same `core.approval_mcp_adapter_cli` module used in Stage 1b.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2**: deterministic adapter validation failure — stop, report `CONTEXT_LOOKUP_FAILED`, and do not continue.
- **1**: unexpected internal failure — stop, report `CONTEXT_LOOKUP_FAILED`, and do not continue.
- **any other code**: unsupported CLI result — stop and report `CONTEXT_LOOKUP_FAILED`.

Require the parsed object to be exactly one of two canonical shapes: `{"kind": "rows", "rows": [...]}` or `{"kind": "transport_error"}`. Call this the **normalized context response**. A `transport_error` kind is not itself a local command failure at this stage — it is passed forward unchanged to Stage 1e, exactly as the bridge's own `verify_approval_operation` already expects.

### Stage 1e — Approval Bridge Verify

Construct exactly this object, in exactly this key order:

```json
{
  "phase": "verify",
  "operation": "load_investigation_approval_context",
  "input": "<the exact same input object used in Stage 1a>",
  "prepared_descriptor": "<the prepared context descriptor from Stage 1a>",
  "executor_response": "<the normalized context response from Stage 1d>"
}
```

Send it through **stdin only** to `core.approval_bridge_cli`.

Interpret the exit code strictly, and treat every one of these as fatal — never as a partial or provisional success:

- **0**: success — continue to the output checks below.
- **2**, code `approval_not_found`: the investigation does not exist (a genuine, structurally valid lookup that finds no row) — stop and report `CONTEXT_LOOKUP_FAILED`.
- **2**, code `approval_response_error`, `approval_persistence_error`, or `approval_bridge_error`: a malformed context row, a descriptor mismatch, or another deterministic failure — stop and report `CONTEXT_LOOKUP_FAILED`.
- **1**, code `approval_transport_error`: the MCP call or its normalization produced a transport failure — stop and report `MCP_CALL_FAILED`.
- **1**, code `internal_error`: an unexpected internal failure — stop and report `CONTEXT_LOOKUP_FAILED`.
- **any other code**: unsupported CLI result — stop and report `CONTEXT_LOOKUP_FAILED`.

Never present a result as successful after any nonzero exit code, and never automatically retry any of these outcomes, and never automatically re-run Stage 1 for any reason.

Require the parsed object to contain exactly `phase`, `operation`, `result`, with `phase` equal to `"verify"` and `operation` equal to `"load_investigation_approval_context"`. Require `result` to contain exactly `investigation_id`, `status`, `confidence` — no other field. Verify that `result.investigation_id` equals the canonical investigation UUID the trusted lookup itself resolved (the same value Stage 1a sent as `investigation_id`, canonicalized) — a mismatch is a `CONTEXT_LOOKUP_FAILED` failure.

Call this the **trusted investigation context**. It is the sole source of the investigation's current `status`/`confidence` anywhere in this workflow — the analyst's own request never contains, and this command never accepts, either value.

## Stage 2 — Deterministic Risk Classification Preview

Construct the **original legitimate request** — the same object used, unchanged, in Stage 3 below:

```json
{
  "investigation_id": "<canonical investigation UUID from the trusted investigation context>",
  "action_type": "update_investigation_state",
  "action_payload": {
    "status": "<only when the analyst supplied status>",
    "confidence": "<only when the analyst supplied confidence>"
  },
  "requested_by": "<the analyst's claimed identity, as typed>"
}
```

Include only whichever of `status`/`confidence` the analyst actually supplied inside `action_payload` — never both keys when only one was given, and never an empty `action_payload`. This reshaping performs no validation of its own; every real rule is enforced entirely by the CLI below.

Construct exactly this envelope, in exactly this key order:

```json
{
  "request": "<the original legitimate request>",
  "current_investigation": {
    "status": "<the trusted investigation context's own status>",
    "confidence": "<the trusted investigation context's own confidence>"
  }
}
```

Do not include `investigation_id` inside `current_investigation` — `core.approval_risk_request_cli`'s own contract accepts exactly `status` and `confidence` there, never a third field.

Send it through **stdin only** to:

- Windows: `py -m core.approval_risk_request_cli`
- macOS or Linux: `python3 -m core.approval_risk_request_cli`
- Only fall back to plain `python -m core.approval_risk_request_cli` if it is confirmed to resolve to Python 3.10 or later.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2**: deterministic request-validation or risk classification failure — stop, report `RISK_CLASSIFICATION_FAILED`, and do not continue.
- **1**: unexpected internal failure — stop, report `RISK_CLASSIFICATION_FAILED`, and do not continue.
- **any other code**: unsupported CLI result — stop and report `RISK_CLASSIFICATION_FAILED`.

Reject the output when stderr is nonempty, stdout is empty, stdout is not valid JSON, stdout contains more than one JSON value, or the parsed value is not a JSON object.

Require the parsed object to contain exactly `investigation_id`, `action_type`, `action_payload`, `requested_by`, `requested_at`, `risk_level`, `required_approvals`. Verify `investigation_id`, `action_type`, `action_payload`, and `requested_by` each equal the original legitimate request's own value.

Call this the **risk classification preview**. It exists only to independently confirm, in Stage 4 below, what the eventual insertion actually produced — it is never itself passed back as request input to Stage 3, because it carries derived fields (`risk_level`, `required_approvals`, a possibly different `requested_at`) that the insertion's own request contract has never accepted. The caller never chooses `risk_level` or `required_approvals` — both are always derived deterministically, by the same Python validator, from the trusted investigation context and the proposed change alone. This document never reproduces or re-explains `core.approval_risk.classify_approval_risk`'s own classification algorithm — that module remains its sole authority.

## Stage 3 — Risk-Aware Approval Insertion

### Stage 3a — Approval Bridge Prepare

Use the existing two-phase approval bridge, in its prepare phase, to construct the exact `insert_risk_aware_pending_approval` operation descriptor — never a hand-written descriptor.

Construct exactly this object, in exactly this key order:

```json
{
  "phase": "prepare",
  "operation": "insert_risk_aware_pending_approval",
  "input": {
    "request": "<the original legitimate request from Stage 2, unchanged>",
    "current_investigation": {
      "status": "<the trusted investigation context's own status>",
      "confidence": "<the trusted investigation context's own confidence>"
    },
    "expires_at": "<the canonical expires_at from analyst input, or null when omitted>"
  }
}
```

`request` is the exact same object built in Stage 2 — never the risk classification preview, and never a caller-supplied `risk_level`/`required_approvals`/`requested_by_normalized`. `current_investigation` is exactly the same trusted `status`/`confidence` from Stage 1e, never a caller-supplied value.

Send it through **stdin only** to `core.approval_bridge_cli`, using the same launcher selected earlier.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2**: deterministic bridge/persistence validation failure — stop, report `PREPARE_FAILED`, and do not continue.
- **1**: unexpected internal failure — stop, report `PREPARE_FAILED`, and do not continue.
- **any other code**: unsupported CLI result — stop and report `PREPARE_FAILED`.

Reject the output when stderr is nonempty, stdout is empty, stdout is not valid JSON, stdout contains more than one JSON value, or the parsed value is not a JSON object.

Require the parsed object to contain exactly `phase`, `operation`, `descriptor`, with `phase` equal to `"prepare"` and `operation` equal to `"insert_risk_aware_pending_approval"`.

Require the descriptor to match the canonical live-context-guarded insert-descriptor shape already owned by `core.approval_persistence`: `operation` equal to `"insert"`, `table` equal to `"approvals"`, a `values` mapping containing exactly `investigation_id`, `action_type`, `action_payload`, `requested_by`, `requested_at`, `status` (equal to `"pending"`), `risk_level`, `required_approvals`, `requested_by_normalized`, and `expires_at` only when one was supplied, plus top-level `expected_current_status` and `expected_current_confidence` fields (never inside `values`, never new `approvals` columns) equal exactly to the trusted investigation context's own `status`/`confidence`, and a `returning` list equal to the full eighteen-field risk-aware approval record contract. Verify every value in `values` matches the original legitimate request from Stage 2, and that `values.risk_level`/`values.required_approvals` equal the Stage 2 risk classification preview's own `risk_level`/`required_approvals` exactly.

This command never manually constructs or alters this descriptor's SQL, its `expected_current_status`/`expected_current_confidence` fields, the derived risk, the derived required-approvals count, or the normalized requester identity — every one of those is produced entirely by `core.approval_persistence.insert_risk_aware_pending_approval` itself, reached only through the bridge.

Call this the **prepared insertion descriptor**. Do not generate SQL directly from it — that remains the MCP adapter's exclusive concern, next.

### Stage 3b — MCP Adapter Prepare Call

Construct exactly this object:

```json
{
  "action": "prepare_call",
  "descriptor": "<the prepared insertion descriptor from Stage 3a>"
}
```

Send it through **stdin only** to `core.approval_mcp_adapter_cli`.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2**: deterministic adapter validation failure (`approval_mcp_adapter_error`) — stop, report `PREPARE_FAILED`, and do not continue.
- **1**: unexpected internal failure (`internal_error`) — stop, report `PREPARE_FAILED`, and do not continue.
- **any other code**: unsupported CLI result — stop and report `PREPARE_FAILED`.

Reject the output when stderr is nonempty, stdout is empty, stdout is not valid JSON, stdout contains more than one JSON value, or the parsed value is not a JSON object.

Require the parsed object to contain exactly `tool` and `arguments`, with `tool` equal exactly to `mcp__supabase__execute_sql` and `arguments` containing exactly one field, `query`, a nonblank string. This query is always the fixed `INSERT ... SELECT ... FROM public.investigations WHERE id = ... AND status = ... AND confidence = ...` template — never an unconditional `VALUES` insertion.

Call this the **insertion MCP request**. Never interpolate any caller-supplied text as a SQL identifier, and never construct SQL by hand anywhere in this workflow.

### Stage 3c — Execute Through Supabase MCP

Invoke only the tool named in the insertion MCP request — `mcp__supabase__execute_sql` — using exactly the `arguments` the adapter returned. Do not rewrite, edit, or append to the generated SQL in any way; do not execute a second SQL statement of any kind; do not use `apply_migration` in place of, or in addition to, this call; do not use a direct database client, driver, or connection string; do not use a REST request to Supabase; do not retry automatically on any failure.

Capture the tool's raw response exactly as returned. Do not parse, inspect, or trust the raw MCP result directly anywhere in this command — it is untrusted data and is handed unmodified to Stage 3d next. Call this the **raw insertion MCP result**.

If the tool call itself fails to return a result at all (a transport-level failure distinct from a structured error envelope), stop and report `MCP_CALL_FAILED`.

### Stage 3d — MCP Adapter Normalize Response

Construct exactly this object:

```json
{
  "action": "normalize_response",
  "operation": "insert_risk_aware_pending_approval",
  "tool_response": "<the raw insertion MCP result from Stage 3c, exactly as returned>"
}
```

Send it through **stdin only** to the same `core.approval_mcp_adapter_cli` module used in Stage 3b.

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2**: deterministic adapter validation failure (`approval_mcp_adapter_error` — an unsupported operation name or a non-mapping `tool_response`) — stop, report `RESPONSE_NORMALIZATION_FAILED`, and do not continue.
- **1**: unexpected internal failure (`internal_error`) — stop, report `RESPONSE_NORMALIZATION_FAILED`, and do not continue.
- **any other code**: unsupported CLI result — stop and report `RESPONSE_NORMALIZATION_FAILED`.

Require the parsed object to be exactly one of two canonical shapes:

```json
{"kind": "rows", "rows": [...]}
```

```json
{"kind": "transport_error"}
```

Call this the **normalized insertion response**. A `transport_error` kind is not itself treated as a local command failure at this stage — it is always passed forward unchanged to Stage 3e, exactly as the bridge's own `verify_approval_operation` already expects to receive it. Never short-circuit here, and never reinterpret a `transport_error` kind, or a genuine zero-row `{"kind": "rows", "rows": []}` result, as any kind of success.

### Stage 3e — Approval Bridge Verify

Use the same two-phase approval bridge, in its verify phase, to independently regenerate and check the prepared insertion descriptor, then complete the insert using the normalized response — reusing every one of `core.approval_persistence.insert_risk_aware_pending_approval`'s own existing response-validation rules unchanged. Never parse the raw MCP result or the normalized response directly in this command; only the bridge itself interprets what the normalized response means.

Construct exactly this object, in exactly this key order:

```json
{
  "phase": "verify",
  "operation": "insert_risk_aware_pending_approval",
  "input": "<the exact same input object used in Stage 3a>",
  "prepared_descriptor": "<the prepared insertion descriptor from Stage 3a>",
  "executor_response": "<the normalized insertion response from Stage 3d>"
}
```

Send it through **stdin only** to `core.approval_bridge_cli`.

Interpret the exit code strictly, and treat every one of these as fatal — never as a partial or provisional success:

- **0**: success — continue to Stage 4 below.
- **2**, code `approval_response_error`: the executor response was malformed, contained more than one row, or the returned row did not match the prepared binding (approval ID, investigation ID, action type, action payload, requested identity, or pending status) — stop and report `VERIFICATION_FAILED`.
- **2**, code `approval_persistence_error` or `approval_bridge_error`: a deterministic input or descriptor-mismatch failure — stop and report `VERIFICATION_FAILED`.
- **2**, code `approval_conflict`: the executor response **contained zero rows** — the live investigation `status`/`confidence` no longer matched the trusted context this request's risk was classified against (a concurrent change between Stage 1 and Stage 3), so the `INSERT ... SELECT ... WHERE` guard matched nothing and inserted nothing — stop and report `PERSISTENCE_CONFLICT`. No approval was created.
- **1**, code `approval_transport_error`: the MCP call or its normalization produced a transport failure — stop and report `MCP_CALL_FAILED`.
- **1**, code `internal_error`: an unexpected internal failure — stop and report `VERIFICATION_FAILED`.
- **any other code**: unsupported CLI result — stop and report `VERIFICATION_FAILED`.

Never present a result as successful after any nonzero exit code, and never automatically retry any of these outcomes. In particular, on `PERSISTENCE_CONFLICT`, never automatically re-run Stage 1 to fetch a fresh context and never automatically re-attempt Stage 3 — the analyst must re-issue `/request-case-update` from the beginning if they still want the change.

Require the parsed object to contain exactly `phase`, `operation`, `result`, with `phase` equal to `"verify"` and `operation` equal to `"insert_risk_aware_pending_approval"`. Require `result` to contain exactly the eighteen risk-aware approval-record fields (the existing sixteen plus `risk_level` and `required_approvals`), and verify:

- `id` is a structurally valid UUID (the newly generated approval ID);
- `investigation_id` equals the canonical investigation UUID from the trusted investigation context;
- `action_type` equals `update_investigation_state`;
- `action_payload` equals exactly the original legitimate request's own `action_payload`;
- `requested_by` equals the original legitimate request's own `requested_by`;
- `status` equals `"pending"`;
- every review and consumption field (`approved_by`, `approved_at`, `rejected_by`, `rejected_at`, `rejection_reason`, `consumed_by`, `consumed_at`) is `null`.

Call this the **created risk-aware approval record**.

## Stage 4 — Cross-Check the Created Approval

Before producing any success output, independently re-verify the created risk-aware approval record against the Stage 1 trusted investigation context and the Stage 2 risk classification preview. Every one of these must hold, or the command fails closed (`VERIFICATION_FAILED`) and no approval is reported as created, even though the database insert itself already succeeded:

1. `result.investigation_id` equals the requested `investigation_id` (the trusted investigation context's own canonical value).
2. `result.action_type` equals the validated requested action, `update_investigation_state`.
3. `result.risk_level` equals the Stage 2 risk classification preview's own `risk_level`.
4. `result.required_approvals` equals the Stage 2 risk classification preview's own `required_approvals`.
5. `result.status` equals `"pending"`.
6. `result.consumed_at` is `null`.
7. `result` satisfies the existing eighteen-field risk-aware record contract (`core.approval_transition.validate_risk_aware_approval_record`'s own shape) — already reused unchanged by the bridge/persistence layer in Stage 3e, re-confirmed here as a final defensive check.

A mismatch on any of these seven checks means this command's own independent verification disagrees with what the database reported — stop, report `VERIFICATION_FAILED`, and do not produce success output. Never attempt a repair, a fallback insertion, or a retry in response to a mismatch here.

## Required Success Output

Only after Stage 4 fully succeeds, display only this safe operational information:

- Approval ID
- Investigation ID
- Proposed Status (when present)
- Proposed Confidence (when present)
- Approval Status: `pending`
- Derived Risk Level
- Required Approval Count
- Claimed Requester Identity (labeled exactly as claimed, never as authenticated or verified)
- Requested At
- Expires At (display `null` explicitly when absent)
- A clear statement that the investigation has not been updated
- The next required action

The next required action always begins with:

```
/review-approval <approval-id>
```

and must distinguish the two possible required-approval counts:

- When `required_approvals` is `1`: state plainly that a single reviewer's `/review-approval <approval-id>` approval is sufficient to move this approval to `approved`.
- When `required_approvals` is `2`: state plainly that **two distinct reviewers** are required — the first `/review-approval <approval-id>` approval moves the approval only to `partially_approved`; a second, different reviewer must independently run `/review-approval <approval-id>` again before it reaches `approved`. The same reviewer identity can never satisfy both approvals, and the original requester can never approve their own request.

Never claim the approval is approved. Never claim the requested change has been applied. Never claim `requested_by` was authenticated or verified.

Never display any of the following anywhere in the success output:

- raw SQL;
- an MCP tool-call descriptor or argument object;
- `action_payload` contents beyond the safe Proposed Status/Proposed Confidence summary already listed above;
- `requested_by_normalized`;
- `expected_current_status`/`expected_current_confidence`;
- any reviewer identity;
- a credential, project URL, project reference, or access token;
- database connection or ownership metadata.

## Required Failure Behavior

Use only these fixed, non-sensitive failure categories. Never expose a raw PostgreSQL error, generated SQL, a credential, a project URL, a project reference, an access token, an MCP untrusted-data delimiter, a stack trace, or an internal owner detail in any of them.

### INVALID_INPUT

Malformed JSON, trailing content, a non-object top-level value, an unknown or Block-6-prohibited field, a missing `investigation_id`/`requested_by`, neither `status` nor `confidence` present, an explicit `null` for `status`/`confidence`, or a blank `requested_by`.

### CONTEXT_LOOKUP_FAILED

Stage 1 (trusted investigation-context lookup) reporting a malformed `investigation_id`, an investigation that does not exist, a malformed or mismatched context row, a descriptor mismatch, or any other deterministic or internal failure during the lookup's prepare, adapter, or verify phases.

### RISK_CLASSIFICATION_FAILED

Stage 2 (`core.approval_risk_request_cli`) reporting a deterministic request-validation or risk classification failure, or an unexpected internal failure.

### VALIDATION_FAILED

Reserved for a local structural mismatch this command's own boundary detects that the delegated validators do not already cover on their own (for example, an internal consistency check between the raw analyst input and a validated-output object).

### PREPARE_FAILED

Stage 1a, Stage 1b, Stage 3a, or Stage 3b reporting a deterministic validation failure or an unexpected internal failure.

### MCP_CALL_FAILED

Stage 1c or Stage 3c's tool call itself failing to return a result, or Stage 1e/Stage 3e classifying the outcome as `approval_transport_error`.

### RESPONSE_NORMALIZATION_FAILED

Stage 1d or Stage 3d (adapter `normalize_response`) reporting a deterministic validation failure or an unexpected internal failure.

### VERIFICATION_FAILED

Stage 1e/Stage 3e reporting a malformed, multiple-row, or binding-mismatched response, a descriptor mismatch, or any other deterministic or internal failure not covered above, or a Stage 4 cross-check mismatch.

### PERSISTENCE_CONFLICT

The Stage 3e insertion's executor response contained zero rows: the live investigation's `status`/`confidence` no longer matched the trusted context this request's risk was classified against — a concurrent investigation change between the trusted lookup (Stage 1) and the insertion (Stage 3). No approval was created. The user-facing message must explain plainly that the investigation changed after the lookup and that the analyst must re-issue `/request-case-update` from the beginning to classify risk against the investigation's current context. Never retried automatically, and never followed by a fallback unconditional insertion.

Do not automatically retry any failure in any category above.

## Security Boundaries

This command must never:

- update `public.investigations`, directly or indirectly;
- call `public.consume_approval_and_update_investigation_state`, `public.record_approval_review_and_promote_status`, or any other atomic RPC;
- approve, reject, or consume an approval;
- change an existing approval row of any kind;
- accept a reviewer identity (`approved_by`/`rejected_by`/`reviewed_by`) or a consumer identity (`consumed_by`) as input;
- execute user-supplied SQL, or interpolate any caller-supplied text as a SQL identifier;
- use `apply_migration`;
- alter schema, permissions, RLS, a policy, or a trigger;
- bypass `core.approval_bridge_cli` or `core.approval_mcp_adapter_cli`;
- treat any typed confirmation phrase as authorization for a mutation beyond the one pending-approval insert this command performs;
- use the legacy direct-update path `/update-case` uses;
- accept the investigation's current `status`/`confidence` as caller input — only Stage 1's trusted lookup ever supplies it;
- accept a caller-chosen `risk_level` or `required_approvals` — both are always derived deterministically by `core.approval_risk`;
- accept a caller-supplied `expected_current_status`/`expected_current_confidence` — both are always derived by `core.approval_persistence.insert_risk_aware_pending_approval` from the trusted lookup alone;
- fall back to the plain, non-context-guarded `insert_pending_approval` operation, or to an unconditional `VALUES` insertion, for any reason, including a `PERSISTENCE_CONFLICT`;
- retry Stage 1 or Stage 3 automatically after any conflict or failure.

The only permitted database mutation anywhere in this command is the insertion of one validated, pending, risk-aware approval, through the existing two-phase prepare/verify bridge and MCP adapter workflow, exactly as described above.

## Required Output

Produce:

- Request Validation Result
- Trusted Investigation Context (Stage 1)
- Risk Classification Preview (Stage 2)
- Prepared Insertion Descriptor (Stage 3a)
- Insertion MCP Request (Stage 3b)
- Raw Insertion MCP Result Handling (Stage 3c)
- Normalized Insertion Response (Stage 3d)
- Created Risk-Aware Approval Record (Stage 3e)
- Cross-Check (Stage 4)
- Created Approval
- Recommended Next Action

## Example Requests

### 1. Status-only request

```json
{
  "investigation_id": "5b1f9c2e-2a3f-4b8e-9a10-1234567890ab",
  "requested_by": "Roshini Analyst",
  "status": "escalated"
}
```

### 2. Confidence-only request

```json
{
  "investigation_id": "5b1f9c2e-2a3f-4b8e-9a10-1234567890ab",
  "requested_by": "Roshini Analyst",
  "confidence": "high"
}
```

### 3. Status-and-confidence request

```json
{
  "investigation_id": "5b1f9c2e-2a3f-4b8e-9a10-1234567890ab",
  "requested_by": "Roshini Analyst",
  "status": "escalated",
  "confidence": "high"
}
```

### 4. Request with expires_at

```json
{
  "investigation_id": "5b1f9c2e-2a3f-4b8e-9a10-1234567890ab",
  "requested_by": "Roshini Analyst",
  "status": "escalated",
  "expires_at": "2026-08-05T00:00:00Z"
}
```

## Safety Rules

- `requested_by` is a claimed identity only — never authenticated, verified, trusted, derived from Supabase Auth, or cryptographically proven.
- Never accept `approval_id`/`id` as input — the approval UUID is always generated by the database insert itself.
- Never accept a reviewer or consumer identity as input.
- Never accept the investigation's current `status`/`confidence`, a `risk_level`, a `required_approvals` count, a `requested_by_normalized` value, or an `expected_current_status`/`expected_current_confidence` pair as input — every one of these is always derived internally, never supplied by the caller.
- Never approve, reject, or consume an approval.
- Never update `public.investigations`.
- Never call the atomic consumption RPC.
- Never generate SQL directly, and never interpolate caller-supplied text as a SQL identifier — only `core.approval_mcp_adapter_cli` ever produces SQL, from an already-verified descriptor.
- Never bypass `core.approval_bridge_cli` or `core.approval_mcp_adapter_cli`.
- Never use `apply_migration` in this workflow.
- Never use the legacy direct-update path `/update-case` uses.
- Never fall back to the plain `insert_pending_approval` operation or to an unconditional `VALUES` insertion for the risk-aware path, for any reason.
- Never retry any failure automatically. This includes a `PERSISTENCE_CONFLICT` — the analyst must re-issue the request from the beginning.
- Never expose a raw PostgreSQL error, generated SQL, a credential, a project URL, a project reference, an access token, an MCP untrusted-data delimiter, a stack trace, or an internal owner detail.
- Never claim the created approval is approved or that the requested change has been applied — it remains `pending` until the required number of distinct reviewers approve it via `/review-approval`.
