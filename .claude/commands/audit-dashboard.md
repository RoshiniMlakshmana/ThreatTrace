---
description: Create a tamper-evident audit record, verify a supplied audit chain, or summarize a supplied audit-record batch, through the read-only Tamper-Evident Audit & Evaluation Dashboard
argument-hint: "{operation: \"create\"|\"verify\"|\"dashboard\", ...}"
---

# ThreatTrace Audit Dashboard Workflow

`/audit-dashboard` is Block 14's Tamper-Evident Audit & Evaluation Dashboard boundary: it answers three things only:

- *what does a deterministic, SHA-256-linked audit record about an already-existing event look like?* (`create`)
- *is a supplied sequence of audit records internally structurally/digest/linkage self-consistent, and does its head match an independently supplied expected digest, when one is provided?* (`verify`)
- *what do the supplied audit records contain?* (`dashboard`)

by consulting the existing, already-committed, deterministic core (`core.tamper_evident_audit`, `core.evaluation_dashboard`, reached only through `core.audit_dashboard_cli`) — and nothing else. This command is strictly a transport adapter.

Caller-supplied `operation` + fields → command-level envelope validation → `core.audit_dashboard_cli`, unchanged → deterministic audit or dashboard result

`/audit-dashboard` never authenticates a writer, never signs anything, never persists anything, never claims a supplied chain is historical truth, and never calls Supabase, MCP, or the network. It never decides whether `event_type`/`sequence`/`event_summary`/`previous_record_digest` is valid, whether a supplied chain is internally consistent, or how supplied records should be aggregated — every one of those is always decided later, entirely by `core.tamper_evident_audit`/`core.evaluation_dashboard`, reached only through `core.audit_dashboard_cli`, never reimplemented in this document.

## What This Provides — and Does Not

The strongest honest claim this command can ever make:

> Given a supplied sequence of audit records, ThreatTrace can detect whether the supplied records are internally structurally/digest/linkage consistent, and whether their supplied head matches an independently supplied expected head digest.

It is **not**: authenticated logging; a digital signature; proof of who wrote a record; trusted timestamping (`occurred_at` is caller-supplied, never independently attested); tamper *prevention* (a fully rewritten chain can still verify internally if no independently trusted anchor is supplied); immutable storage (nothing is persisted anywhere by this command); non-repudiation; replay protection; or proof that a supplied chain is *the* true historical chain. A `verification_outcome`/`audit.verification_outcome` of `"invalid"` is a normal, successfully handled result, never a command failure — an internally broken or unanchored chain is always surfaced honestly, never hidden.

## Request Input

$ARGUMENTS

## Stage 0 — Command-Level Input Shape Validation

`$ARGUMENTS` must be exactly one JSON object. Perform every check below, in order, before Stage 1 — before any CLI invocation:

1. Parse `$ARGUMENTS` as exactly one JSON value.
2. Reject malformed JSON.
3. Reject trailing non-whitespace content after the one parsed JSON value.
4. Reject a top-level value that is not a JSON object.
5. Require an `"operation"` field equal to exactly `"create"`, `"verify"`, or `"dashboard"`. Reject any other value, including a missing one.
6. For `"create"`: require exactly `operation`, `sequence`, `event_type`, `event_reference`, `event_summary`, `occurred_at`, `previous_record_digest` — the same seven-key envelope `core.audit_dashboard_cli` itself requires. Reject a missing or extra field.
7. For `"verify"`: require exactly `operation`, `records`, `expected_head_digest` — the same three-key envelope the CLI itself requires. Reject a missing or extra field.
8. For `"dashboard"`: require exactly `operation`, `records`, `expected_head_digest` — identical shape to `verify`. Reject a missing or extra field.

This command performs **no semantic validation of any field beyond confirming the envelope has the right keys for the selected operation.** It does not decide whether `sequence`/`event_type`/`event_reference`/`event_summary`/`occurred_at`/`previous_record_digest` is valid, whether `records` forms an internally consistent chain, or whether `expected_head_digest` matches — every one of those is always decided later, entirely by `core.tamper_evident_audit`/`core.evaluation_dashboard`, reached only through `core.audit_dashboard_cli`. This command never inserts, synthesizes, defaults, or overwrites `operation` on the caller's behalf, never generates a `sequence` number, never generates `occurred_at` or any other timestamp, never computes a digest, never modifies a supplied record, and never fabricates an `expected_head_digest`/anchor. Every value is passed through completely unchanged.

Call the fully validated envelope the **candidate envelope**.

## Python Launcher Selection

Use the existing project convention for selecting a Python launcher:

1. Try `py`.
2. Otherwise try `python3`.
3. Otherwise use a `python` executable only after confirming it resolves to Python 3.10 or later.

Before continuing, confirm the selected launcher can import `core.audit_dashboard_cli`. If no launcher can be selected, or the import check fails, stop and report `AUDIT_DASHBOARD_CLI_UNAVAILABLE`. Do not install any package. Do not modify the environment.

## Safe CLI Transport

Invoke the CLI through **stdin only**, exactly following the safe invocation pattern already established by `/evaluate-tool-call`, `/evaluate-agent-tool-call`, `/create-decision-binding`, `/ai-security-lab`, and `/record-analyst-feedback`. Never pass JSON through command-line arguments, never create a temporary JSON file, never interpolate caller content directly into executable shell code, and never write request data to disk.

## Stage 1 — Invoke the Audit Dashboard CLI

Send the **candidate envelope exactly as the caller supplied it** — every field, including the caller's own `operation`, unchanged, unreordered, unrepaired — through **stdin only** to `py -m core.audit_dashboard_cli` (or the equivalent selected launcher). This command never adds, removes, renames, normalizes, redacts, reorders, or otherwise transforms any field or value. Never call `core.tamper_evident_audit` or `core.evaluation_dashboard` directly, never call any Block 8/9/10/Mutation-Freeze/Block 11–12/Block 13 module, and never reimplement any canonical hashing, digest verification, chain-linkage verification, trusted-anchor comparison, or dashboard aggregation logic this document does not own.

### Audit Dashboard CLI exit handling

- **0**: success — a created audit record, or a `"valid"`/`"invalid"` `verification_outcome` (top-level for `verify`, or inside `audit` for `dashboard`) — all are normal, successful results. `"invalid"` is never treated as a failure. Continue to the output validation below.
- **2**: a deterministic command/CLI-envelope or core structural-validation failure — stop and report `AUDIT_DASHBOARD_VALIDATION_FAILED`.
- **1**: an unexpected internal failure — stop and report `AUDIT_DASHBOARD_INTERNAL_FAILURE`.
- **any other code**: stop and report `AUDIT_DASHBOARD_INTERNAL_FAILURE`.

Never automatically retry any of these outcomes, and never fall back to displaying a partially-constructed or hand-assembled result.

### Audit Dashboard CLI success-output validation

Require stdout to be exactly one JSON object.

For `"create"`, require exactly the ten fields `core.tamper_evident_audit.create_audit_record` always returns: `audit_version`, `sequence`, `event_type`, `event_reference`, `event_summary`, `occurred_at`, `previous_record_digest`, `audit_persisted`, `execution_performed`, `record_digest`. Require `audit_version` to equal exactly `"1"`, `audit_persisted` to equal exactly `false`, and `execution_performed` to equal exactly `false`.

For `"verify"`, require exactly the eight fields `verify_audit_chain` always returns: `verification_version`, `verification_outcome`, `internal_chain_valid`, `trusted_anchor_verified`, `record_count`, `head_digest`, `observed_evidence`, `execution_performed`. Require `verification_outcome` to be exactly `"valid"` or `"invalid"`, and `execution_performed` to equal exactly `false`.

For `"dashboard"`, require exactly the seven fields `summarize_audit_dashboard` always returns: `dashboard_version`, `audit`, `event_type_counts`, `evaluation_counts`, `feedback_counts`, `policy_counts`, `execution_performed`. Require `execution_performed` to equal exactly `false`.

If the result is missing a required field, contains an unrecognized field, or has `audit_persisted`/`execution_performed` other than `false`: stop, report `AUDIT_DASHBOARD_VALIDATION_FAILED`, and never display the result as if it were successful. Do not repair, complete, or reinterpret a malformed result by hand.

Call the fully validated result the **audit dashboard result**.

## Required Output

Produce, only after the audit dashboard result passes every check above:

### For `"create"`

Display `sequence`, `event_type`, `event_reference`, `event_summary` (when not `null`), `occurred_at`, `previous_record_digest`, and `record_digest`. Label `record_digest` explicitly as an **"SHA-256 content digest"** — never a signature, an authenticated hash, or immutable proof. State plainly: **`audit_persisted: false`** and **`execution_performed: false`**.

### For `"verify"`

Display `verification_outcome`, `internal_chain_valid`, `trusted_anchor_verified`, `record_count`, `head_digest`, and every item in `observed_evidence`.

- `internal_chain_valid: true` means only: *the supplied records are internally structurally/digest/linkage consistent* — never that they represent verified historical truth.
- When `trusted_anchor_verified: true`, state only: *the supplied internally-valid chain's head matched the expected head digest supplied by the caller* — never that ThreatTrace itself trusts that anchor's origin.
- When `trusted_anchor_verified: false`, state that the anchor did not match, or the chain was invalid or empty.
- When `trusted_anchor_verified: null`, state plainly: *no external expected head digest was supplied.*
- When `verification_outcome` is `"invalid"`, present it as a normal, successful verification finding — never a command failure — and display the matched evidence codes plainly.

### For `"dashboard"`

Display `audit` (using the same `"verify"` presentation rules above for its nested fields), `event_type_counts`, `evaluation_counts`, `feedback_counts`, and `policy_counts`. State explicitly that every metric is **derived only from the supplied audit records** — never label them live metrics, authoritative history, authenticated telemetry, or SOC real-time data. When `audit.verification_outcome` is `"invalid"`, state clearly that the displayed counts reflect only what is visibly present in the supplied (internally inconsistent) records, never verified historical truth.

Never display:

- a raw exception message, exception class name, traceback, or internal stack detail;
- a claim that any record's writer was authenticated;
- a claim that `occurred_at` is a trusted timestamp;
- a claim that `record_digest` is a signature or authenticated hash;
- a claim that a matching anchor proves the anchor's own origin was trustworthy;
- a claim that tampering is prevented, that non-repudiation exists, or that replay protection exists;
- a claim that dashboard data is live, real-time, or authenticated telemetry;
- the internal construction of the CLI command or its raw stdin envelope.

## Required Failure Categories

Use only these fixed, non-sensitive failure categories. Never expose a raw exception message, exception class name, traceback, credential, path, or internal detail in any of them.

### AUDIT_DASHBOARD_CLI_UNAVAILABLE

The Python launcher or `core.audit_dashboard_cli` import check failing before any stage below runs.

### AUDIT_DASHBOARD_VALIDATION_FAILED

Stage 0 rejecting malformed JSON, non-object top-level JSON, trailing content, a missing/unknown top-level field (including an invalid or missing `operation`), or a missing/unknown envelope field for the selected operation; or Stage 1 reporting CLI exit code 2, or the CLI success-output validation failing.

### AUDIT_DASHBOARD_INTERNAL_FAILURE

Stage 1 reporting CLI exit code 1 or any other unexpected code.

Do not automatically retry any failure in any category above.

## No-Fallback and No-Retry Policy

On any command-level, CLI, parsing, or result-validation failure:

- stop;
- do not retry automatically;
- do not silently adjust any supplied field to force a different outcome;
- do not invoke Block 8, Block 9, the Emergency Mutation Freeze, Block 10, the AI Security Evaluation Lab, or Analyst Feedback creation to "double-check" or regenerate the event this audit record references;
- do not invoke `/evaluate-tool-call`, `/evaluate-agent-tool-call`, `/create-decision-binding`, `/ai-security-lab`, `/record-analyst-feedback`, `/request-case-update`, `/review-approval`, or `/apply-case-update` automatically.

The caller may always safely resubmit a corrected command later — this command itself never performs that retry automatically, and never hides it.

## Explicit Execution Prohibitions

This command must never invoke, directly or indirectly:

- `core.agent_gateway.evaluate_tool_call` or `core.agent_gateway_cli`;
- `core.agent_identity_policy.evaluate_agent_tool_call` or `core.agent_identity_policy_cli`;
- `core.mutation_freeze.evaluate_mutation_freeze`;
- `core.decision_binding.create_decision_binding`/`verify_decision_binding` or `core.decision_binding_cli`;
- `core.ai_asset_registry.evaluate_ai_security_case` or `core.ai_asset_registry_cli`;
- `core.analyst_feedback.create_analyst_feedback` or `core.analyst_feedback_cli`;
- `mcp__supabase__execute_sql`, `execute_sql`, `apply_migration`, or any Block 6 mutation operation;
- a subprocess of any kind other than the one selected Python launcher running `core.audit_dashboard_cli`;
- a dynamically imported, caller-selected module or function.

The only process this command ever executes is the one committed, deterministic adapter: `py -m core.audit_dashboard_cli` (or the equivalent selected launcher), invoked exactly once per command invocation.

## Security Boundaries

This command must never:

- accept a caller-supplied `audit_version`, `verification_version`, `dashboard_version`, `audit_persisted`, or `execution_performed` as a command-level override;
- decide whether a supplied `event_type`/`sequence`/`event_summary`/`previous_record_digest` is valid, whether a supplied `records` list forms an internally consistent chain, or how to aggregate supplied records — every one of those belongs entirely to `core.tamper_evident_audit`/`core.evaluation_dashboard`;
- read the system clock or generate `occurred_at`, a `sequence` number, or any other value the caller must supply;
- compute a digest of any kind;
- claim a record's writer was authenticated, that `occurred_at` is a trusted timestamp, that `record_digest` is a signature, that tampering is prevented, that non-repudiation exists, or that replay protection exists;
- claim a matching `trusted_anchor_verified` proves the anchor's own origin was trustworthy;
- treat `verification_outcome: "invalid"` (or `audit.verification_outcome: "invalid"`) as a command-level failure;
- persist an audit record anywhere, or claim one was persisted;
- claim dashboard metrics are live, real-time, or authenticated telemetry;
- call `core.agent_gateway`, `core.agent_identity_policy`, `core.mutation_freeze`, `core.decision_binding`, `core.ai_asset_registry`, or `core.analyst_feedback`, directly or indirectly;
- retry any stage automatically, or fall back to a substitute construction after any failure;
- display any raw exception message, exception class name, traceback, credential, environment variable, filesystem path, or internal owner detail.

## Example Invocations

```json
{
  "operation": "create",
  "sequence": 1,
  "event_type": "security_evaluation_result",
  "event_reference": "evaluate:emergency_freeze_bypass:identity_agent:coordinator_agent",
  "event_summary": {"outcome": "pass", "case_type": "emergency_freeze_bypass"},
  "occurred_at": "2026-08-12T18:00:00Z",
  "previous_record_digest": null
}
```

```json
{
  "operation": "verify",
  "records": ["<previously created audit records>"],
  "expected_head_digest": null
}
```

```json
{
  "operation": "dashboard",
  "records": ["<previously created audit records>"],
  "expected_head_digest": null
}
```

## Safety Rules

- Accept exactly one JSON object with exactly the fields required for the selected `operation`. Never insert, synthesize, default, or overwrite `operation` or any other field on the caller's behalf.
- Never generate `occurred_at`, a `sequence` number, a digest, or an anchor, and never read the system clock.
- Never bypass `core.audit_dashboard_cli`, and never reimplement any canonical hashing, digest/chain-verification, or dashboard-aggregation rule that `core.tamper_evident_audit`/`core.evaluation_dashboard` already own.
- Never call `core.agent_gateway`, `core.agent_identity_policy`, `core.mutation_freeze`, `core.decision_binding`, `core.ai_asset_registry`, or `core.analyst_feedback` — the referenced event is never recomputed.
- Never claim a writer was authenticated, that a timestamp is trusted, that a digest is a signature, that tampering is prevented, that non-repudiation exists, or that replay protection exists.
- Never claim a matching anchor proves its own trustworthy origin.
- Never treat `"invalid"` as a command failure — always present it as a normal, successful verification/dashboard finding.
- Never persist an audit record, or claim one was persisted.
- Never claim dashboard metrics are live, real-time, or authenticated telemetry.
- Never call `mcp__supabase__execute_sql`, `execute_sql`, `apply_migration`, or any Block 6 mutation operation.
- Never automatically invoke `/evaluate-tool-call`, `/evaluate-agent-tool-call`, `/create-decision-binding`, `/ai-security-lab`, `/record-analyst-feedback`, `/request-case-update`, `/review-approval`, or `/apply-case-update`.
- Never retry any stage automatically, and never fall back to a substitute construction after a failure.
- Never expose a raw exception message, exception class name, traceback, credential, project reference, environment variable, filesystem path, or internal owner detail.
