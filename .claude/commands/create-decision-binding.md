---
description: Create an unsigned Decision Binding correlating an already-produced Block 9 identity-policy result with exact proposed tool arguments, without evaluating policy or executing anything
argument-hint: "{identity_policy_result, arguments, issued_at, expires_at, approval_reference}"
---

# ThreatTrace Create Decision Binding Workflow

`/create-decision-binding` is Block 10's Decision-to-Execution Binding boundary: it answers *do these exact proposed tool arguments and this exact already-produced Block 9 identity-policy result agree with each other, right now, for this caller-chosen time window?* by consulting the existing, already-committed, deterministic correlator (`core.decision_binding.create_decision_binding`, via `core.decision_binding_cli`) — and nothing else. This command is strictly a transport adapter:

Caller-supplied Block 9 result + exact arguments + caller-supplied `issued_at`/`expires_at` + optional `approval_reference` → command-level shape validation → `core.decision_binding_cli` (`operation: "create"`) → deterministic `created` / `refused` Decision Binding result

`/create-decision-binding` never evaluates Block 8 or Block 9 policy itself, never authenticates an agent, never executes a tool, never calls Supabase or MCP, never executes SQL, never reads the system clock, never generates a timestamp, and never persists, signs, or HMACs the resulting binding. It never decides whether the supplied Block 9 result is structurally acceptable, whether the proposed arguments canonicalize, or whether the requested lifetime is within the approved maximum — every one of those belongs entirely to `core.decision_binding`, reached only through `core.decision_binding_cli`, never reimplemented in this document.

## What a Decision Binding Is — and Is Not

A Decision Binding is a **deterministic, unsigned content correlation** between an already-produced policy decision and the exact arguments it was decided for, valid for a caller-chosen time window of at most 300 seconds. It is:

- **not** authentication;
- **not** authorization;
- **not** an execution permit;
- **not** a capability token, a secure token, or an authenticated token;
- **not** cryptographic proof of origin;
- **not** tamper-proof against a caller who can reconstruct a self-consistent unsigned artifact from the binding's own plain field values (SHA-256 here means deterministic content correlation only, never a signature);
- **not** replay protection of any kind;
- **not** persisted anywhere by this command.

`created` and `refused` are both **successful, valid evaluation outcomes** of this command — a `refused` binding is never a command-level or CLI failure, and never automatically retried, repaired, or resubmitted with adjusted values.

## Creation Input

$ARGUMENTS

## Stage 0 — Command-Level Input Shape Validation

`$ARGUMENTS` must be exactly one JSON object. Perform every check below, in order, before Stage 1 — before any CLI invocation:

1. Parse `$ARGUMENTS` as exactly one JSON value.
2. Reject malformed JSON.
3. Reject trailing non-whitespace content after the one parsed JSON value.
4. Reject a top-level value that is not a JSON object.
5. Allow exactly these five fields, no more and no fewer: `identity_policy_result`, `arguments`, `issued_at`, `expires_at`, `approval_reference`. Reject any field this list does not name — in particular, always reject a caller-supplied `operation`: this command is already specifically the creation operation, and the caller can never select or override which Decision Binding CLI operation runs.
6. Require all five fields to be present. `approval_reference` is a required key whose value may be `null`. `identity_policy_result` and `arguments` are each required only as a **present JSON value** — object, array, string, number, boolean, or `null` are all accepted at this stage without distinction.

This command performs **no type or structural validation of `identity_policy_result` or `arguments` at all, beyond confirming each key is present under item 6.** It never requires either value to be a JSON object, and never rejects one for being an array, string, number, boolean, or `null` — that judgment belongs entirely to `core.decision_binding.create_decision_binding`, which already handles a non-Mapping value gracefully and deterministically: a non-Mapping `identity_policy_result` produces `binding_outcome: "refused"` with `refusal_reason.code: "INVALID_IDENTITY_RESULT_STRUCTURE"`, and a non-Mapping `arguments` produces `binding_outcome: "refused"` with `refusal_reason.code: "ARGUMENTS_NOT_A_MAPPING"` — both normal, successful evaluation outcomes, never a command-level `INVALID_INPUT` failure. This command does not decide, at this or any other stage, whether `identity_policy_result` represents a structurally valid Block 9 result, whether its `canonical_agent_id`, `agent_role`, `canonical_tool_name`, `gateway_decision`, or `final_decision` are individually valid, whether it represents an allowed capability or operation class, or whether `arguments` can be canonically serialized — every one of those is always decided later, entirely by `core.decision_binding.create_decision_binding`, reached only through `core.decision_binding_cli`. Neither value's own field names, elements, or contents are ever transformed, stripped, repaired, or reinterpreted by this command. `issued_at`, `expires_at`, and `approval_reference` are likewise passed through exactly as supplied, with no reformatting: `approval_reference` in particular is treated as an **opaque identifier** — it is never assumed to be a UUID, never parsed, and never normalized; only `null` or a non-blank string reaches the CLI, and the blank/non-string rejection itself belongs to the core, not this command.

Call the five validated values the **candidate identity policy result**, the **candidate arguments object**, the **candidate issued-at value**, the **candidate expires-at value**, and the **candidate approval reference**.

## Python Launcher Selection

Use the existing project convention for selecting a Python launcher:

1. Try `py`.
2. Otherwise try `python3`.
3. Otherwise use a `python` executable only after confirming it resolves to Python 3.10 or later.

Before continuing to Stage 1, confirm the selected launcher can import `core.decision_binding_cli`. If no launcher can be selected, or the import check fails, stop and report `DECISION_BINDING_CLI_UNAVAILABLE`. Do not install any package. Do not modify the environment.

## Safe CLI Transport

Invoke the CLI through **stdin only**, exactly following the safe invocation pattern already established by `/evaluate-tool-call`, `/evaluate-agent-tool-call`, `/request-case-update`, `/review-approval`, and `/apply-case-update`. Never pass JSON through command-line arguments, never create a temporary JSON file, never interpolate caller content directly into executable shell code, and never write request data to disk.

## Stage 1 — No Timestamp Is Generated

Unlike `/evaluate-tool-call` and `/evaluate-agent-tool-call`, this command **never reads the system clock and never generates a timestamp of any kind.** `issued_at` and `expires_at` are security-relevant values that only the caller (or an upstream orchestrator that already knows when the bound Block 9 evaluation occurred) can correctly supply — `core.decision_binding` itself never reads the clock, by design, and this command must not silently invent that behavior on its behalf. The candidate issued-at and expires-at values from Stage 0 are carried forward completely unchanged. There is no "Stage 1" clock read to perform; this stage exists only to record that omission explicitly.

## Stage 2 — Invoke the Decision Binding CLI

Construct exactly this object, in exactly this key order:

```json
{
  "operation": "create",
  "identity_policy_result": "<the candidate identity policy result from Stage 0, unchanged>",
  "arguments": "<the candidate arguments object from Stage 0, unchanged>",
  "issued_at": "<the candidate issued-at value from Stage 0, unchanged>",
  "expires_at": "<the candidate expires-at value from Stage 0, unchanged>",
  "approval_reference": "<the candidate approval reference from Stage 0, unchanged>"
}
```

Never add, remove, rename, normalize, redact, or otherwise transform any field or value beyond adding the fixed literal `"operation": "create"`. Never substitute a caller-supplied value for any of the other five fields. Never call `core.decision_binding` directly, and never reimplement any part of its structural validation, canonicalization, or correlation logic in this document. Never call `core.agent_gateway`, `core.agent_gateway_cli`, `core.agent_identity_policy`, or `core.agent_identity_policy_cli` — the supplied `identity_policy_result` is consumed exactly as given, never (re)produced by this workflow.

Send it through **stdin only** to `py -m core.decision_binding_cli` (or the equivalent selected launcher).

### Decision Binding CLI exit handling

- **0**: success — the result is complete regardless of whether `binding_outcome` is `created` or `refused`; both are normal, successful evaluation outcomes. Continue to the output validation below.
- **2**: a deterministic command/CLI-envelope validation failure — stop and report `DECISION_BINDING_VALIDATION_FAILED`.
- **1**: an unexpected internal failure — stop and report `DECISION_BINDING_INTERNAL_FAILURE`.
- **any other code**: stop and report `DECISION_BINDING_INTERNAL_FAILURE`.

Never automatically retry any of these outcomes, and never fall back to displaying a partially-constructed or hand-assembled result.

### Decision Binding CLI success-output validation

Require stdout to be exactly one JSON object containing exactly the fourteen fields `core.decision_binding.create_decision_binding` always returns: `decision_binding_version`, `binding_outcome`, `canonical_agent_id`, `agent_role`, `canonical_tool_name`, `gateway_decision`, `policy_decision`, `argument_digest`, `approval_reference`, `issued_at`, `expires_at`, `binding_digest`, `refusal_reason`, `identity_authenticated`, `execution_performed`.

Require `decision_binding_version` to equal exactly `"1"`, `identity_authenticated` to equal exactly `false`, and `execution_performed` to equal exactly `false`. Require `binding_outcome` to be exactly one of `created` or `refused`:

| `binding_outcome` | `refusal_reason` | other fields |
|---|---|---|
| `created` | `null` | `canonical_agent_id`, `agent_role`, `canonical_tool_name`, `gateway_decision`, `policy_decision`, `argument_digest`, `issued_at`, `expires_at`, `binding_digest` all non-null |
| `refused` | an object with `code`/`message` | every other field is `null` |

If the result is missing a required field, contains an unrecognized field, has `decision_binding_version` other than `"1"`, has `identity_authenticated` other than `false`, has `execution_performed` other than `false`, or has a `binding_outcome`/`refusal_reason`/other-fields combination that does not match the table above exactly: stop, report `DECISION_BINDING_VALIDATION_FAILED`, and never display the result as if it were successful. Treating an unexpectedly `true` `identity_authenticated` or `execution_performed` as anything other than an invalid, undisplayable result is itself a security requirement of this command — a misleading success must never be shown. Do not repair, complete, or reinterpret a malformed result by hand.

Call the fully validated result the **Decision Binding result**.

## Required Output

Produce, only after the Decision Binding result passes every check above:

- `binding_outcome` (`created` / `refused`)
- `decision_binding_version`
- **`identity_authenticated: false`**
- **`execution_performed: false`**
- An explicit statement equivalent to: **"This is a Decision Binding, not authentication, authorization, an execution permit, or proof of execution. No tool, approval workflow, database operation, or external process was executed, and no binding was persisted by this command."**

### When `binding_outcome` is `created`

Also display:

- Canonical Agent ID (`canonical_agent_id`)
- Agent Role (`agent_role`)
- Canonical Tool Name (`canonical_tool_name`)
- Gateway Decision (`gateway_decision`)
- Policy Decision (`policy_decision`)
- Argument Digest (`argument_digest`) — labeled explicitly: **"unsigned SHA-256 content-correlation digest — not proof of authenticity, authorization, or origin, and not tamper-proof against a caller able to reconstruct this self-consistent unsigned artifact."**
- Binding Digest (`binding_digest`) — labeled with the same explicit caveat as Argument Digest.
- Issued At (`issued_at`, exactly as returned — the caller-supplied value, never a generated one)
- Expires At (`expires_at`, exactly as returned — the caller-supplied value, never a generated one)
- Approval Reference (`approval_reference`, when non-null — displayed verbatim as an opaque caller-supplied identifier, never reformatted, never assumed to be a UUID)

State clearly that this Decision Binding correlates the exact supplied arguments with the exact supplied Block 9 result for the stated time window only, that it is unsigned, that it grants no authorization and performs no execution, and that verifying it later is a separate, not-yet-implemented capability this command does not provide.

### When `binding_outcome` is `refused`

Display `refusal_reason.code` and `refusal_reason.message` exactly as returned. State clearly that this is a normal, successful evaluation outcome — never a runtime or CLI failure — and that no binding was created. Never retry the same request with silently adjusted `issued_at`, `expires_at`, or `approval_reference` values, and never attempt to repair or reinterpret the supplied `identity_policy_result` or `arguments` to force a `created` outcome.

Never display:

- the caller's raw `arguments` separately from what the Decision Binding result itself echoes back through `argument_digest`;
- any field of `identity_policy_result` beyond what `canonical_agent_id`, `agent_role`, `canonical_tool_name`, `gateway_decision`, and `policy_decision` already surface from the Decision Binding result itself;
- SQL or migration text;
- filesystem paths;
- credentials, tokens, or environment values;
- a stack trace, exception class name, or raw internal exception message;
- the internal construction of the CLI command or its raw stdin envelope.

## Required Failure Categories

Use only these fixed, non-sensitive failure categories. Never expose a raw exception message, exception class name, traceback, credential, path, or internal detail in any of them.

### DECISION_BINDING_CLI_UNAVAILABLE

The Python launcher or `core.decision_binding_cli` import check failing before any stage below runs.

### INVALID_INPUT

Stage 0 rejecting malformed JSON, non-object top-level JSON, trailing content, a missing/unknown top-level field (including a caller-supplied `operation`), or a missing `identity_policy_result`/`arguments`/`issued_at`/`expires_at`/`approval_reference` key. A present `identity_policy_result` or `arguments` value is never rejected here regardless of its JSON type — a non-Mapping value is passed through to `core.decision_binding_cli` and reaches its own graceful `refused` outcome (`INVALID_IDENTITY_RESULT_STRUCTURE` or `ARGUMENTS_NOT_A_MAPPING`), never this category.

### DECISION_BINDING_VALIDATION_FAILED

Stage 2 reporting exit code 2, or the Decision Binding CLI success-output validation failing (a malformed result, an unrecognized or missing field, `decision_binding_version` other than `"1"`, `identity_authenticated` other than `false`, `execution_performed` other than `false`, or a `binding_outcome` combination that does not match the fixed table).

### DECISION_BINDING_INTERNAL_FAILURE

Stage 2 reporting exit code 1 or any other unexpected code.

Do not automatically retry any failure in any category above.

## No-Fallback and No-Retry Policy

On any command-level, CLI, parsing, or result-validation failure, or on a `refused` outcome:

- stop;
- do not retry automatically;
- do not silently adjust `issued_at`, `expires_at`, or `approval_reference` to force a different outcome;
- do not repair, complete, or reinterpret a malformed `identity_policy_result` or `arguments` object;
- do not switch to a raw `mcp__supabase__execute_sql` call, a direct database client, or a REST request;
- do not invoke Block 8 or Block 9 directly to "double-check" or regenerate the supplied identity policy result;
- do not invoke `/evaluate-tool-call`, `/evaluate-agent-tool-call`, `/request-case-update`, `/review-approval`, or `/apply-case-update` automatically;
- do not execute the tool named anywhere inside `identity_policy_result` or `arguments`, through any path.

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
- `core.agent_gateway.evaluate_tool_call` or `core.agent_gateway_cli`;
- `core.agent_identity_policy.evaluate_agent_tool_call` or `core.agent_identity_policy_cli`;
- `/evaluate-tool-call`, `/evaluate-agent-tool-call`, `/request-case-update`, `/review-approval`, or `/apply-case-update`;
- a subprocess of any kind other than the one selected Python launcher running `core.decision_binding_cli`;
- a dynamically imported, caller-selected module or function;
- a shell command constructed from `identity_policy_result` or `arguments`;
- the tool named anywhere inside `identity_policy_result` or `arguments`, under any `binding_outcome`, including `created`.

The only process this command ever executes is the one committed, deterministic correlator: `py -m core.decision_binding_cli` (or the equivalent selected launcher), invoked exactly once per command invocation.

## Security Boundaries

This command must never:

- accept a caller-supplied `operation`, `decision_binding_version`, `binding_outcome`, `canonical_agent_id`, `agent_role`, `canonical_tool_name`, `gateway_decision`, `policy_decision`, `argument_digest`, `binding_digest`, `refusal_reason`, `identity_authenticated`, or `execution_performed` as a command-level override;
- accept a caller-supplied SQL descriptor, RPC parameter set, or MCP payload;
- accept more than one JSON object, or a JSON envelope with any field beyond the fixed five caller-facing fields;
- decide whether `identity_policy_result` is structurally valid, whether `arguments` can be canonicalized, whether the requested lifetime is within the approved 300-second maximum, or the resulting `binding_outcome` itself — every one of those belongs entirely to `core.decision_binding.create_decision_binding`;
- read the system clock or generate `issued_at`, `expires_at`, or any other timestamp;
- normalize, reformat, reinterpret, or assume a UUID shape for `approval_reference`;
- repair, strip, or rewrite any field of a caller-supplied `identity_policy_result` or `arguments` object;
- treat `created` as authentication, authorization, an execution permit, or proof that any tool ran;
- treat `refused` as a CLI transport failure;
- treat the `argument_digest`/`binding_digest` SHA-256 values as anything beyond deterministic, unsigned content correlation;
- call `core.agent_gateway`, `core.agent_gateway_cli`, `core.agent_identity_policy`, or `core.agent_identity_policy_cli`, directly or indirectly;
- execute the tool named anywhere inside the supplied identity policy result or arguments, under any `binding_outcome`;
- persist, sign, HMAC, or add replay-protection state to the resulting binding;
- modify Supabase, any database, any file, or any project state as part of normal execution;
- retry any stage automatically, or fall back to a substitute construction after any failure;
- display any raw argument value beyond `argument_digest`, SQL, a credential, an environment variable, a filesystem path, or a stack trace.

## Example Invocation

```json
{
  "identity_policy_result": {
    "canonical_agent_id": "analyst_agent",
    "agent_role": "analyst",
    "canonical_tool_name": "load_risk_aware_approval_record",
    "gateway_decision": "allow",
    "final_decision": "allow",
    "identity_authenticated": false,
    "execution_performed": false
  },
  "arguments": {"approval_id": "7d3f0e4a-4c5f-4d0a-9b12-345678901bcd"},
  "issued_at": "2026-08-12T12:00:00Z",
  "expires_at": "2026-08-12T12:05:00Z",
  "approval_reference": null
}
```

## Safety Rules

- Accept exactly one JSON object with exactly the five caller-facing fields `identity_policy_result`, `arguments`, `issued_at`, `expires_at`, `approval_reference`. Never accept a caller-supplied `operation` or any other field.
- Never generate `issued_at` or `expires_at`, and never read the system clock — both must be exactly what the caller supplied.
- Never bypass `core.decision_binding_cli`, and never reimplement any structural validation, canonicalization, or correlation rule that `core.decision_binding` already owns.
- Never call `core.agent_gateway`, `core.agent_gateway_cli`, `core.agent_identity_policy`, or `core.agent_identity_policy_cli` — the supplied `identity_policy_result` is consumed exactly as given.
- Never execute the tool named inside the supplied identity policy result or arguments, under any `binding_outcome`, including `created`.
- Never persist, sign, HMAC, or add replay-protection state to a binding.
- Never call `mcp__supabase__execute_sql`, `execute_sql`, `apply_migration`, `run_evtx_analysis`, or any Block 6 mutation operation.
- Never automatically invoke `/evaluate-tool-call`, `/evaluate-agent-tool-call`, `/request-case-update`, `/review-approval`, or `/apply-case-update`.
- Never treat `refused` as a command failure, and never attempt a fallback construction.
- Never call a Decision Binding a capability token, a secure token, an authenticated token, execution authorization, or an execution permit — always call it a **Decision Binding**, and always state it is unsigned, is not authentication, is not authorization, and provides no replay protection.
- Never claim a tool was executed, an agent was authenticated, or execution was authorized — always state plainly that no tool, approval workflow, database operation, or external process was executed, and that no binding was persisted.
- Never treat an unexpectedly `true` `identity_authenticated` or `execution_performed` value in the CLI result as displayable — treat it as `DECISION_BINDING_VALIDATION_FAILED` instead.
- Never retry any stage automatically, and never fall back to a substitute construction after a failure.
- Never expose a raw exception message, exception class name, traceback, credential, project reference, environment variable, filesystem path, or internal owner detail.
- Never add verification behavior to this command, and never create `.claude/commands/verify-decision-binding.md` from within this command's own scope.
