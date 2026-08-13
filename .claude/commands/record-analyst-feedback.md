---
description: Record one structured analyst feedback signal about an already-existing investigation decision, security-policy decision, or evaluation result
argument-hint: "{operation: \"create\", target_type, target_reference, analyst_decision, error_category, rationale, evidence_reference, corrected_value, submitted_at}"
---

# ThreatTrace Record Analyst Feedback Workflow

`/record-analyst-feedback` is Block 13's structured analyst feedback boundary: it answers *what does this analyst think of a result ThreatTrace already produced?* by consulting the existing, already-committed, deterministic feedback constructor (`core.analyst_feedback.create_analyst_feedback`, via `core.analyst_feedback_cli`) — and nothing else. This command is strictly a transport adapter:

Caller-supplied `operation: "create"` + target reference + analyst decision + optional metadata → command-level envelope validation → `core.analyst_feedback_cli`, unchanged → deterministic structured feedback record

`/record-analyst-feedback` never recomputes the result it records feedback about, never authenticates the analyst, never persists anything, never retrains anything, never updates a rule or policy, and never calls Supabase, MCP, or the network. It never decides whether `target_type`/`analyst_decision`/`error_category`/`corrected_value` is a recognized value, or whether `rationale` is required for the supplied `analyst_decision` — every one of those is always decided later, entirely by `core.analyst_feedback`, reached only through `core.analyst_feedback_cli`, never reimplemented in this document.

## What Analyst Feedback Is — and Is Not

A recorded feedback record is **structured, analyst-supplied input about an existing result** — a signal that may later support human-driven rule tuning, evaluation-case improvement, false-positive/false-negative analysis, or a future training dataset. It is:

- **not** ground truth;
- **not** an automatic override of the system result it comments on;
- **not** persisted anywhere by this command;
- **not** a cause of automatic retraining, online learning, or any other automatic learning;
- **not** a rule or policy update, automatic or otherwise;
- **not** proof the analyst is authenticated — there is no authentication mechanism anywhere in this project, and this command never claims one;
- **not** verification that `target_reference` or any `evidence_reference` actually exists — both are claimed, opaque references only.

`analyst_decision: "disagree"` produces an **analyst disagreement record**, never a corrected system decision. The original result this feedback references is never changed, recomputed, or superseded by this command.

## Feedback Input

$ARGUMENTS

## Stage 0 — Command-Level Input Shape Validation

`$ARGUMENTS` must be exactly one JSON object. Perform every check below, in order, before Stage 1 — before any CLI invocation:

1. Parse `$ARGUMENTS` as exactly one JSON value.
2. Reject malformed JSON.
3. Reject trailing non-whitespace content after the one parsed JSON value.
4. Reject a top-level value that is not a JSON object.
5. Allow exactly these nine fields, no more and no fewer: `operation`, `target_type`, `target_reference`, `analyst_decision`, `error_category`, `rationale`, `evidence_reference`, `corrected_value`, `submitted_at` — the exact same nine-key envelope `core.analyst_feedback_cli` itself requires. Reject any field this list does not name.
6. Require all nine fields to be present. `error_category`, `rationale`, `evidence_reference`, and `corrected_value` are each a required key whose value may be `null`.
7. Require `operation` to equal exactly the string `"create"` — the only operation `core.analyst_feedback_cli` currently supports. Reject any other value, including a missing one. This command never selects, defaults, synthesizes, or overwrites `operation` on the caller's behalf — the caller must supply it explicitly, exactly like every other field in this envelope.

This command performs **no semantic validation of `target_type`, `target_reference`, `analyst_decision`, `error_category`, `rationale`, `evidence_reference`, `corrected_value`, or `submitted_at` beyond confirming each key is present.** It does not decide, at this or any other stage, whether `target_type` is one of the three recognized values, whether `analyst_decision` is one of the three recognized values, whether `error_category`/`rationale` are correctly required or forbidden for the supplied `analyst_decision`, whether `evidence_reference` is a valid non-empty list of non-blank strings, whether `corrected_value` is valid for the selected `target_type`, or whether `submitted_at` is a valid aware timestamp — every one of those is always decided later, entirely by `core.analyst_feedback.create_analyst_feedback`, reached only through `core.analyst_feedback_cli`. No value is ever transformed, stripped, repaired, or reinterpreted by this command. `target_reference` and every `evidence_reference` entry are treated as **opaque identifiers** — never assumed to be a UUID, never parsed, never normalized, and never checked against Supabase or any other live state.

Call the fully validated nine-field object the **candidate envelope**.

## Python Launcher Selection

Use the existing project convention for selecting a Python launcher:

1. Try `py`.
2. Otherwise try `python3`.
3. Otherwise use a `python` executable only after confirming it resolves to Python 3.10 or later.

Before continuing to Stage 1, confirm the selected launcher can import `core.analyst_feedback_cli`. If no launcher can be selected, or the import check fails, stop and report `ANALYST_FEEDBACK_CLI_UNAVAILABLE`. Do not install any package. Do not modify the environment.

## Safe CLI Transport

Invoke the CLI through **stdin only**, exactly following the safe invocation pattern already established by `/evaluate-tool-call`, `/evaluate-agent-tool-call`, `/create-decision-binding`, and `/ai-security-lab`. Never pass JSON through command-line arguments, never create a temporary JSON file, never interpolate caller content directly into executable shell code, and never write request data to disk.

## Stage 1 — Invoke the Analyst Feedback CLI

Send the **candidate envelope exactly as the caller supplied it** — all nine fields, including the caller's own `operation: "create"`, unchanged, unreordered, unrepaired — through **stdin only** to `py -m core.analyst_feedback_cli` (or the equivalent selected launcher). This command never adds, removes, renames, normalizes, redacts, reorders, or otherwise transforms any field or value, and in particular never inserts, synthesizes, defaults, or overwrites `operation` on the caller's behalf — the caller's own envelope is byte-for-byte what `core.analyst_feedback_cli` receives. Never call `core.analyst_feedback` directly, never call any Block 8/9/10/Mutation-Freeze/Block 11–12 module, and never reimplement any part of the vocabulary, disagreement-rule, or timestamp-validation logic this document does not own.

### Analyst Feedback CLI exit handling

- **0**: success — the feedback record was created, regardless of `analyst_decision`. `"disagree"` is a normal, successful result, never a failure. Continue to the output validation below.
- **2**: a deterministic command/CLI-envelope or core structural-validation failure — stop and report `ANALYST_FEEDBACK_VALIDATION_FAILED`.
- **1**: an unexpected internal failure — stop and report `ANALYST_FEEDBACK_INTERNAL_FAILURE`.
- **any other code**: stop and report `ANALYST_FEEDBACK_INTERNAL_FAILURE`.

Never automatically retry any of these outcomes, and never fall back to displaying a partially-constructed or hand-assembled result.

### Analyst Feedback CLI success-output validation

Require stdout to be exactly one JSON object containing exactly the eleven fields `core.analyst_feedback.create_analyst_feedback` always returns: `feedback_version`, `target_type`, `target_reference`, `analyst_decision`, `error_category`, `rationale`, `evidence_reference`, `corrected_value`, `submitted_at`, `feedback_persisted`, `automatic_learning_performed`.

Require `feedback_version` to equal exactly `"1"`, `feedback_persisted` to equal exactly `false`, and `automatic_learning_performed` to equal exactly `false`. Require `analyst_decision` to be exactly one of `agree`, `disagree`, `insufficient_evidence`.

If the result is missing a required field, contains an unrecognized field, has `feedback_version` other than `"1"`, has `feedback_persisted` other than `false`, or has `automatic_learning_performed` other than `false`: stop, report `ANALYST_FEEDBACK_VALIDATION_FAILED`, and never display the result as if it were successful. Do not repair, complete, or reinterpret a malformed result by hand.

Call the fully validated result the **analyst feedback record**.

## Required Output

Produce, only after the analyst feedback record passes every check above:

- `target_type`
- `target_reference`
- `analyst_decision`
- `error_category` (when not `null`)
- `rationale` (when not `null`)
- `evidence_reference` (when not `null`)
- `corrected_value` (when not `null`)
- `submitted_at`
- **`feedback_persisted: false`**
- **`automatic_learning_performed: false`**
- An explicit statement equivalent to: **"This is structured analyst-supplied feedback. It does not automatically override the system result, retrain a model, update rules or policy, persist the feedback, prove the analyst is authenticated, verify the target or evidence references, or establish ground truth."**

### When `analyst_decision` is `"disagree"`

Present the result explicitly as **an analyst disagreement record** — never as a corrected system decision, and never implying the original result changed. Display `error_category` and `rationale` as the analyst's own stated reasoning. When `corrected_value` is present, label it clearly as the analyst's *proposed* correction only — this command never applies it anywhere.

### When `analyst_decision` is `"agree"` or `"insufficient_evidence"`

State plainly that this is a normal, successfully recorded feedback signal, distinct from a disagreement.

Never display:

- a raw exception message, exception class name, traceback, or internal stack detail;
- a claim that the analyst was authenticated;
- a claim that `target_reference` or any `evidence_reference` was verified to exist;
- a claim that recording this feedback caused any retraining, rule update, or policy update;
- a claim that the original system result was overridden, corrected, or changed;
- the internal construction of the CLI command or its raw stdin envelope.

## Required Failure Categories

Use only these fixed, non-sensitive failure categories. Never expose a raw exception message, exception class name, traceback, credential, path, or internal detail in any of them.

### ANALYST_FEEDBACK_CLI_UNAVAILABLE

The Python launcher or `core.analyst_feedback_cli` import check failing before any stage below runs.

### ANALYST_FEEDBACK_VALIDATION_FAILED

Stage 0 rejecting malformed JSON, non-object top-level JSON, trailing content, a missing/unknown top-level field, an `operation` other than exactly `"create"` (including a missing one), or a missing required field; or Stage 1 reporting CLI exit code 2, or the CLI success-output validation failing.

### ANALYST_FEEDBACK_INTERNAL_FAILURE

Stage 1 reporting CLI exit code 1 or any other unexpected code.

Do not automatically retry any failure in any category above.

## No-Fallback and No-Retry Policy

On any command-level, CLI, parsing, or result-validation failure:

- stop;
- do not retry automatically;
- do not silently adjust `target_type`, `analyst_decision`, `error_category`, `rationale`, `evidence_reference`, `corrected_value`, or `submitted_at` to force a different outcome;
- do not invoke Block 8, Block 9, the Emergency Mutation Freeze, Block 10, or the AI Security Evaluation Lab to "double-check" or regenerate the result this feedback references;
- do not invoke `/evaluate-tool-call`, `/evaluate-agent-tool-call`, `/create-decision-binding`, `/ai-security-lab`, `/request-case-update`, `/review-approval`, or `/apply-case-update` automatically.

The caller may always safely resubmit a corrected command later — this command itself never performs that retry automatically, and never hides it.

## Explicit Execution Prohibitions

This command must never invoke, directly or indirectly:

- `core.agent_gateway.evaluate_tool_call` or `core.agent_gateway_cli`;
- `core.agent_identity_policy.evaluate_agent_tool_call` or `core.agent_identity_policy_cli`;
- `core.mutation_freeze.evaluate_mutation_freeze`;
- `core.decision_binding.create_decision_binding`/`verify_decision_binding` or `core.decision_binding_cli`;
- `core.ai_asset_registry.evaluate_ai_security_case` or `core.ai_asset_registry_cli`;
- `mcp__supabase__execute_sql`, `execute_sql`, `apply_migration`, or any Block 6 mutation operation;
- a subprocess of any kind other than the one selected Python launcher running `core.analyst_feedback_cli`;
- a dynamically imported, caller-selected module or function.

The only process this command ever executes is the one committed, deterministic adapter: `py -m core.analyst_feedback_cli` (or the equivalent selected launcher), invoked exactly once per command invocation.

## Security Boundaries

This command must never:

- accept a caller-supplied `feedback_version`, `feedback_persisted`, or `automatic_learning_performed` as a command-level override, or accept an `operation` value other than exactly `"create"`;
- insert, synthesize, default, or overwrite `operation` on the caller's behalf — the caller must supply it explicitly, exactly like every other envelope field;
- decide whether `target_type`/`analyst_decision`/`error_category`/`corrected_value` is a recognized value, whether `error_category`/`rationale` are correctly required for the supplied `analyst_decision`, or whether `submitted_at` is a valid timestamp — every one of those belongs entirely to `core.analyst_feedback.create_analyst_feedback`;
- read the system clock or generate `submitted_at` or any other timestamp;
- generate a feedback identifier of any kind;
- claim the analyst was authenticated, or claim a registry match/claimed reference is proof of anything beyond what the caller typed;
- verify `target_reference` or any `evidence_reference` against Supabase or any other live state;
- treat `analyst_decision: "disagree"` as a command-level failure, or as an automatic correction to the referenced result;
- persist a feedback record anywhere, or claim one was persisted;
- cause, or claim to cause, automatic retraining, online learning, prompt adaptation, or automatic policy/rule rewriting;
- call `core.agent_gateway`, `core.agent_identity_policy`, `core.mutation_freeze`, `core.decision_binding`, or `core.ai_asset_registry`, directly or indirectly;
- retry any stage automatically, or fall back to a substitute construction after any failure;
- display any raw exception message, exception class name, traceback, credential, environment variable, filesystem path, or internal owner detail.

## Example Invocation

```json
{
  "operation": "create",
  "target_type": "investigation_decision",
  "target_reference": "investigation-123",
  "analyst_decision": "disagree",
  "error_category": "incorrect_classification",
  "rationale": "Observed evidence supports a different classification.",
  "evidence_reference": ["evidence-17"],
  "corrected_value": "contradicted",
  "submitted_at": "2026-08-12T18:00:00Z"
}
```

## Safety Rules

- Accept exactly one JSON object with exactly the nine fields `operation`, `target_type`, `target_reference`, `analyst_decision`, `error_category`, `rationale`, `evidence_reference`, `corrected_value`, `submitted_at` — the same envelope `core.analyst_feedback_cli` itself requires. `operation` must equal exactly `"create"`, caller-supplied; never insert, default, or overwrite it.
- Never generate `submitted_at`, and never read the system clock.
- Never generate a feedback identifier.
- Never bypass `core.analyst_feedback_cli`, and never reimplement any vocabulary, disagreement-rule, or timestamp-validation rule that `core.analyst_feedback` already owns.
- Never call `core.agent_gateway`, `core.agent_identity_policy`, `core.mutation_freeze`, `core.decision_binding`, or `core.ai_asset_registry` — the referenced result is never recomputed.
- Never authenticate, or claim to authenticate, the analyst.
- Never verify `target_reference` or any `evidence_reference` against Supabase or any other live state.
- Never persist a feedback record, or claim one was persisted.
- Never claim recording feedback caused retraining, online learning, or any rule/policy update.
- Never treat `analyst_decision: "disagree"` as a command failure or as an automatic correction — always present it as an analyst disagreement record only.
- Never call `mcp__supabase__execute_sql`, `execute_sql`, `apply_migration`, or any Block 6 mutation operation.
- Never automatically invoke `/evaluate-tool-call`, `/evaluate-agent-tool-call`, `/create-decision-binding`, `/ai-security-lab`, `/request-case-update`, `/review-approval`, or `/apply-case-update`.
- Never retry any stage automatically, and never fall back to a substitute construction after a failure.
- Never expose a raw exception message, exception class name, traceback, credential, project reference, environment variable, filesystem path, or internal owner detail.
