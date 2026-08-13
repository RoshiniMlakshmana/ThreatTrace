---
description: Run one deterministic, local ThreatTrace integration demonstration scenario, through the read-only Block 15 integration demo boundary
argument-hint: "{operation: \"run\", scenario: \"identity_narrowing_deny\"|\"emergency_mutation_freeze\"|\"evaluation_feedback_audit\"|\"decision_binding_argument_drift\"}"
---

# ThreatTrace Integration Demonstration Workflow

`/integration-demo` is Block 15's integration/demonstration boundary: it answers exactly one thing —

*when several already-implemented ThreatTrace components are exercised together, through their own real public APIs, in one fixed, deterministic, local scenario, what happened at each step and what was the final result?*

— by consulting the existing, already-committed, deterministic core (`core.integration_demo`, reached only through `core.integration_demo_cli`) — and nothing else. This command is strictly a transport adapter.

Caller-supplied `operation` + `scenario` → command-level envelope validation → `core.integration_demo_cli`, unchanged → deterministic scenario result

`/integration-demo` never authenticates an agent, never executes a tool, never touches Supabase, MCP, or the network, and never decides which scenario id is valid — every one of those remains entirely `core.integration_demo`'s own concern, reached only through `core.integration_demo_cli`, never reimplemented in this document. One invocation runs exactly one selected scenario; this command never automatically runs all four.

## What This Provides — and Does Not

The strongest honest claim this command can ever make:

> Selected, already-implemented ThreatTrace components are composed together through their own real public APIs, in a fixed, deterministic, local demonstration scenario.

It is **not**: proof that every ThreatTrace feature runs in one runtime path; proof that any database-backed workflow executed; proof that any workflow was persisted; proof that any real tool or action executed; proof that any agent was authenticated; proof that any provenance was cryptographically verified; proof that an assembled audit chain is immutable or represents authenticated historical truth; proof that analyst feedback is correct; proof that automatic learning occurred; or proof that any dashboard metric is live. A `final_outcome` of `identity_scope_denied`, `mutation_freeze_denied`, or `argument_drift_detected` is a normal, successfully demonstrated security result, never a command failure — a security denial, an emergency-freeze narrowing, or an invalid binding verification is always surfaced honestly, never hidden or reframed as an error.

This command also never invokes the existing database-backed approval workflow (`/request-case-update` → `/review-approval` → `/apply-case-update`). That workflow remains a separate, manual, Supabase/MCP-backed path, entirely untouched by any scenario this command can run.

## Request Input

$ARGUMENTS

## Stage 0 — Command-Level Input Shape Validation

`$ARGUMENTS` must be exactly one JSON object. Perform every check below, in order, before Stage 1 — before any CLI invocation:

1. Parse `$ARGUMENTS` as exactly one JSON value.
2. Reject malformed JSON.
3. Reject trailing non-whitespace content after the one parsed JSON value.
4. Reject a top-level value that is not a JSON object.
5. Require an `"operation"` field equal to exactly `"run"`. Reject any other value, including a missing one.
6. Require exactly `operation`, `scenario` — the same two-key envelope `core.integration_demo_cli` itself requires. Reject a missing or extra field.

This command performs **no semantic validation of `scenario` beyond confirming the envelope has exactly these two keys.** It does not decide which scenario ids are valid, does not trim or lowercase `scenario`, and does not normalize it in any way — every one of those remains entirely `core.integration_demo`'s own concern, reached only through `core.integration_demo_cli`. This command never inserts, synthesizes, defaults, or overwrites `operation` or `scenario` on the caller's behalf, never generates a timestamp, never generates tool arguments, never fabricates a finding or evidence code, and never runs more than the one scenario the caller selected. Every value is passed through completely unchanged.

Call the fully validated envelope the **candidate envelope**.

## Python Launcher Selection

Use the existing project convention for selecting a Python launcher:

1. Try `py`.
2. Otherwise try `python3`.
3. Otherwise use a `python` executable only after confirming it resolves to Python 3.10 or later.

Before continuing, confirm the selected launcher can import `core.integration_demo_cli`. If no launcher can be selected, or the import check fails, stop and report `INTEGRATION_DEMO_CLI_UNAVAILABLE`. Do not install any package. Do not modify the environment.

## Safe CLI Transport

Invoke the CLI through **stdin only**, exactly following the safe invocation pattern already established by `/evaluate-tool-call`, `/evaluate-agent-tool-call`, `/create-decision-binding`, `/ai-security-lab`, `/record-analyst-feedback`, and `/audit-dashboard`. Never pass JSON through command-line arguments, never create a temporary JSON file, never interpolate caller content directly into executable shell code, and never write request data to disk.

## Stage 1 — Invoke the Integration Demo CLI

Send the **candidate envelope exactly as the caller supplied it** — both fields, including the caller's own `operation`, unchanged, unreordered, unrepaired — through **stdin only** to `py -m core.integration_demo_cli` (or the equivalent selected launcher). This command never adds, removes, renames, normalizes, redacts, reorders, or otherwise transforms any field or value. Never call `core.integration_demo` directly, never call any Block 8/9/10/11/11-12/13/14 module, and never reimplement any policy, evaluation, hashing, or aggregation logic this document does not own.

### Integration Demo CLI exit handling

- **0**: success — a scenario result whose `final_outcome` is `identity_scope_denied`, `mutation_freeze_denied`, `evaluation_feedback_audited`, or `argument_drift_detected` — all four are normal, successful results. A denial or invalidation is never treated as a failure. Continue to the output validation below.
- **2**: a deterministic command/CLI-envelope or core structural-validation failure — stop and report `INTEGRATION_DEMO_VALIDATION_FAILED`.
- **1**: an unexpected internal failure — stop and report `INTEGRATION_DEMO_INTERNAL_FAILURE`.
- **any other code**: stop and report `INTEGRATION_DEMO_INTERNAL_FAILURE`.

Never automatically retry any of these outcomes, and never fall back to displaying a partially-constructed or hand-assembled result.

### Integration Demo CLI success-output validation

Require stdout to be exactly one JSON object containing exactly the six fields `core.integration_demo.run_integration_scenario` always returns: `integration_version`, `scenario`, `steps`, `final_outcome`, `observed_evidence`, `execution_performed`. Require `integration_version` to equal exactly `"1"` and `execution_performed` to equal exactly `false`. Require `steps` to be a list whose every entry contains exactly `step`, `block`, `function`, `outcome_field`, `outcome_value`. Require `observed_evidence` to be a list.

If the result is missing a required field, contains an unrecognized field, or has `execution_performed` other than `false`: stop, report `INTEGRATION_DEMO_VALIDATION_FAILED`, and never display the result as if it were successful. Do not repair, complete, or reinterpret a malformed result by hand.

Call the fully validated result the **integration demo result**.

## Required Output

Produce, only after the integration demo result passes every check above:

- The selected `scenario`.
- Each entry of `steps`, in order, showing `step`, `block`, `function`, `outcome_field`, and `outcome_value` exactly as returned.
- `final_outcome`, presented as a normal, successfully demonstrated result — including when it is `identity_scope_denied`, `mutation_freeze_denied`, or `argument_drift_detected`. Never describe any of these as a failed demo.
- Every item in `observed_evidence`, presented as real evidence codes actually emitted by the underlying Block 8/9/10/11/11-12/13/14 functions during this run — never invented, never renamed.
- `execution_performed: false`, stated plainly.

When useful, explain the result using only the returned fields — for example, that `identity_scope_denied` demonstrates identity/least-privilege role narrowing, that `mutation_freeze_denied` demonstrates a policy-evaluation-time emergency control (never process termination, credential revocation, or network blocking), that `evaluation_feedback_audited` demonstrates an evaluation result, a non-authoritative analyst reaction to it, and an audit/dashboard summary of both (never that the feedback overrode the evaluation, was persisted, or triggered learning), and that `argument_drift_detected` demonstrates unsigned content correlation detecting a changed argument (never authorization, authentication, a signature, a capability token, replay prevention, or execution gating). Never synthesize a finding, timestamp, argument, or evidence code beyond what the integration demo result itself already contains.

Never display:

- a raw exception message, exception class name, traceback, or internal stack detail;
- a claim that any agent was authenticated;
- a claim that any tool or action actually executed;
- a claim that any workflow was persisted;
- a claim that any provenance was cryptographically verified;
- a claim that an assembled audit chain is immutable or represents authenticated historical truth;
- a claim that analyst feedback is correct or ground truth;
- a claim that automatic learning occurred;
- a claim that any dashboard metric is live or real-time;
- the internal construction of the CLI command or its raw stdin envelope.

## Required Failure Categories

Use only these fixed, non-sensitive failure categories. Never expose a raw exception message, exception class name, traceback, credential, path, or internal detail in any of them.

### INTEGRATION_DEMO_CLI_UNAVAILABLE

The Python launcher or `core.integration_demo_cli` import check failing before any stage below runs.

### INTEGRATION_DEMO_VALIDATION_FAILED

Stage 0 rejecting malformed JSON, non-object top-level JSON, trailing content, a missing/unknown top-level field (including an invalid or missing `operation`), an unsupported `scenario`, or a missing/unknown envelope field; or Stage 1 reporting CLI exit code 2, or the CLI success-output validation failing.

### INTEGRATION_DEMO_INTERNAL_FAILURE

Stage 1 reporting CLI exit code 1 or any other unexpected code.

Do not automatically retry any failure in any category above. A `final_outcome` demonstrating a security denial or an invalid verification is **never** one of these failure categories — do not say "demo failed" merely because the returned scenario demonstrates a deny, a freeze narrowing, or an invalid binding.

## No-Fallback and No-Retry Policy

On any command-level, CLI, parsing, or result-validation failure:

- stop;
- do not retry automatically;
- do not silently adjust `scenario` to force a different outcome;
- do not invoke Block 8, Block 9, the Emergency Mutation Freeze, Block 10, the AI Security Evaluation Lab, Analyst Feedback creation, the Tamper-Evident Audit chain, or the Evaluation Dashboard directly to "double-check" or regenerate the scenario's steps;
- do not invoke `/evaluate-tool-call`, `/evaluate-agent-tool-call`, `/create-decision-binding`, `/ai-security-lab`, `/record-analyst-feedback`, `/audit-dashboard`, `/request-case-update`, `/review-approval`, or `/apply-case-update` automatically.

The caller may always safely resubmit a corrected command later — this command itself never performs that retry automatically, and never hides it.

## Explicit Execution Prohibitions

This command must never invoke, directly or indirectly:

- `core.agent_gateway.evaluate_tool_call` or `core.agent_gateway_cli`;
- `core.agent_identity_policy.evaluate_agent_tool_call` or `core.agent_identity_policy_cli`;
- `core.mutation_freeze.evaluate_mutation_freeze`;
- `core.decision_binding.create_decision_binding`/`verify_decision_binding` or `core.decision_binding_cli`;
- `core.ai_asset_registry.evaluate_ai_security_case` or `core.ai_asset_registry_cli`;
- `core.analyst_feedback.create_analyst_feedback` or `core.analyst_feedback_cli`;
- `core.tamper_evident_audit.create_audit_record`/`verify_audit_chain`, `core.evaluation_dashboard.summarize_audit_dashboard`, or `core.audit_dashboard_cli`;
- `mcp__supabase__execute_sql`, `execute_sql`, `apply_migration`, or any Block 6 mutation operation;
- a subprocess of any kind other than the one selected Python launcher running `core.integration_demo_cli`;
- a dynamically imported, caller-selected module or function.

The only process this command ever executes is the one committed, deterministic adapter: `py -m core.integration_demo_cli` (or the equivalent selected launcher), invoked exactly once per command invocation, running exactly one scenario.

## Security Boundaries

This command must never:

- accept a caller-supplied `integration_version` or `execution_performed` as a command-level override;
- decide which `scenario` ids are valid, trim or lowercase a supplied `scenario`, or reinterpret `final_outcome` — every one of those belongs entirely to `core.integration_demo`;
- read the system clock or generate any timestamp, argument, agent id, or asset/case selection the scenario itself already fixes internally;
- run more than one scenario per invocation, or automatically run all four;
- claim any agent was authenticated, any tool or action executed, any workflow was persisted, or any provenance was cryptographically verified;
- claim an assembled audit chain is immutable or represents authenticated historical truth;
- claim analyst feedback is correct, ground truth, or that it overrode the evaluation it commented on;
- claim automatic learning occurred, or that any dashboard metric is live or real-time;
- treat `identity_scope_denied`, `mutation_freeze_denied`, or `argument_drift_detected` as a command-level failure;
- call `core.agent_gateway`, `core.agent_identity_policy`, `core.mutation_freeze`, `core.decision_binding`, `core.ai_asset_registry`, `core.analyst_feedback`, `core.tamper_evident_audit`, or `core.evaluation_dashboard`, directly or indirectly;
- invoke the database-backed approval workflow (`/request-case-update`, `/review-approval`, `/apply-case-update`) or imply it was exercised by this command;
- retry any stage automatically, or fall back to a substitute construction after any failure;
- display any raw exception message, exception class name, traceback, credential, environment variable, filesystem path, or internal owner detail.

## Example Invocations

```json
{
  "operation": "run",
  "scenario": "identity_narrowing_deny"
}
```

```json
{
  "operation": "run",
  "scenario": "emergency_mutation_freeze"
}
```

```json
{
  "operation": "run",
  "scenario": "evaluation_feedback_audit"
}
```

```json
{
  "operation": "run",
  "scenario": "decision_binding_argument_drift"
}
```

## Safety Rules

- Accept exactly one JSON object with exactly `operation` and `scenario`. Never insert, synthesize, default, or overwrite either field on the caller's behalf.
- Never trim, lowercase, or otherwise normalize `scenario` — pass it through exactly as supplied.
- Never generate a timestamp, argument, agent id, or asset/case selection; never read the system clock.
- Never bypass `core.integration_demo_cli`, and never reimplement any Block 8/9/10/11/11-12/13/14 policy, evaluation, hashing, or aggregation rule that those modules already own.
- Never call any Block 8/9/10/11/11-12/13/14 module directly — the scenario's steps are never recomputed by this command.
- Never claim an agent was authenticated, a tool or action executed, a workflow was persisted, provenance was cryptographically verified, an audit chain is immutable, analyst feedback is correct, automatic learning occurred, or dashboard metrics are live.
- Never treat a denial, freeze narrowing, or invalid verification result as a command failure — always present it as a normal, successfully demonstrated result.
- Never run more than one scenario per invocation.
- Never invoke `/request-case-update`, `/review-approval`, or `/apply-case-update` automatically, or imply the database-backed approval workflow was exercised.
- Never call `mcp__supabase__execute_sql`, `execute_sql`, `apply_migration`, or any Block 6 mutation operation.
- Never retry any stage automatically, and never fall back to a substitute construction after a failure.
- Never expose a raw exception message, exception class name, traceback, credential, project reference, environment variable, filesystem path, or internal owner detail.
