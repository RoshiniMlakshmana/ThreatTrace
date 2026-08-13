# Block 15 — Integration Demonstrations

**The Block 15 MVP is complete.** It composes selected, already-implemented ThreatTrace components — Blocks 8, 9, 10, 11, 11-12, 13, and 14 — through their own real public APIs, in four fixed, deterministic, local demonstration scenarios. It implements no new security primitive and duplicates no existing policy, hashing, evaluation, or aggregation logic.

## 1. Block 15 purpose

"Full integration" here means exactly:

> Selected, already-implemented ThreatTrace components are exercised together, through their own real public APIs, in deterministic, local, fixed-fixture demonstration scenarios.

It does **not** mean every project feature participates in one runtime, or that Block 15 is itself a new production capability. Block 15 orchestrates; it never decides.

## 2. Architecture

```
core/integration_demo.py
  -> real existing public APIs (Blocks 8/9/10/11/11-12/13/14)
  -> compact integration result

core/integration_demo_cli.py
  -> thin stdin/stdout JSON adapter around core.integration_demo

/integration-demo
  -> human-facing command, thin wrapper around core.integration_demo_cli
  -> one invocation runs exactly one selected scenario
```

Each layer adds nothing the layer below it did not already produce. The core module never hashes, never evaluates policy, never aggregates counts, and never authenticates anything — it only calls the real functions that already own those concerns and reports their real, unmodified results back in a compact shape.

## 3. Scenario matrix

| Scenario | Blocks involved | `final_outcome` | Security property demonstrated |
|---|---|---|---|
| `identity_narrowing_deny` | 8, 9 | `identity_scope_denied` | Identity/least-privilege role narrowing beyond the gateway's own decision |
| `emergency_mutation_freeze` | 9, 11 (Mutation Freeze) | `mutation_freeze_denied` | Policy-evaluation-time emergency control narrowing an otherwise-eligible mutation |
| `evaluation_feedback_audit` | 11-12, 13, 14 | `evaluation_feedback_audited` | Deterministic evaluation + human feedback capture + audit correlation + reporting |
| `decision_binding_argument_drift` | 9, 10 | `argument_drift_detected` | Unsigned content correlation detecting a changed argument between decision and re-check |

None of the four proves: real agent authentication, real tool/action execution, database-backed persistence, cryptographically verified provenance, an immutable audit history, correctness of analyst judgment, automatic learning, or live dashboard telemetry. Each scenario's result carries `execution_performed: false`.

## 4. Scenario 1 — identity_narrowing_deny

Fixed fixture: agent `reviewer_agent`, tool `apply_approval_consumption`, a valid `approval_id`.

- Block 8 (`core.agent_gateway.evaluate_tool_call`) decision: `require_approval` — the tool itself is a real, enabled, approval-mutation tool the gateway does not deny outright.
- Block 9 (`core.agent_identity_policy.evaluate_agent_tool_call`) `final_decision`: `deny`, narrowed by evidence `OPERATION_CLASS_NOT_PERMITTED` — `reviewer_agent`'s role ceiling (`approval_reviewer`) permits only `read_only` operation classes, even though `apply_approval_consumption` happens to be on its tool allowlist.

This demonstrates identity/role narrowing beyond what the gateway alone decided. It does **not** demonstrate agent authentication — `agent_id` is a claimed identifier matched against a fixed in-code registry only, exactly as Block 9 itself documents.

## 5. Scenario 2 — emergency_mutation_freeze

Fixed fixture: agent `coordinator_agent`, tool `apply_approval_consumption`, a valid `approval_id`.

- Pre-freeze Block 9 `final_decision`: `require_approval` — `coordinator_agent`'s role permits this mutation request.
- `core.mutation_freeze.evaluate_mutation_freeze(control_mode="mutation_freeze")` narrows the result to `final_decision: deny`, with evidence `MUTATION_FREEZE_ACTIVE`.

This is a **policy-evaluation-time control only**. It is never described as OS process termination, credential/token revocation, network isolation, or database-level enforcement — the Mutation Freeze module itself makes that same disclaimer, and Block 15 never overstates it.

## 6. Scenario 3 — evaluation_feedback_audit

Fixed fixture: asset `gateway_tool:apply_approval_consumption`, case `mutation_policy_bypass`.

- `core.ai_asset_registry.evaluate_ai_security_case` → `evaluation_outcome: "pass"`.
- `core.analyst_feedback.create_analyst_feedback` → `analyst_decision: "disagree"`, `error_category: "evaluation_expectation_mismatch"`, `corrected_value: "fail"`.
- Two linked `core.tamper_evident_audit.create_audit_record` calls (sequence 1: `security_evaluation_result`; sequence 2: `analyst_feedback`, linked by the first record's real `record_digest`).
- `core.tamper_evident_audit.verify_audit_chain` → `verification_outcome: "valid"`, `internal_chain_valid: True`, `trusted_anchor_verified: None` (no `expected_head_digest` was supplied).
- `core.evaluation_dashboard.summarize_audit_dashboard` → `event_type_counts`: 1 `security_evaluation_result`, 1 `analyst_feedback`; `evaluation_counts.outcome_counts.pass`: 1; `feedback_counts.decision_counts.disagree`: 1; `feedback_counts.error_category_counts.evaluation_expectation_mismatch`: 1.

This scenario explicitly does **not** demonstrate that the analyst's disagreement overrode the evaluation (the evaluation result is never re-derived or mutated), that the feedback is authenticated ground truth (there is no analyst-identity field anywhere in this project), that the feedback was persisted (`feedback_persisted` is always `false`), that automatic learning occurred, that an internally valid audit chain is authenticated historical truth (no trusted anchor was supplied here), or that the dashboard reflects live telemetry.

## 7. Scenario 4 — decision_binding_argument_drift

Fixed fixture: agent `coordinator_agent`, tool `apply_approval_consumption`, an original `approval_id`.

- Block 9 `final_decision`: `require_approval`.
- `core.decision_binding.create_decision_binding` → `binding_outcome: "created"`.
- `core.decision_binding.verify_decision_binding` against the **same** arguments → `verification_outcome: "valid"`.
- `core.decision_binding.verify_decision_binding` against a **single changed** `approval_id` → `verification_outcome: "invalid"`, with evidence `ARGUMENT_DIGEST_MISMATCH`.

This demonstrates exact content correlation only — a Decision Binding is deliberately unsigned, exactly as Block 10 itself documents. It does **not** demonstrate authorization, authentication, a signature, a capability token, replay prevention, or execution gating.

## 8. Result contract

Every scenario returns exactly six top-level fields:

`integration_version`, `scenario`, `steps`, `final_outcome`, `observed_evidence`, `execution_performed`.

Every entry in `steps` contains exactly five fields:

`step`, `block`, `function`, `outcome_field`, `outcome_value`.

`observed_evidence` is a deduplicated, order-preserving list of real evidence-code strings actually emitted by the underlying blocks during that run — never invented. `execution_performed` is always `false`.

## 9. CLI contract

`core/integration_demo_cli.py`, invoked as:

```
py -m core.integration_demo_cli
```

Exactly one operation, `"run"`, via a two-key JSON envelope on stdin:

```json
{
  "operation": "run",
  "scenario": "evaluation_feedback_audit"
}
```

`scenario` is passed through to `run_integration_scenario` unchanged — never trimmed, lowercased, or otherwise normalized by the CLI; `core.integration_demo` remains the sole authority on which scenario ids are valid.

Exit codes:

- **0** — a valid deterministic scenario result, including one whose `final_outcome` demonstrates a security denial, an emergency-freeze narrowing, or an invalid binding verification. stderr is empty.
- **2** — malformed JSON, a non-object top level, a missing/extra envelope key, an unsupported `operation`, or an `IntegrationDemoError` from the core (an unrecognized/blank/non-string `scenario`). stderr begins with `INTEGRATION_DEMO_VALIDATION_FAILED`.
- **1** — an unexpected internal failure. stderr begins with `INTEGRATION_DEMO_INTERNAL_FAILURE`.

## 10. Determinism

Every canonical Block 15 scenario uses fixed, hardcoded, in-code fixture constants — agent/tool identifiers, arguments, timestamps, and the asset/case selection for Scenario 3. None of these values is ever derived from the system clock, an environment variable, randomness, or any external source. Block 15 performs no network access, no database access, no Supabase access, no MCP access, generates no random identifier, and never executes a real tool or action.

## 11. Persisted vs. ephemeral

Every Block 15 demo is **ephemeral and local**. Nothing a scenario produces is written to a file, a database, or any other store. Block 15 does **not** claim to run, and never runs, the database-backed approval persistence path (`core.approval_persistence`/`core.approval_bridge`/`core.approval_mcp_adapter`).

## 12. Existing database-backed workflow

The project's existing, already-implemented, database-backed approval workflow —

```
/request-case-update
  -> /review-approval
  -> /apply-case-update
```

— is **not** invoked by the Block 15 deterministic integration demo, in any scenario, at any layer. Nothing in this document or in `core/integration_demo.py`/`core/integration_demo_cli.py`/`.claude/commands/integration-demo.md` implies that workflow was exercised by running a Block 15 scenario.

## 13. Full integration honesty

Block 15 does **not** prove:

- that all ThreatTrace capabilities run together in one process;
- real agent authentication;
- real tool or action execution;
- that any workflow was persisted;
- that provenance was cryptographically verified;
- audit immutability;
- analyst correctness;
- automatic learning;
- live dashboard telemetry.

Every scenario's result carries `execution_performed: false`, and every underlying block it calls already carries its own equivalent honesty disclaimer (`identity_authenticated: false`, `feedback_persisted: false`, `audit_persisted: false`, and so on) — Block 15 changes none of that; it only reports it faithfully.

## 14. Portfolio / interview explanation

The four scenarios together tell one coherent security story, each demonstrating a distinct, technically accurate property:

- **Least privilege** (`identity_narrowing_deny`) — a permission check beyond "is this tool generally allowed" narrows further based on who is claiming to call it.
- **Emergency narrowing** (`emergency_mutation_freeze`) — a separate, policy-evaluation-time kill-switch can deny an otherwise-eligible mutation without touching the identity or gateway layers that produced the original decision.
- **Human feedback + audit visibility** (`evaluation_feedback_audit`) — an automated evaluation, a human reviewer's disagreement with it, and a chained, verifiable record of both are captured without either side silently overriding the other.
- **Decision/action argument correlation** (`decision_binding_argument_drift`) — a decision and the exact arguments it was made about are content-correlated well enough to detect drift, while being explicit that this is not authorization.

## 15. Testing

Actual counts as validated at the close of this checkpoint:

- `tests/test_integration_demo.py` (Checkpoint A core) — **117 passed**
- `tests/test_integration_demo_cli.py` (Checkpoint B CLI) — **73 passed**
- Combined Block 15 (`test_integration_demo.py` + `test_integration_demo_cli.py`) — **190 passed**
- Bounded regression (`test_agent_gateway` + `test_agent_identity_policy` + `test_mutation_freeze` + `test_decision_binding` + `test_ai_asset_registry` + `test_analyst_feedback` + `test_tamper_evident_audit` + `test_evaluation_dashboard` + `test_integration_demo` + `test_integration_demo_cli`) — **548 passed**

These counts reflect the repository as validated at the close of this checkpoint; they are not projected or assumed.
