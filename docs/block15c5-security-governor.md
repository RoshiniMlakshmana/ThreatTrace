# Block 15C.5 — Security Governor / Observable Rogue-Agent Monitor

**Block 15C.5 checkpoint B is complete.** It is a pure, deterministic, local, stateless layer that evaluates one caller-supplied, structured **observable event** describing a role/agent action, and reports whether it crosses a ThreatTrace policy/workflow boundary — and how severely.

## 1. Purpose

The Security Governor answers exactly one question: *given a caller-supplied, structured description of one observable role/agent action, does it cross a ThreatTrace policy/workflow boundary, and if so how severely?* It never decides whether a proposed tool call is generally safe (`core.agent_gateway`'s concern) or whether a claimed agent has the least-privilege capability to make it (`core.agent_identity_policy`'s concern) — it consumes those decisions, when supplied, as inputs (`gateway_decision`, `identity_decision`), never recomputing them.

## 2. Why supervisory governance is needed

Blocks 8/9/10/11 (the tool gateway, identity policy, decision binding, and mutation freeze) each evaluate one proposed action against one fixed rule set. None of them synthesizes a cross-cutting view across an evolving Purple Team workflow: whether an actor is acting within its assigned role for the *current stage*, whether repeated denials indicate an escalating pattern, whether untrusted content is being adopted as an instruction, or whether protected source truth is being mutated. The Governor exists to synthesize exactly that cross-cutting, workflow-aware view — deterministically, from caller-supplied structured state, never from inference.

## 3. Observable-only model

The Governor evaluates **observable, structured state only**. It never inspects free-text reasoning, a chain-of-thought transcript, or anything resembling "intent." Every field on its input `event` is drawn from a fixed, closed vocabulary — there is no free-text field anywhere in the contract, so there is no channel through which private reasoning (or an attempted prompt injection) could ever reach its decision logic. Every result carries `observable_only: true` to make this boundary explicit in the returned data itself, not merely in prose.

## 4. Functional roles

Exactly 8, the same fixed vocabulary Block 15C uses: `bug_bounty`, `context_engine`, `threat_intelligence`, `threat_hunting`, `blue_team`, `red_team`, `purple_ir`, `human_analyst`. The Governor owns a private copy of this vocabulary — it never imports `core.security_handoff`.

## 5. Event contract

`evaluate_security_governor_event` (`core/security_governor.py`) accepts exactly one keyword argument, `event`, a mapping with exactly 16 required fields: `event_version`, `actor_role`, `action_class`, `current_stage`, `required_role`, `gateway_decision`, `identity_decision`, `mutation_freeze_active`, `approval_state`, `decision_binding_state`, `scope_state`, `source_truth_state`, `remote_content_state`, `audit_state`, `prior_policy_denials`, `execution_requested`. Every field is required — an extra or missing field raises `SecurityGovernorError`.

## 6. Action classes

Exactly 6: `stage_contribution`, `approval_decision`, `execution_request`, `source_truth_edit`, `audit_action`, `content_adoption`. `execution_request`, `source_truth_edit`, and `approval_decision` are the three classes treated as an actual mutation attempt for mutation-freeze-narrowing purposes.

## 7. Decisions

Exactly 5, in fixed ascending severity order: `allow`, `warn`, `require_review`, `block`, `freeze`. The final `decision` for one evaluation is the maximum severity among every reason code that triggered, or `allow` if none triggered.

## 8. Reason codes

Exactly 12, evaluated in this fixed order every call: `TOOL_OR_GATEWAY_DENIED`, `IDENTITY_POLICY_DENIED`, `STAGE_BYPASS_ATTEMPT`, `ROLE_SCOPE_VIOLATION`, `MUTATION_FREEZE_ACTIVE`, `SCOPE_EXPANSION_ATTEMPT`, `SOURCE_TRUTH_MODIFICATION`, `UNTRUSTED_CONTENT_INSTRUCTION_ATTEMPT`, `AUDIT_BYPASS_ATTEMPT`, `DECISION_BINDING_REQUIRED`, `APPROVAL_REQUIRED`, `REPEATED_POLICY_DENIAL`. Each is emitted at most once per call; `reason_codes` is returned in this same fixed order.

## 9. Deterministic severity/floor behavior

Each triggered reason code carries a fixed minimum ("floor") decision severity it independently requires — e.g. `TOOL_OR_GATEWAY_DENIED` always floors at `block`; `SOURCE_TRUTH_MODIFICATION` and `AUDIT_BYPASS_ATTEMPT` always floor at `freeze`. Two codes have a context-dependent floor: `MUTATION_FREEZE_ACTIVE` floors at `block` when `action_class` is a mutating class, `warn` otherwise; `APPROVAL_REQUIRED` floors at `block` when `execution_requested` is `true`, `require_review` otherwise. The final `decision` is the maximum floor across every triggered code — never a weighted average, never a majority vote.

## 10. Repeated-denial threshold

`prior_policy_denials` is a caller-supplied, non-negative integer — the Governor keeps no state between calls and never tallies this count itself. At 0–1, it has no effect. At exactly 2, `REPEATED_POLICY_DENIAL` triggers with a `require_review` floor, regardless of anything else in the event. At 3 or more, `REPEATED_POLICY_DENIAL` triggers with a `freeze` floor **only when at least one other reason code also triggered in the same evaluation** — a high denial count alone, on an otherwise clean event, never escalates anything by itself; it requires a fresh violation to combine with.

## 11. Role/stage boundary

The Governor owns a private, fixed `REQUIRED_ROLE_BY_STAGE` mapping across the same 6 stages Block 15C uses (`threat_intel_review`→`threat_intelligence`, `threat_hunt`→`threat_hunting`, `detection_engineering`→`blue_team`, `red_validation`→`red_team`, `purple_remediation`→`purple_ir`, `human_review`→`human_analyst`). `STAGE_BYPASS_ATTEMPT` triggers when the supplied `required_role` itself disagrees with this fixed mapping for `current_stage` — an attempt to route around the stage graph. `ROLE_SCOPE_VIOLATION` triggers independently, whenever `actor_role` disagrees with the fixed mapping's role for `current_stage` — an actor acting outside its own assigned stage.

## 12. Approval boundary

`APPROVAL_REQUIRED` triggers when `execution_requested` is `true` and `approval_state != "approved"`, or when `gateway_decision`/`identity_decision` is `"require_approval"`. A high-impact execution request without approval always floors at `block` — high-impact execution can never proceed under `require_approval`/`pending`/`rejected`/`not_required`.

## 13. Mutation Freeze relationship

`mutation_freeze_active` is caller-supplied claimed state, exactly like `core.mutation_freeze`'s own `control_mode` — the Governor never calls `core.mutation_freeze` and never imports it. When `true`, `MUTATION_FREEZE_ACTIVE` always triggers; its floor is `block` for a mutating `action_class` and `warn` otherwise, so a freeze is visible even on a merely observational action, without over-blocking read-only activity.

## 14. Decision Binding relationship

`decision_binding_state` is caller-supplied claimed state, exactly like a fresh `core.decision_binding.verify_decision_binding` outcome would describe — the Governor never calls `core.decision_binding` and never imports it. `DECISION_BINDING_REQUIRED` triggers whenever `execution_requested` is `true` and `decision_binding_state != "valid"` (i.e. `"missing"` or `"invalid"`), flooring at `block`.

## 15. Gateway/Identity relationship

`gateway_decision`/`identity_decision` are caller-supplied claimed state, exactly like a fresh `core.agent_gateway.evaluate_tool_call`/`core.agent_identity_policy.evaluate_agent_tool_call` decision would describe — the Governor never calls either module and never imports either. A `"deny"` on either always floors at `block` (`TOOL_OR_GATEWAY_DENIED`/`IDENTITY_POLICY_DENIED`); a `"require_approval"` on either contributes to `APPROVAL_REQUIRED`.

## 16. Source-truth protection

`SOURCE_TRUTH_MODIFICATION` triggers when `source_truth_state == "modification_attempted"`, or when `action_class == "source_truth_edit"` — either signal alone is sufficient. It always floors at `freeze`, the Governor's strongest available signal, reflecting that protected upstream truth (e.g. a Block 15A finding's own technical fields, frozen into a Block 15C case's `finding_reference`) must never be silently rewritten.

## 17. Scope protection

`SCOPE_EXPANSION_ATTEMPT` triggers when `scope_state == "expansion_attempt"`, flooring at `block` — an action attempting to operate outside its declared/authorized scope (e.g. outside a Bug Bounty engagement's `allowed_origins`/`allowed_paths`) is never permitted through.

## 18. Prompt-injection boundary

There is no free-text field anywhere in the 16-field event contract. `remote_content_state` is a closed-vocabulary flag (`not_present`/`untrusted_data_only`/`adopted_as_instruction`) describing only a caller-asserted classification of externally-sourced content — the Governor never re-derives that classification from any string content itself. `UNTRUSTED_CONTENT_INSTRUCTION_ATTEMPT` triggers only on `"adopted_as_instruction"` and floors at `block`; `"untrusted_data_only"` (content correctly treated as inert evidence, not as instruction) never triggers anything. This mirrors the prompt-injection boundary documented throughout `core.security_handoff` and the Block 15A Bug Bounty engine — remote content and role-generated text are always data, never instructions.

## 19. Audit-bypass detection

`AUDIT_BYPASS_ATTEMPT` triggers when `audit_state == "bypass_attempted"`, flooring at `freeze` — an observable attempt to bypass or disable auditing is treated with the same severity as a source-truth modification attempt.

## 20. Freeze semantics

`"freeze"` is a **deterministic recommendation/state** this module returns in its `decision` field, plus a `mutation_freeze_recommended` boolean. It is never OS process termination, agent shutdown, network isolation, or credential revocation — the Governor is not a daemon and performs no such action. `execution_performed` is hardcoded `false` in every result this module can ever produce, including every `"block"`/`"freeze"` result.

## 21. Governor CLI

`core/security_governor_cli.py`, invoked as `py -m core.security_governor_cli`. Exactly 1 operation, `"evaluate"`, via a two-field envelope: `operation`, `event`. The CLI validates only top-level envelope shape (JSON parses, is a dict, `operation == "evaluate"`, exact two-key set) — all event-content validation is delegated entirely to `core.security_governor`. Output is exactly the core function's own result, `sort_keys=True`, no wrapper. Exit codes: **0** — any valid decision, including `"block"`/`"freeze"`; **2** — envelope violation or a `SecurityGovernorError` (stderr `SECURITY_GOVERNOR_VALIDATION_FAILED`); **1** — unexpected internal failure (stderr `SECURITY_GOVERNOR_INTERNAL_FAILURE`).

## 22. `/security-governor`

One invocation evaluates exactly one observable event. The command passes the caller's complete envelope through unchanged to the CLI — it never synthesizes any field, never infers a value the caller omitted, and never auto-invokes `/security-memory` or any other command. It renders `decision`/`reason_codes` using the twelve codes' fixed meanings, states `"freeze"` as a deterministic recommendation (never process termination), and states plainly when the Governor is not currently a continuous monitor.

## 23. security-governor Claude agent

`.claude/agents/security-governor.md` is the supervisory interpreter. It requires the complete, exact 16-field event from the caller (never fabricating a missing value), invokes only `core.security_governor_cli`, and reports the Governor's own `decision`/`reason_codes` without override, softening, or escalation. It uses **"observable policy/boundary violation"** rather than "malicious agent" unless externally proven, and it explicitly disclaims: reading private reasoning, killing/disabling/restarting any process or agent, authenticating any identity, and inventing policy state or reason codes outside the fixed vocabulary.

## 24. Monitoring limitation

The Security Governor is **not** currently a background daemon. It does **not** continuously intercept operating-system processes. It evaluates exactly the observable event(s) presented to it, one call at a time, through the CLI or the agent. To monitor ThreatTrace roles, observable action/tool/workflow events must be presented to the Governor by some caller or future routing mechanism. This checkpoint provides the deterministic evaluator, its CLI, and the Claude supervisory agent/interface — it does **not** create an always-running event bus or OS watcher. This is never described as "continuous runtime surveillance" anywhere in this checkpoint's code, tests, commands, or agent definition.

## 25. Security-honesty boundaries

The Governor never: executes a tool, calls MCP, calls Supabase, performs network/filesystem/environment-variable/subprocess/system-clock/randomness access, authenticates an identity, claims cryptographic provenance, kills or suspends a process, disables an agent, reads chain-of-thought, or invents a reason code outside its fixed twelve-code vocabulary. `observable_only` is always `true`; `execution_performed` is always `false` on every result, including every `"block"`/`"freeze"` result.

## 26. Research value

Every evaluation's `reason_codes`/`decision` pair, taken across a sequence of caller-supplied events with an accurate `prior_policy_denials` count, enables future measurement of: reason-code frequency distribution; role/stage boundary-violation rate; repeated-denial escalation rate; freeze-recommendation frequency versus actual freeze engagement (a separate, human-operated control). No experimental improvement is claimed yet — no research harness has been built, and no measurement has been performed in this checkpoint.

## 27. Testing

Actual counts as validated at the close of this checkpoint:

- `tests/test_security_governor.py` (Checkpoint A core) — **73 passed**
- `tests/test_security_governor_cli.py` (Checkpoint B CLI) — **46 passed**
- Combined Governor (core + CLI) — **119 passed**

See `docs/block15d-security-experience-memory.md` §27 and this checkpoint's final validation report for the combined Governor+Memory, AI Asset Registry, and bounded-regression results.

## 28. Limitations

The Governor consumes `gateway_decision`/`identity_decision`/`decision_binding_state`/`mutation_freeze_active` as caller-supplied claimed state — it never independently re-evaluates Block 8/9/10/11 itself, so a caller who supplies an inaccurate claim receives a decision based on that inaccurate claim. There is no event bus, no OS-level hook, and no automatic routing of real tool calls into the Governor in this checkpoint — every evaluation requires an explicit, caller-constructed `event`. `prior_policy_denials` is caller-supplied and untracked by this module; it is never independently audited against `core.tamper_evident_audit`. There is no persistence, no history, and no cross-call memory of any kind — each `evaluate_security_governor_event` call is a single, independent, pure computation.
