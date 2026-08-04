# Block 7 — Shadow Execution / Digital Twin

**The Block 7 MVP is complete.** It is a stateless, read-only, deterministic preview engine: given an existing approval, it calculates exactly what `/apply-case-update` would change, without ever performing execution. The offline implementation — engine, CLI, and command — is fully built, tested, and committed. The authorized live read-only verification attempt was **blocked**, honestly and safely, because no approval record currently exists in the connected Supabase project — see [Live Read-Only Verification](#live-read-only-verification) below. This document does not claim that a complete live shadow report was ever generated.

## Problem and Purpose

Block 6 answers one question: **is an action permitted?** Block 7 adds a second, distinct question: **what would that permitted action actually change?** These are deliberately kept separate from a third, already-existing question — **did the action actually execute?** — which remains the sole responsibility of `/apply-case-update`'s atomic, database-enforced consumption RPC.

| Question | Answered by |
|---|---|
| Is this action permitted? | Block 6 — deterministic risk classification, one/two-person approval |
| What would this action change? | Block 7 — shadow execution / digital twin preview |
| Did this action execute? | `/apply-case-update`'s atomic consumption RPC — the sole final authority |

Given an existing, approved risk-aware approval, `/simulate-case-update` lets an analyst inspect, before ever touching `/apply-case-update`:

- the investigation's current state;
- the state the approval's own stored action would produce;
- exactly which fields would change, and which would not;
- a fixed set of deterministic warnings about the change;
- a rollback-feasibility classification;
- whether the action is currently eligible for execution at all.

Simulation never consumes, approves, rejects, or otherwise changes the approval it inspects, and it never updates the investigation it previews. A shadow-execution report is a preview — it carries no authorization weight and leaves no execution behind it.

## Architecture

```
Caller
  |
  v
/simulate-case-update <approval-id>
  |
  v
Trusted Approval Lookup        (load_risk_aware_approval_record)
  |
  v
Trusted Investigation Lookup   (load_investigation_approval_context)
  |
  v
Pinned UTC simulated_at
  |
  v
shadow_execution_cli
  |
  v
Pure simulate_case_update
  |
  v
Fifteen-Field Read-Only Report
```

`/apply-case-update` sits entirely apart from this pipeline — it is a separate command, invoked separately, by explicit later intent, and it is the only command that ever actually mutates an approval or an investigation.

The trust boundary is strict and asymmetric:

- the caller supplies **only** `approval_id`;
- `investigation_id` is never caller-supplied — it comes exclusively from the bridge-verified approval record's own `investigation_id`;
- `current_state` comes exclusively from the bridge-verified, trusted investigation lookup — never from the caller;
- `proposed_state` comes exclusively from the approval's own stored action — never from a caller-supplied "after" value;
- every warning is deterministic, computed from a small, fixed, closed vocabulary — never generated dynamically, never by a model;
- no new database operation was added anywhere in this Block. Both lookups (`load_risk_aware_approval_record`, `load_investigation_approval_context`) already existed, already committed, already used by `/review-approval` and `/apply-case-update` — Block 7 reuses them verbatim through the same existing two-phase bridge/adapter pipeline, and introduces no new SQL, descriptor, or RPC.

## Supported Action

The MVP supports exactly one action type: `update_investigation_state`, covering:

- a status-only change;
- a confidence-only change;
- a combined status-and-confidence change.

The canonical state fields are `status` and `confidence` — the same two fields the entire approval-gated case-update workflow has always covered. Any field the stored action does not touch is reported unchanged in `proposed_state`, equal to its current value. No other action type is supported, and this document makes no claim otherwise.

## Result Contract

Every simulation returns exactly fifteen top-level fields:

1. `simulation_version`
2. `approval_id`
3. `investigation_id`
4. `action_type`
5. `risk_level`
6. `required_approvals`
7. `eligible_for_execution`
8. `current_state`
9. `proposed_state`
10. `changed_fields`
11. `unchanged_fields`
12. `warnings`
13. `rollback`
14. `simulated_at`
15. `mutation_performed`

`simulation_version` is always `"1"`. `mutation_performed` is always `false` — a report where this field is missing or anything other than the literal `false` is never treated as a valid success.

`changed_fields` and `unchanged_fields` both use the fixed canonical comparison order **status before confidence**, regardless of which field the underlying action actually touches. A successful report where `eligible_for_execution` is `false` is still a **completely valid simulation** — lifecycle ineligibility (a pending, rejected, expired, or already-consumed approval) is a normal report outcome, never a transport error, and it is never converted into a command failure.

## Warning Behavior

Warnings are evaluated, in this fixed order, from a small, closed vocabulary — never generated by a model, and never caller-suppliable or overridable:

1. `ALREADY_CONSUMED`
2. `NOT_APPROVED`
3. `APPROVAL_EXPIRED`
4. `STALE_BINDING`
5. `CLOSING_INVESTIGATION`
6. `REOPENING_INVESTIGATION`
7. `CONFIDENCE_LOWERED`
8. `COMBINED_FIELD_CHANGE`
9. `NO_OP_ACTION`
10. `ROLLBACK_UNCERTAIN`

Each warning carries a fixed severity:

- **blocking** — `ALREADY_CONSUMED`, `NOT_APPROVED`, `APPROVAL_EXPIRED`, `STALE_BINDING`;
- **caution** — `CLOSING_INVESTIGATION`, `REOPENING_INVESTIGATION`, `CONFIDENCE_LOWERED`, `NO_OP_ACTION`;
- **informational** — `COMBINED_FIELD_CHANGE`, `ROLLBACK_UNCERTAIN`.

Every warning message is fixed, deterministic text — never generated dynamically from arbitrary input, and never produced by an LLM. A blocking warning sets `eligible_for_execution` to `false`; it never turns a valid report into a CLI failure. Non-blocking (caution/informational) warnings never affect eligibility at all.

## Rollback Classification

Rollback uses a strict, four-value vocabulary: `fully_reversible`, `conditionally_reversible`, `not_reversible`, `unknown`. The MVP's one supported action type only ever produces the first two:

- a **no-op** (nothing would actually change) → `fully_reversible`;
- any actual supported `status`/`confidence` change → `conditionally_reversible`.

"Rollback" always means creating a **new, separately approved action** that restores the prior value — never an automatic reversal. Block 7 never executes a rollback itself. A `conditionally_reversible` classification is honest about its own limits: the investigation may change again before a rollback is even requested, a rollback request itself needs its own approval, future approval of that request is never guaranteed, and the classification is never a promise that a rollback would actually succeed. `not_reversible` and `unknown` remain in the vocabulary for a future action type; neither is reachable by the one action type this MVP supports today.

## Eligibility

`eligible_for_execution` is `true` only when every one of these holds:

- the approval's own status is `approved`;
- the approval is unexpired at the pinned simulation time;
- the approval is unconsumed;
- the approval's `investigation_id` matches the investigation actually loaded;
- no blocking warning exists.

`pending`, `partially_approved`, `rejected`, and `consumed` approvals are all ineligible, as is an expired approval or one whose investigation binding no longer matches. In every one of these cases, the simulation still completes successfully and returns a complete, valid report — ineligibility is communicated through `eligible_for_execution: false` and the corresponding blocking warning, never through a failure response.

## Security Boundaries

| Control | Description |
|---|---|
| Caller-forged current state blocked | `current_state` always comes from the trusted, bridge-verified investigation lookup — never caller input. |
| Caller-forged proposed state blocked | `proposed_state` is derived only from the approval's own stored action — the caller supplies no "after" value. |
| Caller-selected risk blocked | `risk_level`/`required_approvals` are always read from the trusted approval record, never accepted from the caller. |
| Caller-supplied investigation ID blocked | The investigation lookup is always keyed by the verified approval's own `investigation_id`, never by caller input. |
| Caller-supplied timestamp blocked | `simulated_at` is pinned once, internally, only after both trusted lookups succeed — the caller can never supply or override it. |
| Approval/action substitution blocked | The caller supplies only `approval_id`; the action type and payload always come from the one record that ID resolves to. |
| Fixed read-only lookup templates | Only the two existing, already-committed lookup descriptor shapes are ever generated — no new SQL template exists. |
| Bridge verification | Both lookups are independently re-verified by the existing two-phase approval bridge before their results are trusted. |
| No new SQL operation | Block 7 introduces zero new descriptors, templates, or adapter operations. |
| No mutating RPC | Neither `record_approval_review_and_promote_status` nor `consume_approval_and_update_investigation_state` is ever called. |
| No automatic retry | Every stage stops on failure; nothing is retried automatically. |
| No fallback SQL | No direct query, direct client, or hand-written SQL ever substitutes for the fixed lookup pipeline. |
| Deterministic warnings | The warning vocabulary is fixed and closed; nothing is generated by a model. |
| Sensitive identity suppression | `requested_by`, `approved_by`, `rejected_by`, `consumed_by`, and every normalized identity are excluded from the report. |
| Raw action-payload suppression | The stored `action_payload` is never displayed raw — only the derived `current_state`/`proposed_state`/`changed_fields`/`unchanged_fields`. |
| `mutation_performed` always false | Every report, eligible or not, carries this literal value — never anything else. |
| Separation from `/apply-case-update` | Simulation and execution are two distinct commands; simulation never triggers, chains into, or implies execution. |

Block 7's simulation is **not cryptographically bound** to any later execution — a report is a snapshot at the moment it was generated, and `/apply-case-update`'s own atomic RPC remains the sole, independent, live re-check at execution time, exactly as it already was before this Block existed.

## Live Read-Only Verification

**Status: `LIVE_VERIFICATION_BLOCKED_NO_EXISTING_APPROVAL`.**

An authorized, read-only live verification attempt was performed against the connected Supabase project:

- a read-only preflight was run first;
- the database contained **2 investigations, 0 approvals, and 0 approval reviews**;
- no candidate approval existed to simulate against;
- no synthetic or temporary approval record was created to force a demonstration;
- no simulation was run using fabricated or hand-built data;
- no row, column, or schema object was changed at any point;
- a post-check re-read confirmed the preflight and post-check counts, ID sets, and lifecycle fingerprints were identical.

**A complete live shadow-report verification remains pending until a genuine risk-aware approval record exists** to simulate against. This document does not claim that a full live report was ever generated or displayed — only that the read-only preflight, the honest no-candidate decision, and the preservation check all completed exactly as designed.

## Automated Verification

- **3,800+ automated tests** pass across the full project suite.
- Coverage includes: the pure simulation engine's deterministic contract, its CLI's stdin/stdout boundary, `/simulate-case-update`'s command-level stage ordering and security boundaries, and full Block 6 regression coverage (risk classification, multi-review, persistence, bridge, adapter).
- These tests specifically verify: deterministic, repeatable results; input nonmutation; sensitive-output suppression (no identity, no raw payload, no SQL, no descriptor); fixed warning ordering; every lifecycle-eligibility branch; strict input-envelope validation (missing/unknown/forbidden fields all rejected); the read-only nature of every command boundary; and the absence of any fallback or mutation path.
- The blocked live check is **not equivalent** to a completed live report test — it confirms the read-only preflight and no-candidate safety path work correctly, not that a full end-to-end live report was ever produced.

## Presentation Walkthrough

A concise future demo sequence, once a genuine approved case-update request exists:

1. Create or identify a genuine approved case-update request.
2. Run `/simulate-case-update <approval-id>`.
3. Show the current and proposed `status`/`confidence`.
4. Show the ordered `changed_fields` and `unchanged_fields`.
5. Show the deterministic warnings.
6. Show the rollback classification.
7. Highlight `mutation_performed: false`.
8. Confirm the underlying database record remains unchanged.
9. Run `/apply-case-update` separately, only after explicit execution intent.
10. Compare the real, applied result against the prior preview.

Any temporary demo records should always be cleaned up afterward by their exact UUID — never by a broad text-pattern delete, and never touching any pre-existing record.

## Limitations

- Stateless reports are not persisted — nothing is stored anywhere after a simulation completes.
- A simulation is not cryptographically or otherwise bound to any later execution.
- An old report can become stale the moment the underlying approval or investigation changes.
- Only `update_investigation_state` is supported; no other action type has a simulation path.
- Rollback is descriptive only — Block 7 never executes a rollback.
- Reviewer/requester identity limitations are inherited unchanged from Block 6: claimed, normalized identities, not yet cryptographically authenticated.
- Live report verification is pending a genuine approval record — see [Live Read-Only Verification](#live-read-only-verification) above.
- No graphical dashboard exists yet; the interface remains command-driven.

## Next: Block 8 — AI Agent Gateway / Runtime Firewall

Block 8 will focus on controlling AI-agent tool execution itself, through:

- tool allowlists;
- argument validation;
- least-privilege policies;
- runtime decision gates;
- blocked-action explanations;
- auditable tool-call outcomes.

Block 8 is not implemented as part of Block 7 or this document.
