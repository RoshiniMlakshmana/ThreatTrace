# Block 6 — Risk-Aware Multi-Review Approval Workflow

**Block 6 is complete.** Investigation-changing actions are now gated by a deterministic risk classification that decides, without any caller input, whether one or two independent human reviewers must approve a change before it can ever be applied.

## Problem and Purpose

Block 5 introduced a single approve/reject gate in front of every investigation `status`/`confidence` change. That gate treated every change the same way, regardless of how consequential it was. Block 6 protects investigation-changing actions from unsafe or unilateral execution by separating the workflow into five distinct concerns:

- **request creation** — an analyst proposes a change; nothing happens to the investigation yet;
- **deterministic risk classification** — the system, not the caller, decides how much review the change requires;
- **human review** — one or two independent reviewers record an immutable approve/reject decision;
- **atomic execution** — the change is applied through exactly one database transaction, only once, only after every condition is independently re-verified;
- **audit history** — every review decision is a permanent, unchangeable row.

The objective is to close off an entire class of failure modes that a naive approval gate leaves open:

- a caller selecting their own risk level or required-approval count;
- a requester approving their own request;
- the same reviewer counted twice toward a two-person requirement;
- an approval created against stale investigation context that has since changed;
- an action executing with fewer reviews than its risk actually requires;
- direct manipulation of an approval's lifecycle state outside the reviewed path;
- a consumed approval being replayed to apply its change a second time;
- any unsafe fallback path (a second mutation attempt, a hand-edited query, a bypassed validator) papering over a failure.

## Risk Model

Risk is calculated entirely from the investigation's own trusted, live `status`/`confidence` and the proposed change — never from anything the caller supplies.

| Risk level | Required approvals |
|---|---:|
| low | 1 |
| medium | 1 |
| high | 2 |
| critical | 2 |

Current deterministic classification behavior:

- a confidence-only increase, a confidence-only preservation, or a change that leaves confidence `unknown` → **low**;
- lowering confidence → **medium**;
- an ordinary status change (one that is not a close or a reopen) → **medium**;
- closing an investigation → **high**;
- reopening a closed investigation → **high**;
- a combined status-and-confidence change uses the **maximum** of its component risks;
- **critical** is reserved for future deterministic rules and is not yet reachable by any current classification path.

This has three consequences that hold for every request, with no exception:

- callers cannot select `risk_level`;
- callers cannot select `required_approvals`;
- risk is calculated from the investigation's trusted context, loaded fresh from the database, and the same live context binds the approval's own creation — a change to that context between the lookup and the insert is rejected rather than silently ignored.

## Trusted Request Workflow

```
/request-case-update
  → load trusted investigation status/confidence
  → deterministic risk classification
  → guarded INSERT ... SELECT ... WHERE status = <expected> AND confidence = <expected>
  → pending approval (risk_level + required_approvals attached)
```

- `status` and `confidence` come from one fixed, read-only lookup against the live `investigations` row — the caller cannot supply either value as "current" context.
- The same `status`/`confidence` used for risk classification are reused, unchanged, as insertion guards.
- If the investigation's live `status`/`confidence` no longer match what the lookup returned — a concurrent change between the lookup and the insert — the guarded `INSERT ... SELECT ... WHERE` matches zero rows. No approval is created, and there is no fallback unconditional insert and no automatic retry.
- `requested_by_normalized` is derived internally (case-folded, whitespace-trimmed) for later duplicate/self-review comparisons; it is never caller-supplied and never displayed as if it were an authenticated identity.

## Review Lifecycle

### One-review request

```
pending → approved → consumed
```

### Two-review request

```
pending → partially_approved → approved → consumed
```

### Rejection

```
pending or partially_approved → rejected
```

- Every review is one immutable row in `approval_reviews` — reviews are never updated or deleted, only inserted.
- The requester cannot approve their own request: a reviewer identity that normalizes to the same value as the request's `requested_by_normalized` is rejected before any mutation.
- The same normalized reviewer identity cannot review the same approval twice — attempting it is rejected locally, before any database call, once the existing review history has been loaded.
- Reviewer identities are normalized the same deterministic way as requester identities (case-folded, whitespace-trimmed) purely for duplicate/self-review comparison — normalization is never treated as authentication.
- `approved`, `rejected`, and `consumed` are terminal states — none of them accepts another review.
- An expired request cannot be reviewed.
- `partially_approved` cannot be consumed — a two-review request must reach `approved` (both required, distinct reviews recorded) before `/apply-case-update` will accept it.

Review recording and status promotion happen together, atomically, through a single database function, `record_approval_review_and_promote_status`. This document does not reproduce that function's SQL body — it is the sole place a review row is ever inserted and the sole place an approval's summary status is ever promoted from a review.

## Atomic Consumption

Approved actions are applied through one atomic function, `consume_approval_and_update_investigation_state`. Both one-review and two-review approvals are consumed through this same fixed path — there is no separate consumption function for either risk tier.

Inside its own transaction, the database independently re-verifies every one of the following against the live rows — not against whatever an earlier lookup returned:

- the approval's lifecycle status is genuinely `approved`;
- the required number of distinct approve reviews actually exist;
- no reject review exists for the approval;
- the requester is never counted as one of the required reviewers;
- the approval has not expired;
- the approval is bound to the expected investigation;
- the approval is bound to the expected action type;
- the approval has not already been consumed;
- a replay of an already-consumed approval is rejected, not silently re-applied.

A database-controlled compatibility branch remains available for historical, pre-Block-6 approval records that were never classified for risk. New risk-aware records are never intentionally routed into that branch — it exists only so that older data continues to resolve correctly, not as an escape hatch for new requests.

## Architecture

```
User / Analyst
    |
    v
Claude Command Boundary        (/request-case-update, /review-approval, /apply-case-update)
    |
    v
Validation CLI                 (deterministic Python planning: risk classification, transition rules)
    |
    v
Approval Bridge                (re-derives the exact persistence descriptor; never trusts a caller-built one)
    |
    v
Fixed MCP Adapter              (only allowlisted descriptors become SQL; only fixed templates; no caller SQL)
    |
    v
Supabase RPC / Guarded SQL     (record_approval_review_and_promote_status, consume_approval_and_update_investigation_state)
    |
    v
Approvals + Immutable Reviews + Investigation State
```

The three command workflows share this same architecture:

- **`/request-case-update`** — trusted context lookup → risk classification → guarded insert.
- **`/review-approval`** — trusted record lookup → trusted review-history lookup → transition planning → atomic review-and-promote RPC.
- **`/apply-case-update`** — trusted record lookup → local eligibility check → transition planning → atomic consumption RPC.

The Python validators (risk classification, transition planning) are the **deterministic planning authority** — they decide what *should* happen given trusted inputs. The database is the **final persistence and authorization authority** — every one of its RPCs independently re-checks the real, live state before committing anything, so a planning decision that has gone stale between planning and execution is rejected rather than trusted blindly.

## Security Controls

| Control | Description |
|---|---|
| Caller-selected risk blocked | `risk_level`/`required_approvals` are always derived, never caller-supplied. |
| Caller-supplied current context blocked | `status`/`confidence` used for classification and insertion guards are always loaded fresh, never accepted as request input. |
| TOCTOU protection | The guarded insert and every atomic RPC re-check live state inside their own transaction; a stale plan matches zero rows instead of executing. |
| Requester self-review blocked | A reviewer whose normalized identity matches the requester's normalized identity is rejected before any mutation. |
| Duplicate reviewer blocked | A reviewer who already recorded a decision for an approval is rejected locally before any mutation. |
| Immutable review history | Reviews are insert-only rows; they are never updated or deleted. |
| Partial approval cannot execute | `partially_approved` is not a consumable status; consumption requires the full required review count. |
| Direct table mutation avoided | No command ever issues a direct `INSERT`/`UPDATE` against `approvals` or `approval_reviews`; every mutation goes through an allowlisted descriptor and a fixed RPC or guarded template. |
| Fixed SQL templates | The MCP adapter recognizes only a small, fixed set of descriptor shapes; nothing else can reach the database as SQL. |
| Hardened RPC privileges | `PUBLIC`, `anon`, and `authenticated` cannot execute either atomic RPC; only `service_role` (and the function owner) retain `EXECUTE`. |
| RLS on `approval_reviews` | Row Level Security is enabled on the review table. |
| Stale-state conflicts | A concurrent change between load and mutation surfaces as an explicit conflict, never a silent success or a fallback write. |
| One-time consumption | An approval can be consumed successfully exactly once. |
| Replay protection | Every replay attempt after consumption fails closed as a persistence conflict. |
| Sensitive-output suppression | Normalized identities and raw internal payloads are never displayed to the caller as command output. |

**Identity honesty note:** current reviewer and requester identity is a caller-typed, deterministically normalized **claimed identity** — it is not authenticated, not cryptographically verified, and not derived from Supabase Auth or any other identity provider. Stronger authenticated agent/user identity is planned for a later block, not implemented today. This document does not claim otherwise.

## Live Supabase Verification

Beyond the automated suite, Block 6 was verified against a live Supabase project with a shortened, targeted smoke test covering the critical path. Temporary records were created, exercised, and deleted; no pre-existing record was touched at any point.

### One-review scenario

- a confidence-only increase was requested against a live investigation;
- the deterministic classifier correctly assigned **low** risk and **one** required approval;
- one reviewer's approval promoted the request to `approved`;
- the approved request was **consumed** through the atomic RPC, and the investigation's confidence changed exactly once;
- a replay attempt against the now-consumed approval was **blocked before any mutation**.

### Two-review scenario

- closing an investigation was requested against a live investigation;
- the deterministic classifier correctly assigned **high** risk and **two** required approvals;
- the first reviewer's approval produced `partially_approved`, with the finalized approval fields correctly left unset;
- a **duplicate** attempt by the same reviewer was blocked before any mutation;
- a second, distinct reviewer's approval produced `approved`;
- the approved request was **consumed** through the atomic RPC, and the investigation's status changed exactly once, to `closed`.

Additional confirmations from this live run:

- the explicit PostgreSQL `smallint` binding for the multi-review RPC's approval-count parameter was verified working live, closing the type-resolution defect the smoke test itself had originally surfaced;
- exactly two temporary approvals and three temporary immutable approve reviews existed at the point of maximum live state, immediately before cleanup;
- cleanup restored the database to exactly its pre-test state: the original two investigations, zero approvals, and zero approval reviews;
- no pre-existing row was modified at any point during the test;
- no temporary record remained after cleanup.

No temporary UUIDs, reviewer identities, or other test-run values are reproduced here — they existed only for the duration of the live verification and were deleted immediately afterward.

## Automated Verification

- **3,800+ automated tests** pass across the full project suite.
- Coverage spans: the approval and multi-review request/transition contracts, every command-facing CLI, the persistence layer, the two-phase approval bridge, the MCP adapter's fixed SQL templates, the live schema definition, all three approval commands' documented behavior, replay and conflict handling, and this project's own documentation.
- The live Supabase smoke test **complements** this automated suite — it exists to confirm real database behavior (RPC type resolution, live row locking, actual transaction semantics) that a mocked or in-memory test cannot observe, not to replace the automated suite's much broader coverage of edge cases, malformed input, and the full negative-test matrix.

## Presentation Demo Walkthrough

A short, live-safe walkthrough for demonstrating Block 6:

1. Display an open investigation.
2. Request a low-risk confidence change with `/request-case-update`.
3. Show the one-review approval and consumption, end to end.
4. Attempt to replay the consumed approval and show it denied.
5. Request a high-risk close action with `/request-case-update`.
6. Show the first review producing `partially_approved`.
7. Attempt a duplicate review from the same reviewer and show it denied.
8. Use a second, distinct reviewer to reach `approved`.
9. Consume the approved close action.
10. Show the immutable review rows and the final audit state.

Any temporary records created for a live demo should always be cleaned up afterward by their exact UUID — never by a broad text-pattern delete, and never touching any pre-existing record.

## Limitations

- Reviewer and requester identities are claimed and deterministically normalized, not yet cryptographically authenticated.
- `critical` risk classification is reserved in the model but not yet reachable by any implemented rule.
- The current interface is command-driven (Claude Code slash commands), not a graphical dashboard.
- The live smoke test intentionally covered a minimal critical path (one-review lifecycle, two-review lifecycle, duplicate-reviewer denial, replay denial, cleanup); the much wider negative-test matrix — rejection, expiry, malformed input, concurrent competing reviewers, and every individual risk classification variant — is covered by the automated suite instead of being re-run live.

## Next: Block 7 — Shadow Execution / Digital Twin

Block 7 will simulate a proposed, already-approved action **before** it executes, and show:

- predicted state changes to the investigation;
- affected records;
- likely control impact;
- rollback feasibility;
- warnings surfaced before any mutation occurs.

Block 7 is not implemented as part of Block 6 or this document.
