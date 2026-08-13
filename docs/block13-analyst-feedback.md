# Block 13 — Analyst Feedback Learning

**The Block 13 MVP is complete.** It is a pure, deterministic, local, stateless layer that captures structured analyst feedback about an existing ThreatTrace output — an investigation decision, a security-policy decision, or an evaluation-lab result. It does not recompute, override, or persist the result it comments on, and it does not perform any form of automatic learning.

## 1. Purpose

Block 13 captures **structured analyst feedback about existing ThreatTrace outputs**. "Learning" in this MVP means exactly: producing structured feedback signals that may later support human-driven rule tuning, evaluation-case improvement, false-positive/false-negative analysis, or future training-dataset construction. It does **not** mean automatic model retraining, online learning, prompt adaptation, or automatic policy/rule rewriting — none of which this repository has any mechanism to perform, and none of which this block implies.

## 2. Genuine gap addressed

Prior blocks already produce three distinct kinds of reviewable output: investigation decisions (Blocks 2–3), security-policy decisions (Blocks 8–10 and the Emergency Mutation Freeze), and evaluation-lab results (merged Blocks 11–12). None of them provided any mechanism for recording whether a human analyst agrees or disagrees with one of those outputs, or why. Block 13 closes that specific gap.

Approval/rejection of an action request already belongs entirely to Blocks 4–6 (`/request-case-update` → `/review-approval` → `/apply-case-update`) and is **not** duplicated here — Block 13 never becomes a second approval workflow, and its `analyst_decision` vocabulary (`agree`/`disagree`/`insufficient_evidence`) is deliberately distinct from Block 6's `approve`/`reject`.

## 3. Architecture

```
Existing result (investigation decision, security-policy decision, or evaluation result)
        |
        v
   target_reference (caller-supplied, opaque, never verified)
        |
        v
Analyst Feedback Core (core.analyst_feedback.create_analyst_feedback)
        |
        v
   validated structured feedback record
        |
        v
future human-driven analysis / rule tuning / evaluation-case improvement
```

Block 13 never recomputes or replaces the original result — it only records a structured, caller-supplied opinion about it. It never calls `core.agent_gateway`, `core.agent_identity_policy`, `core.mutation_freeze`, `core.decision_binding`, or `core.ai_asset_registry`.

## 4. Implemented files

| File | Role |
|---|---|
| `core/analyst_feedback.py` | Pure feedback-record constructor — `create_analyst_feedback` |
| `tests/test_analyst_feedback.py` | Core tests (60 tests) |
| `core/analyst_feedback_cli.py` | Stdin/stdout JSON adapter around the core function |
| `tests/test_analyst_feedback_cli.py` | CLI adapter tests (32 tests) |
| `.claude/commands/record-analyst-feedback.md` | Claude Code command wrapping the CLI |
| `docs/block13-analyst-feedback.md` | This document |

No other file exists for this block.

## 5. Public API

`create_analyst_feedback(*, target_type, target_reference, analyst_decision, error_category, rationale, evidence_reference, corrected_value, submitted_at) -> dict[str, Any]` — the module's only public function, keyword-only, no hidden defaults. `AnalystFeedbackError(ValueError)` is raised only for structurally malformed input; a legitimate analyst disagreement is always a normal, successfully created record, never an exception.

## 6. Target types

Exactly three, each backed by a real artifact already produced elsewhere in this project:

| `target_type` | Refers to |
|---|---|
| `investigation_decision` | A `decision_status` object validated by `core.decision_analysis` (Blocks 2–3) |
| `security_policy_decision` | A Block 8/9/Mutation-Freeze `decision`/`final_decision`, or a Block 10 binding/verification outcome |
| `evaluation_result` | A Block 11–12 `evaluate_ai_security_case` result |

## 7. Analyst-decision vocabulary

Exactly `agree`, `disagree`, `insufficient_evidence`. These are deliberately distinct from `allow`/`require_approval`/`deny` (Blocks 8–10's own production policy vocabulary) and from `pass`/`fail`/`not_applicable` (the evaluation-lab's own outcome vocabulary) — an analyst's *opinion* about a result is a different concept from the result itself, and conflating the two vocabularies would blur exactly that distinction. `partially_agree` was considered and deliberately excluded from this MVP (see the Step 1 architecture audit) for simplicity and uniform applicability across all three target types.

## 8. Error categories

Exactly eight: `false_positive`, `false_negative`, `incorrect_severity`, `incorrect_classification`, `missing_evidence`, `policy_mismatch`, `evaluation_expectation_mismatch`, `other`. `error_category` is required, and must be one of these eight values, only when `analyst_decision == "disagree"`; it must be `None` for every other `analyst_decision` value — a non-`None` category is rejected even if it names a real, valid category.

## 9. Rationale behavior

For `analyst_decision == "disagree"`: `rationale` is **required** and must be a non-blank string. For `agree`/`insufficient_evidence`: `rationale` is **optional** — `None`, or a non-blank string if supplied. A blank string (`""`, whitespace-only) is never accepted in either case. `rationale` is analyst-supplied free text; this module never reinterprets, categorizes, or treats its content as evidence — it is stored and returned exactly as supplied.

## 10. Evidence references

`evidence_reference` must be `None` or a non-empty list of non-blank strings — each an opaque reference to an already-existing evidence item, never a raw evidence blob, a nested object, or an arbitrary dictionary. References are never verified to exist against Supabase or any other live persistence. The returned list, when present, is always a freshly constructed copy — the caller's own list object is never mutated or aliased.

## 11. Corrected value

`corrected_value` is optional. When present, it must be a plain string drawn from the closed vocabulary that already governs the selected `target_type`:

- `investigation_decision` → `core.decision_analysis.DECISION_STATUSES` (imported directly, not duplicated);
- `security_policy_decision` → `allow` / `require_approval` / `deny` (imported directly from `core.agent_gateway.DECISIONS`, an already-public constant);
- `evaluation_result` → `pass` / `fail` / `not_applicable` (defined locally in `core/analyst_feedback.py`, since `core.ai_asset_registry` does not export this vocabulary as a public constant — mirrored rather than duplicating that completed block's internals).

`corrected_value` is **analyst-supplied proposed correction metadata only** — it does not mutate the original decision anywhere, and this module never checks whether the proposed correction is logically consistent with the rest of the feedback record.

## 12. submitted_at

Required, caller-supplied, validated as an aware `datetime` or aware ISO-8601 string and normalized to UTC `...Z` form — following the identical convention every other pure module in this project already uses (Block 8's `evaluated_at`, Block 10's `issued_at`/`expires_at`, etc.). This module never reads the system clock and never defaults to "now."

## 13. Record contract

Every feedback record contains exactly eleven fields:

`feedback_version`, `target_type`, `target_reference`, `analyst_decision`, `error_category`, `rationale`, `evidence_reference`, `corrected_value`, `submitted_at`, `feedback_persisted`, `automatic_learning_performed`.

`feedback_persisted` is always `false` and `automatic_learning_performed` is always `false`, in every record this module can ever produce.

## 14. Why there is no feedback_id

No persistence layer exists in this MVP — nothing assigns feedback records a durable identity yet. The pure core also never generates a random UUID (or any other random value), matching the "no randomness" purity invariant every other Block 8–12 core module documents about itself. A real `feedback_id` would need to be assigned by a future persistence layer (a database `INSERT`, for example), exactly like Block 6's `approvals.id` is assigned by the database, never by `core.approval_request`.

## 15. Why there is no analyst identity

This MVP does not authenticate analysts — there is no authentication mechanism anywhere in this project to honestly back an `analyst_id` field. Rather than inventing identity/authentication semantics, this first Block 13 contract records the feedback signal only. A future workflow/persistence layer may add a *claimed* (not authenticated) analyst identity, exactly like Block 6's `reviewer_identity` and Block 9's `agent_id`, if that is explicitly designed and approved later.

## 16. Relationship to Blocks 2–12

- **Blocks 2–3** produce evidence-backed investigation decision context (`decision_status`, evidence records) that `investigation_decision` feedback refers to.
- **Blocks 4–6** own the action approval/rejection workflow — not duplicated by Block 13's `agree`/`disagree`/`insufficient_evidence` vocabulary.
- **Block 7** (shadow execution) can supply contextual evidence for a feedback record's `target_reference`/`evidence_reference` but is not modified by this block.
- **Blocks 8–10 and the Emergency Mutation Freeze** produce the security-policy outcomes `security_policy_decision` feedback refers to — never re-evaluated by Block 13.
- **Blocks 11–12** produce the evaluation results `evaluation_result` feedback refers to — never re-run by Block 13.
- **Block 13** records feedback **about** these existing results only, and never recomputes, overrides, or persists any of them.

## 17. Security honesty

Feedback recorded by this block: is analyst-supplied; is not automatically ground truth; does not override the system result it references; is not persisted anywhere; does not cause model retraining; does not perform online learning; does not rewrite policy or rules; does not authenticate the analyst; does not verify that the referenced target or evidence actually exists; and is not tamper-evident (there is no signature, hash-chain, or integrity mechanism of any kind over a feedback record in this MVP).

## 18. CLI

`core/analyst_feedback_cli.py`, invoked as:

```
py -m core.analyst_feedback_cli
```

One JSON object via stdin; the single supported `operation` is `"create"`. Exit `0` for any successfully created record (including `analyst_decision: "disagree"` — a normal, successful outcome), exit `2` for envelope/input validation failures (including the core's own typed `AnalystFeedbackError`), exit `1` for unexpected internal failures. No `argparse`, no filesystem/network/database/Supabase/MCP access, no system-clock read.

## 19. Claude command

`/record-analyst-feedback` is a thin, user-facing wrapper around `core.analyst_feedback_cli` — it accepts the exact same nine-key JSON envelope the CLI itself requires (including the caller's own `"operation": "create"`), validates only that outer envelope shape, and sends it through stdin **unchanged** — it never inserts, synthesizes, defaults, or overwrites `operation` on the caller's behalf. It adds no learning or policy semantics of its own, and explicitly presents a `"disagree"` result as an analyst disagreement record, never as a corrected system decision.

## 20. Example

An honest disagreement record, referencing an investigation decision — this is the exact same envelope shape both the CLI and `/record-analyst-feedback` accept, since the command passes it through unchanged:

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

This produces a structured feedback record proposing `"contradicted"` (a real `DECISION_STATUSES` value) as the analyst's suggested correction. It does not change investigation `investigation-123`'s actual, already-stored `decision_status` — that remains whatever it was before this feedback was recorded, since this block performs no persistence and no mutation of any kind.

## 21. Tests

As validated at the close of this checkpoint:

- **`tests/test_analyst_feedback.py` — 60 tests** (vocabulary validation, the conditional `error_category`/`rationale` disagreement rule, `corrected_value` domain validation per target type, reference/evidence handling, timestamp validation, honesty fields, and purity/structural checks).
- **`tests/test_analyst_feedback_cli.py` — 32 tests** (envelope dispatch, exit-code behavior, output shape, typed-error surfacing, and structural checks confirming the CLI never imports any other Block directly).
- **Combined Block 13 (core + CLI) — 92 tests.**
- **Bounded regression** (`tests/test_decision_analysis.py` + `tests/test_agent_gateway.py` + `tests/test_agent_identity_policy.py` + `tests/test_decision_binding.py` + `tests/test_mutation_freeze.py` + `tests/test_ai_asset_registry.py` + `tests/test_analyst_feedback.py` + `tests/test_analyst_feedback_cli.py`) — **391 tests**, all passing together.

These counts reflect the repository as validated at the close of this checkpoint; they are not projected or assumed.

## 22. Future possibilities

Listed strictly as **future possibilities, not implemented, not currently planned or approved**:

- a persistent feedback store;
- a claimed analyst identity / authenticated workflow;
- trend analysis over recorded feedback;
- feedback aggregation across many records;
- rule-tuning reports derived from accumulated feedback;
- evaluation-case generation proposals informed by feedback;
- supervised training-dataset export;
- a review/approval step for feedback before it is used for anything;
- tamper-evident feedback history (signing, hash-chaining, or similar).

None of the above is implemented, and this document does not describe any partial implementation of them.
