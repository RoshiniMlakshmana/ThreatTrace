# Block 15D — Validated Security Experience Memory

**Block 15D checkpoint B is complete.** It is a pure, deterministic, local, stateless layer that builds, appends, and structurally searches compact **security experience** records — each one gated by an already-produced Block 15C.5 Governor decision, never admitted as reusable on trust alone.

## 1. Purpose

Block 15D answers exactly one question: *given an already-existing Block 15C security handoff case, its matching Block 15B prioritization result, and an already-produced Block 15C.5 Governor result, what compact, structured "security experience" record can be considered for future advisory reuse — and under what conditions is it actually safe to reuse?* This is called, in code and in prose, **Validated Security Experience Memory** — never "model training," never "learning."

## 2. Why memory is governance-gated

An unsafe or out-of-policy result must never become trusted, reusable memory. Every experience this module can produce is gated by the supplied Governor result's own `decision`: a `"block"`/`"freeze"` decision always forces `"rejected"`/`reusable: false`, unconditionally, regardless of anything else in the supplied case. Admission is never inferred from free text, and never trusted from a caller-asserted status — `create_security_experience` computes `experience_status`/`reusable` itself, from four independently-checked structural conditions plus the Governor decision (see §5, §8).

## 3. Memory state

`memory` is always a plain `{"memory_version": "1", "entries": [...]}` mapping — pure, caller-owned, immutable state. This module never touches a filesystem, a database, Supabase, a vector store, or any embedding/LLM service of any kind, and retains no state between calls. Every public function (`create_security_experience`, `add_security_experience`, `search_security_experiences`) is a single pure computation over its own arguments, returning a new object rather than mutating any input.

## 4. Experience contract

`create_security_experience` (`core/security_experience_memory.py`) returns a dict with exactly 19 fields: `experience_version`, `memory_id`, `case_id`, `finding_id`, `vulnerability_class`, `technical_severity`, `source_finding_status`, `operational_priority`, `organization_context_summary`, `stage_pattern`, `red_validation_summary`, `approval_state`, `governor_decision`, `governor_reason_codes`, `experience_status`, `reusable`, `evidence_references`, `human_review_required`, `execution_performed`.

## 5. Admission states

`experience_status` is one of exactly 3 values: `candidate`, `validated`, `rejected`. Computed as: Governor `decision` in (`block`, `freeze`) → always `rejected`; otherwise, when `current_stage == "human_review"`, `approval_state == "approved"`, at least one stage result is present, and at least one evidence digest is present, all hold together → `validated`; otherwise → `candidate`. This applies identically whether the Governor's decision was `allow`, `warn`, or `require_review` — the four structural conditions, not the specific non-rejecting decision value, determine `validated` vs. `candidate`.

## 6. Candidate/validated/rejected

- **`candidate`** — an admission-eligible workflow that has not yet satisfied every required condition (e.g. approval still pending, or human review not yet reached). Never treated as reusable.
- **`validated`** — every required condition was independently satisfied, and the Governor did not block/freeze. Eligible to be `reusable: true`.
- **`rejected`** — the Governor decision was `"block"` or `"freeze"`. Always `reusable: false`, unconditionally — no combination of otherwise-satisfied conditions overrides this.

## 7. `reusable` flag

A boolean, always `false` unless `experience_status == "validated"`. `add_security_experience` recomputes `memory_id` from an experience's own content on every call (see §14) and rejects any experience whose stored fields — including `reusable` — were tampered with after creation, so a forged `reusable: true` on a Governor-rejected record cannot be smuggled into memory.

## 8. Governor gate

`governor_decision`/`governor_reason_codes` are copied verbatim from the supplied Block 15C.5 Governor result into the experience record — a `"warn"` decision's own reasons are preserved exactly, never edited away, even when the experience separately becomes `validated`/`reusable`. See `docs/block15c5-security-governor.md` for the Governor's own decision/reason-code contract; this module never recomputes it, and never imports `core.security_governor`.

## 9. Human approval requirement

`validated`/`reusable: true` requires `case['approval_state'] == "approved"` and `case['current_stage'] == "human_review"` — the same human-review gate Block 15C itself enforces before recording a caller-reported approval. This module never authenticates that approval; it only requires the already-existing Block 15C case to report it.

## 10. Source finding truth preservation

`source_finding_status` is read once from `case['finding_reference']['finding_status']` and never rewritten. A `"candidate"` source finding remains `"candidate"` in every experience record derived from it, even when that experience's own `experience_status` becomes `"validated"` — the two are deliberately independent judgments (see §21 example). This module never calls back into, imports, or rewrites anything belonging to `core.security_handoff` or `core.context_prioritization`.

## 11. Red validation semantics

`red_validation_summary` is `{result_type, outcome}` from the case's `red_validation` stage result, if one is present, else `null`. It describes only that an externally/caller-supplied Red Team assessment was recorded — never that this module, or ThreatTrace generally, executed an attack.

## 12. Evidence references

`evidence_references` is a compact list of `{reference_type, reference}` entries — a `"finding"` reference to the case's own `finding_id`, plus one `"evidence_digest"` reference per digest already present in `finding_reference.evidence_digests`. This module never stores full remote response excerpts, request/response bodies, or any other raw evidence content — only these compact, digest-level pointers.

## 13. Organization context summary

`organization_context_summary` is a compact 4-field extract (`environment`, `asset_criticality`, `exposure`, `threat_activity`) from the supplied Block 15B `prioritization['context']` — never the full 10-field context object, and never independently re-verified or re-scored.

## 14. Deterministic SEM ID

`memory_id` is `"SEM-"` followed by 16 lowercase hex characters, derived from a private, locally-owned canonical-JSON SHA-256 digest of every other experience field — never imported from `core.security_handoff`'s own `SH-`/`SR-` ID scheme, following this project's established convention of each module owning its own copy of this exact validation shape.

## 15. Hash honesty

`memory_id` (and `case_id`, echoed from the supplied case) are **content correlation only** — never authentication, never a signature, never proof of trusted origin, never a guarantee that the underlying case/prioritization/Governor result was itself accurate. `add_security_experience` recomputes an experience's `memory_id` from its own stored fields and rejects a mismatch, catching accidental or deliberate tampering with the record's content after creation — but this is integrity-of-content-correlation, not cryptographic non-repudiation.

## 16. Append-only memory

`add_security_experience` never mutates the supplied `memory` or any existing entry within it — it returns a new `{"memory_version": "1", "entries": [...]}` dict whose `entries` list is the validated prior entries plus one newly appended, freshly-copied experience. Every prior entry is preserved exactly as it was.

## 17. Duplicate rejection

`add_security_experience` raises `SecurityExperienceMemoryError` with `DUPLICATE_EXPERIENCE` when the supplied `experience['memory_id']` already exists among `memory['entries']` — an experience can be added to a given memory state at most once.

## 18. Structured search

`search_security_experiences` performs deterministic, exact-match structured comparison over a fixed set of query fields only: `technical_severity`, `operational_priority`, `environment`, `asset_criticality`, `exposure`, `threat_activity`, `source_finding_status` (all scoring fields), plus `reusable_only` (a filter, never a scoring dimension). It never uses embeddings, a vector index, or an LLM of any kind.

## 19. `structured_match_score`

For each entry, the count of supplied scoring fields whose value exactly equals the entry's corresponding value, divided by the number of scoring fields supplied (`0.0` when none were supplied). This is a deterministic structural overlap count only — it is never described as, and never intended to approximate, a semantic-similarity score or a probability. `matched_components` lists exactly which fields matched, in a fixed field order.

## 20. `reusable_only` behavior

When `query['reusable_only']` is `true`, every entry with `reusable != true` — including every `"rejected"` entry and every non-reusable `"candidate"` entry — is excluded before scoring. Memory retrieval never surfaces an unsafe or unvalidated experience as if it were reusable.

## 21. Rejected/rogue-attempt records

A Governor `"block"`/`"freeze"` decision (e.g. from `SOURCE_TRUTH_MODIFICATION`, `AUDIT_BYPASS_ATTEMPT`, an unapproved high-impact `execution_request`, or a `REPEATED_POLICY_DENIAL` escalation) still produces a valid experience record — `experience_status: "rejected"`, `reusable: false` — that `add_security_experience` will still accept. This preserves a record of the attempt for future review, without ever making it reusable. Symmetrically: a `source_finding_status: "candidate"` finding can still yield a `validated`/`reusable: true` experience once its handoff workflow, approval, and Governor decision independently satisfy every admission condition — the validated reusable SECURITY EXPERIENCE being supported is never the same claim as the original vulnerability having been automatically validated.

## 22. Prompt-injection boundary

There is no free-text field anywhere in the `create_security_experience`/`add_security_experience`/`search_security_experiences` contracts through which injected instruction-like text could travel. An attempt to smuggle instruction-like text into any closed-vocabulary field (e.g. `approval_state`) is simply a structural validation failure — never an accepted override of `experience_status`, `reusable`, or any other computed field.

## 23. Memory CLI

`core/security_experience_memory_cli.py`, invoked as `py -m core.security_experience_memory_cli`. Exactly 3 operations via three distinct envelopes: `create_experience` (`operation`, `case`, `prioritization`, `governor_result`), `add_experience` (`operation`, `memory`, `experience`), `search` (`operation`, `memory`, `query`). The CLI validates only top-level envelope shape — all nested/content validation is delegated entirely to `core.security_experience_memory`. Output is exactly the core function's own result, `sort_keys=True`, no wrapper. Exit codes: **0** — any valid result, including a `"candidate"`/`"rejected"` `experience_status` or a `reusable_only` search returning zero results; **2** — envelope violation or a `SecurityExperienceMemoryError` (stderr `SECURITY_EXPERIENCE_MEMORY_VALIDATION_FAILED`); **1** — unexpected internal failure (stderr `SECURITY_EXPERIENCE_MEMORY_INTERNAL_FAILURE`).

## 24. `/security-memory`

One invocation performs exactly one memory operation. The command never synthesizes `approval_state`, a Governor decision, validation evidence, organization context, or a source finding's status — it passes the caller's complete envelope through unchanged. It never turns `candidate` into `validated` through prose, and it explicitly distinguishes `source_finding_status` from `experience_status` in every rendering. A `search` result is always presented as *"previous structured validated experience that may inform the current analysis"* — advisory only, never automatically deployed, remediated, approved, or executed.

## 25. No persistence

`memory` exists only for the lifetime of the caller's own request/response chain — this checkpoint stores nothing to a filesystem, database, or Supabase. The caller alone is responsible for retaining a returned `memory` object if they want it available for a later call.

## 26. No embeddings/vector DB

No embedding model, vector index, or similarity library is imported or invoked anywhere in `core/security_experience_memory.py` or `core/security_experience_memory_cli.py`. `structured_match_score` is arithmetic over exact-match booleans only.

## 27. No automatic learning

No model is trained, fine-tuned, or updated by this module. "Memory" here means a caller-owned, structured, append-only record — never a training corpus, and never a mechanism that changes future Governor/handoff/prioritization behavior on its own. Reuse is advisory and manual: a human or a later Claude command decides whether and how to act on a search result.

## 28. No automatic action

`search_security_experiences` never deploys, remediates, approves, or validates a source finding. `create_security_experience`/`add_security_experience` never trigger any downstream action either — every function in this module returns a value; none of them executes anything (`execution_performed` is hardcoded `false` throughout).

## 29. Research value

Across a sequence of experiences, this contract enables future measurement of: validated/reusable rate by `technical_severity`/`operational_priority`; rejection rate attributable to each Governor reason code; time/stage-count from case creation to a `validated` experience; and reuse-search hit rate by query shape. No experimental improvement is claimed yet — no research harness has been built, and no measurement has been performed in this checkpoint.

## 30. Future persistence options

Deliberately deferred, not implemented here: persisting `memory` to Supabase or any other store; any automatic retrieval-augmented retraining; any background indexing service. This checkpoint intentionally keeps memory pure, in-request, and caller-owned so that a future persistence layer can be added as a separate, explicitly-reviewed integration rather than baked into this deterministic core.

## 31. Testing

Actual counts as validated at the close of this checkpoint:

- `tests/test_security_experience_memory.py` (Checkpoint A core) — **85 passed**
- `tests/test_security_experience_memory_cli.py` (Checkpoint B CLI) — **48 passed**
- Combined Memory (core + CLI) — **133 passed**
- Combined Governor + Memory (all four suites) — **252 passed**

See this checkpoint's final validation report for the AI Asset Registry and bounded-regression results.

## 32. Limitations

`case`/`prioritization`/`governor_result` are consumed as plain, duck-typed, caller-supplied mappings — this module never re-derives or independently re-verifies the Block 15C/15B/15C.5 computations that produced them; a caller who supplies internally-inconsistent or fabricated inputs receives an experience record built from those inputs. There is no cross-session persistence, no audit-trail integration with `core.tamper_evident_audit`, and no automatic linkage back into a running Block 15C case (a case does not know an experience was ever created from it). `vulnerability_class` is always `null` in every experience record, because neither the Block 15C case contract nor the Block 15B prioritization contract this module reads ever carries that field.
