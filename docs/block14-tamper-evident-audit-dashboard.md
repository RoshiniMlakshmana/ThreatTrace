# Block 14 — Tamper-Evident Audit & Evaluation Dashboard

**The Block 14 MVP is complete.** It is a pure, deterministic, local, stateless combination of two coupled concerns: SHA-256-linked audit-record correlation with internal-consistency verification, and a read-only summary/dashboard report over a supplied batch of those records. Neither concern persists anything, executes anything, or claims a stronger security property than it actually provides.

## 1. Purpose

Block 14 combines two roadmap items (`docs/architecture.md`'s own "Tamper-evident audit" and "Risk and evaluation dashboard" lines) because the dashboard's only useful input is the audit chain's own normalized record shape.

- The **audit side** answers: *are these supplied records internally consistent, and does the head match an independently supplied expected digest when one is provided?*
- The **dashboard side** answers: *what does this supplied audit-record batch contain?*

## 2. Genuine gap addressed

Prior blocks had mutable Supabase timestamps (`created_at`/`updated_at` on ordinary tables) and Block 10's own SHA-256 content correlation over a single Decision Binding — but nothing chained multiple records together, nothing verified a chain's internal consistency, and nothing aggregated counts across a batch of results. Block 14 closes exactly that gap, and only that gap.

## 3. Honest meaning of tamper-evident

The strongest claim this project can honestly make:

> ThreatTrace can detect content/link/order inconsistencies inside a supplied audit chain, and can compare its head against a caller-supplied expected head digest.

This explicitly does **not** provide: digital signatures; authenticated logging; trusted timestamps (`occurred_at` is caller-supplied, never independently attested); tamper *prevention*; immutable storage (nothing is persisted); non-repudiation; writer identity; replay protection; or proof that a supplied chain is the true historical chain.

## 4. Trust-anchor limitation

A complete alternate chain can be constructed from a fresh genesis record and will still verify internally — `internal_chain_valid` means only that the *supplied* sequence is self-consistent, never that it is the one true history. Without an independently retained expected head digest, internal verification cannot distinguish the real historical chain from a newly constructed, self-consistent alternate one.

`trusted_anchor_verified` is a genuine tri-state:

- **`null`** — no `expected_head_digest` was supplied.
- **`true`** — an anchor was supplied, the chain is internally valid, and its head equals that anchor.
- **`false`** — an anchor was supplied but the chain is invalid, empty, or its head differs.

**Matching an anchor does not prove the anchor itself is trustworthy** — this module has no way to know where the caller's own expected digest came from.

## 5. Architecture

```
Existing Block artifact (investigation decision, approval decision,
shadow-execution result, security-policy decision, Decision Binding
result, security-evaluation result, or analyst feedback)
        |
        v
   event_reference + narrow event_summary
        |
        v
   create_audit_record
        |
        v
   SHA-256-linked audit record
        |
        v
   verify_audit_chain
        |
        v
   internal consistency / optional head comparison
        |
        v
   summarize_audit_dashboard
        |
        v
   deterministic supplied-record metrics
```

## 6. Implemented files

| File | Role |
|---|---|
| `core/tamper_evident_audit.py` | Pure audit-chain engine — `create_audit_record`, `verify_audit_chain` |
| `tests/test_tamper_evident_audit.py` | Audit core tests (58 tests) |
| `core/evaluation_dashboard.py` | Pure dashboard summary — `summarize_audit_dashboard` |
| `tests/test_evaluation_dashboard.py` | Dashboard core tests (44 tests) |
| `core/audit_dashboard_cli.py` | Stdin/stdout JSON adapter around all three functions |
| `tests/test_audit_dashboard_cli.py` | CLI adapter tests (47 tests) |
| `.claude/commands/audit-dashboard.md` | Claude Code command wrapping the CLI |
| `docs/block14-tamper-evident-audit-dashboard.md` | This document |

No other file exists for this block.

## 7. Audit event types

Exactly seven: `investigation_decision`, `approval_decision`, `shadow_execution_result`, `security_policy_decision`, `decision_binding_result`, `security_evaluation_result`, `analyst_feedback`.

`approval_decision` records that an existing Block 4–6 approval decision already happened — it never performs, approves, or rejects anything itself; recording an external fact is categorically different from re-implementing the decision-making Block 6 already owns.

## 8. Audit record contract

Exactly ten fields: `audit_version`, `sequence`, `event_type`, `event_reference`, `event_summary`, `occurred_at`, `previous_record_digest`, `audit_persisted`, `execution_performed`, `record_digest`.

## 9. Sequence semantics

`sequence` is required. A genesis record (`previous_record_digest: null`) must have `sequence == 1`; every later record must have `sequence >= 2`. `create_audit_record` cannot prove a supplied `previous_record_digest` genuinely belongs to `sequence - 1` — that cross-record continuity check is exclusively `verify_audit_chain`'s concern, which enforces exact continuity (`current.sequence == previous.sequence + 1`) across a supplied chain.

## 10. Event reference

`event_reference` is a required, non-blank, opaque string — never assumed to be a UUID, never verified against Supabase or any other live persistence.

## 11. Event summary

Optional. When present, must be a **flat** mapping containing only the keys `outcome`, `case_type`, `error_category`, each a non-blank string — no nested mapping, list, number, or boolean value, and no other key. This is deliberately narrow and dashboard-friendly. The constructor never verifies that a supplied `event_summary` is substantively correct for the referenced event — only its structural shape.

## 12. occurred_at

Required, caller-supplied, validated as an aware `datetime` or aware ISO-8601 string, normalized to UTC `...Z` form. `core.tamper_evident_audit` never reads the system clock. This is not trusted timestamping — the value is exactly what the caller supplied, with no independent attestation of when it actually occurred.

## 13. Previous record digest

`null` for a genesis record; otherwise a string of the form `sha256:` followed by exactly 64 lowercase hexadecimal characters. No other digest algorithm is accepted.

## 14. Canonical hashing

`record_digest` is `"sha256:" + SHA256(canonical JSON bytes)`, computed over the other nine record fields (never over itself). Canonicalization uses `sort_keys=True`, compact separators, full UTF-8 encoding (`ensure_ascii=False`), and rejects non-string mapping keys and unsupported types; no explicit float/NaN/Infinity handling is needed since no legitimate record field ever holds a float. This is a **private, local copy** of the same algorithm Block 10 uses — Block 10's own canonicalization helpers are private (`_canonicalize`/`_canonical_json_digest`) and were deliberately not imported, matching this project's established convention that each module owns its own copy of this exact validation shape rather than sharing one. SHA-256 here means deterministic content correlation only — it is never described as signing.

## 15. Verification API

`verify_audit_chain(*, records, expected_head_digest=None)` checks: exact record structure; genesis semantics (first record's `sequence == 1` and `previous_record_digest is None`); sequence continuity; previous-digest linkage; digest recomputation for every record; and, when supplied, comparison against the expected head digest.

## 16. Verification contract

Exactly eight fields: `verification_version`, `verification_outcome` (`"valid"` / `"invalid"`), `internal_chain_valid`, `trusted_anchor_verified`, `record_count`, `head_digest`, `observed_evidence`, `execution_performed`.

## 17. Evidence codes

Exactly six: `INVALID_RECORD_STRUCTURE`, `GENESIS_LINK_INVALID`, `SEQUENCE_MISMATCH`, `PREVIOUS_DIGEST_MISMATCH`, `DIGEST_MISMATCH`, `TRUSTED_ANCHOR_MISMATCH`.

**Evidence codes are deduplicated by failure class within one verification call — they are not emitted once per affected record.** If three separate records in a supplied chain each have a stale digest, `DIGEST_MISMATCH` still appears exactly once in `observed_evidence`, matching the established `matched_rules`-style convention already used by Blocks 8–10 (a fixed, closed vocabulary, each code emitted at most once per call, in a fixed order) rather than producing an unbounded, per-occurrence evidence list. This is intentional, not a limitation of the implementation.

## 18. Independent linkage testing

To isolate `PREVIOUS_DIGEST_MISMATCH` from `DIGEST_MISMATCH` in tests, the test suite alters a record's `previous_record_digest` field *and then recomputes that record's own `record_digest`* from its new content — so the digest recomputation check passes cleanly and only the linkage check fails. Testing a stale digest after altering unrelated content (without recomputing) instead exercises `DIGEST_MISMATCH`, since the record's own stored digest no longer matches its own content. Both failure modes are tested independently this way.

## 19. Persistence

`audit_persisted` is always `false`. No file or database persistence exists anywhere in this MVP. As established during the Block 14 architecture audit: a mutable database table alone would not solve either the trust-anchoring problem (§4) or provide genuine immutability — Block 6's own `approvals` table already demonstrates this in this same repository, being a plain `UPDATE`-able row with no digest chain over its own history.

## 20. Dashboard meaning

`summarize_audit_dashboard(*, records, expected_head_digest=None)` is a **deterministic reporting API** — not a web UI, not a live dashboard, not real-time telemetry, not a SIEM feed.

## 21. Dashboard input boundary

Audit records only. Raw Block 11–13 outputs are not accepted directly — they must first be normalized into audit records via `create_audit_record`. This keeps the dashboard's input contract single-shaped rather than forcing dual-path validation logic.

## 22. Dashboard result contract

Exactly seven top-level fields: `dashboard_version`; `audit` (`total_records`, `verification_outcome`, `internal_chain_valid`, `trusted_anchor_verified`, `head_digest`, `observed_evidence`); `event_type_counts`; `evaluation_counts` (`outcome_counts`, `case_type_counts`); `feedback_counts` (`decision_counts`, `error_category_counts`); `policy_counts` (`decision_counts`); `execution_performed`.

## 23. Evaluation counts

Exactly `pass`, `fail`, `not_applicable`. An unrecognized supplied `security_evaluation_result` outcome raises `EvaluationDashboardError`. `case_type` is counted only when supplied — never invented. The dashboard never runs `evaluate_ai_security_case` itself.

## 24. Analyst feedback counts

Exactly `agree`, `disagree`, `insufficient_evidence`. `error_category` is counted only when supplied. The dashboard never decides whether analyst feedback was correct.

## 25. Policy counts

Exactly `allow`, `require_approval`, `deny`. The dashboard never runs Block 8, Block 9, the Emergency Mutation Freeze, or Block 10.

## 26. Invalid-chain dashboard behavior

A structurally usable but internally invalid chain can still be summarized — aggregation proceeds from whatever is visibly present in the supplied records, while `audit.verification_outcome`/`audit.internal_chain_valid`/`audit.observed_evidence` make the broken state explicit. These counts are never described as verified historical truth — only as values derived from the supplied records. A record too malformed to safely determine its `event_type`/`event_summary` raises `EvaluationDashboardError` rather than being silently skipped or guessed at.

## 27. Security honesty

Block 14 does not provide: digital signatures; authenticated provenance; immutable audit storage; trusted timestamps; authenticated users/writers; historical truth; attack prevention; replay prevention; automatic policy changes; or automatic learning/remediation. `audit_persisted` and `execution_performed` are always `false` in every result this block can ever produce. No `signature_verified` field exists anywhere — including it, even fixed to `false`, would risk implying signature verification is a roadmap-adjacent capability of this module, so it is addressed only in this prose as an explicit non-goal.

## 28. CLI

`core/audit_dashboard_cli.py`, invoked as:

```
py -m core.audit_dashboard_cli
```

Three operations via a top-level `"operation"` field: `create`, `verify`, `dashboard`. JSON via stdin only; deterministic sorted JSON via stdout only; no `argparse`, no filesystem/network/database/Supabase/MCP access, no system-clock read. Exit `0` for every successfully handled outcome — including `verification_outcome: "invalid"` and a dashboard built over an internally invalid chain — exit `2` for envelope/input validation failures (including the core's own typed `AuditRecordError`/`EvaluationDashboardError`), exit `1` for unexpected internal failures.

## 29. Claude command

`/audit-dashboard` is a thin, user-facing wrapper around `core.audit_dashboard_cli` — it accepts the exact same envelope the CLI itself requires for each operation, validates only that outer envelope shape, and sends it through stdin unchanged. It adds no security semantics of its own, and explicitly presents `"invalid"` as a normal, successful finding rather than a command failure.

## 30. Tests

As validated at the close of this checkpoint:

- **`tests/test_tamper_evident_audit.py` — 58 tests**
- **`tests/test_evaluation_dashboard.py` — 44 tests**
- **`tests/test_audit_dashboard_cli.py` — 47 tests**
- **Combined Block 14 (audit core + dashboard core + CLI) — 149 tests**
- **Bounded regression** (`tests/test_decision_binding.py` + `tests/test_ai_asset_registry.py` + `tests/test_analyst_feedback.py` + `tests/test_analyst_feedback_cli.py` + `tests/test_tamper_evident_audit.py` + `tests/test_evaluation_dashboard.py` + `tests/test_audit_dashboard_cli.py`) — **348 tests passed**.

These counts reflect the repository as validated at the close of this checkpoint; they are not projected or assumed.

## 31. Future possibilities

Listed strictly as **future possibilities, not implemented, not currently planned or approved**:

- append-only persistence;
- external trusted-head storage;
- digital signatures;
- key management;
- trusted timestamping;
- persistent dashboard history;
- trend analysis over time;
- a visual frontend;
- SIEM export;
- alerting on an invalid chain.

None of the above is implemented, and this document does not describe any partial implementation of them.
