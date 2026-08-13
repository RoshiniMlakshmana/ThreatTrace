# Block 15B — Context-Aware Finding Prioritization

**Block 15B is complete.** It is a pure, deterministic, local, stateless layer that computes an explainable operational-priority recommendation for an already-existing technical finding, using caller-supplied organization context. It never changes the finding's own technical truth.

## 1. Purpose

Block 15B answers exactly one question: *given an already-existing technical finding and this organization's own caller-supplied context, how urgently should THIS organization investigate/respond to it?* It separates **technical truth** from **organizational priority** — the same technically validated finding may be high priority for an internet-facing financial payment service and low/medium priority for an isolated marketing demo environment. The vulnerability itself remains the same; context changes priority, not truth.

## 2. Technical truth vs. operational priority

Block 15B never rewrites `finding_status`, `vulnerability_class`, `technical_severity`, `evidence`, `owasp_category`, `cwe`, `validation`, `remediation`, or `detection_opportunity`. It only ever *echoes* `finding_id`/`technical_severity`/`finding_status`/`confidence` in its own result. `operational_priority` is a separate, new judgment about urgency of attention, layered on top of an unchanged technical truth.

## 3. Input finding model

`prioritize_finding` accepts a real Block 15A finding-shaped mapping, read-only. It never imports `core.bug_bounty_findings` — it owns a minimal, locally-owned structural contract requiring: `finding_version == "1"`; a non-blank `finding_id`; a recognized `finding_status`/`technical_severity`/`confidence`; and the mere *presence* (never the content) of `vulnerability_class`, `evidence`, `validation`, `owasp_category`, `cwe`. No other finding field (`target`, `affected_path`, `title`, `reproduction_summary`, `remediation`, `detection_opportunity`) is ever inspected.

## 4. Organization context contract

Exactly 10 fields, no more, no fewer:

```json
{
  "context_version": "1",
  "industry": "...",
  "environment": "...",
  "asset_criticality": "...",
  "exposure": "...",
  "data_sensitivity": "...",
  "detection_coverage": "...",
  "compensating_controls": "...",
  "threat_activity": "...",
  "regulatory_relevance": "..."
}
```

Values are never trimmed, lowercased, or otherwise normalized before comparison.

## 5. Closed vocabularies

| Field | Values |
|---|---|
| `industry` | `financial_services`, `healthcare`, `technology`, `retail`, `government`, `education`, `general`, `other` |
| `environment` | `production`, `staging`, `development`, `test`, `sandbox` |
| `asset_criticality` | `low`, `medium`, `high`, `critical` |
| `exposure` | `internal`, `restricted`, `partner`, `internet_facing` |
| `data_sensitivity` | `public`, `internal`, `confidential`, `restricted` |
| `detection_coverage` | `none`, `partial`, `strong`, `unknown` |
| `compensating_controls` | `none`, `partial`, `strong`, `unknown` |
| `threat_activity` | `unknown`, `none_observed`, `emerging`, `active` |
| `regulatory_relevance` | `none`, `potential`, `direct`, `unknown` |

## 6. Industry is descriptive-only

`industry` contributes exactly `0` to the score, structurally, for every one of its 8 values — `financial_services` never scores differently from `general` given otherwise identical context. This is enforced in code (no scoring branch ever reads it), not merely documented, to prevent industry stereotyping. It is preserved in the output only for traceability, later research, and future policy evolution.

## 7. Technical-severity base bands

`technical_severity` maps to a fixed ordinal `base`: `low=1`, `medium=2`, `high=3`, `critical=4`. This is the priority anchor — an ordinal prioritization band, never a probability model, never CVSS.

## 8. Nominal context/status/confidence modifiers

| Trigger | Modifier | Reason code |
|---|---:|---|
| `environment: production` | +1 | `PRODUCTION_ENVIRONMENT` |
| `environment: development/test/sandbox` | -1 | `ISOLATED_ENVIRONMENT` |
| `asset_criticality: critical` | +1 | `CRITICAL_ASSET` |
| `asset_criticality: low` | -1 | `LOW_CRITICALITY_ASSET` |
| `exposure: internet_facing` | +1 | `INTERNET_EXPOSED` |
| `data_sensitivity: confidential/restricted` | +1 | `SENSITIVE_DATA` |
| `detection_coverage: none` | +1 | `NO_DETECTION_COVERAGE` |
| `compensating_controls: strong` | -1 | `STRONG_COMPENSATING_CONTROLS` |
| `threat_activity: active` | +1 | `ACTIVE_THREAT_ACTIVITY` |
| `regulatory_relevance: direct` | +1 | `DIRECT_REGULATORY_RELEVANCE` |
| `finding_status: validated` | 0 | `VALIDATED_FINDING` |
| `finding_status: candidate` | -1 | `CANDIDATE_FINDING` |
| `finding_status: observation` | -2 | `OBSERVATION_FINDING` |
| `confidence: low` | -1 | `LOW_CONFIDENCE` |

`environment: staging`, `asset_criticality: medium/high`, `exposure: internal/restricted/partner`, `data_sensitivity: public/internal`, `detection_coverage: partial/strong/unknown`, `compensating_controls: none/partial/unknown`, `threat_activity: emerging/none_observed/unknown`, `regulatory_relevance: none/potential/unknown`, and `confidence: medium/high` are all neutral (contribute `0`, no code emitted). `strong` detection coverage never lowers priority — it is caller-claimed coverage, not Red-Team-validated.

## 9. `raw_modifier`

The unclamped sum of every triggered modifier above (industry always excluded, structurally).

## 10. `applied_modifier` clamp `[-1, +2]`

`applied_modifier = clamp(raw_modifier, -1, +2)`. This is the key safety property: no combination of favorable context can lower a finding by more than one band; no combination of unfavorable context (or a low finding-status) can raise a finding by more than two bands.

## 11. Final-score clamp `[1, 4]`

`final = clamp(base + applied_modifier, 1, 4)`. Consequence: a `critical`-severity finding can never fall below `high`, regardless of context. A `low`-severity finding can never rise above `high`, regardless of context.

## 12. Operational-priority mapping

`1 → low`, `2 → medium`, `3 → high`, `4 → critical`.

## 13. Priority direction

`raised` if `final > base`, `lowered` if `final < base`, `unchanged` if equal — always computed relative to the finding's own `technical_severity` band, never to any other baseline.

## 14. Priority reason codes

Exactly 15, fixed order, each `{code, modifier, message}`, deduplicated, emitted only when triggered:

`VALIDATED_FINDING`, `CANDIDATE_FINDING`, `OBSERVATION_FINDING`, `LOW_CONFIDENCE`, `PRODUCTION_ENVIRONMENT`, `ISOLATED_ENVIRONMENT`, `CRITICAL_ASSET`, `LOW_CRITICALITY_ASSET`, `INTERNET_EXPOSED`, `SENSITIVE_DATA`, `NO_DETECTION_COVERAGE`, `STRONG_COMPENSATING_CONTROLS`, `ACTIVE_THREAT_ACTIVITY`, `DIRECT_REGULATORY_RELEVANCE`, `CONTEXT_INCOMPLETE`.

## 15. Context completeness

`incomplete` iff any of `detection_coverage`/`compensating_controls`/`threat_activity`/`regulatory_relevance` is `"unknown"`. Unknown contributes `0` — never favorable, never unfavorable — and adds `CONTEXT_INCOMPLETE` (modifier `0`) exactly once, regardless of how many fields are unknown.

## 16. Candidate vs. validated semantics

Finding status affects urgency, never truth. `finding_status` is echoed unchanged in every result. `candidate`/`observation` apply a bounded negative modifier reflecting that unconfirmed findings generally deserve somewhat less urgency — but Block 15B deliberately imposes **no hard ceiling** preventing a `candidate` finding from reaching `operational_priority: "critical"`.

## 17. Candidate + critical operational priority — worked example

`technical_severity: medium` (base=2), `finding_status: candidate` (-1), on a `production`/`critical`-asset/`internet_facing`/`restricted`-data/`no-detection`/`active-threat`/`direct-regulatory` context (+1 each, seven triggers): `raw_modifier = -1+1+1+1+1+1+1 = 5`; `applied_modifier = clamp(5, -1, 2) = 2`; `final = clamp(2+2, 1, 4) = 4` → `operational_priority: "critical"`, while `finding_status` remains exactly `"candidate"`. This means **"critical priority to investigate,"** never **"critical confirmed vulnerability."**

## 18. Detection coverage semantics

`detection_coverage` is caller-claimed context only — `"strong"` means the caller asserts coverage exists, not that it has been Red-Team-validated to actually fire. `"unknown"` never behaves like `"strong"`.

## 19. Compensating-controls semantics

`compensating_controls` is caller-claimed context only — `"strong"` is never independently verified by Block 15B; no control-efficacy validation exists anywhere in this project.

## 20. Threat-activity semantics

`threat_activity` is caller-supplied context, never a live threat-intelligence lookup — Block 15B never fetches it. `"none_observed"` means *not observed*, never *does not exist*, and therefore never lowers priority.

## 21. Regulatory relevance semantics

`regulatory_relevance` is a coarse, caller-supplied relevance flag, never a compliance/legal determination. `"direct"` raises priority; it never implies a specific regulatory regime (PCI/HIPAA/GDPR/SOX) was actually assessed.

## 22. Human review boundary

`human_review_required` is always `true`; `execution_performed` is always `false`. Block 15B never closes a finding, approves remediation, deploys a control, overrides an analyst, mutates the input finding, or triggers a Blue/Purple/Red action.

## 23. CLI contract

`core/context_prioritization_cli.py`, invoked as `py -m core.context_prioritization_cli`. Exactly one operation, `"prioritize"`, via a three-key JSON envelope: `operation`, `finding`, `context`. Both values are passed through unchanged to `prioritize_finding`. Exit codes: **0** — any valid result, including a `candidate` finding with `operational_priority: "critical"`; **2** — envelope/input errors or a `ContextPrioritizationError` (stderr `CONTEXT_PRIORITIZATION_VALIDATION_FAILED`); **1** — unexpected internal failure (stderr `CONTEXT_PRIORITIZATION_INTERNAL_FAILURE`).

## 24. `/prioritize-finding` behavior

One invocation = one prioritization. The command passes the caller's complete JSON envelope through unchanged to the CLI — it never synthesizes `context`, never infers organization context from a target URL/hostname/application name/webpage evidence/vulnerability title/industry guess, and explicitly distinguishes `technical_severity` from `operational_priority` in its rendered explanation (e.g. *"the technical finding remains medium severity; this organization's context makes it critical-priority for investigation/response"* — never *"the vulnerability became critical"*). A `candidate` finding with `operational_priority: "critical"` is rendered as *critical investigation priority for a candidate finding*, never as a confirmed vulnerability.

## 25. AI Asset Registry

One new asset: `claude_command:prioritize-finding`, `provenance.tier: "repository_declared"` — same convention as every other entry, no verified/authenticated/runtime-discovery/signature claim. No new `gateway_tool`, `identity_agent`, or `claude_subagent` was added — Block 15B is a pure local service, not a governed agent tool and not a new security persona. Current registry totals: `gateway_tool` 8, `identity_agent` 6, `claude_subagent` 3, `claude_command` **26**, `claude_skill` 1, `mcp_server` 2 — **total 46** (45 before this checkpoint). A direct comparison of actual `.claude/commands/*.md` files against registered `claude_command` assets confirmed exact 1:1 coverage (26/26), with no other discrepancy found.

## 26. Security-honesty boundaries

Organization context is caller-supplied in v1 and never authenticated. It may be incomplete or stale. Block 15B never infers it from the assessed target, never fetches threat intelligence, never validates claimed detection coverage or compensating controls, and never makes a compliance determination. `operational_priority` is a deterministic investigation/response prioritization recommendation only — never vulnerability truth, CVSS, an AI/ML risk score, a probability of compromise, a business-loss prediction, or an analyst approval. `human_review_required` is always `true`; `execution_performed` is always `false`.

## 27. Research value

Every result preserves both `priority_score.base` (technical-severity-only) and `priority_score.final` (technical severity + organization context) for the same finding, without needing to re-run anything — enabling a later Block 15E ablation comparing severity-only prioritization against context-aware prioritization. Potential future metrics: expert-priority agreement, top-k critical-finding precision, ranking correlation, unnecessary-escalation reduction, missed high-context-risk findings, and time-to-triage. No experimental improvement is claimed yet — no research harness has been built.

## 28. Testing

Actual counts as validated at the close of this checkpoint:

- `tests/test_context_prioritization.py` (Checkpoint A core) — **222 passed**
- `tests/test_context_prioritization_cli.py` (Checkpoint B CLI) — **64 passed**
- Combined Block 15B (core + CLI) — **286 passed**
- AI Asset Registry (`test_ai_asset_registry` + `test_ai_asset_registry_cli`) — **112 passed**
- Bounded regression (Block 8/9, AI Asset Registry, analyst feedback, audit, dashboard, integration demo, all Block 15A, all Block 15B) — **1253 passed**

## 29. Limitations

Caller-supplied context is unauthenticated. Context may be stale or incomplete. There is no automatic asset discovery. Block 15B performs no threat-intelligence lookup. Claimed detection coverage is not Red-Team-validated. Claimed compensating controls are not independently verified. Regulatory relevance is not a legal/compliance determination. No analyst-feedback learning occurs (Block 13 remains untouched). No ML/LLM scoring of any kind is used. No production action occurs. No new audit event type has been added yet (Block 14's closed `EVENT_TYPES` vocabulary remains untouched). No Block 15C handoff occurs yet.

## 30. Future Block 15C integration

Deliberately deferred, not implemented here: extending `core.analyst_feedback.TARGET_TYPES` so an analyst can record agreement/disagreement with a Block 15B prioritization result; adding a `context_prioritization_result` (or similarly named) event type to Block 14's audit vocabulary; and any handoff wiring a prioritization result into the existing database-backed approval workflow (`/request-case-update` → `/review-approval` → `/apply-case-update`) or the Blue/Purple/Red loop. Each of these touches a completed, closed vocabulary in an already-tested block and deserves its own deliberate design pass, not a side effect of Block 15B.
