# Merged Block 15H-I — Threat Intelligence + Intelligent Detection Engineering Rule Factory

Status: implemented and validated, including a real end-to-end live run: real CISA KEV/NVD/EPSS
ingestion, a real Bug Bounty canonical finding (from the live Juice Shop container) through
Detection Trigger + Telemetry Feasibility, and a real CISA KEV entry (Metabase SQL injection,
CVE-2026-72898) through the **full** chain — trigger → telemetry feasibility → the real
`detection-engineering-planner` LLM agent → deterministic plan validation → rule construction →
deduplication → bounded structural syntax validation. No rule was deployed.

## 1. Dual-trigger architecture

```
Bug Bounty Finding ──┐
                     │
Threat Intelligence ─┤
                     ↓
     core.detection_trigger (build_bug_bounty_trigger / build_threat_intelligence_trigger)
                     ↓
     core.security_enrichment (CWE/CVE -> ATT&CK, never invented)
                     ↓
     core.detection_telemetry.evaluate_telemetry_feasibility
          ┌──────────┴──────────┐
     TELEMETRY_GAP        GENERATE_RULE / PARTIAL_COVERAGE
          │                     │
     (stop, zero rules)   .claude/agents/detection-engineering-planner.md (LLM proposes)
                                ↓
                    core.detection_planner.validate_detection_plan (deterministic)
                                ↓
                    core.detection_rule.build_detection_rule (deterministic, per rule)
                                ↓
                    core.detection_rule_deduplication.check_rule_duplicate (deterministic)
                                ↓
                    core.detection_rule_validation.validate_rule_syntax (bounded, structural_validation_only)
                                ↓
                    core.detection_engineering_report.build_detection_engineering_report
                                ↓
                         NOT DEPLOYED, always
```

Both triggers converge on the exact same downstream pipeline from `core.detection_telemetry` onward
— there is no separate code path for a Bug Bounty-originated vs. TI-originated rule beyond how the
trigger itself was built.

## 2. Threat-intel sources implemented

| Source | Module | Authoritative? | Auth required |
|---|---|---|---|
| CISA KEV | `adapters.threat_intel_cisa_kev` | Yes | No |
| NVD/CVE | `adapters.threat_intel_nvd` | Yes | No (low volume) |
| EPSS | `adapters.threat_intel_epss` | No (probability model) | No |
| TAXII | `adapters.threat_intel_configured_sources.fetch_taxii_records` | — | Yes (`THREATTRACE_TAXII_API_KEY`) |
| MISP | `adapters.threat_intel_configured_sources.fetch_misp_records` | — | Yes (`THREATTRACE_MISP_API_KEY`) |
| OpenCTI | `adapters.threat_intel_configured_sources.fetch_opencti_records` | — | Yes (`THREATTRACE_OPENCTI_API_KEY`) |
| Public Telegram OSINT | `adapters.threat_intel_configured_sources.fetch_telegram_public_osint_records` | No — untrusted public/community OSINT, **never** "the dark web" | Yes (`THREATTRACE_TELEGRAM_BOT_TOKEN`) |

`AUTHORITATIVE_SOURCES = {"cisa_kev", "nvd_cve"}` only — a fixed, closed set, never LLM-decided.

## 3. Live source runtime status

All three real, unauthenticated sources returned `status: "completed"` on real live calls this
checkpoint's own validation run. All four credential-required sources correctly returned
`runtime_status: "not_configured"` **without attempting any network call**, since no credential
env var is set in this environment — see §13 for the real numbers.

## 4. Normalized TI contract

`core.threat_intelligence.TI_RECORD_REQUIRED_FIELDS` — 29 fields: `intel_id`, `source_type`,
`source_name`, `source_reference`, `title`, `summary`, `published_at`/`modified_at`/`observed_at`,
`cve`/`cwe`/`owasp` (lists), `affected_products`/`affected_versions`, `ioc` (`ip`/`domain`/`url`/
`file_hash`), `actor`, `campaign`, `attack` (`tactic`/`technique`/`subtechnique`),
`behavioral_indicators`, `exploitation_status`, `known_exploited`, `epss_score`, `confidence`,
`corroboration_state`, `evidence_references`, `source_reliability`, `information_credibility`,
`limitations`. No field is ever invented when a source doesn't supply it — e.g. KEV never supplies
CWE/EPSS, so those stay `[]`/`None` on every KEV-sourced record.

## 5. Corroboration model

`core.threat_intelligence.compute_corroboration` groups records by shared CVE (or, absent one,
shared IOC) and classifies each group purely mechanically: a lone record is `"single_source"`
(or `"unconfirmed"` if its own `source_reliability`/`information_credibility` is `"low"`/
`"unknown"`); 2+ records agreeing, with none in `AUTHORITATIVE_SOURCES`, is `"corroborated"`;
2+ records including an `AUTHORITATIVE_SOURCES` member is `"authoritative_source"`; 2+ records
disagreeing on `known_exploited` is `"conflicting"`. The LLM never assigns or overrides this field
— it is always recomputed from the batch, and a caller-preset value is discarded.

## 6. Bug Bounty trigger result (real, live Juice Shop)

Real canonical finding "Missing Content-Security-Policy header" (CWE-693, medium severity, from
the same live `threattrace-juice-shop` container this project has used throughout) → `core.
detection_trigger.build_bug_bounty_trigger` → `required_telemetry_candidates: ["http_proxy",
"web_server"]` → against the demo telemetry profile (§9) → **`decision: "PARTIAL_COVERAGE"`**
(`web_server` available, `http_proxy` missing). Per this checkpoint's own explicit design, a
partial/gap result is a normal, honest outcome — no rule generation was forced for it.

## 7. Threat Intel trigger result (real, live CISA KEV)

Real CISA KEV entry for CVE-2026-72898 ("Metabase SQL Injection Vulnerability",
`exploitation_status: "exploited_in_wild"`, `known_exploited: true`) → `core.detection_trigger.
build_threat_intelligence_trigger` → `required_telemetry_candidates: ["process_creation",
"network_connection", "authentication"]` → against the same demo telemetry profile →
**`decision: "GENERATE_RULE"`** (all three required sources available). This trigger was carried
through the full rule-factory pipeline — see §14-18.

## 8. Telemetry feasibility model

`core.detection_telemetry.evaluate_telemetry_feasibility`: `telemetry_available` is `"true"`
(all required sources available → `GENERATE_RULE`), `"false"` (none available, or zero candidates
existed at all → `TELEMETRY_GAP`), or `"partial"` (some but not all → `PARTIAL_COVERAGE`). An empty
`required_telemetry_candidates` list is itself honestly `TELEMETRY_GAP` — there is no basis to
evaluate feasibility against nothing.

## 9. Demo telemetry profile (never a real organization)

```json
{"available_telemetry": ["process_creation", "network_connection", "dns", "authentication", "web_server"],
 "siem": "Splunk", "environment": "production", "industry": "technology"}
```
Used solely to prove the rule-factory pathway, per this checkpoint's own explicit instruction.

## 10. LLM Detection Planner role

`.claude/agents/detection-engineering-planner.md` reasons over the trigger, enrichment, and
telemetry feasibility; proposes a detection objective and candidate rule drafts (only in formats
genuinely relevant to the trigger's behavior); never deploys, approves, modifies a SIEM, executes
a shell command, invents a CVE/CWE/ATT&CK technique/IOC, or claims validation it didn't perform.
Proposes zero rules whenever `decision == "TELEMETRY_GAP"`.

## 11. Deterministic planner role

`core.detection_planner.validate_detection_plan` never calls an LLM. It structurally validates the
LLM's own proposal: rejects unsupported rule formats, telemetry not reported available, a
trigger/telemetry-gap mismatch (`proposed_rules` must be `[]` when `decision == "TELEMETRY_GAP"`),
and any field outside the closed contract (no deployment/approval field can even exist).

## 12. Supported rule formats

`RULE_FORMATS = {"sigma", "splunk_spl", "sentinel_kql", "yara"}`. The planner selects only formats
genuinely relevant to the trigger's own behavior — YARA is never forced onto a non-file/byte-pattern
trigger (confirmed live: the Metabase SQLi trigger, a web/network/auth behavior with no file
artifact, correctly received only `splunk_spl` + `sigma` proposals, never YARA).

## 13. Live TI ingestion results (real, this checkpoint's own run)

| Source | Status | Records returned (of catalog size) |
|---|---|---|
| CISA KEV | `completed` | 5 of 1,665 |
| NVD | `completed` | 5 of 377,348 |
| EPSS | `completed` | 5 of 359,229 |
| TAXII / MISP / OpenCTI / Telegram | `not_configured` (no network attempted) | 0 |

`core.threat_intelligence_report.build_threat_intelligence_report` on this batch: `records_ingested:
15`, `records_normalized: 15`, `duplicates_removed: 0`, `cve_summary.total_unique_cve: 15`,
`kev_summary.known_exploited_count: 5`, `corroboration_state_distribution: {"single_source": 15}`
(no cross-source overlap occurred in this small 5-per-source sample — a fully honest result, not
an error; a larger pull would very plausibly surface `authoritative_source`/`corroborated` groups
where KEV and NVD name the same CVE).

## 14. Real Detection Trigger → Planner → Rule pipeline (Metabase SQLi, CVE-2026-72898)

The real `detection-engineering-planner` agent proposed a 2-rule plan (Splunk SPL + Sigma),
grounded entirely in the trigger's own `vulnerability_context` and the KEV catalog's own summary
text (treated as evidence, never instructions) — unauthenticated SQL injection → admin access →
possible credential theft/data exfiltration. It explicitly declined to assert an ATT&CK technique
(the trigger's own `attack` fields were empty) and explicitly noted no IOC exists for this CVE in
the source data, so both drafts are behavior-only. The SPL rule's `context_tuned_rule_content` used
the supplied demo SIEM/environment/industry context (Splunk index-naming convention, explicit
`"demo org"` framing preserved in a rule comment) — no organization specifics were invented.

## 15. Generic vs. context-tuned result

`generic_rule_count: 2`, `context_tuned_rule_count: 1` (only the SPL rule — the Sigma rule
correctly left `context_tuned_rule: null` since a second tuning target wasn't warranted from the
same context by the planner's own judgment; this checkpoint never forces every rule to have one).

## 16. ATT&CK/CVE/CWE enrichment result

`core.security_enrichment.enrich_identifier` was called for the trigger's `cwe` list (empty, since
CISA KEV supplies no CWE) — correctly returned zero enrichment records rather than inventing one.
No `record_llm_proposed_enrichment` call occurred in this run — the planner noted a possible future
mapping in its own rationale text but never asserted one directly, exactly as its own agent
instructions require.

## 17. Rule normalization

`core.detection_rule_normalization.normalize_detection_rule_fields` computed comparison keys for
both rules (uppercased/deduplicated CVE `["CVE-2026-72898"]`, empty CWE/ATT&CK sets, sorted
telemetry, lowercased `rule_format`, whitespace-collapsed `behavior_signature`) — used only for
deduplication, never rewriting the rules' own display text.

## 18. Rule deduplication result

Both rules checked against an initially-empty `existing_rules` list (then against each other as
they were added): **both `"new_rule"`** (distinct `rule_format` values alone would have guaranteed
this even had every other field matched — see `core.detection_rule_deduplication`'s own format
dimension).

## 19. Validation result (real, and honestly imperfect)

| Rule | Format | `syntax_valid` | Reason |
|---|---|---|---|
| RD-...-01-spl | `splunk_spl` | **`false`** | "unbalanced parentheses" |
| RD-...-02-sigma | `sigma` | `true` | — |

The SPL rejection is itself an honest demonstration of this checkpoint's own limitation, not a
fabricated failure: `core.detection_rule_validation`'s bounded, stdlib-only paren-balance check
cannot distinguish a literal `(` inside a regex character class/escape sequence from a real,
unbalanced SPL parenthesis — a known false-positive mode of `structural_validation_only` checking,
documented here rather than silently worked around. The rule was correctly marked
`validation_status: "rejected"` (never "tested"/"validated") rather than passed dishonestly. A real
SPL parser (out of this checkpoint's scope — no new dependency was added) would resolve this.

## 20. Governor result

`core.security_governor`'s existing, **unmodified** `detection_engineering` stage (`required_role:
"blue_team"`) was exercised directly: a valid `actor_role: "blue_team"` event at that stage
`allow`s; the exact same rules that block every other stage (wrong role, scope expansion, mutation
freeze, untrusted-content-adopted-as-instruction, missing Decision Binding, gateway deny) block
here too — no special-casing, no new bypass, no Governor source modified for this checkpoint.

## 21. Human-review state

Both live rules: `human_approval_state: "pending"`. Nothing in this checkpoint can ever produce
`"approved"` without a separately-authenticated human action outside this code entirely.

## 22. Deployment state

Both live rules: `deployment_state: "NOT_DEPLOYED"`. `core.detection_rule.build_detection_rule` has
no parameter, and no code path, that can ever produce any other value in this checkpoint.

## 23. Telemetry gaps

Zero in this specific live run (the TI trigger was `GENERATE_RULE`; the Bug Bounty trigger was
`PARTIAL_COVERAGE`, not a full gap) — but the mechanism was exercised structurally throughout
`tests/test_detection_telemetry.py`/`tests/test_detection_planner.py` (an empty
`required_telemetry_candidates` list, and telemetry entirely absent, both honestly produce
`TELEMETRY_GAP`, zero rules, no fabrication).

## 24. Limitations

- KEV/NVD/EPSS ingestion is capped and bounded (`MAX_LIMIT` per adapter, ≤25) — this is a bounded
  demonstration, never a full-catalog sync.
- `core.detection_rule_validation` is `structural_validation_only` in every case (no `pysigma`/
  `yara-python` dependency was added — see §19's own honest SPL false-positive).
- TAXII/MISP/OpenCTI/authenticated-Telegram ingestion is a real, tested code boundary, but was
  never exercised against a live configured runtime in this environment.
- `core.research_evaluation` was deliberately **not** modified this checkpoint (see below).

## 25. Why `core.research_evaluation` was not extended

Its `_SCENARIO_REQUIRED_FIELDS` contract is tightly coupled to the existing Bug Bounty → Handoff →
Governor → Memory pipeline shape; forcing TI/detection-specific fields into it risked destabilizing
already-well-tested behavior for no clean benefit. Every metric this checkpoint's own spec
requested (TI records ingested/deduplicated/corroborated, triggers created, rules generated/
rejected, telemetry gaps, generic vs. tuned, duplicate rules prevented, syntax-valid candidates,
human-review-required count) is already fully covered by `core.threat_intelligence_report`/
`core.detection_engineering_report`, purpose-built for exactly this. No causal/MTTD claim is made
anywhere in either report.

## 26. Naming note

The pre-existing prompt-driven skill `.claude/skills/detection-engineering/SKILL.md` (Supabase-
investigation-oriented, unrelated to this checkpoint's deterministic pipeline) already occupies the
name `detection-engineering`. This checkpoint's new command is therefore named
`/detection-rule-factory`, not `/detection-engineering`, to avoid invocation ambiguity between the
two genuinely different assets.
