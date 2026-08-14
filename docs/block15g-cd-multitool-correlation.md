# Block 15G-CD — Bounded DAST + Evidence Normalization + Correlation + Final Bug Bounty Report

Status: implemented and validated, including a real end-to-end live run against the local
Juice Shop container using real Nmap, Nuclei, and ZAP execution through `execute_bug_bounty_tool`.
Burp Suite is implemented as a deterministic adapter boundary but has no compatible local
runtime in this environment — reported honestly as `configured_external_runtime_required`.

## 1. Architecture

```
Analyst
   |
LLM Bug Bounty Planner            (.claude/agents/bug-bounty-planner.md, unchanged)
   |
Tool Permission Policy            (core.bug_bounty_tool_policy)
   |
Security Governor boundary        (core.security_governor -- bug_bounty_assessment stage, Block 15G-B.2)
   |
Tool Adapter (core.bug_bounty_tool_execution)
   |-- HTTP Assessor        (existing, untouched, own orchestration path)
   |-- Nmap / Nuclei        (Block 15G-B)
   |-- ZAP           <- NEW (adapters.bug_bounty_zap, passive-only)
   +-- Burp DAST      <- NEW (adapters.bug_bounty_burp, boundary only -- no runtime here)
   |
Structured Tool Results (per-tool)
   |
Evidence Normalization             <- NEW (core.bug_bounty_evidence_normalization)
   |
Finding Correlation                <- NEW (core.bug_bounty_finding_correlation)
   |
Final Bug Bounty Report            <- NEW (core.bug_bounty_final_report)
   |
(compatible with) Context Prioritization -> Security Handoff  (existing, unmodified)
```

## 2. Tool boundaries

- **ZAP** (`adapters.bug_bounty_zap.run_zap_scan`): talks only to a local ZAP daemon REST API
  (`127.0.0.1:8080` by default), never to the scan target directly. Forces `"safe"` mode via
  ZAP's own API before doing anything else, and refuses to proceed if that isn't confirmed.
  Visits exactly one analyst-approved URL (`accessUrl`) and reads back passive-scan alerts.
  `capability` is always `"passive_only"` — active scanning is never enabled, since this
  checkpoint cannot deterministically prove a safe active-rule allowlist.
- **Burp** (`adapters.bug_bounty_burp`): `run_burp_scan` checks for a runtime configured via
  environment variable only (`THREATTRACE_BURP_API_KEY`, never a request parameter); with none
  configured it reports `runtime_status: "configured_external_runtime_required"` without ever
  attempting a network call. `import_burp_result` is a separate, pure, I/O-free normalizer for
  an already-produced external Burp report, always available regardless of runtime.
- Both adapters share the same `dast_observation` per-observation contract (`rule_id`, `title`,
  `risk`, `confidence`, `url`, `path`, `parameter`, `method`, `cwe`, `owasp_category`,
  `evidence_reference`, `sanitized_evidence`, `source_tool_metadata`).

## 3. A real Docker networking issue found and fixed during live validation

The ZAP daemon runs in its own container; `localhost`/`127.0.0.1` inside that container refers
to the container itself, not the host-published Juice Shop container. `adapters.bug_bounty_zap`
rewrites only the URL string sent to the ZAP daemon (`localhost` → `host.docker.internal`), and
reverses that substitution on every URL ZAP reports back, before any of it reaches this
adapter's own result — every field this adapter ever returns reflects the original,
analyst-approved host, never the internal Docker routing name. This is a pure routing detail,
never a scope change.

## 4. A real spider-mode issue found and fixed during live validation

ZAP's own `"safe"` mode refuses spider operations against a URL with no established
Context/scope (`mode_violation: "Operation not allowed for current mode"`) — discovered against
the real local daemon. Rather than build Context/scope management to work around it, this
checkpoint honors it: the adapter performs no spider/crawl step at all, single-URL passive-only
only. `MAX_SPIDER_URLS`/`MAX_SPIDER_DEPTH` remain declared as reserved bounds for a future
checkpoint.

## 5. Tool policy / execution registry changes

`zap.implemented` and `burp_dast.implemented` both flipped `False → True` in
`core.bug_bounty_tool_policy.TOOL_CATALOG` (a real adapter boundary exists for both — for
`burp_dast`, independent of whether any environment happens to have a runtime configured).
`core.bug_bounty_tool_execution._ADAPTER_REGISTRY` extended to four entries: `nmap`, `nuclei`,
`zap`, `burp_dast`. `authenticated_testing`/`controlled_validation` remain `False`. The
execution flow is unchanged: `evaluate_tool_permission` → supplied real Governor result →
closed adapter registry — never a caller-supplied binary name, never a synthesized Governor
approval.

## 6. Evidence normalization contract

`core.bug_bounty_evidence_normalization.normalize_bug_bounty_evidence` converts each tool's own
result shape (`http_assessor`'s finding list; `nmap`/`nuclei`/`zap`/`burp_dast`'s own
`observations` list) into one common 30-field evidence record (`EVIDENCE_REQUIRED_FIELDS`):
`evidence_id`, `source_tool`, `source_observation_id`, `observation_type`, `host`, `port`,
`scheme`, `url`, `path`, `parameter`, `method`, `title`, `description`, `vulnerability_class`,
`cwe`, `owasp_category`, `cve`, `technical_severity`, `confidence`, `service`, `product`,
`version`, `validation_state`, `sanitized_evidence`, `evidence_digest`, `source_reference`,
`scope_reference`, `first_observed`, `last_observed`, `execution_performed`. No field is ever
invented to complete the schema — a tool with no concept of e.g. `confidence` (Nmap) always
leaves it `None`.

`evidence_id` (`"EV-"` + 16 hex) and `evidence_digest` (`"sha256:"` + 64 hex) are both derived
from the exact same full-content digest — see §8 below for why that matters.

## 7. Correlation rules

`core.bug_bounty_finding_correlation.correlate_bug_bounty_evidence` groups records by a
deterministic fingerprint (`host`, `port`, normalized `path`, `parameter`, and a `category`
derived with priority `cwe` > `vulnerability_class` > `observation_type`) — **never** by title
text. A shared CVE forces grouping independent of the fingerprint. An optional, constrained
`semantic_hints` list (already-produced `same_finding`/`different_finding`/`uncertain`
verdicts, never generated by this module) may additionally merge a pair the fingerprint missed;
`uncertain` never merges, and is surfaced in `uncertain_correlations` for human review instead.
Confidence is only ever raised when ≥2 **distinct** `source_tool` values corroborate a group
(never for repeated observations from the same tool), by exactly one level, capped at `"high"`.
A group is `is_informational` only when every member lacks severity, vulnerability class, CWE,
and CVE.

## 8. A real evidence-identity bug found and fixed during live validation

The first live run revealed that `evidence_id` — deliberately derived from only
`source_tool`/`source_observation_id`/`url`/`title` — could legitimately collide for two
**distinct** observations from the same tool/rule/URL with different underlying evidence text.
A real live ZAP scan produced exactly this: two `"Timestamp Disclosure - Unix"` alerts at the
same URL with two different extracted timestamp values. Because
`core.bug_bounty_finding_correlation` originally indexed records internally by `evidence_id`,
the second colliding record was silently dropped before grouping. Fixed two ways: (1)
`evidence_id` is now derived from the *same* full-content digest as `evidence_digest`, so two
records can only ever collide if their content is genuinely identical; (2) independent of that
fix, `correlate_bug_bounty_evidence` no longer assumes `evidence_id` uniqueness at all — it
indexes internally by record position, so no caller-supplied collision (from this project's own
normalizer or any other) can ever silently drop a record again. Both the original real-world
scenario and the general defensive fix are covered by dedicated regression tests in
`tests/test_bug_bounty_evidence_normalization.py`/`tests/test_bug_bounty_finding_correlation.py`.

## 9. LLM role vs. deterministic role

The LLM (`bug-bounty-planner`, unchanged from Block 15G-A) proposes tool_requests only, and may
optionally supply pre-computed `semantic_hints` for correlation — it never calls
`normalize_bug_bounty_evidence`/`correlate_bug_bounty_evidence`/`build_final_bug_bounty_report`
itself, and a `same_finding` hint can only ever *add* a merge the deterministic fingerprint/CVE
logic missed, never split one it already established. Every actual field mapping, digesting,
grouping, aggregation, and report field is 100% deterministic Python with zero LLM involvement.

## 10. Canonical finding contract

31 fields per `core.bug_bounty_final_report._build_canonical_finding`: `finding_id`, `title`,
`vulnerability_class`, `cwe`, `owasp_category`, `cve`, `host`, `port`, `url`, `path`,
`parameter`, `method`, `technical_severity`, `confidence`, `validation_state`,
`evidence_sources`, `tool_observations`, `sanitized_proof`, `potential_impact`, `prerequisites`,
`exposure`, `remediation`, `mitre_attack_mapping`, `references`, `tools_used`, `scope`,
`governor_reference`, `evidence_digests`, `human_validation_required`, `limitations`, `status`.
`status` is always `"requires_human_review"` in this checkpoint — a deliberate simplification,
never an autonomous `"validated"`/`"confirmed"` claim. `potential_impact`/`prerequisites`/
`exposure`/`remediation`/`mitre_attack_mapping`/`references` are always `None`/`[]`: no source
tool contract carries this data, and this module never synthesizes prose or a mapping to fill
the gap.

## 11. Final report schema

`report_id`, `report_version`, `target`, `scope`, `testing_profile`, `assessment_started_at`,
`assessment_completed_at`, `tools_requested`, `tools_permitted`, `tools_executed`,
`tools_unavailable`, `executive_summary`, `canonical_findings`, `informational_observations`,
`duplicate_evidence_count`, `correlation_summary`, `human_review_items`, `limitations`,
`unsupported_test_categories`, `safety_summary`, `governor_summary`, `evidence_integrity_summary`,
`execution_performed` (always `False`).

## 12. Limitations (always present, never omitted)

- Canonical findings are correlated tool evidence, not exploit-confirmed vulnerabilities.
- No active exploitation, authenticated testing, or controlled validation is attempted.
- ZAP execution uses a passive-only capability profile — active scanning is never enabled.
- Burp Suite execution requires an externally-configured runtime this environment lacks.
- `unsupported_test_categories` is always populated: `authenticated_testing`,
  `controlled_validation`, `active_exploitation`, `active_dast_scanning`, `credential_attacks`,
  `denial_of_service`.

## 13. Live Juice Shop evidence (real, unmocked, this checkpoint's own validation run)

Target: `http://localhost:3000/`, container `threattrace-juice-shop`
(`127.0.0.1:3000`). ZAP runtime: official `zaproxy/zap-stable` image, container
`threattrace-zap`, bound to `127.0.0.1:8080` only, `-config api.disablekey=true` (deviating
from the originally-previewed `api.disablekey=false` since a per-run random key blocks
non-interactive automation — noted for transparency), engine version `2.17.0`, mode `safe`.

- **HTTP assessor**: 3 findings — missing CSP header (medium), `/robots.txt` (low),
  `/.well-known/security.txt` (low).
- **Nmap**: 1 service observation — port 3000/tcp open, service `ppp` (Nmap's own
  `nmap-services` default name for that port; no `-sV` was run, so no product/version invented).
- **Nuclei**: 0 observations — a genuine "no template matched" result, not evidence of
  vulnerability-free status.
- **ZAP**: 5 observations — CSP header not set (medium), Cross-Domain Misconfiguration
  (medium), Modern Web Application (informational), Timestamp Disclosure - Unix ×2 (low, two
  distinct timestamp values at the same URL — see §8).
- **Burp**: `adapter_status: "implemented"`, `runtime_status:
  "configured_external_runtime_required"`, `status: "not_evaluated"`, `execution_performed: false`.

Normalization produced 9 evidence records. Correlation produced 7 groups, 0 exact duplicates:
5 canonical findings and 2 informational observations (the bare Nmap port and the ZAP
"Modern Web Application" info alert). One group — Missing CSP — genuinely merged two tools
(`http_assessor` + `zap`) into one canonical finding with `validation_state: "tool_confirmed"`
and two independent `evidence_sources`, exactly the cross-tool corroboration this checkpoint
exists to produce.

## 14. No public target scanned

Every real request in this checkpoint's validation targeted only `localhost:3000` (Juice Shop)
and `127.0.0.1:8080` (the local ZAP daemon's own API, never itself a scan target).
