# Block 17A — Final End-to-End Validation + Evidence Freeze

**This document is the source of truth for Block 17B presentation metrics.** Every number, ID, and quote below was produced by a real run recorded in this session — nothing is fabricated, estimated, or reused from an earlier checkpoint's narrative.

## 1. Commit Validated

`494cde16758b7ff5af918768a559732691e1d31a` — "feat: package reproducible ThreatTrace runtime" (Block 15L-16). Repository was clean at this commit for the entirety of this validation; **no code changes were required or made** during Block 17A.

## 2. Environment

- **OS**: Windows (platform reported by `runtime.tool_runtime`: `"Windows"`)
- **Python**: 3.13 (`py` launcher)
- **Docker**: Desktop, version 29.3.1
- **Target**: `http://localhost:3000/` (OWASP Juice Shop, container `threattrace-juice-shop`, bound `127.0.0.1:3000`)
- **ZAP**: container `threattrace-zap`, bound `127.0.0.1:8080`, API version `2.17.0`

## 3. Nmap Readiness Discrepancy — Root Cause

**Root cause: Case C — session/PATH environment state, not a runtime-manager or adapter defect.**

Investigation performed:
1. `where.exe nmap` / `where.exe nuclei` in a fresh Bash session → not found.
2. The same check in a fresh PowerShell session (`Get-Command nmap`/`Get-Command nuclei`) → also not found; `$env:PATH` contained no Nmap/Nuclei/ThreatTrace entries in either shell.
3. Direct invocation by known absolute path (`C:\Program Files (x86)\Nmap\nmap.exe --version`) succeeded: **`Nmap version 7.991`**.
4. Code comparison: `adapters.bug_bounty_nmap._find_nmap_executable()` and `runtime.tool_runtime.check_nmap` both call `shutil.which("nmap")` — **byte-for-byte identical discovery method**. There is no divergence between the adapter and the runtime manager to fix.

Conclusion: Nmap genuinely exists and executes correctly at a known, previously-validated install location; it is simply not on `PATH` in this session's shell environment. This is an environmental fact about the current session, not a bug. **No code fix was made or needed.**

Resolution used for this validation: the two known install directories were added to `PATH` for the session only (`export PATH="$PATH:/c/Program Files (x86)/Nmap:..."`) — a reversible, non-persistent, non-destructive action that touches no system file, no repository file, and no Windows configuration.

## 4. Nmap Final Version/Status

**`READY`, version `7.991`** — confirmed both via `python -m runtime.bootstrap check` (with PATH extended) and via a real, successful Nmap scan executed through `core.bug_bounty_tool_execution.execute_bug_bounty_tool` in §9 below.

## 5. Nuclei Readiness Discrepancy — Root Cause

Investigation began identically to Nmap's (same PATH-only discovery method, same session-PATH absence). However, a second, independent fact was discovered during live validation:

- Early in this session, a direct invocation of the previously-known path (`<user-profile>\AppData\Local\ThreatTrace\tools\nuclei\nuclei.exe -version`) **succeeded**, printing real output: `Nuclei Engine Version: v3.11.1`.
- Minutes later, in the same session, the identical direct invocation **failed**: `No such file or directory`. A directory listing and recursive `find` for `nuclei.exe` under that path and its parent both returned **nothing** — the binary itself no longer exists on disk.

**Root cause: the Nuclei binary was genuinely removed from disk between the two checks within this same session.** The most plausible explanation is antivirus/Windows Defender quarantine of a downloaded security-scanner binary — a well-documented behavior for tools like Nuclei that are frequently flagged as "HackTool" — but this was not conclusively confirmed (a best-effort Windows Defender detection-history query returned no output). Regardless of the exact cause, this is **not a ThreatTrace code defect**: `adapters.bug_bounty_nuclei._find_nuclei_executable()` and `runtime.tool_runtime.check_nuclei` are, again, both plain `shutil.which("nuclei")` calls with no divergence, and both correctly and honestly reported the binary's genuine absence once it was gone.

Per instructions, **the tool was not reinstalled**, and live multi-tool validation for Nuclei specifically was honestly stopped/reported as unavailable rather than worked around.

## 6. Nuclei Final Version/Status

**`MISSING`** (adapter-level: `tool_not_installed`) at the time of the live multi-tool Bug Bounty run in §9. Earlier in the same session, before the binary's disappearance, it was confirmed to be version `v3.11.1`. Nuclei Templates directory (`~/nuclei-templates`) was independently confirmed `READY` throughout (unaffected by the binary's disappearance).

## 7. ZAP Version/Status

**`READY`, version `2.17.0`** — confirmed via the real running `threattrace-zap` container's REST API (`GET http://127.0.0.1:8080/JSON/core/view/version/`), and via a real, successful ZAP passive scan executed in §9 below.

## 8. Juice Shop Identity/Status

Container `threattrace-juice-shop`, image `bkimminich/juice-shop:latest`, status `Up` (23+ hours at validation time), bound `127.0.0.1:3000->3000/tcp`. Confirmed reachable at both `http://localhost:3000/` and `http://127.0.0.1:3000/` (`200`). `netstat` confirmed the listening socket is `127.0.0.1:3000` only — no public/LAN bind.

## 9. Final Bug Bounty Run — ID, Planner, Policy, Governor, Tools

Two complementary real runs were performed, both against the identical `http://localhost:3000/` target:

**(A) Multi-tool run** (direct deterministic-core orchestration — the live backend's own Bug Bounty run type is http_assessor-only by Block 15J-K's documented design, so http_assessor+nmap+nuclei+zap together were validated through the same real `core.bug_bounty_tool_policy` → `core.security_governor` → adapter chain the backend itself uses):

- **LLM planner result**: fixed tool plan `["http_assessor", "nmap", "nuclei", "zap"]` (per Block 15J-K's documented fixed-default-plan design; the backend performs no live LLM call for Bug Bounty planning).
- **Policy decisions**: all four tools `execution_permitted: true` (`analyst_permitted`/`profile_permitted`/`adapter_available` all `true`, `human_approval_required: false`, `reason_codes: []`).
- **Governor decisions**: all four `decision: "allow"`, `execution_allowed: true`, `reason_codes: []` (`bug_bounty_assessment` stage, `actor_role: "bug_bounty"`).
- **Tools executed**: `http_assessor` (real, 6 HTTP requests, 12.4s), `nmap` (real, 1 observation, 0.68s), `zap` (real, 5 observations, 3.2s). **`nuclei`**: policy/Governor both permitted it, but the adapter honestly reported `tool_not_installed` (§5/§6) — **`execution_permitted: true` but `execution_performed: false`**, a clean demonstration that analyst permission never fabricates an unimplemented/unavailable adapter run.

**(B) Live-platform run** (real, through the actual backend HTTP API, http_assessor only):
- **Run ID**: `RUN-6e9b191e746ced9981b023aaacc66c8e`
- **Status**: `completed`
- **Event count**: 15 (see §17 for full ordering)
- **Governor decision**: `allow`

## 10-11. Raw Observation Counts / Normalized Evidence Count

From the multi-tool run (A): `http_assessor` produced 5 raw findings, `nmap` 1 observation, `zap` 5 observations, `nuclei` 0 (unavailable) → **11 normalized evidence records** (`core.bug_bounty_evidence_normalization.normalize_bug_bounty_evidence`).

## 12. Duplicate Count

`core.bug_bounty_finding_correlation.correlate_bug_bounty_evidence`: **`duplicate_evidence_count: 0`** (no two records shared an identical `evidence_digest`); **11 input records → 9 correlation groups** (fingerprint/CVE-based grouping merged 2 record-pairs into shared groups — see §14, the CSP finding merged http_assessor + zap into one group).

## 13. Canonical Finding Count

**7 canonical findings** + 2 informational observations (9 groups total, matching §12's 9 correlation groups).

## 14. Canonical Findings (Multi-Tool Run)

| Finding ID | Title | Severity | Confidence | Tools |
|---|---|---|---|---|
| CF-9e27db3adaf4d2cb | Missing Content-Security-Policy header | medium | high | `http_assessor`, `zap` |
| CF-bdb6a8ba8a52c3de | Cross-Domain Misconfiguration | medium | medium | `zap` |
| CF-d18b7480c3c37926 | Notable CORS response headers observed | low | medium | `http_assessor` |
| CF-5c54c603315c1ec9 | Potentially state-changing HTTP methods advertised | low | medium | `http_assessor` |
| CF-19d2ce40de40dc2b | /robots.txt is present and publicly accessible | low | high | `http_assessor` |
| CF-a25fd8be25dee568 | /.well-known/security.txt is present and publicly accessible | low | high | `http_assessor` |
| CF-1d32771ce4746417 | Timestamp Disclosure - Unix | low | low | `zap` |

(Live-platform run (B), http_assessor-only: 3 canonical findings — Missing CSP header, `/robots.txt`, `/.well-known/security.txt` — a subset of the above, consistent with using one fewer tool.)

## 15. Severity Breakdown

Multi-tool run: **low: 5, medium: 2, high: 0, critical: 0** (7 canonical findings). Live-platform run: low: 2, medium: 1 (3 canonical findings).

## 16. Multi-Tool Corroboration

**CF-9e27db3adaf4d2cb ("Missing Content-Security-Policy header") was independently reported by both `http_assessor` and `zap`** (ZAP's own finding: "Content Security Policy (CSP) Header Not Set") and correctly correlated into a single canonical finding with `tools_used: ["http_assessor", "zap"]` and two distinct `evidence_digests` — a genuine, real multi-tool corroboration event, not fabricated.

## 17. Live SSE Event Counts / Ordering

**Bug Bounty run** `RUN-6e9b191e746ced9981b023aaacc66c8e` — **15 events**, sequence 1–15, strictly ordered: `run_created` → `run_started` → `planner_started` → `planner_completed` → `tool_policy_evaluated` → `governor_evaluated` → `tool_started` → `tool_completed` → `http_assessment_completed` → `evidence_normalized` → `finding_correlated` → 3× `canonical_finding_created` → `run_completed`.

**Detection run** `RUN-b65a2b9f175932d765d8825daa406eed` — **13 events**, sequence 1–13: `run_created` → `run_started` → `detection_plan_created` → `telemetry_evaluated` → `governor_evaluated` → `planner_started` → `planner_completed` → 2×(`detection_rule_created` → `detection_rule_validated`) → `human_review_required` → `run_completed`.

## 17b. Bug Bounty → Detection Feasibility Check

The multi-tool-corroborated canonical finding CF-9e27db3adaf4d2cb ("Missing Content-Security-Policy header", `http_assessor` + `zap`) was passed through `core.detection_trigger.build_bug_bounty_trigger` → `core.detection_telemetry.evaluate_telemetry_feasibility` with an intentionally empty `available_telemetry: []` (an honest, unconfigured demo profile). Result: **`decision: "TELEMETRY_GAP"`**, `required_sources: ["http_proxy", "web_server"]`, `missing_sources: ["http_proxy", "web_server"]`. No rule was proposed or forced — exactly the valid, expected outcome per this checkpoint's own instructions.

## 18. Dashboard Validation

Both runs above were performed through the real backend (`python -m backend.app`, `127.0.0.1:8420`). `GET /` returned `200` (dashboard served). `GET /api/runs` after both runs listed exactly the 2 real runs (`RUN-b65a2b9f...` detection/completed, `RUN-6e9b191e...` bug_bounty/completed) — confirming the dashboard's run selector, which reads this exact endpoint, would show only real, non-fixture state. Per Block 15J-K's own dedicated test suite (`tests/test_dashboard_live.py`, re-confirmed passing in §21), the dashboard's source contains no hardcoded finding/Governor/event literals — every value is fetched live. The original static presentation dashboard (`dashboard/threattrace-dashboard.html`) was not touched; no defect was found in it.

## 19. Blocked-Policy Demonstration

Three independent, deterministic negative validations were run against `core.security_governor.evaluate_security_governor_event` (fixture-based, per instructions, rather than an unsafe live action):

| Scenario | Decision | `execution_allowed` | Reason code |
|---|---|---|---|
| Baseline (matches this session's real `allow` events) | `allow` | `true` | — |
| `red_team` actor claiming the `bug_bounty_assessment` stage (requires `bug_bounty`) | `block` | `false` | `ROLE_SCOPE_VIOLATION` |
| `scope_state: "expansion_attempt"` during `detection_engineering` | `block` | `false` | `SCOPE_EXPANSION_ATTEMPT` |
| `remote_content_state: "adopted_as_instruction"` (prompt-injection attempt) | `block` | `false` | `UNTRUSTED_CONTENT_INSTRUCTION_ATTEMPT` |

**LLM proposal ≠ authorization, demonstrated concretely**: the real `detection-engineering-planner` LLM output from §22-28 below was fully ready and valid before any Governor check ran. `backend.orchestrator.run_detection_workflow` checks `governor_result["execution_allowed"]` **before** calling `core.detection_rule.build_detection_rule` for any proposed rule — a blocked Governor decision (as demonstrated above) means the LLM's own proposal is discarded unbuilt, regardless of how well-formed it was. This exact code path is also covered by the pre-existing regression test `tests/test_backend_orchestrator.py::TestDetectionGovernorBlocking::test_014_blocked_governor_stops_before_rule_generation`, re-confirmed passing in §21.

## 20. Benchmark

Not re-run this checkpoint — not necessary for presentation evidence, since this session's own real Bug Bounty findings (§9-16) and the existing fixed supported-category Juice Shop benchmark in [docs/block15f-juice-shop-dashboard.md](block15f-juice-shop-dashboard.md) already provide reproducible precision/recall/F1 evidence. Wording preserved: results there are, and remain, framed as **"on this fixed supported Juice Shop benchmark..."** — never as "ThreatTrace is 100% accurate."

## 21. Full Regression Result

**7,391 passed, 1 skipped (intentional, Windows-only Hayabusa symlink-permission test), 0 failed.** Run once, at the end, per instructions — no code changes were made during Block 17A, so no additional focused-test runs were needed beforehand.

## 22-28. Threat Intelligence + Detection Run Detail

**TI sources queried**: CISA KEV (real, live, bounded to 10 most-recent records), NVD (real, live, keyword search `"LoadMaster"`, 5 records — **no match found for the specific 2026 CVE**, only older 2018–2024 LoadMaster-unrelated CVEs; honestly reported as no enrichment available rather than forced), EPSS (real, live, `cve_ids=["CVE-2026-8037"]`, 1 record, `epss_score: 0.99311`).

**Real TI trigger record selected**: a genuinely different CVE from the one used in the prior Block 15H-I/15J-K checkpoints (not hardcoded to reproduce a prior result) — **CVE-2026-8037, "Progress LoadMaster Command Injection Vulnerability"**, `exploitation_status: "exploited_in_wild"`, `known_exploited: true`, `confidence: "high"`.

**Corroboration/enrichment result**: grouping the real KEV record with the real EPSS record for the same CVE produced `corroboration_state: "conflicting"` — a genuine, expected, deterministic outcome (KEV asserts `known_exploited: true`; EPSS, a probability model, always asserts `known_exploited: false`; any KEV+EPSS pairing on the same CVE will compute `"conflicting"` under this project's corroboration model, documented behavior, not a data error).

**Detection run ID**: `RUN-b65a2b9f175932d765d8825daa406eed`.

**Telemetry decision**: `GENERATE_RULE` (`process_creation`, `network_connection`, `authentication` all available in the supplied demo profile; `missing_sources: []`).

**Real LLM detection-plan result**: the real `detection-engineering-planner` Claude agent was invoked (via the `Agent` tool) with this exact trigger and telemetry result. It produced a genuinely grounded, honest 2-rule plan: no fabricated ATT&CK/CWE (both explicitly absent from the trigger and left unfilled, with a clearly-labeled "suggestion only, not asserted" note for a human to consider CWE-78/T1059 separately), no YARA (correctly judged irrelevant — no file/byte artifact described), and one context-tuned Splunk SPL variant explicitly labeled "DEMO CONTEXT ONLY."

**Rule candidates**: 2 (`RULE-5ac24d1da01e8363` Sigma, `RULE-820e5ba74e679fa8` Splunk SPL) — **0 rejected**.

**Formats**: `["sigma", "splunk_spl"]`.

**Dedup result**: both `new_rule` (no prior rule in this run's history to collide with).

**Syntax/validation status**: **both `syntax_validated`** (`validation_status_distribution: {"syntax_validated": 2}`) — this run's real bounded structural checker happened to pass both drafts; this is an honest, non-cherry-picked outcome (contrast with Block 15H-I's own live validation, which separately and correctly demonstrated the same checker's real false-positive limitation on a different SPL draft — both outcomes are genuine properties of the same bounded, non-parser-based checker, not something staged either way).

**Human review state**: both `pending` (`human_approval_state_distribution: {"pending": 2}`).

**Deployment state**: both **`NOT_DEPLOYED`** (`deployment_state_distribution: {"NOT_DEPLOYED": 2}`) — structurally guaranteed, re-confirmed.

## Final Metrics (Only What Was Actually Measured)

**Bug Bounty**: 4 tools requested, 3 executed (http_assessor, nmap, zap) + 1 honestly unavailable (nuclei); 11 raw observations → 11 normalized evidence records → 9 correlation groups → 7 canonical findings + 2 informational; 0 duplicates prevented needed (0 exact-digest duplicates present); severity low=5/medium=2; 1 multi-tool-corroborated finding.

**Threat Intelligence**: 3 sources queried (CISA KEV, NVD, EPSS), 10+5+1 = 16 records retrieved, 1 record normalized into the working trigger, corroboration states observed: `conflicting` (1).

**Detection**: 1 trigger built, telemetry decision `GENERATE_RULE`, 2 rules proposed, 2 accepted (syntax_validated) / 0 rejected, formats `{sigma, splunk_spl}`, 0 duplicate rules (both `new_rule`), human-review count 2.

**Operational**: Bug Bounty backend run duration: created→completed within ~2s poll interval (real, not precisely timed to the millisecond via this method); event counts 15 (Bug Bounty) + 13 (Detection) = 28 SSE events across 2 live runs; 3 Governor `block` demonstrations + N `allow` decisions (all real runs this session evaluated `allow`).

No MTTD reduction, SOC efficiency improvement, false-positive reduction, causal effectiveness, or production accuracy figure is claimed anywhere in this document — none of those was measured.

## Security Review (Block 17A)

No code was written or modified during Block 17A. The only artifacts of this block are: this document, an optional machine-readable summary (see below), and temporary validation scripts that live in the session scratchpad directory, outside the repository, and were never committed. `git status --short` confirms this (see §"Git Status" below). No `shell=True`, `os.system`, `eval(`, `exec(`, unsafe subprocess, public bind, credential, Supabase/database call, arbitrary command execution, LLM-generated shell, raw scanner output leakage, chain-of-thought exposure, or automatic SIEM deployment was introduced, because nothing was introduced.

## Limitations

- Nuclei was unavailable for live validation due to its binary's disappearance from disk mid-session (see §5) — not re-tested after reinstallation, per instructions not to reinstall unnecessarily.
- The multi-tool Bug Bounty run (A) was performed via direct deterministic-core orchestration, not through the live backend HTTP API, because the backend's own Bug Bounty run type is http_assessor-only by Block 15J-K's own documented design — this is not a defect, but readers should not assume `POST /api/runs/bug-bounty` itself triggers nmap/nuclei/zap.
- NVD enrichment was unavailable for the specific CVE used in the Detection run (no keyword match) — honestly reported as absent rather than forced.
- Structural rule-syntax validation remains bounded/stdlib-only, not a real parser, and not detection-efficacy testing.
- This validation was performed entirely on Windows, against the local Juice Shop/ZAP containers — no cross-platform validation was performed or claimed.

## Known Issues

None discovered that required a code fix. The Nmap/Nuclei readiness discrepancy (§3, §5) was fully investigated and found to be environmental, not a defect.

## Files Modified/Created

- Created: `docs/block17a-final-validation.md` (this document).
- Created (optional): `artifacts/final-validation-summary.json` (see below, if committed).
- No source code, test, or configuration file was modified.

## Git Status

Clean except for the new documentation file(s) listed above; no code changes. See commit section for the exact final `git status --short` output at commit time.

## Security-Honesty Statements (Preserved)

- Nuclei zero findings (in earlier partial checks) ≠ no vulnerabilities — never claimed as "secure."
- Burp not configured (`not_configured` throughout this session) ≠ executed.
- Telemetry gap (§13 of the Bug-Bounty-to-Detection check, run separately from the KEV-triggered run) ≠ a detection rule — none was forced.
- Structural validation (`syntax_validated`, §27) ≠ efficacy validation.
- Human review pending (§28) ≠ approved.
- `NOT_DEPLOYED` (§28) ≠ deployed — structurally guaranteed by `core.detection_rule.build_detection_rule`.
- Evidence digests (§14, §16) ≠ trusted timestamp/non-repudiation proof — content-correlation identifiers only.
