# Block 15F — OWASP Juice Shop Benchmark + Presentation Dashboard

**Block 15F-B checkpoint is complete.** It is a pure, deterministic, local, self-contained HTML presentation layer over the real, controlled Block 15F-A/15F-A.1 OWASP Juice Shop benchmark — never a live data source, never a computation engine of its own.

## 1. Goal

Show a real, measured before/after security-detector improvement — honestly, with unavailable data marked as unavailable rather than invented — in a presentation-quality, self-contained HTML dashboard a recruiter, hiring manager, security engineer, or research reviewer can open directly in a browser.

## 2. Controlled target

**OWASP Juice Shop**, `http://localhost:3000/`, running as a Docker container (`threattrace-juice-shop`) bound only to `127.0.0.1:3000` — never a public or unrelated target.

## 3. Fixed image digest

`sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e` (`bkimminich/juice-shop:latest`, recorded via `docker image inspect` during Block 15F-A0) — the same digest for both the baseline and refined runs, so the comparison is genuinely apples-to-apples.

## 4. Baseline experiment

Block 15F-A0 established an **independent** ground truth (curl/PowerShell HTTP checks, never `core.bug_bounty_assessment` itself) for exactly the observations ThreatTrace's implemented detectors can produce, then ran the real, committed `core.bug_bounty_cli` (`safe_active` profile) against the same target. Result: 6 findings.

## 5. Discovered sitemap false positive

`/sitemap.xml` returned HTTP 200, but independent inspection showed `Content-Type: text/html` and a body identical in shape to Juice Shop's Angular single-page-application catch-all fallback (a deliberately-nonexistent control path returned the same signature) — not a genuine sitemap file. ThreatTrace's original metadata detector qualified any HTTP 200 on the three fixed metadata paths as "present," producing a false `exposed_metadata` finding for this path.

## 6. Evidence refinement

Block 15F-A.1 added `core.bug_bounty_assessment._is_genuine_metadata_resource` — a small, deterministic, reusable evidence-quality check using only the Content-Type header and bounded body excerpt **already fetched** for the same request (no new request, no new path, no new vulnerability class). A response qualifies as genuine when its media type is appropriate for that resource type (`text/plain` for robots.txt/security.txt, `application/xml`/`text/xml` for sitemap.xml) **or** its bounded body contains a recognized structural marker for that resource (robots directives, security.txt fields, or XML/sitemap tags) — either signal alone is sufficient, so a genuine file served with an unexpected media type is still honestly recognized.

## 7. Same-target rerun

The refined CLI was rerun against the **same running container**, same image digest, same `safe_active` envelope. Result: 5 findings (the `/sitemap.xml` finding no longer appears); `network_requests_performed` remained **6** — identical to baseline, confirming no new request was introduced.

## 8. Baseline metrics

Scored with the committed, unmodified `core.juice_shop_ground_truth.build_baseline_ground_truth()` (9 supported cases: 5 positive, 4 negative) through the committed, unmodified `core.benchmark_evaluation.evaluate_benchmark`:

`TP=5, FP=1, FN=0, TN=3` — precision **0.8333333333**, recall **1.0**, F1 **0.9090909091**.

## 9. Refined metrics

Same ground truth, same evaluator, new findings:

`TP=5, FP=0, FN=0, TN=4` — precision **1.0**, recall **1.0**, F1 **1.0**.

## 10. Metric deltas

precision_delta = **+0.1666666667**, recall_delta = **0.0**, f1_delta = **+0.0909090909**, false_positive_delta = **−1**.

## 11. Why recall remained unchanged

The refinement only *removes* a false qualification (a non-genuine response no longer counts as "present") — it never *removes* a genuine positive signal. None of the 5 positive supported cases (CSP-missing, robots.txt, security.txt, advertised methods, CORS) depend on the metadata-qualification logic that changed for `/sitemap.xml`, so every true positive that fired before still fires after. Recall (`TP/(TP+FN)`) is therefore unaffected by construction, not by coincidence.

## 12. Supported benchmark definition

A ground-truth case counts toward the scored benchmark **only** when the observation it describes falls within an already-implemented ThreatTrace detector capability (security-header presence, fixed metadata resource observation, CORS observation, advertised HTTP methods, inert input reflection). This is `core.juice_shop_ground_truth.build_baseline_ground_truth()`'s own `supported_cases` list — the dashboard never scores anything outside it.

## 13. Unsupported categories

SQL injection, executable XSS, IDOR/access-control testing, SSRF, command injection, authenticated workflow testing — genuinely present in Juice Shop's real challenge catalog, but outside this engine's implemented capability. Never counted as false negatives; always disclosed separately.

## 14. Dashboard architecture

`core/presentation_dashboard.py` (`render_presentation_dashboard`) is a pure function: `dashboard_data` mapping in, complete HTML string out — no file I/O, no network, no clock, no randomness, byte-identical output for byte-identical input. `core/presentation_dashboard_cli.py` is the only part of the stack that touches the filesystem — it validates a three-field envelope (`operation`, `dashboard_data`, `output_path`), calls the pure renderer once, and writes the result to `output_path`. `dashboard/threattrace-dashboard.html` is the generated, real, checked-in artifact.

## 15. Executive View

Title, subtitle, and public description; KPI cards (baseline/refined precision, recall, baseline/refined F1, false positives reduced, supported benchmark case count); a prominent "Controlled Result" callout using the required research wording; baseline→refined bars for precision/recall/F1; a compact false-positive badge (`1 → 0`); a "Supported Benchmark Detection Result" table (never labeled overall accuracy); a five-step "Defect Discovery Story" narrative (no raw response body included).

## 16. Research View

A. benchmark before/after (same table as Executive); B. supported-ground-truth coverage counts; C. precision/recall/F1 bars; D. a short evidence-quality-refinement explanation; E. optional research-evaluation metrics (see §17); F. a link back to the Limitations section.

## 17. Optional research metrics

When `dashboard_data.research_evaluation` is a real Block 15E result, the Research View renders context-prioritization movement, Governor decision counts and intervention rate, memory candidate/validated/rejected counts, Governor→Memory protection and unsafe-reusable-violation counts, evidence preservation, Red→Blue revision cycles, human-review counts, validated-defensive-experience rate, MTVD, the stage-count proxy, and every ablation group — read defensively via `.get()` so a partial/evolving research-evaluation shape never crashes the renderer. **This checkpoint's real dashboard supplies `research_evaluation: null`** — no Block 15E experiment was run against this benchmark, so this section renders the honest unavailable-state message instead (see §18).

## 18. Unavailable-state rules

`research_evaluation: null` → the Research View states plainly: *"Not evaluated in this Juice Shop benchmark run,"* plus explicit Governor/Memory/MTVD unavailable messages. This module never fabricates a `0` count, a `0%` rate, or a `100%` protection figure for an unevaluated section — a fabricated zero would falsely imply a real, evaluated sample of size zero rather than "not measured at all."

## 19. MTVD handling

When `research_evaluation` is supplied, MTVD renders `mean_minutes` only if the real `mtvd.available` flag is `true`; otherwise it renders the fixed message *"MTVD unavailable — no qualifying caller-supplied duration."* The stage-count proxy is never substituted for MTVD — they are always rendered as two independent metrics.

## 20. Governor handling

Real Governor decision counts and intervention rate render only when `research_evaluation` is supplied. When it is not, the dashboard states *"Governor metrics were not exercised in this benchmark run"* — it never shows `0` blocks/freezes or a `100%` protection rate, since either would misleadingly imply an evaluated (if empty) sample.

## 21. Memory handling

Real memory candidate/validated/rejected counts and reuse rate render only when `research_evaluation` is supplied. When it is not, the dashboard states *"Validated Security Experience Memory was not evaluated in this benchmark run"* — and this module never calls memory reuse "self-learning," "AI learning," or "model training" anywhere in its rendered output or its own source.

## 22. Architecture terminology

The Architecture section explicitly uses **functional security roles**, **deterministic core services**, **Claude custom agents**, and **policy identities** — and explicitly states ThreatTrace is never described as "eight autonomous agents." The workflow flow diagram (Bug Bounty → Context Prioritization → Security Handoff → Security Governor → Validated Security Experience Memory → Research Evaluation) is always labeled *"Platform workflow — not all stages were exercised in this benchmark"* — for this real dashboard, only Bug Bounty is marked `Executed`; every other stage is marked `Not evaluated`, honestly, because no Context Prioritization, Security Handoff, Governor evaluation, Memory admission, or Research Evaluation experiment was run against this benchmark's findings.

## 23. Limitations

A fixed, always-visible Limitations section (§16 of the implementation spec) lists: supported-capability-benchmark-only scope, one local application, one fixed image digest, unsupported-category exclusion from recall, no SQL injection/XSS/IDOR/authenticated testing, no statistical-significance claim, no generalization claim, and evidence-reference-is-not-authenticity-proof — rendered from `dashboard_data.research_limitations`, never hand-typed into the template beyond the caller-supplied list.

## 24. How to open the dashboard

`dashboard/threattrace-dashboard.html` is fully self-contained (inline CSS, no external script/font/image/CDN reference, no analytics). Open it directly from the local filesystem in any modern browser — no local HTTP server is required, and no dashboard feature depends on one.

## 25. Presentation usage

Intended for exactly the five-step narrative documented in the Block 15F design audit: local Juice Shop target → bounded discovery → finding/context/security workflow (architecture, labeled honestly as not fully exercised here) → Governor + memory (also labeled honestly) → this research dashboard showing the real measured before/after result.

## 26. Reproducibility

Every number in the generated dashboard traces back to: the fixed image digest (§3), the real `core.bug_bounty_cli` output captured during Block 15F-A0/15F-A.1, the committed `core.juice_shop_ground_truth.build_baseline_ground_truth()` manifest, and the committed `core.benchmark_evaluation.evaluate_benchmark()` evaluator — re-running the same findings through the same (unmodified) ground truth and evaluator reproduces the same precision/recall/F1 values byte-for-byte.

## 27. Safety

The generated HTML contains no cookies, no `Authorization` header, no secret, no local username, no Windows absolute path, no raw response body, and no full HTTP dump — verified by direct inspection of the generated file. Every caller-supplied string in `dashboard_data` is HTML-escaped before embedding, so no supplied string (including an adversarial one) can inject a `<script>` tag or any other executable content into the page.

## 28. Testing

Actual counts as validated at the close of this checkpoint:

- `tests/test_presentation_dashboard.py` (core renderer) — **80 passed**
- `tests/test_presentation_dashboard_cli.py` (CLI) — **34 passed**
- Combined Block 15F-B + directly related Block 15F-A/15A suites — see this checkpoint's validation report
- AI Asset Registry (`test_ai_asset_registry` + `test_ai_asset_registry_cli`) — **140 passed**

## 29. Research honesty

The dashboard never claims "ThreatTrace accuracy" (only a named, attributed supported-benchmark result), never claims statistical significance, never claims generalization beyond this one controlled comparison, never calls memory reuse self-learning/AI learning/model training, never claims eight autonomous agents, and never claims visual browser verification unless a human explicitly performed and reported it. Every affirmative-sounding phrase in the module's own source was checked against this list during implementation to avoid a false claim being introduced alongside the honest negation prose that documents these boundaries.

## 30. Future multi-target evaluation

This checkpoint deliberately covers exactly one target, one image digest, one before/after comparison. A future checkpoint could extend the same `dashboard_data` contract to multiple targets/runs (e.g. a `runs: [...]` list) without changing the core renderer's honesty rules — every future addition should continue to render "not evaluated" honestly for any target/run missing real data, exactly as this checkpoint does for the Governor/Memory/MTVD sections today.
