# Block 17B — Presentation + Live Demo Preparation

**Source of truth for every number and claim in this document**: [docs/block17a-final-validation.md](block17a-final-validation.md) and [artifacts/final-validation-summary.json](../artifacts/final-validation-summary.json). No metric below was invented, estimated, or pulled from an earlier, more favorable checkpoint. Where Block 17A and any older narrative disagree, Block 17A wins.

This document does **not** contain a research paper, an abstract, a literature review, or a methodology chapter. It is presentation-preparation material only. The research paper is Block 17E, after presentation feedback (17C) and refinement (17D).

---

## 1. Presentation Title

**"ThreatTrace: An Analyst-Governed, AI-Assisted Security Research Platform"**

(Alternate, shorter: *"ThreatTrace: Connecting Discovery, Intelligence, and Detection Under Deterministic Governance"*)

## 2. Central Research Question

> Can AI reasoning and deterministic governance be combined to connect vulnerability discovery, threat intelligence, and detection engineering into one workflow — while keeping every execution and authorization decision under deterministic, code-enforced control rather than the LLM's own judgment?

## 3. Recommended Slide Count

**14 slides** (within the requested 12–15 range) — see the exact outline below. Slide 4/5 from the original suggested flow are combined into one architecture slide with the Analyst-Governed AI Model as its own follow-on slide, and Slides 13/14 keep "what ThreatTrace refuses to fake" and "contributions" separate since they serve different audience reactions (concern-relief vs. this-is-the-contribution).

## 4. Complete Slide Outline

### Slide 1 — ThreatTrace
- Title + one-line value proposition: *"An analyst-governed, AI-assisted platform connecting vulnerability discovery, threat intelligence, and detection engineering — with deterministic controls between every AI proposal and every action."*

### Slide 2 — Problem
- Security teams run vulnerability discovery, threat intel, prioritization, detection engineering, validation, and human review as **disconnected tools and disconnected people**.
- A real finding can go months without a matching detection rule. A piece of threat intel can go unactioned because nobody connects it to what the organization's own telemetry could support.
- Bullet visual: 5-6 disconnected boxes (Scanner / TI Feed / SIEM / Detection Backlog / Ticketing) with no arrows between them.

### Slide 3 — Research Question
- State the question from §2 above verbatim, large on the slide.
- One supporting line: *"This is an exploration, not a proof — see Limitations."*

### Slide 4 — ThreatTrace Architecture
- One diagram (see [Visual 1](#visual-1--overall-architecture)): LLM reasoning layer → deterministic core → Governor → tools/adapters → TI → Detection Engineering → live dashboard.
- Caption: *"Six real Claude agents. Everything else is deterministic Python."* (Never "eight autonomous agents" — see [docs/architecture.md](architecture.md#the-six-claude-custom-agents).)

### Slide 5 — Analyst-Governed AI Model
- Five-step chain, one line each: **LLM proposes → Policy checks → Governor decides → Deterministic services execute/validate → Human reviews.**
- Callout: *"The LLM never executes a tool or deploys a rule directly, anywhere in this codebase."*

### Slide 6 — Bug Bounty Workflow
- Diagram: Planner → Tool Permission Policy → Security Governor → HTTP/Nmap/Nuclei/ZAP/Burp boundary → Evidence Normalization → Correlation → Canonical Findings.
- Note the closed adapter registry: no tool_id string can ever select an arbitrary binary.

### Slide 7 — Multi-Tool Evidence Correlation
- The real CSP example: `http_assessor` + `zap` both independently found "Missing Content-Security-Policy header" → **one** canonical finding (`CF-9e27db3adaf4d2cb`), not two.
- Line: *"Two observations did not become two vulnerabilities."*

### Slide 8 — Threat Intelligence Workflow
- CISA KEV / NVD / EPSS → normalization → corroboration → enrichment.
- Real example: this session's KEV+EPSS pairing for CVE-2026-8037 computed `corroboration_state: "conflicting"` — explain briefly why (§7 below) as a sign the model is honest, not broken.

### Slide 9 — Intelligent Detection Engineering
- Diagram: Bug Bounty finding **or** Threat Intel record → Detection Trigger → Telemetry Feasibility gate → LLM Planner → deterministic validation → candidate rules.
- Callout: *"A `TELEMETRY_GAP` produces zero rules. ThreatTrace never fabricates a rule when there's no basis to detect the behavior."*

### Slide 10 — Security Governor
- Why the LLM cannot authorize execution itself.
- Show one real `allow` and one real `block` (role-scope violation) result side by side — same evaluator, different input.

### Slide 11 — Live Platform
- Backend (`127.0.0.1:8420`, local-only) → in-memory Run Store/Event Bus → SSE → real-time dashboard.
- Screenshot placeholder: dashboard mid-run.

### Slide 12 — Final Validation Results
- Table of frozen Block 17A metrics only (§6 below). No slide-original numbers.

### Slide 13 — What ThreatTrace Refuses To Fake
- Nuclei unavailable → reported `MISSING`, not silently skipped.
- Burp unconfigured → reported `NOT_CONFIGURED`, not silently skipped.
- Telemetry gap → zero rules, not a fabricated one.
- Human review → `pending`, never auto-approved.
- Deployment → `NOT_DEPLOYED`, structurally guaranteed.

### Slide 14 — Contributions / Limitations / Future Work
- Contribution framing (§8 below) + limitations (§9) on one slide, split top/bottom, to end on both what was built and what wasn't claimed.

---

## 5. Main Architecture Story

Discover/ingest → normalize evidence → understand context → decide what matters → determine whether it's detectable → generate a detection candidate → validate + govern → human review → reuse validated defensive experience. Every arrow in that chain is either a deterministic Python function or a Governor-checked decision point; the only non-deterministic step is the LLM's own proposal, which is never trusted without re-validation on the other side.

## 6. Frozen Metrics (Exact, from Block 17A)

**Do not alter these numbers for the presentation.** Convert none of them into a percentage-improvement claim — none of the underlying "before" states were measured.

| Category | Metric | Value |
|---|---|---|
| Full regression | Passed / Skipped / Failed | 7,391 / 1 / 0 |
| Bug Bounty | Raw observations | 11 |
| Bug Bounty | Normalized evidence records | 11 |
| Bug Bounty | Canonical findings | 7 |
| Bug Bounty | Informational observations | 2 |
| Bug Bounty | Severity | 5 low, 2 medium, 0 high, 0 critical |
| Bug Bounty | Multi-tool corroborated findings | 1 (CSP header, `http_assessor` + `zap`) |
| Bug Bounty | Tools executed | HTTP assessor, Nmap, ZAP |
| Bug Bounty | Nuclei | `MISSING` at final validation |
| Bug Bounty | Burp | `NOT_CONFIGURED` |
| Bug Bounty → Detection | Telemetry decision | `TELEMETRY_GAP`, 0 rules forced |
| Threat Intel | Sources queried | CISA KEV, NVD, EPSS |
| Threat Intel | Real trigger | CVE-2026-8037, Progress LoadMaster Command Injection |
| Detection | Rule candidates | 2 (Sigma, Splunk SPL) |
| Detection | Rejected | 0 |
| Detection | Validation status | both `syntax_validated` |
| Detection | Human review | pending |
| Detection | Deployment | `NOT_DEPLOYED` |
| Live platform | SSE events | 15 (Bug Bounty run), 13 (Detection run) |

## 7. Nuclei — Presentation Treatment

Say exactly this, and no more:

> "Nuclei was successfully integrated and validated in an earlier checkpoint, but the binary was unavailable during the final evidence freeze, so the final run records it as unavailable rather than pretending it executed."

Do not apologize further, do not speculate on-stage about antivirus quarantine (that's in the written record if asked — see Q17 below), and do not treat Nuclei as required for the demo to succeed. The primary live demo (§9 of the task, detailed below) never depends on it.

## 8. Burp — Presentation Treatment

> "Burp DAST requires an analyst-configured external runtime that we don't have configured in this environment, so ThreatTrace honestly reports it as `NOT_CONFIGURED` rather than simulating a scan. ThreatTrace never bundles or auto-installs Burp."

## 9. Contribution / Novelty Framing

State plainly, before listing anything: **individual components (Nmap, ZAP, Sigma, LLM planning) are not claimed as novel.** The contribution under exploration is the combination:

1. Analyst-governed LLM planning with deterministic execution control — the LLM proposes a plan; policy and Governor code re-validate it independently before anything runs.
2. A Security Governor that structurally separates AI reasoning from authorization (evaluates observable state; the LLM's proposal is never itself sufficient).
3. Multi-tool evidence normalization and canonical correlation (real example: CSP finding, §Slide 7).
4. Dual-trigger Detection Engineering — a detection candidate can originate from either a Bug Bounty finding or a Threat Intel record, through the same downstream pipeline.
5. A telemetry feasibility gate that can and does refuse to generate a rule when there's no detection basis (`TELEMETRY_GAP`).
6. Generic + context-aware detection candidate generation from the same trigger.
7. Detection rule normalization/deduplication (fingerprint-based, never title-based).
8. Honest, structurally-enforced validation/deployment states (`NOT_DEPLOYED` cannot be bypassed by any caller).
9. Real-time operational visibility through SSE/dashboard, reflecting only real run state.
10. A defined (though not yet extensively populated) path for validated defensive experience reuse (Security Experience Memory).

**Answer to "isn't this just connecting existing tools with an LLM?"** — see §Tough Novelty Question below.

## 10. Claims Intentionally Avoided

Never say, in the presentation or in answers: fully autonomous SOC, autonomous pentester, production-ready, zero-day prevention, 100% vulnerability detection, automatic remediation, production detection efficacy, authenticated human approval (it's caller-supplied, not authenticated), automatic SIEM deployment. If a reviewer's question pulls toward any of these, redirect to what was actually measured (§6) and what the system structurally refuses to do (Slide 13).

---

## 11. Live Demo — Primary Path (5–8 minutes, does not require Nuclei)

**Prerequisites**: backend running (`python -m backend.app`), Juice Shop and ZAP containers up, dashboard reachable. Verify with `scripts/check-demo-readiness.ps1` before presenting (see §12 below).

| Step | Action | Say |
|---|---|---|
| 1 | Open `http://127.0.0.1:8420/` | "This is the real operational dashboard — no fixture data. Every field you'll see is fetched live from the backend." |
| 2 | Open `http://localhost:3000` (Juice Shop) | "This is our authorized local test environment — OWASP Juice Shop, bound to localhost only." |
| 3 | Start a Bug Bounty run from the dashboard (or `POST /api/runs/bug-bounty`) | "Watch the pipeline: Planner proposes a tool plan, Policy checks it, the Governor decides, then HTTP/Nmap/ZAP actually run." |
| 4 | Watch the live event feed | "Each tool's status moves through requested → permitted → executed — never skipped." |
| 5 | Show canonical findings | "Here's the CSP finding — HTTP assessor and ZAP both found it independently, and correlation merged them into **one** canonical finding, not two." |
| 6 | Point at an informational observation (e.g. an open port / metadata-present entry) | "This is an observation, not a vulnerability — ThreatTrace keeps that distinction explicit rather than inflating a finding count." |
| 7 | Show (or replay, if not re-running live) the Detection workflow from Threat Intelligence | "A real CISA KEV record → telemetry feasibility → the LLM planner proposes rule drafts → deterministic validation checks them." |
| 8 | Show `human_review_required: pending` and `deployment_state: NOT_DEPLOYED` on the rule candidates | Close the demo with the line in §16. |

## 12. Negative-Control Demo (short, safe, fixture-based)

**Do not attempt this against a live target.** Use the already-validated fixture path from Block 17A §19: call `core.security_governor.evaluate_security_governor_event` directly with a role-scope-violation event (`actor_role: "red_team"` claiming the `bug_bounty_assessment` stage, which requires `bug_bounty`) and show the real output: `decision: "block"`, `execution_allowed: false`, `reason_codes: ["ROLE_SCOPE_VIOLATION"]`. One line: *"Same evaluator, same code path as the `allow` you just saw — only the input changed. The LLM's proposal was never the thing that authorized execution."*

## 13. Expected Demo Duration

5–8 minutes for the primary path (§11); +1–2 minutes if the negative-control demo (§12) is included live rather than shown as a pre-captured result.

---

## 14. Backup Demo Plan

See [docs/block17b-demo-backup.md](block17b-demo-backup.md) for the full frozen-evidence fallback.

## 15. Demo Readiness Requirements

**REQUIRED** for the primary demo: Docker, Juice Shop container, backend (`127.0.0.1:8420`), HTTP assessor (always available), Nmap, ZAP.
**OPTIONAL**: Nuclei, Burp — the demo narrative explicitly accounts for either being unavailable (§7, §8).

## 16. Demo Failure / Fallback Plan

See [docs/block17b-demo-backup.md](block17b-demo-backup.md) §"Failure Response Table" for the full per-failure-mode script.

---

## 17. Presentation Visuals Required

1. **Overall architecture** — LLM layer / deterministic core / Governor / tools / TI / Detection Engineering / dashboard (see [docs/architecture.md](architecture.md#system-diagram) for the real Mermaid diagram to adapt).
2. **Planner/Policy/Governor boundary** — the five-step chain from Slide 5.
3. **Bug Bounty evidence correlation** — the real CSP example (two tools → one finding).
4. **Dual-trigger Detection Engineering** — Bug Bounty finding OR TI record → trigger → telemetry gate → planner → validation → candidate.
5. **Live dashboard** — real screenshot, captured per §12 of the readiness/backup process, not a mockup.
6. **Governor allow/block** — two real JSON results side by side (from Block 17A §19).
7. **Canonical finding** — the real CF-9e27db3adaf4d2cb JSON, trimmed to the fields that matter for a slide.
8. **Detection rule lifecycle** — trigger → telemetry → plan → rule → dedup → syntax check → `NOT_DEPLOYED`, using the real CVE-2026-8037 rule IDs.

No decorative or invented diagram — every visual above traces to a real architecture component or a real Block 17A result.

---

## 18. Expected Questions (20) and Concise Answers

1. **Why is this different from SOAR?** — SOAR orchestrates pre-defined playbooks against pre-integrated tools; ThreatTrace's LLM layer proposes plans dynamically from context, but every proposal is re-validated by deterministic policy/Governor code before anything executes — the orchestration logic isn't a fixed playbook, and the authorization boundary is explicit and code-enforced rather than implicit in the playbook author's trust.
2. **Why use an LLM at all?** — To reason over unstructured context (a KEV summary, a canonical finding's free text) and propose a plan/rule a human would otherwise have to draft manually; the LLM's output is treated as a proposal, never as ground truth.
3. **Why not let the LLM execute directly?** — Because LLM output can be wrong, inconsistent, or manipulated by untrusted input (e.g. scanned target content); every execution path in ThreatTrace requires a separate, deterministic Policy + Governor check that doesn't trust the LLM's own claim that something is permitted.
4. **What is actually novel?** — Not any single component; the combination of evidence-preserving multi-tool correlation, a Governor that structurally separates reasoning from authorization, and a telemetry-gated dual-trigger detection pipeline in one measurable workflow. See §9.
5. **How do you prevent hallucinated detections?** — The LLM's rule draft is never trusted as-is: `core.detection_planner` deterministically validates the plan's structure and telemetry alignment, `core.detection_rule` builds the rule from only validated fields, deduplication runs on fingerprints (not titles), and a bounded structural syntax check runs before any rule is marked `syntax_validated`. None of this proves detection *efficacy* — see Q10.
6. **What happens if telemetry is missing?** — `core.detection_telemetry.evaluate_telemetry_feasibility` returns `TELEMETRY_GAP`, and the deterministic plan validator structurally forces zero proposed rules for that case — this was demonstrated live in Block 17A §17b.
7. **How is correlation performed?** — Deterministic fingerprinting over host/port/path/parameter/category (never title text), plus a shared-CVE override — see `core.bug_bounty_finding_correlation`. The real CSP example: two different title strings from two different tools, same fingerprint, merged.
8. **Why is the Governor deterministic rather than another LLM call?** — Because an authorization boundary needs to be predictable, testable, and unable to be argued with by adversarial input; a second LLM evaluating a first LLM's output doesn't remove the trust problem, it duplicates it.
9. **How do you know generated rules actually work?** — We don't claim that. `validation_status` only ever reaches `syntax_validated` in this system (bounded structural check) — never a claim of detection efficacy. That's an explicit, stated limitation.
10. **Why only structural validation?** — Real rule-efficacy testing requires a live SIEM/EDR with real data to test against, which is out of scope for this local research checkpoint; adding a real parser (pySigma etc.) was deliberately avoided to keep the dependency footprint minimal, and the bounded checker's own false-positive limitation is documented, not hidden (see Block 15H-I's own live-validation finding).
11. **Why was Nuclei unavailable?** — See §7 verbatim.
12. **Why was Burp not tested?** — See §8 verbatim.
13. **Why Juice Shop?** — A well-known, deliberately-vulnerable, locally-runnable, non-production application — safe for authorized local testing without touching any real system.
14. **How would this scale?** — Not measured or claimed; the current architecture is a single local backend process with in-memory state, explicitly framed as a local research prototype, not a scaled deployment.
15. **How would production authentication work?** — Not implemented; `backend/` has none today and says so explicitly (`interface_class: "local_development_research_interface"`). A real deployment would need it added as a separate, explicitly-scoped block.
16. **How would SIEM deployment work?** — Not implemented anywhere in this codebase; every rule is structurally `NOT_DEPLOYED`. A real deployment path is a distinct, unbuilt future component.
17. **What are the biggest limitations?** — In-memory-only run history, no production auth, structural-only rule validation, Nuclei/Burp availability gaps in this environment, no cross-platform validation beyond Windows, no comparative/ablation evaluation yet.
18. **How do you protect against prompt injection from target content?** — Fetched target/scan content is treated as untrusted evidence data throughout — normalized into structured fields, never re-interpreted as an instruction; the Governor's own `remote_content_state: "adopted_as_instruction"` check exists specifically to catch and block an attempt to let untrusted content steer a decision (demonstrated in Block 17A §19).
19. **How do you trust threat intelligence?** — We don't claim source-level trust beyond what's structurally computed: `core.threat_intelligence.compute_corroboration` is a deterministic function over caller-supplied source records — CISA KEV/NVD are treated as authoritative sources, EPSS is not (it's a probability model), and disagreement between sources is surfaced as `"conflicting"` rather than silently resolved.
20. **What does Security Experience Memory mean?** — A mechanism for only genuinely validated, human-reviewed defensive outcomes to become reusable — a Governor `block`/`freeze` or an unreviewed draft can never become "reusable" memory. It exists in the codebase; this validation round did not exercise it live, and no claim is made about its measured effectiveness.

## 19. Tough Novelty Question — Full Answer

**"Isn't this just connecting existing tools with an LLM?"**

> "The individual pieces — Nmap, ZAP, Sigma, an LLM proposing text — aren't new, and we're not claiming they are. What's being explored is the combination: evidence-preserving integration across tools, context-aware LLM reasoning that's never trusted as ground truth, deterministic policy and Governor code that authorizes every action independently of what the LLM claims, a telemetry-gated detection-generation step that can refuse to produce a rule, and a structure that lets a defensive outcome from one trigger type (a bug bounty finding) feed the same pipeline as another (threat intel). We haven't run a comparative study against an existing platform to claim this combination is *better* — that's future work, and one of the questions we're bringing back to reviewers today."

Never claim proven superiority without comparative experiments — say this directly if pressed further.

## 20. Questions to Ask Reviewers (for Block 17D / the eventual paper)

1. Which component would benefit most from a stronger comparative evaluation against an existing platform (e.g. an open-source SOAR, a standalone detection-engineering tool)?
2. Would an ablation study (Governor on/off, telemetry gate on/off) meaningfully strengthen the contribution claim, or is the architecture-level combination sufficient framing on its own?
3. Which baseline platforms would be the most credible comparison points?
4. Is the Security Governor's separation from the rest of the workflow convincing as presented, or does it need a more rigorous formal boundary/threat model?
5. Which metrics would make the detection-generation evaluation stronger than "syntax_validated / rejected" counts — e.g. should a future block attempt real efficacy testing against sample logs?

---

## Visuals Appendix

### Visual 1 — Overall Architecture

Adapt directly from [docs/architecture.md](architecture.md#system-diagram)'s real Mermaid diagram — do not redraw from memory, since that diagram already reflects the actual module names and flow.
