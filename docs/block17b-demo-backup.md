# Block 17B — Demo Backup Plan

Live demos fail. This document is the fallback: if the live environment breaks during presentation, the presenter explains the **same validated run** using frozen evidence instead of re-running anything live. Nothing in this document is fabricated — every value below is copied from [docs/block17a-final-validation.md](block17a-final-validation.md) and [artifacts/final-validation-summary.json](../artifacts/final-validation-summary.json), the frozen source of truth.

## Before Presenting: Capture This Evidence

Do this once, ahead of time, while the live environment is known-good (e.g. right after `scripts/check-demo-readiness.ps1` reports all REQUIRED items ready). Do not synthesize any of these — if a capture fails, re-run the underlying step and capture again; never substitute a mockup.

| # | What to capture | How | Where it lives afterward |
|---|---|---|---|
| 1 | Dashboard healthy, no active run | Screenshot of `http://127.0.0.1:8420/` showing "No active run" empty states | `docs/screenshots/` (create locally; not required to be committed) |
| 2 | Bug Bounty run completed | Screenshot of the dashboard mid/post-run, plus `GET /api/runs/{id}` JSON for a real run | Same |
| 3 | Governor `allow` | Screenshot or copy of a real `governor_evaluated` event payload | Same |
| 4 | Governor `block` | Screenshot or copy of the fixture-based negative-control result (Block 17A §19) | Same |
| 5 | Canonical findings list | Screenshot of the Findings panel, or `GET /api/runs/{id}/report` JSON | Same |
| 6 | CSP multi-tool correlation | The specific `CF-9e27db3adaf4d2cb` finding JSON, `tools_used: ["http_assessor", "zap"]` | Already frozen in Block 17A §14 — no live capture needed |
| 7 | TI trigger | The real `DT-08b31b337d9b1091` trigger JSON for CVE-2026-8037 | Already frozen in Block 17A §22-28 — no live capture needed |
| 8 | Telemetry decision | `GENERATE_RULE` result JSON from the Detection run | Already frozen — no live capture needed |
| 9 | Sigma/SPL candidates | Screenshot of the Detection Engineering panel, or the rule JSON | Live capture recommended; frozen IDs available as fallback |
| 10 | Human review pending | Screenshot/JSON showing `human_approval_state_distribution: {"pending": 2}` | Already frozen — no live capture needed |
| 11 | `NOT_DEPLOYED` | Screenshot/JSON showing `deployment_state_distribution: {"NOT_DEPLOYED": 2}` | Already frozen — no live capture needed |

Items 6–8, 10, 11 already exist as real, frozen text in Block 17A and need no live screenshot at all — if the live environment is unavailable, present these directly from the document with the citation "from the Block 17A frozen validation record."

## If the Live Environment Fails Entirely

Narrate the exact same real run using the frozen record instead of a live screen:

> "I'll walk through the same validated run using our frozen evidence record instead of the live environment. This is the exact output from a real run performed during our final validation pass — run ID `RUN-6e9b191e746ced9981b023aaacc66c8e` for the Bug Bounty workflow, and `RUN-b65a2b9f175932d765d8825daa406eed` for the Detection workflow."

Then walk the captured screenshots/JSON from the table above in the same order as the live demo steps (§11 of `docs/block17b-presentation-demo.md`).

## Failure Response Table

| Failure | What to say | Fallback | Can demo continue? |
|---|---|---|---|
| Nmap unavailable | "Nmap isn't on this machine's PATH right now — HTTP assessor and ZAP still give us a real multi-tool correlation example." | Skip Nmap in the live run; use the frozen Nmap result (`READY 7.991`, 1 observation) from Block 17A §4/§9 if asked | Yes |
| ZAP unavailable | "ZAP's container isn't running — I'll show the HTTP-assessor-only path live and the ZAP correlation from our frozen record." | Show frozen CSP multi-tool correlation (item 6 above) instead of a live ZAP run | Yes |
| Docker failure | "Docker isn't available on this machine right now, so our containerized target and ZAP aren't reachable." | Switch entirely to the backup walkthrough (frozen evidence) | Yes, via backup |
| Backend port conflict (`8420` in use) | "Something else is using our backend's port — let me free it or use the backup evidence." | `netstat -ano | findstr 8420` to identify and stop the conflicting process if it's safe to do so; otherwise switch to backup walkthrough | Yes |
| Internet/TI source unavailable | "Our threat intel sources need internet access, which isn't available right now — here's a real KEV/NVD/EPSS result from our frozen validation." | Present the frozen CVE-2026-8037 TI record directly | Yes |
| LLM planner timeout/unavailable | "The detection planner step needs a live model call, which isn't responding — here's the real plan it produced during validation." | Present the frozen Sigma/SPL rule JSON directly | Yes |
| Dashboard not loading | "The dashboard's UI isn't rendering — I'll show the same data through the API directly." | `curl`/`Invoke-RestMethod` against `/api/runs`, `/api/runs/{id}`, `/api/runs/{id}/report` live, or fall back to frozen JSON | Yes |

**General principle**: graceful degradation, never silence. If something breaks, say so plainly, name the fallback, and continue — the honest "here's what really happened when we tested this" narrative is itself consistent with ThreatTrace's own stated design philosophy (Slide 13), so a live failure handled openly does not undermine the presentation's credibility.
