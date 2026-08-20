# ThreatTrace

ThreatTrace runs an authorized bug bounty-style scan, then walks the results through threat intel review, detection engineering, and human review — with every AI proposal deterministically re-checked before anything runs.

ThreatTrace is a **research prototype**, not a production security product. See [Current Maturity](#current-maturity) and [Known Limitations](#known-limitations) before relying on it for anything beyond local, authorized research.

## What does it do?

```
Seed target
   |
HTTP Assessor / httpx / bounded crawler / Katana   (discovery)
   |
Nmap / Nuclei / ZAP                                 (scanning, bounded + policy-gated)
   |
Evidence Normalization -> Correlation -> Findings
   |
(Full Lifecycle only) Prioritization -> Threat Intel -> Threat Hunt -> Detection Engineering -> Red Validation -> Purple Recommendation
   |
Human Review
```

Every stage above is either a deterministic Python module or a real, bounded external tool call — an AI proposal (used only in the Detection Engineering step) is always re-validated by non-AI code before it becomes a rule candidate, and nothing is ever deployed automatically.

## Quick Start

**Prerequisites:** [Git](https://git-scm.com/) and [Docker](https://docs.docker.com/get-docker/) (with Compose v2). Nothing else — no Python, Nmap, Nuclei, httpx, Katana, or ZAP install required.

```bash
git clone <repo-url>
cd ThreatTrace
docker compose up -d --build
```

Open **http://127.0.0.1:8420**.

## Run your first demo

Target field is pre-filled with `http://localhost:3000` (the bundled local [Juice Shop](#juice-shop-demo) container — never a public target). Click:

- **New Bug Bounty Run** — fast, bounded scan only (HTTP Assessor / httpx / crawler / Katana / Nmap / Nuclei / ZAP), or
- **Run Full Security Lifecycle** — the Bug Bounty scan, then real Context Prioritization, Threat Intel/Hunt review, Detection Engineering review, a Red Validation fact-check, and Purple remediation recommendations for the highest-priority findings.

Watch the live event feed, pipeline, and cards below populate as the run progresses.

## What will I see?

| Card | What it shows |
|---|---|
| **Findings** | Canonical findings correlated across tools, with severity, confidence, evidence source count, and CWE/OWASP/CVE/MITRE ATT&CK classification (honestly "Not mapped" when no behavioral evidence supports an ATT&CK technique). |
| **Attack Surface Discovery** | A human-readable summary of what was crawled/discovered, plus a per-endpoint breakdown (what it is, how it was found, whether it was fetched). |
| **HTTP Enrichment (httpx)** | Reachability, status, page title, technology/server headers — observation only, never a vulnerability claim. |
| **Threat Intelligence / Security Lifecycle Detail** | Per-finding review outcome (e.g. "no relevant intel," "telemetry gap") with the real reason, never a fabricated "detected" claim. |
| **Detection Engineering** | Whether a rule candidate was generated, and if not, exactly why (e.g. missing telemetry) — a rule is always `NOT_DEPLOYED`. |
| **Purple Recommendations** | A finding-specific remediation/retest recommendation — a recommendation only, never a claim that remediation was applied. |
| **Human Review** | Stays `AWAITING REVIEW` until a human explicitly approves or rejects each selected finding — a local, unauthenticated development action, never a claim of authenticated analyst sign-off. |
| **Accuracy & Evaluation** | Precision/recall/F1 against a fixed, supported Juice Shop benchmark subset — never a general accuracy claim (Demo target only). |

## Test your own authorized system

Switch **Target Mode** to **Authorized External Target** to scan a system you own or are explicitly authorized to test. You provide the target URL and an explicit scope (allowed host(s), port(s), path prefix(es), and which tools may run — HTTP Assessor/httpx/Katana are on by default; Nmap/Nuclei/ZAP are opt-in, since some bug-bounty programs restrict automated scanning). You must check the acknowledgment box before a run can start.

**This acknowledgment is an operator assertion only — ThreatTrace does not verify or establish that you actually hold legal authorization to test the target.** You are responsible for confirming that yourself, and for following any additional rules a bug-bounty program or client engagement imposes on automated tooling. See [Security Boundaries](#security-boundaries) and [docs/authorized-use.md](docs/authorized-use.md).

## Stop

```bash
docker compose down
```

---

The rest of this document is advanced/reference material: architecture detail, the full command reference, the host-native (non-Docker) setup path, testing, and the current security/maturity model.

## What ThreatTrace Is Not

To avoid over-claiming, ThreatTrace explicitly is **not**:

- a fully autonomous security platform or fully autonomous pentester,
- a production SOC replacement,
- a zero-day prevention system,
- a system that detects 100% of vulnerabilities,
- production-ready SIEM automation.

Every workflow below ends in a human-reviewed artifact (a finding, a draft detection rule, an investigation update) — none of them deploys, remediates, or acts on a system without a separate, explicit human decision.

## Project History

**Block 6 — Risk-Aware Multi-Review Approval Workflow is complete.** See [docs/block6-risk-aware-approvals.md](docs/block6-risk-aware-approvals.md) for the full design, the security-control table, and live Supabase verification evidence.

Investigation-changing actions are now gated by deterministic risk classification, one- or two-person approval depending on that risk, an immutable review history, atomic execution, and replay protection.

**Block 7 — Shadow Execution / Digital Twin MVP is complete.** See [docs/block7-shadow-execution.md](docs/block7-shadow-execution.md) for the full design, the security-control table, and honest live-verification status. `/simulate-case-update` calculates a deterministic before/after preview of an approved case-update action — current state, proposed state, changed and unchanged fields, fixed deterministic warnings, and a rollback-feasibility classification — through a mutation-free command that never touches the database beyond two existing read-only lookups.

A read-only live verification was attempted against the connected Supabase project and was honestly blocked (`LIVE_VERIFICATION_BLOCKED_NO_EXISTING_APPROVAL`) because no approval record currently exists there; no synthetic data was created to force it.

**Block 8 — AI Agent Gateway / Runtime Firewall MVP is complete.** See [docs/block8-agent-gateway.md](docs/block8-agent-gateway.md) for the full design, the security-control table, and demonstration evidence. `/evaluate-tool-call` runs a proposed AI-agent tool call through an immutable, in-code tool registry and a deterministic policy engine — returning `allow`, `require_approval`, or `deny` with strict argument validation and safe redaction, through a command that never executes the tool it evaluates.

**Block 9 — Agent Identity and Least Privilege MVP is complete.** See [docs/block9-agent-identity.md](docs/block9-agent-identity.md) for the full design, the security-control table, and demonstration evidence. `/evaluate-agent-tool-call` resolves a caller-supplied *claimed* agent ID against a fixed, immutable registry — fixed roles, per-agent tool allowlists, operation-class ceilings, and a mutation-request capability flag — and deterministically narrows Block 8's own `allow`/`require_approval`/`deny` decision accordingly. `identity_authenticated` is always `false` and `execution_performed` is always `false` in every report: a registry match is never treated as authentication, and this command never executes the tool it evaluates.

3,900+ automated tests pass, with one intentional Windows-only Hayabusa symlink-permission test skip. A local, non-mutating five-scenario demonstration (analyst allow, observer allowlist denial, analyst mutation denial, coordinator require_approval, unknown-agent denial) completed successfully with no agent authenticated and no tool, database, or external process ever executed. **Block 10** begins with a separate, read-only architecture audit whose exact scope has not yet been selected.

Blocks 10 through 15L-16 — AI asset inventory, AI Security Evaluation Lab, analyst feedback, tamper-evident audit, the Bug Bounty engine, Threat Intelligence ingestion, Detection Engineering, the Security Governor, the live platform backend, and reproducible packaging — are each documented in their own `docs/block*.md` file and summarized in [docs/architecture.md](docs/architecture.md), rather than repeated here as a growing changelog.

## The Problem Being Addressed

Security teams sit on three disconnected streams of work: offensive findings (what's actually exploitable), threat intelligence (what's actually being exploited elsewhere), and detection engineering (what would actually catch it). Each stream is usually its own tool, its own analyst, and its own backlog — so a real finding can go months without a corresponding detection rule, and a piece of threat intel can go unactioned because nobody connects it to what the organization's own telemetry could support. ThreatTrace's Purple Team loop exists to close that gap deterministically: every finding or intel record is evaluated for whether it can be *meaningfully detected* before any rule is drafted, and every drafted rule stays a human-reviewed candidate — never an auto-deployed control.

## Architecture

```
LLM reasoning layer (Claude agents: propose, interpret, explain — never authorize)
        |
Deterministic security cores (core/*.py — validate, enforce, record)
        |
Tool Permission Policy  ->  Security Governor  ->  tool adapters (adapters/*.py)
        |
Evidence Normalization -> Correlation -> Final Report
        |
Threat Intelligence  ->  Detection Engineering  ->  NOT_DEPLOYED rule candidates
        |
backend/ (Starlette, 127.0.0.1-only)  ->  in-memory Run Store / Event Bus (SSE)
        |
dashboard/live/  (real-time operational dashboard)
```

The full component-by-component breakdown — including the explicit distinction between a *functional role*, a *Claude custom agent*, a *policy identity*, and a *deterministic core service* (ThreatTrace does not have "eight autonomous agents"; it has a small number of real Claude agents and a much larger set of deterministic Python modules) — lives in [docs/architecture.md](docs/architecture.md).

## Key Capabilities

| Area | What it does |
|---|---|
| **Bug Bounty engine** | Runs a bounded, scope-checked assessment against an analyst-approved target using an LLM-proposed, deterministically-validated tool plan. |
| **Threat Intelligence ingestion** | Pulls from CISA KEV, NVD/CVE, EPSS (all real, unauthenticated, bounded) and computes deterministic multi-source corroboration. |
| **Detection Engineering** | Turns a Bug Bounty finding or a TI record into a telemetry-feasibility-gated, LLM-proposed, deterministically-validated draft detection rule (Sigma/SPL/KQL/YARA). |
| **Security Governor** | A deterministic policy engine every stage-changing action passes through — role scope, mutation freeze, scope expansion, untrusted-content, and Decision Binding checks. |
| **Real-time dashboard** | Live SSE-driven operational view of an in-progress run — pipeline stage, tool activity, Governor decisions, findings, rule candidates. |
| **Purple Team investigation loop** | The original ThreatTrace loop — Threat Hunter, Red Team, Blue Team, SOC triage, Hayabusa EVTX analysis, Atomic Red Team planning-only mapping — all persisted in Supabase. |
| **Tool Runtime Manager** | Deterministic readiness detection for every tool ThreatTrace can call, with explicit states (`ready`/`missing`/`requires_admin_install`/`container_available`/...) instead of a bare true/false. |

## Bug Bounty Workflow

```
Analyst-supplied scope
  -> LLM Planner proposes a tool plan
  -> Tool Permission Policy (deterministic: is this tool/target/path actually permitted?)
  -> Security Governor (deterministic: does this action cross a policy boundary?)
  -> HTTP / httpx / Crawler / Katana / Nmap / Nuclei / ZAP / Burp adapter boundary (only implemented, permitted tools ever run)
  -> Evidence Normalization -> Correlation (multi-tool corroboration, deduplication)
  -> Final Bug Bounty Report (status is always requires_human_review)
```

The LLM never executes a tool directly — every tool call is re-validated by deterministic policy and Governor code before `adapters/*.py` is ever reached. See [docs/block15a-bug-bounty-agent.md](docs/block15a-bug-bounty-agent.md), [docs/block15g-intelligent-bug-bounty-planner.md](docs/block15g-intelligent-bug-bounty-planner.md), and [docs/block15g-cd-multitool-correlation.md](docs/block15g-cd-multitool-correlation.md).

## Threat Intelligence Workflow

Real, bounded, unauthenticated pulls from CISA KEV, NVD/CVE, and EPSS are normalized into one common record contract, then deterministically corroborated (`unconfirmed` / `single_source` / `corroborated` / `authoritative_source` / `conflicting`) — the LLM never assigns a corroboration state itself. TAXII/MISP/OpenCTI/authenticated-Telegram sources are supported as a real code boundary but honestly report `not_configured` without any credential. See [docs/block15hi-threat-intel-detection-engineering.md](docs/block15hi-threat-intel-detection-engineering.md).

## Detection Engineering Workflow

```
Bug Bounty finding  OR  Threat Intel record
  -> Detection Trigger (deterministic)
  -> Telemetry Feasibility (deterministic gate: is there a basis to even attempt a rule?)
  -> Detection Planner (LLM proposes objective + rule drafts, only in relevant formats)
  -> deterministic plan validation -> rule construction -> deduplication -> structural syntax validation
  -> Human Review required
  -> deployment_state = NOT_DEPLOYED, always
```

A `TELEMETRY_GAP` trigger structurally forces zero proposed rules — ThreatTrace never fabricates a rule when there is no basis to detect the underlying behavior. Structural syntax validation is bounded and stdlib-only; it is explicitly **not** detection-efficacy testing. See [docs/block15hi-threat-intel-detection-engineering.md](docs/block15hi-threat-intel-detection-engineering.md).

## Security Governor

Every Bug Bounty and Detection Engineering stage transition is evaluated by `core/security_governor.py` against sixteen fixed, closed-vocabulary event fields — role scope, gateway/identity decisions, mutation freeze, scope expansion, source-truth protection, untrusted-remote-content adoption, audit bypass, Decision Binding, and repeated-denial escalation. A Governor decision (`allow`/`warn`/`require_review`/`block`/`freeze`) is an **evaluation outcome over caller-supplied observable state** — never proof of intent, never an authenticated identity claim, and never itself an enforcement action (it recommends; the caller enforces). See [docs/block15c5-security-governor.md](docs/block15c5-security-governor.md).

## Real-Time Dashboard

`backend/` (Starlette + uvicorn, `127.0.0.1:8420` only) orchestrates the same deterministic cores above and publishes a structured, sanitized event stream over SSE. `dashboard/live/index.html` is a self-contained (no build step) operational view — system status, pipeline progression, live event feed, tool activity, Governor decisions, findings, Threat Intelligence context, and detection rule candidates (always shown `NOT_DEPLOYED`). Run history is in-memory only — restarting the backend loses it; this is explicitly **not** an audit store. See [docs/block15jk-live-platform-dashboard.md](docs/block15jk-live-platform-dashboard.md).

## Purple Team Investigation Loop

ThreatTrace's original investigation loop remains fully in place alongside the newer Bug Bounty/Detection stack:

- **Threat Hunter** — investigates weak signals via competing malicious/benign hypotheses; never claims compromise without evidence.
- **Red Team** — turns threat intelligence or a supported ATT&CK technique into an authorized adversary-emulation plan mapped to real, verifiable [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests. It proposes; it never executes.
- **Blue Team** — validates whether logs/alerts/detection rules actually caught an authorized simulation.
- **Purple Team** — the coordinating agent that routes between the three entry points and drives gap analysis, improvement recommendations, and retesting.
- **[Hayabusa](https://github.com/Yamato-Security/hayabusa)** — offline Windows Event Log (EVTX) triage via a local MCP server; reads only `evidence/evtx/`, requires an authorization phrase to execute, never reaches outside the project.
- **Supabase** — the persistence layer for investigations, evidence, ATT&CK mappings, handoffs, detection results, and retests. All writes require explicit human confirmation; the read paths (`/case-summary`, `/purple-loop`) are strictly read-only.

See [docs/demo-walkthrough.md](docs/demo-walkthrough.md) for the fictional **PurpleShadow** training scenario that exercises this loop end to end, and [docs/demo-runbook.md](docs/demo-runbook.md) for the current Bug Bounty/Detection/backend operator runbook.

## Approval-Gated Case Updates

Investigation `status`/`confidence` changes are never applied directly — the old direct-write behavior is unavailable. They go through a three-command, approval-gated workflow instead:

```
/request-case-update
→ /review-approval
→ /apply-case-update
```

- `/request-case-update` creates one pending approval for a proposed `status`/`confidence` change. **It does not update the investigation.**
- `/review-approval` lets a reviewer approve or reject that pending approval. It changes only the approval record. **It does not update the investigation.**
- `/apply-case-update` atomically consumes an approved, unconsumed approval and applies its stored change to the investigation. **This is the only command that updates the investigation**, and it does so through one atomic database operation.
- `/update-case` is a deprecated, static compatibility command. It performs no lookup, no validation, and no database operation of any kind — typed confirmation was never authorization, and it is no longer accepted at all. The command only redirects the caller to `/request-case-update`.

`requested_by`, `reviewed_by`, and `consumed_by` are caller-supplied **claimed identities** — none of them is authenticated, verified, cryptographically proven, or derived from Supabase Auth.

Every request is also **classified for risk** the moment it is created: the system, never the caller, decides whether the change needs one reviewer or two, based on the investigation's own trusted, live `status`/`confidence` and the proposed change. See [docs/block6-risk-aware-approvals.md](docs/block6-risk-aware-approvals.md) for the full risk model, review lifecycle, and security controls.

### Examples

Request a pending approval:

```
/request-case-update {"investigation_id":"11111111-1111-4111-8111-111111111111","requested_by":"analyst@example.com","status":"investigating"}
```

Approve the pending approval:

```
/review-approval {"approval_id":"22222222-2222-4222-8222-222222222222","decision":"approve","reviewed_by":"reviewer@example.com"}
```

Atomically apply the approved request:

```
/apply-case-update {"approval_id":"22222222-2222-4222-8222-222222222222","consumed_by":"operator@example.com"}
```

## Available Slash Commands

Investigation-loop commands (the platform's newer Bug Bounty/Detection/live-platform commands are listed in [Quickstart](#quickstart) and [docs/demo-runbook.md](docs/demo-runbook.md) instead of duplicated here):

| Command | Purpose |
|---|---|
| `/red-team` | Convert threat intelligence into an authorized adversary-emulation plan |
| `/blue-team` | Validate whether security controls detected an authorized Red Team simulation |
| `/threat-hunt` | Investigate suspicious behavior via competing hypotheses and telemetry pivots |
| `/triage-case` | Evidence-grounded SOC analyst triage of an existing investigation |
| `/open-case` | Open and store a new investigation in Supabase (requires confirmation) |
| `/add-evidence` | Attach a new evidence record to an investigation (requires confirmation) |
| `/request-case-update` | Request a pending approval to change an investigation's status and/or confidence |
| `/review-approval` | Approve or reject a pending case-update approval |
| `/apply-case-update` | Atomically apply an approved, unconsumed case-update approval |
| `/update-case` | Deprecated — static guidance only; performs no update and redirects to `/request-case-update` |
| `/case-summary` | Read-only summary and timeline of an investigation |
| `/query` | Generate read-only SIEM queries (KQL/SPL) — never executes them |
| `/ingest-ti` | Read-only, structured preview of ingested threat intelligence |
| `/purple-loop` | Read-only router that recommends exactly one safe next command |

## Supported Tools

| Tool | Purpose | Readiness states this checkpoint can report |
|---|---|---|
| `http_assessor` | Passive/safe-active HTTP assessment (pure Python) | always `ready` |
| `httpx` | Bounded HTTP enrichment (status/title/technology/server) of one already-validated target | `ready` / `missing` |
| `crawler` | Bounded, same-origin ThreatTrace discovery crawl | always `ready` (pure Python) |
| `katana` | Bounded, non-headless discovery crawl (second, independent discovery engine) | `ready` / `missing` |
| `nmap` | Network reconnaissance | `ready` / `requires_admin_install` (Windows) / `missing` |
| `nuclei` | Template-based web vulnerability scanning | `ready` / `missing` |
| `zap` | Active/passive DAST via a local Docker container | `ready` / `container_available` / `runtime_unavailable` |
| `burp_dast` | DAST via an analyst-configured external Burp runtime | `ready` / `not_configured` |
| `authenticated_testing` | Declared, not implemented | `not_implemented` |
| `controlled_validation` | Declared, not implemented | `not_implemented` |

`httpx`/`katana` are packaged inside the Docker image (pinned release binaries, same discipline as Nuclei) — no host install needed for the Docker path.

Run `curl http://127.0.0.1:8420/api/system` (Docker) or `python -m runtime.bootstrap check` (host-native) for a live readiness report — see [Quickstart](#quickstart).

## Quickstart

The default, recommended way to run ThreatTrace is **Docker** — no host installation of Python, Nmap, Npcap, Nuclei, or ZAP required, on any platform.

**Prerequisites:** [Docker](https://docs.docker.com/get-docker/) (with Compose v2) and Git. Nothing else.

```bash
git clone <repo-url>
cd Threattrace
docker compose up -d --build
```

Then open **http://127.0.0.1:8420** — the dashboard should immediately show System Readiness with Backend/Governor/HTTP Assessor/Nmap/Nuclei/ZAP/Threat Intelligence/Detection Engineering all `READY` (Burp DAST shown separately, under Optional Integrations). Click **New Bug Bounty Run** to scan the bundled local [Juice Shop](#juice-shop-demo) demo target, and watch the live event feed, Governor decisions, and canonical findings populate.

```bash
docker compose ps       # container + health status
docker compose logs -f threattrace
docker compose down     # stop and remove everything
```

Full architecture, port map, the demo-target-alias model, and production-deployment guidance: [docs/docker-self-hosted-deployment.md](docs/docker-self-hosted-deployment.md).

### Advanced: host-native development

Running the backend directly under a local Python interpreter (rather than in Docker) is still supported, and is the more convenient path if you're actively editing ThreatTrace's own source. It requires **Python 3.10+** (developed and validated on **Windows**; see [Cross-Platform Status](#cross-platform-status)) and, for Nmap/Nuclei/ZAP, either host installs or the demo Docker containers described below.

```powershell
py -m pip install -r requirements.txt        # Windows PowerShell
```
```bash
python3 -m pip install -r requirements.txt   # macOS / Linux
```

`requirements.txt` declares `mcp>=1.28,<2` (used by `mcp/hayabusa_server.py` and by the `backend/` package's transitively-included `starlette`/`uvicorn`). No proprietary tool (Nmap, Nuclei, Burp) is installed by this step — see [Supported Tools](#supported-tools) and `python -m runtime.bootstrap check`.

Optional, tool-specific setup:

1. Place the Hayabusa binary and rule files under `tools/hayabusa/` (not committed — see `.gitignore`).
2. Copy `.mcp.example.json` to `.mcp.json` and fill in your own Supabase project reference and access token, if you intend to use the Purple Team investigation loop. **Never commit `.mcp.json`.**
3. Copy `.env.example` to `.env` and fill in real values only for the optional variables you actually need (e.g. a configured Burp runtime). **Never commit `.env`.**
4. Apply `supabase/schema.sql` to your own Supabase project manually, if using the investigation loop.

Host-native quickstart:

1. Clone the repository.
2. Create a Python 3.10+ environment and `pip install -r requirements.txt`.
3. Run the readiness check: `python -m runtime.bootstrap check`.
4. Start demo dependencies: `python -m runtime.bootstrap start-demo --with-zap`.
5. Start the backend: `python -m backend.app` (binds `127.0.0.1:8420` only).
6. Open the live dashboard: `http://127.0.0.1:8420/`.
7. Run the local Juice Shop demo from the dashboard, or `curl -X POST http://127.0.0.1:8420/api/runs/bug-bounty -d '{"target":"http://localhost:3000/"}'`.
8. Inspect the live event feed, canonical findings, and (for a Detection run) the rule candidates — always `NOT_DEPLOYED`.
9. Stop demo dependencies: `python -m runtime.bootstrap stop-demo`.

Don't run both the Docker stack and a host-native backend against port `8420` at the same time. Full step-by-step detail, including how to exercise the Governor and Detection Engineering paths explicitly, is in [docs/demo-runbook.md](docs/demo-runbook.md).

## Juice Shop Demo

ThreatTrace's live Bug Bounty/Detection validation runs against a local [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) container, bound to `127.0.0.1:3000` only — never a public target. This is the same fixed research target the [supported-category benchmark](#research-framing) below is measured against.

## Research Framing

ThreatTrace includes a bounded, reproducible benchmark against the local Juice Shop target — see `core/benchmark_evaluation.py`, `core/juice_shop_ground_truth.py`, and [docs/block15f-juice-shop-dashboard.md](docs/block15f-juice-shop-dashboard.md) for the reproduction path. Results are reported strictly as **"on this fixed, supported-category Juice Shop benchmark, precision/recall/F1 were X"** — never as "ThreatTrace is N% accurate," and never generalized beyond the vulnerability categories the benchmark actually covers.

## Security Boundaries

- Operates only in explicitly authorized lab environments — see [docs/authorized-use.md](docs/authorized-use.md).
- No automatic attack execution, containment, or detection-rule deployment anywhere in the system.
- Every risky action requires a separate, explicit human decision outside ThreatTrace's automated flow.
- The `backend/` local platform binds `127.0.0.1` only, implements no authentication, and is explicitly not production-hardened.
- **Only test systems you own or are explicitly authorized to assess.** ThreatTrace's Authorized External Target mode requires an operator-declared scope and an explicit acknowledgment checkbox, but **this does not establish that you have legal permission** to test the target — that determination is always the operator's own responsibility. Bug-bounty platforms may impose additional restrictions on automated tools beyond what ThreatTrace itself enforces (exact hostname/port/path scoping, an SSRF destination-network check, and a conservative default tool set); the operator must still follow the program's actual rules.
- Full detail: [SECURITY.md](SECURITY.md).

### Internal network deployment

An organization may point the self-hosted Docker stack at its own internal, explicitly-scoped target instead of (or alongside) the public Juice Shop demo:

```
Organization server (internal, explicitly authorized)
   |
Docker Compose (this repository's docker-compose.yml)
   |
ThreatTrace backend (127.0.0.1-only by default)
   |
Authorized External Target scope (exact host/port/path, operator-declared)
```

The current v0.1 interface is **not production-authenticated** — there is no login, no RBAC, and no multi-user session model. Before any multi-user or production-facing internal deployment, add: TLS termination, SSO/authentication in front of the dashboard, RBAC, persistent (not in-memory) audit storage, secrets management for any credentials the deployment needs, and network isolation for the worker process. None of these exist in this checkpoint.

## Known Limitations

- Local research prototype — not a production security product.
- No production authentication anywhere in the system.
- `backend/` run/event history is in-memory only — lost on restart, never a tamper-evident audit trail.
- Burp DAST requires an analyst-configured external runtime; ThreatTrace never bundles or auto-installs Burp.
- `authenticated_testing` and `controlled_validation` are declared but not implemented.
- No automatic SIEM deployment — every drafted detection rule is `NOT_DEPLOYED`.
- The Detection/Bug Bounty LLM planner steps require either an interactive Claude Code session or a backend caller that already obtained a structured LLM proposal externally — `backend/` itself never calls a model.
- Not every finding or TI record yields a useful detection rule — a `TELEMETRY_GAP` honestly proposes zero rules.
- Structural rule-syntax validation is not detection-efficacy validation.
- Live validation has been performed primarily on **Windows**, against the local Juice Shop container — see [Cross-Platform Status](#cross-platform-status).
- Authorized External Target mode's SSRF protection resolves and rejects loopback/link-local/private/reserved destinations before connecting, but does not pin the validated IP for the subsequent connection — a narrow DNS-rebinding race between validation and connect is a known, disclosed limitation (see `adapters/bug_bounty_http.py`), not a claim of full rebinding resistance.
- Not yet externally security-reviewed and not intended for production/multi-user deployment as-is — see [Internal network deployment](#internal-network-deployment) for what's still missing.

## Repository Structure

```text
ThreatTrace/
├── .claude/
│   ├── agents/          # Purple Team coordinator + Bug Bounty/Detection planner Claude agents
│   ├── commands/        # Investigation, Bug Bounty, Detection, and platform-startup commands
│   └── skills/          # Detection-engineering guidance skill
├── adapters/             # Real I/O boundaries (HTTP/Nmap/Nuclei/ZAP/Burp/TI sources)
├── backend/              # Local-only Starlette backend, Run Store, Event Bus, orchestrator
├── core/                 # Pure, deterministic security/policy/report logic
├── dashboard/
│   ├── threattrace-dashboard.html   # Static presentation/research snapshot
│   └── live/                        # Real-time operational dashboard
├── docs/                 # Architecture, security, per-block design docs, runbooks
├── evidence/evtx/         # Local raw EVTX evidence; excluded from Git
├── mcp/                   # Hayabusa MCP server
├── output/hayabusa/       # Generated analysis results; excluded from Git
├── runtime/               # Tool Runtime Manager + bootstrap CLI
├── supabase/               # Investigation database schema
├── tests/                  # Focused + regression test suites
├── docker-compose.yml       # Local demo dependencies (Juice Shop, optional ZAP)
└── .env.example              # Placeholder-only environment configuration
```

## Testing

ThreatTrace distinguishes three test scopes:

```powershell
# Focused: one new module's own suite
py -m pytest tests/test_runtime_tool_runtime.py -q

# Bounded regression: everything touched by a specific block
py -m pytest tests/test_backend_*.py tests/test_runtime_*.py -q

# Full regression: the entire suite
py -m pytest tests/ -q
```

At the Block 15L-16 checkpoint, the full regression passed 7,391 tests with 1 intentional Windows-only skip (Hayabusa symlink permissions) — a **checkpoint result, not a current guarantee**. Always re-run the suite locally rather than trusting this or any other historical count.

(macOS/Linux: replace `py` with `python3`.)

Historical pass counts reported in per-block docs (e.g. *"at the Block 15J-K checkpoint, 7,300 tests passed"*) are **checkpoint results, not current guarantees** — always re-run the suite locally rather than trusting an old count.

## Current Maturity

**ThreatTrace v0.1.0 — research prototype / early release** (see [`VERSION`](VERSION)). This does not yet follow strict release discipline and should not be treated as a stable API contract. ThreatTrace has been developed and live-validated on Windows against local, authorized targets (a local Juice Shop container, a local ZAP container). It has not undergone external security review, has no production authentication, and is not intended for deployment outside a local research/lab environment. See [docs/architecture.md](docs/architecture.md) for the full block-by-block build history and [SECURITY.md](SECURITY.md) for the current security model.

## License

**License: Apache-2.0.** See [`LICENSE`](LICENSE) for the full, unmodified license text. This license covers ThreatTrace's own source code in this repository only — it does not relicense Nmap, Nuclei, ZAP, httpx, Katana, or OWASP Juice Shop, each of which remains under its own upstream project's own license (see [docs/licensing-notes.md](docs/licensing-notes.md) for the full third-party licensing review, including why no `NOTICE` file is included).

Copyright 2026 Roshini Gowda.

## Responsible-Use Notice

ThreatTrace is intended strictly for authorized security testing, defensive research, and training in environments you own or are explicitly authorized to test. See [docs/authorized-use.md](docs/authorized-use.md) for the full policy. Do not point any part of this system at a target you do not have explicit, documented authorization to test.
