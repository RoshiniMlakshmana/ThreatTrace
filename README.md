# ThreatTrace

ThreatTrace is an AI-powered Purple Team investigation system that traces threats from attack simulation to detection validation. It coordinates authorized Red Team simulations and Blue Team detection validation in a single loop, so that every finding — whether it starts from threat intelligence, an unexplained anomaly, or a completed test — ends with a concrete answer about detection coverage.

ThreatTrace is built for **authorized lab environments only**. It does not run attacks, does not touch production or third-party systems, and never takes an action that changes a system state without a human approving it first.

For the current architecture, approval boundary, filesystem boundaries, security limitations, and planned improvements, see [docs/architecture.md](docs/architecture.md).

## Project Structure

```text
ThreatTrace/
├── .claude/
│   ├── agents/          # Purple Team coordinator and Atomic mapper
│   ├── commands/        # Investigation and Purple Team commands
│   ├── hooks/           # Post-write validation
│   └── skills/          # Detection-engineering guidance
├── docs/                # Architecture and demonstration documentation
├── evidence/evtx/       # Local raw EVTX evidence; excluded from Git
├── mcp/                 # Hayabusa MCP server
├── output/hayabusa/     # Generated analysis results; excluded from Git
└── supabase/            # Investigation database schema
```

## Investigation Entry Points

ThreatTrace supports three ways into an investigation, each led by a different role:

1. **Known threat or technique — Red Team led.** Starts from threat intelligence, a known actor's TTPs, an IOC, or a MITRE ATT&CK technique that needs validation. The Red Team workflow proposes a safe, catalog-verified Atomic Red Team test plan.
2. **Unknown anomaly — Threat Hunter led.** Starts from suspicious behavior that has not triggered any alert. The Threat Hunter forms competing hypotheses and pivots through telemetry before deciding whether the finding warrants escalation.
3. **Completed simulation — Blue Team led.** Starts from test results, telemetry, or alerts that already exist. The Blue Team workflow validates whether the activity was actually detected and identifies gaps.

All three entry points converge on the same Purple Team loop: ingest → analyze → map to ATT&CK → propose a simulation → get approval → review telemetry → judge detection → recommend improvements → retest.

## Workflows

- **Threat Hunter** — investigates weak signals and unexplained activity that never triggered an alert. Builds both malicious and benign hypotheses side by side, recommends telemetry pivots (narrowing and broadening), and only hands a finding to the Purple Team when evidence actually supports attacker behavior or points to a detection gap. It never claims compromise without evidence.
- **Red Team** — turns threat intelligence or a supported ATT&CK technique into an authorized adversary-emulation plan, mapped to real, verifiable Atomic Red Team tests. It proposes; it never executes.
- **Blue Team** — validates whether logs, alerts, and detection rules actually caught an authorized simulation, classifying the result as detected, partially detected, not detected, or insufficient telemetry, and identifying the specific gap.
- **Purple Team** — the coordinating agent. It routes investigations between the three entry points, keeps Red Team and Blue Team findings connected, and drives the loop through gap analysis, improvement recommendations, and retesting.

## SOC Analyst Triage and Competing Hypotheses

Before an investigation is escalated or closed, ThreatTrace supports an evidence-grounded SOC analyst triage pass (`/triage-case`) that reviews everything stored against an investigation and reasons about it the way a SOC analyst would: what's confirmed, what's assumed, and what's still missing. Throughout the loop — most explicitly in the Threat Hunter workflow — findings are evaluated against **competing hypotheses** (malicious and benign explanations held simultaneously) rather than a single assumed narrative, so that confidence scores reflect what the evidence actually supports.

## Supabase Case and Evidence Storage

Investigation state lives in Supabase. The schema tracks:

- **investigations** — the root case record: title, entry point, status, and confidence.
- **evidence** — individual telemetry items or observations, each tagged as supporting, contradicting, or neutral toward the working hypothesis.
- **attack_mappings** — MITRE ATT&CK techniques tied to an investigation, marked provisional or supported.
- **handoffs** — every transfer of an investigation between roles (Threat Hunter, Red Team, Blue Team, Purple Team).
- **detection_results** — Blue Team validation outcomes and identified gaps.
- **retests** — planned and completed retests of a detection improvement, gated on explicit approval.

All writes to Supabase (opening a case, adding evidence, updating status) require explicit user confirmation before they happen. Read paths (`/case-summary`, `/purple-loop`) are strictly read-only.

## Hayabusa Offline EVTX Analysis

ThreatTrace integrates [Hayabusa](https://github.com/Yamato-Security/hayabusa) as a local MCP server (`mcp/hayabusa_server.py`) for offline Windows Event Log (EVTX) triage — timeline generation, log metrics, and event-ID metrics. It only ever reads `.evtx` files placed under `evidence/evtx/`, validates every input path against traversal and symlink tricks, and requires an explicit authorization phrase before running. It never reaches outside the local evidence directory and never runs automatically as part of any other workflow.

### Hayabusa Plan and Execute Boundary

- `hayabusa_status`, `list_evtx_files`, and `plan_evtx_analysis` are read-only or planning tools — none of them execute Hayabusa.
- `run_evtx_analysis` is the only Hayabusa tool that executes a process and writes a CSV result.
- Execution currently requires the configured authorization phrase.
- EVTX input paths must remain under `evidence/evtx/`.
- CSV output paths must remain under `output/hayabusa/`.
- Analysis types are selected from a fixed allowlist, not arbitrary input.
- Existing output files cannot be overwritten.
- The authorization phrase is only an initial safeguard — it is not the final human-approval workflow.

## MITRE ATT&CK Mapping

Every supported finding — from Threat Hunter evidence, Red Team intelligence, or Blue Team telemetry — is mapped to MITRE ATT&CK technique IDs, stored with a rationale, and labeled provisional or supported depending on how strong the evidence is. Mappings are never invented; they are only ever tied to a technique the evidence actually justifies.

## Atomic Red Team Planning Only

The `atomic-mapper` agent matches evidence-supported ATT&CK techniques against a locally available [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) catalog and reports verified test matches — name, GUID, supported OS, prerequisites, expected telemetry, and cleanup requirements — pulled only from files it actually read, never fabricated. **It never executes a test.** Execution always requires a separate, explicit, human-approved step outside of ThreatTrace's automated flow.

## Human Approval and Safety Controls

- Operates only in an explicitly authorized lab environment; never targets public or third-party systems; never performs destructive actions.
- **Read-only investigation and planning** (evidence review, hypothesis-forming, ATT&CK mapping, Hayabusa/Atomic planning tools) may proceed without changing any system.
- **Supabase database writes** (opening a case, adding evidence, updating status) require explicit human confirmation before they happen.
- **Red Team or Atomic test execution** requires explicit human approval and is never triggered automatically.
- **Detection rules** must not be modified or deployed automatically, under any circumstance.
- **Other system-changing operations** (e.g. Hayabusa execution) require explicit human confirmation, not just a planning step.
- Approval does not automatically mean execution — each remains a distinct, separately confirmed step.
- Never exposes credentials, API keys, or other sensitive information.
- Clearly separates confirmed evidence from assumptions throughout every workflow.

The following controls are **planned but not yet implemented**: verified approval IDs, evidence hashes, action hashes, approval expiry, reviewer identity validation, and tamper-evident audit history. Today's authorization phrase (see Hayabusa Plan and Execute Boundary, above) is an initial safeguard, not a substitute for these.

## Available Slash Commands

| Command | Purpose |
|---|---|
| `/red-team` | Convert threat intelligence into an authorized adversary-emulation plan |
| `/blue-team` | Validate whether security controls detected an authorized Red Team simulation |
| `/threat-hunt` | Investigate suspicious behavior via competing hypotheses and telemetry pivots |
| `/triage-case` | Evidence-grounded SOC analyst triage of an existing investigation |
| `/open-case` | Open and store a new investigation in Supabase (requires confirmation) |
| `/add-evidence` | Attach a new evidence record to an investigation (requires confirmation) |
| `/update-case` | Update an investigation's status and/or confidence (requires confirmation) |
| `/case-summary` | Read-only summary and timeline of an investigation |
| `/query` | Generate read-only SIEM queries (KQL/SPL) — never executes them |
| `/ingest-ti` | Read-only, structured preview of ingested threat intelligence |
| `/purple-loop` | Read-only router that recommends exactly one safe next command |

## PurpleShadow: Fictional Training Demonstration

ThreatTrace ships a walkthrough built around **PurpleShadow**, an entirely fictional training scenario used to demonstrate the full investigation loop end to end without touching real intelligence or real systems. See [`docs/demo-walkthrough.md`](docs/demo-walkthrough.md) for the full narrative, including how it moves from evidence collection through Red Team routing to a planning-only Atomic Red Team mapping — with no test ever executed.

## Current Limitations

- Investigation state, evidence, and confidence scoring depend entirely on what is manually ingested or queried — there is no live telemetry collection.
- Hayabusa analysis is local and offline only; it does not integrate with a SIEM or EDR platform directly.
- Atomic Red Team mapping is limited to whatever catalog content is locally available under `references/`.
- There is no automated response, containment, or detection-rule deployment by design — every risky step is a human decision.
- Confidence and severity scoring are qualitative (low/medium/high), not statistically derived.
- **Detection Engineering** is currently guidance provided through the `detection-engineering` skill, not a complete, dedicated workflow command.
- **Dedicated validation and retest orchestration** is not yet implemented as its own command — today it is covered only generically (e.g. via `/update-case`).

## Future Enterprise Improvements

- Direct SIEM/EDR API integration for live telemetry pulls instead of manual evidence entry.
- Automated (but still approval-gated) detection-rule staging and version control.
- Multi-analyst collaboration and audit trail on Supabase-stored investigations.
- Expanded Atomic Red Team catalog sync and richer OS/prerequisite filtering.
- Role-based access control aligned to Red Team / Blue Team / SOC analyst boundaries.

## Local Setup

ThreatTrace requires Python 3.10 or later.

### Windows PowerShell

```powershell
py -m pip install -r requirements.txt
```

### macOS or Linux

```bash
python3 -m pip install -r requirements.txt
```

`requirements.txt` contains exactly one dependency, `mcp>=1.28,<2`, which is required by `mcp/hayabusa_server.py`. That file's other imports — `os`, `subprocess`, `datetime`, and `pathlib` — are Python standard library and need no installation. `requirements.txt` does not install Hayabusa itself; the Hayabusa binary must still be placed manually (see below).

**Portability note:** Windows commonly uses the `py` launcher, while macOS and Linux commonly use `python3`. `.mcp.example.json`'s Hayabusa entry (`"command": "python"`) may need to be adjusted to whichever command actually resolves on your system — `py`, `python3`, or `python` — after you copy it to `.mcp.json`.

1. Clone the repository and install the Python dependencies listed in `requirements.txt` (used by the Hayabusa MCP server, `mcp/hayabusa_server.py`).
2. Place the Hayabusa binary and rule files under `tools/hayabusa/` (not committed — see `.gitignore`).
3. Copy `.mcp.example.json` to `.mcp.json` and fill in your own Supabase project reference and access token. **Never commit `.mcp.json`.**
4. Apply `supabase/schema.sql` to your own Supabase project manually (via the Supabase CLI or dashboard) — it is not applied automatically.
5. Place any EVTX evidence under `evidence/evtx/` (git-ignored except for a placeholder).
6. Start Claude Code in the project directory; the configured MCP servers and slash commands become available automatically.

## Responsible-Use Notice

ThreatTrace is intended strictly for authorized security testing, defensive research, and training in environments you own or are explicitly authorized to test. Do not point any part of this system — Red Team planning, Atomic Red Team mapping, or Hayabusa analysis — at systems you do not have explicit, documented authorization to test. All attack-simulation execution and detection-rule changes require a human decision outside of this system's automated flow.
