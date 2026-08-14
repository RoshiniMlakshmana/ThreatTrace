# ThreatTrace Demo Runbook (Technical Operator Runbook)

This is a **technical operator runbook**, not a presentation script — it walks an authorized operator through the current Bug Bounty / Detection Engineering / live platform workflow, deterministically and reproducibly, on a local machine. For the original fictional **PurpleShadow** investigation-loop walkthrough, see [docs/demo-walkthrough.md](demo-walkthrough.md). Block 17B will build the actual presentation script from this runbook.

Every command below is shown for **Windows PowerShell** (the platform this project was developed and validated on) with a **macOS/Linux Bash** equivalent alongside it. See [Cross-Platform Status](#cross-platform-status) at the end.

## Prerequisites

- Python 3.10+, with `pip install -r requirements.txt` already run.
- Docker Desktop (or an equivalent Docker daemon) running, if you want the Juice Shop/ZAP demo containers.
- Nothing else is strictly required — `http_assessor` is pure Python.

## 1. Check readiness

```powershell
py -m runtime.bootstrap check
```
```bash
python3 -m runtime.bootstrap check
```

Expected shape (real values vary by machine):

```
ThreatTrace Runtime Readiness (platform: Windows)

HTTP Assessor          READY
Nmap                   REQUIRES_ADMIN_INSTALL
Nuclei                 MISSING
Nuclei Templates       READY
Docker                 READY 29.3.1
ZAP                    CONTAINER_AVAILABLE
Burp DAST              NOT_CONFIGURED
Authenticated Testing  NOT_IMPLEMENTED
Controlled Validation  NOT_IMPLEMENTED
```

`http_assessor` being `READY` is all that's required for the rest of this runbook. Nmap/Nuclei/ZAP/Burp are optional — see [Failure Modes](#failure-modes) below if you want them and they aren't ready.

## 2. Start demo dependencies

```powershell
py -m runtime.bootstrap start-demo --with-zap
```
```bash
python3 -m runtime.bootstrap start-demo --with-zap
```

This starts the local Juice Shop container (`threattrace-juice-shop`, bound to `127.0.0.1:3000`) and, with `--with-zap`, the local ZAP container (`threattrace-zap`, bound to `127.0.0.1:8080`) if Docker reports it `container_available`. Omit `--with-zap` if you only want the Bug Bounty `http_assessor` path. Add `--dry-run` first if you want to see exactly what would run without executing anything.

Equivalent via Docker Compose:

```bash
docker compose --profile zap up -d      # Juice Shop + ZAP
docker compose up -d                    # Juice Shop only
```

## 3. Start the backend

```powershell
py -m backend.app
```
```bash
python3 -m backend.app
```

This binds `127.0.0.1:8420` only. Confirm it's up:

```powershell
Invoke-RestMethod http://127.0.0.1:8420/api/health
```
```bash
curl -s http://127.0.0.1:8420/api/health
```

Expected: `{"status":"ok","backend_version":"1","bind":"127.0.0.1:8420","interface_class":"local_development_research_interface"}`.

## 4. Open the live dashboard

Open `http://127.0.0.1:8420/` in a browser. You'll see "No active run." in every section — that's the correct, honest empty state, not an error.

## 5. Run a Bug Bounty workflow

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8420/api/runs/bug-bounty `
  -ContentType "application/json" -Body '{"target":"http://localhost:3000/"}'
```
```bash
curl -s -X POST http://127.0.0.1:8420/api/runs/bug-bounty \
  -H "Content-Type: application/json" -d '{"target":"http://localhost:3000/"}'
```

Response: `{"run_id":"RUN-...","status":"created"}`. Watch it complete either in the dashboard (select the new run from the dropdown) or by polling:

```powershell
Invoke-RestMethod http://127.0.0.1:8420/api/runs/RUN-...
```
```bash
curl -s http://127.0.0.1:8420/api/runs/RUN-...
```

## 6. Observe the Governor decision

In the completed run's JSON (or the dashboard's "Security Governor" panel), look at `governor_decisions`:

```json
"governor_decisions": [{"stage": "bug_bounty_assessment", "decision": "allow"}]
```

A real `block`/`freeze` decision would appear here if role scope, mutation freeze, or scope-expansion rules were violated — the run would stop at `status: "blocked"` with the tool never executed. See [SECURITY.md](../SECURITY.md#security-governor-limitations) for what a Governor decision does and does not prove.

## 7. Inspect canonical findings

```powershell
Invoke-RestMethod http://127.0.0.1:8420/api/runs/RUN-.../report
```
```bash
curl -s http://127.0.0.1:8420/api/runs/RUN-.../report
```

Look at `report.canonical_findings` — each entry carries `status: "requires_human_review"`. Against a stock Juice Shop container you should typically see findings like a missing `Content-Security-Policy` header and the presence of `/robots.txt`/`/.well-known/security.txt`.

## 8. Run a Threat Intel / Detection example

Detection runs require a real trigger input and (for a non-`TELEMETRY_GAP` result) an already-produced LLM proposal — the backend never calls an LLM itself (see [docs/block15jk-live-platform-dashboard.md](block15jk-live-platform-dashboard.md#8-the-backend-never-calls-an-llm)). The simplest reproducible path uses a real canonical finding from step 7 as the trigger:

```bash
curl -s -X POST http://127.0.0.1:8420/api/runs/detection \
  -H "Content-Type: application/json" \
  -d '{
    "trigger_source": "bug_bounty",
    "trigger_input": <one canonical_finding object from step 7>,
    "telemetry_context": {"available_telemetry": [], "siem": "Splunk"}
  }'
```

With `available_telemetry: []`, this deterministically produces `TELEMETRY_GAP` and zero proposed rules — see the next step.

## 9. Observe the telemetry gate

```json
"telemetry_evaluated": {"decision": "TELEMETRY_GAP", "missing_sources": [...]}
```

`rule_candidate_count` on the completed run will be `0`. This is the honest, structurally-enforced outcome when there's no basis to propose a rule — ThreatTrace never fabricates one. To see a real `GENERATE_RULE` result with actual rule candidates, supply `available_telemetry` matching the trigger's `required_telemetry_candidates`, plus a real `llm_proposal` (`detection_objective`/`proposed_rules`/`telemetry_recommendation`) obtained by separately invoking the `detection-engineering-planner` Claude agent — see [docs/block15hi-threat-intel-detection-engineering.md](block15hi-threat-intel-detection-engineering.md) for a full worked example.

## 10. Inspect a rule candidate and verify NOT_DEPLOYED

Once a `GENERATE_RULE` run has produced rule candidates:

```powershell
Invoke-RestMethod http://127.0.0.1:8420/api/runs/RUN-.../report
```
```bash
curl -s http://127.0.0.1:8420/api/runs/RUN-.../report
```

Check `report.deployment_state_distribution` — it will read `{"NOT_DEPLOYED": N}` for every rule this system can ever produce. This is a structural guarantee (`core.detection_rule.build_detection_rule` has no parameter capable of setting anything else), not merely today's configuration.

## 11. Shutdown

```powershell
py -m runtime.bootstrap stop-demo
```
```bash
python3 -m runtime.bootstrap stop-demo
```

Then stop the backend process (`Ctrl+C` in the terminal running `python -m backend.app`). Run history is in-memory only — it is gone the moment the backend process stops.

## Failure Modes

| Symptom | Likely cause | What to do |
|---|---|---|
| `python -m runtime.bootstrap check` shows `Docker MISSING` | Docker not installed or not on `PATH` | Install Docker Desktop; re-run the check |
| Docker shows `RUNTIME_UNAVAILABLE` | Docker CLI present but daemon not running | Start Docker Desktop; re-run the check |
| `Nmap REQUIRES_ADMIN_INSTALL` | Nmap/Npcap require an administrator-performed host install on Windows | Install Nmap + Npcap manually as administrator; ThreatTrace never does this automatically |
| `Nuclei MISSING` | Nuclei binary not on `PATH` | Install Nuclei to a user-local location and add it to `PATH`; no admin required |
| `Nuclei Templates MISSING` | No `~/nuclei-templates` directory (or `THREATTRACE_NUCLEI_TEMPLATES_DIR` unset/empty) | Run `nuclei -update-templates` manually — ThreatTrace never runs this for you |
| `ZAP RUNTIME_UNAVAILABLE` | Docker not ready, or the `threattrace-zap` container's API isn't responding | Re-check Docker; `docker logs threattrace-zap` |
| `ZAP CONTAINER_AVAILABLE` | Docker is ready but no `threattrace-zap` container is running yet | `python -m runtime.bootstrap start-demo --with-zap` |
| `Burp DAST NOT_CONFIGURED` | No `THREATTRACE_BURP_API_KEY` set | Expected unless you've configured an external Burp runtime — see `.env.example` |
| Juice Shop unreachable at `http://localhost:3000/` | Container not started, or a port conflict | `python -m runtime.bootstrap start-demo`; check `docker ps` for a port conflict on `3000` |
| `POST /api/runs/bug-bounty` returns `409 CONCURRENT_RUN_ACTIVE` | Another Bug Bounty run is still in progress | Wait for it to reach a terminal status, or check `GET /api/system`'s `active_bug_bounty_run_id` |
| Backend fails to bind `127.0.0.1:8420` | Another process already using that port | Stop the other process, or check what's bound to it (`netstat -ano \| findstr 8420` on Windows, `lsof -i :8420` on macOS/Linux) |
| `python -m backend.app` fails to import | `starlette`/`uvicorn` not installed | `pip install -r requirements.txt` again — both are declared dependencies |

## Cross-Platform Status

This project was developed and live-validated on **Windows** (PowerShell, `py` launcher, Docker Desktop). It is **expected to work on macOS/Linux where the same dependencies are available, but has not been validated there** — treat any macOS/Linux-specific behavior as unverified until someone actually runs it and reports back. `runtime.tool_runtime.check_nmap` in particular has Windows-specific `requires_admin_install` framing; on macOS/Linux a missing Nmap is reported plain `missing` instead, since neither platform requires the same Npcap-driver administrator install Windows does.
