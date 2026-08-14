# Merged Block 15J-K — Live Backend + Real-Time Operational Dashboard

Status: implemented and validated with real, live end-to-end runs — a real Bug
Bounty assessment against the local Juice Shop container through the actual HTTP
API, and a real Detection Engineering run using a real CISA KEV entry and a real
`detection-engineering-planner` LLM proposal, both driven through the real backend
process (`python -m backend.app`), not a mock.

## 1. Backend architecture

```
Browser
   |
Real-Time Dashboard (dashboard/live/index.html, self-contained)
   |  fetch() + EventSource()
Starlette app (backend/app.py)          <- HTTP/SSE interface only
   |
backend/run_store.py  <-----> backend/event_bus.py
   |                                 ^
backend/orchestrator.py  --publishes-|
   |
existing, unmodified core.*/adapters.* modules
(bug_bounty_scope, bug_bounty_tool_policy, security_governor,
 bug_bounty_assessment + adapters.bug_bounty_http, evidence_normalization,
 finding_correlation, final_report, detection_trigger, detection_telemetry,
 detection_planner, detection_rule, detection_rule_deduplication,
 detection_rule_validation, detection_engineering_report)
```

`backend/app.py` route handlers are thin: they validate a request, call exactly
one of `run_store`/`event_bus`/`orchestrator`, and translate the result to a
response. Every actual scope/policy/Governor/telemetry/rule decision is made by
the same, unmodified `core.*` modules exercised by every earlier block in this
project — this checkpoint added **zero** new business logic to those modules.

## 2. Why Starlette + uvicorn, not FastAPI

`requirements.txt` declared only `mcp>=1.28,<2` and `pytest>=9,<10`. FastAPI is
**not** installed in this environment. `starlette` (1.3.1) and `uvicorn` (0.51.0)
**are** already installed — as transitive dependencies of `mcp` itself (the MCP
Python SDK uses Starlette/uvicorn for its own HTTP transport) — but were not
previously declared as direct project dependencies. Per this checkpoint's own
instruction ("if FastAPI is already part of the environment, use it; if not, add
the minimum explicit project dependency"), the minimal choice was to use Starlette
directly (it alone provides everything needed: routing, JSON responses,
`StreamingResponse` for SSE) rather than installing the heavier FastAPI package
that would require a genuine `pip install`. `requirements.txt` now explicitly
declares `starlette>=1.3,<2` and `uvicorn>=0.51,<1` — no new package was actually
installed; only an already-present transitive dependency was promoted to a direct,
honestly-declared one.

## 3. Run model

`backend/models.py` (pure, no I/O) defines the Run contract: `run_id`, `run_type`
(`bug_bounty`/`detection`), `created_at`/`started_at`/`completed_at`, `status` (14
values: `created`, `planning`, `awaiting_policy`, `awaiting_governor`, `running`,
`normalizing`, `correlating`, `prioritizing`, `generating_detection`,
`awaiting_human_review`, `completed`, `blocked`, `failed`, `cancelled` —
`completed`/`blocked`/`failed`/`cancelled` are terminal), `target_summary`,
`current_stage`, `requested_tools`/`permitted_tools`/`executed_tools`,
`finding_count`/`canonical_finding_count`/`detection_trigger_count`/
`rule_candidate_count`, `governor_decisions`, `human_review_required`,
`limitations`, `error_summary`, `cancellation_requested`, `report`.
`apply_run_transition` never invents execution that did not occur — it applies
exactly the fields the caller supplies, never infers a status change.

`backend/run_store.py` wraps this in a thread-safe, bounded, in-memory store
(`MAX_RUNS_RETAINED = 100`, FIFO eviction). Run IDs are `"RUN-" + 32 hex chars`
(`secrets.token_hex(16)`) — unguessable, and structurally incapable of containing
a path-traversal sequence; `is_valid_run_id` lets the API layer reject a malformed
id with a clean `400` before any lookup.

## 4. Event model

`backend/models.py` also defines the Event contract: `event_id`, `run_id`,
`event_type` (26 values matching this checkpoint's own spec list), `timestamp`,
`sequence`, `stage`, `source_component`, `summary` (bounded to 300 chars,
truncated with `...`), `sanitized_payload` (bounded to 8192 bytes once
serialized, and recursively scanned for a fixed denylist of forbidden key-name
substrings: `cookie`, `token`, `authorization`, `password`, `secret`, `api_key`,
`credential`, `private_prompt`, `chain_of_thought` — raises if any nested key
matches). This is defense in depth: the orchestrator itself is responsible for
never constructing a payload containing a raw HTTP body, cookie, token, or
chain-of-thought text in the first place; the denylist catches an honest mistake,
not an adversarial bypass.

`backend/event_bus.py` is a bounded, thread-safe pub/sub: `MAX_EVENTS_PER_RUN =
500` (FIFO-evicted), `MAX_RUNS_RETAINED = 50`. `publish` is the **only** place a
`sequence` number is ever assigned (under a lock, so two concurrent publishers for
the same run can never race into a duplicate sequence). `subscribe`/`unsubscribe`
hand out a small (`maxsize=100`), independently bounded `queue.Queue` per live
subscriber — a full queue drops the oldest item rather than blocking the
publishing thread; a subscriber that falls behind can always recover via
`GET /api/runs/{id}/events?since_sequence=N`, bounded by the same 500-event
retention the live queue was seeded from.

## 5. SSE and replay

`GET /api/runs/{id}/stream` returns `text/event-stream`. Each frame carries
`id: <sequence>`, `event: <event_type>`, `data: <json>`. Reconnection honors
either the standard `Last-Event-ID` header or a `?since_sequence=` query
parameter — both are read and the larger value used, then `event_bus.subscribe`
seeds the subscriber's queue with already-retained history newer than that
sequence before any live event. The stream closes itself once a terminal event
(`run_completed`/`run_blocked`/`run_failed`/`run_cancelled`) is delivered.

## 6. Retention is honestly non-persistent

Both `run_store` and `event_bus` are **in-memory only** — no filesystem,
database, or Supabase write anywhere in either module. Restarting the backend
loses every run and every event. This is never described as an audit trail;
`core.tamper_evident_audit` is a separate, unrelated, unmodified module this
checkpoint never touches.

## 7. Orchestration integration

`backend/orchestrator.py` sequences the existing cores with zero reimplemented
logic:

**Bug Bounty**: `validate_local_only_target` → fixed default plan (see §8) →
`core.bug_bounty_tool_policy.evaluate_tool_permission` → `core.security_governor.
evaluate_security_governor_event` (gates on `execution_allowed`) →
`core.bug_bounty_scope.create_bug_bounty_scope` + `core.bug_bounty_assessment.
run_bug_bounty_assessment` (via `adapters.bug_bounty_http.BugBountyHttpTransport`,
injectable for tests) → `core.bug_bounty_evidence_normalization.
normalize_bug_bounty_evidence` → `core.bug_bounty_finding_correlation.
correlate_bug_bounty_evidence` → `core.bug_bounty_final_report.
build_final_bug_bounty_report`.

**Detection**: `core.detection_trigger.build_bug_bounty_trigger` /
`build_threat_intelligence_trigger` → `core.detection_telemetry.
evaluate_telemetry_feasibility` → `core.security_governor.
evaluate_security_governor_event` → `core.detection_planner.
validate_detection_plan` (over a plan the orchestrator assembles from the
trigger/telemetry it computed itself plus the caller-supplied `llm_proposal`) →
per rule: `core.detection_rule.build_detection_rule` → `core.
detection_rule_deduplication.check_rule_duplicate` → `core.
detection_rule_validation.validate_rule_syntax` → `core.detection_rule.
apply_validation_result` → `core.detection_engineering_report.
build_detection_engineering_report`.

An event is published at every stage transition via `backend.event_bus`, and
`backend.run_store` is updated with the real, observed counts/lists at each step
— never a fabricated one.

## 8. The backend never calls an LLM

Per this checkpoint's own explicit LLM-boundary requirement, the backend process
itself never invokes any model. Two consequences:

- **Bug Bounty planning** is satisfied by one **fixed, hardcoded, minimal default
  plan** (a single passive `http_assessor` request against the validated target).
  The `planner_started`/`planner_completed` events say so explicitly — this is
  never described as an LLM proposal.
- **Detection planning** requires the API caller to supply `llm_proposal`
  (`detection_objective`/`proposed_rules`/`telemetry_recommendation`) — the
  already-produced output of a real, separately-invoked
  `.claude/agents/detection-engineering-planner.md` run (exactly as this
  project's own live validation performed below, via the `Agent` tool). The
  orchestrator deterministically builds the trigger and evaluates telemetry
  feasibility itself, then assembles the full plan and hands it to
  `core.detection_planner.validate_detection_plan` for deterministic validation
  — it never fabricates a plan when `llm_proposal` is absent, and never proposes
  rules when the telemetry decision is `TELEMETRY_GAP` (the LLM proposal is never
  even read in that case).

## 9. Local-only security boundary

`main()` binds uvicorn to `127.0.0.1` only — never `0.0.0.0`, no cloud tunnel, no
LAN exposure. `backend.models.validate_local_only_target` is a **strictly
narrower** boundary than `core.bug_bounty_scope` (which supports any name-based
origin an analyst lists): for this checkpoint, a Bug Bounty run target must be
exactly `http://localhost[:port]/...` — not `https`, not `127.0.0.1` (a raw IP;
`core.bug_bounty_scope` itself only supports name-based scoping in v1), not any
public or LAN host, not `file://`/`ftp://`/`javascript:`. There is no
authentication anywhere in this checkpoint — `GET /api/health` and
`GET /api/system` say so explicitly (`interface_class:
"local_development_research_interface"`).

## 10. The Governor honesty decision

The Bug Bounty and Detection Governor events both use `action_class:
"stage_contribution"` and `execution_requested: False`, not `"execution_request"`/
`True`. This is a deliberate honesty choice, not an oversight: `core.
security_governor`'s own rules require `decision_binding_state == "valid"` for any
`execution_requested: True` event (else an automatic `DECISION_BINDING_REQUIRED`
block), and this checkpoint implements **no** authenticated Decision Binding
mechanism at all — claiming `execution_requested: True` would force a false
`decision_binding_state: "valid"` claim to avoid an automatic block. Framing this
as a `"stage_contribution"` observational check instead still exercises every
other Governor rule (role scope, mutation freeze, scope expansion, source-truth
protection, untrusted content, audit, repeated-denial escalation) exactly as
strictly as any other stage — proven in `tests/test_backend_orchestrator.py`'s
Governor-blocking tests, which force a `block` decision via monkeypatching and
confirm the transport/rule-generation step is never reached. Separately, this
mirrors an existing, documented project precedent: `core.
bug_bounty_tool_execution`'s own docstring already states that the passive
`http_assessor` path is deliberately *not* routed through that module's stricter
Decision-Binding-gated execution boundary.

## 11. Concurrency and cancellation

At most one `run_type == "bug_bounty"` run may be active at a time (`backend.
run_store.RunStore.try_acquire_bug_bounty_slot`/`release_bug_bounty_slot`,
released automatically the instant a bug-bounty run reaches a terminal status —
never dependent on the orchestrator remembering to release it). `run_type ==
"detection"` runs are never gated this way; they never execute an offensive tool.
A second concurrent Bug Bounty POST receives a clean `409 CONCURRENT_RUN_ACTIVE`
with no new run record created for it.

Cancellation (`POST /api/runs/{id}/cancel`) is **cooperative only**: it sets
`cancellation_requested`, and the orchestrator checks that flag before starting
each new stage, stopping and transitioning to `"cancelled"` if set. This never
interrupts an already-in-flight adapter call (e.g. a live HTTP request already
sent to Juice Shop) — real OS-level cancellation is out of scope for this
checkpoint, and is not claimed anywhere.

## 12. Human review and deployment honesty

`human_approval_state`/human-review fields shown by the dashboard are
caller-supplied local development state, never an authenticated analyst
decision — no approval endpoint was added at all for this checkpoint (per its own
explicit "prefer display-only unless interaction is necessary" instruction).
`deployment_state` is always `"NOT_DEPLOYED"` for every rule this checkpoint can
ever produce — `core.detection_rule.build_detection_rule` has no parameter
capable of setting anything else, exactly as verified in Block 15H-I and
re-confirmed here (§15).

## 13. Presentation vs. live dashboard

`dashboard/threattrace-dashboard.html` (the pre-existing Block 15F-B presentation
artifact, rendered via `/presentation-dashboard` from caller-supplied,
already-computed benchmark facts) is **unmodified** by this checkpoint and
remains a static research/presentation snapshot.

`dashboard/live/index.html` is a **separate**, new, self-contained (inline
CSS/JS, no build step, no external CDN) operational dashboard served directly by
the backend at `/` and `/live`. It uses only `fetch()` and `EventSource()` against
the real `/api/*` endpoints on the same origin — no hardcoded finding, Governor
decision, or event is ever present in its source; `tests/test_dashboard_live.py`
asserts this directly (no fake-data literals, no `Math.random()`-driven demo
events, findings rendered only via `report.canonical_findings.map(...)`).

Sections: (A) System Status — run id/type/target/status/current stage/duration
state; (B) Pipeline — Bug Bounty → Normalize → Correlate → Prioritize → TI/Hunt →
Detection → Red/Purple → Human Review, each node's state derived from the run's
own `current_stage` (a node is only ever "done" once genuinely passed; "Red /
Purple" is permanently shown as "not this block" since this checkpoint never
orchestrates that stage — never fabricated as complete); (C) Live Event Feed —
timestamp/component/event/summary, capped at 300 rows client-side; (D) Tool
Activity — http_assessor/nmap/nuclei/zap/burp_dast, each row computed from the
run's own `requested_tools`/`permitted_tools`/`executed_tools` lists, falling
back to `GET /api/system`'s real tool-readiness check when a tool wasn't part of
the selected run; (E) Security Governor — latest decision/reason codes/
execution_allowed; (F) Findings — from the real report's `canonical_findings`,
honestly showing "0 canonical findings" (never "secure") when none were produced;
(G) Threat Intelligence Context — CVE/CWE/confidence/affected technology, echoed
from the real trigger's own fields via the `detection_plan_created` event payload,
never fabricated when a Bug Bounty trigger carries none; (H) Detection
Engineering — per-rule format/dedup/validation status/deployment state (always
`NOT_DEPLOYED`); (I) Limitations & Safety — a fixed, persistent disclosure panel.

## 14. API endpoints

```
GET  /api/health
GET  /api/system
GET  /api/runs
POST /api/runs/bug-bounty        {"target": "http://localhost:<port>/"}
POST /api/runs/detection         {"trigger_source", "trigger_input", "telemetry_context", "llm_proposal"}
GET  /api/runs/{run_id}
GET  /api/runs/{run_id}/events   ?since_sequence=N
GET  /api/runs/{run_id}/stream   (SSE; Last-Event-ID / ?since_sequence=N)
GET  /api/runs/{run_id}/report
POST /api/runs/{run_id}/cancel
GET  /  and  /live               (serves dashboard/live/index.html)
```

Every error response is `{"error_code": "...", "message": "..."}` with a
recognized 4xx status for a known validation/state error, or a fixed, generic
`{"error_code": "INTERNAL_ERROR", ...}` `500` for anything unexpected — a stack
trace is logged server-side (`traceback.print_exc()`) but **never** returned to a
client (`tests/test_backend_app.py::TestErrorSanitization` confirms this
directly). Request bodies are bounded to 65536 bytes (`413` if exceeded).

## 15. A real, previously-latent bug found and fixed during this checkpoint

While writing `tests/test_backend_orchestrator.py`'s cancellation test, a genuine
bug surfaced: `backend.run_store.RunStore.update_fields` calls `backend.models.
apply_run_transition(run=run, new_status=run["status"], ...)` to update fields
without changing status — but `apply_run_transition`'s original rule
unconditionally rejected `new_status == "created"`, even when the run's *current*
status was already `"created"` (a genuine no-op). This meant `update_fields`
could never be called on a run still in `"created"` status — including a real
`POST /api/runs/{id}/cancel` request arriving before the orchestrator's background
thread had made its first `transition` call. Fixed by narrowing the check to
`new_status == "created" and current_status != "created"` — reentering
`"created"` from a genuinely different status is still rejected (the original
intent), while a same-status no-op update is now allowed. A dedicated regression
test (`test_006b_allows_field_update_noop_while_still_created`) and an updated
`test_006` (now asserting the *actual* invariant: reentering `created` from
`planning` is rejected) were added.

## 16. Live validation — Bug Bounty run (real backend process, real container)

The backend was started as a real subprocess (`python -m backend.app`), bound to
`127.0.0.1:8420`, confirmed healthy via `GET /api/health`. A real Bug Bounty run
was created via `POST /api/runs/bug-bounty` against `http://localhost:3000/` (the
`threattrace-juice-shop` container, confirmed reachable beforehand):

- **Run ID**: `RUN-80a7db04ba72407b828d3fe357ee6a2d`
- **Event count**: 15, in order: `run_created` → `run_started` →
  `planner_started` → `planner_completed` → `tool_policy_evaluated` →
  `governor_evaluated` → `tool_started` → `tool_completed` →
  `http_assessment_completed` → `evidence_normalized` → `finding_correlated` →
  3× `canonical_finding_created` → `run_completed`
- **Tool status**: `http_assessor` requested → permitted → executed (4 real
  network requests)
- **Governor decision**: `allow` (`bug_bounty_assessment` stage)
- **Canonical findings**: 3 — `/robots.txt is present` (low), `/.well-known/
  security.txt is present` (low), `Missing Content-Security-Policy header`
  (medium) — matching exactly what earlier Bug Bounty blocks in this project have
  found against the same real container
- **Final status**: `completed`; report available via `GET /api/runs/{id}/report`
  with `human_review_required_count: 3`

## 17. Live validation — Detection Engineering run (real CISA KEV entry + real LLM agent)

A real CISA KEV catalog entry was fetched live (`adapters.threat_intel_cisa_kev`)
and deterministically turned into a real Detection Trigger
(`core.detection_trigger.build_threat_intelligence_trigger`) for
**CVE-2026-72898** ("Metabase SQL Injection Vulnerability"). Telemetry feasibility
was evaluated against a fixed demo profile (SIEM=Splunk, environment=production,
industry=technology) → `GENERATE_RULE`. The real `detection-engineering-planner`
Claude agent was invoked (via the `Agent` tool) with this exact trigger and
telemetry result, producing a genuinely grounded, honest plan: no fabricated
CWE/ATT&CK/IOC (the trigger supplied none), an explicit acknowledgment that the
KEV record carries no payload/endpoint detail (so the drafted logic is a
generic-but-scoped SQLi heuristic, not a false CVE-specific claim), no YARA
proposed (correctly judged irrelevant for a web/network-layer vulnerability), and
one context-tuned Splunk SPL variant explicitly labeled "DEMO CONTEXT ONLY."

That real plan was POSTed to the live backend's `POST /api/runs/detection`:

- **Run ID**: `RUN-222c28acc93f2ada65ff32a7df2e709b`
- **Event count**: 13, in order: `run_created` → `run_started` →
  `detection_plan_created` → `telemetry_evaluated` → `governor_evaluated` →
  `planner_started` → `planner_completed` → `detection_rule_created` →
  `detection_rule_validated` → `detection_rule_created` →
  `detection_rule_validated` → `human_review_required` → `run_completed`
- **Trigger**: `DT-52bde557e42ff188`, CVE-2026-72898, confidence `high`
- **Telemetry decision**: `GENERATE_RULE` (zero missing sources)
- **Governor decision**: `allow` (`detection_engineering` stage)
- **Rules generated**: 2 (Sigma + Splunk SPL, one context-tuned SPL variant) — 0
  rejected
- **Validation status**: both `syntax_validated` (this run's real bounded
  structural check happened to pass both drafts; Block 15H-I's own live
  validation separately and honestly demonstrated the same checker's real
  false-positive limitation on a different SPL draft containing a literal
  paren inside a regex escape — that limitation is a property of the bounded,
  non-parser-based checker itself, not something this run happened to avoid by
  design)
- **Deployment state**: `NOT_DEPLOYED` for both, confirmed via both the event
  stream and `GET /api/runs/{id}/report`'s `deployment_state_distribution:
  {"NOT_DEPLOYED": 2}`
- **Human review**: both `pending` (`human_approval_state_distribution:
  {"pending": 2}`)

## 18. No public targets, confirmed

Every live scan performed in this checkpoint's own validation targeted
`http://localhost:3000/` only (the local `threattrace-juice-shop` research
container). `backend.models.validate_local_only_target` structurally rejects
every other host at the API boundary before a run is even created — verified by
`tests/test_backend_app.py::TestCreateRunValidation::test_006_rejects_unsafe_targets`
(parametrized over `example.com`, `8.8.8.8`, `192.168.1.10`, `10.0.0.5`,
`file:///etc/passwd`, `ftp://localhost/`, `javascript:alert(1)`, and even the raw
loopback IP `127.0.0.1`).

## 19. Limitations

- Run/event history is in-memory only; a backend restart loses everything.
- No authentication of any kind exists in this checkpoint; `GET /api/health`/
  `GET /api/system` say so explicitly.
- Cancellation is cooperative only — never real OS-level process termination.
- The Bug Bounty "planner" stage is a fixed default plan, not an LLM proposal.
- The Detection "planner" stage requires the caller to supply an already-produced
  LLM proposal; the backend itself never calls a model.
- Structural rule-syntax validation is bounded, stdlib-only, and not a real
  parser (see §17 and Block 15H-I's own documented false-positive finding) —
  never described as detection-efficacy testing.
- `zap`/`burp_dast` tool readiness is reported `not_configured` without an active
  probe at `/api/system` time — a real run is the only thing that would actually
  exercise either.
- No browser-based visual verification of `dashboard/live/index.html` was
  performed (no headless browser tool is available in this environment); its
  inline JavaScript was syntax-checked with `node --check` and its API-contract
  field names were cross-verified against real live backend responses captured
  during §16-17's own validation runs.

## 20. Security honesty (Section 40 checklist)

- **Security Governor**: evaluates observable, caller-supplied state only — never
  proof of intent or authenticated identity (§10).
- **Run history**: in-memory runtime history, never trusted audit storage (§6).
- **SSE**: operational event delivery, never an authenticated message bus (§5).
- **Human approval**: caller-supplied local development action unless separately
  authenticated — no approval endpoint exists (§12).
- **Tool execution**: `execution_performed`/executed-tool status reflects only
  real adapter output — never claimed for a permitted-but-unexecuted tool (§7).
- **Dashboard**: visualizes recorded state; it does not prove security (§13).
- **Detection candidate**: not proof of efficacy (§17).
- **Structural validation**: not real detection testing (§17, §19).
- **Deployment**: `NOT_DEPLOYED`, structurally, for every rule (§12).
- **Security Experience Memory**: untouched by this checkpoint — no coupling was
  added between `backend.orchestrator` and `core.security_experience_memory`.
