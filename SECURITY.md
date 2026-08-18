# Security Policy

## Scope of Use

ThreatTrace is designed to operate **only within explicitly authorized lab environments**. It must never be pointed at public infrastructure, third-party systems, or any environment for which the operator does not hold documented authorization to test.

This applies equally to the Bug Bounty engine (`core.bug_bounty_*`, `adapters.bug_bounty_*`) and the live platform backend (`backend/`): `backend.models.validate_local_only_target` structurally rejects any Bug Bounty run target whose host is not exactly `localhost` — no public host, no LAN host/IP, not even the raw loopback IP `127.0.0.1` (only name-based `localhost` scoping is supported). The `backend/` process itself binds `127.0.0.1:8420` only and is never exposed to a LAN or the public internet. See [docs/authorized-use.md](docs/authorized-use.md) for the full policy.

## Execution Boundaries

- **No automatic attack execution.** Red Team proposals, Atomic Red Team mappings, and threat-intelligence analysis produce plans and recommendations only. Running an actual test is always a separate, deliberate, human-initiated action outside of ThreatTrace's automated flow.
- **No automatic containment or response.** ThreatTrace never isolates hosts, blocks indicators, disables accounts, or takes any other containment or remediation action on its own.
- **Human approval required for risky actions.** Any action that changes a system, deploys or modifies a detection rule, writes to Supabase, or executes a simulation requires explicit, informed user confirmation before it happens.

## Evidence-Grounded Decisions

- Findings, ATT&CK mappings, and detection verdicts must be grounded in evidence that was actually collected or observed — never assumed or fabricated.
- Confirmed evidence is always clearly distinguished from working hypotheses or assumptions.
- Low-confidence findings are not escalated, and compromise is not claimed, without supporting evidence.
- When evidence is incomplete, the correct response is to request additional telemetry, not to proceed on assumption.

## Current Enforcement Status

- Read-only evidence analysis and action planning may proceed without changing systems.
- Supabase writes, case updates, Red Team or Atomic test execution, detection-rule changes, and other system-changing actions require explicit human confirmation.
- Approval and execution are separate actions — an approval must not automatically trigger execution.
- ThreatTrace currently uses written safety instructions and initial technical safeguards, but the complete human-approval gateway is not implemented yet.

### Current Hayabusa Safeguards

- EVTX inputs are restricted to `evidence/evtx/`.
- CSV outputs are restricted to `output/hayabusa/`.
- Analysis types come from a fixed allowlist.
- Existing output files are not overwritten.
- `plan_evtx_analysis` does not execute Hayabusa.
- `run_evtx_analysis` is the only current Hayabusa execution tool.
- Execution currently requires an authorization phrase.
- The authorization phrase is an initial safeguard, not the final approval system.

## Approval-Gated Case Updates

Investigation `status`/`confidence` changes are never applied directly.

- A proposed change becomes one pending approval via `/request-case-update`. No investigation update occurs at request time.
- `/review-approval` changes only the approval record — approved or rejected. It never updates the investigation.
- `/apply-case-update` applies the change through exactly one atomic PostgreSQL RPC, `consume_approval_and_update_investigation_state`, which consumes the approval and updates the investigation together in the same database transaction.
- The applied `status`/`confidence` values come only from the approval's own stored `action_payload` — never from a value supplied directly to `/apply-case-update`.
- The atomic RPC is the final authority against TOCTOU (time-of-check to time-of-use) changes: it independently re-checks the approval's status, expiry, and stored bindings against the live database row inside its own transaction, not against whatever an earlier lookup returned.
- An approved request can be consumed successfully exactly once. Every replay attempt fails closed as a persistence conflict, never as a silent success.
- Expiry is checked at the moment of atomic consumption, not only at request or review time.
- `PUBLIC`, `anon`, and `authenticated` cannot execute the atomic RPC. Only `service_role` (and the function owner) retain `EXECUTE` permission on it.
- `requested_by`, `reviewed_by`, and `consumed_by` are caller-supplied **claimed identities** — none of them is authenticated, verified, cryptographically proven, or derived from Supabase Auth.

This workflow does not implement Supabase Auth, cryptographic identity verification, action hashing, immutable history, risk-tiered approval, full two-person approval for every action, or credential management — those remain planned for later blocks.

## Bug Bounty / Detection Engineering Security Model (Blocks 15A–15H-I)

- Every Bug Bounty tool execution requires, in order: analyst-supplied scope/permissions validated by `core.bug_bounty_scope`, a `core.bug_bounty_tool_policy.evaluate_tool_permission` result with `execution_permitted: True`, and a Governor result with `execution_allowed: True` — `core.bug_bounty_tool_execution` never proceeds without both, and never accepts a caller-supplied boolean claiming either is already true.
- The tool adapter registry (`adapters.bug_bounty_{http,nmap,nuclei,zap,burp,httpx,katana}`) is a fixed, hardcoded Python mapping — there is no code path by which a `tool_id` string selects an arbitrary binary.
- `authenticated_testing` and `controlled_validation` are declared capabilities with `implemented: False` in `core.bug_bounty_tool_policy.TOOL_CATALOG` — no adapter exists for either, and analyst permission alone can never make an unimplemented adapter run.
- Detection rule candidates are drafts, never proof of detection efficacy. `core.detection_rule.build_detection_rule` has **no parameter capable of setting `deployment_state` to anything but `NOT_DEPLOYED`** — this is a structural guarantee, not a policy choice that could be silently bypassed by a caller.
- Structural rule-syntax validation (`core.detection_rule_validation`, bounded, stdlib-only) is explicitly **not** detection-efficacy testing, and never claims to be.
- A `TELEMETRY_GAP` telemetry-feasibility result structurally forces zero proposed rules (`core.detection_planner.validate_detection_plan` raises if a caller attempts otherwise) — ThreatTrace never fabricates a rule when there is no basis to detect the underlying behavior.

## Authorized External Target Security Model (Final Pre-Release Block)

- `backend.models.validate_authorized_external_target_scope` is the sole entry point for a non-Demo-Mode target. It requires the caller-declared `operator_scope_acknowledged` field to be the literal `True` -- this is a **caller/operator assertion only**, never proof that ThreatTrace has verified real-world legal authorization to test the declared target.
- Scope is exact-hostname only in this checkpoint -- a `*` in any declared host is rejected (`EXTERNAL_SCOPE_WILDCARD_NOT_ALLOWED`), even though the underlying `core.bug_bounty_scope` engine itself supports a single leading wildcard label. No CIDR ranges, subdomain brute forcing, or automatic scope expansion are supported at all -- there is structurally no field for any of them in this contract.
- Only a fixed set of tool ids (`http_assessor`/`crawler`/`httpx`/`katana`/`nmap`/`nuclei`/`zap`/`burp_dast`) can ever be requested through this endpoint; a tool the operator did not explicitly list in `scope.allowed_tools` can never become policy-permitted for that run, regardless of what is installed.
- Every proposed request against an Authorized External Target is still independently re-evaluated by `core.bug_bounty_scope.evaluate_bug_bounty_request_scope` before being sent -- including every redirect hop -- exactly like a Demo Mode run. There is no `external_mode = bypass_scope` shortcut anywhere in this codebase.
- `adapters.bug_bounty_http.BugBountyHttpTransport` additionally performs a real destination-network check (`allow_private_destinations=False`, the default for every Authorized External Target run) before connecting: the target hostname is resolved, and the request is rejected if any resolved address is loopback, link-local (this covers the well-known `169.254.169.254` cloud-metadata address), private (RFC1918 / IPv6 unique-local), reserved, multicast, or unspecified. **This is not full DNS-rebinding resistance** -- the validated address is not pinned for the subsequent connection, so a narrow TOCTOU window between validation and connect remains; this is a disclosed, known v1 limitation, never claimed as eliminated. The Demo Mode path (`allow_private_destinations=True`, unchanged) is deliberately exempt, since the trusted `juice-shop` Docker-network alias is itself a private address by construction.
- Katana's own discovered URLs are **untrusted candidate data** (see `adapters.bug_bounty_katana`'s own module docstring) -- the adapter performs no scope evaluation itself; `backend.orchestrator._merge_katana_discoveries_into_attack_surface` independently re-validates every single one before it is ever merged into the attack-surface inventory or exposed to any other tool.

## Security Governor Limitations

`core.security_governor.evaluate_security_governor_event` evaluates **caller-supplied observable state only**. Concretely:

- A Governor `decision` (`allow`/`warn`/`require_review`/`block`/`freeze`) is an evaluation outcome over the sixteen fields it was given — never proof that the caller's claimed `actor_role`, `gateway_decision`, or `identity_decision` was actually authenticated.
- The Governor performs no I/O, calls no LLM, and never inspects free-text reasoning or a chain-of-thought transcript — only the fixed, closed-vocabulary event fields.
- `execution_performed` is always `False` in every Governor result — the Governor recommends; it never itself executes, blocks, or terminates anything. Enforcement is the caller's separate responsibility.
- A `block`/`freeze` decision is a deterministic recommendation this module returns — never a daemon, never something the Governor module itself enacts.

## Decision Binding Limitations

`decision_binding_state` is one of the sixteen Governor event fields, but **no real cryptographic Decision Binding mechanism is implemented anywhere in this repository**. Every module that constructs a Governor event supplies this field as caller-asserted observable state, exactly like every other field. `backend.orchestrator`'s own Bug Bounty and Detection Governor events deliberately use `action_class: "stage_contribution"` and `execution_requested: False` rather than falsely claiming `decision_binding_state: "valid"` to avoid the Governor's own automatic `DECISION_BINDING_REQUIRED` block for an `execution_requested: True` event — see [docs/block15jk-live-platform-dashboard.md](docs/block15jk-live-platform-dashboard.md#10-the-governor-honesty-decision) for the full rationale. Treat `decision_binding_state: "valid"` anywhere in this codebase as **asserted, not authenticated**, until a real binding mechanism is built.

## Evidence Digest Limitations

Every `evidence_digest`/`evidence_id` computed across this codebase (`core.bug_bounty_evidence_normalization`, `core.bug_bounty_findings`, `core.security_handoff`, etc.) is a SHA-256 digest over the record's own content, used exclusively for **content correlation** — detecting when two observations describe the same underlying evidence. None of them is ever a claim of cryptographic authenticity, remote-response integrity, or non-repudiation. A digest proves two records are byte-identical in content; it proves nothing about who produced the underlying HTTP response, whether it was tampered with in transit, or whether the source system was itself compromised.

## Live Platform Backend Security Model (Block 15J-K)

- `backend/app.py` binds `127.0.0.1:8420` only — never `0.0.0.0`, never a LAN interface, no cloud tunnel, no reverse proxy configuration anywhere in this repository.
- **No authentication of any kind is implemented.** `GET /api/health`/`GET /api/system` say so explicitly (`interface_class: "local_development_research_interface"`). Anyone with local access to the machine (or anything that can reach `127.0.0.1` on it) can call every endpoint.
- Run/event history (`backend.run_store`, `backend.event_bus`) is **in-memory only** — never written to disk, a database, or Supabase, and never described as an audit trail. Restarting the backend loses everything.
- `POST /api/runs/{id}/cancel` and any human-review state the dashboard displays are **caller-supplied local development actions**, never an authenticated analyst decision, unless a separate authentication mechanism is added in a future block.
- Every event published to `backend.event_bus` is bounded (≤8192 bytes serialized) and recursively scanned for a fixed denylist of forbidden key-name substrings (`cookie`, `token`, `authorization`, `password`, `secret`, `api_key`, `credential`, `private_prompt`, `chain_of_thought`) before it can ever be stored — defense in depth, not a guarantee that the orchestrator itself never constructs an unsafe payload (it is independently responsible for that too).
- The backend never calls an LLM itself — see [docs/block15jk-live-platform-dashboard.md](docs/block15jk-live-platform-dashboard.md#8-the-backend-never-calls-an-llm).

## No Automatic SIEM Deployment

Nothing in this repository writes to, configures, or deploys against a real SIEM/EDR platform. Detection rule candidates are structured text (Sigma/SPL/KQL/YARA) held in-memory or returned in an API response — `core.detection_rule`'s structural `NOT_DEPLOYED` guarantee (above) means no code path in this repository can ever change that without a future, explicitly-scoped block adding real deployment integration.

## Tool Runtime Manager Security Model (Block 15L-16)

- `runtime.tool_runtime` only *detects* tool/runtime availability — it never runs an install, update, or privilege-elevation command. A missing Nmap/Npcap on Windows is reported `requires_admin_install`, never silently worked around or auto-installed.
- Every subprocess invocation in `runtime.tool_runtime`/`runtime.bootstrap` uses a fixed, closed `argv` list with `shell=False` — no LLM-generated command, and no caller-supplied string, is ever concatenated into a shell command.
- `runtime.bootstrap start-demo` only ever starts two fixed, named containers (`threattrace-juice-shop`, `threattrace-zap`), both bound to `127.0.0.1` only; `stop-demo` only ever stops those same two fixed names — never an arbitrary or pre-existing container.

## Current Security Limitations

- The validation hook runs after `Write` or `Edit` operations and is advisory rather than a preventive `PreToolUse` gateway.
- No project-level AI Agent Gateway currently validates every tool call automatically.
- Verified approval IDs, reviewer identity validation, evidence hashes, action hashes, approval expiry, immutable audit history, action budgets, and kill-switch controls are planned but not implemented.
- Supabase Row Level Security is enabled in the schema, but application access policies are not yet defined.
- `backend/` implements no authentication; it is a local development/research interface only, never production-hardened.
- Real Decision Binding (see above) is not implemented anywhere in this repository.
- `authenticated_testing` and `controlled_validation` remain declared, not implemented.
- No automatic SIEM/EDR deployment exists anywhere in this repository.

For the detailed approval boundary, filesystem boundary, and planned security improvements, see [docs/architecture.md](docs/architecture.md).

## Secrets and Private Telemetry

- Credentials, API keys, access tokens, and other secrets must never be committed to this repository or displayed in any output.
- Never commit:
  - `.mcp.json`
  - `.claude/settings.local.json`
  - `.env` or other environment files
  - Supabase access tokens or project credentials
  - raw EVTX evidence
  - generated Hayabusa output
  - local binaries
  - third-party repositories
- Only the placeholder `.mcp.example.json` belongs in version control for MCP configuration.
- See `.gitignore` for the current exclusion rules and treat any gap in that file as something to fix before committing, not something to work around.
- Absolute local file paths and machine-specific details should not appear in committed documentation or code.

## Security Verification

Contributors should run the full test suite locally before proposing changes:

### Windows PowerShell

```powershell
py -m pytest tests/ -q
```

### macOS or Linux

```bash
python3 -m pytest tests/ -q
```

- Tests verify path validation, the fixed analysis allowlist, authorization rejection, no-overwrite protection, and that planning cannot reach execution.
- Hayabusa-capable subprocess calls are mocked.
- The real Hayabusa binary is never executed.
- Tests use temporary evidence and output directories, not the repository's real evidence.

## Reporting a Concern

If you discover a security issue in ThreatTrace itself (not a finding *produced by* ThreatTrace, which belongs in the investigation workflow instead), open an issue describing the concern without including any live credentials, private telemetry, or details about a real, non-lab target.

- Never publish credentials, private telemetry, real-target details, or unpatched exploit details in a public issue.
- For a sensitive ThreatTrace vulnerability, create only a minimal non-sensitive issue asking the maintainers for a private reporting method.
- Do not publish reproduction details that could expose users before a fix.
- Non-sensitive documentation, testing, or configuration concerns may be reported normally.
