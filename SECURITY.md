# Security Policy

## Scope of Use

ThreatTrace is designed to operate **only within explicitly authorized lab environments**. It must never be pointed at public infrastructure, third-party systems, or any environment for which the operator does not hold documented authorization to test.

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

## Current Security Limitations

- The validation hook runs after `Write` or `Edit` operations and is advisory rather than a preventive `PreToolUse` gateway.
- No project-level AI Agent Gateway currently validates every tool call.
- Verified approval IDs, reviewer identity validation, evidence hashes, action hashes, approval expiry, immutable audit history, action budgets, and kill-switch controls are planned but not implemented.
- Supabase Row Level Security is enabled in the schema, but application access policies are not yet defined.

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
