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

## Secrets and Private Telemetry

- Credentials, API keys, access tokens, and other secrets must never be committed to this repository or displayed in any output.
- `.mcp.json` (the real MCP server configuration, including Supabase credentials) must never be committed — only the placeholder `.mcp.example.json` belongs in version control.
- Private telemetry, EVTX files, generated analysis output (CSV/timeline data), and any other locally collected evidence must not be committed. See `.gitignore` for the current exclusion rules and treat any gap in that file as something to fix before committing, not something to work around.
- Absolute local file paths and machine-specific details should not appear in committed documentation or code.

## Reporting a Concern

If you discover a security issue in ThreatTrace itself (not a finding *produced by* ThreatTrace, which belongs in the investigation workflow instead), open an issue describing the concern without including any live credentials, private telemetry, or details about a real, non-lab target.
