# ThreatTrace

ThreatTrace is an AI-powered Purple Team investigation system that traces threats from attack simulation to detection validation.

## Project Objective

The project coordinates authorized Red Team simulations and Blue Team detection validation to identify security gaps, improve detections, and retest security controls.

## Purple Team Loop

1. Ingest and analyze threat intelligence.
2. Identify attacker behaviors and indicators of compromise.
3. Map behaviors to MITRE ATT&CK techniques.
4. Propose a safe Atomic Red Team simulation.
5. Wait for explicit user approval before execution.
6. Review the generated telemetry and security alerts.
7. Determine whether the activity was detected.
8. Recommend detection improvements.
9. Retest after improvements are applied.

## Project Commands

- `/red-team` — Creates an authorized adversary-emulation plan from threat intelligence.
- `/blue-team` — Validates logs, alerts, telemetry, and detection coverage.
- `/threat-hunt` — Investigates unknown anomalies and weak signals using competing hypotheses, telemetry pivots, MITRE ATT&CK mapping, and confidence scoring.

## Project Agent

- `purple-team` — Coordinates the Red Team and Blue Team workflows and manages the complete investigation loop.

The Purple Team agent supports three investigation entry points:

1. Known threat or technique — Red Team led
2. Unknown anomaly — Threat Hunter led
3. Completed simulation — Blue Team led

## Threat Hunter

- The Threat Hunter investigates suspicious behavior that may not have triggered an alert.
- It creates malicious and benign hypotheses.
- It recommends narrowing and broadening telemetry pivots.
- It does not claim compromise without supporting evidence.
- It hands findings to the Purple Team only when evidence suggests attacker behavior or a detection gap.
- Threat Hunter behavior is defined by the project-local `.claude/commands/threat-hunt.md` and the relevant project instructions under `.claude/` — not by any file outside this repository.

## MCP Server

- `supabase` — Stores and retrieves threat intelligence, investigation findings, detection results, and retest information.

## Safety Requirements

- Operate only in an explicitly authorized lab.
- Never target public or third-party systems.
- Never perform destructive actions.
- Never expose passwords, credentials, API keys, or sensitive information.
- Never execute attack simulations automatically.
- Never modify or deploy detection rules automatically.
- Ask for confirmation before performing any action that changes a system.
- Clearly separate confirmed evidence from assumptions.

## Project Rules

- Preserve investigation evidence.
- Map attacker behavior to MITRE ATT&CK when evidence supports it.
- Do not claim that an attack was detected without logs or alerts.
- Request additional telemetry when evidence is incomplete.
- Keep Red Team and Blue Team findings connected through the Purple Team workflow.
