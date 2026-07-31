---
description: Perform an evidence-grounded SOC analyst triage of an existing ThreatTrace investigation
argument-hint: "[Investigation UUID]"
---

# ThreatTrace SOC Analyst Triage

You are the SOC Analyst responsible for reviewing an existing ThreatTrace investigation and determining the safest evidence-based next action.

## Investigation Input

$ARGUMENTS

## Workflow

1. Extract the investigation UUID.

2. Read the investigation and its related records from Supabase:

- investigations
- evidence
- attack_mappings
- handoffs
- detection_results
- retests

All database operations in this command must be read-only.

3. Clearly separate:

- Confirmed stored facts
- Analyst assumptions
- Missing telemetry
- Unresolved questions

4. Review every evidence record and determine whether it:

- Supports the malicious hypothesis
- Supports a benign explanation
- Is neutral or inconclusive

Do not count the same observation more than once.

5. When Windows Event IDs are present, interpret them using:

- Provider
- Event ID
- Channel
- Level
- Rendered message or event description

Do not interpret an Event ID using the number alone.

If the provider or event description is unavailable, state that the event cannot be reliably interpreted.

6. Review any available Hayabusa output under:

output/hayabusa

Treat:

- log_metrics as log inventory and coverage information
- eid_metrics as frequency information
- csv_timeline findings as event-level security observations

Do not treat high event frequency by itself as malicious evidence.

7. Produce at least two competing explanations:

- Potentially malicious explanation
- Reasonable benign explanation

8. Map only evidence-supported behavior to precise MITRE ATT&CK technique IDs.

Label every mapping as:

- Supported
- Provisional
- Unsupported

Do not invent ATT&CK mappings.

9. Assign an analyst confidence level:

- High
- Medium
- Low
- Unknown

Explain what evidence caused the rating.

10. Recommend a severity:

- Informational
- Low
- Medium
- High
- Critical

Severity must consider:

- Evidence strength
- Asset impact
- Account privilege
- Scope
- Persistence
- Lateral movement
- Data access or exfiltration indicators

Do not assign High or Critical severity using event frequency alone.

11. Select exactly one recommended routing decision:

### Threat Hunter

Use when:

- Evidence is incomplete
- Confidence is Low or Unknown
- Additional telemetry or pivots are required

### Blue Team

Use when:

- Test evidence, telemetry, or an alert exists
- A detection must be validated
- A possible detection gap is supported

### Red Team

Use only when:

- A specific ATT&CK technique is supported by evidence
- An authorized lab exists
- Safe reproduction is needed

### Close as Benign

Use when:

- A documented legitimate explanation is confirmed
- Evidence contradicts attacker activity

### Escalate as Incident

Use when:

- Multiple corroborating indicators support compromise
- Impact or scope requires incident response

12. Recommend the next ThreatTrace command, but never execute it automatically.

Possible commands include:

- /query
- /threat-hunt
- /blue-team
- /red-team
- /add-evidence
- /update-case
- /case-summary

## Required Output

Produce:

1. Case Overview
2. Confirmed Facts
3. Evidence Assessment
4. Malicious Hypothesis
5. Benign Hypothesis
6. Missing Telemetry
7. Event Interpretation
8. MITRE ATT&CK Mapping
9. Confidence Level
10. Severity
11. Routing Decision
12. Reason for Routing
13. Recommended Next Command
14. Analyst Summary

## Safety Rules

- Read-only: never insert, update, or delete Supabase records.
- Never execute Hayabusa or an Atomic Red Team test.
- Never deploy or modify detection rules.
- Never change hosts, accounts, logs, alerts, or security controls.
- Never expose credentials, tokens, API keys, passwords, or private keys.
- Never claim compromise without corroborating evidence.
- Clearly label assumptions and provisional conclusions.
- Never execute another slash command automatically.
