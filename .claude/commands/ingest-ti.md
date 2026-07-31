---
description: Ingest and analyze threat intelligence into a structured, read-only preview for ThreatTrace, without touching Supabase or any indicator
argument-hint: "[threat report text, actor/campaign name, IOC list, advisory, or file path]"
---

# ThreatTrace Threat Intelligence Ingestion Workflow

You extract, structure, and analyze threat intelligence for ThreatTrace. You never contact indicators, never execute anything, and never write to Supabase — this command only produces a structured preview.

## Threat Intelligence Input

$ARGUMENTS

## Workflow

1. Accept threat-intelligence content in any of these forms:

- threat report text
- threat actor or campaign name
- IOC list
- security advisory
- file path containing authorized threat-intelligence content

If a file path is given, read it as inert text only.

2. Extract:

- report title
- source
- publication date when available
- threat actor or campaign
- targeted industries or platforms
- indicators of compromise
- malware or tools
- attacker behaviors and procedures
- vulnerabilities and CVEs
- MITRE ATT&CK techniques

3. Clearly separate:

- confirmed information taken directly from the supplied source
- analytical assumptions you are adding
- information that is missing or uncertain

4. Validate indicators by format only (regex/pattern shape, not liveness or reputation):

- IPv4 or IPv6 address
- domain
- URL
- file hash (MD5/SHA1/SHA256 length and character set)
- email address
- CVE identifier

5. Do not contact, browse to, resolve, execute, detonate, or scan any indicator. Format validation only.

6. Map supported attacker behaviors to precise MITRE ATT&CK technique IDs (not just tactic names).

7. Mark every ATT&CK mapping as either:

- supported (directly evidenced by the source content)
- provisional (inferred or incomplete)

8. Identify potential investigation opportunities:

- threat hunting hypotheses
- relevant telemetry sources
- possible detection opportunities
- possible Red Team validation opportunities

9. Recommend the appropriate ThreatTrace entry point for this intelligence:

- known_threat
- unknown_anomaly
- completed_simulation

10. Display a structured preview of everything extracted and analyzed.

11. Do not automatically create an investigation, evidence record, ATT&CK mapping, handoff, detection result, or retest in Supabase.

12. When the intelligence warrants opening a case, recommend the user run `/open-case` themselves — do not execute it or any other command automatically.

## Required Output

Produce:

- Threat Intelligence Summary
- Source Assessment
- Confirmed Findings
- Indicators of Compromise
- Threat Actor Behaviors
- MITRE ATT&CK Mapping
- Assumptions and Intelligence Gaps
- Threat Hunting Opportunities
- Detection Opportunities
- Red Team Validation Opportunities
- Recommended Entry Point
- Recommended Next Command
- Safety Confirmation

## Safety Rules

- Do not browse to or interact with indicators.
- Do not execute malware, scripts, commands, or payloads.
- Do not scan public or third-party systems.
- Do not treat unverified intelligence as confirmed fact.
- Do not modify Supabase — no insert, update, or delete.
- Do not execute another slash command automatically.
- Never expose or store passwords, API keys, tokens, credentials, or private keys.
