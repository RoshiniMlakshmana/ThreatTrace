---
description: Design and validate evidence-grounded detection logic for ThreatTrace investigations using ATT&CK mappings, expected telemetry, KQL, SPL, and safe validation plans.
---

# ThreatTrace Detection Engineering Skill

Use this skill when the user wants to design, review, improve, or validate a detection for an evidence-supported attacker behavior or MITRE ATT&CK technique.

## Inputs

Accept any combination of:

- ThreatTrace investigation UUID
- MITRE ATT&CK technique ID
- Evidence-supported attacker behavior
- Existing detection rule
- Expected telemetry
- SIEM platform: Microsoft Sentinel or Splunk
- Available log sources
- Verified Atomic Red Team mapping

## Workflow

1. When an investigation UUID is provided:

- Read the investigation from Supabase.
- Read its evidence, ATT&CK mappings, and detection results.
- Use read-only operations only.
- Do not modify the investigation.

2. Separate:

- Confirmed evidence
- Supported ATT&CK mappings
- Provisional mappings
- Assumptions
- Missing telemetry

3. Do not design a detection for a technique that is supported only by speculation.

4. Identify the required telemetry, including where relevant:

- Windows Security Events
- Sysmon
- PowerShell logging
- Microsoft Defender telemetry
- Authentication logs
- DNS or proxy logs
- Process creation
- Scheduled-task events

5. Produce detection logic for the requested platform:

- KQL for Microsoft Sentinel or Defender
- SPL for Splunk
- Sigma-style pseudologic when the platform is not specified

6. Clearly label the query language.

7. Use only read-only search logic.

8. Never generate commands that:

- Disable security controls
- Isolate hosts
- Delete logs
- Modify accounts
- Deploy or enable rules automatically

9. For every proposed detection, explain:

- Detection objective
- Required log source
- Important fields
- Detection conditions
- ATT&CK technique covered
- Expected true-positive behavior
- Likely false positives
- Recommended exclusions
- Severity recommendation
- Investigation steps
- Telemetry gaps

10. When a verified Atomic Red Team mapping exists, create a validation plan containing:

- Atomic test name
- Atomic test GUID
- Expected telemetry
- Success criteria
- Cleanup requirement
- Required authorization

Do not include execution commands or execute the test.

11. Never invent:

- Event fields
- Atomic test details
- Query results
- Detection results
- Existing organizational rules

If the required schema or field name is unknown, label it as a placeholder requiring environment validation.

12. Do not claim a detection works until supporting test telemetry or alert evidence exists.

## Required Output

Produce:

- Detection Objective
- Evidence Basis
- ATT&CK Coverage
- Required Data Sources
- Detection Logic
- KQL, SPL, or Sigma-Style Query
- Important Fields
- False-Positive Analysis
- Recommended Tuning
- Severity Recommendation
- Analyst Investigation Steps
- Atomic Validation Plan
- Success Criteria
- Telemetry Gaps
- Deployment Status
- Recommended Next ThreatTrace Command
- Safety Confirmation

## Safety Rules

- Do not deploy or modify detection rules.
- Do not execute Atomic Red Team tests.
- Do not change hosts, accounts, logs, alerts, or security controls.
- Do not modify Supabase.
- Do not invent evidence, telemetry, fields, or results.
- Clearly distinguish confirmed facts from assumptions.
- Require explicit authorization before recommending any simulation execution.
- Treat every produced rule as a draft until validated in the user's authorized environment.
