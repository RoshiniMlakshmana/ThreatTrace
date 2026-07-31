# Demo Walkthrough: PurpleShadow

> **PurpleShadow is entirely fictional training data.** No part of this walkthrough refers to a real threat actor, a real organization, or a real incident. It exists solely to demonstrate how a finding moves through the full ThreatTrace investigation loop, from evidence to a planning-only Atomic Red Team mapping, without ever executing a test.

## 1. Investigation Creation

The walkthrough opens a single investigation for the fictional "PurpleShadow" scenario using `/open-case`, entered as a **known-threat** entry point (Red Team led), since the starting input is a fabricated threat-intelligence summary rather than an unexplained anomaly or completed test evidence. The case is created with an initial status of `open` and confidence `unknown`, pending evidence.

## 2. Evidence Collection

Two evidence records are added to the investigation via `/add-evidence`, each after explicit confirmation:

1. A record describing scripting-based execution activity consistent with a living-off-the-land technique.
2. A record describing scheduled-task creation activity used for persistence.

Both records are stored with a source description and a note on whether they support the working hypothesis — neither is treated as confirmed compromise on its own.

## 3. MITRE ATT&CK Mapping

Based on the two evidence records, the investigation is mapped to two ATT&CK techniques:

- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1053.005** — Scheduled Task/Job: Scheduled Task

Both mappings are stored as `provisional` initially and promoted to `supported` once the evidence clearly ties to each technique, with a rationale recorded for each.

## 4. Confidence and Severity

After both evidence records and both ATT&CK mappings are in place, the investigation's confidence is updated to **medium** via `/update-case`. Medium reflects that the behavior pattern is consistent with known attacker tradecraft, but that Blue Team validation has not yet occurred — it is not treated as high confidence until detection results are on record. Severity is likewise assessed as **medium**, consistent with a persistence + execution pairing rather than a confirmed high-impact outcome.

## 5. Red Team Routing

With two ATT&CK techniques supported by stored evidence, the Purple Team router (`/purple-loop`) evaluates the investigation and determines that Red Team simulation planning is the appropriate next stage — because both `T1059.001` and `T1053.005` are evidence-supported and no test evidence yet exists. The router recommends `/red-team` as the single safe next command; it does not execute it.

## 6. Planning-Only Atomic Test Mapping

The `atomic-mapper` agent is used to check whether a real, locally available Atomic Red Team test exists for each supported technique. For both `T1059.001` and `T1053.005`, it reports the matching test's name, GUID, supported operating systems, prerequisites, expected telemetry, and cleanup requirement — pulled only from catalog content actually present locally, never invented. Each result is classified (e.g. verified match) alongside a mapping-confidence rating.

## 7. No Test Execution

At every stage of this walkthrough, PurpleShadow remains a **planning exercise**:

- No Atomic Red Team test is executed.
- No Hayabusa analysis is run against real evidence as part of this demo.
- No detection rule is created, modified, or deployed.
- No system state is changed at any point.

The walkthrough stops at a fully-formed, evidence-grounded plan — technique mappings, a Red Team routing decision, and a verified-but-unexecuted Atomic test mapping — which is exactly the point where a human would decide whether to authorize execution in a real, explicitly authorized lab.
