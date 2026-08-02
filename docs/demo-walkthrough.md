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

After both evidence records and both ATT&CK mappings are in place, the analyst proposes raising the investigation's confidence to **medium** — reflecting that the behavior pattern is consistent with known attacker tradecraft, but that Blue Team validation has not yet occurred. This proposed change goes through the approval-gated case-update workflow rather than any direct write.

### Step 1 — Request

```
/request-case-update {"investigation_id":"11111111-1111-4111-8111-111111111111","requested_by":"analyst@example.com","confidence":"medium"}
```

This creates exactly one pending approval. **The investigation is not updated at this point.** `requested_by` above is a claimed requester identity, not an authenticated one.

### Step 2 — Review

```
/review-approval {"approval_id":"22222222-2222-4222-8222-222222222222","decision":"approve","reviewed_by":"reviewer@example.com"}
```

This changes only the approval record to `approved`. **The investigation is still not updated.** `reviewed_by` above is a claimed reviewer identity, not an authenticated one.

### Step 3 — Apply

```
/apply-case-update {"approval_id":"22222222-2222-4222-8222-222222222222","consumed_by":"operator@example.com"}
```

`/apply-case-update` accepts no `status` or `confidence` of its own — the applied value comes only from the approval's own stored `action_payload` (`confidence: medium`, in this case). This single atomic operation marks the approval `consumed` and updates the investigation's confidence together, in the same database transaction. `consumed_by` above is a claimed consumer identity, not an authenticated one. The approval's final status becomes `consumed`, and **it cannot be consumed again** — any replay attempt fails closed.

Severity is likewise assessed as **medium**, consistent with a persistence + execution pairing rather than a confirmed high-impact outcome. Severity itself is a separate analyst judgment recorded outside the approval-gated `status`/`confidence` workflow described above.

### If the Reviewer Had Rejected Instead

Had the reviewer instead run:

```
/review-approval {"approval_id":"22222222-2222-4222-8222-222222222222","decision":"reject","reviewed_by":"reviewer@example.com","rejection_reason":"Blue Team validation has not yet occurred; confidence should remain unknown until detection results are on record."}
```

the approval's status would become `rejected`, **the investigation would remain completely unchanged**, and the rejected approval could never be applied — the analyst would need to submit a new `/request-case-update` for any different proposed change.

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
