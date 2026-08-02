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

## Hayabusa Row Handoff

This section applies only when already-generated `csv_timeline` output is available, one row is visible and potentially relevant, and the analyst wants to prepare that row for evidence review. Only one candidate row may be prepared per handoff.

### Candidate-row rules

You may:

- inspect already-generated `csv_timeline` output;
- identify one candidate row;
- display the complete selected row;
- explain why the row deserves analyst review;
- show relevant surrounding-event context separately;
- propose explicit field aliases;
- generate a copyable preparation request.

You must not:

- classify the row as confirmed malicious without supporting evidence;
- automatically select multiple rows;
- automatically invoke `/prepare-hayabusa-evidence`;
- automatically invoke `/add-evidence`;
- automatically normalize or insert evidence;
- calculate `trust_level` or `confidence`;
- infer ATT&CK mappings as part of the handoff.

Use cautious language such as "potentially relevant," "suspicious pattern," "candidate evidence," "requires analyst review," and "may support or contradict the current hypothesis." Do not call a row confirmed malicious solely because Hayabusa produced it.

### Row identifier

Use a descriptive identifier based on the row's visible position:

```
row-<visible-row-number>
```

For example: `row-17`.

This is a review-time reference only:

- it is not a database identifier;
- it is not cryptographically stable;
- it may change if the CSV is regenerated or reordered;
- evidence hashing and permanent identifiers are not implemented here.

Do not create a hash or UUID for the row.

### Source location

Preserve the project-relative path of the already-generated `csv_timeline` CSV exactly as it exists. Do not invent a source path, convert it to an absolute path, read another file automatically, or copy the CSV into a temporary repository file. `core.hayabusa_evidence_adapter` (via `/prepare-hayabusa-evidence`) will validate the path later — do not duplicate that validation here.

### Alias-proposal rules

Propose aliases only from exact column headers visibly present in the selected row. Supported normalized targets: `event_id`, `host_name`, `user_name`, `process_name`, `command_line`, `ip_address`, `file_hash`, `observed_at`.

Format:

```json
{
  "event_id": "ExactVisibleHeader",
  "host_name": "ExactVisibleHeader"
}
```

- The JSON key is the supported normalized evidence field.
- The JSON value is the exact visible CSV column header.
- Do not perform case-insensitive matching.
- Do not use approximate matching.
- Do not infer a mapping from an ambiguous header.
- Do not promote a value merely because its contents look similar.
- Do not map one CSV column to multiple normalized fields.

When a header is ambiguous: leave it unmapped, explain briefly why no alias was proposed, and state that it remains preserved inside `details.hayabusa_row`. These aliases are proposals for analyst review, not guaranteed-valid mappings — do not duplicate the adapter's own validation logic here.

### Keep triage rationale separate

The following must remain outside the copyable preparation-request JSON:

- why the row appears suspicious;
- surrounding-event interpretation;
- hypothesis reasoning;
- supporting or contradicting analysis;
- recommended follow-up investigation;
- missing evidence;
- analyst commentary.

Do not insert triage rationale into `row`, `details`, `provenance`, `assertion_type`, `trust_level`, `confidence`, or `evidence_type`. The selected row inside the request must remain an exact representation of the visible CSV row.

### Handoff output format

When one candidate row is identified, display exactly these sections:

# Hayabusa Evidence Handoff

## Candidate Hayabusa Evidence Row

Show:

- Investigation ID
- Analysis type: `csv_timeline`
- Source location
- Row identifier
- Evidence type
- Complete selected row as formatted JSON

Do not silently remove columns from the selected row.

## Why This Row Requires Review

Explain why the row may be relevant, which visible values triggered review, whether it may support or contradict a current hypothesis, which surrounding events should be checked, and what additional evidence would strengthen or weaken the interpretation. This section is narrative only and must not enter the preparation-request JSON.

## Proposed Field Aliases

Show a JSON object containing only unambiguous proposed aliases. When no safe alias can be proposed, show `{}` and explain which ambiguous headers were deliberately left unmapped.

## Copyable Preparation Request

Show exactly one fenced JSON object suitable for manual submission to `/prepare-hayabusa-evidence`. The object may contain only:

```json
{
  "row": { ... },
  "investigation_id": "...",
  "analysis_type": "csv_timeline",
  "source_location": "...",
  "row_identifier": "row-...",
  "evidence_type": "...",
  "observed_at": "...",
  "supports_hypothesis": true,
  "field_aliases": { ... }
}
```

Required fields: `row`, `investigation_id`, `analysis_type`, `source_location`, `row_identifier`, `evidence_type`.

Include `observed_at` only when the exact visible header is unambiguous, its value is directly present, and the value is not inferred, reconstructed, or replaced with the current time. When `observed_at` is represented through `field_aliases`, do not also include a separate `observed_at` value — avoid creating the direct-and-aliased conflict the adapter rejects.

Include `supports_hypothesis` only when the analyst explicitly supplied the value. Do not infer it from the triage narrative.

Include `field_aliases` only when aliases are proposed.

Do not include: triage rationale; `trust_level`; `confidence`; ATT&CK techniques; evidence hashes; `integrity_verified`; approval information; audit information; containment instructions; shell commands; command-line quoting; temporary filenames; secrets.

## Analyst Next Step

State clearly:

1. Review the selected row, source path, row identifier, evidence type, and proposed aliases.
2. Correct or remove any unsafe or ambiguous alias.
3. Manually invoke `/prepare-hayabusa-evidence` using the copyable JSON request.
4. `/prepare-hayabusa-evidence` performs preparation and review only.
5. No Supabase write occurs during preparation.
6. Storing evidence requires a separate manual `/add-evidence` action.
7. `/add-evidence` still requires its own review and exact "Add evidence" confirmation.
8. Preparing the row is not insertion approval.

### log_metrics and eid_metrics

Keep these outputs as supporting context only. They may describe log availability, highlight coverage gaps, show event-frequency patterns, and guide additional review. They must not produce a Hayabusa evidence handoff, be converted into individual evidence rows, be sent to `/prepare-hayabusa-evidence`, or be treated as malicious evidence solely because a count is high.

### Safety boundaries

- One candidate `csv_timeline` row at a time.
- Human review and selection are mandatory.
- No automatic row ingestion.
- No bulk evidence preparation.
- No automatic command chaining.
- No automatic `/prepare-hayabusa-evidence` invocation.
- No automatic `/add-evidence` invocation.
- No Supabase write.
- No trust-level selection.
- No confidence calculation.
- No ATT&CK inference in the handoff.
- No evidence hashing.
- No approval or audit action.
- No containment or execution action.
- No Hayabusa process execution.
- No network request.
- No temporary evidence files.

### Synthetic example

Selected row from `output/hayabusa/case-example-timeline.csv`, `row-17`:

```json
{
  "EventID": "4104",
  "Computer": "EXAMPLE-HOST-02",
  "CommandLine": "powershell.exe -NoProfile -EncodedCommand ZQBjAGgAbwAgAHQAZQBzAHQA",
  "User": "EXAMPLE\\svc-test"
}
```

Why this row requires review (narrative only, not part of the JSON request): the `CommandLine` value uses `-EncodedCommand`, a pattern worth reviewing for obfuscated PowerShell execution; the host `EXAMPLE-HOST-02` and account `EXAMPLE\svc-test` should be checked against nearby events for related activity; this may support a hypothesis of scripted execution, or may reflect a benign scheduled task — additional surrounding events and process-ancestry evidence would help confirm either direction.

Proposed field aliases:

```json
{
  "event_id": "EventID",
  "host_name": "Computer",
  "command_line": "CommandLine"
}
```

(`User` was left unmapped in this example only to illustrate that an analyst may choose not to propose every possible alias in a given review; it remains preserved inside `details.hayabusa_row` regardless.)

Copyable preparation request:

```json
{
  "row": {
    "EventID": "4104",
    "Computer": "EXAMPLE-HOST-02",
    "CommandLine": "powershell.exe -NoProfile -EncodedCommand ZQBjAGgAbwAgAHQAZQBzAHQA",
    "User": "EXAMPLE\\svc-test"
  },
  "investigation_id": "22222222-2222-2222-2222-222222222222",
  "analysis_type": "csv_timeline",
  "source_location": "output/hayabusa/case-example-timeline.csv",
  "row_identifier": "row-17",
  "evidence_type": "windows_event",
  "field_aliases": {
    "event_id": "EventID",
    "host_name": "Computer",
    "command_line": "CommandLine"
  }
}
```

No evidence has been inserted. This is a preview-only handoff — the analyst must separately invoke `/prepare-hayabusa-evidence` and, later, `/add-evidence` with its own confirmation to store anything.

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

12. Recommend the next ThreatTrace command, but never execute, invoke, or chain it automatically.

Possible commands include:

- /query
- /threat-hunt
- /blue-team
- /red-team
- /add-evidence
- /request-case-update
- /review-approval
- /apply-case-update
- /case-summary

When triage identifies a proposed `status`/`confidence` change, route through the approval-gated workflow rather than any direct update:

- When the analyst proposes a new status/confidence change and no approval yet exists for it, recommend `/request-case-update`.
- When a pending approval already exists and requires a decision, recommend `/review-approval`.
- When an approval has been approved and is ready to apply, recommend `/apply-case-update`.
- When an approval has been rejected, explain that it cannot be applied and that a new `/request-case-update` is required for any different proposed change.
- When an approval has already been consumed, explain that it cannot be consumed again.

`/update-case` is deprecated static guidance only — never recommend it as a way to change status or confidence. It may be mentioned only to point an analyst who typed it toward `/request-case-update`.

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
- Never invoke or chain `/request-case-update`, `/review-approval`, or `/apply-case-update` automatically — recommend only.
- Never update an investigation or an approval directly, call Supabase or MCP, execute SQL, or treat typed confirmation as authorization.
