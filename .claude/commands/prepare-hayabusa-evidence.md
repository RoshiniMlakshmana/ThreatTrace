---
description: Convert one analyst-selected Hayabusa csv_timeline row into a normalized, source-trust-assessed evidence preview, without writing to Supabase
argument-hint: "[investigation UUID, selected csv_timeline row JSON, and adaptation metadata]"
---

# ThreatTrace Prepare Hayabusa Evidence Workflow

You convert one analyst-selected Hayabusa `csv_timeline` row into a normalized, source-trust-assessed evidence preview. **This command is preview-only.** It never writes to Supabase and never invokes `/add-evidence` on its own — it only prepares a candidate for the analyst to review and, separately, submit later.

## Selection Input

$ARGUMENTS

## Required Inputs

Request or extract:

- `investigation_id`
- the selected row, as one JSON object
- `analysis_type`
- `source_location`
- `row_identifier`
- `evidence_type`

Optional:

- `observed_at`
- `supports_hypothesis`
- `field_aliases`

Only one selected row may be handled per invocation. `analysis_type` is ultimately validated by `core.hayabusa_evidence_adapter` (via `core.hayabusa_evidence_cli`) — do not duplicate its validation rules here; this command only assembles and forwards the request.

## Workflow

### 1. Verify Investigation

Perform the existing read-only investigation lookup (the same lookup `/add-evidence` and `/case-summary` use) against the `investigations` table by the supplied UUID.

If the investigation does not exist:

- Stop.
- Report this clearly.
- Do not invoke any CLI.

### 2. Assemble Adapter Request

Build exactly one JSON object containing only:

- `row`
- `investigation_id`
- `analysis_type`
- `source_location`
- `row_identifier`
- `evidence_type`
- `observed_at`, when supplied
- `supports_hypothesis`, when supplied
- `field_aliases`, when supplied

Do not add any field this list doesn't name.

### 3. Secret and Sensitive-Data Scan

Before invoking any CLI, scan:

- every selected-row field, including nested values;
- `investigation_id`, `analysis_type`, `source_location`, `row_identifier`, `evidence_type`;
- `field_aliases`;
- `observed_at`.

Look for suspected:

- passwords
- API keys
- access tokens
- credentials
- private keys
- connection strings

If any suspected secret is found:

- Fail closed.
- Do not invoke any CLI.
- Do not display the suspected secret value.
- Identify only the affected field category (e.g. "the selected row's `CommandLine` column appears to contain a credential").
- Ask the analyst to remove or redact it and resubmit.

### 4. Invoke the Hayabusa Evidence Adapter CLI

- Windows: `py -m core.hayabusa_evidence_cli`
- macOS or Linux: `python3 -m core.hayabusa_evidence_cli`
- Only fall back to plain `python -m core.hayabusa_evidence_cli` if it is confirmed to resolve to Python 3.10 or later.

Send the exact adapter request assembled in step 2 through **stdin**. Do not:

- pass row data through command-line arguments;
- create a temporary repository file;
- read the CSV file automatically;
- select a row automatically — the row must already be analyst-selected input.

Handle results strictly by exit code:

- **Exit code 0**: stderr must be empty. Parse stdout as exactly one JSON object — the unnormalized evidence candidate.
- **Exit code 2**: show the concise adapter or input error from stderr. Stop.
- **Exit code 1**: show the generic adapter failure message from stderr. Stop.
- **Any other exit code**: fail closed. Report that adaptation could not be completed safely.

Reject success output, without attempting to repair it, if:

- stdout is empty;
- stdout is not valid JSON;
- stdout contains more than one JSON value;
- the parsed value is not a JSON object;
- stderr contains any content.

### 5. Normalize the Candidate

- Windows: `py -m core.evidence_cli`
- macOS or Linux: `python3 -m core.evidence_cli`

Send the exact candidate JSON object from step 4 through **stdin**, unmodified — do not reconstruct or change it before normalization. Apply the same strict handling used by `/add-evidence`:

- **Exit code 0**: parse exactly one JSON object from stdout.
- **Exit code 2**: show the concise validation error and stop.
- **Exit code 1**: show the generic failure and stop.
- **Any other exit code**: fail closed.
- Reject empty, malformed, multiple-value, non-object, or stderr-containing "success" output, without repairing it.

### 6. Assess Source Trust

- Windows: `py -m core.source_trust_cli`
- macOS or Linux: `python3 -m core.source_trust_cli`

Send the exact normalized evidence JSON from step 5 through **stdin**. Handle exit codes and malformed output with the same strictness as steps 4–5.

On success, require the result to contain **exactly**: `recommended_trust_level`, `reason_codes`, `conflicts_with_supplied_trust_level`. Reject the result if any additional or missing key is present.

This assessment is advisory only. Do not automatically change `trust_level` on the normalized candidate.

## Display

Display:

# Prepared Hayabusa Evidence Review

## Selection Metadata

Show:

- Investigation ID
- Analysis type
- Source location
- Selected row identifier
- Explicit field aliases used

Do not unnecessarily repeat the complete raw row in this summary — it already appears inside the Normalized Evidence Candidate's `details.hayabusa_row`.

## Normalized Evidence Candidate

Show exactly the normalized JSON object returned by `core.evidence_cli` in step 5. Do not modify or reconstruct it.

## Advisory Source-Trust Assessment

Show exactly:

- Current trust level
- Recommended trust level
- Deterministic reason codes
- Conflict indicator

Explain:

- This assesses source reliability, not whether the evidence is true.
- It does not calculate confidence.
- It does not modify the normalized candidate.
- Final trust selection is handled later by `/add-evidence`.

## Next Step

State clearly:

- No Supabase write has occurred.
- No evidence has been added to the investigation.
- Review the normalized candidate and trust assessment.
- To store it, manually invoke `/add-evidence` using the normalized candidate.
- `/add-evidence` will repeat its own secret scan, normalization checks, advisory trust review, final preview, and exact "Add evidence" confirmation — nothing from this command is trusted or skipped there.
- Do not treat preparation as insertion approval.

## Example

Selected row (synthetic):

- `EventID`: `4104`
- `Computer`: `EXAMPLE-HOST-01`
- `CommandLine`: `powershell.exe -NoProfile -Command "Write-Output test"`

Request assembled and sent to `core.hayabusa_evidence_cli`:

```
{
  "row": {
    "EventID": "4104",
    "Computer": "EXAMPLE-HOST-01",
    "CommandLine": "powershell.exe -NoProfile -Command \"Write-Output test\""
  },
  "investigation_id": "11111111-1111-1111-1111-111111111111",
  "analysis_type": "csv_timeline",
  "source_location": "output/hayabusa/example-case.csv",
  "row_identifier": "row-7",
  "evidence_type": "windows_event",
  "field_aliases": {
    "event_id": "EventID",
    "host_name": "Computer",
    "command_line": "CommandLine"
  }
}
```

The adapter produces an unnormalized candidate (`source_type: hayabusa`, `assertion_type: derived_fact`, the three aliased fields, and the complete row preserved in `details.hayabusa_row`). That candidate is sent unmodified to `core.evidence_cli`, which returns the normalized evidence record. That normalized record is sent unmodified to `core.source_trust_cli`, which returns an advisory recommendation (for example, `recommended_trust_level: "low"` with reason codes explaining that identity/collection-method provenance was not supplied). The command displays the Selection Metadata, Normalized Evidence Candidate, and Advisory Source-Trust Assessment sections, then states plainly that no Supabase write occurred and that `/add-evidence` must be run separately to store it.

(This example uses only synthetic hosts, commands, paths, and IDs.)

## Required Output

Produce:

- Investigation Validation
- Secret Scan Result
- Adapter Result
- Normalization Result
- Advisory Source-Trust Assessment
- Selection Metadata
- Normalized Evidence Candidate
- Next Step

## Safety Boundaries

- `csv_timeline` only — `log_metrics` and `eid_metrics` are not supported.
- One analyst-selected row only, per invocation.
- No automatic row selection.
- No CSV or EVTX file reading.
- No bulk ingestion.
- No Supabase write.
- No automatic invocation of `/add-evidence`.
- No MITRE ATT&CK inference.
- No confidence calculation.
- No evidence hashing.
- No automatic trust-level modification.
- No approval, audit, containment, or execution action.
- No Hayabusa process execution.
- No network request.
- No temporary repository evidence files.
- Fail closed on any CLI problem: a non-zero or unrecognized exit code, empty stdout, non-JSON stdout, more than one JSON value on stdout, a non-object result, or unexpected stderr content on success, for any of the three CLIs (`core.hayabusa_evidence_cli`, `core.evidence_cli`, `core.source_trust_cli`).
- Stop and report the full error if the investigation does not exist or any step (secret scan, adaptation, normalization, or trust assessment) fails.
