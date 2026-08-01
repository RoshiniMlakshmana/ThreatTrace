---
description: Produce a read-only, advisory "What would change my decision?" preview for a ThreatTrace investigation using analyst-supplied reasoning
argument-hint: "[investigation UUID, selected supporting/contradicting evidence IDs, current assessment, and decision status]"
---

# ThreatTrace Decision Review Workflow

You produce a read-only, advisory preview that answers "What would change my current decision?" for one existing investigation. This command never writes to Supabase, never modifies any record, and never executes anything. Every piece of reasoning in the preview — the current assessment, the decision status, and every advisory condition list — is supplied entirely by the analyst. This command does not call an AI model to generate, revise, or improve any of it.

The command validates only what the analyst already selected and typed, using the same deterministic Python validators already relied on elsewhere in ThreatTrace:

- `core.decision_context_cli` (wrapping `core.decision_context.validate_decision_context`)
- `core.decision_warning_formatter_cli` (wrapping `core.decision_warning_formatter.format_decision_warnings`)
- `core.decision_analysis_cli` (wrapping `core.decision_analysis.validate_decision_analysis`)

Do not re-implement, duplicate, or write inline Python for any rule those adapters already enforce.

## Review Input

$ARGUMENTS

## Input Envelope

The input must be exactly one JSON object. Reject anything else — malformed JSON, trailing non-whitespace content after the object, or a top-level JSON value that is not an object.

Allow exactly these fields:

Required:

- `investigation_id`
- `supporting_evidence_ids`
- `contradicting_evidence_ids`
- `current_assessment`
- `decision_status`

Optional (each defaults to `[]` when omitted):

- `unresolved_assumptions`
- `evidence_gaps`
- `strengthen_conditions`
- `weaken_conditions`
- `reversal_conditions`
- `recommended_next_evidence`
- `limitations`

Reject every field this list does not name. In particular, always reject:

- `hypothesis_id`
- `generated_at`
- `confidence`
- `trust_level`
- `investigation_status`
- `evidence_records`
- `approval`
- `execute`
- `persist`

None of those nine fields is ever accepted from analyst input — `hypothesis_id` and `generated_at` are supplied later by this workflow and the validators themselves; `confidence` and `trust_level` are read-only database values this command never sets; `investigation_status` does not belong to the analyst-supplied request; `evidence_records` is assembled later from a read-only Supabase lookup, never from analyst input; and `approval`, `execute`, and `persist` name actions this command never performs, so no field could ever have a purpose.

## Request Validation

Perform every validation step below, in order, before any Supabase operation:

1. Parse `$ARGUMENTS` as exactly one JSON value.
2. Reject malformed JSON.
3. Reject trailing non-whitespace content after the one JSON value.
4. Reject a top-level value that is not a JSON object.
5. Reject any field not listed under Input Envelope.
6. Verify all five required fields (`investigation_id`, `supporting_evidence_ids`, `contradicting_evidence_ids`, `current_assessment`, `decision_status`) are present.
7. Validate and canonicalize `investigation_id` and every evidence ID as UUIDs.
8. Reject duplicate evidence IDs within either list and reject any ID appearing in both lists.
9. Validate `current_assessment`.
10. Validate `decision_status`.
11. Validate all seven optional reasoning collections.
12. Apply the project's existing secret-scanning convention (the same one `/add-evidence` and `/prepare-hayabusa-evidence` already use) only to `current_assessment` and the seven optional reasoning collections.

Do not scan or print complete database records at any point — no evidence record, no investigation record, is ever printed in full; only the specific summarized fields named later in this workflow are ever displayed.

### `investigation_id`

Must be a string, nonblank after trimming, and a structurally valid UUID (any UUID version). Canonicalize it to lowercase standard hyphenated form before it is used in any Supabase query.

### `supporting_evidence_ids`

Must be explicitly present and a JSON array composed only of valid UUID strings. Canonicalize every entry before use. Reject duplicates within the list. An empty list is valid.

### `contradicting_evidence_ids`

Apply the identical rules. An empty list is valid. Reject any evidence ID that also appears in `supporting_evidence_ids` — the two groups must be disjoint. Never move or reclassify an ID between groups; the analyst's own grouping is the only grouping this command ever uses.

### `current_assessment`

Must be explicitly present, a string, and nonblank after trimming. This value is entirely analyst-authored — never rewrite it, never improve its wording, and never generate a replacement for it.

### `decision_status`

Must be explicitly present and exactly one of:

- `supported`
- `partially_supported`
- `contradicted`
- `inconclusive`
- `insufficient_evidence`

This value is entirely analyst-supplied — never calculate it and never replace it with a computed value.

### Optional reasoning collections

The seven optional fields are:

- `unresolved_assumptions`
- `evidence_gaps`
- `strengthen_conditions`
- `weaken_conditions`
- `reversal_conditions`
- `recommended_next_evidence`
- `limitations`

Each field must be either omitted (in which case it becomes `[]`) or a JSON array of nonblank strings. Reject `null`, a single string in place of an array, a non-string entry, a blank entry, or a duplicate entry within one collection. Preserve the analyst's own list order — never reorder, deduplicate silently, or regroup any of these entries.

## Secret Scan

Before any Supabase operation, scan only `current_assessment` and the seven optional reasoning collections for suspected:

- passwords
- API keys
- access tokens
- credentials
- private keys
- connection strings

Do not scan the evidence IDs, the investigation ID, or `decision_status` — those are UUIDs and a fixed controlled vocabulary value, never free text.

If any suspected secret is found:

- Stop before any Supabase operation.
- Report that the analyst-authored reasoning appears to contain potentially sensitive content, and name only the affected field (e.g. "the `current_assessment` field appears to contain a credential").
- Do not echo the matched value.
- Do not echo the complete request.
- Ask the analyst to remove or redact it and resubmit.

## Reasoning Model

Every piece of reasoning in this workflow — `current_assessment`, `decision_status`, `unresolved_assumptions`, `evidence_gaps`, `strengthen_conditions`, `weaken_conditions`, `reversal_conditions`, `recommended_next_evidence`, and `limitations` — is supplied entirely by the analyst in the request. Do not call an AI model, and do not otherwise generate or revise any of these values. In the final preview, label all of this reasoning:

Analyst supplied — not persisted

Never describe any of this reasoning as system-generated, AI-generated, approved, or confirmed.

## Python Launcher Selection

Use the existing project convention for selecting a Python launcher:

1. Try `py`.
2. Otherwise try `python3`.
3. Otherwise use a `python` executable only after confirming it resolves to Python 3.10 or later.

Select one launcher and reuse the same launcher for all three CLI invocations in this workflow.

Before continuing to any Supabase read, confirm the selected launcher can import all three required modules:

- `core.decision_context_cli`
- `core.decision_warning_formatter_cli`
- `core.decision_analysis_cli`

If no launcher can be selected, or the import check fails for any of the three modules, stop and report that the decision-review Python CLIs are unavailable. Do not install any package. Do not modify the environment.

## Safe CLI Transport

Invoke all three CLIs through **stdin only**, exactly following the safe invocation pattern already established by `/add-evidence` and `/prepare-hayabusa-evidence`. Never:

- pass JSON through command-line arguments;
- create a temporary JSON file;
- interpolate analyst content directly into executable shell code;
- write request data to disk.

## Supabase Read-Only Lookup

Use the same Supabase access convention the existing commands already use. Every operation in this section is read-only — this workflow never inserts, updates, or deletes any record.

### Investigation query

Query the `investigations` table by the canonical investigation UUID. Request only the three fields `validate_decision_context` needs:

- `id`
- `status`
- `confidence`

Distinguish these outcomes and respond exactly as follows:

- **Query or tool failure**: stop and report "Investigation lookup failed."
- **Valid empty result**: stop and report "Investigation not found."
- **Malformed response**: stop and report "Investigation lookup returned malformed data."
- **Multiple returned rows**: stop and report "Investigation lookup returned multiple records."
- **Exactly one valid row**: continue to the evidence query.

Never print a raw database error, connection detail, token, URL, header, or stack trace.

### Evidence query

Combine the canonical `supporting_evidence_ids` and `contradicting_evidence_ids` lists into one selected-ID set.

When the combined set is empty, skip the evidence query entirely and use an empty `evidence_records` list.

When at least one ID exists, perform exactly **one** filtered read query against the `evidence` table, scoped by:

- `investigation_id` equals the canonical investigation ID;
- `id` is in the complete selected-ID set.

Request only the six fields `validate_decision_context` needs:

- `id`
- `investigation_id`
- `trust_level`
- `confidence`
- `assertion_type`
- `supports_hypothesis`

Never request `details`, `provenance`, `source`, `source_location`, `command_line`, `file_hash`, raw event data, or any complete evidence payload — those fields must never appear in the query, the preview, or any error message.

Distinguish these outcomes and respond exactly as follows:

- **Query or tool failure**: stop and report "Evidence lookup failed."
- **Malformed response**: stop and report "Evidence lookup returned malformed data."
- **Duplicate returned evidence IDs**: stop and report "Evidence lookup returned duplicate records."
- **Missing requested IDs**: stop and report "One or more selected evidence records were not found."
- **Unrequested returned IDs**: stop and report "Evidence lookup returned unrequested records."
- **Cross-investigation evidence**: stop and report "Evidence belongs to a different investigation."
- **Valid complete result**: continue to Stage 1.

Never expose a raw database error in any of these messages.

## Stage 1 — Decision-Context CLI

Construct exactly this object — no additional field:

```json
{
  "investigation_id": "<canonical investigation UUID>",
  "investigation": {
    "id": "...",
    "status": "...",
    "confidence": "..."
  },
  "supporting_evidence_ids": ["..."],
  "contradicting_evidence_ids": ["..."],
  "evidence_records": [
    {
      "id": "...",
      "investigation_id": "...",
      "trust_level": "...",
      "confidence": "...",
      "assertion_type": "...",
      "supports_hypothesis": true
    }
  ]
}
```

Send it through **stdin only** to:

- Windows: `py -m core.decision_context_cli`
- macOS or Linux: `python3 -m core.decision_context_cli`
- Only fall back to plain `python -m core.decision_context_cli` if it is confirmed to resolve to Python 3.10 or later.

### Context CLI exit handling

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2**: deterministic input or context-validation failure — stop, present a short categorized error, and do not continue to warning formatting or analysis validation.
- **1**: unexpected internal failure — stop, present a short categorized error, and do not continue.
- **any other code**: unsupported CLI result — stop and report that context validation could not be completed safely.

Never present a partial preview as valid after a nonzero result.

### Context CLI success-output checks

Reject the output — treating it as a failure even though the exit code was 0 — when any of these hold:

- stderr is nonempty;
- stdout is empty;
- stdout is not valid JSON;
- stdout contains more than one JSON value;
- the parsed value is not a JSON object;
- an unexpected top-level field is present;
- a required top-level field is missing.

Require the parsed object to contain exactly these top-level fields:

- `investigation`
- `supporting_evidence`
- `contradicting_evidence`
- `warnings`

Require `investigation` to contain exactly `id`, `status`, `confidence`. Require every entry of `supporting_evidence` and `contradicting_evidence` to contain exactly `id`, `trust_level`, `confidence`, `assertion_type`, `supports_hypothesis`. Require every entry of `warnings` to contain exactly `evidence_id`, `code`.

Verify all of the following, stopping on any mismatch:

- `investigation.id` equals the canonical request `investigation_id`;
- the `supporting_evidence` IDs equal the requested `supporting_evidence_ids`, in the same order;
- the `contradicting_evidence` IDs equal the requested `contradicting_evidence_ids`, in the same order;
- no evidence ID appears in both `supporting_evidence` and `contradicting_evidence`.

Call this the **validated context**. Every later stage reads from it, never from the raw request.

## Stage 2 — Warning-Formatter CLI

Take only `validated_context["warnings"]` — nothing else — and send that JSON array through **stdin only** to:

- Windows: `py -m core.decision_warning_formatter_cli`
- macOS or Linux: `python3 -m core.decision_warning_formatter_cli`
- Only fall back to plain `python -m core.decision_warning_formatter_cli` if it is confirmed to resolve to Python 3.10 or later.

Do not recreate or duplicate the warning-code-to-explanation mapping anywhere in this command's own Markdown — that mapping belongs entirely to `core.decision_warning_formatter`, and this command only ever displays whatever text the CLI returns.

### Warning CLI exit handling

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2**: warning-format validation failure — stop and do not continue.
- **1**: unexpected formatter failure — stop and do not continue.
- **any other code**: unsupported CLI result — stop and report that warning formatting could not be completed safely.

Never display unformatted warnings as a valid final preview after a nonzero result.

### Warning CLI success-output checks

Reject the output when any of these hold:

- stderr is nonempty;
- stdout is empty;
- the output is not valid JSON;
- the output contains more than one JSON value;
- the output is not a JSON array;
- the output length differs from the length of `validated_context["warnings"]`.

Require every entry to contain exactly `evidence_id`, `code`, `explanation`.

For each position, verify that `evidence_id` and `code` match the corresponding entry in `validated_context["warnings"]`, and that the array order is unchanged. Never rewrite the returned explanation text.

Call this the **formatted warnings**.

## Stage 3 — Decision-Analysis CLI

Only build this stage's request after Stage 1 (context validation) has fully succeeded.

Use:

- `investigation_id` from `validated_context["investigation"]["id"]`;
- `supporting_evidence_ids` rebuilt from `validated_context["supporting_evidence"]` (its `id` fields, in order);
- `contradicting_evidence_ids` rebuilt from `validated_context["contradicting_evidence"]` (its `id` fields, in order).

Never reuse the raw request's evidence-ID lists for this handoff — always rebuild them from the validated context, so that what is analyzed is exactly what the context validator already confirmed exists and is correctly grouped.

Construct exactly this object:

```json
{
  "investigation_id": "<ID from validated context>",
  "hypothesis_id": null,
  "current_assessment": "<analyst-supplied value>",
  "decision_status": "<analyst-supplied value>",
  "supporting_evidence_ids": ["<IDs rebuilt from validated context>"],
  "contradicting_evidence_ids": ["<IDs rebuilt from validated context>"],
  "unresolved_assumptions": [],
  "evidence_gaps": [],
  "strengthen_conditions": [],
  "weaken_conditions": [],
  "reversal_conditions": [],
  "recommended_next_evidence": [],
  "limitations": []
}
```

Populate the seven reasoning collections from the validated request (each already defaulted to `[]` when the analyst omitted it). Always send `hypothesis_id` as `null` — never any other value. Never include `generated_at` in the request; the validator generates it.

Send the object through **stdin only** to:

- Windows: `py -m core.decision_analysis_cli`
- macOS or Linux: `python3 -m core.decision_analysis_cli`
- Only fall back to plain `python -m core.decision_analysis_cli` if it is confirmed to resolve to Python 3.10 or later.

### Analysis CLI exit handling

Interpret the exit code strictly:

- **0**: potential success — continue to the output checks below.
- **2**: deterministic analysis-validation failure — stop and do not continue.
- **1**: unexpected internal failure — stop and do not continue.
- **any other code**: unsupported CLI result — stop and report that analysis validation could not be completed safely.

Never present a partial decision preview as valid after a nonzero result.

### Analysis CLI success-output checks

Reject the output when any of these hold:

- stderr is nonempty;
- stdout is empty;
- the output is not valid JSON;
- the output contains more than one JSON value;
- the output is not a JSON object;
- a required field is missing;
- an unexpected field is present.

Require the parsed object to contain exactly these fields:

- `investigation_id`
- `hypothesis_id`
- `current_assessment`
- `decision_status`
- `supporting_evidence_ids`
- `contradicting_evidence_ids`
- `unresolved_assumptions`
- `evidence_gaps`
- `strengthen_conditions`
- `weaken_conditions`
- `reversal_conditions`
- `recommended_next_evidence`
- `limitations`
- `generated_at`

Verify all of the following, stopping on any mismatch:

- `investigation_id` equals the validated context's investigation ID;
- `hypothesis_id` is `null`;
- `current_assessment` equals the trimmed analyst value;
- `decision_status` equals the analyst-supplied status;
- `supporting_evidence_ids` equals the validated-context supporting IDs, in order;
- `contradicting_evidence_ids` equals the validated-context contradicting IDs, in order;
- every one of the seven reasoning collections equals the validated analyst input, in order;
- `generated_at` is a nonblank UTC timestamp ending in `Z`.

Never replace, recalculate, or reinterpret any returned value. Call this the **validated analysis**.

## Final Preview

Only display the preview below after Stage 1, Stage 2, and Stage 3 have all fully succeeded. Use exactly these sections, in exactly this order:

# Decision Review

## Decision Context

Display:

- Investigation ID
- Existing Investigation Status
- Existing Investigation Confidence

State:

Existing investigation metadata — unchanged

## Supporting Evidence

For every entry in the validated context's `supporting_evidence`, display:

- Evidence ID
- Source Trust
- Evidence Confidence
- Assertion Type
- Stored supports_hypothesis Value

If empty, display:

No supporting evidence was selected.

Do not call any of this evidence malicious or benign.

## Contradicting Evidence

Use the same fields as Supporting Evidence, drawn from the validated context's `contradicting_evidence`.

If empty, display:

No contradicting evidence was selected.

## Context Warnings

For every entry in the formatted warnings, display:

- Evidence ID
- Warning Code
- Fixed Explanation

If empty, display:

No context warnings were produced.

State:

Warnings are advisory metadata checks and are not proof of maliciousness.

## Current Assessment

Display:

- Current Assessment
- Decision Status
- Generated At

Label this section:

Analyst supplied — not persisted

Never claim the assessment was generated or approved by ThreatTrace.

## Why the Current Assessment Holds

Do not generate narrative reasoning here. Display only:

- Analyst-selected supporting evidence IDs
- Analyst-selected contradicting evidence IDs

State:

ThreatTrace did not generate a causal explanation. The analyst must compare the supplied assessment with both evidence groups.

## Unresolved Assumptions

Display the validated `unresolved_assumptions` list in order. If empty, display:

None supplied.

## Evidence Gaps

Display the validated `evidence_gaps` list in order. If empty, display:

None supplied.

## What Would Strengthen the Assessment

Display the validated `strengthen_conditions` list in order. If empty, display:

None supplied.

## What Would Weaken the Assessment

Display the validated `weaken_conditions` list in order. If empty, display:

None supplied.

## What Would Reverse the Assessment

Display the validated `reversal_conditions` list in order. If empty, display:

None supplied.

## Recommended Next Evidence

Display the validated `recommended_next_evidence` list in order. If empty, display:

None supplied.

## Limitations

Display the validated `limitations` list in order. If empty, display:

None supplied.

## Analyst Next Step

State clearly, in meaning:

- No decision-analysis record was written.
- No evidence record was inserted or modified.
- No investigation status or confidence changed.
- No approval occurred.
- No containment or execution occurred.
- The preview remains advisory until an analyst independently decides what to do next.

Recommend exactly one existing command, and never invoke it automatically:

1. When `evidence_gaps` or `recommended_next_evidence` is nonempty, recommend `/query`.
2. Otherwise, recommend `/case-summary`.

Never recommend more than one command.

## No Confirmation Phrase

This command performs no write of any kind. Therefore:

- do not request the phrase "Add evidence" or any other confirmation phrase;
- do not define a new confirmation phrase for this command;
- do not pause for approval before displaying the preview — there is nothing to approve.

## Fatal-Boundary Behavior

No partial preview may ever be labeled valid after a fatal error in any category below. Every category stops the workflow entirely before the Final Preview is shown.

### Request error

Malformed input, a missing field, an unknown field, an invalid UUID, a duplicate or overlapping evidence ID, a blank assessment, an unsupported decision status, a malformed reasoning collection, or potential secret content in analyst reasoning.

### Database error

A query or tool failure, a malformed response, "investigation not found," duplicate rows, selected evidence missing, unrequested evidence, or cross-investigation evidence.

### Context-validation error

A Stage 1 CLI exit code of 2, malformed Stage 1 output, or a context ID/order mismatch.

### Warning-formatting error

A Stage 2 CLI exit code of 2, malformed Stage 2 output, or a warning count/order mismatch.

### Analysis-validation error

A Stage 3 CLI exit code of 2, malformed Stage 3 output, or an analysis handoff mismatch.

### Internal tooling error

Any CLI exit code of 1, an unsupported exit code from any of the three CLIs, or an unavailable Python launcher.

For every category, use a short, safe message. Never print a raw database error, a stack trace, a complete request object, a full evidence record, `details`, `provenance`, a token, a connection string, or an environment value.

## Required Output

Produce:

- Request Validation Result
- Secret Scan Result
- Investigation Lookup Result
- Evidence Lookup Result
- Decision Context
- Supporting Evidence
- Contradicting Evidence
- Context Warnings
- Current Assessment
- Why the Current Assessment Holds
- Unresolved Assumptions
- Evidence Gaps
- What Would Strengthen the Assessment
- What Would Weaken the Assessment
- What Would Reverse the Assessment
- Recommended Next Evidence
- Limitations
- Analyst Next Step

## Safety Rules

- Authorized investigations only.
- Read-only Supabase access — this workflow never inserts, updates, or deletes any record.
- Explicit analyst evidence selection only; this command never chooses or classifies evidence automatically.
- The current assessment and decision status are always analyst-supplied; this command never generates or replaces either one.
- No automatic evidence classification into supporting or contradicting groups.
- No AI-generated reasoning anywhere in this workflow.
- No database writes of any kind.
- No investigation mutation — status and confidence are read and displayed, never changed.
- No confidence calculation.
- No trust modification.
- No approval action of any kind.
- No containment action of any kind.
- No Red Team execution of any kind.
- No automatic slash-command chaining — the next-step command is only named, never invoked.
- No raw evidence details or provenance ever appear in the preview.
- Stop on every failed boundary described above; never display a partial preview after a fatal error.
