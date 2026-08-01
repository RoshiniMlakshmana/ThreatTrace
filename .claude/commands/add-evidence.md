---
description: Attach a new evidence record to an existing ThreatTrace investigation in Supabase after explicit confirmation
argument-hint: "[investigation UUID and evidence details]"
---

# ThreatTrace Add Evidence Workflow

You attach structured, normalized evidence records to an existing investigation in the connected ThreatTrace Supabase database. This command is the **only** evidence write path in ThreatTrace. Every proposed record must pass through the official evidence-normalization CLI adapter (`core.evidence_cli`, wrapping `core/evidence_normalizer.py`) before it is previewed or inserted — that adapter, not this command, is the single source of truth for field rules. After normalization, every record also receives an advisory-only source-trust assessment from `core.source_trust_cli` (wrapping `core/source_trust_policy.py`) — a recommendation the analyst may accept or decline, but which is never adopted automatically.

## Evidence Input

$ARGUMENTS

## Workflow

1. Extract the investigation UUID and the evidence details from the input. If the investigation UUID is missing, request it before continuing.

2. Verify that the investigation exists in Supabase by looking it up in the `investigations` table using the supplied UUID (read-only).

- If it does not exist, stop and report this clearly. Do not proceed to evidence collection, normalization, or insertion.

3. Assemble an evidence payload from the supplied arguments.

Required fields:

- `investigation_id`
- `evidence_type`
- `source`

Supported optional fields:

- `observed_at`
- `details`
- `supports_hypothesis`
- `source_type`
- `source_identifier`
- `source_location`
- `ingested_at`
- `assertion_type`
- `trust_level`
- `confidence`
- `event_id`
- `host_name`
- `user_name`
- `process_name`
- `command_line`
- `ip_address`
- `file_hash`
- `provenance`

Do not invent values for fields the input did not supply — leave them out of the assembled payload and let the normalizer apply its own defaults.

4. Scan every supplied field, including nested `details` and `provenance`, for suspected:

- passwords
- API keys
- access tokens
- credentials
- private keys
- connection strings

If any suspected secret is found:

- Do not normalize the payload.
- Do not display a preview.
- Do not request confirmation.
- Do not write to Supabase.
- Tell the analyst which field category must be cleaned up (e.g. "the `details` field appears to contain a credential") without displaying the suspected secret value itself, and ask them to resubmit.

5. Validate and normalize the assembled payload by invoking the official evidence-normalization CLI adapter, `core.evidence_cli`. Treat it — and the `core.evidence_normalizer.normalize_evidence` function it wraps — as the single source of truth for required fields, allowed top-level fields, controlled vocabularies, timestamp validation, string trimming, default values, `details`/`provenance` validation, and the Boolean `supports_hypothesis` check. Do not re-implement, duplicate, or write custom inline Python for any of those rules here.

Invoke it as a short-lived, read-only local Python module run from the project root (never a long-running process):

- Windows: `py -m core.evidence_cli`
- macOS or Linux: `python3 -m core.evidence_cli`
- Only fall back to plain `python -m core.evidence_cli` if it is confirmed to resolve to Python 3.10 or later.
- Never install Python or any package to satisfy this step.

Send exactly one JSON object — containing only the assembled payload's supported evidence fields and nothing else — through the adapter's **stdin**. Do not:

- pass evidence through command-line arguments;
- place evidence in a temporary repository file;
- include any suspected secret (secrets are handled in step 4, before this step ever runs);
- add unsupported fields, `id`, or `created_at`.

Then read the adapter's result strictly by its exit code:

- **Exit code 0**: stderr must be empty. Parse stdout as JSON. Use that parsed dictionary — and only that dictionary — for the preview and the eventual insert.
- **Exit code 2**: input or evidence validation failed. Display the adapter's concise stderr message (it already begins with either `Evidence validation failed:` or `Invalid JSON input:`). Do not preview. Do not request confirmation. Do not write.
- **Exit code 1**: an unexpected normalization failure occurred. Display the adapter's generic stderr message. Do not preview. Do not request confirmation. Do not write.
- **Any other exit code**: fail closed. Do not write. Report that normalization could not be completed safely.

Treat malformed output as failure even after exit code 0, without attempting to repair it. Fail closed if:

- stdout is empty;
- stdout is not valid JSON;
- stdout contains more than one JSON value;
- the parsed result is not a JSON object;
- stderr contains any unexpected content.

6. After successful normalization, parse the normalized evidence JSON `core.evidence_cli` returned — this is the record every later step reasons about. Do not display it yet; the source-trust assessment (next) must run first.

## Source-Trust Assessment

After successful normalization and before any preview or confirmation:

1. Send the exact normalized evidence JSON object — unmodified — through **stdin** to the source-trust CLI adapter, `core.source_trust_cli`:

- Windows: `py -m core.source_trust_cli`
- macOS or Linux: `python3 -m core.source_trust_cli`
- Only fall back to plain `python -m core.source_trust_cli` if it is confirmed to resolve to Python 3.10 or later.

Do not:

- pass evidence through command-line arguments;
- create a temporary repository file;
- modify the normalized evidence before assessment;
- invoke `core.source_trust_policy.assess_source_trust` directly with improvised inline Python — the CLI adapter is the only invocation path.

2. Read the adapter's result strictly by its exit code:

- **Exit code 0**: stdout must contain exactly one JSON object and stderr must be empty. Parse the advisory assessment.
- **Exit code 2**: display the concise policy or input error from stderr. Do not preview. Do not request confirmation. Do not write to Supabase.
- **Exit code 1**: display the generic failure message from stderr. Do not preview. Do not request confirmation. Do not write.
- **Any other exit code**: fail closed. Report that source-trust assessment could not be completed safely. Do not write.

3. Treat malformed success output as failure, without attempting to repair it. Reject the output if:

- stdout is empty;
- stdout is not valid JSON;
- stdout contains more than one JSON value;
- the parsed value is not a JSON object;
- stderr contains any content on exit code 0;
- the object contains any key other than `recommended_trust_level`, `reason_codes`, and `conflicts_with_supplied_trust_level`.

## Advisory Display

Display:

## Advisory Source-Trust Assessment

Show exactly:

- Current trust level (the normalized record's `trust_level`)
- Recommended trust level (`recommended_trust_level`)
- Deterministic reason codes (`reason_codes`)
- Whether the recommendation conflicts with the supplied trust level (`conflicts_with_supplied_trust_level`)

Explain plainly:

- This is an advisory source-reliability assessment.
- It does not determine whether the evidence content is true.
- It does not calculate confidence.
- It does not modify the evidence automatically.

## Analyst Decision

If `recommended_trust_level` matches the normalized record's current `trust_level`:

- State that no trust-level change is proposed.
- Continue directly to the Final Evidence Preview using the normalized record from step 5/6 as the final candidate.

If the recommendation differs, or the current `trust_level` is `unknown`:

Require exactly one of these two analyst decisions before continuing — do not proceed on anything else:

Use recommended trust

or:

Keep current trust

**Use recommended trust:**

- Create a copy of the normalized evidence dictionary. Change only `trust_level` to `recommended_trust_level`. Do not change `confidence` or any other field.
- Send that updated candidate through `core.evidence_cli` again, via stdin only, applying the exact same strict exit-code handling and malformed-output rejection used in the normalization step above.
- Confirm that only `trust_level` changed compared with the earlier normalized record. If any other value changed unexpectedly, fail closed: do not preview, do not request confirmation, do not write.
- Use this newly re-normalized result as the final candidate.

**Keep current trust:**

- Preserve the original normalized evidence dictionary unchanged.
- Do not rerun the normalizer.
- Use it as the final candidate.

**Any other response**: cancel or pause the operation. Do not display the Final Evidence Preview. Do not write to Supabase.

The source-trust recommendation must never be adopted automatically.

## Final Preview and Insertion

1. After the trust decision resolves, display:

## Final Evidence Preview

Show exactly the final candidate dictionary that would be inserted — do not reconstruct, re-normalize, or silently change it. It will include every one of:

`investigation_id`, `evidence_type`, `source`, `observed_at`, `details`, `supports_hypothesis`, `source_type`, `source_identifier`, `source_location`, `ingested_at`, `assertion_type`, `trust_level`, `confidence`, `event_id`, `host_name`, `user_name`, `process_name`, `command_line`, `ip_address`, `file_hash`, `provenance`.

Clearly label any value that defaulted to `unknown`, `None`, or an empty object.

2. Do not insert the record until the user explicitly confirms with exactly:

Add evidence

- Displaying the Final Evidence Preview performs no database write by itself.
- Any response other than the exact phrase — including "yes", "continue", "approved", "looks good", "Use recommended trust", "Keep current trust", or similar wording — cancels or pauses the write. Do not treat it as confirmation.

3. After exact confirmation, use the connected Supabase MCP server to insert **one** record into the `evidence` table:

- Insert exactly the final candidate dictionary — never the original raw payload.
- Do not add `id` or `created_at`; both are database-generated.
- Do not add any field the final candidate did not contain.
- Do not invoke the trust policy again. Do not invoke the evidence normalizer again. Insert exactly what was previewed and approved.

4. Read the new record back using its generated UUID.

5. Compare the stored evidence fields against the exact approved Final Evidence Preview, accounting only for database-generated fields (`id`, `created_at`).

- Report any mismatch clearly.
- Never silently correct or overwrite a mismatch.

## Example

Adapter flow:

```
Evidence payload JSON
        ↓
py -m core.evidence_cli
        ↓
Normalized JSON
        ↓
Preview
        ↓
Exact "Add evidence" confirmation
        ↓
Supabase insert
```

Input JSON sent to the adapter's stdin:

- `evidence_type`: `windows_event`
- `source`: `Hayabusa CSV`
- `source_type`: `hayabusa`
- `assertion_type`: `observation`
- `event_id`: `4104`
- `trust_level`: `high`
- `confidence`: `medium`

Normalized result the adapter returns on stdout:

- `event_id` becomes the string `"4104"`
- controlled values (`source_type`, `assertion_type`, `trust_level`, `confidence`) are lowercase
- missing optional strings (e.g. `host_name`, `source_identifier`) become `None`
- missing `details` and `provenance` become `{}`
- `ingested_at` is generated in UTC

(This example is illustrative only — it does not contain real credentials, hosts, users, or evidence.)

## Required Output

Produce:

- Investigation Validation
- Secret Scan Result
- Normalization Result
- Advisory Source-Trust Assessment
- Trust Decision
- Final Evidence Preview
- Approval Status
- Created Evidence ID
- Stored Evidence Record
- Read-Back Verification
- Recommended Next Investigation Step

## Safety Rules

- Never store passwords, API keys, access tokens, private keys, credentials, or connection strings — scan every supplied field, including nested `details` and `provenance`, before normalization.
- `core.evidence_cli` (wrapping `core.evidence_normalizer.normalize_evidence`) is the single source of truth for field validation; do not duplicate, reimplement, or write inline Python for its rules in this command.
- `core.source_trust_cli` (wrapping `core.source_trust_policy.assess_source_trust`) is advisory only. Its recommendation must never be adopted automatically — only an explicit "Use recommended trust" decision may change `trust_level`, and even then only that one field changes.
- Fail closed on any adapter problem, for either CLI: a non-zero or unrecognized exit code, empty stdout, non-JSON stdout, more than one JSON value on stdout, a non-object result, unexpected stderr content on success, or (for the source-trust CLI specifically) a result object containing any key outside `recommended_trust_level`, `reason_codes`, and `conflicts_with_supplied_trust_level`. In every such case: no preview, no confirmation prompt, no insert.
- Do not modify or delete existing evidence.
- Do not modify or delete the parent investigation.
- Do not modify database tables, policies, indexes, triggers, or constraints.
- Do not insert evidence without the exact confirmation phrase "Add evidence".
- Insert only the final candidate dictionary; never the raw input.
- Do not automatically ingest Hayabusa CSV files or any other external source — this command only accepts evidence explicitly supplied in its input.
- Do not infer trust, confidence, ATT&CK techniques, or recommendations that were not explicitly supplied. The source-trust CLI's recommendation is advisory input for the analyst, not an inference this command makes on its own.
- Do not calculate or modify `confidence` anywhere in this workflow.
- Do not compute or store an evidence hash.
- Do not add approval IDs, reviewer identity, action hashes, expiry, or audit logic.
- Do not open a second evidence write path; this command remains the only one.
- Stop and report the full error if the investigation does not exist or any step (secret scan, normalization, source-trust assessment, or the database operation) fails.
