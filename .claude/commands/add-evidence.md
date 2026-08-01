---
description: Attach a new evidence record to an existing ThreatTrace investigation in Supabase after explicit confirmation
argument-hint: "[investigation UUID and evidence details]"
---

# ThreatTrace Add Evidence Workflow

You attach structured, normalized evidence records to an existing investigation in the connected ThreatTrace Supabase database. This command is the **only** evidence write path in ThreatTrace. Every proposed record must pass through the official evidence-normalization CLI adapter (`core.evidence_cli`, wrapping `core/evidence_normalizer.py`) before it is previewed or inserted — that adapter, not this command, is the single source of truth for field rules.

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

6. After successful normalization, display:

## Normalized Evidence Preview

Show exactly the parsed JSON object `core.evidence_cli` returned on stdout — do not reconstruct, re-normalize, or silently change it after the adapter returns it. It will include every one of:

`investigation_id`, `evidence_type`, `source`, `observed_at`, `details`, `supports_hypothesis`, `source_type`, `source_identifier`, `source_location`, `ingested_at`, `assertion_type`, `trust_level`, `confidence`, `event_id`, `host_name`, `user_name`, `process_name`, `command_line`, `ip_address`, `file_hash`, `provenance`.

Clearly label any value that defaulted to `unknown`, `None`, or an empty object, so the analyst can see what the normalizer filled in versus what they supplied.

7. Do not insert the record until the user explicitly confirms with exactly:

Add evidence

- Displaying the normalized preview performs no database write by itself.
- Any response other than the exact phrase — including "yes", "continue", "approved", "looks good", or similar wording — cancels or pauses the write. Do not treat it as confirmation.

8. After exact confirmation, use the connected Supabase MCP server to insert **one** record into the `evidence` table:

- Insert exactly the parsed normalized dictionary the CLI returned in step 5 — never the original raw payload.
- Do not add `id` or `created_at`; both are database-generated.
- Do not add any field the CLI did not return.
- Do not invoke `core.evidence_cli` again or re-run normalization with different values at this point. Insert exactly what was previewed and approved.

9. Read the new record back using its generated UUID.

10. Compare the stored evidence fields against the exact approved normalized preview, accounting only for database-generated fields (`id`, `created_at`).

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
- Normalized Evidence Preview
- Approval Status
- Created Evidence ID
- Stored Evidence Record
- Read-Back Verification
- Recommended Next Investigation Step

## Safety Rules

- Never store passwords, API keys, access tokens, private keys, credentials, or connection strings — scan every supplied field, including nested `details` and `provenance`, before normalization.
- `core.evidence_cli` (wrapping `core.evidence_normalizer.normalize_evidence`) is the single source of truth for field validation; do not duplicate, reimplement, or write inline Python for its rules in this command.
- Fail closed on any adapter problem: a non-zero or unrecognized exit code, empty stdout, non-JSON stdout, more than one JSON value on stdout, a non-object result, or unexpected stderr content on success. In every such case: no preview, no confirmation prompt, no insert.
- Do not modify or delete existing evidence.
- Do not modify or delete the parent investigation.
- Do not modify database tables, policies, indexes, triggers, or constraints.
- Do not insert evidence without the exact confirmation phrase "Add evidence".
- Insert only the normalized dictionary; never the raw input.
- Do not automatically ingest Hayabusa CSV files or any other external source — this command only accepts evidence explicitly supplied in its input.
- Do not infer trust, confidence, ATT&CK techniques, or recommendations that were not explicitly supplied.
- Do not compute or store an evidence hash.
- Do not add approval IDs, reviewer identity, action hashes, expiry, or audit logic.
- Do not open a second evidence write path; this command remains the only one.
- Stop and report the full error if the investigation does not exist or any step (secret scan, normalization, or the database operation) fails.
