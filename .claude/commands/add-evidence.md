---
description: Attach a new evidence record to an existing ThreatTrace investigation in Supabase after explicit confirmation
argument-hint: "[investigation UUID and evidence details]"
---

# ThreatTrace Add Evidence Workflow

You attach structured, normalized evidence records to an existing investigation in the connected ThreatTrace Supabase database. This command is the **only** evidence write path in ThreatTrace. Every proposed record must pass through the shared normalizer (`core/evidence_normalizer.py`) before it is previewed or inserted — that module, not this command, is the single source of truth for field rules.

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

5. Validate and normalize the assembled payload by calling `core.evidence_normalizer.normalize_evidence`. Treat that module as the single source of truth for required fields, allowed top-level fields, controlled vocabularies, timestamp validation, string trimming, default values, `details`/`provenance` validation, and the Boolean `supports_hypothesis` check — do not re-implement or duplicate any of those rules here.

Invoke it as a short-lived, read-only local Python subprocess (never a long-running process), run from the project root so `core` imports as a normal package:

- Prefer `py` (the Windows launcher) when available.
- Otherwise prefer `python3` (typical on macOS/Linux) when available.
- Only fall back to plain `python` if it is confirmed to resolve to Python 3.10 or later.
- Never install Python or any package to satisfy this step.

Pass the assembled payload as JSON on stdin and read a single JSON result from stdout, for example:

```
<python-launcher> -c "
import json, sys
from core.evidence_normalizer import normalize_evidence, EvidenceValidationError
try:
    result = normalize_evidence(json.loads(sys.stdin.read()))
except EvidenceValidationError as exc:
    print(json.dumps({\"ok\": False, \"error\": str(exc)}))
else:
    print(json.dumps({\"ok\": True, \"result\": result}, default=str))
"
```

If no suitable launcher is found, the `core` package cannot be imported, or the subprocess fails or returns anything other than the expected JSON shape: **fail closed**. Do not display a preview, do not request confirmation, do not write to Supabase, and report the error clearly to the analyst.

6. If the normalizer reports failure (`EvidenceValidationError`), display a concise message beginning with:

Evidence validation failed:

- Include only the human-readable validation message the normalizer returned.
- Do not display a preview.
- Do not ask for confirmation.
- Do not insert anything.

7. After successful normalization, display:

## Normalized Evidence Preview

Show exactly the normalized dictionary that will be inserted, including every one of:

`investigation_id`, `evidence_type`, `source`, `observed_at`, `details`, `supports_hypothesis`, `source_type`, `source_identifier`, `source_location`, `ingested_at`, `assertion_type`, `trust_level`, `confidence`, `event_id`, `host_name`, `user_name`, `process_name`, `command_line`, `ip_address`, `file_hash`, `provenance`.

Clearly label any value that defaulted to `unknown`, `None`, or an empty object, so the analyst can see what the normalizer filled in versus what they supplied.

8. Do not insert the record until the user explicitly confirms with exactly:

Add evidence

- Displaying the normalized preview performs no database write by itself.
- Any response other than the exact phrase — including general agreement such as "yes", "continue", or "looks good" — cancels or pauses the write. Do not treat it as confirmation.

9. After exact confirmation, use the connected Supabase MCP server to insert **one** record into the `evidence` table:

- Insert the normalized dictionary produced in step 5 — never the original raw payload.
- Do not add `id` or `created_at`; both are database-generated.
- Do not add any field the normalizer did not return.
- Do not re-run normalization with different values at this point. Insert exactly what was previewed and approved.

10. Read the new record back using its generated UUID.

11. Compare the stored evidence fields against the exact approved normalized preview.

- Report any mismatch clearly.
- Never silently correct or overwrite a mismatch.

## Example

Input:

- `evidence_type`: `windows_event`
- `source`: `Hayabusa CSV`
- `source_type`: `hayabusa`
- `assertion_type`: `observation`
- `event_id`: `4104`
- `trust_level`: `high`
- `confidence`: `medium`

Normalized result:

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
- `core.evidence_normalizer.normalize_evidence` is the single source of truth for field validation; do not duplicate or reimplement its rules in this command.
- If the normalizer cannot be loaded or executed, fail closed: no preview, no confirmation prompt, no insert.
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
