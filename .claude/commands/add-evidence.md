---
description: Attach a new evidence record to an existing ThreatTrace investigation in Supabase after explicit confirmation
argument-hint: "[investigation UUID and evidence details]"
---

# ThreatTrace Add Evidence Workflow

You attach structured evidence records to an existing investigation in the connected ThreatTrace Supabase database.

## Evidence Input

$ARGUMENTS

## Workflow

1. Extract the investigation UUID and the evidence details from the input. If the investigation UUID is missing, request it before continuing.

2. Verify that the investigation exists in Supabase by looking it up in the `investigations` table using the supplied UUID.

- If it does not exist, stop and report this clearly. Do not proceed to evidence collection or insertion.

3. Extract or request the following evidence fields:

- evidence_type
- source
- observed_at
- details
- supports_hypothesis: true, false, or null

4. Validate `supports_hypothesis` as one of:

- true
- false
- null

5. Never store passwords, API keys, tokens, credentials, or private keys in any field, including `details`. If the input contains any such value, refuse to include it and ask the user to remove it.

6. Display an evidence preview containing:

- Investigation ID
- Evidence type
- Source
- Observed at
- Details
- Supports hypothesis

7. Do not insert the record until the user explicitly confirms with:

Add evidence

8. After confirmation, use the connected Supabase MCP server to insert only one record into the `evidence` table.

9. Read the new record back using its generated UUID.

10. Confirm that all stored values match the approved preview.

## Required Output

Produce:

- Investigation Validation
- Evidence Validation
- Evidence Preview
- Approval Status
- Created Evidence ID
- Stored Evidence Record
- Recommended Next Investigation Step

## Safety Rules

- Never store passwords, API keys, access tokens, private keys, or credentials.
- Do not modify or delete existing evidence.
- Do not modify or delete the parent investigation.
- Do not modify database tables, policies, indexes, triggers, or constraints.
- Do not insert evidence without explicit user approval.
- Stop and report the full error if the investigation does not exist or the database operation fails.
