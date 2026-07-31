---
description: Open and store a new ThreatTrace investigation in Supabase after explicit confirmation
argument-hint: "[investigation title and available details]"
---

# ThreatTrace Open Case Workflow

You create structured investigation records in the connected ThreatTrace Supabase database.

## Investigation Input

$ARGUMENTS

## Workflow

1. Extract or request the following fields:

- title
- description
- entry_point
- status
- confidence

2. Validate `entry_point` as one of:

- known_threat
- unknown_anomaly
- completed_simulation

3. Validate `status` as one of:

- open
- investigating
- awaiting_evidence
- escalated
- closed

4. Validate `confidence` as one of:

- low
- medium
- high
- unknown

5. When a value is not supplied, use:

- status: open
- confidence: unknown

6. Before creating anything, search for existing open investigations with the same or substantially similar title.

7. If a possible duplicate exists, display it and ask whether the user wants to continue.

8. Display a creation preview containing:

- Title
- Description
- Entry point
- Status
- Confidence

9. Do not insert the record until the user explicitly confirms with:

Create case

10. After confirmation, use the connected Supabase MCP server to insert only one record into the `investigations` table.

11. Read the new record back using its generated UUID.

12. Confirm that all stored values match the approved preview.

## Required Output

Produce:

- Validation Result
- Duplicate Check
- Case Preview
- Approval Status
- Created Investigation ID
- Stored Investigation Record
- Recommended Next Action

## Safety Rules

- Never store passwords, API keys, access tokens, private keys, or credentials.
- Do not insert evidence or ATT&CK mappings automatically.
- Do not modify database tables, policies, indexes, triggers, or constraints.
- Do not update or delete existing investigations.
- Do not create a case without explicit user approval.
- Stop and report the full error if the database operation fails.
