---
description: Update the status and/or confidence of an existing ThreatTrace investigation in Supabase after explicit confirmation
argument-hint: "[investigation UUID, new status and/or confidence, reason]"
---

# ThreatTrace Update Case Workflow

You update the status and/or confidence of an existing investigation in the connected ThreatTrace Supabase database.

## Update Input

$ARGUMENTS

## Workflow

1. Extract from the input:

- investigation UUID
- new status, new confidence, or both
- reason for the update

If the investigation UUID or a supporting reason is missing, request it before continuing.

2. Verify that the investigation exists in Supabase by looking it up in the `investigations` table using the supplied UUID.

- If it does not exist, stop and report this clearly. Do not proceed to validation or preview.

3. Read and display its current:

- title
- status
- confidence
- updated_at

4. Validate the proposed `status` as one of:

- open
- investigating
- awaiting_evidence
- escalated
- closed

5. Validate the proposed `confidence` as one of:

- low
- medium
- high
- unknown

6. Require a clear reason for the change, grounded in evidence already recorded for this investigation (e.g. in the `evidence` table) or otherwise supplied by the user. Do not accept a vague or unsupported reason — ask for specifics if needed.

7. Display an update preview showing:

- Current values (status, confidence)
- Proposed values (status, confidence)
- Reason

8. Do not update anything until the user types exactly:

Update case

9. After approval, update only the approved `status` and/or `confidence` fields on the `investigations` table for that UUID. Do not touch any other field, table, or row.

10. Read the investigation back and confirm:

- the approved values were saved
- `updated_at` changed automatically via the database trigger

11. Never modify the title, description, evidence, ATT&CK mappings, handoffs, detection results, or retests.

12. Stop and report the complete error if validation fails or the database update fails.

## Required Output

Produce:

- Investigation Validation
- Current Case State
- Update Validation
- Update Preview
- Approval Status
- Updated Investigation Record
- Trigger Verification
- Recommended Next Action

## Safety Rules

- Do not change case status or confidence without supporting evidence.
- Do not invent evidence.
- Do not perform automatic escalation.
- Do not modify database schema, policies, indexes, triggers, or constraints.
- Do not update anything without explicit user approval.
