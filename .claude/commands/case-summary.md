---
description: Produce a complete, read-only summary and timeline of a ThreatTrace investigation from Supabase
argument-hint: "[investigation UUID]"
---

# ThreatTrace Case Summary Workflow

You produce a complete, read-only summary of an existing investigation in the connected ThreatTrace Supabase database. This command never inserts, updates, or deletes any record.

## Summary Input

$ARGUMENTS

## Workflow

1. Extract the investigation UUID from the input. If it is missing, request it before continuing.

2. Verify that the investigation exists in Supabase by looking it up in the `investigations` table.

- If it does not exist, stop and report this clearly. Do not proceed further.

3. Read the investigation record:

- id
- title
- description
- entry_point
- status
- confidence
- created_at
- updated_at

4. Read all related records for this investigation from:

- evidence
- attack_mappings
- handoffs
- detection_results
- retests

5. For any of these tables with zero related records, state that clearly rather than omitting the section.

6. Produce a chronological investigation timeline using every available timestamp across the investigation record and all related records (e.g. `created_at`, `updated_at`, `observed_at`).

7. Summarize:

- Confirmed facts (only what is actually stored)
- Current assumptions (explicitly labeled as assumptions, not facts)
- Missing telemetry (based on gaps visible in the stored evidence)
- Supported or provisional ATT&CK mappings, labeled accordingly
- Current handoff state (most recent handoff status and roles involved)
- Detection validation status (most recent detection result, or none on file)
- Pending retests (any with `approval_status` of `pending` or `approved`)

8. Recommend the next investigation action based only on what is stored — do not introduce external assumptions or invented telemetry.

9. Do not invent, infer, or fabricate any missing information. If something is unknown, say so explicitly.

10. Do not insert, update, or delete anything in any table.

11. Do not modify database schema, policies, indexes, triggers, or constraints.

## Required Output

Produce:

- Case Overview
- Current State
- Evidence Summary
- MITRE ATT&CK Mappings
- Team Handoffs
- Detection Results
- Retest Status
- Investigation Timeline
- Missing Information
- Recommended Next Action
- Read-Only Execution Confirmation

## Safety Rules

- Read-only: never insert, update, or delete any Supabase record.
- Never modify database schema, policies, indexes, triggers, or constraints.
- Never invent facts, evidence, ATT&CK mappings, or timestamps not present in the database.
- Clearly distinguish confirmed stored facts from assumptions.
- Stop and report the complete error if the investigation does not exist or a read operation fails.
