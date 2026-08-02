---
description: Deprecated compatibility notice — direct case updates are disabled; use the approval-gated workflow instead
argument-hint: "(ignored — this command performs no action)"
---

# ThreatTrace Update Case — Deprecated Compatibility Command

`/update-case` is a **deprecated compatibility command**. It is static guidance only: it performs no database operation, no investigation lookup, no approval lookup, no preview, no validation, and no mutation of any kind. Direct case updates through this command are disabled. Status and confidence changes now require the approval-gated workflow:

`/request-case-update` → `/review-approval` → `/apply-case-update`

This command always returns the one static response below, regardless of what is supplied as input. It never queries Supabase, never calls MCP, never generates or executes SQL, and never updates `public.investigations` or `public.approvals`.

## Command Input (Ignored)

$ARGUMENTS

This command never parses, inspects, interprets, validates, executes, or echoes the text above, and it never includes any part of it in its own response. Any argument value has no effect on this command's behavior — the static response below is identical no matter what is supplied here.

## Required Response

Always produce exactly this response, in this order, and perform nothing else:

1. State clearly: "Direct case updates through `/update-case` are disabled."
2. State clearly: "Status and confidence changes now require the approval-gated workflow."
3. Present the three-command workflow, in this exact order:
   1. `/request-case-update` — creates a pending approval request for a proposed `status`/`confidence` change; it does not update the investigation.
   2. `/review-approval` — a reviewer approves or rejects the pending request; it does not update the investigation.
   3. `/apply-case-update` — atomically consumes an approved request and applies the change to the investigation.
4. State clearly: "No database operation was performed."
5. State clearly: "The investigation was not updated."
6. Show the example below.
7. Recommend that the caller run `/request-case-update` next, and never anything else.

### Example

```
/request-case-update {"investigation_id":"11111111-1111-4111-8111-111111111111","requested_by":"analyst@example.com","status":"investigating"}
```

`requested_by` above is a **claimed requester identity** — not an authenticated or verified one — exactly as `/request-case-update` itself already documents. This example is illustrative only. It is never executed, forwarded to, delegated to, or simulated by this command.

## This Command Never Invokes the Workflow It Describes

This command only names `/request-case-update`, `/review-approval`, and `/apply-case-update` as the caller's own next steps. It never invokes, executes, forwards to, delegates to, or simulates any of the three commands, and it never chains one command into another automatically.

## No Confirmation Phrase

The previous typed-confirmation phrase this command once required is removed completely and does not appear anywhere in this file. No replacement phrase is defined in its place. No typed word or phrase — including "yes", "confirm", "proceed", "approve", or any other natural-language confirmation — authorizes this command to perform any action, because this command never performs a mutating action of any kind for any input.

## Absolute Non-Execution Boundaries

This command must never:

- query an investigation;
- query an approval;
- call Supabase;
- call MCP;
- call `mcp__supabase__execute_sql`;
- call `apply_migration`;
- execute SQL;
- generate SQL;
- create a persistence descriptor;
- call `core.approval_request_cli`;
- call `core.approval_transition_cli`;
- call `core.approval_bridge_cli`;
- call `core.approval_mcp_adapter_cli`;
- update `public.investigations`;
- update `public.approvals`;
- invoke `consume_approval_and_update_investigation_state`;
- create an approval;
- approve an approval;
- reject an approval;
- consume an approval;
- perform a preview;
- perform a retry;
- perform a fallback mutation;
- use a direct database client;
- use a REST request;
- execute a shell command;
- run a Python script;
- access the network;
- expose a credential, a token, a project URL, a project reference, generated SQL, a raw database error, or a stack trace.

This command is static guidance only. It performs no I/O of any kind.

## Required Output

Produce exactly:

- Deprecation Notice
- Approval-Gated Workflow
- Example Request
- Recommended Next Action

## Safety Rules

- This is a deprecated compatibility command — static guidance only, never a live operation.
- Never parse, inspect, interpret, validate, execute, or echo `$ARGUMENTS`.
- Never look up an investigation or an approval.
- Never show a preview of any kind.
- Never require, accept, or recognize any typed confirmation phrase as authorization.
- Never call Supabase, MCP, or any of the approval workflow's Python CLIs.
- Never generate or execute SQL.
- Never update `public.investigations` or `public.approvals`.
- Never approve, reject, or consume an approval.
- Never invoke, execute, forward to, delegate to, or simulate `/request-case-update`, `/review-approval`, or `/apply-case-update` — only name them as the caller's own next steps.
- Never retry or fall back to any mutation.
- Never expose a credential, a token, a project URL, a project reference, generated SQL, a raw database error, or a stack trace.
