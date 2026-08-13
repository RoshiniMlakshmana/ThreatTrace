---
description: Compute one deterministic, context-aware operational-priority recommendation for a caller-supplied technical finding, through the read-only Block 15B prioritization boundary
argument-hint: "{operation: \"prioritize\", finding: {...}, context: {...}}"
---

# ThreatTrace Context Prioritization Workflow

`/prioritize-finding` is Block 15B's context-aware prioritization boundary: it answers exactly one thing --

*given an already-existing technical finding and this organization's own caller-supplied context, how urgently should THIS organization investigate/respond to it?*

-- by consulting the existing, already-committed, deterministic core (`core.context_prioritization`, reached only through `core.context_prioritization_cli`) -- and nothing else. This command is strictly a transport adapter. **One invocation runs exactly one prioritization.**

Caller-supplied `operation` + complete `finding`/`context` → command-level envelope validation → `core.context_prioritization_cli`, unchanged → deterministic prioritization result

## Technical Truth Is Never the Same Thing as Operational Priority

The finding's own `finding_status`, `technical_severity`, `vulnerability_class`, `evidence`, `owasp_category`, `cwe`, and `validation` are never changed by this command -- they are exactly what the caller's `finding` already said. `operational_priority` is a **separate, new judgment about urgency of investigation/response**, layered on top of an unchanged technical truth. Saying "the vulnerability became critical" is never an accurate description of this command's output -- say instead: *the technical finding remains `<technical_severity>` severity, but this organization's context makes it `<operational_priority>`-priority for investigation/response.*

## What This Provides -- and Does Not

The strongest honest claim this command can ever make:

> Given a caller-supplied technical finding and caller-supplied organization context, ThreatTrace can compute a deterministic, explainable investigation/response priority recommendation -- never a change to the finding's own technical truth.

It is **not**: a CVSS score; an AI/ML-generated risk score; a probability or likelihood of compromise; a compliance/regulatory determination; proof that claimed detection coverage actually fires (no Red Team validation has occurred); proof that claimed compensating controls actually work (never independently verified); or proof that the supplied organization context is authentic, current, or complete. `human_review_required` is always `true` -- this command never approves, closes, or acts on a finding.

## Request Input

$ARGUMENTS

## Stage 0 -- Command-Level Input Shape Validation

`$ARGUMENTS` must be exactly one JSON object. Perform every check below, in order, before Stage 1 -- before any CLI invocation:

1. Parse `$ARGUMENTS` as exactly one JSON value.
2. Reject malformed JSON.
3. Reject trailing non-whitespace content after the one parsed JSON value.
4. Reject a top-level value that is not a JSON object.
5. Require an `"operation"` field equal to exactly `"prioritize"`. Reject any other value, including a missing one.
6. Require exactly `operation`, `finding`, `context` -- the same three-key envelope `core.context_prioritization_cli` itself requires. Reject a missing or extra field.

This command performs **no semantic validation of `finding` or `context` beyond confirming the envelope has exactly these three keys.** It does not decide whether `finding` is shaped correctly, whether `context` supplies all ten required fields, or whether any value belongs to its closed vocabulary -- every one of those is always decided later, entirely by `core.context_prioritization`, reached only through `core.context_prioritization_cli`. This command never inserts, synthesizes, defaults, or overwrites `operation`/`finding`/`context` on the caller's behalf, and never infers any organization-context value from a target URL, hostname, application name, webpage evidence, vulnerability title, or industry guess -- if the caller omits a required context field, that surfaces as a normal validation failure, never a silently invented default. Every value is passed through completely unchanged -- never trimmed, lowercased, or reordered.

Call the fully validated envelope the **candidate envelope**.

## Python Launcher Selection

Use the existing project convention for selecting a Python launcher:

1. Try `py`.
2. Otherwise try `python3`.
3. Otherwise use a `python` executable only after confirming it resolves to Python 3.10 or later.

Before continuing, confirm the selected launcher can import `core.context_prioritization_cli`. If no launcher can be selected, or the import check fails, stop and report `CONTEXT_PRIORITIZATION_CLI_UNAVAILABLE`. Do not install any package. Do not modify the environment.

## Safe CLI Transport

Invoke the CLI through **stdin only**, exactly following the safe invocation pattern already established by `/evaluate-tool-call`, `/evaluate-agent-tool-call`, `/create-decision-binding`, `/ai-security-lab`, `/record-analyst-feedback`, `/audit-dashboard`, `/integration-demo`, and `/bug-bounty`. Never pass JSON through command-line arguments, never create a temporary JSON file, never interpolate caller content directly into executable shell code, and never write request data to disk.

## Stage 1 -- Invoke the Context Prioritization CLI

Send the **candidate envelope exactly as the caller supplied it** -- every field, including the caller's own `operation`, unchanged, unreordered, unrepaired -- through **stdin only** to `py -m core.context_prioritization_cli` (or the equivalent selected launcher). This command never adds, removes, renames, normalizes, redacts, reorders, or otherwise transforms any field or value. Never call `core.context_prioritization` directly, and never reimplement any finding-shape validation, context-vocabulary check, scoring weight, clamp, reason-code, or completeness rule this document does not own. Never automatically invoke `/bug-bounty`, `/red-team`, `/blue-team`, `/purple-loop`, `/request-case-update`, `/review-approval`, or `/apply-case-update`.

### Context Prioritization CLI exit handling

- **0**: success -- a valid prioritization result, including one whose `finding_status` is `"candidate"` and whose computed `operational_priority` is `"critical"`. That combination is never a command failure. Continue to the output validation below.
- **2**: a deterministic command/CLI-envelope or core structural-validation failure -- stop and report `CONTEXT_PRIORITIZATION_VALIDATION_FAILED`.
- **1**: an unexpected internal failure -- stop and report `CONTEXT_PRIORITIZATION_INTERNAL_FAILURE`.
- **any other code**: stop and report `CONTEXT_PRIORITIZATION_INTERNAL_FAILURE`.

Never automatically retry any of these outcomes, and never fall back to displaying a partially-constructed or hand-assembled result.

### Context Prioritization CLI success-output validation

Require stdout to be exactly one JSON object containing exactly the thirteen fields `core.context_prioritization.prioritize_finding` always returns: `prioritization_version`, `finding_id`, `technical_severity`, `finding_status`, `confidence`, `context`, `priority_score`, `operational_priority`, `priority_direction`, `priority_reasons`, `context_completeness`, `human_review_required`, `execution_performed`. Require `prioritization_version` to equal exactly `"1"`, `human_review_required` to equal exactly `true`, and `execution_performed` to equal exactly `false`.

If the result is missing a required field, contains an unrecognized field, or has `human_review_required`/`execution_performed` other than their fixed values: stop, report `CONTEXT_PRIORITIZATION_VALIDATION_FAILED`, and never display the result as if it were successful. Do not repair, complete, or reinterpret a malformed result by hand.

Call the fully validated result the **prioritization result**.

## Required Output

Produce, only after the prioritization result passes every check above:

- `finding_id`, `technical_severity`, `finding_status`, `confidence` -- all echoed exactly as returned.
- `context`, exactly as returned, labeled as **caller-supplied organization context**, never as verified or authenticated.
- `priority_score` (`base`, `raw_modifier`, `applied_modifier`, `final`), labeled explicitly as **ThreatTrace's own deterministic internal prioritization bands** -- never CVSS, an AI/ML risk score, a probability, a likelihood, an exploitability score, or a financial-loss score.
- `operational_priority`, clearly distinguished from `technical_severity` in prose -- e.g. *"the technical finding remains `medium` severity; this organization's context makes it `critical`-priority for investigation/response."* Never say "the vulnerability became critical."
- `priority_direction`.
- Every item in `priority_reasons`, presented as the real triggered reason codes.
- `context_completeness` -- when `"incomplete"`, state plainly that one or more context fields were supplied as `"unknown"` and contributed no positive or negative weight.
- `human_review_required: true`, stated plainly as the stopping point for this command.

When `finding_status` is `"candidate"` and `operational_priority` is `"critical"` (or any high value), explain this explicitly as **critical investigation priority for a candidate (not yet confirmed) finding** -- never as "a critical confirmed vulnerability," and never promote `candidate` to `validated` through your own explanation.

Never display:

- a raw exception message, exception class name, traceback, or internal stack detail;
- a claim that `context` was authenticated or independently verified;
- a claim that claimed `detection_coverage`/`compensating_controls` were validated (they are caller-asserted, never Red-Team-verified or independently confirmed);
- a claim that `threat_activity` reflects a live threat-intelligence lookup (it is exactly the value the caller supplied) -- and never claim `"none_observed"` means no threat exists;
- a claim that `regulatory_relevance` is a compliance/legal determination;
- a claim that `industry` changed the score (it never does -- it is descriptive only);
- a claim that any `candidate` finding was validated or confirmed;
- the internal construction of the CLI command or its raw stdin envelope.

## Required Failure Categories

Use only these fixed, non-sensitive failure categories. Never expose a raw exception message, exception class name, traceback, credential, path, or internal detail in any of them.

### CONTEXT_PRIORITIZATION_CLI_UNAVAILABLE

The Python launcher or `core.context_prioritization_cli` import check failing before any stage below runs.

### CONTEXT_PRIORITIZATION_VALIDATION_FAILED

Stage 0 rejecting malformed JSON, non-object top-level JSON, trailing content, a missing/unknown top-level field (including an invalid or missing `operation`), or Stage 1 reporting CLI exit code 2, or the CLI success-output validation failing.

### CONTEXT_PRIORITIZATION_INTERNAL_FAILURE

Stage 1 reporting CLI exit code 1 or any other unexpected code.

Do not automatically retry any failure in any category above. A result with `operational_priority: "critical"` for a `"candidate"` finding, or `context_completeness: "incomplete"`, is **never** one of these failure categories.

## No-Fallback and No-Retry Policy

On any command-level, CLI, parsing, or result-validation failure:

- stop;
- do not retry automatically;
- do not silently invent a missing `context` field or adjust a supplied one to force a different outcome;
- do not automatically invoke `/bug-bounty`, `/red-team`, `/blue-team`, `/purple-loop`, `/request-case-update`, `/review-approval`, or `/apply-case-update`.

The caller may always safely resubmit a corrected command later -- this command itself never performs that retry automatically, and never hides it.

## Explicit Execution Prohibitions

This command must never invoke, directly or indirectly:

- `core.context_prioritization.prioritize_finding` directly (only through `core.context_prioritization_cli`);
- `core.bug_bounty_scope`, `core.bug_bounty_findings`, `core.bug_bounty_assessment`, `adapters.bug_bounty_http`, or `core.bug_bounty_cli`;
- `core.agent_gateway.evaluate_tool_call`, `core.agent_identity_policy.evaluate_agent_tool_call`, or any Block 8/9 module;
- `core.analyst_feedback.create_analyst_feedback` or `core.tamper_evident_audit`/`core.evaluation_dashboard`;
- `mcp__supabase__execute_sql`, `execute_sql`, `apply_migration`, or any Block 6 mutation operation;
- `/bug-bounty`, `/red-team`, `/blue-team`, `/purple-loop`, `/request-case-update`, `/review-approval`, or `/apply-case-update`;
- a subprocess of any kind other than the one selected Python launcher running `core.context_prioritization_cli`;
- a dynamically imported, caller-selected module or function.

The only process this command ever executes is the one committed, deterministic adapter: `py -m core.context_prioritization_cli` (or the equivalent selected launcher), invoked exactly once per command invocation, running exactly one prioritization.

## Security Boundaries

This command must never:

- accept a caller-supplied `prioritization_version`, `human_review_required`, or `execution_performed` as a command-level override;
- decide whether a supplied `finding`/`context` is valid, or synthesize/infer any `context` field from `target`/hostname/application name/webpage evidence/vulnerability title/industry guess -- every one of those belongs entirely to `core.context_prioritization`;
- treat a result whose `operational_priority` is `"critical"` for a `"candidate"` finding, or whose `context_completeness` is `"incomplete"`, as a command-level failure;
- claim `context` was authenticated, that claimed detection coverage/compensating controls were verified, that `threat_activity` reflects a real threat-intelligence lookup, that `regulatory_relevance` is a compliance determination, or that `industry` affected the score;
- claim a `candidate` finding was validated or confirmed;
- call `core.bug_bounty_scope`/`core.bug_bounty_findings`/`core.bug_bounty_assessment`/`adapters.bug_bounty_http`, `core.agent_gateway`, `core.agent_identity_policy`, `core.analyst_feedback`, or `core.tamper_evident_audit`, directly or indirectly;
- automatically invoke `/bug-bounty`, `/red-team`, `/blue-team`, `/purple-loop`, or any database-backed approval command;
- retry any stage automatically, or fall back to a substitute construction after any failure;
- display any raw exception message, exception class name, traceback, credential, environment variable, filesystem path, or internal owner detail.

## Example Invocation

```json
{
  "operation": "prioritize",
  "finding": {
    "finding_version": "1",
    "finding_id": "BB15A-0000000000000000",
    "target": "https://app.example.test/",
    "affected_path": "/",
    "affected_parameter": null,
    "title": "Missing Strict-Transport-Security header",
    "finding_status": "validated",
    "vulnerability_class": "security_header_misconfiguration",
    "owasp_category": "A05:2021 Security Misconfiguration",
    "cwe": "CWE-693",
    "technical_severity": "medium",
    "confidence": "high",
    "evidence": [],
    "validation": {"method": "deterministic_header_presence_check", "confirmed": true},
    "reproduction_summary": "Requested / and observed no Strict-Transport-Security header.",
    "remediation": "Add a Strict-Transport-Security response header.",
    "detection_opportunity": "Alert on responses missing this header.",
    "human_approval_required": true,
    "assessment_performed": true,
    "network_requests_performed": 1,
    "execution_performed": false
  },
  "context": {
    "context_version": "1",
    "industry": "financial_services",
    "environment": "production",
    "asset_criticality": "critical",
    "exposure": "internet_facing",
    "data_sensitivity": "restricted",
    "detection_coverage": "none",
    "compensating_controls": "none",
    "threat_activity": "active",
    "regulatory_relevance": "direct"
  }
}
```

## Safety Rules

- Accept exactly one JSON object with exactly `operation`, `finding`, `context`. Never insert, synthesize, default, or overwrite any field on the caller's behalf.
- Never infer, guess, or normalize any `context` value -- pass every value through exactly as supplied.
- Never bypass `core.context_prioritization_cli`, and never reimplement any finding-shape validation, context-vocabulary check, scoring weight, clamp, reason-code, or completeness rule that `core.context_prioritization` already owns.
- Never claim `context` is authenticated, that claimed controls/detection coverage are verified, that `threat_activity` is a live threat-intelligence lookup, that `regulatory_relevance` is a compliance determination, or that `industry` affects the score.
- Never say "the vulnerability became critical" -- always distinguish `technical_severity` from `operational_priority` explicitly.
- Never promote a `candidate` finding to validated/confirmed through explanation, even when `operational_priority` is `critical`.
- Never treat a valid result as a command failure merely because of its computed priority or its `context_completeness`.
- Never automatically invoke `/bug-bounty`, `/red-team`, `/blue-team`, `/purple-loop`, or any database-backed approval command.
- Never retry any stage automatically, and never fall back to a substitute construction after a failure.
- Never expose a raw exception message, exception class name, traceback, credential, project reference, environment variable, filesystem path, or internal owner detail.
