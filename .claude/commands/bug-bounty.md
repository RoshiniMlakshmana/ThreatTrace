---
description: Run one real, bounded, scope-checked Bug Bounty web-application assessment against a caller-supplied target and complete technical scope
argument-hint: "{operation: \"assess\", target, target_type, allowed_origins, allowed_paths, excluded_paths, testing_profile}"
---

# ThreatTrace Bug Bounty Assessment Workflow

`/bug-bounty` is Block 15A's human-invoked real assessment boundary: it answers exactly one thing --

*for this caller-supplied target and complete technical scope, what does one bounded, deterministic, real `GET`/`HEAD`/`OPTIONS` web-application assessment observe, and what evidence-backed findings does it support?*

-- by consulting the existing, already-committed, deterministic core (`core.bug_bounty_scope`, `core.bug_bounty_findings`, `core.bug_bounty_assessment`, and the real transport `adapters.bug_bounty_http.BugBountyHttpTransport`, reached only through `core.bug_bounty_cli`) -- and nothing else. This command is strictly a transport adapter. **One invocation runs exactly one assessment.**

Caller-supplied `operation` + complete scope fields → command-level envelope validation → `core.bug_bounty_cli`, unchanged → deterministic assessment result

## This Command CAN Make Real Network Requests

Unlike every other ThreatTrace command, running `/bug-bounty` can send real, bounded HTTP requests to the caller-supplied `target` (and, within scope, a small number of related URLs -- see `docs/block15a-bug-bounty-agent.md` for the exact request cap, redirect limit, and rate limit). `target`/`allowed_origins`/`allowed_paths`/`excluded_paths`/`testing_profile` are **caller-supplied technical scope only** -- this command never authenticates, and has no way to authenticate, that the caller was legally/organizationally authorized to test the supplied target. `execution_performed: false` in the returned result does **not** mean no network request happened -- it means no remediation was applied, no production configuration changed, and no detection rule was created or applied. A real request having occurred is represented honestly through the result's own `assessment_performed`/`network_requests_performed` fields.

## What This Provides -- and Does Not

The strongest honest claim this command can ever make:

> For the caller-supplied target and complete technical scope, ThreatTrace can observe a bounded set of `GET`/`HEAD`/`OPTIONS` responses and report deterministic, evidence-backed findings from the implemented v1 check classes.

It is **not**: a comprehensive penetration test; full OWASP Top 10 coverage; proof the target is secure when `findings` is empty; proof of exploitation for any `candidate` finding; proof of caller authorization; or proof that any `validated` finding is anything beyond the narrow deterministic condition it directly checked (see `docs/block15a-bug-bounty-agent.md` for the exact vocabulary). A `REQUEST_FAILED`/blocked-redirect observation, or an assessment with zero findings, is a normal, successfully completed assessment result -- never a command failure.

## Request Input

$ARGUMENTS

## Stage 0 -- Command-Level Input Shape Validation

`$ARGUMENTS` must be exactly one JSON object. Perform every check below, in order, before Stage 1 -- before any CLI invocation:

1. Parse `$ARGUMENTS` as exactly one JSON value.
2. Reject malformed JSON.
3. Reject trailing non-whitespace content after the one parsed JSON value.
4. Reject a top-level value that is not a JSON object.
5. Require an `"operation"` field equal to exactly `"assess"`. Reject any other value, including a missing one.
6. Require exactly `operation`, `target`, `target_type`, `allowed_origins`, `allowed_paths`, `excluded_paths`, `testing_profile` -- the same seven-key envelope `core.bug_bounty_cli` itself requires. Reject a missing or extra field. `allowed_paths`/`excluded_paths` must be present (their value may be `null`) -- never omitted.

This command performs **no semantic validation of `target`/`target_type`/`allowed_origins`/`allowed_paths`/`excluded_paths`/`testing_profile` beyond confirming the envelope has exactly these seven keys.** It does not decide whether the target URL is well-formed, whether an origin/path entry is valid, or whether the testing profile is recognized -- every one of those is always decided later, entirely by `core.bug_bounty_scope`, reached only through `core.bug_bounty_cli`. This command never inserts, synthesizes, defaults, or overwrites `operation` or any scope field on the caller's behalf, never infers `allowed_origins` from `target`, never trims or lowercases any supplied value, and never changes `testing_profile` (e.g. from `"passive"` to `"safe_active"`) on its own judgment. Every value is passed through completely unchanged.

Call the fully validated envelope the **candidate envelope**.

## Python Launcher Selection

Use the existing project convention for selecting a Python launcher:

1. Try `py`.
2. Otherwise try `python3`.
3. Otherwise use a `python` executable only after confirming it resolves to Python 3.10 or later.

Before continuing, confirm the selected launcher can import `core.bug_bounty_cli`. If no launcher can be selected, or the import check fails, stop and report `BUG_BOUNTY_CLI_UNAVAILABLE`. Do not install any package. Do not modify the environment.

## Safe CLI Transport

Invoke the CLI through **stdin only**, exactly following the safe invocation pattern already established by `/evaluate-tool-call`, `/evaluate-agent-tool-call`, `/create-decision-binding`, `/ai-security-lab`, `/record-analyst-feedback`, `/audit-dashboard`, and `/integration-demo`. Never pass JSON through command-line arguments, never create a temporary JSON file, never interpolate caller content directly into executable shell code, and never write request data to disk.

## Stage 1 -- Invoke the Bug Bounty CLI

Send the **candidate envelope exactly as the caller supplied it** -- every field, including the caller's own `operation`, unchanged, unreordered, unrepaired -- through **stdin only** to `py -m core.bug_bounty_cli` (or the equivalent selected launcher). This command never adds, removes, renames, normalizes, redacts, reorders, or otherwise transforms any field or value. Never call `core.bug_bounty_scope`, `core.bug_bounty_findings`, `core.bug_bounty_assessment`, or `adapters.bug_bounty_http` directly, and never reimplement any scope-matching, evidence-redaction, finding-validation, or assessment-check logic this document does not own. Never invoke `curl`, `wget`, `nuclei`, `zap`, `ffuf`, `burp`, `sqlmap`, or any other external network tool -- the only real assessment engine in this project is `adapters.bug_bounty_http.BugBountyHttpTransport`, reached only through `core.bug_bounty_cli`.

### Bug Bounty CLI exit handling

- **0**: success -- a valid assessment result, including one whose `findings` is empty, or which contains a `REQUEST_FAILED` or blocked-redirect observation. None of those is a command failure. Continue to the output validation below.
- **2**: a deterministic command/CLI-envelope or core scope-validation failure -- stop and report `BUG_BOUNTY_VALIDATION_FAILED`.
- **1**: an unexpected internal failure -- stop and report `BUG_BOUNTY_INTERNAL_FAILURE`.
- **any other code**: stop and report `BUG_BOUNTY_INTERNAL_FAILURE`.

Never automatically retry any of these outcomes, and never fall back to displaying a partially-constructed or hand-assembled result.

### Bug Bounty CLI success-output validation

Require stdout to be exactly one JSON object containing exactly the eight fields `core.bug_bounty_assessment.run_bug_bounty_assessment` always returns: `assessment_version`, `target`, `testing_profile`, `findings`, `observed_evidence`, `assessment_performed`, `network_requests_performed`, `human_approval_required`, `execution_performed`. Require `assessment_version` to equal exactly `"1"`, `human_approval_required` to equal exactly `true`, and `execution_performed` to equal exactly `false`. Require `findings` to be a list whose every entry contains exactly the 21 fields `core.bug_bounty_findings.create_bug_bounty_finding` always returns.

If the result is missing a required field, contains an unrecognized field, or has `human_approval_required`/`execution_performed` other than their fixed values: stop, report `BUG_BOUNTY_VALIDATION_FAILED`, and never display the result as if it were successful. Do not repair, complete, or reinterpret a malformed result by hand.

Call the fully validated result the **assessment result**.

## Required Output

Produce, only after the assessment result passes every check above:

- `target` and `testing_profile`.
- Every entry in `findings`: `title`, `finding_status`, `vulnerability_class`, `affected_path`, `affected_parameter` (when not `null`), `technical_severity`, `confidence`, `owasp_category`/`cwe` (when not `null`), `reproduction_summary`, `remediation`/`detection_opportunity` (when not `null`).
- Every item in `observed_evidence`, presented as real assessment-level codes actually emitted during this run.
- `assessment_performed` and `network_requests_performed`, stated plainly.
- `human_approval_required: true`, stated plainly, as the stopping point for this command.

When rendering each finding:

- Label `finding_status: "validated"` as *deterministically validated within the implemented check* -- never as a fully confirmed, exploited, or production-relevant vulnerability beyond that narrow claim.
- Keep `"candidate"` as candidate, and `"observation"` as observation -- never upgraded in prose.
- Describe `vulnerability_class: "input_reflection"` as reflection observed -- never XSS.
- Describe `vulnerability_class: "redirect_observation"` as a redirect observed -- never an open redirect.
- Describe `vulnerability_class: "http_method_observation"` as an advertised-method observation -- never claim exploitability merely because a method was advertised.
- If `findings` is empty, state only that the implemented v1 checks found nothing to report for this scope/profile -- never that the target is secure.

Never display:

- a raw exception message, exception class name, traceback, or internal stack detail;
- a claim that this was a complete penetration test or achieved full OWASP Top 10 coverage;
- a claim that caller authorization was verified or authenticated;
- a claim that any `candidate` finding is confirmed/exploited;
- a claim that `technical_severity`/`confidence` reflects organizational or business risk (that is a separate, later concern);
- the internal construction of the CLI command or its raw stdin envelope.

## Required Failure Categories

Use only these fixed, non-sensitive failure categories. Never expose a raw exception message, exception class name, traceback, credential, path, or internal detail in any of them.

### BUG_BOUNTY_CLI_UNAVAILABLE

The Python launcher or `core.bug_bounty_cli` import check failing before any stage below runs.

### BUG_BOUNTY_VALIDATION_FAILED

Stage 0 rejecting malformed JSON, non-object top-level JSON, trailing content, a missing/unknown top-level field (including an invalid or missing `operation`, or a missing `allowed_paths`/`excluded_paths` key), or Stage 1 reporting CLI exit code 2, or the CLI success-output validation failing.

### BUG_BOUNTY_INTERNAL_FAILURE

Stage 1 reporting CLI exit code 1 or any other unexpected code.

Do not automatically retry any failure in any category above. A valid result containing `REQUEST_FAILED`, a blocked-redirect observation, or zero findings is **never** one of these failure categories -- do not call it a command failure merely because the target didn't yield findings or a network attempt failed honestly.

## No-Fallback and No-Retry Policy

On any command-level, CLI, parsing, or result-validation failure:

- stop;
- do not retry automatically;
- do not silently adjust `target`/`allowed_origins`/`allowed_paths`/`excluded_paths`/`testing_profile` to force a different outcome;
- do not widen scope, change the testing profile, or attempt a different URL on the caller's behalf;
- do not automatically invoke `/request-case-update`, `/review-approval`, `/apply-case-update`, `/red-team`, `/blue-team`, or `/purple-loop`.

The caller may always safely resubmit a corrected command later -- this command itself never performs that retry automatically, and never hides it.

## Explicit Execution Prohibitions

This command must never invoke, directly or indirectly:

- `core.bug_bounty_scope.create_bug_bounty_scope`/`evaluate_bug_bounty_request_scope`, `core.bug_bounty_findings.create_bug_bounty_evidence`/`create_bug_bounty_finding`, or `core.bug_bounty_assessment.run_bug_bounty_assessment` directly (only through `core.bug_bounty_cli`);
- `adapters.bug_bounty_http.BugBountyHttpTransport` directly, or any other network client;
- `curl`, `wget`, `nuclei`, `zap`, `ffuf`, `burp`, `sqlmap`, or any other external scanner/tool;
- `core.agent_gateway.evaluate_tool_call`, `core.agent_identity_policy.evaluate_agent_tool_call`, or any Block 8/9 module;
- `mcp__supabase__execute_sql`, `execute_sql`, `apply_migration`, or any Block 6 mutation operation;
- `/request-case-update`, `/review-approval`, `/apply-case-update`, `/red-team`, `/blue-team`, or `/purple-loop`;
- a subprocess of any kind other than the one selected Python launcher running `core.bug_bounty_cli`;
- a dynamically imported, caller-selected module or function.

The only process this command ever executes is the one committed, deterministic adapter: `py -m core.bug_bounty_cli` (or the equivalent selected launcher), invoked exactly once per command invocation, running exactly one assessment.

## Security Boundaries

This command must never:

- accept a caller-supplied `assessment_version`, `human_approval_required`, or `execution_performed` as a command-level override;
- decide whether a supplied `target`/`allowed_origins`/`allowed_paths`/`excluded_paths`/`testing_profile` is valid -- every one of those belongs entirely to `core.bug_bounty_scope`;
- infer `allowed_origins` from `target`, or synthesize/default `allowed_paths`/`excluded_paths`/`testing_profile`;
- treat a valid assessment result containing `REQUEST_FAILED`, a blocked-redirect observation, or zero findings as a command-level failure;
- claim caller authorization was authenticated, that a `candidate` finding is confirmed/exploited, that a comprehensive penetration test occurred, or that the target is secure because findings are empty;
- claim `technical_severity`/`confidence` reflects organization/business risk;
- automatically invoke the database-backed approval workflow or any Red/Blue/Purple command;
- retry any stage automatically, or fall back to a substitute construction after any failure;
- display any raw exception message, exception class name, traceback, credential, environment variable, filesystem path, or internal owner detail.

## Example Invocation

```json
{
  "operation": "assess",
  "target": "http://localhost:3000/",
  "target_type": "web_application",
  "allowed_origins": ["http://localhost:3000"],
  "allowed_paths": ["/"],
  "excluded_paths": [],
  "testing_profile": "passive"
}
```

## Safety Rules

- Accept exactly one JSON object with exactly the seven fields `core.bug_bounty_cli` requires. Never insert, synthesize, default, or overwrite any field on the caller's behalf.
- Never trim, lowercase, or otherwise normalize `target` or any scope field -- pass every value through exactly as supplied.
- Never infer `allowed_origins` from `target`, and never change `testing_profile` on your own judgment.
- Never bypass `core.bug_bounty_cli`, and never reimplement any scope-matching, evidence-redaction, finding-validation, or assessment-check rule that `core.bug_bounty_scope`/`core.bug_bounty_findings`/`core.bug_bounty_assessment` already own.
- Never invoke `curl`, `wget`, `nuclei`, `zap`, `ffuf`, `burp`, `sqlmap`, or any process other than the selected Python launcher running `core.bug_bounty_cli`.
- Never claim caller authorization was authenticated, that a candidate finding is confirmed, that coverage is comprehensive, or that the target is secure because findings are empty.
- Never treat a valid result containing `REQUEST_FAILED` or zero findings as a command failure.
- Never automatically invoke `/request-case-update`, `/review-approval`, `/apply-case-update`, `/red-team`, `/blue-team`, or `/purple-loop`.
- Never retry any stage automatically, and never fall back to a substitute construction after a failure.
- Never expose a raw exception message, exception class name, traceback, credential, project reference, environment variable, filesystem path, or internal owner detail.
