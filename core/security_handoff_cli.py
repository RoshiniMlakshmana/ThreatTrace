"""Command-line adapter for `core.security_handoff` (Block 15C,
checkpoint B).

Input is read from stdin, as a single JSON object. Its top-level
`"operation"` field selects which of the three functions is called:
`"create_case"`, `"append_stage"`, or `"record_approval"`. Output is
that function's own deterministic result, written to stdout as JSON.
Errors are written to stderr only.

## Security honesty

This CLI records deterministic **security handoff case** state only --
it never executes anything. Threat Intelligence, Threat Hunting, Blue
Team/Detection Engineering, Red Team, and Purple Team/IR role outputs
are **caller/external inputs** in this checkpoint -- this CLI never
invokes `/ingest-ti`, `/threat-hunt`, `/blue-team`, `/red-team`,
`/purple-loop`, or the `detection-engineering` skill, and never performs
any of the work those roles describe. A `red_validation` stage result
whose `outcome` is `"validated"` means an externally/caller-supplied Red
Team assessment was **recorded**, never that this CLI executed an
attack. A `detection_engineering` stage result with `outcome:
"candidate_ready"` means a detection candidate was **proposed**, never
deployed. A `purple_remediation` stage result is always a
**recommendation**, never remediation having been applied. Approval
(`record_approval`) is **caller-reported and unauthenticated** -- this
CLI never contacts Supabase, never verifies an approval database row,
and never executes any downstream action; `current_stage` remains
`"human_review"` even after `"approved"` is recorded -- there is no
`"complete"` state. `human_review_required` remains `True` in every
result this CLI can ever produce.

## Thin adapter boundary

This adapter is a thin wrapper only:

- It owns exactly one thing per operation: that operation's own closed
  envelope shape. It never validates the *content* of `finding`,
  `prioritization`, `case`, `stage`, `role`, `result_type`, `outcome`,
  `evidence_references`, `recommendation`, `approval_state`, or
  `approval_reference` itself -- after confirming the envelope has
  exactly the required keys for the selected operation, every value is
  passed directly, completely unchanged, to the corresponding
  `core.security_handoff` function. All finding/prioritization
  validation, substitution/mismatch detection, case validation, stage-
  transition logic, role/result-type/outcome compatibility, evidence-
  reference validation, approval-state rules, and deterministic ID
  generation belong entirely to `core.security_handoff`, never
  reimplemented here.
- It never imports any other Block's module -- only
  `core.security_handoff`'s own public functions and
  `SecurityHandoffError` are ever imported here.
- It never calls Supabase, MCP, or any other external system; never
  constructs SQL; never reads the system clock, an environment
  variable, or the filesystem; and never persists anything. Its output
  remains exactly the pure core function's own result -- this adapter
  never wraps it in any additional envelope and never overwrites any of
  its fields.

A `needs_review`/`blocked`/`not_applicable` stage-result outcome, a Red
`"blocked"`→Blue-revision cycle, or an externally-reported
`"approved"`/`"rejected"` approval decision is, exactly like it is in
the core, a normal, successful result -- never a CLI failure.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object (the real
  `core.security_handoff` result for the selected operation).
- 2 -- invalid input (malformed/non-object JSON, a missing/unknown
  `operation`, a missing/unknown top-level envelope field for the
  selected operation, or a structurally invalid value rejected by the
  core's own `SecurityHandoffError`); stdout is empty; stderr begins
  with `SECURITY_HANDOFF_VALIDATION_FAILED`.
- 1 -- an unexpected internal failure; stdout is empty; stderr begins
  with `SECURITY_HANDOFF_INTERNAL_FAILURE`.

Usage:

    py -m core.security_handoff_cli
    python3 -m core.security_handoff_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.security_handoff import (
    SecurityHandoffError,
    append_security_stage_result,
    create_security_handoff_case,
    record_security_handoff_approval,
)

_VALIDATION_ERROR_PREFIX = "SECURITY_HANDOFF_VALIDATION_FAILED:"
_INTERNAL_ERROR_PREFIX = "SECURITY_HANDOFF_INTERNAL_FAILURE:"

_ALLOWED_OPERATIONS = frozenset({"create_case", "append_stage", "record_approval"})

_CREATE_CASE_ENVELOPE_FIELDS = frozenset({"operation", "finding", "prioritization"})

_APPEND_STAGE_ENVELOPE_FIELDS = frozenset({
    "operation", "case", "stage", "role", "result_type", "outcome",
    "evidence_references", "recommendation",
})

_RECORD_APPROVAL_ENVELOPE_FIELDS = frozenset({
    "operation", "case", "approval_state", "approval_reference",
})

_ENVELOPE_FIELDS_BY_OPERATION = {
    "create_case": _CREATE_CASE_ENVELOPE_FIELDS,
    "append_stage": _APPEND_STAGE_ENVELOPE_FIELDS,
    "record_approval": _RECORD_APPROVAL_ENVELOPE_FIELDS,
}


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, dispatch it to the
    create_case, append_stage, or record_approval function, and write
    the result to stdout.

    Returns 0 on success (including a `needs_review`/`blocked`/
    `not_applicable` stage-result outcome, a Red `"blocked"`→Blue-
    revision cycle, or an `"approved"`/`"rejected"` approval decision --
    every one of those is a normal, successful result), 2 for invalid
    input (malformed JSON, non-object JSON, a missing/unknown
    `operation`, a missing/unknown envelope field for the selected
    operation, or a structurally invalid value rejected by the core's
    own `SecurityHandoffError`), and 1 for any unexpected internal
    failure.
    """
    try:
        raw_text = stdin.read()

        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} invalid JSON input: {exc}\n")
            return 2

        if not isinstance(parsed, dict):
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} input must be a JSON object.\n")
            return 2

        operation = parsed.get("operation")
        if operation not in _ALLOWED_OPERATIONS:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} operation must be 'create_case', 'append_stage', or 'record_approval'.\n"
            )
            return 2

        allowed_fields = _ENVELOPE_FIELDS_BY_OPERATION[operation]

        unknown_fields = set(parsed) - allowed_fields
        if unknown_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} unrecognized field(s): {', '.join(sorted(unknown_fields))}\n"
            )
            return 2

        missing_fields = [field for field in allowed_fields if field not in parsed]
        if missing_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} missing required field(s): {', '.join(sorted(missing_fields))}\n"
            )
            return 2

        try:
            if operation == "create_case":
                result = create_security_handoff_case(
                    finding=parsed["finding"],
                    prioritization=parsed["prioritization"],
                )
            elif operation == "append_stage":
                result = append_security_stage_result(
                    case=parsed["case"],
                    stage=parsed["stage"],
                    role=parsed["role"],
                    result_type=parsed["result_type"],
                    outcome=parsed["outcome"],
                    evidence_references=parsed["evidence_references"],
                    recommendation=parsed["recommendation"],
                )
            else:
                result = record_security_handoff_approval(
                    case=parsed["case"],
                    approval_state=parsed["approval_state"],
                    approval_reference=parsed["approval_reference"],
                )
        except SecurityHandoffError as exc:
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} {exc}\n")
            return 2

        stdout.write(json.dumps(result, sort_keys=True, ensure_ascii=False))
        stdout.write("\n")
        return 0
    except Exception:
        stderr.write(f"{_INTERNAL_ERROR_PREFIX} unexpected failure.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
