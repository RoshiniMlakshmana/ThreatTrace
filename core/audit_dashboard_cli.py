"""Command-line adapter for `core.tamper_evident_audit`'s
`create_audit_record`/`verify_audit_chain` and
`core.evaluation_dashboard`'s `summarize_audit_dashboard` (Block 14).

Input is read from stdin, as a single JSON object. Its top-level
`"operation"` field selects which of the three functions is called:
`"create"`, `"verify"`, or `"dashboard"`. Output is that function's own
deterministic result, written to stdout as JSON. Errors are written to
stderr only.

This adapter is a transport wrapper only:

- It owns exactly one thing per operation: the operation's own closed
  envelope shape. It never validates `sequence`, `event_type`,
  `event_reference`, `event_summary`, `occurred_at`,
  `previous_record_digest`, `records`, or `expected_head_digest`
  itself -- after confirming the envelope has exactly the required keys
  for the selected operation, every value is passed directly to the
  corresponding core function, even when one of them is malformed. All
  canonical hashing, digest verification, chain-linkage verification,
  trusted-anchor semantics, dashboard aggregation, and evaluation/
  feedback/policy vocabulary checks belong entirely to
  `core.tamper_evident_audit` and `core.evaluation_dashboard`.
- It never implements or duplicates any Block 14 validation, hashing,
  or aggregation rule of its own, and never imports any other Block's
  module -- only `core.tamper_evident_audit`'s and
  `core.evaluation_dashboard`'s own public functions and exceptions are
  ever imported here.
- It never calls Supabase, MCP, Hayabusa, or any other external system;
  never constructs SQL; never reads the system clock, an environment
  variable, or the filesystem; and never persists anything. Its output
  remains exactly the pure core function's own result -- including
  `audit_persisted: false` and `execution_performed: false` -- this
  adapter never wraps it in any additional envelope and never
  overwrites any of its fields.

A `verification_outcome`/`audit.verification_outcome` of `"invalid"` is,
exactly like it is in the core, a normal, successfully handled result --
never a CLI failure. This adapter never converts an internally-invalid
or unanchored chain into a processing error.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object (a created
  audit record, a `"valid"`/`"invalid"` verification result, or a
  dashboard summary -- including one built over a structurally usable
  but internally invalid chain -- are all successful outcomes, never a
  CLI failure).
- 2 -- invalid input (malformed/non-object JSON, a missing/unknown
  `operation`, a missing/unknown top-level envelope field for the
  selected operation, or a structurally invalid field value rejected by
  the core's own `AuditRecordError`/`EvaluationDashboardError`); stdout
  is empty.
- 1 -- an unexpected internal failure; stdout is empty.

Usage:

    py -m core.audit_dashboard_cli
    python3 -m core.audit_dashboard_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.evaluation_dashboard import EvaluationDashboardError, summarize_audit_dashboard
from core.tamper_evident_audit import AuditRecordError, create_audit_record, verify_audit_chain

_VALIDATION_ERROR_PREFIX = "Audit dashboard CLI validation failed:"
_INTERNAL_ERROR_PREFIX = "Audit dashboard CLI internal error:"

_ALLOWED_OPERATIONS = frozenset({"create", "verify", "dashboard"})

_CREATE_ENVELOPE_FIELDS = frozenset({
    "operation",
    "sequence",
    "event_type",
    "event_reference",
    "event_summary",
    "occurred_at",
    "previous_record_digest",
})

_VERIFY_ENVELOPE_FIELDS = frozenset({"operation", "records", "expected_head_digest"})
_DASHBOARD_ENVELOPE_FIELDS = frozenset({"operation", "records", "expected_head_digest"})


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, dispatch it to the create,
    verify, or dashboard function, and write the result to stdout.

    Returns 0 on success (including a `verification_outcome`/
    `audit.verification_outcome` of `"invalid"`, a normal, successful
    result), 2 for invalid input (malformed JSON, non-object JSON, a
    missing/unknown `operation`, a missing/unknown envelope field for
    the selected operation, or a structurally invalid field value
    rejected by the core's own `AuditRecordError`/
    `EvaluationDashboardError`), and 1 for any unexpected internal
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
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} operation must be 'create', 'verify', or 'dashboard'.\n")
            return 2

        if operation == "create":
            allowed_fields = _CREATE_ENVELOPE_FIELDS
        elif operation == "verify":
            allowed_fields = _VERIFY_ENVELOPE_FIELDS
        else:
            allowed_fields = _DASHBOARD_ENVELOPE_FIELDS

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
            if operation == "create":
                result = create_audit_record(
                    sequence=parsed["sequence"],
                    event_type=parsed["event_type"],
                    event_reference=parsed["event_reference"],
                    event_summary=parsed["event_summary"],
                    occurred_at=parsed["occurred_at"],
                    previous_record_digest=parsed["previous_record_digest"],
                )
            elif operation == "verify":
                result = verify_audit_chain(
                    records=parsed["records"],
                    expected_head_digest=parsed["expected_head_digest"],
                )
            else:
                result = summarize_audit_dashboard(
                    records=parsed["records"],
                    expected_head_digest=parsed["expected_head_digest"],
                )
        except (AuditRecordError, EvaluationDashboardError) as exc:
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
