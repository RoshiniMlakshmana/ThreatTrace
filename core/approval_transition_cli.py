"""Command-line adapter for
`core.approval_transition.validate_approval_transition`.

Input is read from stdin, as a single JSON object containing exactly two
fields: `current_record` and `transition_request`. Output is the
validated transition plan, written to stdout as JSON. Errors are written
to stderr only.

This adapter is a transport wrapper only:

- It owns exactly one thing: the two-field top-level envelope shape. It
  never validates `current_record` or `transition_request` itself --
  after confirming the envelope has exactly these two keys, both nested
  values are passed directly to `validate_approval_transition`, even when
  one of them is malformed. All lifecycle rules, state-machine
  enforcement, two-person comparison, expiry enforcement, UUID/timestamp
  canonicalization, and identity handling belong entirely to that
  validator.
- It never implements or duplicates any lifecycle vocabulary, and never
  imports `core.approval_request` directly -- `validate_approval_transition`
  already composes with it internally.
- It never queries Supabase, never persists an approval, never performs a
  conditional update, and never updates an investigation. Its output
  remains exactly:

      Validated transition plan -- not persisted

Exit codes:

- 0 -- success; stdout contains exactly one JSON object.
- 2 -- invalid input (malformed/non-object JSON, multiple JSON values,
  trailing content, a missing/unknown top-level envelope field, or a
  payload that fails approval-transition validation); stdout is empty.
- 1 -- an unexpected internal failure; stdout is empty.

Usage:

    py -m core.approval_transition_cli
    python3 -m core.approval_transition_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.approval_transition import ApprovalTransitionError, validate_approval_transition

_VALIDATION_ERROR_PREFIX = "Approval transition validation failed:"
_JSON_ERROR_PREFIX = "Invalid JSON input:"
_UNEXPECTED_ERROR_MESSAGE = "Approval transition validation failed."

_ALLOWED_ENVELOPE_FIELDS = frozenset({"current_record", "transition_request"})


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, validate it, and write the result to stdout.

    Returns 0 on success, 2 for invalid input (malformed JSON, non-object
    JSON, multiple JSON values, trailing content, a missing/unknown
    top-level envelope field, or a payload that fails approval-transition
    validation), and 1 for any unexpected internal failure.
    """
    try:
        raw_text = stdin.read()

        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            stderr.write(f"{_JSON_ERROR_PREFIX} {exc}\n")
            return 2

        if not isinstance(parsed, dict):
            stderr.write("Approval transition input must be a JSON object.\n")
            return 2

        unknown_fields = set(parsed) - _ALLOWED_ENVELOPE_FIELDS
        if unknown_fields:
            stderr.write(
                f"{_JSON_ERROR_PREFIX} unrecognized field(s): {', '.join(sorted(unknown_fields))}\n"
            )
            return 2

        missing_fields = [field for field in _ALLOWED_ENVELOPE_FIELDS if field not in parsed]
        if missing_fields:
            stderr.write(
                f"{_JSON_ERROR_PREFIX} missing required field(s): {', '.join(sorted(missing_fields))}\n"
            )
            return 2

        try:
            result = validate_approval_transition(
                parsed["current_record"],
                parsed["transition_request"],
            )
        except ApprovalTransitionError as exc:
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} {exc}\n")
            return 2

        stdout.write(json.dumps(result, sort_keys=True, ensure_ascii=False))
        stdout.write("\n")
        return 0
    except Exception:
        stderr.write(f"{_UNEXPECTED_ERROR_MESSAGE}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
