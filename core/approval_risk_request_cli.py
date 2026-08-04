"""Command-line adapter for
`core.approval_request.validate_risk_aware_approval_request`.

Input is read from stdin, as a single JSON object containing exactly two
fields: `request` and `current_investigation`. Output is the validated,
risk-classified request, written to stdout as JSON. Errors are written to
stderr only.

This adapter is a transport wrapper only:

- It owns exactly one thing: the two-field top-level envelope shape. It
  never validates `request` or `current_investigation` itself -- after
  confirming the envelope has exactly these two keys, both nested values
  are passed directly to `validate_risk_aware_approval_request`, even when
  one of them is malformed. All request-field validation,
  canonicalization, and risk classification (`risk_level`,
  `required_approvals`) belong entirely to that function.
- It never implements or duplicates any risk vocabulary, action-type
  vocabulary, or investigation-status/confidence vocabulary of its own.
- It never queries Supabase, never creates an approval row, never
  persists a review, and never updates an investigation.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object.
- 2 -- invalid input (malformed/non-object JSON, multiple JSON values,
  trailing content, a missing/unknown top-level envelope field, or a
  payload that fails risk-aware approval-request validation); stdout is
  empty.
- 1 -- an unexpected internal failure; stdout is empty.

Usage:

    py -m core.approval_risk_request_cli
    python3 -m core.approval_risk_request_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.approval_request import ApprovalRequestError, validate_risk_aware_approval_request

_VALIDATION_ERROR_PREFIX = "Risk-aware approval request validation failed:"
_JSON_ERROR_PREFIX = "Invalid JSON input:"
_UNEXPECTED_ERROR_MESSAGE = "Risk-aware approval request validation failed."

_ALLOWED_ENVELOPE_FIELDS = frozenset({"request", "current_investigation"})


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, validate it, and write the result to stdout.

    Returns 0 on success, 2 for invalid input (malformed JSON, non-object
    JSON, multiple JSON values, trailing content, a missing/unknown
    top-level envelope field, or a payload that fails risk-aware
    approval-request validation), and 1 for any unexpected internal
    failure.
    """
    try:
        raw_text = stdin.read()

        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            stderr.write(f"{_JSON_ERROR_PREFIX} {exc}\n")
            return 2

        if not isinstance(parsed, dict):
            stderr.write("Risk-aware approval request input must be a JSON object.\n")
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
            result = validate_risk_aware_approval_request(
                parsed["request"],
                parsed["current_investigation"],
            )
        except ApprovalRequestError as exc:
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
