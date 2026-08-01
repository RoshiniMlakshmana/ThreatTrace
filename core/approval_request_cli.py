"""Command-line adapter for `core.approval_request.validate_approval_request`.

Input is read from stdin, as a single JSON object describing one proposed
approval request. Output is the validated, canonicalized request, written
to stdout as JSON. Errors are written to stderr only.

This adapter is a transport wrapper only:

- All structural validation and canonicalization belong to
  `validate_approval_request`; this module never duplicates its field,
  vocabulary, UUID, or timestamp rules, and never pre-normalizes,
  inspects, or generates any part of the payload itself.
- It never invokes `core.approval_transition` or any approval-transition
  logic, never queries Supabase, never creates an approval row, never
  approves, rejects, or consumes anything, and never updates an
  investigation.
- It performs no file, subprocess, network, or AI-model access, and has no
  persistence or other external side effect anywhere in it.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object.
- 2 -- invalid input (malformed/non-object JSON, multiple JSON values,
  trailing content, or a payload that fails approval-request validation);
  stdout is empty.
- 1 -- an unexpected internal failure; stdout is empty.

Usage:

    py -m core.approval_request_cli
    python3 -m core.approval_request_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.approval_request import ApprovalRequestError, validate_approval_request

_VALIDATION_ERROR_PREFIX = "Approval request validation failed:"
_JSON_ERROR_PREFIX = "Invalid JSON input:"
_UNEXPECTED_ERROR_MESSAGE = "Approval request validation failed."


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON object from stdin, validate it, and write the result to stdout.

    Returns 0 on success, 2 for invalid input (malformed JSON, non-object
    JSON, multiple JSON values, trailing content, or a payload that fails
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
            stderr.write("Approval request input must be a JSON object.\n")
            return 2

        try:
            result = validate_approval_request(parsed)
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
