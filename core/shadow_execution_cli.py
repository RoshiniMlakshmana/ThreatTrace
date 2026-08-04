"""Command-line adapter for
`core.shadow_execution.simulate_case_update`.

Input is read from stdin, as a single JSON object containing exactly
three fields: `approval_record`, `investigation_context`, and
`simulated_at`. Output is the deterministic shadow-execution simulation
report, written to stdout as JSON. Errors are written to stderr only.

This adapter is a transport wrapper only:

- It owns exactly one thing: the three-field top-level envelope shape. It
  never validates `approval_record`, `investigation_context`, or
  `simulated_at` itself -- after confirming the envelope has exactly
  these three keys, all three values are passed directly to
  `simulate_case_update`, even when one of them is malformed. All
  risk-aware approval-record validation, investigation-context
  validation, timestamp canonicalization, eligibility rules, warning
  rules, rollback classification, and state-diff calculation belong
  entirely to that function.
- It never implements or duplicates any vocabulary, eligibility rule,
  warning rule, or rollback classification of its own.
- It never queries Supabase, never calls MCP, never constructs SQL or an
  RPC parameter set, never reads the system clock, never reads an
  environment variable or the filesystem, and never performs any
  investigation or approval mutation of any kind. Its output remains
  exactly the pure engine's own fifteen-field simulation report,
  including `mutation_performed: false` -- this adapter never wraps it in
  any additional envelope.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object (the simulation
  report -- possibly reporting `eligible_for_execution: false`, which is
  a normal, successful report, never a CLI failure).
- 2 -- invalid input (malformed/non-object JSON, a missing/unknown
  top-level envelope field, or a payload that fails shadow-execution
  validation); stdout is empty.
- 1 -- an unexpected internal failure; stdout is empty.

Usage:

    py -m core.shadow_execution_cli
    python3 -m core.shadow_execution_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.shadow_execution import ShadowExecutionError, simulate_case_update

_VALIDATION_ERROR_PREFIX = "Shadow execution validation failed:"
_JSON_ERROR_PREFIX = "Invalid JSON input:"
_UNEXPECTED_ERROR_MESSAGE = "Shadow execution validation failed."

_ALLOWED_ENVELOPE_FIELDS = frozenset({"approval_record", "investigation_context", "simulated_at"})


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, simulate it, and write the result to stdout.

    Returns 0 on success (including a successful report where
    `eligible_for_execution` is `false`), 2 for invalid input (malformed
    JSON, non-object JSON, a missing/unknown top-level envelope field, or
    a payload that fails shadow-execution validation), and 1 for any
    unexpected internal failure.
    """
    try:
        raw_text = stdin.read()

        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            stderr.write(f"{_JSON_ERROR_PREFIX} {exc}\n")
            return 2

        if not isinstance(parsed, dict):
            stderr.write("Shadow execution input must be a JSON object.\n")
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
            result = simulate_case_update(
                approval_record=parsed["approval_record"],
                investigation_context=parsed["investigation_context"],
                simulated_at=parsed["simulated_at"],
            )
        except ShadowExecutionError as exc:
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
