"""Command-line adapter for
`core.decision_warning_formatter.format_decision_warnings`.

Input is read from stdin, as a single JSON array of already-produced
decision-context warning objects. Output is the formatted warning list,
written to stdout as a JSON array. Errors are written to stderr only.

This adapter is a transport wrapper only:

- All structural validation and formatting belong to
  `format_decision_warnings`; this module never duplicates its field,
  warning-code, or explanation-text rules.
- The caller must already have a produced warning list (e.g. from
  `core.decision_context.validate_decision_context`) -- this CLI never
  generates a warning, never recalculates warning precedence, and never
  invokes either decision validator or either decision validator CLI.
- It performs no file, subprocess, network, or AI-model access, and has no
  persistence or other external side effect anywhere in it.

Exit codes:

- 0 -- success; stdout contains exactly one JSON array.
- 2 -- invalid input (malformed/non-array JSON, or a payload that fails
  decision-warning formatting); stdout is empty.
- 1 -- an unexpected internal failure; stdout is empty.

Usage:

    py -m core.decision_warning_formatter_cli
    python3 -m core.decision_warning_formatter_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.decision_warning_formatter import (
    DecisionWarningFormatError,
    format_decision_warnings,
)

_VALIDATION_ERROR_PREFIX = "Decision warning formatting failed:"
_JSON_ERROR_PREFIX = "Invalid JSON input:"
_UNEXPECTED_ERROR_MESSAGE = "Decision warning formatting failed."


def main(
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Read one JSON array from stdin, format it, and write the result to stdout.

    Returns 0 on success, 2 for invalid input (malformed JSON, non-array
    JSON, multiple JSON values, trailing content, or a payload that fails
    decision-warning formatting), and 1 for any unexpected internal
    failure.
    """
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr

    try:
        raw_text = stdin.read()

        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            stderr.write(f"{_JSON_ERROR_PREFIX} {exc}\n")
            return 2

        if not isinstance(parsed, list):
            stderr.write("Decision warning formatter input must be a JSON array.\n")
            return 2

        try:
            result = format_decision_warnings(parsed)
        except DecisionWarningFormatError as exc:
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
