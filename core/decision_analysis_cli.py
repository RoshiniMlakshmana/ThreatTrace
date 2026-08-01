"""Command-line adapter for `core.decision_analysis.validate_decision_analysis`.

Input is read from stdin, as a single JSON object representing one proposed
"What Would Change My Decision?" analysis. Output is the validated
decision-analysis object, written to stdout as JSON. Errors are written to
stderr only.

This adapter is a transport wrapper only:

- All structural validation belongs to `validate_decision_analysis`; this
  module never duplicates its field, vocabulary, or condition-list rules.
- It never invokes `core.decision_context.validate_decision_context` and
  never performs any database existence or evidence-ownership check --
  evidence IDs are references only.
- It does not generate an assessment, does not calculate `decision_status`
  or confidence, does not calculate or modify source trust, and does not
  generate assumptions, gaps, or conditions -- `current_assessment`,
  `decision_status`, and every advisory collection are always
  caller-supplied.
- `hypothesis_id` remains governed entirely by the validator's None-only
  v1 rule; this module never supplies or replaces it.
- It performs no file, subprocess, network, or AI-model access, and has no
  persistence or other external side effect anywhere in it.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object.
- 2 -- invalid input (malformed/non-object JSON, or a payload that fails
  decision-analysis validation); stdout is empty.
- 1 -- an unexpected internal failure; stdout is empty.

Usage:

    py -m core.decision_analysis_cli
    python3 -m core.decision_analysis_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.decision_analysis import DecisionAnalysisError, validate_decision_analysis

_VALIDATION_ERROR_PREFIX = "Decision analysis validation failed:"
_JSON_ERROR_PREFIX = "Invalid JSON input:"
_UNEXPECTED_ERROR_MESSAGE = "Decision analysis validation failed."


def main(
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Read one JSON object from stdin, validate it, and write the result to stdout.

    Returns 0 on success, 2 for invalid input (malformed JSON, non-object
    JSON, multiple JSON values, trailing content, or a payload that fails
    decision-analysis validation), and 1 for any unexpected internal
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

        if not isinstance(parsed, dict):
            stderr.write("Decision analysis input must be a JSON object.\n")
            return 2

        try:
            result = validate_decision_analysis(parsed)
        except DecisionAnalysisError as exc:
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
