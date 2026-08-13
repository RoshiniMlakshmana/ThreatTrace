"""Command-line adapter for
`core.analyst_feedback.create_analyst_feedback` (Block 13).

Input is read from stdin, as a single JSON object containing exactly
nine fields: `operation`, `target_type`, `target_reference`,
`analyst_decision`, `error_category`, `rationale`, `evidence_reference`,
`corrected_value`, `submitted_at`. Output is the deterministic feedback
record, written to stdout as JSON. Errors are written to stderr only.

This adapter is a transport wrapper only:

- It owns exactly one thing: the nine-field top-level envelope shape,
  and the fixed literal `operation` value `"create"`. It never
  validates `target_type`, `target_reference`, `analyst_decision`,
  `error_category`, `rationale`, `evidence_reference`,
  `corrected_value`, or `submitted_at` itself -- after confirming the
  envelope has exactly these nine keys and `operation` is `"create"`,
  the other eight values are passed directly to
  `create_analyst_feedback`, even when one of them is malformed. All
  vocabulary checks, the conditional `error_category`/`rationale`
  disagreement rule, `corrected_value` domain validation, and timestamp
  normalization belong entirely to `core.analyst_feedback`.
- It never implements or duplicates any Block 13 validation rule of its
  own, and never imports any other Block's module -- only
  `core.analyst_feedback`'s own `create_analyst_feedback` and
  `AnalystFeedbackError` are ever imported here.
- It never calls Supabase, MCP, Hayabusa, or any other external system;
  never constructs SQL; never reads the system clock, an environment
  variable, or the filesystem; and never persists anything. Its output
  remains exactly the pure core function's own result -- including
  `feedback_persisted: false` and `automatic_learning_performed: false`
  -- this adapter never wraps it in any additional envelope and never
  overwrites any of its fields.

A `"disagree"` `analyst_decision` is, exactly like it is in the core, a
normal, successfully created feedback record -- never a CLI failure.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object (the created
  feedback record, regardless of `analyst_decision`).
- 2 -- invalid input (malformed/non-object JSON, a missing/unknown
  `operation`, a missing/unknown top-level envelope field, or a
  structurally invalid field value rejected by the core's own
  `AnalystFeedbackError`); stdout is empty.
- 1 -- an unexpected internal failure; stdout is empty.

Usage:

    py -m core.analyst_feedback_cli
    python3 -m core.analyst_feedback_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.analyst_feedback import AnalystFeedbackError, create_analyst_feedback

_VALIDATION_ERROR_PREFIX = "Analyst feedback CLI validation failed:"
_INTERNAL_ERROR_PREFIX = "Analyst feedback CLI internal error:"

_ALLOWED_OPERATIONS = frozenset({"create"})

_CREATE_ENVELOPE_FIELDS = frozenset({
    "operation",
    "target_type",
    "target_reference",
    "analyst_decision",
    "error_category",
    "rationale",
    "evidence_reference",
    "corrected_value",
    "submitted_at",
})


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, create an analyst feedback
    record, and write the result to stdout.

    Returns 0 on success (including an `analyst_decision: "disagree"`
    record, a normal, successful result), 2 for invalid input
    (malformed JSON, non-object JSON, a missing/unknown `operation`, a
    missing/unknown envelope field, or a structurally invalid field
    value rejected by the core's own `AnalystFeedbackError`), and 1 for
    any unexpected internal failure.
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
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} operation must be 'create'.\n")
            return 2

        unknown_fields = set(parsed) - _CREATE_ENVELOPE_FIELDS
        if unknown_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} unrecognized field(s): {', '.join(sorted(unknown_fields))}\n"
            )
            return 2

        missing_fields = [field for field in _CREATE_ENVELOPE_FIELDS if field not in parsed]
        if missing_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} missing required field(s): {', '.join(sorted(missing_fields))}\n"
            )
            return 2

        try:
            result = create_analyst_feedback(
                target_type=parsed["target_type"],
                target_reference=parsed["target_reference"],
                analyst_decision=parsed["analyst_decision"],
                error_category=parsed["error_category"],
                rationale=parsed["rationale"],
                evidence_reference=parsed["evidence_reference"],
                corrected_value=parsed["corrected_value"],
                submitted_at=parsed["submitted_at"],
            )
        except AnalystFeedbackError as exc:
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
