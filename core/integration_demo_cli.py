"""Command-line adapter for
`core.integration_demo.run_integration_scenario` (Block 15, checkpoint B).

Input is read from stdin, as a single JSON object containing exactly two
fields: `operation` (always `"run"`) and `scenario` (one of the four
recognized integration-demo scenario ids). Output is the deterministic
scenario result, written to stdout as JSON. Errors are written to
stderr only.

This adapter is a thin transport wrapper only:

- It owns exactly one thing: the two-field top-level envelope shape, and
  the fixed literal `operation` value `"run"`. It never validates
  `scenario` itself, and never trims, lowercases, or otherwise
  normalizes it -- after confirming the envelope has exactly these two
  keys and `operation` is `"run"`, `scenario` is passed directly, byte
  for byte, to `run_integration_scenario`, even when it is malformed,
  blank, or unrecognized. `core.integration_demo` remains the sole
  authority on which scenario ids are valid.
- It never implements or duplicates any Block 8/9/10/11/11-12/13/14
  policy, evaluation, hashing, or aggregation logic, and never imports
  any module other than `core.integration_demo` -- only
  `run_integration_scenario` and `IntegrationDemoError` are ever
  imported here.
- It never calls Supabase, MCP, or any other external system; never
  constructs SQL; never reads the system clock, an environment
  variable, or the filesystem; and never persists anything. Its output
  remains exactly the pure core function's own result -- including
  `execution_performed: false` -- this adapter never wraps it in any
  additional envelope, adds a status/success field, renames a field, or
  reinterprets `final_outcome`.

A scenario result that demonstrates a security denial, an emergency
freeze narrowing, or an invalid binding verification is, exactly like it
is in the core, a normal, successful result -- never a CLI failure.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object (the real
  `run_integration_scenario` result, regardless of which security
  outcome it demonstrates).
- 2 -- invalid input (malformed/non-object JSON, a missing/unknown
  `operation`, a missing/unknown top-level envelope field, or a
  structurally invalid `scenario` value rejected by the core's own
  `IntegrationDemoError`); stdout is empty; stderr begins with
  `INTEGRATION_DEMO_VALIDATION_FAILED`.
- 1 -- an unexpected internal failure; stdout is empty; stderr begins
  with `INTEGRATION_DEMO_INTERNAL_FAILURE`.

Usage:

    py -m core.integration_demo_cli
    python3 -m core.integration_demo_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.integration_demo import IntegrationDemoError, run_integration_scenario

_VALIDATION_ERROR_PREFIX = "INTEGRATION_DEMO_VALIDATION_FAILED:"
_INTERNAL_ERROR_PREFIX = "INTEGRATION_DEMO_INTERNAL_FAILURE:"

_ALLOWED_OPERATIONS = frozenset({"run"})

_RUN_ENVELOPE_FIELDS = frozenset({"operation", "scenario"})


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, run one deterministic
    integration-demo scenario, and write the result to stdout.

    Returns 0 on success (including a scenario result whose
    `final_outcome` reflects a security denial, an emergency freeze
    narrowing, or an invalid binding verification -- every one of those
    is a normal, successful result), 2 for invalid input (malformed
    JSON, non-object JSON, a missing/unknown `operation`, a
    missing/unknown envelope field, or a structurally invalid `scenario`
    value rejected by the core's own `IntegrationDemoError`), and 1 for
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
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} operation must be 'run'.\n")
            return 2

        unknown_fields = set(parsed) - _RUN_ENVELOPE_FIELDS
        if unknown_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} unrecognized field(s): {', '.join(sorted(unknown_fields))}\n"
            )
            return 2

        missing_fields = [field for field in _RUN_ENVELOPE_FIELDS if field not in parsed]
        if missing_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} missing required field(s): {', '.join(sorted(missing_fields))}\n"
            )
            return 2

        try:
            result = run_integration_scenario(scenario=parsed["scenario"])
        except IntegrationDemoError as exc:
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
