"""Command-line adapter for
`core.security_governor.evaluate_security_governor_event` (Block
15C.5, checkpoint B).

Input is read from stdin, as a single JSON object containing exactly
two fields: `operation` (always `"evaluate"`), `event`. Output is the
deterministic Governor result, written to stdout as JSON. Errors are
written to stderr only.

## Security honesty

This CLI performs **no network request of any kind** -- it is a pure,
local, deterministic computation over whatever `event` the caller
supplies via stdin. It never executes a tool, calls MCP, calls
Supabase, kills a process, or performs any I/O of any kind.
`execution_performed` is always `false` in every result this CLI can
ever produce -- including a `"block"` or `"freeze"` decision. A
`"block"` or `"freeze"` `decision` is a normal, successfully evaluated
security result, never a CLI failure -- see Exit codes below.

## Thin adapter boundary

This adapter is a thin wrapper only:

- It owns exactly one thing: the two-field top-level envelope shape,
  and the fixed literal `operation` value `"evaluate"`. It never
  validates the *content* of `event` itself -- after confirming the
  envelope has exactly these two keys and `operation` is `"evaluate"`,
  `event` is passed directly, completely unchanged, to
  `evaluate_security_governor_event`. This adapter never trims,
  lowercases, reorders, or otherwise normalizes any nested value, never
  synthesizes a missing `event` field, and never infers any `event`
  field from anything else -- every structural/vocabulary check (the
  sixteen-field event contract, every closed vocabulary, the reason-code
  evaluation order, the severity/floor computation, the repeated-denial
  threshold) belongs entirely to `core.security_governor`, never
  reimplemented here.
- Its output remains exactly `evaluate_security_governor_event`'s own
  result -- this adapter never wraps it in any additional envelope,
  never adds a `success`/`status` field, and never adds explanatory
  prose to stdout.

A `"block"` or `"freeze"` decision is, exactly like it is in the core,
a normal, successful result -- never a CLI validation failure. This
adapter never reframes `"freeze"` as process termination or any other
enforcement action; it is a deterministic recommendation only.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object (the real
  `evaluate_security_governor_event` result, regardless of which
  `decision` it computed -- `"allow"`, `"warn"`, `"require_review"`,
  `"block"`, and `"freeze"` are all exit 0).
- 2 -- invalid input (malformed/non-object JSON, a missing/unknown
  `operation`, a missing/unknown top-level envelope field, or a
  structurally invalid `event` rejected by the core's own
  `SecurityGovernorError`); stdout is empty; stderr begins with
  `SECURITY_GOVERNOR_VALIDATION_FAILED`.
- 1 -- an unexpected internal failure; stdout is empty; stderr begins
  with `SECURITY_GOVERNOR_INTERNAL_FAILURE`.

Usage:

    py -m core.security_governor_cli
    python3 -m core.security_governor_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.security_governor import SecurityGovernorError, evaluate_security_governor_event

_VALIDATION_ERROR_PREFIX = "SECURITY_GOVERNOR_VALIDATION_FAILED:"
_INTERNAL_ERROR_PREFIX = "SECURITY_GOVERNOR_INTERNAL_FAILURE:"

_ALLOWED_OPERATIONS = frozenset({"evaluate"})

_EVALUATE_ENVELOPE_FIELDS = frozenset({"operation", "event"})


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, evaluate one deterministic
    Governor event, and write the result to stdout.

    Returns 0 on success (including a `"block"` or `"freeze"` decision
    -- a normal, successful result), 2 for invalid input (malformed
    JSON, non-object JSON, a missing/unknown `operation`, a
    missing/unknown envelope field, or a structurally invalid `event`
    rejected by the core's own `SecurityGovernorError`), and 1 for any
    unexpected internal failure.
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
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} operation must be 'evaluate'.\n")
            return 2

        unknown_fields = set(parsed) - _EVALUATE_ENVELOPE_FIELDS
        if unknown_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} unrecognized field(s): {', '.join(sorted(unknown_fields))}\n"
            )
            return 2

        missing_fields = [field for field in _EVALUATE_ENVELOPE_FIELDS if field not in parsed]
        if missing_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} missing required field(s): {', '.join(sorted(missing_fields))}\n"
            )
            return 2

        try:
            result = evaluate_security_governor_event(event=parsed["event"])
        except SecurityGovernorError as exc:
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
