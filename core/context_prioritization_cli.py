"""Command-line adapter for
`core.context_prioritization.prioritize_finding` (Block 15B,
checkpoint B).

Input is read from stdin, as a single JSON object containing exactly
three fields: `operation` (always `"prioritize"`), `finding`, `context`.
Output is the deterministic prioritization result, written to stdout as
JSON. Errors are written to stderr only.

## Security honesty

This CLI performs **no network request of any kind** -- it is a pure,
local, deterministic computation over whatever `finding`/`context` the
caller supplies via stdin. `context` is caller-supplied organization
configuration only; this CLI never authenticates who supplied it, never
verifies it against any external source, and never performs a
threat-intelligence lookup of any kind -- `threat_activity` is exactly
the value the caller passed in, nothing more. `operational_priority` is
a deterministic investigation/response prioritization recommendation
only -- it never modifies, and this CLI never reports, any change to
the finding's own technical truth (`finding_status`, `technical_severity`,
`vulnerability_class`, `evidence`, `owasp_category`, `cwe`, `validation`
all remain exactly what the caller's `finding` already said).
`human_review_required` is always `true` in every result this CLI can
ever produce, and no production action of any kind occurs here.

## Thin adapter boundary

This adapter is a thin wrapper only:

- It owns exactly one thing: the three-field top-level envelope shape,
  and the fixed literal `operation` value `"prioritize"`. It never
  validates the *content* of `finding` or `context` itself -- after
  confirming the envelope has exactly these three keys and `operation`
  is `"prioritize"`, both values are passed directly, completely
  unchanged, to `prioritize_finding`. This adapter never trims,
  lowercases, reorders, or otherwise normalizes any nested value, never
  synthesizes a missing `finding`/`context` field, and never infers
  `context` from anything -- every structural/vocabulary check
  (finding-shape validation, the ten-field context contract, every
  closed vocabulary, the scoring weights, the `[-1, +2]`/`[1, 4]`
  clamps, the reason-code vocabulary, context completeness) belongs
  entirely to `core.context_prioritization`, never reimplemented here.
- Its output remains exactly `prioritize_finding`'s own result -- this
  adapter never wraps it in any additional envelope, never adds a
  `success`/`status` field, and never adds explanatory prose to stdout.

A `candidate` finding whose computed `operational_priority` is
`"critical"` is, exactly like it is in the core, a normal, successful
result -- never a CLI validation failure. This adapter never reframes it
as confirmation that the finding was validated.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object (the real
  `prioritize_finding` result, regardless of which `operational_priority`
  it computed).
- 2 -- invalid input (malformed/non-object JSON, a missing/unknown
  `operation`, a missing/unknown top-level envelope field, or a
  structurally invalid `finding`/`context` rejected by the core's own
  `ContextPrioritizationError`); stdout is empty; stderr begins with
  `CONTEXT_PRIORITIZATION_VALIDATION_FAILED`.
- 1 -- an unexpected internal failure; stdout is empty; stderr begins
  with `CONTEXT_PRIORITIZATION_INTERNAL_FAILURE`.

Usage:

    py -m core.context_prioritization_cli
    python3 -m core.context_prioritization_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.context_prioritization import ContextPrioritizationError, prioritize_finding

_VALIDATION_ERROR_PREFIX = "CONTEXT_PRIORITIZATION_VALIDATION_FAILED:"
_INTERNAL_ERROR_PREFIX = "CONTEXT_PRIORITIZATION_INTERNAL_FAILURE:"

_ALLOWED_OPERATIONS = frozenset({"prioritize"})

_PRIORITIZE_ENVELOPE_FIELDS = frozenset({"operation", "finding", "context"})


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, compute one deterministic
    context-aware operational-priority result, and write it to stdout.

    Returns 0 on success (including a `candidate` finding whose computed
    `operational_priority` is `"critical"` -- a normal, successful
    result), 2 for invalid input (malformed JSON, non-object JSON, a
    missing/unknown `operation`, a missing/unknown envelope field, or a
    structurally invalid `finding`/`context` rejected by the core's own
    `ContextPrioritizationError`), and 1 for any unexpected internal
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
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} operation must be 'prioritize'.\n")
            return 2

        unknown_fields = set(parsed) - _PRIORITIZE_ENVELOPE_FIELDS
        if unknown_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} unrecognized field(s): {', '.join(sorted(unknown_fields))}\n"
            )
            return 2

        missing_fields = [field for field in _PRIORITIZE_ENVELOPE_FIELDS if field not in parsed]
        if missing_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} missing required field(s): {', '.join(sorted(missing_fields))}\n"
            )
            return 2

        try:
            result = prioritize_finding(finding=parsed["finding"], context=parsed["context"])
        except ContextPrioritizationError as exc:
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
