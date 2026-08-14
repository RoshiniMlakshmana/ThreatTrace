"""Command-line adapter for `core.security_experience_memory` (Block
15D, checkpoint B).

Input is read from stdin, as a single JSON object. Its top-level
`"operation"` field selects which of the three functions is called:
`"create_experience"`, `"add_experience"`, or `"search"`. Output is
that function's own deterministic result, written to stdout as JSON.
Errors are written to stderr only.

## Security honesty

This CLI performs **no persistence, network, or LLM/model access of
any kind** -- `memory` is exactly the caller-supplied prior state,
returned only as a new, in-memory JSON value; nothing is ever written
to a filesystem, database, or vector store, and no embedding or
similarity model is ever invoked. `search`'s `structured_match_score`
is a deterministic structural overlap count only -- this CLI never
describes it as semantic similarity or a probability. Governance gates
admission: a `"block"`/`"freeze"` Governor result always yields a
`"rejected"`/non-reusable experience from `create_experience`,
regardless of anything else in the supplied case -- this CLI never
overrides that with a caller-supplied `experience_status`/`reusable`
value, because it never accepts either as an input field in the first
place (both are always computed by the core). `execution_performed` is
always `false` in every result this CLI can ever produce.

## Thin adapter boundary

This adapter is a thin wrapper only:

- It owns exactly one thing per operation: that operation's own closed
  envelope shape. It never validates the *content* of `case`,
  `prioritization`, `governor_result`, `memory`, `experience`, or
  `query` itself -- after confirming the envelope has exactly the
  required keys for the selected operation, every value is passed
  directly, completely unchanged, to the corresponding
  `core.security_experience_memory` function. All case/prioritization/
  Governor-result validation, admission-rule computation, memory-shape
  validation, duplicate-detection, and structured-search scoring belong
  entirely to `core.security_experience_memory`, never reimplemented
  here.
- It never imports any other Block's module -- only
  `core.security_experience_memory`'s own public functions and
  `SecurityExperienceMemoryError` are ever imported here.
- It never calls Supabase, MCP, or any other external system; never
  constructs SQL; never reads the system clock, an environment
  variable, or the filesystem; and never persists anything. Its output
  remains exactly the pure core function's own result -- this adapter
  never wraps it in any additional envelope and never overwrites any of
  its fields.

A `"candidate"`/`"rejected"` `experience_status`, or a `reusable_only`
search that returns zero results, is, exactly like it is in the core,
a normal, successful result -- never a CLI failure.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object (the real
  `core.security_experience_memory` result for the selected operation).
- 2 -- invalid input (malformed/non-object JSON, a missing/unknown
  `operation`, a missing/unknown top-level envelope field for the
  selected operation, or a structurally invalid value rejected by the
  core's own `SecurityExperienceMemoryError`); stdout is empty; stderr
  begins with `SECURITY_EXPERIENCE_MEMORY_VALIDATION_FAILED`.
- 1 -- an unexpected internal failure; stdout is empty; stderr begins
  with `SECURITY_EXPERIENCE_MEMORY_INTERNAL_FAILURE`.

Usage:

    py -m core.security_experience_memory_cli
    python3 -m core.security_experience_memory_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.security_experience_memory import (
    SecurityExperienceMemoryError,
    add_security_experience,
    create_security_experience,
    search_security_experiences,
)

_VALIDATION_ERROR_PREFIX = "SECURITY_EXPERIENCE_MEMORY_VALIDATION_FAILED:"
_INTERNAL_ERROR_PREFIX = "SECURITY_EXPERIENCE_MEMORY_INTERNAL_FAILURE:"

_ALLOWED_OPERATIONS = frozenset({"create_experience", "add_experience", "search"})

_CREATE_EXPERIENCE_ENVELOPE_FIELDS = frozenset({
    "operation", "case", "prioritization", "governor_result",
})

_ADD_EXPERIENCE_ENVELOPE_FIELDS = frozenset({"operation", "memory", "experience"})

_SEARCH_ENVELOPE_FIELDS = frozenset({"operation", "memory", "query"})

_ENVELOPE_FIELDS_BY_OPERATION = {
    "create_experience": _CREATE_EXPERIENCE_ENVELOPE_FIELDS,
    "add_experience": _ADD_EXPERIENCE_ENVELOPE_FIELDS,
    "search": _SEARCH_ENVELOPE_FIELDS,
}


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, dispatch it to the
    create_experience, add_experience, or search function, and write
    the result to stdout.

    Returns 0 on success (including a `"candidate"`/`"rejected"`
    `experience_status`, or a `reusable_only` search returning zero
    results -- every one of those is a normal, successful result), 2
    for invalid input (malformed JSON, non-object JSON, a
    missing/unknown `operation`, a missing/unknown envelope field for
    the selected operation, or a structurally invalid value rejected by
    the core's own `SecurityExperienceMemoryError`), and 1 for any
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
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} operation must be "
                "'create_experience', 'add_experience', or 'search'.\n"
            )
            return 2

        allowed_fields = _ENVELOPE_FIELDS_BY_OPERATION[operation]

        unknown_fields = set(parsed) - allowed_fields
        if unknown_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} unrecognized field(s): {', '.join(sorted(unknown_fields))}\n"
            )
            return 2

        missing_fields = [field for field in allowed_fields if field not in parsed]
        if missing_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} missing required field(s): {', '.join(sorted(missing_fields))}\n"
            )
            return 2

        try:
            if operation == "create_experience":
                result = create_security_experience(
                    case=parsed["case"],
                    prioritization=parsed["prioritization"],
                    governor_result=parsed["governor_result"],
                )
            elif operation == "add_experience":
                result = add_security_experience(
                    memory=parsed["memory"],
                    experience=parsed["experience"],
                )
            else:
                result = search_security_experiences(
                    memory=parsed["memory"],
                    query=parsed["query"],
                )
        except SecurityExperienceMemoryError as exc:
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
