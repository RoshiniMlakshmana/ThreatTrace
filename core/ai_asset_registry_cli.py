"""Command-line adapter for `core.ai_asset_registry`'s three public
functions -- `lookup_ai_asset`, `list_ai_assets`, and
`evaluate_ai_security_case` (Combined Block 11-12).

Input is read from stdin, as a single JSON object. Its top-level
`"operation"` field selects which of the three functions is called:
`"lookup"`, `"list"`, or `"evaluate"`. Output is that function's own
deterministic result, written to stdout as JSON. Errors are written to
stderr only.

This adapter is a transport wrapper only:

- It owns exactly one thing per operation: the operation's own closed
  envelope shape. It never validates `asset_id`, `asset_type`, or
  `case_type` itself -- after confirming the envelope has exactly the
  required keys for the selected operation, every value is passed
  directly to the corresponding core function, even when one of them is
  malformed. All inventory lookup, listing, and evaluation-case logic
  belongs entirely to `core.ai_asset_registry`.
- It never implements or duplicates any Block 8, Block 9, Emergency
  Mutation Freeze, Block 10, inventory, or evaluation-applicability rule
  of its own, and never imports any of those modules directly -- only
  `core.ai_asset_registry`'s own three public functions and its
  `AIAssetRegistryError` are ever imported here.
- It never calls Supabase, MCP, Hayabusa, or any other external system;
  never constructs SQL; never reads the system clock, an environment
  variable, or the filesystem; and never executes a tool. Its output
  remains exactly the pure core function's own result -- including
  `execution_performed: false` on an evaluation result -- this adapter
  never wraps it in any additional envelope and never overwrites any of
  its fields.

A `"pass"` evaluation outcome, exactly like the core function it wraps,
means only that the tested deterministic security property behaved as
expected for that defined case -- never that the AI system is secure,
that a model or prompt is authentic, that runtime enforcement occurred,
that an agent was authenticated, or that execution occurred. An
inventory `found: false` and an evaluation `"fail"`/`"not_applicable"`
are each a normal, successfully handled result, never a CLI failure.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object (the core
  function's own result -- inventory `found: true`/`found: false` and
  evaluation `"pass"`/`"fail"`/`"not_applicable"` are all successful
  outcomes, never a CLI failure).
- 2 -- invalid input (malformed/non-object JSON, a missing/unknown
  `operation`, a missing/unknown top-level envelope field for the
  selected operation, or a structurally invalid `asset_id`/
  `asset_type`/`case_type` value rejected by the core's own
  `AIAssetRegistryError`); stdout is empty.
- 1 -- an unexpected internal failure; stdout is empty.

Usage:

    py -m core.ai_asset_registry_cli
    python3 -m core.ai_asset_registry_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.ai_asset_registry import (
    AIAssetRegistryError,
    evaluate_ai_security_case,
    list_ai_assets,
    lookup_ai_asset,
)

_VALIDATION_ERROR_PREFIX = "AI asset registry CLI validation failed:"
_INTERNAL_ERROR_PREFIX = "AI asset registry CLI internal error:"

_ALLOWED_OPERATIONS = frozenset({"lookup", "list", "evaluate"})

_LOOKUP_ENVELOPE_FIELDS = frozenset({"operation", "asset_id"})
_LIST_ENVELOPE_FIELDS = frozenset({"operation", "asset_type"})
_EVALUATE_ENVELOPE_FIELDS = frozenset({"operation", "case_type", "asset_id"})


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, dispatch it to the lookup,
    list, or evaluate `core.ai_asset_registry` function, and write the
    result to stdout.

    Returns 0 on success (including an inventory `found: false` result
    or an evaluation `"fail"`/`"not_applicable"` outcome, all of which
    are normal, successful results), 2 for invalid input (malformed
    JSON, non-object JSON, a missing/unknown `operation`, a
    missing/unknown envelope field for the selected operation, or a
    structurally invalid field value rejected by the core's own
    `AIAssetRegistryError`), and 1 for any unexpected internal failure.
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
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} operation must be 'lookup', 'list', or 'evaluate'.\n")
            return 2

        if operation == "lookup":
            allowed_fields = _LOOKUP_ENVELOPE_FIELDS
        elif operation == "list":
            allowed_fields = _LIST_ENVELOPE_FIELDS
        else:
            allowed_fields = _EVALUATE_ENVELOPE_FIELDS

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
            if operation == "lookup":
                result = lookup_ai_asset(asset_id=parsed["asset_id"])
            elif operation == "list":
                result = list_ai_assets(asset_type=parsed["asset_type"])
            else:
                result = evaluate_ai_security_case(
                    case_type=parsed["case_type"],
                    asset_id=parsed["asset_id"],
                )
        except AIAssetRegistryError as exc:
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
