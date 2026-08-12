"""Command-line adapter for `core.decision_binding.create_decision_binding`
and `core.decision_binding.verify_decision_binding` (Block 10).

Input is read from stdin, as a single JSON object. Its top-level
`"operation"` field selects which of the two pure Decision Binding
functions is called: `"create"` or `"verify"`. Output is that function's
own deterministic result, written to stdout as JSON. Errors are written
to stderr only.

This adapter is a transport wrapper only:

- It owns exactly one thing per operation: the operation's own closed
  envelope shape. It never validates `identity_policy_result`,
  `arguments`, `issued_at`, `expires_at`, `binding`,
  `fresh_identity_policy_result`, `verification_time`, or
  `approval_reference` itself -- after confirming the envelope has
  exactly the required keys for the selected operation, every value is
  passed directly to the corresponding core function, even when one of
  them is malformed. All structural validation, canonicalization,
  digesting, correlation, and rule evaluation belong entirely to
  `core.decision_binding`.
- It never implements or duplicates any Block 8, Block 9, or Block 10
  policy or correlation rule of its own, and never imports
  `core.agent_gateway` or `core.agent_identity_policy` -- a caller-supplied
  `identity_policy_result` / `fresh_identity_policy_result` is consumed
  exactly as given, never (re)produced by this module.
- It never calls Supabase, MCP, Hayabusa, or any other external system;
  never constructs SQL; never reads the system clock, an environment
  variable, or the filesystem; and never executes a tool. Its output
  remains exactly the pure core function's own result -- including
  `identity_authenticated: false`, `execution_performed: false`, and (for
  `"verify"`) `replay_protection_provided: false` -- this adapter never
  wraps it in any additional envelope and never overwrites any of those
  fields.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object (the core
  function's own result -- a `"created"`/`"refused"` `binding_outcome` and
  a `"valid"`/`"invalid"` `verification_outcome` are all successful
  evaluations, never a CLI failure).
- 2 -- invalid input (malformed/non-object JSON, a missing/unknown/invalid
  `operation`, or a missing/unknown top-level envelope field for the
  selected operation); stdout is empty. `core.decision_binding` is
  designed to never raise for a normal validation condition -- every such
  condition is represented through `refusal_reason` or
  `matched_verification_rules` instead -- so this code path is reached
  only by a malformed envelope, never by a raised core exception.
- 1 -- an unexpected internal failure; stdout is empty.

Usage:

    py -m core.decision_binding_cli
    python3 -m core.decision_binding_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.decision_binding import create_decision_binding, verify_decision_binding

_VALIDATION_ERROR_PREFIX = "Decision binding CLI validation failed:"
_INTERNAL_ERROR_PREFIX = "Decision binding CLI internal error:"

_ALLOWED_OPERATIONS = frozenset({"create", "verify"})

_CREATE_ENVELOPE_FIELDS = frozenset({
    "operation",
    "identity_policy_result",
    "arguments",
    "issued_at",
    "expires_at",
    "approval_reference",
})

_VERIFY_ENVELOPE_FIELDS = frozenset({
    "operation",
    "binding",
    "fresh_identity_policy_result",
    "arguments",
    "verification_time",
    "approval_reference",
})


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, dispatch it to the create or
    verify Decision Binding core function, and write the result to stdout.

    Returns 0 on success (including a `"refused"` `binding_outcome` or an
    `"invalid"` `verification_outcome`, both of which are normal,
    successful evaluations), 2 for invalid input (malformed JSON,
    non-object JSON, a missing/unknown/invalid `operation`, or a
    missing/unknown envelope field for the selected operation), and 1 for
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
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} operation must be 'create' or 'verify'.\n")
            return 2

        allowed_fields = _CREATE_ENVELOPE_FIELDS if operation == "create" else _VERIFY_ENVELOPE_FIELDS

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

        if operation == "create":
            result = create_decision_binding(
                identity_policy_result=parsed["identity_policy_result"],
                arguments=parsed["arguments"],
                issued_at=parsed["issued_at"],
                expires_at=parsed["expires_at"],
                approval_reference=parsed["approval_reference"],
            )
        else:
            result = verify_decision_binding(
                binding=parsed["binding"],
                fresh_identity_policy_result=parsed["fresh_identity_policy_result"],
                arguments=parsed["arguments"],
                verification_time=parsed["verification_time"],
                approval_reference=parsed["approval_reference"],
            )

        stdout.write(json.dumps(result, sort_keys=True, ensure_ascii=False))
        stdout.write("\n")
        return 0
    except Exception:
        stderr.write(f"{_INTERNAL_ERROR_PREFIX} unexpected failure.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
