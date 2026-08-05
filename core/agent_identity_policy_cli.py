"""Command-line adapter for
`core.agent_identity_policy.evaluate_agent_tool_call`.

Input is read from stdin, as a single JSON object containing exactly
four fields: `agent_id`, `tool_name`, `arguments`, and `evaluated_at`.
Output is the deterministic identity-aware policy report, written to
stdout as JSON. Errors are written to stderr only.

This adapter is a transport wrapper only:

- It owns exactly one thing: the four-field top-level envelope shape. It
  never validates `agent_id`, `tool_name`, `arguments`, or
  `evaluated_at` itself -- after confirming the envelope has exactly
  these four keys, all four values are passed directly to
  `evaluate_agent_tool_call`, even when one of them is malformed. All
  agent-registry lookup, role lookup, capability lookup, Block 8
  integration, tool classification, operation-class checks, allowlist
  checks, mutation-request checks, identity-rule matching and ordering,
  final-decision calculation, and safe capability summarization belong
  entirely to that function.
- It never implements or duplicates any agent registry, role map, rule
  vocabulary, or decision-ordering rule of its own.
- It never authenticates or verifies the caller -- a registry match
  remains a claimed identity only, never proof of identity.
- It never calls Supabase, MCP, Hayabusa, or any other external system;
  never constructs SQL; never reads the system clock, an environment
  variable, or the filesystem; and never executes the proposed tool.
  Its output remains exactly the pure engine's own fifteen-field
  decision report, including `identity_authenticated: false` and
  `execution_performed: false` -- this adapter never wraps it in any
  additional envelope.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object (the identity
  policy report -- `allow`, `require_approval`, and `deny` are all
  successful policy decisions, never a CLI failure).
- 2 -- invalid input (malformed/non-object JSON, a missing/unknown
  top-level envelope field, or a payload that fails identity-policy
  validation); stdout is empty.
- 1 -- an unexpected internal failure; stdout is empty.

Usage:

    py -m core.agent_identity_policy_cli
    python3 -m core.agent_identity_policy_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.agent_identity_policy import AgentIdentityPolicyError, evaluate_agent_tool_call

_VALIDATION_ERROR_PREFIX = "Agent identity policy validation failed:"
_JSON_ERROR_PREFIX = "Invalid JSON input:"
_UNEXPECTED_ERROR_MESSAGE = "Agent identity policy validation failed."

_ALLOWED_ENVELOPE_FIELDS = frozenset({"agent_id", "tool_name", "arguments", "evaluated_at"})


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, evaluate it, and write the result to stdout.

    Returns 0 on success (including a `deny` or `require_approval`
    decision, both of which are normal, successful policy outcomes), 2
    for invalid input (malformed JSON, non-object JSON, a missing/unknown
    top-level envelope field, or a payload that fails identity-policy
    validation), and 1 for any unexpected internal failure.
    """
    try:
        raw_text = stdin.read()

        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            stderr.write(f"{_JSON_ERROR_PREFIX} {exc}\n")
            return 2

        if not isinstance(parsed, dict):
            stderr.write("Agent identity policy input must be a JSON object.\n")
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
            result = evaluate_agent_tool_call(
                agent_id=parsed["agent_id"],
                tool_name=parsed["tool_name"],
                arguments=parsed["arguments"],
                evaluated_at=parsed["evaluated_at"],
            )
        except AgentIdentityPolicyError as exc:
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
