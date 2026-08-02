"""Command-line adapter for the strict Supabase MCP descriptor adapter in
`core.approval_mcp_adapter`.

Input is read from stdin, as a single JSON object describing either a
`"prepare_call"` or a `"normalize_response"` action. Output is exactly one
JSON object, written to stdout on success or to stderr on failure. Errors
are never written to stdout.

This adapter is a transport wrapper only:

- All descriptor validation, SQL-template generation, value encoding, and
  live-response parsing/normalization belongs entirely to
  `core.approval_mcp_adapter`; this module never duplicates any of it.
- It performs no file, subprocess, network, Supabase, or MCP access of its
  own -- it only reads one JSON object from stdin and writes one JSON
  object to stdout or stderr.
- It never invokes `mcp__supabase__execute_sql` itself and never fabricates
  a tool response -- both the request Claude should issue and the response
  Claude received are passed through stdin/stdout only.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object (the adapter
  function's own result).
- 2 -- invalid input (malformed JSON, non-object JSON, an unknown action, a
  missing/unknown/reordered envelope field) or a deterministic adapter
  validation failure (`approval_mcp_adapter_error`); stdout is empty,
  stderr contains exactly one JSON error object.
- 1 -- any unexpected internal failure (`internal_error`); stdout is
  empty, stderr contains exactly one JSON error object. No traceback is
  ever emitted.

Usage:

    py -m core.approval_mcp_adapter_cli
    python3 -m core.approval_mcp_adapter_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.approval_mcp_adapter import (
    ApprovalMcpAdapterError,
    normalize_supabase_mcp_response,
    prepare_supabase_mcp_call,
)

_PREPARE_CALL_ENVELOPE_FIELDS = ("action", "descriptor")
_NORMALIZE_RESPONSE_ENVELOPE_FIELDS = ("action", "operation", "tool_response")

_INVALID_JSON_MESSAGE = "Invalid JSON input."
_INVALID_ENVELOPE_MESSAGE = "Invalid approval MCP adapter request."
_INTERNAL_ERROR_MESSAGE = "Approval MCP adapter failed."


def _write_error(stderr: TextIO, code: str, message: str) -> None:
    stderr.write(json.dumps({"ok": False, "error": {"code": code, "message": message}}, sort_keys=True, ensure_ascii=False))
    stderr.write("\n")


def _write_result(stdout: TextIO, result: dict) -> None:
    stdout.write(json.dumps(result, sort_keys=True, ensure_ascii=False))
    stdout.write("\n")


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON action-request object from stdin, dispatch it to the
    prepare_supabase_mcp_call or normalize_supabase_mcp_response adapter
    function, and write the result to stdout.

    Returns 0 on success, 2 for invalid input or a deterministic adapter
    validation failure, and 1 for any unexpected internal failure.
    """
    try:
        raw_text = stdin.read()

        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError:
            _write_error(stderr, "invalid_json", _INVALID_JSON_MESSAGE)
            return 2

        if not isinstance(parsed, dict):
            _write_error(stderr, "invalid_envelope", _INVALID_ENVELOPE_MESSAGE)
            return 2

        action = parsed.get("action")

        if action == "prepare_call":
            if tuple(parsed) != _PREPARE_CALL_ENVELOPE_FIELDS:
                _write_error(stderr, "invalid_envelope", _INVALID_ENVELOPE_MESSAGE)
                return 2
            try:
                result = prepare_supabase_mcp_call(parsed["descriptor"])
            except ApprovalMcpAdapterError as exc:
                _write_error(stderr, "approval_mcp_adapter_error", str(exc))
                return 2
            except Exception:
                _write_error(stderr, "internal_error", _INTERNAL_ERROR_MESSAGE)
                return 1
            _write_result(stdout, result)
            return 0

        if action == "normalize_response":
            if tuple(parsed) != _NORMALIZE_RESPONSE_ENVELOPE_FIELDS:
                _write_error(stderr, "invalid_envelope", _INVALID_ENVELOPE_MESSAGE)
                return 2
            try:
                result = normalize_supabase_mcp_response(parsed["operation"], parsed["tool_response"])
            except ApprovalMcpAdapterError as exc:
                _write_error(stderr, "approval_mcp_adapter_error", str(exc))
                return 2
            except Exception:
                _write_error(stderr, "internal_error", _INTERNAL_ERROR_MESSAGE)
                return 1
            _write_result(stdout, result)
            return 0

        _write_error(stderr, "invalid_envelope", _INVALID_ENVELOPE_MESSAGE)
        return 2
    except Exception:
        _write_error(stderr, "internal_error", _INTERNAL_ERROR_MESSAGE)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
