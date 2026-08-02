"""Command-line adapter for the transport-neutral two-phase prepare/verify
approval bridge in `core.approval_bridge`.

Input is read from stdin, as a single JSON object describing either a
`"prepare"` or a `"verify"` phase request. Output is exactly one JSON
object, written to stdout on success or to stderr on failure. Errors are
never written to stdout.

This adapter is a transport wrapper only:

- All bridge logic (operation validation, descriptor capture, descriptor
  regeneration/comparison, executor-response-envelope validation, and
  dispatch to the underlying persistence functions) belongs entirely to
  `core.approval_bridge`; this module never duplicates any of it.
- It performs no file, subprocess, network, Supabase, or MCP access of
  its own, and has no persistence or other external side effect anywhere
  in it -- it only reads one JSON object from stdin and writes one JSON
  object to stdout or stderr.
- It never accepts a record, a transition plan, or a secret through a
  command-line argument -- stdin is the only transport for any of them.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object (the bridge
  function's own result).
- 2 -- invalid input (malformed JSON, non-object JSON, an unknown phase,
  a missing/unknown/reordered envelope field) or a deterministic bridge/
  persistence validation failure (`approval_not_found`, `approval_conflict`,
  `approval_response_error`, `approval_persistence_error`,
  `approval_bridge_error`); stdout is empty, stderr contains exactly one
  JSON error object.
- 1 -- an executor transport failure (`approval_transport_error`) or any
  unexpected internal failure (`internal_error`); stdout is empty, stderr
  contains exactly one JSON error object. No traceback is ever emitted.

Usage:

    py -m core.approval_bridge_cli
    python3 -m core.approval_bridge_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.approval_bridge import (
    ApprovalBridgeError,
    prepare_approval_operation,
    verify_approval_operation,
)
from core.approval_persistence import (
    ApprovalConflictError,
    ApprovalNotFoundError,
    ApprovalPersistenceError,
    ApprovalResponseError,
    ApprovalTransportError,
)

_PREPARE_ENVELOPE_FIELDS = ("phase", "operation", "input")
_VERIFY_ENVELOPE_FIELDS = ("phase", "operation", "input", "prepared_descriptor", "executor_response")

_INVALID_JSON_MESSAGE = "Invalid JSON input."
_INVALID_ENVELOPE_MESSAGE = "Invalid approval bridge request."
_INTERNAL_ERROR_MESSAGE = "Approval bridge failed."


def _write_error(stderr: TextIO, code: str, message: str) -> None:
    stderr.write(json.dumps({"ok": False, "error": {"code": code, "message": message}}, sort_keys=True, ensure_ascii=False))
    stderr.write("\n")


def _write_result(stdout: TextIO, result: dict) -> None:
    stdout.write(json.dumps(result, sort_keys=True, ensure_ascii=False))
    stdout.write("\n")


def _classify_exception(exc: Exception) -> tuple[str, int] | None:
    """Map a raised exception to (error_code, exit_code). Subclasses are
    checked before their shared base class. Returns None for any
    exception type this CLI does not recognize."""
    if isinstance(exc, ApprovalNotFoundError):
        return "approval_not_found", 2
    if isinstance(exc, ApprovalConflictError):
        return "approval_conflict", 2
    if isinstance(exc, ApprovalResponseError):
        return "approval_response_error", 2
    if isinstance(exc, ApprovalTransportError):
        return "approval_transport_error", 1
    if isinstance(exc, ApprovalPersistenceError):
        return "approval_persistence_error", 2
    if isinstance(exc, ApprovalBridgeError):
        return "approval_bridge_error", 2
    return None


def _handle_bridge_exception(exc: Exception, stderr: TextIO) -> int:
    classified = _classify_exception(exc)
    if classified is None:
        _write_error(stderr, "internal_error", _INTERNAL_ERROR_MESSAGE)
        return 1
    code, exit_code = classified
    _write_error(stderr, code, str(exc))
    return exit_code


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON phase-request object from stdin, dispatch it to the
    prepare or verify bridge function, and write the result to stdout.

    Returns 0 on success, 2 for invalid input or a deterministic bridge/
    persistence validation failure, and 1 for an executor transport
    failure or any unexpected internal failure.
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

        phase = parsed.get("phase")

        if phase == "prepare":
            if tuple(parsed) != _PREPARE_ENVELOPE_FIELDS:
                _write_error(stderr, "invalid_envelope", _INVALID_ENVELOPE_MESSAGE)
                return 2
            try:
                result = prepare_approval_operation(parsed["operation"], parsed["input"])
            except Exception as exc:
                return _handle_bridge_exception(exc, stderr)
            _write_result(stdout, result)
            return 0

        if phase == "verify":
            if tuple(parsed) != _VERIFY_ENVELOPE_FIELDS:
                _write_error(stderr, "invalid_envelope", _INVALID_ENVELOPE_MESSAGE)
                return 2
            try:
                result = verify_approval_operation(
                    parsed["operation"],
                    parsed["input"],
                    parsed["prepared_descriptor"],
                    parsed["executor_response"],
                )
            except Exception as exc:
                return _handle_bridge_exception(exc, stderr)
            _write_result(stdout, result)
            return 0

        _write_error(stderr, "invalid_envelope", _INVALID_ENVELOPE_MESSAGE)
        return 2
    except Exception:
        _write_error(stderr, "internal_error", _INTERNAL_ERROR_MESSAGE)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
