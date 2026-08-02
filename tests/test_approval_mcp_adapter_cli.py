"""Tests for core.approval_mcp_adapter_cli: the stdin/stdout JSON wrapper
around core.approval_mcp_adapter's prepare_supabase_mcp_call and
normalize_supabase_mcp_response.

All tests invoke `main()` directly with `io.StringIO` streams (matching
the CLI's own dependency-injected stdin/stdout/stderr signature) rather
than spawning a subprocess.
"""

from __future__ import annotations

import io
import json

import pytest

from core.approval_mcp_adapter_cli import main


def _run(payload) -> tuple[int, str, str]:
    stdin = io.StringIO(payload if isinstance(payload, str) else json.dumps(payload))
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


_RECORD_FIELDS = (
    "id", "investigation_id", "action_type", "action_payload", "requested_by", "requested_at",
    "status", "approved_by", "approved_at", "rejected_by", "rejected_at", "rejection_reason",
    "expires_at", "consumed_by", "consumed_at", "created_at",
)


def _select_descriptor() -> dict:
    return {
        "operation": "select",
        "table": "approvals",
        "columns": list(_RECORD_FIELDS),
        "filters": {"id": "22222222-2222-2222-2222-222222222222"},
        "limit": 2,
    }


_BLOCK_UUID = "abcdef12-abcd-abcd-abcd-abcdef123456"


def _wrap_block(inner_json_text: str) -> str:
    return f"prose\n<untrusted-data-{_BLOCK_UUID}>\n{inner_json_text}\n</untrusted-data-{_BLOCK_UUID}>\nmore prose"


class TestPrepareCallAction:
    def test_success_returns_tool_and_arguments(self):
        exit_code, stdout, stderr = _run({"action": "prepare_call", "descriptor": _select_descriptor()})
        assert exit_code == 0
        assert stderr == ""
        parsed = json.loads(stdout)
        assert set(parsed) == {"tool", "arguments"}
        assert parsed["tool"] == "mcp__supabase__execute_sql"

    def test_output_is_sorted_and_ascii_preserving(self):
        descriptor = _select_descriptor()
        _, stdout, _ = _run({"action": "prepare_call", "descriptor": descriptor})
        assert stdout == json.dumps(json.loads(stdout), sort_keys=True, ensure_ascii=False) + "\n"

    def test_invalid_descriptor_produces_adapter_error(self):
        exit_code, stdout, stderr = _run({"action": "prepare_call", "descriptor": {"operation": "delete"}})
        assert exit_code == 2
        assert stdout == ""
        error = json.loads(stderr)
        assert error["ok"] is False
        assert error["error"]["code"] == "approval_mcp_adapter_error"
        assert error["error"]["message"] == "Invalid approval MCP descriptor."

    def test_missing_descriptor_field_is_invalid_envelope(self):
        exit_code, stdout, stderr = _run({"action": "prepare_call"})
        assert exit_code == 2
        error = json.loads(stderr)
        assert error["error"]["code"] == "invalid_envelope"

    def test_extra_envelope_field_is_invalid_envelope(self):
        exit_code, _, stderr = _run({"action": "prepare_call", "descriptor": _select_descriptor(), "extra": 1})
        assert exit_code == 2
        assert json.loads(stderr)["error"]["code"] == "invalid_envelope"


class TestNormalizeResponseAction:
    def test_success_returns_rows(self):
        payload = {
            "action": "normalize_response",
            "operation": "load_approval_record",
            "tool_response": {"result": _wrap_block("[]")},
        }
        exit_code, stdout, stderr = _run(payload)
        assert exit_code == 0
        assert stderr == ""
        assert json.loads(stdout) == {"kind": "rows", "rows": []}

    def test_transport_error_is_a_normal_success_result_not_an_error(self):
        payload = {
            "action": "normalize_response",
            "operation": "load_approval_record",
            "tool_response": {"error": {"name": "HttpException", "message": "raw postgres text"}},
        }
        exit_code, stdout, stderr = _run(payload)
        assert exit_code == 0
        assert stderr == ""
        assert json.loads(stdout) == {"kind": "transport_error"}

    def test_raw_error_message_never_appears_in_output(self):
        payload = {
            "action": "normalize_response",
            "operation": "load_approval_record",
            "tool_response": {"error": {"name": "HttpException", "message": "super secret raw postgres detail"}},
        }
        _, stdout, stderr = _run(payload)
        assert "super secret raw postgres detail" not in stdout
        assert "super secret raw postgres detail" not in stderr

    def test_unsupported_operation_produces_adapter_error(self):
        payload = {
            "action": "normalize_response",
            "operation": "delete_approval",
            "tool_response": {"result": _wrap_block("[]")},
        }
        exit_code, stdout, stderr = _run(payload)
        assert exit_code == 2
        assert stdout == ""
        error = json.loads(stderr)
        assert error["error"]["code"] == "approval_mcp_adapter_error"

    def test_missing_operation_field_is_invalid_envelope(self):
        payload = {"action": "normalize_response", "tool_response": {"result": _wrap_block("[]")}}
        exit_code, _, stderr = _run(payload)
        assert exit_code == 2
        assert json.loads(stderr)["error"]["code"] == "invalid_envelope"


class TestEnvelopeAndInputHandling:
    def test_invalid_json_input(self):
        exit_code, stdout, stderr = _run("{not valid json")
        assert exit_code == 2
        assert stdout == ""
        assert json.loads(stderr)["error"]["code"] == "invalid_json"

    def test_non_object_json_input(self):
        exit_code, stdout, stderr = _run("[1, 2, 3]")
        assert exit_code == 2
        assert json.loads(stderr)["error"]["code"] == "invalid_envelope"

    def test_unknown_action_is_invalid_envelope(self):
        exit_code, stdout, stderr = _run({"action": "delete_everything"})
        assert exit_code == 2
        assert json.loads(stderr)["error"]["code"] == "invalid_envelope"

    def test_missing_action_field_is_invalid_envelope(self):
        exit_code, stdout, stderr = _run({"descriptor": _select_descriptor()})
        assert exit_code == 2
        assert json.loads(stderr)["error"]["code"] == "invalid_envelope"

    def test_stdout_and_stderr_are_mutually_exclusive_on_error(self):
        exit_code, stdout, stderr = _run({"action": "prepare_call", "descriptor": {"operation": "bogus"}})
        assert stdout == ""
        assert stderr != ""

    def test_stderr_empty_on_success(self):
        exit_code, stdout, stderr = _run({"action": "prepare_call", "descriptor": _select_descriptor()})
        assert stderr == ""

    def test_no_traceback_ever_emitted(self):
        exit_code, stdout, stderr = _run({"action": "prepare_call", "descriptor": {"operation": "bogus"}})
        assert "Traceback" not in stderr
        assert "Traceback" not in stdout
