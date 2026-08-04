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


# ---------------------------------------------------------------------------
# Block 6, Step 4R1: risk-aware operations through the real adapter CLI
# ---------------------------------------------------------------------------


_RISK_AWARE_RECORD_FIELDS = _RECORD_FIELDS + ("risk_level", "required_approvals")

_REVIEW_LOOKUP_COLUMNS = (
    "approval_id", "reviewer_identity", "reviewer_identity_normalized", "decision", "decided_at",
)


def _risk_aware_insert_descriptor() -> dict:
    return {
        "operation": "insert",
        "table": "approvals",
        "values": {
            "investigation_id": "11111111-1111-1111-1111-111111111111",
            "action_type": "update_investigation_state",
            "action_payload": {"status": "closed"},
            "requested_by": "analyst@example.com",
            "requested_at": "2026-01-01T00:00:00Z",
            "status": "pending",
            "risk_level": "high",
            "required_approvals": 2,
            "requested_by_normalized": "analyst@example.com",
        },
        "returning": list(_RISK_AWARE_RECORD_FIELDS),
    }


def _review_select_descriptor() -> dict:
    return {
        "operation": "select",
        "table": "approval_reviews",
        "columns": list(_REVIEW_LOOKUP_COLUMNS),
        "filters": {"approval_id": "33333333-3333-3333-3333-333333333333"},
        "order_by": "decided_at",
        "limit": 10,
    }


def _review_rpc_descriptor() -> dict:
    return {
        "operation": "rpc",
        "function": "record_approval_review_and_promote_status",
        "parameters": {
            "approval_id": "55555555-5555-5555-5555-555555555555",
            "expected_from_status": "pending",
            "expected_to_status": "partially_approved",
            "expected_required_approvals": 2,
            "expected_approval_count_before": 0,
            "reviewer_identity": "reviewer@example.com",
            "reviewer_identity_normalized": "reviewer@example.com",
            "decision": "approve",
            "decided_at": "2026-01-01T03:00:00Z",
            "rejection_reason": None,
        },
    }


class TestBlock6RiskAwarePrepareCall:
    def test_risk_aware_insert_prepare_call(self):
        exit_code, stdout, stderr = _run({"action": "prepare_call", "descriptor": _risk_aware_insert_descriptor()})
        assert exit_code == 0
        assert stderr == ""
        parsed = json.loads(stdout)
        assert set(parsed) == {"tool", "arguments"}
        assert parsed["tool"] == "mcp__supabase__execute_sql"
        query = parsed["arguments"]["query"]
        assert query.startswith("INSERT INTO public.approvals (")
        assert "risk_level" in query
        assert "required_approvals" in query
        assert "requested_by_normalized" in query
        assert query.endswith("RETURNING " + ", ".join(_RISK_AWARE_RECORD_FIELDS) + ";")

    def test_review_lookup_prepare_call(self):
        exit_code, stdout, stderr = _run({"action": "prepare_call", "descriptor": _review_select_descriptor()})
        assert exit_code == 0
        assert stderr == ""
        parsed = json.loads(stdout)
        assert set(parsed) == {"tool", "arguments"}
        expected_query = (
            "SELECT " + ", ".join(_REVIEW_LOOKUP_COLUMNS) + " FROM public.approval_reviews "
            "WHERE approval_id = '33333333-3333-3333-3333-333333333333'::uuid "
            "ORDER BY decided_at LIMIT 10;"
        )
        assert parsed["arguments"]["query"] == expected_query

    def test_atomic_review_rpc_prepare_call(self):
        exit_code, stdout, stderr = _run({"action": "prepare_call", "descriptor": _review_rpc_descriptor()})
        assert exit_code == 0
        assert stderr == ""
        parsed = json.loads(stdout)
        expected_query = (
            "SELECT * FROM public.record_approval_review_and_promote_status("
            "'55555555-5555-5555-5555-555555555555'::uuid, "
            "'pending', "
            "'partially_approved', "
            "2, "
            "0, "
            "'reviewer@example.com', "
            "'reviewer@example.com', "
            "'approve', "
            "'2026-01-01T03:00:00Z'::timestamptz, "
            "NULL);"
        )
        assert parsed["arguments"]["query"] == expected_query

    def test_twenty_four_field_normalize_response_and_zero_row_behavior(self):
        row = {
            "id": "55555555-5555-5555-5555-555555555555",
            "investigation_id": "11111111-1111-1111-1111-111111111111",
            "action_type": "update_investigation_state",
            "action_payload": {"status": "closed"},
            "status": "partially_approved",
            "requested_by": "analyst@example.com",
            "requested_at": "2026-01-01 00:00:00+00",
            "expires_at": None,
            "approved_by": None,
            "approved_at": None,
            "rejected_by": None,
            "rejected_at": None,
            "rejection_reason": None,
            "consumed_by": None,
            "consumed_at": None,
            "created_at": "2026-01-01 00:00:00+00",
            "risk_level": "high",
            "required_approvals": 2,
            "review_approval_id": "55555555-5555-5555-5555-555555555555",
            "reviewer_identity": "reviewer@example.com",
            "reviewer_identity_normalized": "reviewer@example.com",
            "review_decision": "approve",
            "review_decided_at": "2026-01-01 03:00:00+00",
            "approval_count": 1,
        }
        assert len(row) == 24

        success_payload = {
            "action": "normalize_response",
            "operation": "apply_multi_review_transition",
            "tool_response": {"result": _wrap_block(json.dumps([row]))},
        }
        exit_code, stdout, stderr = _run(success_payload)
        assert exit_code == 0
        assert stderr == ""
        parsed = json.loads(stdout)
        assert parsed["kind"] == "rows"
        assert parsed["rows"][0]["requested_at"] == "2026-01-01T00:00:00Z"
        assert parsed["rows"][0]["review_decided_at"] == "2026-01-01T03:00:00Z"
        assert parsed["rows"][0]["approval_count"] == 1

        zero_row_payload = {
            "action": "normalize_response",
            "operation": "apply_multi_review_transition",
            "tool_response": {"result": _wrap_block("[]")},
        }
        zero_exit_code, zero_stdout, zero_stderr = _run(zero_row_payload)
        assert zero_exit_code == 0
        assert zero_stderr == ""
        assert json.loads(zero_stdout) == {"kind": "rows", "rows": []}

        # No raw PostgreSQL error and no traceback is ever exposed, even
        # for a genuine tool-level error on this same operation.
        error_payload = {
            "action": "normalize_response",
            "operation": "apply_multi_review_transition",
            "tool_response": {"error": {"name": "HttpException", "message": "raw postgres detail"}},
        }
        error_exit_code, error_stdout, error_stderr = _run(error_payload)
        assert error_exit_code == 0
        assert json.loads(error_stdout) == {"kind": "transport_error"}
        assert "raw postgres detail" not in error_stdout
        assert "raw postgres detail" not in error_stderr
        assert "Traceback" not in error_stdout
        assert "Traceback" not in error_stderr
