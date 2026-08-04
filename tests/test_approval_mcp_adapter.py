"""Tests for core.approval_mcp_adapter: the strict Supabase MCP descriptor
adapter, SQL-template generation, value encoding, and live-response
normalization.

Every expected SQL string below is a hand-computed literal, not derived
from the module's own encoding logic -- so these tests fail if the
production templates or encoders drift, rather than merely re-asserting
whatever the implementation currently produces.
"""

from __future__ import annotations

import copy
import json

import pytest

import core.approval_mcp_adapter as adapter_module
from core.approval_mcp_adapter import (
    ApprovalMcpAdapterError,
    normalize_supabase_mcp_response,
    prepare_supabase_mcp_call,
)

_RECORD_FIELDS = adapter_module._RECORD_FIELDS
_RETURNING_TEXT = ", ".join(_RECORD_FIELDS)

_RISK_AWARE_RECORD_FIELDS = adapter_module._RISK_AWARE_RECORD_FIELDS
_RISK_AWARE_RETURNING_TEXT = ", ".join(_RISK_AWARE_RECORD_FIELDS)
_REVIEW_LOOKUP_COLUMNS = adapter_module._REVIEW_LOOKUP_COLUMNS
_REVIEW_LOOKUP_TEXT = ", ".join(_REVIEW_LOOKUP_COLUMNS)


# ---------------------------------------------------------------------------
# Descriptor fixtures
# ---------------------------------------------------------------------------


def _insert_descriptor(with_expires_at: bool = False) -> dict:
    values = {
        "investigation_id": "11111111-1111-1111-1111-111111111111",
        "action_type": "update_investigation_state",
        "action_payload": {"confidence": "high", "status": "escalated"},
        "requested_by": "analyst@example.com",
        "requested_at": "2026-01-01T00:00:00Z",
        "status": "pending",
    }
    if with_expires_at:
        values["expires_at"] = "2026-01-02T00:00:00Z"
    return {
        "operation": "insert",
        "table": "approvals",
        "values": values,
        "returning": list(_RECORD_FIELDS),
    }


def _select_descriptor() -> dict:
    return {
        "operation": "select",
        "table": "approvals",
        "columns": list(_RECORD_FIELDS),
        "filters": {"id": "22222222-2222-2222-2222-222222222222"},
        "limit": 2,
    }


def _review_null_filters() -> dict:
    return {
        "approved_by": None,
        "approved_at": None,
        "rejected_by": None,
        "rejected_at": None,
        "rejection_reason": None,
        "consumed_by": None,
        "consumed_at": None,
    }


def _approve_descriptor() -> dict:
    filters = {"id": "33333333-3333-3333-3333-333333333333", "status": "pending"}
    filters.update(_review_null_filters())
    return {
        "operation": "update",
        "table": "approvals",
        "values": {
            "status": "approved",
            "approved_by": "reviewer@example.com",
            "approved_at": "2026-01-01T01:00:00Z",
        },
        "filters": filters,
        "returning": list(_RECORD_FIELDS),
    }


def _reject_descriptor() -> dict:
    filters = {"id": "44444444-4444-4444-4444-444444444444", "status": "pending"}
    filters.update(_review_null_filters())
    return {
        "operation": "update",
        "table": "approvals",
        "values": {
            "status": "rejected",
            "rejected_by": "reviewer@example.com",
            "rejected_at": "2026-01-01T02:00:00Z",
            "rejection_reason": "insufficient evidence",
        },
        "filters": filters,
        "returning": list(_RECORD_FIELDS),
    }


def _rpc_descriptor() -> dict:
    return {
        "operation": "rpc",
        "function": "consume_approval_and_update_investigation_state",
        "parameters": {
            "approval_id": "55555555-5555-5555-5555-555555555555",
            "expected_investigation_id": "66666666-6666-6666-6666-666666666666",
            "expected_action_type": "update_investigation_state",
            "consumed_by": "system",
            "consumed_at": "2026-01-01T03:00:00Z",
        },
    }


def _risk_aware_insert_descriptor(with_expires_at: bool = False) -> dict:
    values = {
        "investigation_id": "11111111-1111-1111-1111-111111111111",
        "action_type": "update_investigation_state",
        "action_payload": {"confidence": "high", "status": "escalated"},
        "requested_by": "analyst@example.com",
        "requested_at": "2026-01-01T00:00:00Z",
        "status": "pending",
        "risk_level": "high",
        "required_approvals": 2,
        "requested_by_normalized": "analyst@example.com",
    }
    if with_expires_at:
        values["expires_at"] = "2026-01-02T00:00:00Z"
    return {
        "operation": "insert",
        "table": "approvals",
        "values": values,
        "returning": list(_RISK_AWARE_RECORD_FIELDS),
    }


def _risk_aware_select_descriptor() -> dict:
    return {
        "operation": "select",
        "table": "approvals",
        "columns": list(_RISK_AWARE_RECORD_FIELDS),
        "filters": {"id": "22222222-2222-2222-2222-222222222222"},
        "limit": 2,
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


def _review_rpc_descriptor(decision: str = "approve", rejection_reason: str | None = None) -> dict:
    return {
        "operation": "rpc",
        "function": "record_approval_review_and_promote_status",
        "parameters": {
            "approval_id": "55555555-5555-5555-5555-555555555555",
            "expected_from_status": "pending",
            "expected_to_status": "partially_approved" if decision == "approve" else "rejected",
            "expected_required_approvals": 2,
            "expected_approval_count_before": 0,
            "reviewer_identity": "reviewer@example.com",
            "reviewer_identity_normalized": "reviewer@example.com",
            "decision": decision,
            "decided_at": "2026-01-01T03:00:00Z",
            "rejection_reason": rejection_reason,
        },
    }


# ---------------------------------------------------------------------------
# ApprovalMcpAdapterError
# ---------------------------------------------------------------------------


class TestExceptionType:
    def test_is_exception_subclass(self):
        assert issubclass(ApprovalMcpAdapterError, Exception)

    def test_carries_fixed_message(self):
        with pytest.raises(ApprovalMcpAdapterError) as excinfo:
            prepare_supabase_mcp_call("not a mapping")
        assert str(excinfo.value) == "Invalid approval MCP descriptor."


# ---------------------------------------------------------------------------
# prepare_supabase_mcp_call -- shape of the returned tool-call request
# ---------------------------------------------------------------------------


class TestPreparedCallShape:
    def test_top_level_keys_are_exactly_tool_and_arguments(self):
        result = prepare_supabase_mcp_call(_select_descriptor())
        assert set(result) == {"tool", "arguments"}

    def test_tool_name_is_execute_sql(self):
        result = prepare_supabase_mcp_call(_select_descriptor())
        assert result["tool"] == "mcp__supabase__execute_sql"

    def test_arguments_contains_only_query(self):
        result = prepare_supabase_mcp_call(_select_descriptor())
        assert set(result["arguments"]) == {"query"}
        assert isinstance(result["arguments"]["query"], str)

    def test_generated_sql_ends_with_semicolon(self):
        for descriptor in (
            _insert_descriptor(), _select_descriptor(), _approve_descriptor(),
            _reject_descriptor(), _rpc_descriptor(),
        ):
            result = prepare_supabase_mcp_call(descriptor)
            assert result["arguments"]["query"].endswith(";")


# ---------------------------------------------------------------------------
# INSERT template
# ---------------------------------------------------------------------------


class TestInsertTemplate:
    def test_exact_sql_without_expires_at(self):
        result = prepare_supabase_mcp_call(_insert_descriptor(with_expires_at=False))
        expected = (
            "INSERT INTO public.approvals "
            "(investigation_id, action_type, action_payload, requested_by, requested_at, status) "
            "VALUES ("
            "'11111111-1111-1111-1111-111111111111'::uuid, "
            "'update_investigation_state', "
            "'{\"confidence\":\"high\",\"status\":\"escalated\"}'::jsonb, "
            "'analyst@example.com', "
            "'2026-01-01T00:00:00Z'::timestamptz, "
            "'pending') "
            "RETURNING " + _RETURNING_TEXT + ";"
        )
        assert result["arguments"]["query"] == expected

    def test_exact_sql_with_expires_at(self):
        result = prepare_supabase_mcp_call(_insert_descriptor(with_expires_at=True))
        expected = (
            "INSERT INTO public.approvals "
            "(investigation_id, action_type, action_payload, requested_by, requested_at, status, expires_at) "
            "VALUES ("
            "'11111111-1111-1111-1111-111111111111'::uuid, "
            "'update_investigation_state', "
            "'{\"confidence\":\"high\",\"status\":\"escalated\"}'::jsonb, "
            "'analyst@example.com', "
            "'2026-01-01T00:00:00Z'::timestamptz, "
            "'pending', "
            "'2026-01-02T00:00:00Z'::timestamptz) "
            "RETURNING " + _RETURNING_TEXT + ";"
        )
        assert result["arguments"]["query"] == expected

    def test_column_order_is_fixed_regardless_of_dict_construction_order(self):
        forward = _insert_descriptor(with_expires_at=True)
        reordered = dict(forward)
        reordered["values"] = {
            "status": forward["values"]["status"],
            "requested_at": forward["values"]["requested_at"],
            "expires_at": forward["values"]["expires_at"],
            "action_payload": forward["values"]["action_payload"],
            "action_type": forward["values"]["action_type"],
            "requested_by": forward["values"]["requested_by"],
            "investigation_id": forward["values"]["investigation_id"],
        }
        sql_forward = prepare_supabase_mcp_call(forward)["arguments"]["query"]
        sql_reordered = prepare_supabase_mcp_call(reordered)["arguments"]["query"]
        assert sql_forward == sql_reordered

    def test_unicode_action_payload_preserved(self):
        descriptor = _insert_descriptor()
        descriptor["values"]["action_payload"] = {"note": "café"}
        result = prepare_supabase_mcp_call(descriptor)
        assert "café" in result["arguments"]["query"]
        assert "\\u00e9" not in result["arguments"]["query"]

    def test_jsonb_key_order_is_deterministic(self):
        descriptor_a = _insert_descriptor()
        descriptor_a["values"]["action_payload"] = {"b": 1, "a": 2}
        descriptor_b = _insert_descriptor()
        descriptor_b["values"]["action_payload"] = {"a": 2, "b": 1}
        sql_a = prepare_supabase_mcp_call(descriptor_a)["arguments"]["query"]
        sql_b = prepare_supabase_mcp_call(descriptor_b)["arguments"]["query"]
        assert sql_a == sql_b
        assert "'{\"a\":2,\"b\":1}'::jsonb" in sql_a

    def test_text_value_escapes_single_quote(self):
        descriptor = _insert_descriptor()
        descriptor["values"]["requested_by"] = "o'brien@example.com"
        result = prepare_supabase_mcp_call(descriptor)
        assert "'o''brien@example.com'" in result["arguments"]["query"]

    @pytest.mark.parametrize(
        "mutation",
        [
            lambda d: d.pop("table"),
            lambda d: d.__setitem__("table", "other_table"),
            lambda d: d.__setitem__("operation", "select"),
            lambda d: d.__setitem__("extra", 1),
            lambda d: d["values"].pop("action_type"),
            lambda d: d["values"].__setitem__("unexpected_field", "x"),
            lambda d: d["values"].__setitem__("status", "approved"),
            lambda d: d.__setitem__("returning", list(_RECORD_FIELDS)[::-1]),
            lambda d: d.__setitem__("returning", list(_RECORD_FIELDS)[:-1]),
            lambda d: d.__setitem__("values", "not a mapping"),
        ],
    )
    def test_malformed_insert_descriptor_rejected(self, mutation):
        descriptor = _insert_descriptor()
        mutation(descriptor)
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(descriptor)


# ---------------------------------------------------------------------------
# SELECT template
# ---------------------------------------------------------------------------


class TestSelectTemplate:
    def test_exact_sql(self):
        result = prepare_supabase_mcp_call(_select_descriptor())
        expected = (
            "SELECT " + _RETURNING_TEXT + " FROM public.approvals "
            "WHERE id = '22222222-2222-2222-2222-222222222222'::uuid LIMIT 2;"
        )
        assert result["arguments"]["query"] == expected

    @pytest.mark.parametrize(
        "mutation",
        [
            lambda d: d.__setitem__("limit", 1),
            lambda d: d.__setitem__("columns", list(_RECORD_FIELDS)[::-1]),
            lambda d: d["filters"].__setitem__("status", "pending"),
            lambda d: d.pop("limit"),
            lambda d: d.__setitem__("table", "approvals_v2"),
        ],
    )
    def test_malformed_select_descriptor_rejected(self, mutation):
        descriptor = _select_descriptor()
        mutation(descriptor)
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(descriptor)


# ---------------------------------------------------------------------------
# UPDATE (review transition) template
# ---------------------------------------------------------------------------


class TestUpdateTemplate:
    def test_exact_sql_for_approve(self):
        result = prepare_supabase_mcp_call(_approve_descriptor())
        expected = (
            "UPDATE public.approvals SET "
            "status = 'approved', approved_by = 'reviewer@example.com', approved_at = '2026-01-01T01:00:00Z'::timestamptz "
            "WHERE id = '33333333-3333-3333-3333-333333333333'::uuid AND status = 'pending' "
            "AND approved_by IS NULL AND approved_at IS NULL AND rejected_by IS NULL AND rejected_at IS NULL "
            "AND rejection_reason IS NULL AND consumed_by IS NULL AND consumed_at IS NULL "
            "RETURNING " + _RETURNING_TEXT + ";"
        )
        assert result["arguments"]["query"] == expected

    def test_exact_sql_for_reject(self):
        result = prepare_supabase_mcp_call(_reject_descriptor())
        expected = (
            "UPDATE public.approvals SET "
            "status = 'rejected', rejected_by = 'reviewer@example.com', rejected_at = '2026-01-01T02:00:00Z'::timestamptz, "
            "rejection_reason = 'insufficient evidence' "
            "WHERE id = '44444444-4444-4444-4444-444444444444'::uuid AND status = 'pending' "
            "AND approved_by IS NULL AND approved_at IS NULL AND rejected_by IS NULL AND rejected_at IS NULL "
            "AND rejection_reason IS NULL AND consumed_by IS NULL AND consumed_at IS NULL "
            "RETURNING " + _RETURNING_TEXT + ";"
        )
        assert result["arguments"]["query"] == expected

    def test_reordered_dict_keys_produce_identical_sql(self):
        forward = _approve_descriptor()
        reordered = dict(forward)
        reordered["filters"] = {key: forward["filters"][key] for key in reversed(list(forward["filters"]))}
        sql_forward = prepare_supabase_mcp_call(forward)["arguments"]["query"]
        sql_reordered = prepare_supabase_mcp_call(reordered)["arguments"]["query"]
        assert sql_forward == sql_reordered

    @pytest.mark.parametrize(
        "mutation",
        [
            lambda d: d["filters"].__setitem__("consumed_by", "someone"),
            lambda d: d["filters"].__setitem__("status", "approved"),
            lambda d: d["values"].pop("approved_by"),
            lambda d: d["values"].__setitem__("rejected_by", "x"),
            lambda d: d["values"].__setitem__("status", "rejected"),
            lambda d: d["filters"].pop("consumed_at"),
            lambda d: d.__setitem__("returning", list(_RECORD_FIELDS)[:-1]),
        ],
    )
    def test_malformed_approve_descriptor_rejected(self, mutation):
        descriptor = _approve_descriptor()
        mutation(descriptor)
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(descriptor)

    def test_malformed_reject_descriptor_missing_reason_rejected(self):
        descriptor = _reject_descriptor()
        descriptor["values"].pop("rejection_reason")
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(descriptor)

    def test_mixed_approve_reject_fields_rejected(self):
        descriptor = _approve_descriptor()
        descriptor["values"]["rejected_by"] = "someone"
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(descriptor)


# ---------------------------------------------------------------------------
# RPC template
# ---------------------------------------------------------------------------


class TestRpcTemplate:
    def test_exact_sql(self):
        result = prepare_supabase_mcp_call(_rpc_descriptor())
        expected = (
            "SELECT * FROM public.consume_approval_and_update_investigation_state("
            "'55555555-5555-5555-5555-555555555555'::uuid, "
            "'66666666-6666-6666-6666-666666666666'::uuid, "
            "'update_investigation_state', "
            "'system', "
            "'2026-01-01T03:00:00Z'::timestamptz);"
        )
        assert result["arguments"]["query"] == expected

    @pytest.mark.parametrize(
        "mutation",
        [
            lambda d: d.__setitem__("function", "some_other_function"),
            lambda d: d["parameters"].__setitem__("expected_action_type", "delete_investigation"),
            lambda d: d["parameters"].pop("consumed_by"),
            lambda d: d["parameters"].__setitem__("extra", 1),
        ],
    )
    def test_malformed_rpc_descriptor_rejected(self, mutation):
        descriptor = _rpc_descriptor()
        mutation(descriptor)
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(descriptor)


# ---------------------------------------------------------------------------
# Value encoders (exercised indirectly through the templates)
# ---------------------------------------------------------------------------


class TestValueEncoding:
    def test_uppercase_uuid_rejected(self):
        descriptor = _select_descriptor()
        descriptor["filters"]["id"] = "abcdef12-abcd-abcd-abcd-abcdef123456".upper()
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(descriptor)

    def test_non_string_uuid_rejected(self):
        descriptor = _select_descriptor()
        descriptor["filters"]["id"] = 12345
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(descriptor)

    def test_malformed_uuid_shape_rejected(self):
        descriptor = _select_descriptor()
        descriptor["filters"]["id"] = "not-a-uuid"
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(descriptor)

    def test_padded_uuid_rejected(self):
        descriptor = _select_descriptor()
        descriptor["filters"]["id"] = " 22222222-2222-2222-2222-222222222222"
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(descriptor)

    def test_naive_timestamp_rejected(self):
        descriptor = _insert_descriptor()
        descriptor["values"]["requested_at"] = "2026-01-01T00:00:00"
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(descriptor)

    def test_space_separated_timestamp_rejected(self):
        descriptor = _insert_descriptor()
        descriptor["values"]["requested_at"] = "2026-01-01 00:00:00+00"
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(descriptor)

    def test_padded_timestamp_rejected(self):
        descriptor = _insert_descriptor()
        descriptor["values"]["requested_at"] = "2026-01-01T00:00:00Z "
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(descriptor)

    def test_fractional_seconds_timestamp_accepted(self):
        descriptor = _insert_descriptor()
        descriptor["values"]["requested_at"] = "2026-01-01T00:00:00.123456Z"
        result = prepare_supabase_mcp_call(descriptor)
        assert "'2026-01-01T00:00:00.123456Z'::timestamptz" in result["arguments"]["query"]

    def test_non_mapping_jsonb_rejected(self):
        descriptor = _insert_descriptor()
        descriptor["values"]["action_payload"] = "not a mapping"
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(descriptor)

    def test_non_string_text_field_rejected(self):
        descriptor = _insert_descriptor()
        descriptor["values"]["requested_by"] = 42
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(descriptor)


# ---------------------------------------------------------------------------
# Descriptor call-shape and non-mutation
# ---------------------------------------------------------------------------


class TestPrepareCallInputHandling:
    def test_non_mapping_descriptor_rejected(self):
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(["not", "a", "mapping"])

    def test_unknown_top_level_operation_rejected(self):
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call({"operation": "delete", "table": "approvals"})

    def test_descriptor_not_mutated(self):
        descriptor = _insert_descriptor(with_expires_at=True)
        before = copy.deepcopy(descriptor)
        prepare_supabase_mcp_call(descriptor)
        assert descriptor == before

    def test_nested_values_mapping_identity_preserved(self):
        descriptor = _insert_descriptor()
        values_ref = descriptor["values"]
        prepare_supabase_mcp_call(descriptor)
        assert descriptor["values"] is values_ref


# ---------------------------------------------------------------------------
# normalize_supabase_mcp_response -- call-level validation (raises)
# ---------------------------------------------------------------------------


class TestNormalizeCallValidation:
    def test_unsupported_operation_raises(self):
        with pytest.raises(ApprovalMcpAdapterError):
            normalize_supabase_mcp_response("delete_approval", {"result": "[]"})

    def test_operation_alias_rejected(self):
        with pytest.raises(ApprovalMcpAdapterError):
            normalize_supabase_mcp_response("insert_approval", {"result": "[]"})

    def test_non_mapping_tool_response_raises(self):
        with pytest.raises(ApprovalMcpAdapterError):
            normalize_supabase_mcp_response("load_approval_record", "not a mapping")

    def test_exception_message_is_fixed_and_generic(self):
        with pytest.raises(ApprovalMcpAdapterError) as excinfo:
            normalize_supabase_mcp_response("bogus_operation", {"result": "[]"})
        assert str(excinfo.value) == "Invalid approval MCP response."


# ---------------------------------------------------------------------------
# normalize_supabase_mcp_response -- envelope classification (never raises)
# ---------------------------------------------------------------------------


def _wrap_block(uuid_text: str, inner_json_text: str) -> str:
    return f"some prose\n<untrusted-data-{uuid_text}>\n{inner_json_text}\n</untrusted-data-{uuid_text}>\nmore prose"


_BLOCK_UUID = "abcdef12-abcd-abcd-abcd-abcdef123456"


class TestNormalizeEnvelopeClassification:
    def test_zero_rows(self):
        response = {"result": _wrap_block(_BLOCK_UUID, "[]")}
        assert normalize_supabase_mcp_response("load_approval_record", response) == {"kind": "rows", "rows": []}

    def test_error_response_becomes_transport_error(self):
        response = {"error": {"name": "HttpException", "message": "raw postgres text"}}
        assert normalize_supabase_mcp_response("load_approval_record", response) == {"kind": "transport_error"}

    def test_non_mapping_error_becomes_transport_error(self):
        response = {"error": "just a string"}
        assert normalize_supabase_mcp_response("load_approval_record", response) == {"kind": "transport_error"}

    def test_both_result_and_error_present_becomes_transport_error(self):
        response = {"result": _wrap_block(_BLOCK_UUID, "[]"), "error": {"name": "x", "message": "y"}}
        assert normalize_supabase_mcp_response("load_approval_record", response) == {"kind": "transport_error"}

    def test_neither_result_nor_error_present_becomes_transport_error(self):
        assert normalize_supabase_mcp_response("load_approval_record", {}) == {"kind": "transport_error"}

    def test_unknown_outer_key_becomes_transport_error(self):
        response = {"result": _wrap_block(_BLOCK_UUID, "[]"), "extra": 1}
        assert normalize_supabase_mcp_response("load_approval_record", response) == {"kind": "transport_error"}

    def test_non_string_result_becomes_transport_error(self):
        response = {"result": 12345}
        assert normalize_supabase_mcp_response("load_approval_record", response) == {"kind": "transport_error"}

    def test_missing_block_becomes_transport_error(self):
        response = {"result": "no block here at all"}
        assert normalize_supabase_mcp_response("load_approval_record", response) == {"kind": "transport_error"}

    def test_multiple_blocks_becomes_transport_error(self):
        one = _wrap_block(_BLOCK_UUID, "[]")
        other_uuid = "11111111-2222-3333-4444-555555555555"
        two = _wrap_block(other_uuid, "[]")
        response = {"result": one + "\n" + two}
        assert normalize_supabase_mcp_response("load_approval_record", response) == {"kind": "transport_error"}

    def test_mismatched_uuid_tags_becomes_transport_error(self):
        text = (
            f"<untrusted-data-{_BLOCK_UUID}>\n[]\n"
            f"</untrusted-data-11111111-2222-3333-4444-555555555555>"
        )
        response = {"result": text}
        assert normalize_supabase_mcp_response("load_approval_record", response) == {"kind": "transport_error"}

    def test_invalid_json_becomes_transport_error(self):
        response = {"result": _wrap_block(_BLOCK_UUID, "{not valid json")}
        assert normalize_supabase_mcp_response("load_approval_record", response) == {"kind": "transport_error"}

    def test_json_object_instead_of_array_becomes_transport_error(self):
        response = {"result": _wrap_block(_BLOCK_UUID, '{"id": 1}')}
        assert normalize_supabase_mcp_response("load_approval_record", response) == {"kind": "transport_error"}

    def test_non_mapping_row_becomes_transport_error(self):
        response = {"result": _wrap_block(_BLOCK_UUID, '["just a string"]')}
        assert normalize_supabase_mcp_response("load_approval_record", response) == {"kind": "transport_error"}

    def test_malformed_response_never_becomes_empty_rows(self):
        response = {"result": "garbage, no block"}
        result = normalize_supabase_mcp_response("load_approval_record", response)
        assert result != {"kind": "rows", "rows": []}
        assert result == {"kind": "transport_error"}


# ---------------------------------------------------------------------------
# normalize_supabase_mcp_response -- row and timestamp normalization
# ---------------------------------------------------------------------------


def _pg_row(**overrides) -> dict:
    row = {
        "id": "77777777-7777-7777-7777-777777777777",
        "investigation_id": "11111111-1111-1111-1111-111111111111",
        "action_type": "update_investigation_state",
        "action_payload": {"confidence": "high"},
        "requested_by": "analyst@example.com",
        "requested_at": "2026-01-01 00:00:00+00",
        "status": "pending",
        "approved_by": None,
        "approved_at": None,
        "rejected_by": None,
        "rejected_at": None,
        "rejection_reason": None,
        "expires_at": None,
        "consumed_by": None,
        "consumed_at": None,
        "created_at": "2026-01-01 00:00:00+00",
    }
    row.update(overrides)
    return row


class TestRowTimestampNormalization:
    def test_utc_offset_normalized_to_z(self):
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([_pg_row()]))}
        result = normalize_supabase_mcp_response("load_approval_record", response)
        row = result["rows"][0]
        assert row["requested_at"] == "2026-01-01T00:00:00Z"
        assert row["created_at"] == "2026-01-01T00:00:00Z"

    def test_nonzero_offset_converted_to_utc(self):
        row = _pg_row(requested_at="2026-01-01 05:30:00+05:30")
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}
        result = normalize_supabase_mcp_response("load_approval_record", response)
        assert result["rows"][0]["requested_at"] == "2026-01-01T00:00:00Z"

    def test_fractional_seconds_preserved(self):
        row = _pg_row(requested_at="2026-01-01 00:00:00.123456+00")
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}
        result = normalize_supabase_mcp_response("load_approval_record", response)
        assert result["rows"][0]["requested_at"] == "2026-01-01T00:00:00.123456Z"

    def test_four_digit_offset_without_colon(self):
        row = _pg_row(requested_at="2026-01-01 00:00:00+0530")
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}
        result = normalize_supabase_mcp_response("load_approval_record", response)
        assert result["rows"][0]["requested_at"] == "2025-12-31T18:30:00Z"

    def test_naive_timestamp_becomes_transport_error(self):
        row = _pg_row(requested_at="2026-01-01 00:00:00")
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}
        assert normalize_supabase_mcp_response("load_approval_record", response) == {"kind": "transport_error"}

    def test_malformed_timestamp_becomes_transport_error(self):
        row = _pg_row(requested_at="2026-13-01 00:00:00+00")
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}
        assert normalize_supabase_mcp_response("load_approval_record", response) == {"kind": "transport_error"}

    def test_non_string_timestamp_becomes_transport_error(self):
        row = _pg_row(requested_at=12345)
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}
        assert normalize_supabase_mcp_response("load_approval_record", response) == {"kind": "transport_error"}

    def test_null_timestamp_field_passes_through_as_null(self):
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([_pg_row()]))}
        result = normalize_supabase_mcp_response("load_approval_record", response)
        assert result["rows"][0]["approved_at"] is None

    def test_multi_row_order_preserved(self):
        rows = [
            _pg_row(id="a1111111-1111-1111-1111-111111111111", requested_at="2026-01-01 00:00:00+00"),
            _pg_row(id="a2222222-2222-2222-2222-222222222222", requested_at="2026-01-02 00:00:00+00"),
        ]
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps(rows))}
        result = normalize_supabase_mcp_response("load_approval_record", response)
        assert [row["id"] for row in result["rows"]] == [rows[0]["id"], rows[1]["id"]]
        assert result["rows"][0]["requested_at"] == "2026-01-01T00:00:00Z"
        assert result["rows"][1]["requested_at"] == "2026-01-02T00:00:00Z"


class TestOperationAwareNormalization:
    def test_insert_operation_only_touches_its_own_fields(self):
        row = _pg_row(approved_at="not a real timestamp at all")
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}
        result = normalize_supabase_mcp_response("insert_pending_approval", response)
        assert result["kind"] == "rows"
        assert result["rows"][0]["approved_at"] == "not a real timestamp at all"

    def test_load_operation_normalizes_approved_at(self):
        row = _pg_row(status="approved", approved_by="reviewer@example.com", approved_at="2026-01-01 00:00:00+00")
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}
        result = normalize_supabase_mcp_response("load_approval_record", response)
        assert result["rows"][0]["approved_at"] == "2026-01-01T00:00:00Z"

    def test_consumption_operation_normalizes_investigation_updated_at(self):
        row = _pg_row(
            status="consumed",
            consumed_by="system",
            consumed_at="2026-01-01 00:00:00+00",
        )
        row["investigation_status"] = "resolved"
        row["investigation_confidence"] = "0.87"
        row["investigation_updated_at"] = "2026-01-01 00:05:00+00"
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}
        result = normalize_supabase_mcp_response("apply_approval_consumption", response)
        normalized_row = result["rows"][0]
        assert normalized_row["investigation_updated_at"] == "2026-01-01T00:05:00Z"
        assert normalized_row["investigation_status"] == "resolved"
        assert normalized_row["investigation_confidence"] == "0.87"

    def test_review_transition_operation_normalizes_rejected_at(self):
        row = _pg_row(
            status="rejected",
            rejected_by="reviewer@example.com",
            rejected_at="2026-01-01 00:00:00+00",
            rejection_reason="insufficient evidence",
        )
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}
        result = normalize_supabase_mcp_response("apply_approval_review_transition", response)
        assert result["rows"][0]["rejected_at"] == "2026-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# Preservation of non-timestamp field types
# ---------------------------------------------------------------------------


class TestFieldPreservation:
    def test_jsonb_object_preserved_as_native_mapping(self):
        row = _pg_row(action_payload={"confidence": "high", "nested": {"a": 1}})
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}
        result = normalize_supabase_mcp_response("load_approval_record", response)
        assert result["rows"][0]["action_payload"] == {"confidence": "high", "nested": {"a": 1}}

    def test_unicode_text_field_preserved(self):
        row = _pg_row(rejection_reason="café evidence insuffisante")
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row], ensure_ascii=False))}
        result = normalize_supabase_mcp_response("load_approval_record", response)
        assert result["rows"][0]["rejection_reason"] == "café evidence insuffisante"

    def test_null_field_preserved(self):
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([_pg_row()]))}
        result = normalize_supabase_mcp_response("load_approval_record", response)
        assert result["rows"][0]["rejection_reason"] is None

    def test_unknown_extra_field_preserved_untouched(self):
        row = _pg_row()
        row["unexpected_future_field"] = "some value"
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}
        result = normalize_supabase_mcp_response("load_approval_record", response)
        assert result["rows"][0]["unexpected_future_field"] == "some value"


# ---------------------------------------------------------------------------
# Non-mutation and independence
# ---------------------------------------------------------------------------


class TestNormalizeNonMutation:
    def test_tool_response_not_mutated(self):
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([_pg_row()]))}
        before = copy.deepcopy(response)
        normalize_supabase_mcp_response("load_approval_record", response)
        assert response == before

    def test_returned_row_is_independent_copy(self):
        row = _pg_row(action_payload={"confidence": "high"})
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}
        result = normalize_supabase_mcp_response("load_approval_record", response)
        result["rows"][0]["action_payload"]["confidence"] = "mutated"
        # Re-normalize from a fresh, untouched response to prove independence.
        response_again = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}
        result_again = normalize_supabase_mcp_response("load_approval_record", response_again)
        assert result_again["rows"][0]["action_payload"]["confidence"] == "high"

    def test_two_calls_do_not_share_row_objects(self):
        row = _pg_row()
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}
        first = normalize_supabase_mcp_response("load_approval_record", response)
        second = normalize_supabase_mcp_response("load_approval_record", response)
        assert first["rows"][0] is not second["rows"][0]


# ---------------------------------------------------------------------------
# Block 6, Step 4: fixed templates for risk-aware operations
# ---------------------------------------------------------------------------


class TestBlock6RiskAwareTemplates:
    # 1. Fixed risk-aware approval INSERT SQL (both without and with
    # expires_at -- one descriptor shape, one test).
    def test_exact_risk_aware_insert_sql(self):
        result = prepare_supabase_mcp_call(_risk_aware_insert_descriptor(with_expires_at=False))
        expected_without_expiry = (
            "INSERT INTO public.approvals "
            "(investigation_id, action_type, action_payload, requested_by, requested_at, status, "
            "risk_level, required_approvals, requested_by_normalized) "
            "VALUES ("
            "'11111111-1111-1111-1111-111111111111'::uuid, "
            "'update_investigation_state', "
            "'{\"confidence\":\"high\",\"status\":\"escalated\"}'::jsonb, "
            "'analyst@example.com', "
            "'2026-01-01T00:00:00Z'::timestamptz, "
            "'pending', "
            "'high', "
            "2, "
            "'analyst@example.com') "
            "RETURNING " + _RISK_AWARE_RETURNING_TEXT + ";"
        )
        assert result["arguments"]["query"] == expected_without_expiry

        result_with_expiry = prepare_supabase_mcp_call(_risk_aware_insert_descriptor(with_expires_at=True))
        expected_with_expiry = (
            "INSERT INTO public.approvals "
            "(investigation_id, action_type, action_payload, requested_by, requested_at, status, "
            "risk_level, required_approvals, requested_by_normalized, expires_at) "
            "VALUES ("
            "'11111111-1111-1111-1111-111111111111'::uuid, "
            "'update_investigation_state', "
            "'{\"confidence\":\"high\",\"status\":\"escalated\"}'::jsonb, "
            "'analyst@example.com', "
            "'2026-01-01T00:00:00Z'::timestamptz, "
            "'pending', "
            "'high', "
            "2, "
            "'analyst@example.com', "
            "'2026-01-02T00:00:00Z'::timestamptz) "
            "RETURNING " + _RISK_AWARE_RETURNING_TEXT + ";"
        )
        assert result_with_expiry["arguments"]["query"] == expected_with_expiry

    # 2. Fixed risk-aware approval SELECT SQL.
    def test_exact_risk_aware_select_sql(self):
        result = prepare_supabase_mcp_call(_risk_aware_select_descriptor())
        expected = (
            "SELECT " + _RISK_AWARE_RETURNING_TEXT + " FROM public.approvals "
            "WHERE id = '22222222-2222-2222-2222-222222222222'::uuid LIMIT 2;"
        )
        assert result["arguments"]["query"] == expected

    # 3. Fixed ordered approval-review SELECT SQL.
    def test_exact_ordered_review_select_sql(self):
        result = prepare_supabase_mcp_call(_review_select_descriptor())
        expected = (
            "SELECT " + _REVIEW_LOOKUP_TEXT + " FROM public.approval_reviews "
            "WHERE approval_id = '33333333-3333-3333-3333-333333333333'::uuid "
            "ORDER BY decided_at LIMIT 10;"
        )
        assert result["arguments"]["query"] == expected

    # 4. Fixed record_approval_review_and_promote_status RPC SQL (both
    # the approve and reject shapes -- one descriptor family, one test).
    def test_exact_review_rpc_sql(self):
        result = prepare_supabase_mcp_call(_review_rpc_descriptor(decision="approve"))
        expected_approve = (
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
        assert result["arguments"]["query"] == expected_approve

        reject_descriptor = _review_rpc_descriptor(decision="reject", rejection_reason="insufficient evidence")
        reject_result = prepare_supabase_mcp_call(reject_descriptor)
        expected_reject = (
            "SELECT * FROM public.record_approval_review_and_promote_status("
            "'55555555-5555-5555-5555-555555555555'::uuid, "
            "'pending', "
            "'rejected', "
            "2, "
            "0, "
            "'reviewer@example.com', "
            "'reviewer@example.com', "
            "'reject', "
            "'2026-01-01T03:00:00Z'::timestamptz, "
            "'insufficient evidence');"
        )
        assert reject_result["arguments"]["query"] == expected_reject

    # 5. Exact escaping and canonical timestamp/JSON encoding.
    def test_exact_escaping_and_canonicalization(self):
        # Single-quote escaping in a Block 6 rejection_reason value passed
        # through the new nullable_text encoder.
        escaped_descriptor = _review_rpc_descriptor(decision="reject", rejection_reason="reviewer's concern")
        escaped_result = prepare_supabase_mcp_call(escaped_descriptor)
        assert "'reviewer''s concern'" in escaped_result["arguments"]["query"]

        # NULL literal (not the string "None" or an empty string) for an
        # absent rejection_reason on an approve descriptor.
        approve_result = prepare_supabase_mcp_call(_review_rpc_descriptor(decision="approve"))
        assert approve_result["arguments"]["query"].endswith("NULL);")

        # Canonical timestamp round trip on the risk-aware insert path.
        insert_result = prepare_supabase_mcp_call(_risk_aware_insert_descriptor())
        assert "'2026-01-01T00:00:00Z'::timestamptz" in insert_result["arguments"]["query"]

    # 6. Forged or unknown descriptors rejected, across every Block 6
    # descriptor shape.
    def test_forged_or_unknown_descriptors_rejected(self):
        forged_insert = _risk_aware_insert_descriptor()
        forged_insert["values"].pop("risk_level")
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(forged_insert)

        forged_select = _risk_aware_select_descriptor()
        forged_select["columns"] = list(_RISK_AWARE_RECORD_FIELDS)[::-1]
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(forged_select)

        forged_review_select = _review_select_descriptor()
        forged_review_select["table"] = "approvals"
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(forged_review_select)

        unknown_function_rpc = _review_rpc_descriptor()
        unknown_function_rpc["function"] = "some_other_function"
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(unknown_function_rpc)

        forged_rpc_params = _review_rpc_descriptor()
        forged_rpc_params["parameters"]["extra"] = 1
        with pytest.raises(ApprovalMcpAdapterError):
            prepare_supabase_mcp_call(forged_rpc_params)


class TestBlock6ReviewRpcResultNormalization:
    def _review_rpc_row(self, **overrides) -> dict:
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
        row.update(overrides)
        return row

    # 7. Twenty-four-field successful response normalization.
    def test_twenty_four_field_success_normalization(self):
        row = self._review_rpc_row()
        assert len(row) == 24
        response = {"result": _wrap_block(_BLOCK_UUID, json.dumps([row]))}

        result = normalize_supabase_mcp_response("apply_multi_review_transition", response)

        assert result["kind"] == "rows"
        normalized_row = result["rows"][0]
        assert normalized_row["requested_at"] == "2026-01-01T00:00:00Z"
        assert normalized_row["review_decided_at"] == "2026-01-01T03:00:00Z"
        assert normalized_row["approval_count"] == 1
        assert normalized_row["risk_level"] == "high"

    # 8. Zero-row and transport-error normalization, for both the review
    # RPC and the ordered review lookup.
    def test_zero_row_and_transport_error_normalization(self):
        zero_row_response = {"result": _wrap_block(_BLOCK_UUID, "[]")}
        assert normalize_supabase_mcp_response("apply_multi_review_transition", zero_row_response) == {
            "kind": "rows", "rows": [],
        }

        transport_error_response = {"error": {"name": "HttpException", "message": "raw postgres text"}}
        assert normalize_supabase_mcp_response("apply_multi_review_transition", transport_error_response) == {
            "kind": "transport_error",
        }

        assert normalize_supabase_mcp_response("load_approval_reviews", zero_row_response) == {
            "kind": "rows", "rows": [],
        }
        assert normalize_supabase_mcp_response("load_approval_reviews", transport_error_response) == {
            "kind": "transport_error",
        }
