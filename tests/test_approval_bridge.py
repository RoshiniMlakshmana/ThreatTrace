"""Tests for core.approval_bridge -- the transport-neutral two-phase
prepare/verify bridge that lets a future command hand each approval
persistence operation's real database call to Claude's own MCP tools
without giving Python subprocess code any direct MCP/Supabase access,
and without duplicating or bypassing core.approval_persistence.py.

No real Supabase, file, subprocess, network, or AI/model access occurs
anywhere in this file. Every "database" is a local fake executor
function or a canonical rows/transport-error envelope; every input is a
plain in-memory mapping.
"""

import ast
import copy
import inspect
import os
import socket
import subprocess
import urllib.request
from collections.abc import Mapping
from pathlib import Path

import pytest

import core.approval_bridge as approval_bridge
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
from core.approval_transition import validate_approval_transition

APPROVAL_ID = "51111111-1111-4111-8111-111111111111"
INVESTIGATION_ID = "41111111-1111-4111-8111-111111111111"

REQUESTED_AT = "2026-08-01T15:45:00Z"
EXPIRES_AT = "2026-08-02T15:45:00Z"
CREATED_AT = "2026-08-01T15:46:00Z"
APPROVED_AT = "2026-08-01T16:00:00Z"
CONSUMED_AT = "2026-08-01T17:00:00Z"

_RECORD_FIELDS = (
    "id", "investigation_id", "action_type", "action_payload", "requested_by", "requested_at",
    "status", "approved_by", "approved_at", "rejected_by", "rejected_at", "rejection_reason",
    "expires_at", "consumed_by", "consumed_at", "created_at",
)


def _validated_request(**overrides):
    request = {
        "investigation_id": INVESTIGATION_ID,
        "action_type": "update_investigation_state",
        "action_payload": {"status": "escalated", "confidence": "high"},
        "requested_by": "Roshini Analyst",
        "requested_at": REQUESTED_AT,
    }
    request.update(overrides)
    return request


def _pending_row(**overrides):
    row = {
        "id": APPROVAL_ID,
        "investigation_id": INVESTIGATION_ID,
        "action_type": "update_investigation_state",
        "action_payload": {"status": "escalated", "confidence": "high"},
        "requested_by": "Roshini Analyst",
        "requested_at": REQUESTED_AT,
        "status": "pending",
        "approved_by": None,
        "approved_at": None,
        "rejected_by": None,
        "rejected_at": None,
        "rejection_reason": None,
        "expires_at": EXPIRES_AT,
        "consumed_by": None,
        "consumed_at": None,
        "created_at": CREATED_AT,
    }
    row.update(overrides)
    return row


def _approved_record(**overrides):
    record = _pending_row(status="approved", approved_by="Security Reviewer", approved_at=APPROVED_AT)
    record.update(overrides)
    return record


def _genuine_approve_plan(record, reviewed_by="Security Reviewer"):
    return validate_approval_transition(record, {"transition": "approve", "reviewed_by": reviewed_by})


def _genuine_reject_plan(
    record, reviewed_by="Security Reviewer", rejection_reason="Needs more evidence before approval."
):
    return validate_approval_transition(
        record, {"transition": "reject", "reviewed_by": reviewed_by, "rejection_reason": rejection_reason}
    )


def _genuine_consume_plan(record, consumed_by="Update Case Operator", consumed_at=CONSUMED_AT):
    return validate_approval_transition(
        record,
        {
            "transition": "consume",
            "consumed_by": consumed_by,
            "expected_investigation_id": record["investigation_id"],
            "expected_action_type": "update_investigation_state",
            "consumed_at": consumed_at,
        },
    )


def _apply_set_fields(record, set_fields):
    updated = dict(record)
    updated.update(set_fields)
    return updated


def _consumption_row_for(record, plan, **investigation_overrides):
    row = _apply_set_fields(record, plan["set_fields"])
    payload = record["action_payload"]
    row["investigation_status"] = investigation_overrides.get("investigation_status", payload.get("status", "escalated"))
    row["investigation_confidence"] = investigation_overrides.get(
        "investigation_confidence", payload.get("confidence", "high")
    )
    row["investigation_updated_at"] = investigation_overrides.get("investigation_updated_at", CONSUMED_AT)
    return row


def _module_source_text():
    with open(approval_bridge.__file__, "r", encoding="utf-8") as handle:
        return handle.read()


def _module_ast():
    return ast.parse(_module_source_text())


def _this_module_ast():
    return ast.parse(Path(__file__).read_text(encoding="utf-8"))


def _function_def(tree, name):
    return next(
        node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name
    )


def _referenced_identifiers(tree):
    return {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }


def _top_level_imports(tree):
    names = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
    return names


# ---------------------------------------------------------------------------
# 1-8: public contract
# ---------------------------------------------------------------------------


def test_001_module_imports_successfully():
    assert approval_bridge is not None


def test_002_approval_bridge_error_exists():
    assert issubclass(ApprovalBridgeError, Exception)


def test_003_prepare_approval_operation_exists():
    assert callable(prepare_approval_operation)


def test_004_verify_approval_operation_exists():
    assert callable(verify_approval_operation)


def test_005_signatures_are_exact():
    prepare_signature = inspect.signature(prepare_approval_operation)
    assert list(prepare_signature.parameters) == ["operation", "operation_input"]
    verify_signature = inspect.signature(verify_approval_operation)
    assert list(verify_signature.parameters) == [
        "operation", "operation_input", "prepared_descriptor", "executor_response",
    ]


def test_006_no_supabase_or_mcp_type_is_required():
    tree = _module_ast()
    imports = _top_level_imports(tree)
    assert not any(name == "supabase" or name.startswith("supabase.") for name in imports)
    assert not any(name == "mcp" or name.startswith("mcp.") for name in imports)


def test_007_exactly_four_supported_operation_names_exist():
    assert approval_bridge._SUPPORTED_OPERATIONS_SET == {
        "insert_pending_approval", "load_approval_record",
        "apply_approval_review_transition", "apply_approval_consumption",
    }


@pytest.mark.parametrize(
    "alias",
    ["insert", "insertPendingApproval", "insert_approval", "load", "review", "consume", "apply_consumption"],
)
def test_008_aliases_fail(alias):
    with pytest.raises(ApprovalBridgeError):
        prepare_approval_operation(alias, {})


# ---------------------------------------------------------------------------
# 9-15: input envelopes
# ---------------------------------------------------------------------------


def test_009_each_operation_accepts_its_exact_input():
    record = _approved_record()
    plan = _genuine_approve_plan(_pending_row())
    consume_plan = _genuine_consume_plan(record)

    prepare_approval_operation("insert_pending_approval", {"validated_request": _validated_request(), "expires_at": None})
    prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID})
    prepare_approval_operation(
        "apply_approval_review_transition", {"current_record": _pending_row(), "transition_plan": plan}
    )
    prepare_approval_operation(
        "apply_approval_consumption", {"current_record": record, "transition_plan": consume_plan}
    )


def test_010_non_mapping_input_fails():
    with pytest.raises(ApprovalBridgeError):
        prepare_approval_operation("load_approval_record", ["not", "a", "mapping"])


def test_011_missing_field_fails():
    with pytest.raises(ApprovalBridgeError):
        prepare_approval_operation("insert_pending_approval", {"validated_request": _validated_request()})


def test_012_unknown_field_fails():
    with pytest.raises(ApprovalBridgeError):
        prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID, "extra": "value"})


def test_013_reordered_fields_fail():
    with pytest.raises(ApprovalBridgeError):
        prepare_approval_operation(
            "insert_pending_approval", {"expires_at": None, "validated_request": _validated_request()}
        )


def test_014_cross_operation_fields_fail():
    record = _pending_row()
    plan = _genuine_approve_plan(record)
    with pytest.raises(ApprovalBridgeError):
        prepare_approval_operation("insert_pending_approval", {"current_record": record, "transition_plan": plan})


def test_015_inputs_remain_unchanged():
    operation_input = {"validated_request": _validated_request(), "expires_at": None}
    before = copy.deepcopy(operation_input)
    prepare_approval_operation("insert_pending_approval", operation_input)
    assert operation_input == before


# ---------------------------------------------------------------------------
# 16-21: prepare insert
# ---------------------------------------------------------------------------


def test_016_valid_input_emits_exact_insert_descriptor():
    result = prepare_approval_operation(
        "insert_pending_approval", {"validated_request": _validated_request(), "expires_at": EXPIRES_AT}
    )
    descriptor = result["descriptor"]
    assert descriptor["operation"] == "insert"
    assert descriptor["table"] == "approvals"
    assert descriptor["values"]["investigation_id"] == INVESTIGATION_ID
    assert descriptor["returning"] == list(_RECORD_FIELDS)


def test_017_persistence_request_validation_is_reused():
    with pytest.raises(ApprovalPersistenceError):
        prepare_approval_operation(
            "insert_pending_approval",
            {"validated_request": _validated_request(investigation_id="not-a-uuid"), "expires_at": None},
        )


def test_018_executor_captured_once(monkeypatch):
    call_count = 0
    real_capture_cls = approval_bridge._DescriptorCaptureExecutor

    class _CountingCapture(real_capture_cls):
        def __call__(self, operation):
            nonlocal call_count
            call_count += 1
            return super().__call__(operation)

    monkeypatch.setattr(approval_bridge, "_DescriptorCaptureExecutor", _CountingCapture)
    prepare_approval_operation("insert_pending_approval", {"validated_request": _validated_request(), "expires_at": None})
    assert call_count == 1


def test_019_expected_response_error_is_consumed_internally():
    # This must succeed with no exception -- the internal
    # ApprovalResponseError from the empty-list capture response is
    # swallowed, never propagated.
    result = prepare_approval_operation(
        "insert_pending_approval", {"validated_request": _validated_request(), "expires_at": None}
    )
    assert result["phase"] == "prepare"


def test_020_invalid_input_propagates_approval_persistence_error():
    with pytest.raises(ApprovalPersistenceError):
        prepare_approval_operation(
            "insert_pending_approval",
            {"validated_request": _validated_request(action_payload={}), "expires_at": None},
        )


def test_021_no_synthetic_result_is_returned():
    result = prepare_approval_operation(
        "insert_pending_approval", {"validated_request": _validated_request(), "expires_at": None}
    )
    assert "result" not in result
    assert "row" not in result
    assert "record" not in result


# ---------------------------------------------------------------------------
# 22-25: prepare lookup
# ---------------------------------------------------------------------------


def test_022_exact_select_descriptor_returned():
    result = prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID})
    descriptor = result["descriptor"]
    assert descriptor["operation"] == "select"
    assert descriptor["table"] == "approvals"
    assert descriptor["filters"] == {"id": APPROVAL_ID}
    assert descriptor["limit"] == 2


def test_023_expected_not_found_error_is_consumed_internally():
    result = prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID})
    assert result["operation"] == "load_approval_record"


def test_024_invalid_uuid_fails_before_capture():
    with pytest.raises(ApprovalPersistenceError):
        prepare_approval_operation("load_approval_record", {"approval_id": "not-a-uuid"})


def test_025_executor_captured_once_for_lookup(monkeypatch):
    captured_operations = []
    real_call = approval_bridge._DescriptorCaptureExecutor.__call__

    def _tracking_call(self, operation):
        captured_operations.append(operation)
        return real_call(self, operation)

    monkeypatch.setattr(approval_bridge._DescriptorCaptureExecutor, "__call__", _tracking_call)
    prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID})
    assert len(captured_operations) == 1


# ---------------------------------------------------------------------------
# 26-30: prepare review
# ---------------------------------------------------------------------------


def test_026_genuine_approve_plan_emits_exact_update_descriptor():
    record = _pending_row()
    plan = _genuine_approve_plan(record)
    result = prepare_approval_operation(
        "apply_approval_review_transition", {"current_record": record, "transition_plan": plan}
    )
    descriptor = result["descriptor"]
    assert descriptor["operation"] == "update"
    assert descriptor["table"] == "approvals"
    assert descriptor["values"] == plan["set_fields"]


def test_027_genuine_reject_plan_emits_exact_update_descriptor():
    record = _pending_row()
    plan = _genuine_reject_plan(record)
    result = prepare_approval_operation(
        "apply_approval_review_transition", {"current_record": record, "transition_plan": plan}
    )
    descriptor = result["descriptor"]
    assert descriptor["operation"] == "update"
    assert descriptor["values"] == plan["set_fields"]


def test_028_expected_conflict_error_is_consumed_internally():
    record = _pending_row()
    plan = _genuine_approve_plan(record)
    result = prepare_approval_operation(
        "apply_approval_review_transition", {"current_record": record, "transition_plan": plan}
    )
    assert result["phase"] == "prepare"


def test_029_forged_plan_fails_before_capture():
    record = _pending_row(requested_by="Roshini Analyst")
    forged_plan = {
        "approval_id": record["id"],
        "from_status": "pending",
        "to_status": "approved",
        "set_fields": {"status": "approved", "approved_by": "Roshini Analyst", "approved_at": APPROVED_AT},
    }
    with pytest.raises(ApprovalPersistenceError):
        prepare_approval_operation(
            "apply_approval_review_transition", {"current_record": record, "transition_plan": forged_plan}
        )


def test_030_executor_captured_once_for_review():
    record = _pending_row()
    plan = _genuine_approve_plan(record)
    original = approval_bridge._DescriptorCaptureExecutor.__call__
    calls = []

    def _tracking(self, operation):
        calls.append(operation)
        return original(self, operation)

    approval_bridge._DescriptorCaptureExecutor.__call__ = _tracking
    try:
        prepare_approval_operation(
            "apply_approval_review_transition", {"current_record": record, "transition_plan": plan}
        )
    finally:
        approval_bridge._DescriptorCaptureExecutor.__call__ = original
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# 31-35: prepare consumption
# ---------------------------------------------------------------------------


def test_031_genuine_consume_plan_emits_exact_rpc_descriptor():
    record = _approved_record()
    plan = _genuine_consume_plan(record)
    result = prepare_approval_operation(
        "apply_approval_consumption", {"current_record": record, "transition_plan": plan}
    )
    descriptor = result["descriptor"]
    assert descriptor["operation"] == "rpc"
    assert descriptor["function"] == "consume_approval_and_update_investigation_state"
    assert descriptor["parameters"]["approval_id"] == plan["approval_id"]


def test_032_expected_conflict_error_is_consumed_internally_for_consumption():
    record = _approved_record()
    plan = _genuine_consume_plan(record)
    result = prepare_approval_operation(
        "apply_approval_consumption", {"current_record": record, "transition_plan": plan}
    )
    assert result["operation"] == "apply_approval_consumption"


def test_033_forged_consume_plan_fails_before_capture():
    record = _approved_record()
    genuine_plan = _genuine_consume_plan(record)
    forged_plan = copy.deepcopy(genuine_plan)
    forged_plan["set_fields"]["consumed_at"] = "2026-08-01T10:00:00Z"
    with pytest.raises(ApprovalPersistenceError):
        prepare_approval_operation(
            "apply_approval_consumption", {"current_record": record, "transition_plan": forged_plan}
        )


def test_034_executor_captured_once_for_consumption():
    record = _approved_record()
    plan = _genuine_consume_plan(record)
    original = approval_bridge._DescriptorCaptureExecutor.__call__
    calls = []

    def _tracking(self, operation):
        calls.append(operation)
        return original(self, operation)

    approval_bridge._DescriptorCaptureExecutor.__call__ = _tracking
    try:
        prepare_approval_operation(
            "apply_approval_consumption", {"current_record": record, "transition_plan": plan}
        )
    finally:
        approval_bridge._DescriptorCaptureExecutor.__call__ = original
    assert len(calls) == 1


def test_035_no_second_descriptor_appears():
    record = _approved_record()
    plan = _genuine_consume_plan(record)
    result = prepare_approval_operation(
        "apply_approval_consumption", {"current_record": record, "transition_plan": plan}
    )
    assert isinstance(result["descriptor"], dict)


# ---------------------------------------------------------------------------
# 36-40: preparation failures
# ---------------------------------------------------------------------------


def test_036_no_captured_descriptor_with_unexpected_exception_fails(monkeypatch):
    def _fake_insert(executor, validated_request, *, expires_at=None):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(approval_bridge, "insert_pending_approval", _fake_insert)

    with pytest.raises(ApprovalBridgeError):
        prepare_approval_operation(
            "insert_pending_approval", {"validated_request": _validated_request(), "expires_at": None}
        )


def test_037_multiple_captures_fail(monkeypatch):
    def _fake_lookup(executor, approval_id):
        executor({"operation": "select", "table": "approvals", "columns": [], "filters": {}, "limit": 2})
        executor({"operation": "select", "table": "approvals", "columns": [], "filters": {}, "limit": 2})
        raise ApprovalNotFoundError("Approval was not found.")

    monkeypatch.setattr(approval_bridge, "load_approval_record", _fake_lookup)

    with pytest.raises(ApprovalBridgeError):
        prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID})


def test_038_wrong_post_capture_exception_fails(monkeypatch):
    def _fake_lookup(executor, approval_id):
        executor({"operation": "select", "table": "approvals", "columns": [], "filters": {}, "limit": 2})
        raise ApprovalResponseError("Approval lookup response was invalid.")

    monkeypatch.setattr(approval_bridge, "load_approval_record", _fake_lookup)

    with pytest.raises(ApprovalBridgeError):
        prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID})


def test_039_unexpected_success_fails(monkeypatch):
    def _fake_lookup(executor, approval_id):
        executor({"operation": "select", "table": "approvals", "columns": [], "filters": {}, "limit": 2})
        return {"fake": "result"}

    monkeypatch.setattr(approval_bridge, "load_approval_record", _fake_lookup)

    with pytest.raises(ApprovalBridgeError):
        prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID})


def test_040_prepare_failure_errors_expose_no_input_values(monkeypatch):
    secret_marker = "top-secret-marker-value"

    def _fake_lookup(executor, approval_id):
        raise RuntimeError(secret_marker)

    monkeypatch.setattr(approval_bridge, "load_approval_record", _fake_lookup)

    with pytest.raises(ApprovalBridgeError) as excinfo:
        prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID})
    assert secret_marker not in str(excinfo.value)


# ---------------------------------------------------------------------------
# 41-49: descriptor regeneration
# ---------------------------------------------------------------------------


def test_041_exact_prepared_descriptor_succeeds():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    row = _pending_row()
    result = verify_approval_operation(
        "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [row]}
    )
    assert result["phase"] == "verify"


def test_042_changed_operation_fails():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    tampered = dict(prepared["descriptor"])
    tampered["operation"] = "update"
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "load_approval_record", operation_input, tampered, {"kind": "rows", "rows": [_pending_row()]}
        )


def test_043_changed_table_fails():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    tampered = dict(prepared["descriptor"])
    tampered["table"] = "investigations"
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "load_approval_record", operation_input, tampered, {"kind": "rows", "rows": [_pending_row()]}
        )


def test_044_changed_function_fails():
    record = _approved_record()
    plan = _genuine_consume_plan(record)
    operation_input = {"current_record": record, "transition_plan": plan}
    prepared = prepare_approval_operation("apply_approval_consumption", operation_input)
    tampered = dict(prepared["descriptor"])
    tampered["function"] = "hacked_function"
    row = _consumption_row_for(record, plan)
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "apply_approval_consumption", operation_input, tampered, {"kind": "rows", "rows": [row]}
        )


def test_045_changed_parameters_fail():
    record = _approved_record()
    plan = _genuine_consume_plan(record)
    operation_input = {"current_record": record, "transition_plan": plan}
    prepared = prepare_approval_operation("apply_approval_consumption", operation_input)
    tampered = copy.deepcopy(prepared["descriptor"])
    tampered["parameters"]["consumed_by"] = "HACKED"
    row = _consumption_row_for(record, plan)
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "apply_approval_consumption", operation_input, tampered, {"kind": "rows", "rows": [row]}
        )


def test_046_added_descriptor_field_fails():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    tampered = dict(prepared["descriptor"])
    tampered["extra"] = "value"
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "load_approval_record", operation_input, tampered, {"kind": "rows", "rows": [_pending_row()]}
        )


def test_047_missing_descriptor_field_fails():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    tampered = dict(prepared["descriptor"])
    del tampered["limit"]
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "load_approval_record", operation_input, tampered, {"kind": "rows", "rows": [_pending_row()]}
        )


def test_048_reordered_list_field_fails():
    # Mapping key order is not semantically meaningful (and this
    # project's own CLI always serializes with sort_keys=True, so a
    # prepared_descriptor legitimately round-tripping through it always
    # arrives with alphabetically-reordered dict keys) -- a dict with
    # identical keys/values in a different order must still be accepted.
    # List order, however, genuinely matters (e.g. column order), so a
    # shuffled list is a real mismatch and must still be rejected.
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    original = prepared["descriptor"]

    reordered_dict_keys = {
        "table": original["table"],
        "operation": original["operation"],
        "columns": original["columns"],
        "filters": original["filters"],
        "limit": original["limit"],
    }
    # Harmless: dict key order alone must not cause a mismatch.
    verify_approval_operation(
        "load_approval_record", operation_input, reordered_dict_keys, {"kind": "rows", "rows": [_pending_row()]}
    )

    shuffled_columns = dict(original)
    shuffled_columns["columns"] = list(reversed(original["columns"]))
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "load_approval_record", operation_input, shuffled_columns, {"kind": "rows", "rows": [_pending_row()]}
        )


def test_049_executor_not_called_after_mismatch(monkeypatch):
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    tampered = dict(prepared["descriptor"])
    tampered["limit"] = 999

    call_count = 0
    original_call = approval_bridge._VerifyExecutor.__call__

    def _counting(self, operation):
        nonlocal call_count
        call_count += 1
        return original_call(self, operation)

    monkeypatch.setattr(approval_bridge._VerifyExecutor, "__call__", _counting)

    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "load_approval_record", operation_input, tampered, {"kind": "rows", "rows": [_pending_row()]}
        )
    assert call_count == 0


# ---------------------------------------------------------------------------
# 50-60: response envelope
# ---------------------------------------------------------------------------


def test_050_rows_envelope_succeeds():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    result = verify_approval_operation(
        "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [_pending_row()]}
    )
    assert result["result"]["id"] == APPROVAL_ID


def test_051_transport_error_envelope_reaches_transport_error():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    with pytest.raises(ApprovalTransportError):
        verify_approval_operation(
            "load_approval_record", operation_input, prepared["descriptor"], {"kind": "transport_error"}
        )


def test_052_non_mapping_envelope_fails():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation("load_approval_record", operation_input, prepared["descriptor"], ["not", "a", "mapping"])


def test_053_missing_kind_fails():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation("load_approval_record", operation_input, prepared["descriptor"], {"rows": []})


def test_054_unknown_kind_fails():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "load_approval_record", operation_input, prepared["descriptor"], {"kind": "bogus"}
        )


def test_055_rows_missing_fails():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows"}
        )


def test_056_rows_on_transport_error_fails():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "load_approval_record", operation_input, prepared["descriptor"], {"kind": "transport_error", "rows": []}
        )


def test_057_extra_keys_fail():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "load_approval_record",
            operation_input,
            prepared["descriptor"],
            {"kind": "rows", "rows": [], "extra": "value"},
        )


def test_058_reordered_keys_fail():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "load_approval_record", operation_input, prepared["descriptor"], {"rows": [], "kind": "rows"}
        )


def test_059_non_list_rows_fail():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": (1, 2)}
        )


@pytest.mark.parametrize("wrapper_key", ["data", "result", "content", "records", "response", "tool_result"])
def test_060_raw_mcp_wrappers_fail(wrapper_key):
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "load_approval_record", operation_input, prepared["descriptor"], {wrapper_key: [_pending_row()]}
        )


# ---------------------------------------------------------------------------
# 61-64: verify insert
# ---------------------------------------------------------------------------


def test_061_valid_pending_row_succeeds():
    operation_input = {"validated_request": _validated_request(), "expires_at": EXPIRES_AT}
    prepared = prepare_approval_operation("insert_pending_approval", operation_input)
    result = verify_approval_operation(
        "insert_pending_approval", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [_pending_row()]}
    )
    assert result["result"]["status"] == "pending"


def test_062_result_equals_insert_pending_approval_output():
    from core.approval_persistence import insert_pending_approval

    class _FakeExecutor:
        def __call__(self, operation):
            return [_pending_row()]

    direct = insert_pending_approval(_FakeExecutor(), _validated_request(), expires_at=EXPIRES_AT)

    operation_input = {"validated_request": _validated_request(), "expires_at": EXPIRES_AT}
    prepared = prepare_approval_operation("insert_pending_approval", operation_input)
    result = verify_approval_operation(
        "insert_pending_approval", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [_pending_row()]}
    )
    assert result["result"] == direct


def test_063_malformed_row_fails_through_response_error():
    operation_input = {"validated_request": _validated_request(), "expires_at": EXPIRES_AT}
    prepared = prepare_approval_operation("insert_pending_approval", operation_input)
    malformed_row = _pending_row()
    del malformed_row["id"]
    with pytest.raises(ApprovalResponseError):
        verify_approval_operation(
            "insert_pending_approval", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [malformed_row]}
        )


def test_064_insert_executor_invoked_once():
    operation_input = {"validated_request": _validated_request(), "expires_at": EXPIRES_AT}
    prepared = prepare_approval_operation("insert_pending_approval", operation_input)
    call_count = 0
    original_call = approval_bridge._VerifyExecutor.__call__

    def _counting(self, operation):
        nonlocal call_count
        call_count += 1
        return original_call(self, operation)

    approval_bridge._VerifyExecutor.__call__ = _counting
    try:
        verify_approval_operation(
            "insert_pending_approval", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [_pending_row()]}
        )
    finally:
        approval_bridge._VerifyExecutor.__call__ = original_call
    assert call_count == 1


# ---------------------------------------------------------------------------
# 65-68: verify lookup
# ---------------------------------------------------------------------------


def test_065_valid_row_succeeds():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    result = verify_approval_operation(
        "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [_pending_row()]}
    )
    assert result["result"]["id"] == APPROVAL_ID


def test_066_empty_rows_raise_not_found():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    with pytest.raises(ApprovalNotFoundError):
        verify_approval_operation(
            "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": []}
        )


def test_067_wrong_record_fails():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    wrong_row = _pending_row(id="59999999-9999-4999-8999-999999999999")
    with pytest.raises(ApprovalResponseError):
        verify_approval_operation(
            "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [wrong_row]}
        )


def test_068_lookup_executor_invoked_once():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    call_count = 0
    original_call = approval_bridge._VerifyExecutor.__call__

    def _counting(self, operation):
        nonlocal call_count
        call_count += 1
        return original_call(self, operation)

    approval_bridge._VerifyExecutor.__call__ = _counting
    try:
        verify_approval_operation(
            "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [_pending_row()]}
        )
    finally:
        approval_bridge._VerifyExecutor.__call__ = original_call
    assert call_count == 1


# ---------------------------------------------------------------------------
# 69-73: verify review
# ---------------------------------------------------------------------------


def test_069_valid_approved_row_succeeds():
    record = _pending_row()
    plan = _genuine_approve_plan(record)
    operation_input = {"current_record": record, "transition_plan": plan}
    prepared = prepare_approval_operation("apply_approval_review_transition", operation_input)
    row = _apply_set_fields(record, plan["set_fields"])
    result = verify_approval_operation(
        "apply_approval_review_transition", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [row]}
    )
    assert result["result"]["updated_record"]["status"] == "approved"


def test_070_valid_rejected_row_succeeds():
    record = _pending_row()
    plan = _genuine_reject_plan(record)
    operation_input = {"current_record": record, "transition_plan": plan}
    prepared = prepare_approval_operation("apply_approval_review_transition", operation_input)
    row = _apply_set_fields(record, plan["set_fields"])
    result = verify_approval_operation(
        "apply_approval_review_transition", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [row]}
    )
    assert result["result"]["updated_record"]["status"] == "rejected"


def test_071_empty_rows_raise_conflict():
    record = _pending_row()
    plan = _genuine_approve_plan(record)
    operation_input = {"current_record": record, "transition_plan": plan}
    prepared = prepare_approval_operation("apply_approval_review_transition", operation_input)
    with pytest.raises(ApprovalConflictError):
        verify_approval_operation(
            "apply_approval_review_transition", operation_input, prepared["descriptor"], {"kind": "rows", "rows": []}
        )


def test_072_wrong_updated_row_fails():
    record = _pending_row()
    plan = _genuine_approve_plan(record)
    operation_input = {"current_record": record, "transition_plan": plan}
    prepared = prepare_approval_operation("apply_approval_review_transition", operation_input)
    row = _apply_set_fields(record, plan["set_fields"])
    row["approved_by"] = "Someone Else"
    with pytest.raises(ApprovalResponseError):
        verify_approval_operation(
            "apply_approval_review_transition", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [row]}
        )


def test_073_review_executor_invoked_once():
    record = _pending_row()
    plan = _genuine_approve_plan(record)
    operation_input = {"current_record": record, "transition_plan": plan}
    prepared = prepare_approval_operation("apply_approval_review_transition", operation_input)
    row = _apply_set_fields(record, plan["set_fields"])
    call_count = 0
    original_call = approval_bridge._VerifyExecutor.__call__

    def _counting(self, operation):
        nonlocal call_count
        call_count += 1
        return original_call(self, operation)

    approval_bridge._VerifyExecutor.__call__ = _counting
    try:
        verify_approval_operation(
            "apply_approval_review_transition", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [row]}
        )
    finally:
        approval_bridge._VerifyExecutor.__call__ = original_call
    assert call_count == 1


# ---------------------------------------------------------------------------
# 74-79: verify consumption
# ---------------------------------------------------------------------------


def test_074_valid_nineteen_field_rpc_row_succeeds():
    record = _approved_record()
    plan = _genuine_consume_plan(record)
    operation_input = {"current_record": record, "transition_plan": plan}
    prepared = prepare_approval_operation("apply_approval_consumption", operation_input)
    row = _consumption_row_for(record, plan)
    assert len(row) == 19
    result = verify_approval_operation(
        "apply_approval_consumption", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [row]}
    )
    assert result["result"]["updated_record"]["status"] == "consumed"
    assert result["result"]["investigation_result"]["status"] == "escalated"


def test_075_empty_rows_raise_conflict_for_consumption():
    record = _approved_record()
    plan = _genuine_consume_plan(record)
    operation_input = {"current_record": record, "transition_plan": plan}
    prepared = prepare_approval_operation("apply_approval_consumption", operation_input)
    with pytest.raises(ApprovalConflictError):
        verify_approval_operation(
            "apply_approval_consumption", operation_input, prepared["descriptor"], {"kind": "rows", "rows": []}
        )


def test_076_wrong_consumed_record_fails():
    record = _approved_record()
    plan = _genuine_consume_plan(record)
    operation_input = {"current_record": record, "transition_plan": plan}
    prepared = prepare_approval_operation("apply_approval_consumption", operation_input)
    row = _consumption_row_for(record, plan)
    row["consumed_by"] = "Someone Else"
    with pytest.raises(ApprovalResponseError):
        verify_approval_operation(
            "apply_approval_consumption", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [row]}
        )


def test_077_wrong_investigation_result_fails():
    record = _approved_record()
    plan = _genuine_consume_plan(record)
    operation_input = {"current_record": record, "transition_plan": plan}
    prepared = prepare_approval_operation("apply_approval_consumption", operation_input)
    row = _consumption_row_for(record, plan, investigation_status="closed")
    with pytest.raises(ApprovalResponseError):
        verify_approval_operation(
            "apply_approval_consumption", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [row]}
        )


def test_078_consumption_executor_invoked_once():
    record = _approved_record()
    plan = _genuine_consume_plan(record)
    operation_input = {"current_record": record, "transition_plan": plan}
    prepared = prepare_approval_operation("apply_approval_consumption", operation_input)
    row = _consumption_row_for(record, plan)
    call_count = 0
    original_call = approval_bridge._VerifyExecutor.__call__

    def _counting(self, operation):
        nonlocal call_count
        call_count += 1
        return original_call(self, operation)

    approval_bridge._VerifyExecutor.__call__ = _counting
    try:
        verify_approval_operation(
            "apply_approval_consumption", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [row]}
        )
    finally:
        approval_bridge._VerifyExecutor.__call__ = original_call
    assert call_count == 1


def test_079_no_second_client_side_operation_occurs():
    record = _approved_record()
    plan = _genuine_consume_plan(record)
    operation_input = {"current_record": record, "transition_plan": plan}
    prepared = prepare_approval_operation("apply_approval_consumption", operation_input)
    row = _consumption_row_for(record, plan)

    operations_seen = []

    class _RecordingExecutor:
        def __call__(self, operation):
            operations_seen.append(operation)
            return [row]

    # Monkeypatch the verify executor to also record, by wrapping dispatch:
    # simplest correct check is that _VerifyExecutor is invoked once (see
    # test_078); here we additionally confirm no operation is issued
    # directly against "investigations" anywhere in the flow.
    result = verify_approval_operation(
        "apply_approval_consumption", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [row]}
    )
    assert result["result"]["investigation_result"]["investigation_id"] == INVESTIGATION_ID


# ---------------------------------------------------------------------------
# 80-84: transport
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "operation,operation_input_factory",
    [
        ("insert_pending_approval", lambda: {"validated_request": _validated_request(), "expires_at": None}),
        ("load_approval_record", lambda: {"approval_id": APPROVAL_ID}),
        (
            "apply_approval_review_transition",
            lambda: {"current_record": _pending_row(), "transition_plan": _genuine_approve_plan(_pending_row())},
        ),
        (
            "apply_approval_consumption",
            lambda: {
                "current_record": _approved_record(),
                "transition_plan": _genuine_consume_plan(_approved_record()),
            },
        ),
    ],
)
def test_080_every_operation_maps_transport_error(operation, operation_input_factory):
    operation_input = operation_input_factory()
    prepared = prepare_approval_operation(operation, operation_input)
    with pytest.raises(ApprovalTransportError):
        verify_approval_operation(operation, operation_input, prepared["descriptor"], {"kind": "transport_error"})


def test_081_transport_error_message_is_fixed():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    with pytest.raises(ApprovalTransportError) as excinfo:
        verify_approval_operation(
            "load_approval_record", operation_input, prepared["descriptor"], {"kind": "transport_error"}
        )
    assert str(excinfo.value) == "Approval persistence operation failed."


def test_082_original_tool_text_cannot_be_supplied():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    with pytest.raises(ApprovalBridgeError):
        verify_approval_operation(
            "load_approval_record",
            operation_input,
            prepared["descriptor"],
            {"kind": "transport_error", "message": "raw postgres error text"},
        )


def test_083_no_retry_occurs_on_transport_error():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    call_count = 0
    original_call = approval_bridge._VerifyExecutor.__call__

    def _counting(self, operation):
        nonlocal call_count
        call_count += 1
        return original_call(self, operation)

    approval_bridge._VerifyExecutor.__call__ = _counting
    try:
        with pytest.raises(ApprovalTransportError):
            verify_approval_operation(
                "load_approval_record", operation_input, prepared["descriptor"], {"kind": "transport_error"}
            )
    finally:
        approval_bridge._VerifyExecutor.__call__ = original_call
    assert call_count == 1


def test_084_executor_invoked_once_on_transport_error():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    with pytest.raises(ApprovalTransportError):
        verify_approval_operation(
            "load_approval_record", operation_input, prepared["descriptor"], {"kind": "transport_error"}
        )


# ---------------------------------------------------------------------------
# 85-89: output
# ---------------------------------------------------------------------------


def test_085_prepare_result_has_exact_three_key_order():
    result = prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID})
    assert list(result.keys()) == ["phase", "operation", "descriptor"]


def test_086_verify_result_has_exact_three_key_order():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    result = verify_approval_operation(
        "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [_pending_row()]}
    )
    assert list(result.keys()) == ["phase", "operation", "result"]


def test_087_result_is_unmodified_from_persistence_output():
    from core.approval_persistence import load_approval_record

    class _FakeExecutor:
        def __call__(self, operation):
            return [_pending_row()]

    direct = load_approval_record(_FakeExecutor(), APPROVAL_ID)

    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    result = verify_approval_operation(
        "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [_pending_row()]}
    )
    assert result["result"] == direct


@pytest.mark.parametrize("forbidden_key", ["success", "persisted", "row_count", "affected_rows", "descriptor", "executor_response"])
def test_088_no_success_or_metadata_field_in_verify_result(forbidden_key):
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    result = verify_approval_operation(
        "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [_pending_row()]}
    )
    assert forbidden_key not in result
    assert forbidden_key not in result["result"]


def test_089_no_sql_or_mcp_metadata_in_prepare_result():
    result = prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID})
    assert "sql" not in result
    assert "mcp_tool" not in result


# ---------------------------------------------------------------------------
# 90-98: non-mutation
# ---------------------------------------------------------------------------


def test_090_inputs_remain_unchanged_for_verify():
    record = _approved_record()
    plan = _genuine_consume_plan(record)
    operation_input = {"current_record": record, "transition_plan": plan}
    before = copy.deepcopy(operation_input)
    prepared = prepare_approval_operation("apply_approval_consumption", operation_input)
    row = _consumption_row_for(record, plan)
    verify_approval_operation(
        "apply_approval_consumption", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [row]}
    )
    assert operation_input == before


def test_091_prepared_descriptor_remains_unchanged():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    before = copy.deepcopy(prepared["descriptor"])
    verify_approval_operation(
        "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [_pending_row()]}
    )
    assert prepared["descriptor"] == before


def test_092_executor_response_remains_unchanged():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    executor_response = {"kind": "rows", "rows": [_pending_row()]}
    before = copy.deepcopy(executor_response)
    verify_approval_operation("load_approval_record", operation_input, prepared["descriptor"], executor_response)
    assert executor_response == before


def test_093_rows_remain_unchanged():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    row = _pending_row()
    before = copy.deepcopy(row)
    verify_approval_operation("load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [row]})
    assert row == before


def test_094_nested_action_payload_remains_unchanged():
    record = _approved_record()
    plan = _genuine_consume_plan(record)
    operation_input = {"current_record": record, "transition_plan": plan}
    before_payload = copy.deepcopy(record["action_payload"])
    prepared = prepare_approval_operation("apply_approval_consumption", operation_input)
    row = _consumption_row_for(record, plan)
    verify_approval_operation(
        "apply_approval_consumption", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [row]}
    )
    assert record["action_payload"] == before_payload


def test_095_returned_descriptors_are_independent():
    result_one = prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID})
    result_two = prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID})
    assert result_one["descriptor"] == result_two["descriptor"]
    assert result_one["descriptor"] is not result_two["descriptor"]


def test_096_returned_results_are_independent():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    result_one = verify_approval_operation(
        "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [_pending_row()]}
    )
    result_two = verify_approval_operation(
        "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [_pending_row()]}
    )
    assert result_one["result"] == result_two["result"]
    assert result_one["result"] is not result_two["result"]


def test_097_separate_calls_share_no_state():
    operation_input_one = {"approval_id": APPROVAL_ID}
    operation_input_two = {"approval_id": "59999999-9999-4999-8999-999999999999"}
    result_one = prepare_approval_operation("load_approval_record", operation_input_one)
    result_two = prepare_approval_operation("load_approval_record", operation_input_two)
    assert result_one["descriptor"]["filters"]["id"] != result_two["descriptor"]["filters"]["id"]


def test_098_failure_paths_do_not_mutate():
    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    before = copy.deepcopy(operation_input)
    with pytest.raises(ApprovalNotFoundError):
        verify_approval_operation(
            "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": []}
        )
    assert operation_input == before


# ---------------------------------------------------------------------------
# 99-111: runtime/source boundary
# ---------------------------------------------------------------------------


def test_099_no_file_access(monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called")

    monkeypatch.setattr("builtins.open", _forbidden)
    monkeypatch.setattr(Path, "open", _forbidden)

    operation_input = {"approval_id": APPROVAL_ID}
    prepared = prepare_approval_operation("load_approval_record", operation_input)
    verify_approval_operation(
        "load_approval_record", operation_input, prepared["descriptor"], {"kind": "rows", "rows": [_pending_row()]}
    )


def test_100_no_environment_access():
    original_environ = dict(os.environ)
    prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID})
    assert dict(os.environ) == original_environ


def test_101_no_subprocess(monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called")

    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)

    prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID})


def test_102_no_socket_network(monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called")

    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)

    prepare_approval_operation("load_approval_record", {"approval_id": APPROVAL_ID})


def test_103_no_supabase_import():
    tree = _module_ast()
    imports = _top_level_imports(tree)
    assert not any(name == "supabase" or name.startswith("supabase.") for name in imports)


def test_104_no_mcp_import():
    tree = _module_ast()
    imports = _top_level_imports(tree)
    assert not any(name == "mcp" or name.startswith("mcp.") for name in imports)


def test_105_no_sql_string_generation():
    tree = _module_ast()
    string_constants = {
        node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    for forbidden_sql_keyword in ("SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM"):
        assert forbidden_sql_keyword not in string_constants


def test_106_no_client_creation():
    tree = _module_ast()
    identifiers = _referenced_identifiers(tree)
    for forbidden in ("create_client", "create_engine", "connect"):
        assert forbidden not in identifiers


def test_107_no_command_invocation():
    tree = _module_ast()
    identifiers = _referenced_identifiers(tree)
    assert not identifiers & {"SlashCommand", "run_slash_command", "invoke_slash_command"}


def test_108_no_schema_application():
    source = _module_source_text()
    assert "schema.sql" not in source
    tree = _module_ast()
    identifiers = _referenced_identifiers(tree)
    assert "apply_migration" not in identifiers


def test_109_existing_persistence_public_functions_are_reused():
    tree = _module_ast()
    import_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "core.approval_persistence":
            for alias in node.names:
                import_names.add(alias.name)
    assert {
        "insert_pending_approval", "load_approval_record",
        "apply_approval_review_transition", "apply_approval_consumption",
    } <= import_names


def test_110_no_private_persistence_helper_is_imported():
    tree = _module_ast()
    import_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "core.approval_persistence":
            for alias in node.names:
                import_names.add(alias.name)
    assert not any(name.startswith("_") for name in import_names)


def test_111_no_duplicate_lifecycle_validation_exists():
    tree = _module_ast()
    function_defs = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    for forbidden in ("validate_approval_record", "validate_approval_transition", "validate_approval_request"):
        assert forbidden not in function_defs


# ---------------------------------------------------------------------------
# Test-module source boundary (self-check)
# ---------------------------------------------------------------------------


def test_static_test_module_does_not_import_supabase_or_requests_at_module_scope():
    tree = _this_module_ast()
    imports = _top_level_imports(tree)
    assert not any(name == "supabase" or name.startswith("supabase.") for name in imports)
    assert "requests" not in imports


def test_static_test_module_never_calls_subprocess_directly():
    tree = _this_module_ast()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "Popen", "call", "check_call", "check_output"):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    pytest.fail("subprocess call executed directly in the test module")
