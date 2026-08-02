"""Tests for core.approval_persistence -- the dependency-injected
persistence boundary for inserting one pending approval and loading one
approval record by its canonical primary key.

This module is not the approval-transition validator's test suite --
lifecycle-transition semantics remain fully covered by
tests/test_approval_transition.py, and the sixteen-field record contract
remains fully covered by tests/test_approval_record.py. This file covers
only the persistence adapter itself: exact operation-descriptor shape,
executor-response normalization, delegation to the existing validators,
error taxonomy, non-mutation, and runtime/source boundaries.

No real Supabase, file, subprocess, network, or AI/model access occurs
anywhere in this file. Every "database" is a local fake executor
function; every input is a plain in-memory mapping.
"""

import ast
import copy
import inspect
import os
import socket
import subprocess
import urllib.request
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

import pytest

import core.approval_persistence as approval_persistence
from core.approval_persistence import (
    ApprovalExecutor,
    ApprovalNotFoundError,
    ApprovalPersistenceError,
    ApprovalResponseError,
    ApprovalTransportError,
    insert_pending_approval,
    load_approval_record,
)
from core.approval_request import ApprovalRequestError
from core.approval_transition import ApprovalTransitionError, validate_approval_record

APPROVAL_ID = "51111111-1111-4111-8111-111111111111"
INVESTIGATION_ID = "41111111-1111-4111-8111-111111111111"

REQUESTED_AT = "2026-08-01T15:45:00Z"
EXPIRES_AT = "2026-08-02T15:45:00Z"
CREATED_AT = "2026-08-01T15:46:00Z"

OLD_REQUESTED_AT = "2020-01-01T00:00:00Z"
OLD_EXPIRES_AT = "2020-01-02T00:00:00Z"
OLD_CREATED_AT = "2020-01-01T00:00:01Z"
OLD_APPROVED_AT = "2020-01-01T12:00:00Z"

_RECORD_FIELDS = (
    "id",
    "investigation_id",
    "action_type",
    "action_payload",
    "requested_by",
    "requested_at",
    "status",
    "approved_by",
    "approved_at",
    "rejected_by",
    "rejected_at",
    "rejection_reason",
    "expires_at",
    "consumed_by",
    "consumed_at",
    "created_at",
)

_NULLABLE_FIELDS = (
    "approved_by",
    "approved_at",
    "rejected_by",
    "rejected_at",
    "rejection_reason",
    "expires_at",
    "consumed_by",
    "consumed_at",
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


class _RecordingExecutor:
    """A local fake executor: records every operation it receives and
    returns a fixed, precomputed response (or raises a fixed exception)."""

    def __init__(self, response=None, *, raises=None):
        self.response = response
        self.raises = raises
        self.calls = []

    def __call__(self, operation):
        self.calls.append(operation)
        if self.raises is not None:
            raise self.raises
        return self.response


def _module_source_text():
    with open(approval_persistence.__file__, "r", encoding="utf-8") as handle:
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
# 1-10: public contract
# ---------------------------------------------------------------------------


def test_001_module_imports_successfully():
    assert approval_persistence is not None


def test_002_approval_executor_exists():
    assert hasattr(approval_persistence, "ApprovalExecutor")


def test_003_insert_pending_approval_exists():
    assert callable(insert_pending_approval)


def test_004_load_approval_record_exists():
    assert callable(load_approval_record)


def test_005_approval_persistence_error_exists():
    assert issubclass(ApprovalPersistenceError, Exception)


def test_006_approval_not_found_error_subclasses_persistence_error():
    assert issubclass(ApprovalNotFoundError, ApprovalPersistenceError)


def test_007_approval_response_error_subclasses_persistence_error():
    assert issubclass(ApprovalResponseError, ApprovalPersistenceError)


def test_008_approval_transport_error_subclasses_persistence_error():
    assert issubclass(ApprovalTransportError, ApprovalPersistenceError)


def test_009_approval_conflict_error_does_not_exist_yet():
    assert not hasattr(approval_persistence, "ApprovalConflictError")


def test_010_plain_function_executor_works_without_any_client_type():
    executor = _RecordingExecutor(response=[_pending_row()])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert result["status"] == "pending"


# ---------------------------------------------------------------------------
# 11-18: insert signature
# ---------------------------------------------------------------------------


def test_011_to_018_insert_signature_shape():
    signature = inspect.signature(insert_pending_approval)
    parameters = signature.parameters

    assert parameters["executor"].default is inspect.Parameter.empty  # 11
    assert parameters["validated_request"].default is inspect.Parameter.empty  # 12
    assert parameters["expires_at"].kind == inspect.Parameter.KEYWORD_ONLY  # 13
    assert parameters["expires_at"].default is None  # 14
    assert "approval_id" not in parameters  # 15
    assert "created_at" not in parameters  # 16
    assert "status" not in parameters  # 17
    assert set(parameters) == {"executor", "validated_request", "expires_at"}  # 18


# ---------------------------------------------------------------------------
# 19-40: validated-request boundary
# ---------------------------------------------------------------------------


def test_019_canonical_validated_request_succeeds():
    executor = _RecordingExecutor(response=[_pending_row(expires_at=None)])
    result = insert_pending_approval(executor, _validated_request())
    assert result["status"] == "pending"


def test_020_input_must_be_a_mapping():
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, ["not", "a", "mapping"])


def test_021_exact_five_field_shape_required():
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request()
    request["status"] = "pending"
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, request)


@pytest.mark.parametrize(
    "missing_field",
    ["investigation_id", "action_type", "action_payload", "requested_by", "requested_at"],
)
def test_022_to_026_missing_required_request_field_fails(missing_field):
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request()
    del request[missing_field]
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, request)


def test_027_unknown_field_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request(extra_field="unexpected")
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, request)


def test_028_multiple_unknown_fields_fail():
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request(extra_one="a", extra_two="b")
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, request)


def test_029_noncanonical_investigation_uuid_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request(investigation_id=INVESTIGATION_ID.upper())
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, request)


def test_030_padded_investigation_uuid_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request(investigation_id=f" {INVESTIGATION_ID} ")
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, request)


def test_031_padded_action_type_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request(action_type=" update_investigation_state ")
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, request)


def test_032_padded_requested_by_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request(requested_by=" Roshini Analyst")
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, request)


def test_033_offset_requested_at_not_already_canonical_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request(requested_at="2026-08-01T15:45:00+00:00")
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, request)


def test_034_naive_requested_at_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request(requested_at=datetime(2026, 8, 1, 15, 45, 0))
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, request)


def test_035_invalid_action_payload_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request(action_payload={"status": "not-a-real-status"})
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, request)


def test_036_empty_action_payload_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request(action_payload={})
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, request)


def test_037_unknown_action_payload_key_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request(action_payload={"status": "escalated", "bogus": "x"})
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, request)


def test_038_raw_approval_request_error_never_escapes():
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request(action_payload={})
    try:
        insert_pending_approval(executor, request)
        pytest.fail("expected ApprovalPersistenceError")
    except ApprovalRequestError:
        pytest.fail("ApprovalRequestError must never escape insert_pending_approval")
    except ApprovalPersistenceError:
        pass


def test_039_executor_not_called_after_request_input_failure():
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request(action_payload={})
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, request)
    assert executor.calls == []


def test_040_request_validator_called_exactly_once_for_valid_input(monkeypatch):
    call_count = 0
    real = approval_persistence.validate_approval_request

    def _counting_wrapper(payload):
        nonlocal call_count
        call_count += 1
        return real(payload)

    monkeypatch.setattr(approval_persistence, "validate_approval_request", _counting_wrapper)

    executor = _RecordingExecutor(response=[_pending_row()])
    insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)

    assert call_count == 1


# ---------------------------------------------------------------------------
# 41-54: expiry
# ---------------------------------------------------------------------------


def test_041_none_expiry_succeeds():
    executor = _RecordingExecutor(response=[_pending_row(expires_at=None)])
    result = insert_pending_approval(executor, _validated_request(), expires_at=None)
    assert result["expires_at"] is None


def test_042_canonical_utc_z_expiry_succeeds():
    executor = _RecordingExecutor(response=[_pending_row()])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert result["expires_at"] == EXPIRES_AT


def test_043_aware_datetime_expiry_succeeds():
    dt = datetime(2026, 8, 2, 15, 45, 0, tzinfo=timezone.utc)
    executor = _RecordingExecutor(response=[_pending_row()])
    result = insert_pending_approval(executor, _validated_request(), expires_at=dt)
    assert result["expires_at"] == EXPIRES_AT


def test_044_offset_expiry_canonicalizes_to_utc_z():
    executor = _RecordingExecutor(response=[_pending_row()])
    insert_pending_approval(
        executor, _validated_request(), expires_at="2026-08-02T20:45:00+05:00"
    )
    assert executor.calls[0]["values"]["expires_at"] == EXPIRES_AT


def test_045_expiry_equality_with_requested_at_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, _validated_request(), expires_at=REQUESTED_AT)


def test_046_expiry_before_requested_at_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, _validated_request(), expires_at="2026-08-01T10:00:00Z")


def test_047_naive_datetime_expiry_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, _validated_request(), expires_at=datetime(2026, 8, 2, 15, 45, 0))


def test_048_naive_string_expiry_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, _validated_request(), expires_at="2026-08-02T15:45:00")


def test_049_malformed_expiry_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, _validated_request(), expires_at="not-a-timestamp")


def test_050_non_string_non_datetime_expiry_fails():
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, _validated_request(), expires_at=12345)


def test_051_expiry_validation_does_not_use_wall_clock_time():
    request = _validated_request(requested_at=OLD_REQUESTED_AT)
    row = _pending_row(
        requested_at=OLD_REQUESTED_AT,
        created_at=OLD_CREATED_AT,
        expires_at=OLD_EXPIRES_AT,
    )
    executor = _RecordingExecutor(response=[row])
    result = insert_pending_approval(executor, request, expires_at=OLD_EXPIRES_AT)
    assert result["expires_at"] == OLD_EXPIRES_AT


def test_052_executor_not_called_after_expiry_failure():
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, _validated_request(), expires_at="not-a-timestamp")
    assert executor.calls == []


def test_053_supplied_expiry_input_remains_unchanged():
    dt = datetime(2026, 8, 2, 15, 45, 0, tzinfo=timezone.utc)
    original = dt
    executor = _RecordingExecutor(response=[_pending_row()])
    insert_pending_approval(executor, _validated_request(), expires_at=dt)
    assert dt == original
    assert dt.tzinfo is timezone.utc


def test_054_no_default_duration_is_invented():
    executor = _RecordingExecutor(response=[_pending_row(expires_at=None)])
    insert_pending_approval(executor, _validated_request(), expires_at=None)
    assert "expires_at" not in executor.calls[0]["values"]


# ---------------------------------------------------------------------------
# 55-74: insert operation descriptor
# ---------------------------------------------------------------------------


def test_055_to_074_insert_operation_descriptor_shape():
    executor = _RecordingExecutor(response=[_pending_row()])
    insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)

    assert len(executor.calls) == 1  # 55
    operation = executor.calls[0]

    assert operation["operation"] == "insert"  # 56
    assert operation["table"] == "approvals"  # 57

    values = operation["values"]
    assert len(values) == 7  # 59 (expiry supplied)
    assert values["status"] == "pending"  # 60
    assert values["expires_at"] == EXPIRES_AT  # 62

    for forbidden in (
        "id", "created_at", "approved_by", "approved_at", "rejected_by",
        "rejected_at", "rejection_reason", "consumed_by", "consumed_at",
        "updated_at", "action_hash", "target_type", "target_id",
        "auth_token", "user_id",
    ):
        assert forbidden not in values  # 63-71

    assert operation["returning"] == list(_RECORD_FIELDS)  # 72, 73
    assert set(operation) == {"operation", "table", "values", "returning"}  # 74

    executor_no_expiry = _RecordingExecutor(response=[_pending_row(expires_at=None)])
    insert_pending_approval(executor_no_expiry, _validated_request(), expires_at=None)
    values_no_expiry = executor_no_expiry.calls[0]["values"]
    assert len(values_no_expiry) == 6  # 58
    assert "expires_at" not in values_no_expiry  # 61


# ---------------------------------------------------------------------------
# 75-90: insert response success
# ---------------------------------------------------------------------------


def test_075_exactly_one_pending_row_succeeds():
    executor = _RecordingExecutor(response=[_pending_row()])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert result["status"] == "pending"


def test_076_returned_result_has_exactly_sixteen_fields():
    executor = _RecordingExecutor(response=[_pending_row()])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert set(result) == set(_RECORD_FIELDS)


def test_077_returned_field_order_matches_record_contract():
    executor = _RecordingExecutor(response=[_pending_row()])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert list(result) == list(_RECORD_FIELDS)


def test_078_returned_result_equals_direct_validate_approval_record_output():
    row = _pending_row()
    executor = _RecordingExecutor(response=[row])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    direct = validate_approval_record(row)
    assert result == direct


def test_079_database_generated_id_preserved_canonically():
    executor = _RecordingExecutor(response=[_pending_row(id=APPROVAL_ID.upper())])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert result["id"] == APPROVAL_ID


def test_080_database_generated_created_at_preserved_canonically():
    dt = datetime(2026, 8, 1, 15, 46, 0, tzinfo=timezone.utc)
    executor = _RecordingExecutor(response=[_pending_row(created_at=dt)])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert result["created_at"] == CREATED_AT


def test_081_request_fields_match_exactly():
    executor = _RecordingExecutor(response=[_pending_row()])
    request = _validated_request()
    result = insert_pending_approval(executor, request, expires_at=EXPIRES_AT)
    assert result["investigation_id"] == request["investigation_id"]
    assert result["action_type"] == request["action_type"]
    assert result["action_payload"] == request["action_payload"]
    assert result["requested_by"] == request["requested_by"]
    assert result["requested_at"] == request["requested_at"]


def test_082_status_is_pending():
    executor = _RecordingExecutor(response=[_pending_row()])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert result["status"] == "pending"


def test_083_all_lifecycle_fields_are_none():
    executor = _RecordingExecutor(response=[_pending_row()])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    for field_name in ("approved_by", "approved_at", "rejected_by", "rejected_at", "rejection_reason", "consumed_by", "consumed_at"):
        assert result[field_name] is None


def test_084_canonical_supplied_expires_at_matches():
    executor = _RecordingExecutor(response=[_pending_row()])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert result["expires_at"] == EXPIRES_AT


def test_085_omitted_expiry_requires_returned_expires_at_none():
    executor = _RecordingExecutor(response=[_pending_row(expires_at=None)])
    result = insert_pending_approval(executor, _validated_request(), expires_at=None)
    assert result["expires_at"] is None


def test_086_nullable_omitted_keys_restored_as_none():
    row = _pending_row()
    for field_name in _NULLABLE_FIELDS:
        if row[field_name] is None:
            del row[field_name]
    executor = _RecordingExecutor(response=[row])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert result["approved_by"] is None
    assert result["rejected_by"] is None
    assert result["consumed_by"] is None


def test_087_validate_approval_record_called_exactly_once(monkeypatch):
    call_count = 0
    real = approval_persistence.validate_approval_record

    def _counting_wrapper(current_record):
        nonlocal call_count
        call_count += 1
        return real(current_record)

    monkeypatch.setattr(approval_persistence, "validate_approval_record", _counting_wrapper)

    executor = _RecordingExecutor(response=[_pending_row()])
    insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)

    assert call_count == 1


def test_088_no_persistence_receipt_returned():
    executor = _RecordingExecutor(response=[_pending_row()])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert "persisted" not in result


def test_089_no_operation_descriptor_returned():
    executor = _RecordingExecutor(response=[_pending_row()])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert "operation" not in result
    assert "table" not in result
    assert "returning" not in result


def test_090_no_executor_metadata_returned():
    executor = _RecordingExecutor(response=[_pending_row()])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert set(result) == set(_RECORD_FIELDS)


# ---------------------------------------------------------------------------
# 91-124: insert response failure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("response", [None, {"id": APPROVAL_ID}, (1, 2), "not-a-list"])
def test_091_to_094_non_list_response_fails(response):
    executor = _RecordingExecutor(response=response)
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_095_empty_list_fails():
    executor = _RecordingExecutor(response=[])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_096_multiple_rows_fail():
    executor = _RecordingExecutor(response=[_pending_row(), _pending_row()])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_097_non_mapping_row_fails():
    executor = _RecordingExecutor(response=["not-a-mapping"])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


@pytest.mark.parametrize(
    "missing_field",
    ["id", "investigation_id", "action_type", "action_payload", "requested_by", "requested_at", "status", "created_at"],
)
def test_098_to_105_missing_required_row_field_fails(missing_field):
    row = _pending_row()
    del row[missing_field]
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_106_unknown_row_field_fails():
    row = _pending_row(unexpected_field="value")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_107_invalid_row_uuid_fails():
    row = _pending_row(id="not-a-uuid")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_108_invalid_row_chronology_fails():
    row = _pending_row(created_at="2026-08-01T10:00:00Z")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_109_invalid_lifecycle_shape_fails():
    row = _pending_row(approved_by="Security Reviewer")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_110_wrong_status_fails():
    row = _pending_row(
        status="approved",
        approved_by="Security Reviewer",
        approved_at="2026-08-01T16:00:00Z",
    )
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_111_frozen_investigation_field_mismatch_fails():
    row = _pending_row(investigation_id="42222222-2222-4222-8222-222222222222")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_112_frozen_action_type_mismatch_fails(monkeypatch):
    import core.approval_request as approval_request_module

    monkeypatch.setattr(
        approval_request_module,
        "ACTION_TYPES",
        frozenset({"update_investigation_state", "fake_other_action"}),
    )
    row = _pending_row(action_type="fake_other_action")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_113_frozen_action_payload_mismatch_fails():
    row = _pending_row(action_payload={"status": "escalated", "confidence": "low"})
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_114_frozen_requester_mismatch_fails():
    row = _pending_row(requested_by="Someone Else")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_115_frozen_requested_at_mismatch_fails():
    row = _pending_row(
        requested_at="2026-08-01T16:00:00Z",
        created_at="2026-08-01T16:01:00Z",
    )
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_116_returned_expiry_mismatch_fails():
    row = _pending_row(expires_at="2026-08-05T00:00:00Z")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_117_approval_metadata_unexpectedly_populated_fails():
    row = _pending_row(approved_by="Security Reviewer", approved_at="2026-08-01T16:00:00Z")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_118_rejection_metadata_unexpectedly_populated_fails():
    row = _pending_row(rejected_by="Security Reviewer", rejected_at="2026-08-01T16:00:00Z")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_119_consumption_metadata_unexpectedly_populated_fails():
    row = _pending_row(consumed_by="Update Case Operator", consumed_at="2026-08-01T16:00:00Z")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_120_approval_transition_error_never_escapes():
    row = _pending_row(approved_by="Security Reviewer")
    executor = _RecordingExecutor(response=[row])
    try:
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
        pytest.fail("expected ApprovalResponseError")
    except ApprovalTransitionError:
        pytest.fail("ApprovalTransitionError must never escape insert_pending_approval")
    except ApprovalResponseError:
        pass


def test_121_errors_do_not_expose_returned_row():
    secret_marker = "top-secret-row-marker"
    row = _pending_row(requested_by=secret_marker)
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError) as excinfo:
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert secret_marker not in str(excinfo.value)


def test_122_errors_do_not_expose_action_payload():
    secret_marker = "top-secret-payload-marker"
    row = _pending_row(action_payload={"status": "escalated", "confidence": "low", secret_marker: "x"})
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError) as excinfo:
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert secret_marker not in str(excinfo.value)


def test_123_errors_do_not_expose_identity():
    secret_marker = "confidential-identity-marker"
    row = _pending_row(approved_by=secret_marker)
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError) as excinfo:
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert secret_marker not in str(excinfo.value)


def test_124_errors_do_not_expose_planted_secret_values():
    secret_marker = "planted-secret-value-zzz"
    row = _pending_row(rejection_reason=secret_marker, status="pending")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError) as excinfo:
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert secret_marker not in str(excinfo.value)


# ---------------------------------------------------------------------------
# 125-137: lookup signature and UUID
# ---------------------------------------------------------------------------


def test_125_to_137_lookup_signature_and_uuid_handling():
    signature = inspect.signature(load_approval_record)
    parameters = signature.parameters

    assert parameters["executor"].default is inspect.Parameter.empty  # 125
    assert parameters["approval_id"].default is inspect.Parameter.empty  # 126
    assert set(parameters) == {"executor", "approval_id"}
    assert "investigation_id" not in parameters  # 135
    assert "status" not in parameters  # 136
    assert "requested_by" not in parameters  # 137

    executor = _RecordingExecutor(response=[_pending_row()])
    result = load_approval_record(executor, APPROVAL_ID)
    assert result["id"] == APPROVAL_ID  # 127

    executor_upper = _RecordingExecutor(response=[_pending_row()])
    result_upper = load_approval_record(executor_upper, APPROVAL_ID.upper())
    assert result_upper["id"] == APPROVAL_ID  # 128
    assert executor_upper.calls[0]["filters"]["id"] == APPROVAL_ID

    executor_brace = _RecordingExecutor(response=[_pending_row()])
    result_brace = load_approval_record(executor_brace, f"{{{APPROVAL_ID}}}")
    assert result_brace["id"] == APPROVAL_ID  # 129

    executor_padded = _RecordingExecutor(response=[_pending_row()])
    result_padded = load_approval_record(executor_padded, f"  {APPROVAL_ID}  ")
    assert result_padded["id"] == APPROVAL_ID  # 130

    executor_invalid = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        load_approval_record(executor_invalid, "not-a-uuid")  # 131
    assert executor_invalid.calls == []

    executor_blank = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        load_approval_record(executor_blank, "   ")  # 132

    executor_int = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        load_approval_record(executor_int, 12345)  # 133

    executor_bool = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        load_approval_record(executor_bool, True)  # 134


# ---------------------------------------------------------------------------
# 138-150: lookup operation descriptor
# ---------------------------------------------------------------------------


def test_138_to_150_lookup_operation_descriptor_shape():
    executor = _RecordingExecutor(response=[_pending_row()])
    load_approval_record(executor, APPROVAL_ID)

    assert len(executor.calls) == 1  # 138
    operation = executor.calls[0]

    assert operation["operation"] == "select"  # 139
    assert operation["table"] == "approvals"  # 140
    assert len(operation["columns"]) == 16  # 141
    assert operation["columns"] == list(_RECORD_FIELDS)  # 142
    assert set(operation["filters"]) == {"id"}  # 143
    assert operation["filters"]["id"] == APPROVAL_ID  # 144
    assert operation["limit"] == 2  # 145
    assert "action_type" not in operation["filters"]  # 146
    assert "investigation_id" not in operation["filters"]  # 147
    assert "status" not in operation["filters"]  # 148
    assert "expires_at" not in operation["filters"]  # 149
    assert set(operation) == {"operation", "table", "columns", "filters", "limit"}  # 150


# ---------------------------------------------------------------------------
# 151-168: lookup response
# ---------------------------------------------------------------------------


def test_151_zero_rows_raises_not_found():
    executor = _RecordingExecutor(response=[])
    with pytest.raises(ApprovalNotFoundError):
        load_approval_record(executor, APPROVAL_ID)


def test_152_one_row_succeeds():
    executor = _RecordingExecutor(response=[_pending_row()])
    result = load_approval_record(executor, APPROVAL_ID)
    assert result["status"] == "pending"


def test_153_multiple_rows_raise_response_error():
    executor = _RecordingExecutor(response=[_pending_row(), _pending_row()])
    with pytest.raises(ApprovalResponseError):
        load_approval_record(executor, APPROVAL_ID)


def test_154_non_list_response_raises_response_error():
    executor = _RecordingExecutor(response={"id": APPROVAL_ID})
    with pytest.raises(ApprovalResponseError):
        load_approval_record(executor, APPROVAL_ID)


def test_155_non_mapping_row_raises_response_error():
    executor = _RecordingExecutor(response=["not-a-mapping"])
    with pytest.raises(ApprovalResponseError):
        load_approval_record(executor, APPROVAL_ID)


def test_156_missing_nullable_fields_restored_as_none():
    row = _pending_row()
    del row["approved_by"]
    del row["rejected_by"]
    del row["consumed_by"]
    executor = _RecordingExecutor(response=[row])
    result = load_approval_record(executor, APPROVAL_ID)
    assert result["approved_by"] is None
    assert result["rejected_by"] is None
    assert result["consumed_by"] is None


def test_157_missing_required_field_raises_response_error():
    row = _pending_row()
    del row["status"]
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        load_approval_record(executor, APPROVAL_ID)


def test_158_unknown_field_raises_response_error():
    row = _pending_row(unexpected_field="value")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        load_approval_record(executor, APPROVAL_ID)


def test_159_returned_id_mismatch_raises_response_error():
    row = _pending_row(id="59999999-9999-4999-8999-999999999999")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        load_approval_record(executor, APPROVAL_ID)


def test_160_invalid_lifecycle_row_raises_response_error():
    row = _pending_row(rejected_by="Security Reviewer")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        load_approval_record(executor, APPROVAL_ID)


def test_161_invalid_chronology_row_raises_response_error():
    row = _pending_row(created_at="2026-08-01T10:00:00Z")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        load_approval_record(executor, APPROVAL_ID)


def test_162_historically_expired_pending_row_succeeds():
    row = _pending_row(
        requested_at=OLD_REQUESTED_AT,
        created_at=OLD_CREATED_AT,
        expires_at=OLD_EXPIRES_AT,
    )
    executor = _RecordingExecutor(response=[row])
    result = load_approval_record(executor, APPROVAL_ID)
    assert result["expires_at"] == OLD_EXPIRES_AT


def test_163_historically_expired_approved_row_succeeds_when_structurally_valid():
    row = _pending_row(
        status="approved",
        requested_at=OLD_REQUESTED_AT,
        created_at=OLD_CREATED_AT,
        approved_by="Security Reviewer",
        approved_at=OLD_APPROVED_AT,
        expires_at=OLD_EXPIRES_AT,
    )
    executor = _RecordingExecutor(response=[row])
    result = load_approval_record(executor, APPROVAL_ID)
    assert result["status"] == "approved"


def test_164_returned_output_equals_validate_approval_record():
    row = _pending_row()
    executor = _RecordingExecutor(response=[row])
    result = load_approval_record(executor, APPROVAL_ID)
    direct = validate_approval_record(row)
    assert result == direct


def test_165_validate_approval_record_called_exactly_once(monkeypatch):
    call_count = 0
    real = approval_persistence.validate_approval_record

    def _counting_wrapper(current_record):
        nonlocal call_count
        call_count += 1
        return real(current_record)

    monkeypatch.setattr(approval_persistence, "validate_approval_record", _counting_wrapper)

    executor = _RecordingExecutor(response=[_pending_row()])
    load_approval_record(executor, APPROVAL_ID)

    assert call_count == 1


def test_166_approval_transition_error_never_escapes_lookup():
    row = _pending_row(rejected_by="Security Reviewer")
    executor = _RecordingExecutor(response=[row])
    try:
        load_approval_record(executor, APPROVAL_ID)
        pytest.fail("expected ApprovalResponseError")
    except ApprovalTransitionError:
        pytest.fail("ApprovalTransitionError must never escape load_approval_record")
    except ApprovalResponseError:
        pass


def test_167_lookup_errors_do_not_expose_approval_row():
    secret_marker = "top-secret-lookup-marker"
    row = _pending_row(requested_by=secret_marker, rejected_by="Security Reviewer")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError) as excinfo:
        load_approval_record(executor, APPROVAL_ID)
    assert secret_marker not in str(excinfo.value)


def test_168_lookup_errors_do_not_expose_secret_markers():
    secret_marker = "another-secret-marker-value"
    row = _pending_row(rejection_reason=secret_marker)
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError) as excinfo:
        load_approval_record(executor, APPROVAL_ID)
    assert secret_marker not in str(excinfo.value)


# ---------------------------------------------------------------------------
# 169-181: transport failures
# ---------------------------------------------------------------------------


def test_169_insert_executor_exception_becomes_transport_error():
    executor = _RecordingExecutor(raises=RuntimeError("boom"))
    with pytest.raises(ApprovalTransportError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)


def test_170_lookup_executor_exception_becomes_transport_error():
    executor = _RecordingExecutor(raises=RuntimeError("boom"))
    with pytest.raises(ApprovalTransportError):
        load_approval_record(executor, APPROVAL_ID)


def test_171_to_178_transport_error_redacts_everything():
    secret_exception_message = "postgres://user:hunter2@db.internal:5432/prod?sslmode=require"
    executor = _RecordingExecutor(
        raises=RuntimeError(
            secret_exception_message
            + " service_role_key=sk-fake-secret-key action_payload={'status':'x'} identity=jane"
        )
    )
    with pytest.raises(ApprovalTransportError) as excinfo:
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)

    message = str(excinfo.value)
    assert "RuntimeError" not in message  # 171
    assert secret_exception_message not in message  # 172
    assert "Traceback" not in message  # 173
    assert "postgres://" not in message  # 174
    assert "sk-fake-secret-key" not in message  # 175
    assert "action_payload" not in message  # 176
    assert "identity=jane" not in message  # 177
    assert "approvals" not in message  # 178 (no raw operation descriptor content)
    assert excinfo.value.__cause__ is None


def test_179_persistence_error_before_executor_not_misclassified():
    executor = _RecordingExecutor(response=[_pending_row()])
    try:
        insert_pending_approval(executor, {"not": "valid"}, expires_at=EXPIRES_AT)
    except ApprovalTransportError:
        pytest.fail("invalid adapter input must not be classified as a transport error")
    except ApprovalPersistenceError:
        pass
    assert executor.calls == []


def test_180_and_181_executor_not_retried_on_transport_failure():
    executor = _RecordingExecutor(raises=RuntimeError("boom"))
    with pytest.raises(ApprovalTransportError):
        insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert len(executor.calls) == 1


# ---------------------------------------------------------------------------
# 182-195: non-mutation and independence
# ---------------------------------------------------------------------------


def test_182_and_183_validated_request_and_nested_payload_unchanged():
    request = _validated_request()
    before = copy.deepcopy(request)
    executor = _RecordingExecutor(response=[_pending_row()])
    insert_pending_approval(executor, request, expires_at=EXPIRES_AT)
    assert request == before


def test_184_and_185_executor_response_list_and_row_unchanged():
    row = _pending_row()
    response = [row]
    before_response = copy.deepcopy(response)
    executor = _RecordingExecutor(response=response)
    insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert response == before_response


def test_186_nested_response_action_payload_unchanged():
    row = _pending_row()
    before_payload = copy.deepcopy(row["action_payload"])
    executor = _RecordingExecutor(response=[row])
    insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert row["action_payload"] == before_payload


def test_187_returned_result_independent_from_request():
    request = _validated_request()
    executor = _RecordingExecutor(response=[_pending_row()])
    result = insert_pending_approval(executor, request, expires_at=EXPIRES_AT)
    assert result is not request
    assert result["action_payload"] is not request["action_payload"]


def test_188_returned_result_independent_from_executor_row():
    row = _pending_row()
    executor = _RecordingExecutor(response=[row])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert result is not row
    assert result["action_payload"] is not row["action_payload"]


def test_189_returned_action_payload_independent():
    row = _pending_row()
    executor = _RecordingExecutor(response=[row])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    result["action_payload"]["status"] = "mutated"
    assert row["action_payload"]["status"] == "escalated"


def test_190_separate_insert_calls_return_independent_objects():
    executor_one = _RecordingExecutor(response=[_pending_row()])
    executor_two = _RecordingExecutor(response=[_pending_row()])
    result_one = insert_pending_approval(executor_one, _validated_request(), expires_at=EXPIRES_AT)
    result_two = insert_pending_approval(executor_two, _validated_request(), expires_at=EXPIRES_AT)
    assert result_one == result_two
    assert result_one is not result_two


def test_191_separate_lookup_calls_return_independent_objects():
    executor_one = _RecordingExecutor(response=[_pending_row()])
    executor_two = _RecordingExecutor(response=[_pending_row()])
    result_one = load_approval_record(executor_one, APPROVAL_ID)
    result_two = load_approval_record(executor_two, APPROVAL_ID)
    assert result_one == result_two
    assert result_one is not result_two


def test_192_hostile_executor_mutation_of_operation_values_does_not_mutate_request():
    request = _validated_request()

    def _hostile(operation):
        operation["values"]["requested_by"] = "HACKED"
        return [_pending_row()]

    insert_pending_approval(_hostile, request, expires_at=EXPIRES_AT)
    assert request["requested_by"] == "Roshini Analyst"


def test_193_hostile_executor_mutation_of_returning_list_does_not_affect_later_calls():
    def _hostile(operation):
        operation["returning"].append("hacked_field")
        return [_pending_row()]

    insert_pending_approval(_hostile, _validated_request(), expires_at=EXPIRES_AT)

    executor_two = _RecordingExecutor(response=[_pending_row()])
    insert_pending_approval(executor_two, _validated_request(), expires_at=EXPIRES_AT)
    assert executor_two.calls[0]["returning"] == list(_RECORD_FIELDS)


def test_194_hostile_executor_mutation_of_lookup_columns_does_not_affect_later_calls():
    def _hostile(operation):
        operation["columns"].append("hacked_field")
        return [_pending_row()]

    load_approval_record(_hostile, APPROVAL_ID)

    executor_two = _RecordingExecutor(response=[_pending_row()])
    load_approval_record(executor_two, APPROVAL_ID)
    assert executor_two.calls[0]["columns"] == list(_RECORD_FIELDS)


def test_195_failure_paths_do_not_mutate_input():
    request = _validated_request(action_payload={})
    before = copy.deepcopy(request)
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        insert_pending_approval(executor, request, expires_at=EXPIRES_AT)
    assert request == before


# ---------------------------------------------------------------------------
# 196-210: output exclusions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "excluded_key",
    [
        "persisted",
        "row_count",
        "affected_rows",
        "database_result",
        "executor_result",
        "operation",
        "from_status",
        "to_status",
        "set_fields",
        "transition_plan",
        "authentication_result",
        "action_hash",
        "target_type",
        "updated_at",
        "execution_result",
    ],
)
def test_196_to_210_output_never_contains_forbidden_keys(excluded_key):
    insert_executor = _RecordingExecutor(response=[_pending_row()])
    insert_result = insert_pending_approval(insert_executor, _validated_request(), expires_at=EXPIRES_AT)
    assert excluded_key not in insert_result

    lookup_executor = _RecordingExecutor(response=[_pending_row()])
    lookup_result = load_approval_record(lookup_executor, APPROVAL_ID)
    assert excluded_key not in lookup_result


# ---------------------------------------------------------------------------
# 211-232: runtime boundary
# ---------------------------------------------------------------------------


def test_211_to_216_import_has_no_side_effects(monkeypatch):
    import importlib
    import sys

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called during import")

    monkeypatch.setattr("builtins.open", _forbidden)
    monkeypatch.setattr(Path, "open", _forbidden)
    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)
    monkeypatch.setattr(os.environ, "get", _forbidden)

    module_name = "core.approval_persistence"
    existing = sys.modules.pop(module_name, None)
    supabase_already_loaded = "supabase" in sys.modules
    try:
        reloaded = importlib.import_module(module_name)
        assert reloaded is not None
        # Confirm importing this module does not itself newly load supabase
        # -- it may already be present in sys.modules because some other
        # test file imported it (only to install monkeypatch guards).
        assert supabase_already_loaded == ("supabase" in sys.modules)  # 216
    finally:
        if existing is not None:
            sys.modules[module_name] = existing


def test_217_to_222_insert_works_under_runtime_guards(monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called")

    try:
        import requests
    except ImportError:
        requests = None

    try:
        import supabase
    except ImportError:
        supabase = None

    monkeypatch.setattr("builtins.open", _forbidden)
    monkeypatch.setattr(Path, "open", _forbidden)
    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)

    if requests is not None:
        monkeypatch.setattr(requests, "get", _forbidden)
        monkeypatch.setattr(requests, "post", _forbidden)

    if supabase is not None and hasattr(supabase, "create_client"):
        monkeypatch.setattr(supabase, "create_client", _forbidden)

    executor = _RecordingExecutor(response=[_pending_row()])
    result = insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert result["status"] == "pending"


def test_223_lookup_works_under_the_same_guards(monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called")

    monkeypatch.setattr("builtins.open", _forbidden)
    monkeypatch.setattr(Path, "open", _forbidden)
    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)

    executor = _RecordingExecutor(response=[_pending_row()])
    result = load_approval_record(executor, APPROVAL_ID)
    assert result["status"] == "pending"


def test_224_and_225_environment_and_cwd_unchanged():
    original_cwd = os.getcwd()
    original_environ = dict(os.environ)

    executor = _RecordingExecutor(response=[_pending_row()])
    insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)

    assert os.getcwd() == original_cwd
    assert dict(os.environ) == original_environ


def test_226_hayabusa_not_imported():
    import sys

    executor = _RecordingExecutor(response=[_pending_row()])
    insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    assert "mcp.hayabusa_server" not in sys.modules


def test_227_to_232_no_forbidden_behavior_keywords_in_source():
    tree = _module_ast()
    identifiers = _referenced_identifiers(tree)

    for forbidden in (
        "containment",
        "execute_simulation",
        "run_atomic",
        "authenticate",
    ):
        assert forbidden not in identifiers

    source = _module_source_text()
    assert "/update-case" not in source
    assert "apply_migration" not in source


# ---------------------------------------------------------------------------
# 233-261: source boundary
# ---------------------------------------------------------------------------


def test_233_production_module_imports_only_approved_modules():
    tree = _module_ast()
    top_level_imports = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level_imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top_level_imports.add(node.module.split(".")[0])

    allowed = {"__future__", "copy", "uuid", "collections", "datetime", "typing", "core"}
    assert top_level_imports <= allowed


@pytest.mark.parametrize(
    "forbidden_module",
    ["supabase", "requests", "urllib", "socket", "subprocess", "os", "pathlib", "mcp"],
)
def test_234_to_241_no_forbidden_module_imported(forbidden_module):
    tree = _module_ast()
    imports = _top_level_imports(tree)
    assert not any(name == forbidden_module or name.startswith(forbidden_module + ".") for name in imports)


@pytest.mark.parametrize("forbidden_name", ["anthropic", "openai", "model"])
def test_242_no_ai_model_import(forbidden_name):
    tree = _module_ast()
    imports = _top_level_imports(tree)
    assert not any(name == forbidden_name or name.startswith(forbidden_name + ".") for name in imports)


@pytest.mark.parametrize(
    "forbidden_identifier",
    [
        "execute_sql",
        "psycopg",
        "connect",
        "environ",
        "getenv",
        "create_client",
        "approve",
        "reject",
        "consume",
        "transaction",
        "commit",
        "rollback",
        "hash",
        "auth",
        "authenticate",
        "token",
        "containment",
    ],
)
def test_243_to_257_no_forbidden_identifiers_referenced(forbidden_identifier):
    tree = _module_ast()
    identifiers = _referenced_identifiers(tree)
    assert forbidden_identifier not in identifiers


def test_250_only_insert_and_select_operations_exist():
    tree = _module_ast()
    operation_values = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key_node, value_node in zip(node.keys, node.values):
                if (
                    isinstance(key_node, ast.Constant)
                    and key_node.value == "operation"
                    and isinstance(value_node, ast.Constant)
                ):
                    operation_values.add(value_node.value)
    assert operation_values == {"insert", "select"}


def test_258_no_approval_conflict_error_yet():
    assert not hasattr(approval_persistence, "ApprovalConflictError")


def test_259_public_functions_only_call_the_executor_for_io():
    tree = _module_ast()
    for function_name in ("insert_pending_approval", "load_approval_record"):
        fn = _function_def(tree, function_name)
        called = {
            node.func.id
            for node in ast.walk(fn)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert "open" not in called
        assert "eval" not in called
        assert "exec" not in called


def test_260_validate_approval_request_remains_request_contract_owner():
    tree = _module_ast()
    import_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "core.approval_request":
            for alias in node.names:
                import_names.add(alias.name)
    assert "validate_approval_request" in import_names


def test_261_validate_approval_record_remains_record_contract_owner():
    tree = _module_ast()
    import_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "core.approval_transition":
            for alias in node.names:
                import_names.add(alias.name)
    assert "validate_approval_record" in import_names


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
