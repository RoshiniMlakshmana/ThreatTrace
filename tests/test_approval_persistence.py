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
import json
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
    ApprovalConflictError,
    ApprovalExecutor,
    ApprovalNotFoundError,
    ApprovalPersistenceError,
    ApprovalResponseError,
    ApprovalTransportError,
    apply_approval_consumption,
    apply_approval_review_transition,
    insert_pending_approval,
    load_approval_record,
)
from core.approval_request import ApprovalRequestError
from core.approval_transition import (
    ApprovalTransitionError,
    validate_approval_record,
    validate_approval_transition,
)

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


def test_009_approval_conflict_error_exists_and_subclasses_persistence_error():
    assert hasattr(approval_persistence, "ApprovalConflictError")
    assert issubclass(approval_persistence.ApprovalConflictError, ApprovalPersistenceError)


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


def test_250_only_insert_select_update_and_rpc_operations_exist():
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
    assert operation_values == {"insert", "select", "update", "rpc"}


def test_258_approval_conflict_error_reserved_for_review_transitions():
    # ApprovalConflictError now exists (Step 8), but only for a
    # structurally-genuine approve/reject update matched against zero
    # rows -- covered functionally in the review-transition test section.
    assert issubclass(approval_persistence.ApprovalConflictError, ApprovalPersistenceError)


def test_259_public_functions_only_call_the_executor_for_io():
    tree = _module_ast()
    for function_name in ("insert_pending_approval", "load_approval_record", "apply_approval_review_transition"):
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
# apply_approval_review_transition -- fixtures
# ---------------------------------------------------------------------------

# Fixed, deterministic default reviewed_at for _genuine_approve_plan/
# _genuine_reject_plan below -- strictly after REQUESTED_AT and strictly
# before EXPIRES_AT for the default _canonical_pending_record() window, so
# these helpers never fall through to validate_approval_transition's own
# wall-clock (`datetime.now(timezone.utc)`) generation path. Advancing the
# real system date must never change what these fixtures produce; a caller
# that needs a different (still explicit) moment passes reviewed_at=...
# directly, as several tests below already do.
REVIEWED_AT = "2026-08-01T16:00:00Z"


def _canonical_pending_record(**overrides):
    return _pending_row(**overrides)


def _genuine_approve_plan(current_record, reviewed_by="Security Reviewer", reviewed_at=REVIEWED_AT):
    request = {"transition": "approve", "reviewed_by": reviewed_by, "reviewed_at": reviewed_at}
    return validate_approval_transition(current_record, request)


def _genuine_reject_plan(
    current_record,
    reviewed_by="Security Reviewer",
    reviewed_at=REVIEWED_AT,
    rejection_reason="Needs more evidence before approval.",
):
    request = {
        "transition": "reject",
        "reviewed_by": reviewed_by,
        "rejection_reason": rejection_reason,
        "reviewed_at": reviewed_at,
    }
    return validate_approval_transition(current_record, request)


def _apply_set_fields(record, set_fields):
    updated = dict(record)
    updated.update(set_fields)
    return updated


def _review_executor_for(record, plan, *, row_override=None):
    response = row_override if row_override is not None else [_apply_set_fields(record, plan["set_fields"])]
    return _RecordingExecutor(response=response)


# ---------------------------------------------------------------------------
# apply_approval_review_transition -- public boundary
# ---------------------------------------------------------------------------


def test_review_conflict_error_subclasses_persistence_error():
    assert issubclass(ApprovalConflictError, ApprovalPersistenceError)


def test_review_signature_has_exactly_three_required_parameters():
    signature = inspect.signature(apply_approval_review_transition)
    parameters = signature.parameters
    assert list(parameters) == ["executor", "current_record", "transition_plan"]
    for name in parameters:
        assert parameters[name].default is inspect.Parameter.empty


def test_review_no_transition_request_or_now_parameter():
    signature = inspect.signature(apply_approval_review_transition)
    assert "transition_request" not in signature.parameters
    assert "now" not in signature.parameters


def test_review_no_consume_specific_persistence_function_exists():
    assert not hasattr(approval_persistence, "apply_approval_consume_transition")
    assert not hasattr(approval_persistence, "consume_pending_approval")
    assert not hasattr(approval_persistence, "apply_approval_consume")


def test_review_required_docstring_phrase_exists():
    assert (
        "Verified approval review update -- no consumption or investigation update"
        in apply_approval_review_transition.__doc__
    )


# ---------------------------------------------------------------------------
# apply_approval_review_transition -- approve success
# ---------------------------------------------------------------------------


def test_review_genuine_approve_plan_succeeds():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _review_executor_for(record, plan)
    result = apply_approval_review_transition(executor, record, plan)
    assert result["updated_record"]["status"] == "approved"


def test_review_approve_executor_called_exactly_once():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _review_executor_for(record, plan)
    apply_approval_review_transition(executor, record, plan)
    assert len(executor.calls) == 1


def test_review_approve_descriptor_is_exact():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _review_executor_for(record, plan)
    apply_approval_review_transition(executor, record, plan)
    operation = executor.calls[0]
    assert operation["operation"] == "update"
    assert operation["table"] == "approvals"
    assert operation["values"] == plan["set_fields"]
    assert set(operation) == {"operation", "table", "values", "filters", "returning"}


def test_review_return_contains_exactly_transition_plan_and_updated_record():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _review_executor_for(record, plan)
    result = apply_approval_review_transition(executor, record, plan)
    assert list(result) == ["transition_plan", "updated_record"]


def test_review_approved_metadata_matches_plan():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _review_executor_for(record, plan)
    result = apply_approval_review_transition(executor, record, plan)
    updated = result["updated_record"]
    assert updated["approved_by"] == plan["set_fields"]["approved_by"]
    assert updated["approved_at"] == plan["set_fields"]["approved_at"]


def test_review_frozen_fields_unchanged_after_approve():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _review_executor_for(record, plan)
    result = apply_approval_review_transition(executor, record, plan)
    updated = result["updated_record"]
    for field_name in (
        "id", "investigation_id", "action_type", "action_payload",
        "requested_by", "requested_at", "expires_at", "created_at",
    ):
        assert updated[field_name] == record[field_name]


def test_review_rejection_and_consumption_fields_none_after_approve():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _review_executor_for(record, plan)
    result = apply_approval_review_transition(executor, record, plan)
    updated = result["updated_record"]
    for field_name in ("rejected_by", "rejected_at", "rejection_reason", "consumed_by", "consumed_at"):
        assert updated[field_name] is None


# ---------------------------------------------------------------------------
# apply_approval_review_transition -- reject success
# ---------------------------------------------------------------------------


def test_review_genuine_reject_plan_succeeds():
    record = _canonical_pending_record()
    plan = _genuine_reject_plan(record)
    executor = _review_executor_for(record, plan)
    result = apply_approval_review_transition(executor, record, plan)
    assert result["updated_record"]["status"] == "rejected"


def test_review_self_rejection_succeeds():
    record = _canonical_pending_record(requested_by="Roshini Analyst")
    plan = _genuine_reject_plan(record, reviewed_by="Roshini Analyst")
    executor = _review_executor_for(record, plan)
    result = apply_approval_review_transition(executor, record, plan)
    assert result["updated_record"]["rejected_by"] == "Roshini Analyst"


def test_review_rejection_metadata_matches_plan():
    record = _canonical_pending_record()
    plan = _genuine_reject_plan(record)
    executor = _review_executor_for(record, plan)
    result = apply_approval_review_transition(executor, record, plan)
    updated = result["updated_record"]
    assert updated["rejected_by"] == plan["set_fields"]["rejected_by"]
    assert updated["rejected_at"] == plan["set_fields"]["rejected_at"]
    assert updated["rejection_reason"] == plan["set_fields"]["rejection_reason"]


def test_review_frozen_fields_unchanged_after_reject():
    record = _canonical_pending_record()
    plan = _genuine_reject_plan(record)
    executor = _review_executor_for(record, plan)
    result = apply_approval_review_transition(executor, record, plan)
    updated = result["updated_record"]
    for field_name in (
        "id", "investigation_id", "action_type", "action_payload",
        "requested_by", "requested_at", "expires_at", "created_at",
    ):
        assert updated[field_name] == record[field_name]


def test_review_approval_and_consumption_fields_none_after_reject():
    record = _canonical_pending_record()
    plan = _genuine_reject_plan(record)
    executor = _review_executor_for(record, plan)
    result = apply_approval_review_transition(executor, record, plan)
    updated = result["updated_record"]
    for field_name in ("approved_by", "approved_at", "consumed_by", "consumed_at"):
        assert updated[field_name] is None


# ---------------------------------------------------------------------------
# apply_approval_review_transition -- input failure
# ---------------------------------------------------------------------------


def test_review_malformed_record_fails_before_executor():
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_review_transition(executor, ["not", "a", "mapping"], {})
    assert executor.calls == []


def test_review_noncanonical_record_fails():
    record = _canonical_pending_record(id=APPROVAL_ID.upper())
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_review_transition(executor, record, {})
    assert executor.calls == []


def test_review_non_pending_record_fails():
    record = _canonical_pending_record(
        status="approved",
        approved_by="Security Reviewer",
        approved_at="2026-08-01T16:00:00Z",
    )
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_review_transition(executor, record, {})
    assert executor.calls == []


def test_review_malformed_plan_fails():
    record = _canonical_pending_record()
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_review_transition(executor, record, {"not": "a valid plan"})
    assert executor.calls == []


def test_review_plan_id_mismatch_fails():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    forged_plan = copy.deepcopy(plan)
    forged_plan["approval_id"] = "59999999-9999-4999-8999-999999999999"
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_review_transition(executor, record, forged_plan)
    assert executor.calls == []


def test_review_from_status_mismatch_fails():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    forged_plan = copy.deepcopy(plan)
    forged_plan["from_status"] = "approved"
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_review_transition(executor, record, forged_plan)
    assert executor.calls == []


def test_review_consume_plan_fails():
    record = _canonical_pending_record()
    forged_plan = {
        "approval_id": record["id"],
        "from_status": "pending",
        "to_status": "consumed",
        "set_fields": {
            "status": "consumed",
            "consumed_by": "Someone",
            "consumed_at": "2026-08-01T17:00:00Z",
        },
    }
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_review_transition(executor, record, forged_plan)
    assert executor.calls == []


def test_review_genuine_expanded_consume_plan_rejected_before_executor():
    # Step 11 expanded the real consume-plan contract to six top-level
    # keys (approval_id, from_status, to_status, set_fields,
    # expected_investigation_id, expected_action_type). This function
    # must still reject a consume plan outright -- consumption remains
    # entirely outside its scope -- and must do so before the executor
    # is ever invoked, regardless of the plan's now-larger shape.
    approved_record = _canonical_pending_record(
        status="approved",
        approved_by="Security Reviewer",
        approved_at="2026-08-01T16:00:00Z",
    )
    genuine_consume_plan = validate_approval_transition(
        approved_record,
        {
            "transition": "consume",
            "consumed_by": "Update Case Operator",
            "expected_investigation_id": INVESTIGATION_ID,
            "expected_action_type": "update_investigation_state",
            "consumed_at": "2026-08-01T17:00:00Z",
        },
    )
    assert set(genuine_consume_plan) == {
        "approval_id", "from_status", "to_status", "set_fields",
        "expected_investigation_id", "expected_action_type",
    }

    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_review_transition(executor, approved_record, genuine_consume_plan)
    assert executor.calls == []


def test_review_no_rpc_or_consume_operation_descriptor_exists():
    # apply_approval_review_transition itself must never build an "rpc" or
    # "consume" operation descriptor -- that remains apply_approval_
    # consumption's exclusive concern (Step 16). This check is scoped to
    # apply_approval_review_transition's own function body, not the whole
    # module, since the module as a whole now legitimately contains an
    # "rpc" operation descriptor for the separate consumption function.
    tree = _module_ast()
    fn = _function_def(tree, "apply_approval_review_transition")
    operation_values = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Dict):
            for key_node, value_node in zip(node.keys, node.values):
                if (
                    isinstance(key_node, ast.Constant)
                    and key_node.value == "operation"
                    and isinstance(value_node, ast.Constant)
                ):
                    operation_values.add(value_node.value)
    assert "rpc" not in operation_values
    assert "consume" not in operation_values
    assert operation_values == {"update"}


def test_review_no_investigation_table_descriptor_exists_after_expansion():
    tree = _module_ast()
    table_values = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key_node, value_node in zip(node.keys, node.values):
                if (
                    isinstance(key_node, ast.Constant)
                    and key_node.value == "table"
                    and isinstance(value_node, ast.Constant)
                ):
                    table_values.add(value_node.value)
    assert table_values == {"approvals"}


def test_review_forged_approve_plan_fails():
    # A forged approved_at that predates requested_at cannot be
    # reproduced by recomputing through validate_approval_transition --
    # unlike swapping in a different (equally valid) reviewer name, this
    # is a genuine, detectable chronology violation.
    record = _canonical_pending_record()
    genuine_plan = _genuine_approve_plan(record)
    forged_plan = copy.deepcopy(genuine_plan)
    forged_plan["set_fields"]["approved_at"] = "2026-08-01T10:00:00Z"
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_review_transition(executor, record, forged_plan)
    assert executor.calls == []


def test_review_forged_reject_plan_fails():
    # A forged blank rejection_reason cannot be reproduced by recomputing
    # through validate_approval_transition -- it fails that validator's
    # own nonblank requirement, a genuine, detectable forgery.
    record = _canonical_pending_record()
    genuine_plan = _genuine_reject_plan(record)
    forged_plan = copy.deepcopy(genuine_plan)
    forged_plan["set_fields"]["rejection_reason"] = "   "
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_review_transition(executor, record, forged_plan)
    assert executor.calls == []


def test_review_self_approval_plan_fails():
    record = _canonical_pending_record(requested_by="Roshini Analyst")
    forged_plan = {
        "approval_id": record["id"],
        "from_status": "pending",
        "to_status": "approved",
        "set_fields": {
            "status": "approved",
            "approved_by": "Roshini Analyst",
            "approved_at": "2026-08-01T16:00:00Z",
        },
    }
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_review_transition(executor, record, forged_plan)
    assert executor.calls == []


def test_review_expired_approve_plan_fails():
    record = _canonical_pending_record(expires_at="2026-08-01T15:50:00Z")
    forged_plan = {
        "approval_id": record["id"],
        "from_status": "pending",
        "to_status": "approved",
        "set_fields": {
            "status": "approved",
            "approved_by": "Security Reviewer",
            "approved_at": "2026-08-02T00:00:00Z",
        },
    }
    executor = _RecordingExecutor(response=[_pending_row()])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_review_transition(executor, record, forged_plan)
    assert executor.calls == []


def test_review_rejection_after_expiry_succeeds():
    record = _canonical_pending_record(expires_at="2026-08-01T15:50:00Z")
    plan = _genuine_reject_plan(record, reviewed_at="2026-08-02T00:00:00Z")
    executor = _review_executor_for(record, plan)
    result = apply_approval_review_transition(executor, record, plan)
    assert result["updated_record"]["status"] == "rejected"


# ---------------------------------------------------------------------------
# apply_approval_review_transition -- descriptor
# ---------------------------------------------------------------------------


def test_review_descriptor_operation_is_update():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _review_executor_for(record, plan)
    apply_approval_review_transition(executor, record, plan)
    assert executor.calls[0]["operation"] == "update"


def test_review_descriptor_table_is_approvals():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _review_executor_for(record, plan)
    apply_approval_review_transition(executor, record, plan)
    assert executor.calls[0]["table"] == "approvals"


def test_review_descriptor_values_equal_set_fields_exactly():
    record = _canonical_pending_record()
    plan = _genuine_reject_plan(record)
    executor = _review_executor_for(record, plan)
    apply_approval_review_transition(executor, record, plan)
    assert executor.calls[0]["values"] == plan["set_fields"]


def test_review_descriptor_filters_contain_id_pending_and_seven_null_guards():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _review_executor_for(record, plan)
    apply_approval_review_transition(executor, record, plan)
    filters = executor.calls[0]["filters"]
    assert filters == {
        "id": record["id"],
        "status": "pending",
        "approved_by": None,
        "approved_at": None,
        "rejected_by": None,
        "rejected_at": None,
        "rejection_reason": None,
        "consumed_by": None,
        "consumed_at": None,
    }
    assert list(filters) == [
        "id", "status", "approved_by", "approved_at", "rejected_by",
        "rejected_at", "rejection_reason", "consumed_by", "consumed_at",
    ]


def test_review_descriptor_returning_contains_sixteen_columns_in_order():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _review_executor_for(record, plan)
    apply_approval_review_transition(executor, record, plan)
    assert executor.calls[0]["returning"] == list(_RECORD_FIELDS)


def test_review_descriptor_has_no_unrelated_filter_or_metadata():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _review_executor_for(record, plan)
    apply_approval_review_transition(executor, record, plan)
    operation = executor.calls[0]
    assert "limit" not in operation
    assert "row_count" not in operation
    assert "expected_count" not in operation
    assert "investigation_id" not in operation["filters"]
    assert "action_type" not in operation["filters"]
    assert "expires_at" not in operation["filters"]


# ---------------------------------------------------------------------------
# apply_approval_review_transition -- response
# ---------------------------------------------------------------------------


def test_review_zero_rows_raises_conflict():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _RecordingExecutor(response=[])
    with pytest.raises(ApprovalConflictError):
        apply_approval_review_transition(executor, record, plan)


def test_review_no_retry_on_conflict():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _RecordingExecutor(response=[])
    with pytest.raises(ApprovalConflictError):
        apply_approval_review_transition(executor, record, plan)
    assert len(executor.calls) == 1


def test_review_multiple_rows_fail():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    row = _apply_set_fields(record, plan["set_fields"])
    executor = _RecordingExecutor(response=[row, copy.deepcopy(row)])
    with pytest.raises(ApprovalResponseError):
        apply_approval_review_transition(executor, record, plan)


@pytest.mark.parametrize("response", [None, {"id": APPROVAL_ID}, (1, 2), "not-a-list"])
def test_review_malformed_response_fails(response):
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _RecordingExecutor(response=response)
    with pytest.raises(ApprovalResponseError):
        apply_approval_review_transition(executor, record, plan)


def test_review_nullable_keys_restore_correctly():
    record = _canonical_pending_record()
    plan = _genuine_reject_plan(record)
    row = _apply_set_fields(record, plan["set_fields"])
    del row["consumed_by"]
    del row["consumed_at"]
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_review_transition(executor, record, plan)
    assert result["updated_record"]["consumed_by"] is None
    assert result["updated_record"]["consumed_at"] is None


@pytest.mark.parametrize(
    "field_name,new_value",
    [
        ("investigation_id", "42222222-2222-4222-8222-222222222222"),
        ("requested_by", "Someone Else"),
        ("requested_at", "2026-08-01T16:00:00Z"),
        ("action_payload", {"status": "escalated", "confidence": "low"}),
        ("expires_at", "2026-08-05T00:00:00Z"),
        ("created_at", "2026-08-01T15:47:00Z"),
        ("id", "59999999-9999-4999-8999-999999999999"),
    ],
)
def test_review_changed_frozen_field_fails(field_name, new_value):
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    row = _apply_set_fields(record, plan["set_fields"])
    row[field_name] = new_value
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_review_transition(executor, record, plan)


def test_review_wrong_final_status_fails():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    row = _apply_set_fields(record, plan["set_fields"])
    row["status"] = "rejected"
    row["approved_by"] = None
    row["approved_at"] = None
    row["rejected_by"] = "Security Reviewer"
    row["rejected_at"] = plan["set_fields"]["approved_at"]
    row["rejection_reason"] = "Some other reason entirely."
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_review_transition(executor, record, plan)


def test_review_wrong_lifecycle_metadata_fails():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    row = _apply_set_fields(record, plan["set_fields"])
    row["approved_by"] = "Someone Completely Different"
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_review_transition(executor, record, plan)


# ---------------------------------------------------------------------------
# apply_approval_review_transition -- redaction
# ---------------------------------------------------------------------------


def test_review_transport_error_exposes_no_raw_exception():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    secret_message = "connection failed: postgres://user:hunter2@db.internal/prod"
    executor = _RecordingExecutor(raises=RuntimeError(secret_message))
    with pytest.raises(ApprovalTransportError) as excinfo:
        apply_approval_review_transition(executor, record, plan)
    message = str(excinfo.value)
    assert secret_message not in message
    assert "RuntimeError" not in message
    assert excinfo.value.__cause__ is None


def test_review_conflict_error_exposes_no_record_or_plan():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    executor = _RecordingExecutor(response=[])
    with pytest.raises(ApprovalConflictError) as excinfo:
        apply_approval_review_transition(executor, record, plan)
    message = str(excinfo.value)
    assert record["requested_by"] not in message
    assert plan["set_fields"]["approved_by"] not in message


def test_review_response_error_exposes_no_row_or_secrets():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    secret_marker = "top-secret-review-marker"
    row = _apply_set_fields(record, plan["set_fields"])
    row["approved_by"] = secret_marker
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError) as excinfo:
        apply_approval_review_transition(executor, record, plan)
    assert secret_marker not in str(excinfo.value)


# ---------------------------------------------------------------------------
# apply_approval_review_transition -- non-mutation and independence
# ---------------------------------------------------------------------------


def test_review_inputs_and_response_unchanged():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    before_record = copy.deepcopy(record)
    before_plan = copy.deepcopy(plan)
    row = _apply_set_fields(record, plan["set_fields"])
    response = [row]
    before_response = copy.deepcopy(response)
    executor = _RecordingExecutor(response=response)
    apply_approval_review_transition(executor, record, plan)
    assert record == before_record
    assert plan == before_plan
    assert response == before_response


def test_review_returned_objects_are_independent():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    row = _apply_set_fields(record, plan["set_fields"])
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_review_transition(executor, record, plan)
    assert result["transition_plan"] is not plan
    assert result["transition_plan"]["set_fields"] is not plan["set_fields"]
    assert result["updated_record"] is not row
    assert result["updated_record"]["action_payload"] is not row["action_payload"]


def test_review_hostile_executor_mutation_cannot_alter_inputs():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    row = _apply_set_fields(record, plan["set_fields"])

    def _hostile(operation):
        operation["values"]["approved_by"] = "HACKED"
        operation["filters"]["id"] = "hacked"
        return [row]

    apply_approval_review_transition(_hostile, record, plan)
    assert plan["set_fields"]["approved_by"] != "HACKED"
    assert record["id"] != "hacked"


def test_review_separate_calls_share_no_mutable_state():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    row = _apply_set_fields(record, plan["set_fields"])

    executor_one = _RecordingExecutor(response=[copy.deepcopy(row)])
    executor_two = _RecordingExecutor(response=[copy.deepcopy(row)])

    result_one = apply_approval_review_transition(executor_one, record, plan)
    result_two = apply_approval_review_transition(executor_two, record, plan)

    assert result_one == result_two
    assert result_one["updated_record"] is not result_two["updated_record"]


# ---------------------------------------------------------------------------
# apply_approval_review_transition -- runtime and source boundaries
# ---------------------------------------------------------------------------


def test_review_no_concrete_supabase_import():
    tree = _module_ast()
    imports = _top_level_imports(tree)
    assert not any(name == "supabase" or name.startswith("supabase.") for name in imports)


def test_review_works_under_runtime_guards(monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called")

    monkeypatch.setattr("builtins.open", _forbidden)
    monkeypatch.setattr(Path, "open", _forbidden)
    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)

    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    row = _apply_set_fields(record, plan["set_fields"])
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_review_transition(executor, record, plan)
    assert result["updated_record"]["status"] == "approved"


def test_review_no_consume_descriptor_ever_built():
    # Scoped to apply_approval_review_transition's own function body --
    # the module as a whole now legitimately contains the literal string
    # "consume" inside apply_approval_consumption's genuine-plan
    # reconstruction (Step 16), which is a wholly separate function.
    tree = _module_ast()
    fn = _function_def(tree, "apply_approval_review_transition")
    string_constants = {
        node.value
        for node in ast.walk(fn)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert "consume" not in string_constants


def test_review_no_investigation_table_descriptor():
    tree = _module_ast()
    table_values = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key_node, value_node in zip(node.keys, node.values):
                if (
                    isinstance(key_node, ast.Constant)
                    and key_node.value == "table"
                    and isinstance(value_node, ast.Constant)
                ):
                    table_values.add(value_node.value)
    assert table_values == {"approvals"}


def test_review_no_transaction_or_rpc_keyword():
    tree = _module_ast()
    identifiers = _referenced_identifiers(tree)
    for forbidden in ("transaction", "rpc", "begin", "commit", "rollback"):
        assert forbidden not in identifiers


def test_review_no_update_case_hashing_auth_or_containment():
    source = _module_source_text()
    assert "/update-case" not in source
    tree = _module_ast()
    identifiers = _referenced_identifiers(tree)
    for forbidden in ("hash", "auth", "authenticate", "containment"):
        assert forbidden not in identifiers


# ---------------------------------------------------------------------------
# apply_approval_consumption -- fixtures
# ---------------------------------------------------------------------------

APPROVED_AT = "2026-08-01T16:00:00Z"
CONSUMED_AT = "2026-08-01T17:00:00Z"


def _canonical_approved_record(**overrides):
    record = _pending_row(
        status="approved",
        approved_by="Security Reviewer",
        approved_at=APPROVED_AT,
    )
    record.update(overrides)
    return record


def _genuine_consume_plan(
    current_record,
    consumed_by="Update Case Operator",
    consumed_at=CONSUMED_AT,
    expected_investigation_id=None,
    expected_action_type="update_investigation_state",
):
    request = {
        "transition": "consume",
        "consumed_by": consumed_by,
        "expected_investigation_id": (
            expected_investigation_id if expected_investigation_id is not None else current_record["investigation_id"]
        ),
        "expected_action_type": expected_action_type,
    }
    if consumed_at is not None:
        request["consumed_at"] = consumed_at
    return validate_approval_transition(current_record, request)


def _consumption_row_for(
    record,
    plan,
    *,
    investigation_status=None,
    investigation_confidence=None,
    investigation_updated_at=CONSUMED_AT,
):
    approval_row = _apply_set_fields(record, plan["set_fields"])
    payload = record["action_payload"]
    row = dict(approval_row)
    row["investigation_status"] = (
        investigation_status if investigation_status is not None else payload.get("status", "escalated")
    )
    row["investigation_confidence"] = (
        investigation_confidence if investigation_confidence is not None else payload.get("confidence", "high")
    )
    row["investigation_updated_at"] = investigation_updated_at
    return row


def _consumption_executor_for(record, plan, *, row_override=None):
    response = row_override if row_override is not None else [_consumption_row_for(record, plan)]
    return _RecordingExecutor(response=response)


# ---------------------------------------------------------------------------
# apply_approval_consumption -- public contract
# ---------------------------------------------------------------------------


def test_consume_function_exists_and_is_callable():
    assert callable(apply_approval_consumption)


def test_consume_signature_has_exactly_three_required_parameters():
    signature = inspect.signature(apply_approval_consumption)
    parameters = signature.parameters
    assert list(parameters) == ["executor", "current_record", "transition_plan"]
    for name in parameters:
        assert parameters[name].default is inspect.Parameter.empty


def test_consume_no_transition_request_now_or_replacement_value_parameter():
    signature = inspect.signature(apply_approval_consumption)
    for forbidden in ("transition_request", "now", "status", "confidence", "action_payload", "investigation_record"):
        assert forbidden not in signature.parameters


def test_consume_required_docstring_phrase_exists():
    assert (
        "Verified atomic approval consumption -- approval and investigation changed together"
        in apply_approval_consumption.__doc__
    )


def test_consume_no_new_exception_class_introduced():
    tree = _module_ast()
    defined_classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    assert set(defined_classes) == {
        "ApprovalExecutor",
        "ApprovalPersistenceError",
        "ApprovalNotFoundError",
        "ApprovalResponseError",
        "ApprovalTransportError",
        "ApprovalConflictError",
    }


# ---------------------------------------------------------------------------
# apply_approval_consumption -- current approved record
# ---------------------------------------------------------------------------


def test_consume_canonical_approved_record_succeeds():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert result["updated_record"]["status"] == "consumed"


def test_consume_non_mapping_record_fails():
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, ["not", "a", "mapping"], {})
    assert executor.calls == []


def test_consume_missing_record_field_fails():
    record = _canonical_approved_record()
    del record["created_at"]
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, {})
    assert executor.calls == []


def test_consume_unknown_record_field_fails():
    record = _canonical_approved_record(extra_field="unexpected")
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, {})
    assert executor.calls == []


def test_consume_noncanonical_approval_id_fails():
    record = _canonical_approved_record(id=APPROVAL_ID.upper())
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, {})
    assert executor.calls == []


def test_consume_noncanonical_investigation_id_fails():
    record = _canonical_approved_record(investigation_id=INVESTIGATION_ID.upper())
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, {})
    assert executor.calls == []


def test_consume_noncanonical_record_timestamp_fails():
    record = _canonical_approved_record(approved_at="2026-08-01T16:00:00+00:00")
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, {})
    assert executor.calls == []


def test_consume_pending_record_fails():
    record = _canonical_pending_record()
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, {})
    assert executor.calls == []


def test_consume_rejected_record_fails():
    record = _canonical_pending_record(
        status="rejected",
        rejected_by="Security Reviewer",
        rejected_at=APPROVED_AT,
        rejection_reason="Needs more evidence before approval.",
    )
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, {})
    assert executor.calls == []


def test_consume_already_consumed_record_fails():
    record = _canonical_approved_record(
        status="consumed",
        consumed_by="Update Case Operator",
        consumed_at=CONSUMED_AT,
    )
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, {})
    assert executor.calls == []


def test_consume_record_validator_called_exactly_once(monkeypatch):
    call_count = 0
    real = approval_persistence.validate_approval_record

    def _counting_wrapper(current_record):
        nonlocal call_count
        call_count += 1
        return real(current_record)

    monkeypatch.setattr(approval_persistence, "validate_approval_record", _counting_wrapper)

    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)

    # validate_approval_record is called once for the current-record
    # boundary, once for the expected-consumed-record candidate, and once
    # for the returned response row -- three calls total, never zero.
    assert call_count == 3


def test_consume_approval_transition_error_never_escapes():
    record = _canonical_pending_record()
    executor = _RecordingExecutor(response=[{}])
    try:
        apply_approval_consumption(executor, record, {})
        pytest.fail("expected ApprovalPersistenceError")
    except ApprovalTransitionError:
        pytest.fail("ApprovalTransitionError must never escape apply_approval_consumption")
    except ApprovalPersistenceError:
        pass


# ---------------------------------------------------------------------------
# apply_approval_consumption -- consume-plan envelope
# ---------------------------------------------------------------------------


def test_consume_genuine_six_field_plan_succeeds():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    assert list(plan.keys()) == [
        "approval_id", "from_status", "to_status", "set_fields",
        "expected_investigation_id", "expected_action_type",
    ]
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert result["updated_record"]["status"] == "consumed"


def test_consume_non_mapping_plan_fails():
    record = _canonical_approved_record()
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, ["not", "a", "mapping"])
    assert executor.calls == []


def test_consume_old_four_field_consume_plan_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    old_shaped_plan = {
        "approval_id": plan["approval_id"],
        "from_status": plan["from_status"],
        "to_status": plan["to_status"],
        "set_fields": plan["set_fields"],
    }
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, old_shaped_plan)
    assert executor.calls == []


@pytest.mark.parametrize(
    "missing_field",
    ["approval_id", "from_status", "to_status", "set_fields", "expected_investigation_id", "expected_action_type"],
)
def test_consume_missing_envelope_field_fails(missing_field):
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    del plan[missing_field]
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_unknown_plan_field_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["extra_metadata"] = "unexpected"
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_reordered_plan_accepted():
    # Step 39: mapping insertion order is never part of the security
    # contract -- a genuine plan's top-level keys, reordered exactly as
    # they are after round-tripping through core.approval_transition_cli's
    # own sort_keys=True JSON output, must still be accepted. Only key
    # membership and values are checked, never insertion order.
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    reordered_plan = {
        "from_status": plan["from_status"],
        "approval_id": plan["approval_id"],
        "to_status": plan["to_status"],
        "set_fields": plan["set_fields"],
        "expected_investigation_id": plan["expected_investigation_id"],
        "expected_action_type": plan["expected_action_type"],
    }
    executor = _consumption_executor_for(record, reordered_plan)
    result = apply_approval_consumption(executor, record, reordered_plan)
    assert result["updated_record"]["status"] == "consumed"


def test_consume_approve_plan_fails():
    record = _canonical_approved_record()
    pending_record = _canonical_pending_record()
    approve_plan = _genuine_approve_plan(pending_record)
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, approve_plan)
    assert executor.calls == []


def test_consume_reject_plan_fails():
    record = _canonical_approved_record()
    pending_record = _canonical_pending_record()
    reject_plan = _genuine_reject_plan(pending_record)
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, reject_plan)
    assert executor.calls == []


def test_consume_noncanonical_approval_id_in_plan_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["approval_id"] = f" {plan['approval_id']} "
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_approval_id_mismatch_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["approval_id"] = "59999999-9999-4999-8999-999999999999"
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_from_status_other_than_approved_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["from_status"] = "pending"
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_to_status_other_than_consumed_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["to_status"] = "approved"
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_noncanonical_expected_investigation_id_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["expected_investigation_id"] = f" {plan['expected_investigation_id']} "
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_investigation_binding_mismatch_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["expected_investigation_id"] = "59999999-9999-4999-8999-999999999999"
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_noncanonical_expected_action_type_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["expected_action_type"] = "UPDATE_INVESTIGATION_STATE"
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_action_type_mismatch_fails(monkeypatch):
    import core.approval_request as approval_request_module
    import core.approval_transition as approval_transition_module

    broadened = frozenset({"update_investigation_state", "fake_other_action"})
    monkeypatch.setattr(approval_request_module, "ACTION_TYPES", broadened)
    monkeypatch.setattr(approval_transition_module, "ACTION_TYPES", broadened)

    record = _canonical_approved_record(action_type="fake_other_action")
    # Build a genuine plan matching this record's own action_type first
    # (a real mismatch cannot be validator-constructed directly), then
    # forge only the top-level expected_action_type field afterward.
    genuine_plan = _genuine_consume_plan(record, expected_action_type="fake_other_action")
    forged_plan = dict(genuine_plan)
    forged_plan["expected_action_type"] = "update_investigation_state"
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, forged_plan)
    assert executor.calls == []


def test_consume_unsupported_action_type_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["expected_action_type"] = "delete_everything"
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


# ---------------------------------------------------------------------------
# apply_approval_consumption -- set_fields
# ---------------------------------------------------------------------------


def test_consume_set_fields_exact_three_key_shape_required():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    assert set(plan["set_fields"].keys()) == {"status", "consumed_by", "consumed_at"}


def test_consume_set_fields_reordered_accepted():
    # Step 39: same principle applied to the nested set_fields mapping --
    # a genuine plan's set_fields, reordered, must still be accepted.
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    reordered_set_fields = {
        "consumed_by": plan["set_fields"]["consumed_by"],
        "status": plan["set_fields"]["status"],
        "consumed_at": plan["set_fields"]["consumed_at"],
    }
    plan["set_fields"] = reordered_set_fields
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert result["updated_record"]["status"] == "consumed"


def test_consume_set_fields_status_must_equal_consumed():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["set_fields"] = {**plan["set_fields"], "status": "approved"}
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_set_fields_missing_consumed_by_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["set_fields"] = {"status": "consumed", "consumed_at": plan["set_fields"]["consumed_at"]}
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_set_fields_missing_consumed_at_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["set_fields"] = {"status": "consumed", "consumed_by": plan["set_fields"]["consumed_by"]}
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_set_fields_unknown_field_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["set_fields"] = {**plan["set_fields"], "unexpected": "value"}
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_set_fields_binding_field_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["set_fields"] = {**plan["set_fields"], "expected_investigation_id": record["investigation_id"]}
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_set_fields_investigation_field_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["set_fields"] = {**plan["set_fields"], "investigation_status": "escalated"}
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_set_fields_approval_field_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["set_fields"] = {**plan["set_fields"], "approved_by": "Security Reviewer"}
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_set_fields_rejection_field_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["set_fields"] = {**plan["set_fields"], "rejection_reason": "Some reason"}
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


def test_consume_set_fields_persistence_metadata_fails():
    record = _canonical_approved_record()
    plan = dict(_genuine_consume_plan(record))
    plan["set_fields"] = {**plan["set_fields"], "row_count": 1}
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, plan)
    assert executor.calls == []


# ---------------------------------------------------------------------------
# apply_approval_consumption -- genuine-plan verification
# ---------------------------------------------------------------------------


def test_consume_validate_approval_transition_called_exactly_once(monkeypatch):
    call_count = 0
    real = approval_persistence.validate_approval_transition

    def _counting_wrapper(current_record, transition_request):
        nonlocal call_count
        call_count += 1
        return real(current_record, transition_request)

    monkeypatch.setattr(approval_persistence, "validate_approval_transition", _counting_wrapper)

    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)

    assert call_count == 1


def test_consume_reconstructed_request_has_exactly_five_fields(monkeypatch):
    captured = {}
    real = approval_persistence.validate_approval_transition

    def _capturing_wrapper(current_record, transition_request):
        captured["transition_request"] = transition_request
        return real(current_record, transition_request)

    monkeypatch.setattr(approval_persistence, "validate_approval_transition", _capturing_wrapper)

    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)

    assert set(captured["transition_request"].keys()) == {
        "transition", "consumed_by", "consumed_at", "expected_investigation_id", "expected_action_type",
    }


def test_consume_reconstructed_request_values_match_the_plan(monkeypatch):
    captured = {}
    real = approval_persistence.validate_approval_transition

    def _capturing_wrapper(current_record, transition_request):
        captured["transition_request"] = transition_request
        return real(current_record, transition_request)

    monkeypatch.setattr(approval_persistence, "validate_approval_transition", _capturing_wrapper)

    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)

    request = captured["transition_request"]
    assert request["transition"] == "consume"
    assert request["consumed_by"] == plan["set_fields"]["consumed_by"]
    assert request["consumed_at"] == plan["set_fields"]["consumed_at"]
    assert request["expected_investigation_id"] == plan["expected_investigation_id"]
    assert request["expected_action_type"] == plan["expected_action_type"]


def test_consume_forged_consumed_by_fails():
    record = _canonical_approved_record()
    genuine_plan = _genuine_consume_plan(record)
    forged_plan = copy.deepcopy(genuine_plan)
    forged_plan["set_fields"]["consumed_by"] = "   "
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, forged_plan)
    assert executor.calls == []


def test_consume_forged_consumed_at_fails():
    record = _canonical_approved_record()
    genuine_plan = _genuine_consume_plan(record)
    forged_plan = copy.deepcopy(genuine_plan)
    forged_plan["set_fields"]["consumed_at"] = "2026-08-01T10:00:00Z"
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, forged_plan)
    assert executor.calls == []


def test_consume_expired_consume_plan_fails():
    record = _canonical_approved_record(expires_at="2026-08-01T16:30:00Z")
    genuine_plan_at_valid_time = _genuine_consume_plan(record, consumed_at="2026-08-01T16:15:00Z")
    forged_plan = copy.deepcopy(genuine_plan_at_valid_time)
    forged_plan["set_fields"]["consumed_at"] = "2026-08-02T00:00:00Z"
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, forged_plan)
    assert executor.calls == []


def test_consume_consumed_at_before_approved_at_fails():
    record = _canonical_approved_record()
    genuine_plan = _genuine_consume_plan(record)
    forged_plan = copy.deepcopy(genuine_plan)
    forged_plan["set_fields"]["consumed_at"] = "2026-08-01T10:00:00Z"
    executor = _RecordingExecutor(response=[{}])
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, forged_plan)
    assert executor.calls == []


def test_consume_consumed_at_exactly_at_expiry_fails():
    record = _canonical_approved_record(expires_at=CONSUMED_AT)
    with pytest.raises(ApprovalTransitionError):
        _genuine_consume_plan(record)


def test_consume_same_principal_consumption_remains_allowed():
    record = _canonical_approved_record(requested_by="Roshini Analyst", approved_by="Security Reviewer")
    plan = _genuine_consume_plan(record, consumed_by="Roshini Analyst")
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert result["updated_record"]["consumed_by"] == "Roshini Analyst"


def test_consume_validator_generated_plan_is_accepted_unchanged():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert result["transition_plan"] == plan


# ---------------------------------------------------------------------------
# apply_approval_consumption -- expected consumed record
# ---------------------------------------------------------------------------


def test_consume_expected_record_status_is_consumed():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert result["updated_record"]["status"] == "consumed"


def test_consume_expected_record_consumed_by_matches():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert result["updated_record"]["consumed_by"] == plan["set_fields"]["consumed_by"]


def test_consume_expected_record_consumed_at_matches():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert result["updated_record"]["consumed_at"] == plan["set_fields"]["consumed_at"]


def test_consume_expected_record_approval_metadata_unchanged():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert result["updated_record"]["approved_by"] == record["approved_by"]
    assert result["updated_record"]["approved_at"] == record["approved_at"]


def test_consume_expected_record_rejection_fields_remain_null():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert result["updated_record"]["rejected_by"] is None
    assert result["updated_record"]["rejected_at"] is None
    assert result["updated_record"]["rejection_reason"] is None


def test_consume_expected_record_frozen_request_fields_unchanged():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    updated = result["updated_record"]
    for field_name in ("id", "investigation_id", "action_type", "requested_by", "requested_at"):
        assert updated[field_name] == record[field_name]


def test_consume_expected_record_expires_at_unchanged():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert result["updated_record"]["expires_at"] == record["expires_at"]


def test_consume_expected_record_created_at_unchanged():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert result["updated_record"]["created_at"] == record["created_at"]


def test_consume_expected_record_action_payload_unchanged():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert result["updated_record"]["action_payload"] == record["action_payload"]


def test_consume_expected_candidate_validated_exactly_once(monkeypatch):
    call_count = 0
    real = approval_persistence.validate_approval_record

    def _counting_wrapper(current_record):
        nonlocal call_count
        call_count += 1
        return real(current_record)

    monkeypatch.setattr(approval_persistence, "validate_approval_record", _counting_wrapper)

    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)

    assert call_count == 3


# ---------------------------------------------------------------------------
# apply_approval_consumption -- RPC descriptor
# ---------------------------------------------------------------------------


def test_consume_executor_called_exactly_once():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)
    assert len(executor.calls) == 1


def test_consume_operation_equals_rpc():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)
    assert executor.calls[0]["operation"] == "rpc"


def test_consume_function_name_is_exact():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)
    assert executor.calls[0]["function"] == "consume_approval_and_update_investigation_state"


def test_consume_descriptor_contains_exactly_operation_function_parameters():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)
    assert set(executor.calls[0]) == {"operation", "function", "parameters"}


def test_consume_parameters_contain_exactly_five_fields_in_order():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)
    parameters = executor.calls[0]["parameters"]
    assert list(parameters.keys()) == [
        "approval_id", "expected_investigation_id", "expected_action_type", "consumed_by", "consumed_at",
    ]


def test_consume_parameter_values_are_exact():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)
    parameters = executor.calls[0]["parameters"]
    assert parameters["approval_id"] == plan["approval_id"]
    assert parameters["expected_investigation_id"] == plan["expected_investigation_id"]
    assert parameters["expected_action_type"] == plan["expected_action_type"]
    assert parameters["consumed_by"] == plan["set_fields"]["consumed_by"]
    assert parameters["consumed_at"] == plan["set_fields"]["consumed_at"]


@pytest.mark.parametrize(
    "forbidden_key",
    ["table", "values", "filters", "returning", "limit", "current_record", "transition_plan", "row_count"],
)
def test_consume_descriptor_excludes_forbidden_top_level_keys(forbidden_key):
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)
    assert forbidden_key not in executor.calls[0]


@pytest.mark.parametrize(
    "forbidden_parameter",
    ["status", "confidence", "action_payload", "requested_by", "approved_by", "auth_token", "action_hash"],
)
def test_consume_parameters_exclude_forbidden_fields(forbidden_parameter):
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)
    assert forbidden_parameter not in executor.calls[0]["parameters"]


# ---------------------------------------------------------------------------
# apply_approval_consumption -- conflict
# ---------------------------------------------------------------------------


def test_consume_zero_rows_raises_conflict():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _RecordingExecutor(response=[])
    with pytest.raises(ApprovalConflictError):
        apply_approval_consumption(executor, record, plan)


def test_consume_conflict_message_is_deterministic():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _RecordingExecutor(response=[])
    with pytest.raises(ApprovalConflictError) as excinfo:
        apply_approval_consumption(executor, record, plan)
    assert str(excinfo.value) == "Approval consumption conflicted."


def test_consume_conflict_exposes_no_approval_id():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _RecordingExecutor(response=[])
    with pytest.raises(ApprovalConflictError) as excinfo:
        apply_approval_consumption(executor, record, plan)
    assert plan["approval_id"] not in str(excinfo.value)


def test_consume_conflict_exposes_no_identity():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _RecordingExecutor(response=[])
    with pytest.raises(ApprovalConflictError) as excinfo:
        apply_approval_consumption(executor, record, plan)
    assert plan["set_fields"]["consumed_by"] not in str(excinfo.value)


def test_consume_conflict_exposes_no_binding():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _RecordingExecutor(response=[])
    with pytest.raises(ApprovalConflictError) as excinfo:
        apply_approval_consumption(executor, record, plan)
    assert plan["expected_investigation_id"] not in str(excinfo.value)


def test_consume_conflict_executor_called_exactly_once():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _RecordingExecutor(response=[])
    with pytest.raises(ApprovalConflictError):
        apply_approval_consumption(executor, record, plan)
    assert len(executor.calls) == 1


def test_consume_conflict_no_load_after_conflict_occurs():
    tree = _module_ast()
    fn = _function_def(tree, "apply_approval_consumption")
    called = {
        node.func.id
        for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "load_approval_record" not in called


def test_consume_conflict_is_not_approval_not_found_error():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _RecordingExecutor(response=[])
    try:
        apply_approval_consumption(executor, record, plan)
        pytest.fail("expected ApprovalConflictError")
    except ApprovalNotFoundError:
        pytest.fail("ApprovalNotFoundError must never be raised by apply_approval_consumption")
    except ApprovalConflictError:
        pass


# ---------------------------------------------------------------------------
# apply_approval_consumption -- response shape
# ---------------------------------------------------------------------------


def test_consume_exactly_one_nineteen_field_row_succeeds():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    assert len(row) == 19
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_consumption(executor, record, plan)
    assert result["updated_record"]["status"] == "consumed"


@pytest.mark.parametrize("response", [None, {"id": APPROVAL_ID}, (1, 2), "not-a-list"])
def test_consume_malformed_response_shape_fails(response):
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _RecordingExecutor(response=response)
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_generator_response_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)

    def _generator():
        yield row

    executor = _RecordingExecutor(response=_generator())
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_multiple_rows_fail():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    executor = _RecordingExecutor(response=[row, copy.deepcopy(row)])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_non_mapping_row_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _RecordingExecutor(response=["not-a-mapping"])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


@pytest.mark.parametrize(
    "missing_field", ["id", "investigation_id", "action_type", "requested_by", "requested_at", "status", "created_at"]
)
def test_consume_missing_required_approval_field_fails(missing_field):
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    del row[missing_field]
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_missing_investigation_status_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    del row["investigation_status"]
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_missing_investigation_confidence_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    del row["investigation_confidence"]
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_missing_investigation_updated_at_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    del row["investigation_updated_at"]
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_unknown_row_field_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    row["unexpected_field"] = "value"
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_nullable_approval_fields_restored_as_none():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    del row["rejected_by"]
    del row["rejection_reason"]
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_consumption(executor, record, plan)
    assert result["updated_record"]["rejected_by"] is None
    assert result["updated_record"]["rejection_reason"] is None


def test_consume_response_errors_do_not_return_partial_output():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    row["unexpected_field"] = "value"
    executor = _RecordingExecutor(response=[row])
    try:
        result = apply_approval_consumption(executor, record, plan)
        pytest.fail(f"expected ApprovalResponseError, got a result: {result!r}")
    except ApprovalResponseError:
        pass


# ---------------------------------------------------------------------------
# apply_approval_consumption -- returned approval verification
# ---------------------------------------------------------------------------


def test_consume_returned_approval_validated_exactly_once(monkeypatch):
    call_count = 0
    real = approval_persistence.validate_approval_record

    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)

    def _counting_wrapper(current_record):
        nonlocal call_count
        call_count += 1
        return real(current_record)

    monkeypatch.setattr(approval_persistence, "validate_approval_record", _counting_wrapper)
    executor = _RecordingExecutor(response=[row])
    apply_approval_consumption(executor, record, plan)

    assert call_count == 3


def test_consume_returned_record_equals_expected_record():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_consumption(executor, record, plan)
    expected_approval_portion = {key: row[key] for key in _RECORD_FIELDS}
    assert result["updated_record"] == expected_approval_portion


@pytest.mark.parametrize(
    "field_name,new_value",
    [
        ("id", "59999999-9999-4999-8999-999999999999"),
        ("investigation_id", "42222222-2222-4222-8222-222222222222"),
        ("requested_by", "Someone Else"),
        ("requested_at", "2026-08-01T16:00:00Z"),
        ("action_payload", {"status": "escalated", "confidence": "low"}),
        ("approved_by", "Someone Completely Different"),
        ("approved_at", "2026-08-01T15:50:00Z"),
        ("expires_at", "2026-08-05T00:00:00Z"),
        ("consumed_by", "Someone Else Entirely"),
        ("consumed_at", "2026-08-01T18:00:00Z"),
        ("created_at", "2026-08-01T15:47:00Z"),
    ],
)
def test_consume_changed_frozen_or_lifecycle_field_fails(field_name, new_value):
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    row[field_name] = new_value
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_changed_action_type_fails(monkeypatch):
    import core.approval_request as approval_request_module

    monkeypatch.setattr(
        approval_request_module, "ACTION_TYPES", frozenset({"update_investigation_state", "fake_other_action"})
    )
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    row["action_type"] = "fake_other_action"
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_wrong_status_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    row["status"] = "approved"
    row["consumed_by"] = None
    row["consumed_at"] = None
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_unexpected_rejection_metadata_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    row["status"] = "rejected"
    row["rejected_by"] = "Security Reviewer"
    row["rejected_at"] = APPROVED_AT
    row["rejection_reason"] = "Some other reason entirely."
    row["approved_by"] = None
    row["approved_at"] = None
    row["consumed_by"] = None
    row["consumed_at"] = None
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_returned_approval_transition_error_never_escapes():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    row["rejected_by"] = "Security Reviewer"
    executor = _RecordingExecutor(response=[row])
    try:
        apply_approval_consumption(executor, record, plan)
        pytest.fail("expected ApprovalResponseError")
    except ApprovalTransitionError:
        pytest.fail("ApprovalTransitionError must never escape apply_approval_consumption")
    except ApprovalResponseError:
        pass


# ---------------------------------------------------------------------------
# apply_approval_consumption -- investigation result
# ---------------------------------------------------------------------------


def test_consume_valid_status_succeeds():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_status="escalated")
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_consumption(executor, record, plan)
    assert result["investigation_result"]["status"] == "escalated"


def test_consume_valid_confidence_succeeds():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_confidence="high")
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_consumption(executor, record, plan)
    assert result["investigation_result"]["confidence"] == "high"


def test_consume_aware_updated_at_succeeds():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_updated_at="2026-08-01T17:00:00Z")
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_consumption(executor, record, plan)
    assert result["investigation_result"]["updated_at"] == "2026-08-01T17:00:00Z"


def test_consume_offset_updated_at_canonicalizes_to_utc_z():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_updated_at="2026-08-01T12:00:00-05:00")
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_consumption(executor, record, plan)
    assert result["investigation_result"]["updated_at"] == "2026-08-01T17:00:00Z"


def test_consume_aware_datetime_updated_at_succeeds():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    dt = datetime(2026, 8, 1, 17, 0, 0, tzinfo=timezone.utc)
    row = _consumption_row_for(record, plan, investigation_updated_at=dt)
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_consumption(executor, record, plan)
    assert result["investigation_result"]["updated_at"] == "2026-08-01T17:00:00Z"


def test_consume_naive_updated_at_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_updated_at="2026-08-01T17:00:00")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_malformed_updated_at_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_updated_at="not-a-timestamp")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_blank_status_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_status="   ")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_padded_status_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_status=" escalated")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_unknown_status_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_status="not-a-real-status")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_non_string_status_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_status=12345)
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_blank_confidence_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_confidence="   ")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_padded_confidence_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_confidence=" high")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_unknown_confidence_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_confidence="extreme")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_non_string_confidence_fails():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_confidence=99)
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_returned_investigation_id_equals_expected_binding():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert result["investigation_result"]["investigation_id"] == plan["expected_investigation_id"]


def test_consume_public_result_key_order_is_exact():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert list(result.keys()) == ["transition_plan", "updated_record", "investigation_result"]
    assert list(result["investigation_result"].keys()) == ["investigation_id", "status", "confidence", "updated_at"]


def test_consume_public_result_uses_status_confidence_updated_at_names():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    investigation_result = result["investigation_result"]
    assert "status" in investigation_result
    assert "confidence" in investigation_result
    assert "updated_at" in investigation_result


def test_consume_raw_investigation_prefixed_keys_not_returned_publicly():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    investigation_result = result["investigation_result"]
    assert "investigation_status" not in investigation_result
    assert "investigation_confidence" not in investigation_result
    assert "investigation_updated_at" not in investigation_result


# ---------------------------------------------------------------------------
# apply_approval_consumption -- stored-action binding
# ---------------------------------------------------------------------------


def test_consume_status_only_payload_requires_matching_returned_status():
    record = _canonical_approved_record(action_payload={"status": "escalated"})
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_status="escalated", investigation_confidence="unknown")
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_consumption(executor, record, plan)
    assert result["investigation_result"]["status"] == "escalated"


def test_consume_status_only_payload_permits_any_valid_returned_confidence():
    record = _canonical_approved_record(action_payload={"status": "escalated"})
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_status="escalated", investigation_confidence="medium")
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_consumption(executor, record, plan)
    assert result["investigation_result"]["confidence"] == "medium"


def test_consume_confidence_only_payload_requires_matching_returned_confidence():
    record = _canonical_approved_record(action_payload={"confidence": "high"})
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_status="investigating", investigation_confidence="high")
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_consumption(executor, record, plan)
    assert result["investigation_result"]["confidence"] == "high"


def test_consume_confidence_only_payload_permits_any_valid_returned_status():
    record = _canonical_approved_record(action_payload={"confidence": "high"})
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_status="closed", investigation_confidence="high")
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_consumption(executor, record, plan)
    assert result["investigation_result"]["status"] == "closed"


def test_consume_status_and_confidence_payload_requires_both_exact_matches():
    record = _canonical_approved_record(action_payload={"status": "escalated", "confidence": "high"})
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_status="escalated", investigation_confidence="high")
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_consumption(executor, record, plan)
    assert result["investigation_result"]["status"] == "escalated"
    assert result["investigation_result"]["confidence"] == "high"


def test_consume_mismatched_stored_status_fails():
    record = _canonical_approved_record(action_payload={"status": "escalated", "confidence": "high"})
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_status="closed", investigation_confidence="high")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_mismatched_stored_confidence_fails():
    record = _canonical_approved_record(action_payload={"status": "escalated", "confidence": "high"})
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_status="escalated", investigation_confidence="low")
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError):
        apply_approval_consumption(executor, record, plan)


def test_consume_no_caller_replacement_value_is_accepted():
    signature = inspect.signature(apply_approval_consumption)
    assert "status" not in signature.parameters
    assert "confidence" not in signature.parameters


def test_consume_python_does_not_claim_prior_value_verification():
    # When a payload field is absent, apply_approval_consumption only
    # requires the returned value to remain a valid vocabulary member --
    # it never compares against (or claims to know) the investigation's
    # prior stored value, since no prior investigation record is ever
    # read or supplied.
    record = _canonical_approved_record(action_payload={"status": "escalated"})
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan, investigation_status="escalated", investigation_confidence="unknown")
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_consumption(executor, record, plan)
    assert result["investigation_result"]["confidence"] == "unknown"


# ---------------------------------------------------------------------------
# apply_approval_consumption -- transport/error safety
# ---------------------------------------------------------------------------


def test_consume_executor_exception_becomes_transport_error():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _RecordingExecutor(raises=RuntimeError("boom"))
    with pytest.raises(ApprovalTransportError):
        apply_approval_consumption(executor, record, plan)


def test_consume_transport_error_redacts_everything():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    secret_exception_message = "postgres://user:hunter2@db.internal:5432/prod?sslmode=require"
    executor = _RecordingExecutor(
        raises=RuntimeError(
            secret_exception_message
            + " service_role_key=sk-fake-secret-key action_payload={'status':'x'} identity=jane"
            + " expected_investigation_id=" + plan["expected_investigation_id"]
        )
    )
    with pytest.raises(ApprovalTransportError) as excinfo:
        apply_approval_consumption(executor, record, plan)

    message = str(excinfo.value)
    assert "RuntimeError" not in message
    assert secret_exception_message not in message
    assert "Traceback" not in message
    assert "postgres://" not in message
    assert "sk-fake-secret-key" not in message
    assert "action_payload" not in message
    assert "identity=jane" not in message
    assert plan["expected_investigation_id"] not in message
    assert excinfo.value.__cause__ is None


def test_consume_response_errors_expose_no_row():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    secret_marker = "top-secret-consume-marker"
    row = _consumption_row_for(record, plan)
    row["consumed_by"] = secret_marker
    executor = _RecordingExecutor(response=[row])
    with pytest.raises(ApprovalResponseError) as excinfo:
        apply_approval_consumption(executor, record, plan)
    assert secret_marker not in str(excinfo.value)


def test_consume_persistence_error_before_executor_not_misclassified():
    record = _canonical_pending_record()
    executor = _RecordingExecutor(response=[{}])
    try:
        apply_approval_consumption(executor, record, {})
    except ApprovalTransportError:
        pytest.fail("invalid adapter input must not be classified as a transport error")
    except ApprovalPersistenceError:
        pass
    assert executor.calls == []


def test_consume_executor_invoked_once_only_on_transport_failure():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _RecordingExecutor(raises=RuntimeError("boom"))
    with pytest.raises(ApprovalTransportError):
        apply_approval_consumption(executor, record, plan)
    assert len(executor.calls) == 1


# ---------------------------------------------------------------------------
# apply_approval_consumption -- non-mutation and independence
# ---------------------------------------------------------------------------


def test_consume_inputs_and_response_unchanged():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    before_record = copy.deepcopy(record)
    before_plan = copy.deepcopy(plan)
    row = _consumption_row_for(record, plan)
    response = [row]
    before_response = copy.deepcopy(response)
    executor = _RecordingExecutor(response=response)
    apply_approval_consumption(executor, record, plan)
    assert record == before_record
    assert plan == before_plan
    assert response == before_response


def test_consume_hostile_executor_mutation_cannot_alter_inputs():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)

    def _hostile(operation):
        operation["parameters"]["consumed_by"] = "HACKED"
        operation["parameters"]["approval_id"] = "hacked"
        return [row]

    apply_approval_consumption(_hostile, record, plan)
    assert plan["set_fields"]["consumed_by"] != "HACKED"
    assert record["id"] != "hacked"


def test_consume_returned_objects_are_independent():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)
    executor = _RecordingExecutor(response=[row])
    result = apply_approval_consumption(executor, record, plan)
    assert result["transition_plan"] is not plan
    assert result["transition_plan"]["set_fields"] is not plan["set_fields"]
    assert result["updated_record"] is not row
    assert result["updated_record"]["action_payload"] is not row["action_payload"]
    assert result["investigation_result"] is not row


def test_consume_separate_calls_return_independent_objects():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    row = _consumption_row_for(record, plan)

    executor_one = _RecordingExecutor(response=[copy.deepcopy(row)])
    executor_two = _RecordingExecutor(response=[copy.deepcopy(row)])

    result_one = apply_approval_consumption(executor_one, record, plan)
    result_two = apply_approval_consumption(executor_two, record, plan)

    assert result_one == result_two
    assert result_one["updated_record"] is not result_two["updated_record"]
    assert result_one["investigation_result"] is not result_two["investigation_result"]


def test_consume_failure_paths_do_not_mutate_inputs():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    before_record = copy.deepcopy(record)
    before_plan = copy.deepcopy(plan)
    executor = _RecordingExecutor(response=[])
    with pytest.raises(ApprovalConflictError):
        apply_approval_consumption(executor, record, plan)
    assert record == before_record
    assert plan == before_plan


# ---------------------------------------------------------------------------
# apply_approval_consumption -- output exclusions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "excluded_key",
    [
        "persisted", "success", "row_count", "affected_rows", "database_result",
        "executor_result", "rpc_result", "operation", "title", "description",
        "authentication_result", "action_hash", "execution_result",
    ],
)
def test_consume_output_never_contains_forbidden_keys(excluded_key):
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert excluded_key not in result
    assert excluded_key not in result["updated_record"]
    assert excluded_key not in result["investigation_result"]


# ---------------------------------------------------------------------------
# apply_approval_consumption -- existing regressions
# ---------------------------------------------------------------------------


def test_consume_insert_behavior_remains_unchanged():
    executor = _RecordingExecutor(response=[_pending_row(expires_at=None)])
    result = insert_pending_approval(executor, _validated_request(), expires_at=None)
    assert result["status"] == "pending"


def test_consume_lookup_behavior_remains_unchanged():
    executor = _RecordingExecutor(response=[_pending_row()])
    result = load_approval_record(executor, APPROVAL_ID)
    assert result["status"] == "pending"


def test_consume_approve_persistence_remains_unchanged():
    pending_record = _canonical_pending_record()
    plan = _genuine_approve_plan(pending_record)
    executor = _review_executor_for(pending_record, plan)
    result = apply_approval_review_transition(executor, pending_record, plan)
    assert result["updated_record"]["status"] == "approved"


def test_consume_reject_persistence_remains_unchanged():
    pending_record = _canonical_pending_record()
    plan = _genuine_reject_plan(pending_record)
    executor = _review_executor_for(pending_record, plan)
    result = apply_approval_review_transition(executor, pending_record, plan)
    assert result["updated_record"]["status"] == "rejected"


def test_consume_existing_insert_descriptor_unchanged():
    executor = _RecordingExecutor(response=[_pending_row()])
    insert_pending_approval(executor, _validated_request(), expires_at=EXPIRES_AT)
    operation = executor.calls[0]
    assert operation["operation"] == "insert"
    assert set(operation) == {"operation", "table", "values", "returning"}


def test_consume_existing_select_descriptor_unchanged():
    executor = _RecordingExecutor(response=[_pending_row()])
    load_approval_record(executor, APPROVAL_ID)
    operation = executor.calls[0]
    assert operation["operation"] == "select"
    assert set(operation) == {"operation", "table", "columns", "filters", "limit"}


def test_consume_existing_update_descriptor_unchanged():
    pending_record = _canonical_pending_record()
    plan = _genuine_approve_plan(pending_record)
    executor = _review_executor_for(pending_record, plan)
    apply_approval_review_transition(executor, pending_record, plan)
    operation = executor.calls[0]
    assert operation["operation"] == "update"
    assert set(operation) == {"operation", "table", "values", "filters", "returning"}


def test_consume_existing_exception_behavior_unchanged():
    executor = _RecordingExecutor(response=[])
    with pytest.raises(ApprovalNotFoundError):
        load_approval_record(executor, APPROVAL_ID)


# ---------------------------------------------------------------------------
# apply_approval_consumption -- runtime boundary
# ---------------------------------------------------------------------------


def test_consume_import_performs_no_side_effects(monkeypatch):
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
    try:
        reloaded = importlib.import_module(module_name)
        assert reloaded is not None
    finally:
        if existing is not None:
            sys.modules[module_name] = existing


def test_consume_works_under_runtime_guards(monkeypatch):
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

    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    result = apply_approval_consumption(executor, record, plan)
    assert result["updated_record"]["status"] == "consumed"


def test_consume_environment_and_cwd_unchanged():
    original_cwd = os.getcwd()
    original_environ = dict(os.environ)

    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)

    assert os.getcwd() == original_cwd
    assert dict(os.environ) == original_environ


def test_consume_hayabusa_not_imported():
    import sys

    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)
    assert "mcp.hayabusa_server" not in sys.modules


def test_consume_no_cli_or_slash_command_invoked():
    tree = _module_ast()
    fn = _function_def(tree, "apply_approval_consumption")
    called = {
        node.func.id
        for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & {"SlashCommand", "run_slash_command", "invoke_slash_command"}


def test_consume_no_second_executor_call_occurs():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    executor = _consumption_executor_for(record, plan)
    apply_approval_consumption(executor, record, plan)
    assert len(executor.calls) == 1


def test_consume_no_client_side_investigation_update_descriptor():
    tree = _module_ast()
    fn = _function_def(tree, "apply_approval_consumption")
    table_values = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Dict):
            for key_node, value_node in zip(node.keys, node.values):
                if (
                    isinstance(key_node, ast.Constant)
                    and key_node.value == "table"
                    and isinstance(value_node, ast.Constant)
                ):
                    table_values.add(value_node.value)
    assert table_values == set()


def test_consume_no_authentication_containment_or_red_team_behavior():
    tree = _module_ast()
    fn = _function_def(tree, "apply_approval_consumption")
    identifiers = _referenced_identifiers(fn)
    for forbidden in ("auth", "authenticate", "containment", "execute_simulation", "run_atomic"):
        assert forbidden not in identifiers


# ---------------------------------------------------------------------------
# apply_approval_consumption -- source boundary
# ---------------------------------------------------------------------------


def test_consume_production_module_imports_only_approved_modules():
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


def test_consume_investigation_statuses_imported_from_owner():
    tree = _module_ast()
    import_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "core.decision_context":
            for alias in node.names:
                import_names.add(alias.name)
    assert "INVESTIGATION_STATUSES" in import_names


def test_consume_confidence_levels_imported_from_owner():
    tree = _module_ast()
    import_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "core.evidence_normalizer":
            for alias in node.names:
                import_names.add(alias.name)
    assert "CONFIDENCE_LEVELS" in import_names


def test_consume_validate_approval_transition_is_reused_not_reimplemented():
    tree = _module_ast()
    import_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "core.approval_transition":
            for alias in node.names:
                import_names.add(alias.name)
    assert "validate_approval_transition" in import_names
    function_defs = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    assert "validate_approval_transition" not in function_defs


def test_consume_validate_approval_record_is_reused_not_reimplemented():
    tree = _module_ast()
    import_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "core.approval_transition":
            for alias in node.names:
                import_names.add(alias.name)
    assert "validate_approval_record" in import_names
    function_defs = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    assert "validate_approval_record" not in function_defs


@pytest.mark.parametrize("forbidden_module", ["supabase", "requests", "socket", "subprocess", "os", "mcp"])
def test_consume_no_forbidden_module_imported(forbidden_module):
    tree = _module_ast()
    imports = _top_level_imports(tree)
    assert not any(name == forbidden_module or name.startswith(forbidden_module + ".") for name in imports)


def test_consume_no_sql_string_in_source():
    tree = _module_ast()
    fn = _function_def(tree, "apply_approval_consumption")
    string_constants = {
        node.value for node in ast.walk(fn) if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    for forbidden_sql_keyword in ("SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM"):
        assert forbidden_sql_keyword not in string_constants


def test_consume_no_database_connection_or_client_creation():
    tree = _module_ast()
    identifiers = _referenced_identifiers(tree)
    for forbidden in ("connect", "create_client", "create_engine", "psycopg2"):
        assert forbidden not in identifiers


def test_consume_only_one_rpc_operation_descriptor_exists():
    tree = _module_ast()
    operation_values = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key_node, value_node in zip(node.keys, node.values):
                if (
                    isinstance(key_node, ast.Constant)
                    and key_node.value == "operation"
                    and isinstance(value_node, ast.Constant)
                    and value_node.value == "rpc"
                ):
                    operation_values.append(value_node.value)
    assert len(operation_values) == 1


def test_consume_rpc_function_name_is_exact_string_constant():
    tree = _module_ast()
    string_constants = {
        node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert "consume_approval_and_update_investigation_state" in string_constants


def test_consume_no_separate_approvals_update_added_for_consumption():
    tree = _module_ast()
    fn = _function_def(tree, "apply_approval_consumption")
    called = {
        node.func.id
        for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "_invoke_executor" in called
    invoke_calls = [
        node for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_invoke_executor"
    ]
    assert len(invoke_calls) == 1


def test_consume_no_two_call_sequence_exists():
    tree = _module_ast()
    fn = _function_def(tree, "apply_approval_consumption")
    invoke_calls = [
        node for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_invoke_executor"
    ]
    assert len(invoke_calls) == 1


def test_consume_no_transaction_emulation_exists():
    tree = _module_ast()
    identifiers = _referenced_identifiers(tree)
    for forbidden in ("commit", "rollback", "begin", "transaction"):
        assert forbidden not in identifiers


def test_consume_no_update_case_integration_exists():
    source = _module_source_text()
    assert "/update-case" not in source


def test_consume_no_action_hashing_exists():
    tree = _module_ast()
    identifiers = _referenced_identifiers(tree)
    assert "hash" not in identifiers
    assert "action_hash" not in identifiers


def test_consume_no_authentication_exists_module_wide():
    tree = _module_ast()
    identifiers = _referenced_identifiers(tree)
    for forbidden in ("auth", "authenticate"):
        assert forbidden not in identifiers


def test_consume_no_containment_exists_module_wide():
    tree = _module_ast()
    identifiers = _referenced_identifiers(tree)
    assert "containment" not in identifiers


def test_consume_no_red_team_execution_exists_module_wide():
    tree = _module_ast()
    identifiers = _referenced_identifiers(tree)
    for forbidden in ("execute_simulation", "run_atomic"):
        assert forbidden not in identifiers


# ---------------------------------------------------------------------------
# Step 39 regression: genuine plans must survive the real
# sort_keys=True JSON round-trip core.approval_transition_cli actually
# produces -- mapping insertion order is never part of the security
# contract. These plans always come from validate_approval_transition
# itself, never hand-built, exactly like the rest of this module's own
# "genuine plan" fixtures.
# ---------------------------------------------------------------------------


def test_persistence_regression_001_approve_plan_survives_sort_keys_round_trip():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    round_tripped_plan = json.loads(json.dumps(plan, sort_keys=True))
    before = copy.deepcopy(round_tripped_plan)
    executor = _review_executor_for(record, round_tripped_plan)
    result = apply_approval_review_transition(executor, record, round_tripped_plan)
    assert result["updated_record"]["status"] == "approved"
    assert round_tripped_plan == before


def test_persistence_regression_002_reject_plan_survives_sort_keys_round_trip():
    record = _canonical_pending_record()
    plan = _genuine_reject_plan(record)
    round_tripped_plan = json.loads(json.dumps(plan, sort_keys=True))
    before = copy.deepcopy(round_tripped_plan)
    executor = _review_executor_for(record, round_tripped_plan)
    result = apply_approval_review_transition(executor, record, round_tripped_plan)
    assert result["updated_record"]["status"] == "rejected"
    assert round_tripped_plan == before


def test_persistence_regression_003_consume_plan_survives_sort_keys_round_trip():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    round_tripped_plan = json.loads(json.dumps(plan, sort_keys=True))
    before = copy.deepcopy(round_tripped_plan)
    executor = _consumption_executor_for(record, round_tripped_plan)
    result = apply_approval_consumption(executor, record, round_tripped_plan)
    assert result["updated_record"]["status"] == "consumed"
    assert round_tripped_plan == before


def test_persistence_regression_004_sorted_approve_plan_extra_key_rejected():
    record = _canonical_pending_record()
    plan = _genuine_approve_plan(record)
    round_tripped_plan = json.loads(json.dumps(plan, sort_keys=True))
    tampered = copy.deepcopy(round_tripped_plan)
    tampered["set_fields"]["extra_field"] = "unexpected"
    executor = _review_executor_for(record, round_tripped_plan)
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_review_transition(executor, record, tampered)
    assert executor.calls == []


def test_persistence_regression_005_sorted_reject_plan_missing_key_rejected():
    record = _canonical_pending_record()
    plan = _genuine_reject_plan(record)
    round_tripped_plan = json.loads(json.dumps(plan, sort_keys=True))
    tampered = copy.deepcopy(round_tripped_plan)
    del tampered["set_fields"]["rejection_reason"]
    executor = _review_executor_for(record, round_tripped_plan)
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_review_transition(executor, record, tampered)
    assert executor.calls == []


def test_persistence_regression_006_sorted_consume_plan_incorrect_key_rejected():
    record = _canonical_approved_record()
    plan = _genuine_consume_plan(record)
    round_tripped_plan = json.loads(json.dumps(plan, sort_keys=True))
    tampered = copy.deepcopy(round_tripped_plan)
    tampered["set_fields"]["consumed_by_wrong"] = tampered["set_fields"].pop("consumed_by")
    executor = _consumption_executor_for(record, round_tripped_plan)
    with pytest.raises(ApprovalPersistenceError):
        apply_approval_consumption(executor, record, tampered)
    assert executor.calls == []


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
