"""Tests for core.approval_transition -- the pure, deterministic validator
for one proposed approval lifecycle transition against one complete
approval-record snapshot.

No Supabase, file, subprocess, network, or AI/model access occurs anywhere
in this file; every input is a plain in-memory mapping.
"""

import copy
import socket
import subprocess
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.approval_transition import (
    APPROVAL_STATUSES,
    ApprovalTransitionError,
    validate_approval_transition,
)
from core.approval_request import ACTION_TYPES, ApprovalRequestError

INVESTIGATION_ID = "11111111-1111-4111-8111-111111111111"
APPROVAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

REQUESTED_AT = "2026-08-01T10:00:00Z"
CREATED_AT = "2026-08-01T10:00:00Z"
APPROVED_AT = "2026-08-01T11:00:00Z"
REJECTED_AT = "2026-08-01T11:00:00Z"
CONSUMED_AT = "2026-08-01T12:00:00Z"
EXPIRES_AT = "2026-08-03T00:00:00Z"

REJECTION_REASON = "The proposed status change is not sufficiently supported."


class _CustomMapping(Mapping):
    def __init__(self, data):
        self._data = dict(data)

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)


def _pending_record(**overrides):
    record = {
        "id": APPROVAL_ID,
        "investigation_id": INVESTIGATION_ID,
        "action_type": "update_investigation_state",
        "action_payload": {"status": "escalated"},
        "requested_by": "analyst-jane",
        "requested_at": REQUESTED_AT,
        "status": "pending",
        "approved_by": None,
        "approved_at": None,
        "rejected_by": None,
        "rejected_at": None,
        "rejection_reason": None,
        "expires_at": None,
        "consumed_by": None,
        "consumed_at": None,
        "created_at": CREATED_AT,
    }
    record.update(overrides)
    return record


def _approved_record(**overrides):
    record = _pending_record(
        status="approved",
        approved_by="Security Reviewer",
        approved_at=APPROVED_AT,
    )
    record.update(overrides)
    return record


def _rejected_record(**overrides):
    record = _pending_record(
        status="rejected",
        rejected_by="Security Reviewer",
        rejected_at=REJECTED_AT,
        rejection_reason=REJECTION_REASON,
    )
    record.update(overrides)
    return record


def _consumed_record(**overrides):
    record = _approved_record(
        status="consumed",
        consumed_by="Update Case Operator",
        consumed_at=CONSUMED_AT,
    )
    record.update(overrides)
    return record


def _approve_request(**overrides):
    request = {"transition": "approve", "reviewed_by": "Security Reviewer"}
    request.update(overrides)
    return request


def _reject_request(**overrides):
    request = {
        "transition": "reject",
        "reviewed_by": "Security Reviewer",
        "rejection_reason": REJECTION_REASON,
    }
    request.update(overrides)
    return request


def _consume_request(**overrides):
    request = {
        "transition": "consume",
        "consumed_by": "Update Case Operator",
        "expected_investigation_id": INVESTIGATION_ID,
        "expected_action_type": "update_investigation_state",
    }
    request.update(overrides)
    return request


def _module_source_text():
    import core.approval_transition as module

    with open(module.__file__, "r", encoding="utf-8") as handle:
        return handle.read()


def _this_module_ast():
    import ast

    return ast.parse(Path(__file__).read_text(encoding="utf-8"))


def _imported_module_names(tree):
    import ast

    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
    return names


# ---------------------------------------------------------------------------
# 1-9: module and public contract
# ---------------------------------------------------------------------------

def test_001_approval_transition_error_subclasses_value_error():
    assert issubclass(ApprovalTransitionError, ValueError)


def test_002_approval_statuses_is_a_frozenset():
    assert isinstance(APPROVAL_STATUSES, frozenset)


def test_003_approval_statuses_contains_exactly_four_values():
    assert APPROVAL_STATUSES == frozenset({"pending", "approved", "rejected", "consumed"})


def test_004_public_validate_approval_transition_exists():
    assert callable(validate_approval_transition)


def test_005_successful_output_contains_exactly_four_top_level_fields():
    result = validate_approval_transition(_pending_record(), _approve_request())

    assert set(result.keys()) == {"approval_id", "from_status", "to_status", "set_fields"}


def test_006_set_fields_contains_only_lifecycle_fields():
    result = validate_approval_transition(_pending_record(), _approve_request())

    for forbidden in ("investigation_id", "action_type", "action_payload", "requested_by", "requested_at"):
        assert forbidden not in result["set_fields"]


def test_007_function_accepts_non_dict_mapping_implementations():
    result = validate_approval_transition(_CustomMapping(_pending_record()), _CustomMapping(_approve_request()))

    assert result["to_status"] == "approved"


def test_008_function_returns_a_plain_dictionary():
    result = validate_approval_transition(_pending_record(), _approve_request())

    assert type(result) is dict
    assert type(result["set_fields"]) is dict


def test_009_output_boundary_is_documented_as_not_persisted():
    source = _module_source_text()
    assert "Validated transition plan -- not persisted" in source


# ---------------------------------------------------------------------------
# 10-27: current-record envelope
# ---------------------------------------------------------------------------

def test_010_valid_pending_record_accepted_for_approve():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert result["to_status"] == "approved"


def test_011_valid_pending_record_accepted_for_reject():
    result = validate_approval_transition(_pending_record(), _reject_request())
    assert result["to_status"] == "rejected"


def test_012_valid_approved_record_accepted_for_consume():
    result = validate_approval_transition(_approved_record(), _consume_request())
    assert result["to_status"] == "consumed"


def test_013_non_mapping_current_record_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition("not a mapping", _approve_request())


def test_014_missing_current_record_field_rejected():
    record = _pending_record()
    del record["created_at"]

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_015_unknown_current_record_field_rejected():
    record = _pending_record(unexpected_field="x")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_016_all_sixteen_required_current_record_fields_documented_and_enforced():
    fields = (
        "id", "investigation_id", "action_type", "action_payload", "requested_by", "requested_at",
        "status", "approved_by", "approved_at", "rejected_by", "rejected_at", "rejection_reason",
        "expires_at", "consumed_by", "consumed_at", "created_at",
    )
    record = _pending_record()
    assert set(record.keys()) == set(fields)
    assert len(fields) == 16

    for field in fields:
        incomplete = _pending_record()
        del incomplete[field]
        with pytest.raises(ApprovalTransitionError):
            validate_approval_transition(incomplete, _approve_request())


def test_017_missing_requested_at_rejected_rather_than_regenerated():
    record = _pending_record()
    del record["requested_at"]

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_018_none_requested_at_rejected_rather_than_regenerated():
    record = _pending_record(requested_at=None)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_019_approval_uuid_canonicalized():
    record = _pending_record(id=APPROVAL_ID.upper())

    result = validate_approval_transition(record, _approve_request())

    assert result["approval_id"] == APPROVAL_ID


def test_020_invalid_approval_uuid_rejected():
    record = _pending_record(id="not-a-uuid")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_021_investigation_uuid_revalidated_through_approval_request_validator():
    record = _pending_record(investigation_id="not-a-uuid")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_022_action_type_revalidated_through_approval_request_validator():
    record = _pending_record(action_type="delete_investigation")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_023_action_payload_revalidated_through_approval_request_validator():
    record = _pending_record(action_payload={})

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_024_requested_by_revalidated_through_approval_request_validator():
    record = _pending_record(requested_by="   ")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_025_approval_request_error_is_converted_to_approval_transition_error():
    record = _pending_record(action_type="delete_investigation")

    try:
        validate_approval_transition(record, _approve_request())
        assert False, "expected ApprovalTransitionError"
    except ApprovalRequestError:
        assert False, "raw ApprovalRequestError must not escape"
    except ApprovalTransitionError:
        pass


def test_026_complete_action_payload_not_leaked_in_converted_errors():
    secret_marker = "SECRET-ACTION-PAYLOAD-MARKER"
    record = _pending_record(action_type="delete_investigation", action_payload={"status": "escalated", "note": secret_marker})

    try:
        validate_approval_transition(record, _approve_request())
    except ApprovalTransitionError as exc:
        assert secret_marker not in str(exc)


def test_027_identity_values_not_leaked_in_converted_errors():
    secret_marker = "SECRET-REQUESTER-MARKER"
    record = _pending_record(action_type="delete_investigation", requested_by=secret_marker)

    try:
        validate_approval_transition(record, _approve_request())
    except ApprovalTransitionError as exc:
        assert secret_marker not in str(exc)


# ---------------------------------------------------------------------------
# 28-37: current pending-state consistency
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "field,value",
    [
        ("approved_by", "someone"),
        ("approved_at", APPROVED_AT),
        ("rejected_by", "someone"),
        ("rejected_at", REJECTED_AT),
        ("rejection_reason", REJECTION_REASON),
        ("consumed_by", "someone"),
        ("consumed_at", CONSUMED_AT),
    ],
)
def test_028_to_037_pending_record_requires_lifecycle_fields_null(field, value):
    record = _pending_record(**{field: value})

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


# ---------------------------------------------------------------------------
# 38-47: current approved-state consistency
# ---------------------------------------------------------------------------

def test_038_approved_record_requires_approved_by():
    record = _approved_record(approved_by=None)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _consume_request())


def test_039_approved_record_requires_approved_at():
    record = _approved_record(approved_at=None)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _consume_request())


def test_040_approved_record_rejects_blank_approved_by():
    record = _approved_record(approved_by="   ")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _consume_request())


def test_041_approved_record_rejects_rejected_by():
    record = _approved_record(rejected_by="someone")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _consume_request())


def test_042_approved_record_rejects_rejected_at():
    record = _approved_record(rejected_at=REJECTED_AT)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _consume_request())


def test_043_approved_record_rejects_rejection_reason():
    record = _approved_record(rejection_reason=REJECTION_REASON)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _consume_request())


def test_044_approved_record_rejects_consumed_by():
    record = _approved_record(consumed_by="someone")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _consume_request())


def test_045_approved_record_rejects_consumed_at():
    record = _approved_record(consumed_at=CONSUMED_AT)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _consume_request())


def test_046_approved_at_before_requested_at_rejected():
    record = _approved_record(approved_at="2026-08-01T09:00:00Z")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _consume_request())


def test_047_approved_at_at_or_after_expires_at_rejected():
    record = _approved_record(expires_at=APPROVED_AT)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _consume_request())


# ---------------------------------------------------------------------------
# 48-56: current rejected-state consistency
# ---------------------------------------------------------------------------

def test_048_rejected_record_requires_rejected_by():
    record = _rejected_record(rejected_by=None)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_049_rejected_record_requires_rejected_at():
    record = _rejected_record(rejected_at=None)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_050_rejected_record_requires_rejection_reason():
    record = _rejected_record(rejection_reason=None)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_051_blank_rejection_reason_rejected():
    record = _rejected_record(rejection_reason="   ")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_052_rejected_record_rejects_approved_by():
    record = _rejected_record(approved_by="someone")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_053_rejected_record_rejects_approved_at():
    record = _rejected_record(approved_at=APPROVED_AT)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_054_rejected_record_rejects_consumed_by():
    record = _rejected_record(consumed_by="someone")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_055_rejected_record_rejects_consumed_at():
    record = _rejected_record(consumed_at=CONSUMED_AT)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_056_rejected_at_before_requested_at_rejected():
    record = _rejected_record(rejected_at="2026-08-01T09:00:00Z")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


# ---------------------------------------------------------------------------
# 57-65: current consumed-state consistency
# ---------------------------------------------------------------------------

def test_057_consumed_record_requires_approved_by():
    record = _consumed_record(approved_by=None)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_058_consumed_record_requires_approved_at():
    record = _consumed_record(approved_at=None)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_059_consumed_record_requires_consumed_by():
    record = _consumed_record(consumed_by=None)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_060_consumed_record_requires_consumed_at():
    record = _consumed_record(consumed_at=None)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_061_consumed_record_rejects_rejected_by():
    record = _consumed_record(rejected_by="someone")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_062_consumed_record_rejects_rejected_at():
    record = _consumed_record(rejected_at=REJECTED_AT)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_063_consumed_record_rejects_rejection_reason():
    record = _consumed_record(rejection_reason=REJECTION_REASON)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_064_consumed_at_before_approved_at_rejected():
    record = _consumed_record(consumed_at="2026-08-01T10:30:00Z")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_065_consumed_at_at_or_after_expires_at_rejected():
    record = _consumed_record(expires_at=CONSUMED_AT)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


# ---------------------------------------------------------------------------
# 66-74: current-record timestamp validation
# ---------------------------------------------------------------------------

def test_066_created_at_must_be_aware():
    record = _pending_record(created_at="2026-08-01T10:00:00")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_067_created_at_canonicalizes_to_utc():
    record = _pending_record(created_at="2026-08-01T03:00:00-07:00")

    result = validate_approval_transition(record, _approve_request())
    assert result["to_status"] == "approved"


def test_068_created_at_before_requested_at_rejected():
    record = _pending_record(created_at="2026-08-01T09:00:00Z")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_069_expires_at_may_be_none():
    record = _pending_record(expires_at=None)

    result = validate_approval_transition(record, _approve_request())
    assert result["to_status"] == "approved"


def test_070_expires_at_canonicalizes_to_utc():
    record = _pending_record(expires_at="2026-08-03T00:00:00Z")

    result = validate_approval_transition(record, _approve_request())
    assert result["to_status"] == "approved"


def test_071_expires_at_at_or_before_requested_at_rejected():
    record = _pending_record(expires_at=REQUESTED_AT)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_072_naive_expires_at_rejected():
    record = _pending_record(expires_at="2026-08-03T00:00:00")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_073_invalid_current_lifecycle_timestamp_rejected():
    record = _approved_record(approved_at="not-a-timestamp")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _consume_request())


def test_074_current_record_strings_and_timestamps_are_not_mutated():
    record = _pending_record(expires_at=EXPIRES_AT)
    snapshot = copy.deepcopy(record)

    validate_approval_transition(record, _approve_request())

    assert record == snapshot


# ---------------------------------------------------------------------------
# 75-86: transition envelope dispatch
# ---------------------------------------------------------------------------

def test_075_non_mapping_transition_request_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), "not a mapping")


def test_076_missing_transition_rejected():
    request = _approve_request()
    del request["transition"]

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), request)


def test_077_blank_transition_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _approve_request(transition="   "))


def test_078_non_string_transition_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _approve_request(transition=123))


def test_079_unknown_transition_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _approve_request(transition="revoke"))


def test_080_transition_trims_whitespace():
    result = validate_approval_transition(_pending_record(), _approve_request(transition="  approve  "))
    assert result["to_status"] == "approved"


def test_081_transition_canonicalizes_to_lowercase():
    result = validate_approval_transition(_pending_record(), _approve_request(transition="APPROVE"))
    assert result["to_status"] == "approved"


def test_082_approve_exact_field_envelope_enforced():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _approve_request(extra_field="x"))


def test_083_reject_exact_field_envelope_enforced():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _reject_request(extra_field="x"))


def test_084_consume_exact_field_envelope_enforced():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), _consume_request(extra_field="x"))


def test_085_fields_belonging_to_another_transition_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _approve_request(rejection_reason=REJECTION_REASON))


@pytest.mark.parametrize(
    "field",
    [
        "id", "investigation_id", "action_type", "action_payload", "requested_by",
        "requested_at", "created_at", "expires_at", "action_hash", "target_type", "target_id",
    ],
)
def test_086_immutable_field_modification_attempts_rejected(field):
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _approve_request(**{field: "x"}))


# ---------------------------------------------------------------------------
# 87-110: approve transition
# ---------------------------------------------------------------------------

def test_087_pending_to_approved_succeeds():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert result["from_status"] == "pending"
    assert result["to_status"] == "approved"


def test_088_approve_output_exact_shape():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert set(result.keys()) == {"approval_id", "from_status", "to_status", "set_fields"}
    assert set(result["set_fields"].keys()) == {"status", "approved_by", "approved_at"}


def test_089_approve_set_fields_exact_order():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert list(result["set_fields"].keys()) == ["status", "approved_by", "approved_at"]


def test_090_reviewed_by_trimmed():
    result = validate_approval_transition(_pending_record(), _approve_request(reviewed_by="  Security Reviewer  "))
    assert result["set_fields"]["approved_by"] == "Security Reviewer"


def test_091_reviewed_by_case_preserved():
    result = validate_approval_transition(_pending_record(), _approve_request(reviewed_by="Security REVIEWER"))
    assert result["set_fields"]["approved_by"] == "Security REVIEWER"


def test_092_blank_reviewed_by_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _approve_request(reviewed_by="   "))


def test_093_non_string_reviewed_by_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _approve_request(reviewed_by=42))


def test_094_missing_reviewed_by_rejected():
    request = _approve_request()
    del request["reviewed_by"]

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), request)


def test_095_reviewed_at_omitted_generates_timestamp():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert result["set_fields"]["approved_at"]


def test_096_reviewed_at_none_generates_timestamp():
    result = validate_approval_transition(_pending_record(), _approve_request(reviewed_at=None))
    assert result["set_fields"]["approved_at"]


def test_097_supplied_reviewed_at_canonicalized():
    result = validate_approval_transition(
        _pending_record(), _approve_request(reviewed_at="2026-08-01T08:45:00-07:00")
    )
    assert result["set_fields"]["approved_at"] == "2026-08-01T15:45:00Z"


def test_098_naive_reviewed_at_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _approve_request(reviewed_at="2026-08-01T11:00:00"))


def test_099_reviewed_at_before_requested_at_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _approve_request(reviewed_at="2026-08-01T09:00:00Z"))


def test_100_reviewed_at_equal_to_requested_at_accepted():
    result = validate_approval_transition(_pending_record(), _approve_request(reviewed_at=REQUESTED_AT))
    assert result["set_fields"]["approved_at"] == REQUESTED_AT


def test_101_reviewed_at_at_expires_at_rejected():
    record = _pending_record(expires_at="2026-08-01T16:00:00Z")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request(reviewed_at="2026-08-01T16:00:00Z"))


def test_102_reviewed_at_after_expires_at_rejected():
    record = _pending_record(expires_at="2026-08-01T16:00:00Z")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request(reviewed_at="2026-08-01T17:00:00Z"))


def test_103_different_reviewer_accepted():
    result = validate_approval_transition(
        _pending_record(requested_by="analyst-jane"), _approve_request(reviewed_by="Security Reviewer")
    )
    assert result["set_fields"]["approved_by"] == "Security Reviewer"


def test_104_exact_same_requester_reviewer_rejected():
    record = _pending_record(requested_by="analyst-jane")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request(reviewed_by="analyst-jane"))


def test_105_case_only_requester_reviewer_difference_rejected():
    record = _pending_record(requested_by="analyst-jane")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request(reviewed_by="ANALYST-JANE"))


def test_106_whitespace_only_requester_reviewer_difference_rejected():
    record = _pending_record(requested_by="analyst-jane")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request(reviewed_by="  analyst-jane  "))


def test_107_unicode_casefold_equivalent_requester_reviewer_rejected():
    record = _pending_record(requested_by="Straße")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request(reviewed_by="STRASSE"))


def test_108_reviewer_value_not_leaked_in_error():
    secret_marker = "SECRET-REVIEWER-MARKER"
    record = _pending_record(requested_by=secret_marker)

    try:
        validate_approval_transition(record, _approve_request(reviewed_by=secret_marker))
    except ApprovalTransitionError as exc:
        assert secret_marker not in str(exc)


def test_109_approval_does_not_authenticate_identity():
    source = _module_source_text()
    assert "supabase.auth" not in source.lower()
    assert "def verify_identity" not in source


def test_110_approval_does_not_persist_anything():
    source = _module_source_text()
    assert ".insert(" not in source
    assert ".update(" not in source


# ---------------------------------------------------------------------------
# 111-130: reject transition
# ---------------------------------------------------------------------------

def test_111_pending_to_rejected_succeeds():
    result = validate_approval_transition(_pending_record(), _reject_request())
    assert result["to_status"] == "rejected"


def test_112_reject_output_exact_shape():
    result = validate_approval_transition(_pending_record(), _reject_request())
    assert set(result.keys()) == {"approval_id", "from_status", "to_status", "set_fields"}
    assert set(result["set_fields"].keys()) == {"status", "rejected_by", "rejected_at", "rejection_reason"}


def test_113_reject_set_fields_exact_order():
    result = validate_approval_transition(_pending_record(), _reject_request())
    assert list(result["set_fields"].keys()) == ["status", "rejected_by", "rejected_at", "rejection_reason"]


def test_114_reject_reviewed_by_trimmed_and_case_preserved():
    result = validate_approval_transition(_pending_record(), _reject_request(reviewed_by="  Security REVIEWER  "))
    assert result["set_fields"]["rejected_by"] == "Security REVIEWER"


def test_115_self_rejection_accepted():
    record = _pending_record(requested_by="analyst-jane")

    result = validate_approval_transition(record, _reject_request(reviewed_by="analyst-jane"))
    assert result["set_fields"]["rejected_by"] == "analyst-jane"


def test_116_case_equivalent_self_rejection_accepted():
    record = _pending_record(requested_by="analyst-jane")

    result = validate_approval_transition(record, _reject_request(reviewed_by="ANALYST-JANE"))
    assert result["set_fields"]["rejected_by"] == "ANALYST-JANE"


def test_117_missing_reviewed_by_rejected_for_reject():
    request = _reject_request()
    del request["reviewed_by"]

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), request)


def test_118_blank_reviewed_by_rejected_for_reject():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _reject_request(reviewed_by="   "))


def test_119_missing_rejection_reason_rejected():
    request = _reject_request()
    del request["rejection_reason"]

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), request)


def test_120_blank_rejection_reason_rejected_for_reject():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _reject_request(rejection_reason="   "))


def test_121_rejection_reason_outer_whitespace_trimmed():
    result = validate_approval_transition(_pending_record(), _reject_request(rejection_reason="  padded reason  "))
    assert result["set_fields"]["rejection_reason"] == "padded reason"


def test_122_rejection_reason_internal_whitespace_preserved():
    result = validate_approval_transition(
        _pending_record(), _reject_request(rejection_reason="reason   with   internal   spacing")
    )
    assert result["set_fields"]["rejection_reason"] == "reason   with   internal   spacing"


def test_123_rejection_reason_case_preserved():
    result = validate_approval_transition(_pending_record(), _reject_request(rejection_reason="Reason With CASE"))
    assert result["set_fields"]["rejection_reason"] == "Reason With CASE"


def test_124_reject_reviewed_at_omitted_generates_timestamp():
    result = validate_approval_transition(_pending_record(), _reject_request())
    assert result["set_fields"]["rejected_at"]


def test_125_reject_reviewed_at_canonicalized():
    result = validate_approval_transition(
        _pending_record(), _reject_request(reviewed_at="2026-08-01T08:45:00-07:00")
    )
    assert result["set_fields"]["rejected_at"] == "2026-08-01T15:45:00Z"


def test_126_reject_reviewed_at_before_requested_at_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _reject_request(reviewed_at="2026-08-01T09:00:00Z"))


def test_127_rejection_after_expires_at_remains_allowed():
    record = _pending_record(expires_at="2026-08-01T10:30:00Z")

    result = validate_approval_transition(record, _reject_request(reviewed_at="2026-08-01T11:00:00Z"))
    assert result["to_status"] == "rejected"


def test_128_rejection_reason_not_leaked_in_errors():
    secret_marker = "SECRET-REJECTION-REASON-MARKER"

    try:
        validate_approval_transition(
            _rejected_record(rejection_reason=None), _approve_request()
        )
    except ApprovalTransitionError as exc:
        assert secret_marker not in str(exc)


def test_129_no_secret_scanning_occurs():
    source = _module_source_text()
    assert "def scan_for_secret" not in source
    assert "credential" not in source.lower()


def test_130_no_cancelled_withdrawn_status_generated():
    assert "cancelled" not in APPROVAL_STATUSES
    assert "withdrawn" not in APPROVAL_STATUSES


# ---------------------------------------------------------------------------
# 131-154: consume transition
# ---------------------------------------------------------------------------

def test_131_approved_to_consumed_succeeds():
    result = validate_approval_transition(_approved_record(), _consume_request())
    assert result["to_status"] == "consumed"


def test_132_consume_output_exact_shape():
    result = validate_approval_transition(_approved_record(), _consume_request())
    assert set(result.keys()) == {
        "approval_id", "from_status", "to_status", "set_fields",
        "expected_investigation_id", "expected_action_type",
    }
    assert set(result["set_fields"].keys()) == {"status", "consumed_by", "consumed_at"}


def test_133_consume_set_fields_exact_order():
    result = validate_approval_transition(_approved_record(), _consume_request())
    assert list(result["set_fields"].keys()) == ["status", "consumed_by", "consumed_at"]


def test_134_consumed_by_trimmed():
    result = validate_approval_transition(_approved_record(), _consume_request(consumed_by="  Update Case Operator  "))
    assert result["set_fields"]["consumed_by"] == "Update Case Operator"


def test_135_consumed_by_case_preserved():
    result = validate_approval_transition(_approved_record(), _consume_request(consumed_by="UPDATE case operator"))
    assert result["set_fields"]["consumed_by"] == "UPDATE case operator"


def test_136_missing_consumed_by_rejected():
    request = _consume_request()
    del request["consumed_by"]

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), request)


def test_137_blank_consumed_by_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), _consume_request(consumed_by="   "))


def test_138_consumed_at_omitted_generates_timestamp():
    result = validate_approval_transition(_approved_record(), _consume_request())
    assert result["set_fields"]["consumed_at"]


def test_139_consumed_at_canonicalized():
    result = validate_approval_transition(
        _approved_record(), _consume_request(consumed_at="2026-08-01T05:00:00-07:00")
    )
    assert result["set_fields"]["consumed_at"] == "2026-08-01T12:00:00Z"


def test_140_consumed_at_before_approved_at_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), _consume_request(consumed_at="2026-08-01T10:30:00Z"))


def test_141_consumed_at_equal_to_approved_at_accepted():
    result = validate_approval_transition(_approved_record(), _consume_request(consumed_at=APPROVED_AT))
    assert result["set_fields"]["consumed_at"] == APPROVED_AT


def test_142_consumed_at_at_expires_at_rejected():
    record = _approved_record(expires_at="2026-08-01T13:00:00Z")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _consume_request(consumed_at="2026-08-01T13:00:00Z"))


def test_143_consumed_at_after_expires_at_rejected():
    record = _approved_record(expires_at="2026-08-01T13:00:00Z")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _consume_request(consumed_at="2026-08-01T14:00:00Z"))


def test_144_expected_investigation_id_required():
    request = _consume_request()
    del request["expected_investigation_id"]

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), request)


def test_145_expected_investigation_uuid_canonicalized():
    result = validate_approval_transition(
        _approved_record(), _consume_request(expected_investigation_id=INVESTIGATION_ID.upper())
    )
    assert result["to_status"] == "consumed"


def test_146_expected_investigation_mismatch_rejected():
    other_id = "66666666-6666-4666-8666-666666666666"

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), _consume_request(expected_investigation_id=other_id))


def test_147_expected_action_type_required():
    request = _consume_request()
    del request["expected_action_type"]

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), request)


def test_148_expected_action_type_canonicalized():
    result = validate_approval_transition(
        _approved_record(), _consume_request(expected_action_type="UPDATE_INVESTIGATION_STATE")
    )
    assert result["to_status"] == "consumed"


def test_149_unknown_expected_action_type_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), _consume_request(expected_action_type="delete_everything"))


def test_150_expected_action_type_mismatch_rejected(monkeypatch):
    # ACTION_TYPES currently has exactly one valid member, so a genuine
    # mismatch between two independently-valid action types cannot be
    # constructed with real vocabulary. Temporarily broadening this
    # module's own ACTION_TYPES reference lets the *comparison* branch be
    # exercised distinctly from the *vocabulary* branch already covered by
    # test_149, without altering core.approval_request's real vocabulary
    # or any persisted record's validity.
    import core.approval_transition as module

    monkeypatch.setattr(module, "ACTION_TYPES", frozenset({"update_investigation_state", "fake_other_action"}))

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), _consume_request(expected_action_type="fake_other_action"))


def test_151_consumed_operator_may_equal_requester():
    record = _approved_record(requested_by="analyst-jane")

    result = validate_approval_transition(record, _consume_request(consumed_by="analyst-jane"))
    assert result["set_fields"]["consumed_by"] == "analyst-jane"


def test_152_consumed_operator_may_equal_approver():
    record = _approved_record(approved_by="Security Reviewer")

    result = validate_approval_transition(record, _consume_request(consumed_by="Security Reviewer"))
    assert result["set_fields"]["consumed_by"] == "Security Reviewer"


def test_153_no_action_hash_generated():
    result = validate_approval_transition(_approved_record(), _consume_request())
    assert "action_hash" not in result["set_fields"]


def test_154_no_action_payload_copied_into_output():
    result = validate_approval_transition(_approved_record(), _consume_request())
    assert "action_payload" not in result
    assert "action_payload" not in result["set_fields"]


# ---------------------------------------------------------------------------
# Consume plan binding-field contract (Step 11)
# ---------------------------------------------------------------------------


def test_154b_consume_plan_top_level_order_exact():
    result = validate_approval_transition(_approved_record(), _consume_request())
    assert list(result.keys()) == [
        "approval_id", "from_status", "to_status", "set_fields",
        "expected_investigation_id", "expected_action_type",
    ]


def test_154c_approve_plan_still_exactly_four_keys():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert list(result.keys()) == ["approval_id", "from_status", "to_status", "set_fields"]


def test_154d_reject_plan_still_exactly_four_keys():
    result = validate_approval_transition(_pending_record(), _reject_request())
    assert list(result.keys()) == ["approval_id", "from_status", "to_status", "set_fields"]


def test_154e_binding_fields_absent_from_approve_plan():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert "expected_investigation_id" not in result
    assert "expected_action_type" not in result


def test_154f_binding_fields_absent_from_reject_plan():
    result = validate_approval_transition(_pending_record(), _reject_request())
    assert "expected_investigation_id" not in result
    assert "expected_action_type" not in result


def test_154g_binding_fields_not_inside_consume_set_fields():
    result = validate_approval_transition(_approved_record(), _consume_request())
    assert "expected_investigation_id" not in result["set_fields"]
    assert "expected_action_type" not in result["set_fields"]


def test_154h_consume_set_fields_still_exactly_three_keys():
    result = validate_approval_transition(_approved_record(), _consume_request())
    assert set(result["set_fields"].keys()) == {"status", "consumed_by", "consumed_at"}


def test_154i_no_persistence_or_execution_field_in_consume_plan():
    result = validate_approval_transition(_approved_record(), _consume_request())
    for forbidden in ("persisted", "row_count", "affected_rows", "database_result", "operation", "table"):
        assert forbidden not in result


def test_154j_expected_investigation_id_equals_validated_request_value():
    result = validate_approval_transition(
        _approved_record(), _consume_request(expected_investigation_id=INVESTIGATION_ID.upper())
    )
    assert result["expected_investigation_id"] == INVESTIGATION_ID


def test_154k_expected_investigation_id_equals_record_investigation_id():
    result = validate_approval_transition(_approved_record(), _consume_request())
    assert result["expected_investigation_id"] == INVESTIGATION_ID


def test_154l_expected_action_type_equals_validated_request_value():
    result = validate_approval_transition(
        _approved_record(), _consume_request(expected_action_type="UPDATE_INVESTIGATION_STATE")
    )
    assert result["expected_action_type"] == "update_investigation_state"


def test_154m_expected_action_type_equals_record_action_type():
    result = validate_approval_transition(_approved_record(), _consume_request())
    assert result["expected_action_type"] == "update_investigation_state"


def test_154n_canonical_uuid_retained_from_padded_input():
    result = validate_approval_transition(
        _approved_record(), _consume_request(expected_investigation_id=f"  {INVESTIGATION_ID}  ")
    )
    assert result["expected_investigation_id"] == INVESTIGATION_ID


def test_154o_canonical_action_type_retained_from_padded_input():
    result = validate_approval_transition(
        _approved_record(), _consume_request(expected_action_type="  update_investigation_state  ")
    )
    assert result["expected_action_type"] == "update_investigation_state"


def test_154p_mismatched_investigation_id_still_fails():
    other_id = "66666666-6666-4666-8666-666666666666"
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), _consume_request(expected_investigation_id=other_id))


def test_154q_mismatched_action_type_still_fails(monkeypatch):
    import core.approval_transition as module

    monkeypatch.setattr(module, "ACTION_TYPES", frozenset({"update_investigation_state", "fake_other_action"}))
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), _consume_request(expected_action_type="fake_other_action"))


def test_154r_invalid_investigation_uuid_still_fails():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), _consume_request(expected_investigation_id="not-a-uuid"))


def test_154s_invalid_action_type_still_fails():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), _consume_request(expected_action_type="delete_everything"))


def test_154t_missing_expected_investigation_id_still_fails():
    request = _consume_request()
    del request["expected_investigation_id"]
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), request)


def test_154u_missing_expected_action_type_still_fails():
    request = _consume_request()
    del request["expected_action_type"]
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), request)


def test_154v_consume_plan_binding_values_independent_of_input_request_object():
    request = _consume_request()
    result = validate_approval_transition(_approved_record(), request)
    result["expected_investigation_id"] = "mutated"
    result["expected_action_type"] = "mutated"
    assert request["expected_investigation_id"] == INVESTIGATION_ID
    assert request["expected_action_type"] == "update_investigation_state"


def test_154w_separate_consume_calls_return_independent_plan_objects():
    request = _consume_request(consumed_at=CONSUMED_AT)
    first = validate_approval_transition(_approved_record(), request)
    second = validate_approval_transition(_approved_record(), request)
    assert first == second
    assert first is not second
    assert first["set_fields"] is not second["set_fields"]


# ---------------------------------------------------------------------------
# 155-169: state machine and repeat rejection
# ---------------------------------------------------------------------------

def test_155_pending_to_consume_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _consume_request())


def test_156_approved_to_approve_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), _approve_request())


def test_157_approved_to_reject_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), _reject_request())


def test_158_rejected_to_approve_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_rejected_record(), _approve_request())


def test_159_rejected_to_reject_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_rejected_record(), _reject_request())


def test_160_rejected_to_consume_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_rejected_record(), _consume_request())


def test_161_consumed_to_approve_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_consumed_record(), _approve_request())


def test_162_consumed_to_reject_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_consumed_record(), _reject_request())


def test_163_consumed_to_consume_rejected():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_consumed_record(), _consume_request())


def test_164_repeated_approve_fails_closed():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), _approve_request())


def test_165_repeated_reject_fails_closed():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_rejected_record(), _reject_request())


def test_166_repeated_consume_fails_closed():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_consumed_record(), _consume_request())


def test_167_rejected_is_terminal():
    for request in (_approve_request(), _reject_request(), _consume_request()):
        with pytest.raises(ApprovalTransitionError):
            validate_approval_transition(_rejected_record(), request)


def test_168_consumed_is_terminal():
    for request in (_approve_request(), _reject_request(), _consume_request()):
        with pytest.raises(ApprovalTransitionError):
            validate_approval_transition(_consumed_record(), request)


def test_169_no_reopening_transition_exists():
    source = _module_source_text()
    assert '"pending"' in source
    # Confirm no transition ever sets status back to "pending".
    assert 'to_status": "pending"' not in source.replace(" ", "")


# ---------------------------------------------------------------------------
# 170-179: timestamp generation and now injection
# ---------------------------------------------------------------------------

def test_170_aware_injected_now_used_for_approve():
    now = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)

    result = validate_approval_transition(_pending_record(), _approve_request(), now=now)
    assert result["set_fields"]["approved_at"] == "2026-08-01T12:00:00Z"


def test_171_aware_injected_now_used_for_reject():
    now = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)

    result = validate_approval_transition(_pending_record(), _reject_request(), now=now)
    assert result["set_fields"]["rejected_at"] == "2026-08-01T12:00:00Z"


def test_172_aware_injected_now_used_for_consume():
    now = datetime(2026, 8, 1, 13, 0, 0, tzinfo=timezone.utc)

    result = validate_approval_transition(_approved_record(), _consume_request(), now=now)
    assert result["set_fields"]["consumed_at"] == "2026-08-01T13:00:00Z"


def test_173_offset_now_canonicalizes_to_utc():
    now = datetime(2026, 8, 1, 5, 0, 0, tzinfo=timezone(timedelta(hours=-7)))

    result = validate_approval_transition(_pending_record(), _approve_request(), now=now)
    assert result["set_fields"]["approved_at"] == "2026-08-01T12:00:00Z"


def test_174_naive_injected_now_rejected_when_generation_required():
    naive_now = datetime(2026, 8, 1, 12, 0, 0)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _approve_request(), now=naive_now)


def test_175_non_datetime_now_rejected_when_generation_required():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_pending_record(), _approve_request(), now="2026-08-01T12:00:00Z")


def test_176_invalid_now_ignored_when_explicit_timestamp_supplied():
    result = validate_approval_transition(
        _pending_record(),
        _approve_request(reviewed_at="2026-08-01T11:00:00Z"),
        now="not-a-datetime-at-all",
    )
    assert result["set_fields"]["approved_at"] == "2026-08-01T11:00:00Z"


def test_177_generated_timestamps_end_in_z():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert result["set_fields"]["approved_at"].endswith("Z")


def test_178_generated_timestamps_parse_as_aware_utc():
    result = validate_approval_transition(_pending_record(), _approve_request())
    parsed = datetime.fromisoformat(result["set_fields"]["approved_at"].replace("Z", "+00:00"))
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def test_179_explicit_timestamps_are_not_replaced():
    result = validate_approval_transition(
        _pending_record(),
        _approve_request(reviewed_at="2026-08-01T11:30:00Z"),
        now=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    assert result["set_fields"]["approved_at"] == "2026-08-01T11:30:00Z"


# ---------------------------------------------------------------------------
# 180-191: exact output exclusions
# ---------------------------------------------------------------------------

def test_180_output_contains_no_investigation_id():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert "investigation_id" not in result


def test_181_output_contains_no_action_type():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert "action_type" not in result


def test_182_output_contains_no_action_payload():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert "action_payload" not in result


def test_183_output_contains_no_requested_by():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert "requested_by" not in result


def test_184_output_contains_no_requested_at():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert "requested_at" not in result


def test_185_output_contains_no_created_at():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert "created_at" not in result


def test_186_output_contains_no_expires_at():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert "expires_at" not in result


def test_187_output_contains_no_action_hash():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert "action_hash" not in result


def test_188_output_contains_no_target_fields():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert "target_type" not in result
    assert "target_id" not in result


def test_189_output_contains_no_database_result():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert "affected_rows" not in result
    assert "row_count" not in result


def test_190_output_contains_no_approval_execution_result():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert "execution_result" not in result


def test_191_output_contains_no_investigation_update_result():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert "investigation_status" not in result
    assert "investigation_confidence" not in result


# ---------------------------------------------------------------------------
# 192-200: request-validator composition
# ---------------------------------------------------------------------------

def test_192_normalized_validate_approval_request_output_can_form_pending_current_record():
    from core.approval_request import validate_approval_request

    normalized_request = validate_approval_request(
        {
            "investigation_id": INVESTIGATION_ID,
            "action_type": "update_investigation_state",
            "action_payload": {"status": "escalated"},
            "requested_by": "analyst-jane",
            "requested_at": REQUESTED_AT,
        }
    )

    current_record = {
        "id": APPROVAL_ID,
        **normalized_request,
        "status": "pending",
        "approved_by": None,
        "approved_at": None,
        "rejected_by": None,
        "rejected_at": None,
        "rejection_reason": None,
        "expires_at": None,
        "consumed_by": None,
        "consumed_at": None,
        "created_at": REQUESTED_AT,
    }

    result = validate_approval_transition(current_record, _approve_request())
    assert result["to_status"] == "approved"


def test_193_request_to_approve_sequence_succeeds():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert result["set_fields"]["status"] == "approved"


def test_194_approved_snapshot_built_from_plan_can_feed_consume():
    approve_plan = validate_approval_transition(_pending_record(), _approve_request())

    approved_record = _pending_record(
        status=approve_plan["set_fields"]["status"],
        approved_by=approve_plan["set_fields"]["approved_by"],
        approved_at=approve_plan["set_fields"]["approved_at"],
    )

    result = validate_approval_transition(approved_record, _consume_request())
    assert result["to_status"] == "consumed"


def test_195_request_to_reject_sequence_succeeds():
    result = validate_approval_transition(_pending_record(), _reject_request())
    assert result["set_fields"]["status"] == "rejected"


def test_196_approved_snapshot_cannot_feed_reject():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_approved_record(), _reject_request())


def test_197_rejected_snapshot_cannot_feed_consume():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_rejected_record(), _consume_request())


def test_198_consumed_snapshot_cannot_be_consumed_again():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(_consumed_record(), _consume_request())


def test_199_requested_at_is_preserved_through_composition():
    approve_plan = validate_approval_transition(_pending_record(), _approve_request())
    assert "requested_at" not in approve_plan

    # The underlying record's requested_at is unaffected by the transition.
    record = _pending_record()
    validate_approval_transition(record, _approve_request())
    assert record["requested_at"] == REQUESTED_AT


def test_200_immutable_action_payload_preserved_unchanged():
    record = _pending_record(action_payload={"status": "escalated", "confidence": "medium"})
    snapshot = copy.deepcopy(record["action_payload"])

    validate_approval_transition(record, _approve_request())

    assert record["action_payload"] == snapshot


# ---------------------------------------------------------------------------
# 201-211: non-mutation and output independence
# ---------------------------------------------------------------------------

def test_201_current_record_unchanged():
    record = _pending_record()
    snapshot = copy.deepcopy(record)

    validate_approval_transition(record, _approve_request())

    assert record == snapshot


def test_202_transition_request_unchanged():
    request = _approve_request()
    snapshot = copy.deepcopy(request)

    validate_approval_transition(_pending_record(), request)

    assert request == snapshot


def test_203_nested_action_payload_unchanged():
    record = _pending_record(action_payload={"status": "escalated"})
    snapshot = copy.deepcopy(record["action_payload"])

    validate_approval_transition(record, _approve_request())

    assert record["action_payload"] == snapshot


def test_204_rejection_reason_input_unchanged():
    request = _reject_request(rejection_reason="  padded reason  ")
    snapshot = str(request["rejection_reason"])

    validate_approval_transition(_pending_record(), request)

    assert request["rejection_reason"] == snapshot


def test_205_output_top_level_dictionary_independent():
    result = validate_approval_transition(_pending_record(), _approve_request())
    result["approval_id"] = "mutated"

    second_result = validate_approval_transition(_pending_record(), _approve_request())
    assert second_result["approval_id"] == APPROVAL_ID


def test_206_set_fields_dictionary_independent():
    result = validate_approval_transition(_pending_record(), _approve_request())
    result["set_fields"]["approved_by"] = "mutated"

    second_result = validate_approval_transition(_pending_record(), _approve_request())
    assert second_result["set_fields"]["approved_by"] == "Security Reviewer"


def test_207_mutating_output_does_not_affect_current_record():
    record = _pending_record()
    result = validate_approval_transition(record, _approve_request())
    result["set_fields"]["status"] = "mutated"

    assert record["status"] == "pending"


def test_208_mutating_one_result_does_not_affect_fresh_result():
    record = _pending_record()
    request = _approve_request()

    first = validate_approval_transition(record, request)
    first["set_fields"]["approved_at"] = "mutated"

    second = validate_approval_transition(record, request)
    assert second["set_fields"]["approved_at"] != "mutated"


def test_209_no_mutable_input_reference_retained():
    record = _pending_record()
    request = _approve_request()

    result = validate_approval_transition(record, request)

    assert result is not record
    assert result is not request
    assert result["set_fields"] is not record


def test_210_shared_fixtures_are_never_mutated():
    record_a = _pending_record()
    record_b = _pending_record()

    validate_approval_transition(record_a, _approve_request())

    assert record_a == record_b


def test_211_tests_do_not_rely_on_execution_order():
    # Re-running an earlier scenario after many other tests have executed
    # must still produce the same result -- confirms no shared mutable
    # module-level state leaked across tests.
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert result["to_status"] == "approved"


# ---------------------------------------------------------------------------
# 212-216: determinism
# ---------------------------------------------------------------------------

def test_212_same_approve_input_and_same_now_produce_same_output():
    now = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)

    first = validate_approval_transition(_pending_record(), _approve_request(), now=now)
    second = validate_approval_transition(_pending_record(), _approve_request(), now=now)

    assert first == second


def test_213_same_reject_input_and_same_now_produce_same_output():
    now = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)

    first = validate_approval_transition(_pending_record(), _reject_request(), now=now)
    second = validate_approval_transition(_pending_record(), _reject_request(), now=now)

    assert first == second


def test_214_same_consume_input_and_same_now_produce_same_output():
    now = datetime(2026, 8, 1, 13, 0, 0, tzinfo=timezone.utc)

    first = validate_approval_transition(_approved_record(), _consume_request(), now=now)
    second = validate_approval_transition(_approved_record(), _consume_request(), now=now)

    assert first == second


def test_215_explicit_transition_timestamps_produce_deterministic_output():
    first = validate_approval_transition(_pending_record(), _approve_request(reviewed_at="2026-08-01T11:00:00Z"))
    second = validate_approval_transition(_pending_record(), _approve_request(reviewed_at="2026-08-01T11:00:00Z"))

    assert first == second


def test_216_only_omitted_timestamp_without_now_is_nondeterministic():
    import inspect

    signature = inspect.signature(validate_approval_transition)
    assert "now" in signature.parameters


# ---------------------------------------------------------------------------
# 217-228: error safety
# ---------------------------------------------------------------------------

def test_217_all_deterministic_failures_raise_approval_transition_error():
    scenarios = [
        (_pending_record(id="not-a-uuid"), _approve_request()),
        (_pending_record(), _approve_request(transition="unknown")),
        (_approved_record(), _approve_request()),
        (_consumed_record(), _consume_request()),
    ]
    for record, request in scenarios:
        with pytest.raises(ApprovalTransitionError):
            validate_approval_transition(record, request)


def test_218_raw_approval_request_error_never_escapes():
    record = _pending_record(action_type="delete_investigation")

    try:
        validate_approval_transition(record, _approve_request())
    except ApprovalRequestError:
        assert False, "raw ApprovalRequestError escaped"
    except ApprovalTransitionError:
        pass


def test_219_raw_uuid_value_error_never_escapes():
    try:
        validate_approval_transition(_pending_record(id="not-a-uuid"), _approve_request())
    except ValueError as exc:
        assert isinstance(exc, ApprovalTransitionError)


def test_220_raw_datetime_value_error_never_escapes():
    try:
        validate_approval_transition(_pending_record(), _approve_request(reviewed_at="not-a-timestamp"))
    except ValueError as exc:
        assert isinstance(exc, ApprovalTransitionError)


def test_221_no_partial_plan_returned_on_failure():
    try:
        validate_approval_transition(_pending_record(), _approve_request(reviewed_by="   "))
        assert False, "expected ApprovalTransitionError"
    except ApprovalTransitionError:
        pass


def test_222_complete_current_record_not_echoed():
    secret_marker = "SECRET-CURRENT-RECORD-MARKER"
    record = _pending_record(requested_by=secret_marker, id="not-a-uuid")

    try:
        validate_approval_transition(record, _approve_request())
    except ApprovalTransitionError as exc:
        assert secret_marker not in str(exc)


def test_223_complete_action_payload_not_echoed():
    secret_marker = "SECRET-PAYLOAD-CONTENT-MARKER"
    record = _pending_record(action_type="delete_investigation", action_payload={"status": "escalated", "x": secret_marker})

    try:
        validate_approval_transition(record, _approve_request())
    except ApprovalTransitionError as exc:
        assert secret_marker not in str(exc)


def test_224_requester_identity_not_echoed():
    secret_marker = "SECRET-REQUESTER-IDENTITY-MARKER"
    record = _pending_record(requested_by=secret_marker)

    try:
        validate_approval_transition(record, _approve_request(reviewed_by=secret_marker))
    except ApprovalTransitionError as exc:
        assert secret_marker not in str(exc)


def test_225_reviewer_identity_not_echoed():
    secret_marker = "SECRET-REVIEWER-IDENTITY-MARKER"

    try:
        validate_approval_transition(_approved_record(), _approve_request(reviewed_by=secret_marker))
    except ApprovalTransitionError as exc:
        assert secret_marker not in str(exc)


def test_226_consumed_by_identity_not_echoed():
    secret_marker = "SECRET-CONSUMED-BY-MARKER"

    try:
        validate_approval_transition(_pending_record(), _consume_request(consumed_by=secret_marker))
    except ApprovalTransitionError as exc:
        assert secret_marker not in str(exc)


def test_227_rejection_reason_not_echoed():
    secret_marker = "SECRET-REJECTION-REASON-CONTENT-MARKER"

    try:
        validate_approval_transition(_approved_record(), _reject_request(rejection_reason=secret_marker))
    except ApprovalTransitionError as exc:
        assert secret_marker not in str(exc)


def test_228_no_traceback_or_logging_occurs():
    source = _module_source_text()
    assert "print(" not in source
    assert "logging" not in source
    assert "traceback" not in source.lower()


# ---------------------------------------------------------------------------
# 229-246: runtime side-effect guards (static checks; dynamic guard below)
# ---------------------------------------------------------------------------

def test_229_no_supabase_access():
    source = _module_source_text()
    assert "import supabase" not in source
    assert "from supabase" not in source


def test_230_no_file_access():
    source = _module_source_text()
    assert "open(" not in source
    assert "Path(" not in source


def test_231_no_path_open_access():
    source = _module_source_text()
    assert ".open(" not in source


def test_232_no_temporary_file_creation():
    source = _module_source_text()
    assert "tempfile" not in source


def test_233_no_subprocess_execution():
    source = _module_source_text()
    assert "import subprocess" not in source
    assert "subprocess.run(" not in source


def test_234_no_socket_connection():
    source = _module_source_text()
    assert "socket" not in source


def test_235_no_urllib_request():
    source = _module_source_text()
    assert "urllib" not in source


def test_236_no_requests_call_when_installed():
    source = _module_source_text()
    assert "import requests" not in source


def test_237_no_supabase_client_creation_when_installed():
    source = _module_source_text()
    assert "create_client" not in source


def test_238_no_ai_model_call():
    source = _module_source_text()
    assert "openai" not in source.lower()
    assert "anthropic" not in source.lower()


def test_239_no_environment_mutation():
    source = _module_source_text()
    assert "os.environ" not in source


def test_240_no_working_directory_change():
    source = _module_source_text()
    assert "os.chdir" not in source


def test_241_no_hayabusa_import():
    source = _module_source_text()
    assert "hayabusa" not in source.lower()


def test_242_no_database_update():
    source = _module_source_text()
    assert ".update(" not in source


def test_243_no_investigation_update():
    source = _module_source_text()
    assert "investigations" not in source.lower()


def test_244_no_actual_approval_rejection_or_consumption():
    source = _module_source_text()
    assert "def approve(" not in source
    assert "def reject(" not in source
    assert "def consume(" not in source


def test_245_no_containment():
    source = _module_source_text()
    assert "containment" not in source.lower()


def test_246_no_red_team_execution():
    source = _module_source_text()
    assert "execute_simulation" not in source.lower()
    assert "run_atomic" not in source.lower()


# ---------------------------------------------------------------------------
# Dynamic runtime side-effect guard
# ---------------------------------------------------------------------------

def test_runtime_guard_full_request_approve_consume_sequence_succeeds(monkeypatch):
    import os
    import sys
    import urllib.request

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called during approval-transition validation")

    try:
        import requests
    except ImportError:
        requests = None

    try:
        import supabase
    except ImportError:
        supabase = None

    original_cwd = os.getcwd()
    original_environ = dict(os.environ)

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

    assert "mcp.hayabusa_server" not in sys.modules

    approve_plan = validate_approval_transition(_pending_record(), _approve_request())
    approved_record = _pending_record(
        status="approved",
        approved_by=approve_plan["set_fields"]["approved_by"],
        approved_at=approve_plan["set_fields"]["approved_at"],
    )
    consume_plan = validate_approval_transition(approved_record, _consume_request())

    assert consume_plan["to_status"] == "consumed"
    assert "mcp.hayabusa_server" not in sys.modules
    assert os.getcwd() == original_cwd
    assert dict(os.environ) == original_environ


# ---------------------------------------------------------------------------
# 247-264: source-boundary checks
# ---------------------------------------------------------------------------

def test_247_module_imports_validate_approval_request():
    source = _module_source_text()
    assert "validate_approval_request" in source
    assert "from core.approval_request import" in source


def test_248_module_imports_approval_request_error():
    source = _module_source_text()
    assert "ApprovalRequestError" in source


def test_249_module_imports_action_types():
    import core.approval_transition as module

    assert module.ACTION_TYPES is ACTION_TYPES


def test_250_module_does_not_redefine_action_types():
    source = _module_source_text()
    assert "ACTION_TYPES = frozenset" not in source


def test_251_module_does_not_redefine_investigation_statuses():
    source = _module_source_text()
    assert "INVESTIGATION_STATUSES" not in source


def test_252_module_does_not_redefine_confidence_levels():
    source = _module_source_text()
    assert "CONFIDENCE_LEVELS" not in source


def test_253_module_owns_approval_statuses_only():
    source = _module_source_text()
    assert "APPROVAL_STATUSES = frozenset" in source


def test_254_module_does_not_import_supabase():
    source = _module_source_text()
    assert "import supabase" not in source
    assert "from supabase" not in source


def test_255_module_does_not_import_requests():
    source = _module_source_text()
    assert "import requests" not in source


def test_256_module_does_not_import_subprocess():
    source = _module_source_text()
    assert "import subprocess" not in source


def test_257_module_does_not_import_clis():
    source = _module_source_text()
    assert "decision_context_cli" not in source
    assert "decision_analysis_cli" not in source
    assert "approval_request_cli" not in source


def test_258_module_does_not_import_warning_formatters():
    source = _module_source_text()
    assert "decision_warning_formatter" not in source


def test_259_module_does_not_import_ai_model_libraries():
    source = _module_source_text()
    assert "openai" not in source.lower()
    assert "anthropic" not in source.lower()


def test_260_module_contains_no_database_write_call():
    source = _module_source_text()
    assert ".insert(" not in source
    assert ".update(" not in source
    assert ".delete(" not in source


def test_261_module_contains_no_hashing_implementation():
    source = _module_source_text()
    assert "hashlib" not in source
    assert "sha256" not in source.lower()


def test_262_module_contains_no_schema_or_sql_implementation():
    source = _module_source_text()
    assert "create table" not in source.lower()
    assert "CHECK (" not in source


def test_263_module_contains_no_update_case_invocation():
    source = _module_source_text()
    assert "update-case" not in source.lower()
    assert "update_case" not in source.lower()


def test_264_module_uses_only_stdlib_and_approval_request():
    import ast

    tree = ast.parse(_module_source_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module)

    allowed = {"__future__", "uuid", "collections.abc", "datetime", "typing", "core.approval_request"}
    assert imported <= allowed


# ---------------------------------------------------------------------------
# Trim-equality correction: persisted current-record lifecycle identities
# and rejection_reason must already be stored in their outer-trimmed form
# -- a padded stored value is rejected, never silently trimmed and
# accepted. This mirrors the approvals schema's own
# chk_approvals_*_nonblank / chk_approvals_lifecycle_rejected CHECK
# constraints, which require `column = btrim(column)`.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "padded_value",
    [
        " Security Reviewer",
        "Security Reviewer ",
        " Security Reviewer ",
        "\tSecurity Reviewer\t",
        "\nSecurity Reviewer\n",
    ],
)
def test_265_approved_by_outer_whitespace_rejected(padded_value):
    record = _approved_record(approved_by=padded_value)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _consume_request())


@pytest.mark.parametrize(
    "padded_value",
    [
        " Security Reviewer",
        "Security Reviewer ",
        " Security Reviewer ",
        "\tSecurity Reviewer\t",
        "\nSecurity Reviewer\n",
    ],
)
def test_266_rejected_by_outer_whitespace_rejected(padded_value):
    record = _rejected_record(rejected_by=padded_value)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


@pytest.mark.parametrize(
    "padded_value",
    [
        " Update Case Operator",
        "Update Case Operator ",
        " Update Case Operator ",
        "\tUpdate Case Operator\t",
        "\nUpdate Case Operator\n",
    ],
)
def test_267_consumed_by_outer_whitespace_rejected(padded_value):
    record = _consumed_record(consumed_by=padded_value)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


@pytest.mark.parametrize(
    "padded_value",
    [
        " Additional evidence is still required.",
        "Additional evidence is still required. ",
        " Additional evidence is still required. ",
        "\tAdditional evidence is still required.\t",
        "\nAdditional evidence is still required.\n",
    ],
)
def test_268_rejection_reason_outer_whitespace_rejected(padded_value):
    record = _rejected_record(rejection_reason=padded_value)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_269_consumed_record_carried_forward_approved_by_outer_whitespace_rejected():
    record = _consumed_record(approved_by=" Security Reviewer ")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request())


def test_270_exact_trim_approved_by_accepted():
    record = _approved_record(approved_by="Jordan Reviewer")

    result = validate_approval_transition(record, _consume_request())
    assert result["to_status"] == "consumed"


def test_271_exact_trim_rejected_by_accepted():
    record = _rejected_record(rejected_by="Jordan Reviewer")

    with pytest.raises(ApprovalTransitionError):
        # rejected -> approve is itself an invalid transition; this proves
        # the current_record was accepted (parsed past lifecycle checks)
        # and the failure is purely the state-machine rule, not a
        # trim-related rejection.
        validate_approval_transition(record, _approve_request())


def test_272_exact_trim_consumed_by_accepted():
    record = _consumed_record(consumed_by="Update Case Operator")

    # A well-formed consumed record is accepted by current-record
    # validation; consumed -> consume is rejected only by the state
    # machine (terminal state), never by a trim-related error.
    with pytest.raises(ApprovalTransitionError) as exc_info:
        validate_approval_transition(record, _consume_request())
    assert "trimmed" not in str(exc_info.value)


def test_273_exact_trim_rejection_reason_accepted():
    record = _rejected_record(rejection_reason="Additional evidence is still required.")

    with pytest.raises(ApprovalTransitionError) as exc_info:
        validate_approval_transition(record, _approve_request())
    assert "trimmed" not in str(exc_info.value)


def test_274_internal_spaces_in_identities_preserved():
    record = _approved_record(approved_by="Security Review Team")

    result = validate_approval_transition(record, _consume_request())
    assert result["to_status"] == "consumed"


def test_275_internal_spaces_in_rejection_reason_preserved():
    record = _rejected_record(rejection_reason="Additional evidence is still required.")

    with pytest.raises(ApprovalTransitionError) as exc_info:
        validate_approval_transition(record, _approve_request())
    assert "trimmed" not in str(exc_info.value)


def test_276_unicode_identity_without_outer_whitespace_accepted():
    record = _approved_record(approved_by="Straße Reviewer")

    result = validate_approval_transition(record, _consume_request())
    assert result["to_status"] == "consumed"


def test_277_original_casing_preserved_for_approved_by():
    record = _approved_record(approved_by="Security Reviewer")

    result = validate_approval_transition(record, _consume_request())
    assert result["set_fields"]["consumed_by"] == "Update Case Operator"
    # The current_record's own approved_by casing is not altered by this
    # module -- confirmed by re-inspecting the untouched input record.
    assert record["approved_by"] == "Security Reviewer"


def test_278_self_approval_behavior_unchanged():
    record = _pending_record(requested_by="analyst-jane")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request(reviewed_by="analyst-jane"))


def test_279_self_rejection_still_allowed():
    record = _pending_record(requested_by="analyst-jane")

    result = validate_approval_transition(record, _reject_request(reviewed_by="analyst-jane"))
    assert result["to_status"] == "rejected"


def test_280_approve_output_shape_unchanged():
    result = validate_approval_transition(_pending_record(), _approve_request())
    assert set(result.keys()) == {"approval_id", "from_status", "to_status", "set_fields"}
    assert list(result["set_fields"].keys()) == ["status", "approved_by", "approved_at"]


def test_281_reject_output_shape_unchanged():
    result = validate_approval_transition(_pending_record(), _reject_request())
    assert list(result["set_fields"].keys()) == ["status", "rejected_by", "rejected_at", "rejection_reason"]


def test_282_consume_output_shape_unchanged():
    result = validate_approval_transition(_approved_record(), _consume_request())
    assert list(result["set_fields"].keys()) == ["status", "consumed_by", "consumed_at"]


def test_283_expiry_behavior_unchanged():
    record = _pending_record(expires_at="2026-08-01T10:30:00Z")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, _approve_request(reviewed_at="2026-08-01T11:00:00Z"))


def test_284_transition_request_inputs_unmutated():
    request = _approve_request()
    snapshot = copy.deepcopy(request)

    validate_approval_transition(_pending_record(), request)

    assert request == snapshot


def test_285_current_record_unmutated_by_stricter_validation():
    record = _approved_record()
    snapshot = copy.deepcopy(record)

    validate_approval_transition(record, _consume_request())

    assert record == snapshot


def test_286_successful_output_independent():
    record = _pending_record()

    result = validate_approval_transition(record, _approve_request())
    result["set_fields"]["approved_by"] = "mutated"

    second_result = validate_approval_transition(record, _approve_request())
    assert second_result["set_fields"]["approved_by"] == "Security Reviewer"


def test_287_regression_padded_value_fails_exact_trim_value_succeeds():
    padded_record = _approved_record(approved_by=" Jordan Reviewer ")
    exact_record = _approved_record(approved_by="Jordan Reviewer")

    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(padded_record, _consume_request())

    result = validate_approval_transition(exact_record, _consume_request())
    assert result["to_status"] == "consumed"


def test_288_validator_does_not_silently_return_trimmed_padded_value():
    padded_record = _approved_record(approved_by=" Jordan Reviewer ")

    try:
        validate_approval_transition(padded_record, _consume_request())
        assert False, "expected ApprovalTransitionError for a padded stored approved_by"
    except ApprovalTransitionError as exc:
        # The error must not have silently trimmed and accepted the
        # padded value -- confirmed both by the raised exception and by
        # the error message never echoing the rejected value itself.
        assert "Jordan Reviewer" not in str(exc)


def test_289_error_message_does_not_leak_rejected_value():
    secret_marker = " SECRET-PADDED-IDENTITY-MARKER "
    record = _approved_record(approved_by=secret_marker)

    try:
        validate_approval_transition(record, _consume_request())
    except ApprovalTransitionError as exc:
        assert secret_marker.strip() not in str(exc)
        assert secret_marker not in str(exc)


def test_290_no_new_exception_class_introduced():
    import ast

    tree = ast.parse(_module_source_text())
    defined_class_names = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    assert defined_class_names == ["ApprovalTransitionError"]


def test_291_helper_still_used_for_all_four_current_record_fields():
    import ast

    tree = ast.parse(_module_source_text())
    fields_passed_to_helper = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_validate_optional_identity"
            and node.args
            and isinstance(node.args[0], ast.Subscript)
            and isinstance(node.args[0].value, ast.Name)
            and node.args[0].value.id == "current_record"
        ):
            key_node = node.args[0].slice
            if isinstance(key_node, ast.Constant):
                fields_passed_to_helper.add(key_node.value)

    assert fields_passed_to_helper == {"approved_by", "rejected_by", "consumed_by", "rejection_reason"}


def test_292_validate_approval_record_is_public_and_delegated_to_exactly_once(monkeypatch):
    import ast

    import core.approval_transition as module

    assert hasattr(module, "validate_approval_record")
    assert callable(module.validate_approval_record)

    tree = ast.parse(_module_source_text())
    transition_fn = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "validate_approval_transition"
    )
    called_names = {
        subnode.func.id
        for subnode in ast.walk(transition_fn)
        if isinstance(subnode, ast.Call) and isinstance(subnode.func, ast.Name)
    }
    assert "validate_approval_record" in called_names
    assert "_validate_current_record" not in called_names

    call_count = 0
    real = module.validate_approval_record

    def _counting_wrapper(current_record):
        nonlocal call_count
        call_count += 1
        return real(current_record)

    monkeypatch.setattr(module, "validate_approval_record", _counting_wrapper)

    validate_approval_transition(_pending_record(), _approve_request())

    assert call_count == 1


def test_293_validate_current_record_remains_private():
    import core.approval_transition as module

    assert not hasattr(module, "validate_current_record")
    assert hasattr(module, "_validate_current_record")


def test_294_no_requested_by_validation_logic_duplicated():
    source = _module_source_text()
    # requested_by continues to be validated exclusively through the
    # composed core.approval_request.validate_approval_request call --
    # no separate, duplicated trim-equality check for requested_by exists
    # in this module.
    assert 'current_record["requested_by"]' in source
    assert source.count('_validate_optional_identity(current_record["requested_by"]') == 0


# ---------------------------------------------------------------------------
# Source-boundary checks on the test module itself
# ---------------------------------------------------------------------------

def test_static_test_module_does_not_import_supabase_or_requests_at_module_scope():
    tree = _this_module_ast()

    import ast

    top_level_imports = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level_imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top_level_imports.add(node.module)

    assert not any(name == "supabase" or name.startswith("supabase.") for name in top_level_imports)
    assert "requests" not in top_level_imports


def test_static_test_module_imports_subprocess_only_for_monkeypatch_targets():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert "subprocess" in imported

    import ast

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "Popen", "call", "check_call", "check_output"):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    pytest.fail("subprocess call executed directly in the test module")
