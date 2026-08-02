"""Tests for core.approval_transition.validate_approval_record -- the
public, pure validator for one complete approval-record snapshot,
evaluated in isolation and independent of any proposed lifecycle
transition.

This module does not test lifecycle-transition semantics themselves
(approve/reject/consume state-machine rules, two-person separation,
transition-request shape) -- those remain fully covered by
tests/test_approval_transition.py. This file covers only the public
`validate_approval_record` contract: its exact input/output shape, its
delegation to the existing (still-private) current-record validation,
and the record-level rules that validator enforces on its own.

No Supabase, file, subprocess, network, or AI/model access occurs anywhere
in this file; every input is a plain in-memory mapping.
"""

import ast
import copy
import inspect
import socket
import subprocess
import urllib.request
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.approval_transition import (
    ApprovalTransitionError,
    validate_approval_record,
    validate_approval_transition,
)
from core.approval_request import ApprovalRequestError

INVESTIGATION_ID = "22222222-2222-4222-8222-222222222222"
APPROVAL_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

REQUESTED_AT = "2026-08-01T10:00:00Z"
CREATED_AT = "2026-08-01T10:00:00Z"
APPROVED_AT = "2026-08-01T11:00:00Z"
REJECTED_AT = "2026-08-01T11:00:00Z"
CONSUMED_AT = "2026-08-01T12:00:00Z"
EXPIRES_AT = "2026-08-03T00:00:00Z"

REJECTION_REASON = "The proposed status change is not sufficiently supported."

# A wholly separate, long-past timeline used only to prove that
# validate_approval_record never consults wall-clock time: every value
# below is chronologically self-consistent, but "expired" many years
# before this suite ever runs.
OLD_REQUESTED_AT = "2020-01-01T00:00:00Z"
OLD_CREATED_AT = "2020-01-01T00:00:00Z"
OLD_APPROVED_AT = "2020-01-01T12:00:00Z"
OLD_CONSUMED_AT = "2020-01-01T18:00:00Z"
OLD_EXPIRES_AT = "2020-01-02T00:00:00Z"

_ALL_FIELDS = (
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


def _module_ast():
    return ast.parse(_module_source_text())


def _this_module_ast():
    return ast.parse(Path(__file__).read_text(encoding="utf-8"))


def _function_def(tree, name):
    return next(
        node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name
    )


def _called_names(node):
    return {
        subnode.func.id
        for subnode in ast.walk(node)
        if isinstance(subnode, ast.Call) and isinstance(subnode.func, ast.Name)
    }


def _referenced_identifiers(tree):
    """Collect identifiers actually referenced as code (ast.Name/ast.Attribute),
    excluding string constants -- so a bare substring search against this
    file's own text never self-matches an assertion literal that merely
    names the forbidden identifier."""
    return {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }


# ---------------------------------------------------------------------------
# 001-010: public contract
# ---------------------------------------------------------------------------


def test_001_validate_approval_record_is_importable_and_callable():
    assert callable(validate_approval_record)


def test_002_accepts_a_single_positional_argument():
    result = validate_approval_record(_pending_record())
    assert isinstance(result, dict)


def test_003_rejects_now_keyword_argument():
    with pytest.raises(TypeError):
        validate_approval_record(_pending_record(), now=datetime.now(timezone.utc))


def test_004_rejects_transition_request_keyword_argument():
    with pytest.raises(TypeError):
        validate_approval_record(_pending_record(), transition_request=_approve_request())


def test_005_returns_a_dict_for_valid_pending_input():
    result = validate_approval_record(_pending_record())
    assert isinstance(result, dict)


def test_006_docstring_contains_exact_contract_phrase():
    assert "Validated approval record -- not proof of persistence" in validate_approval_record.__doc__


def test_007_raises_approval_transition_error_for_invalid_input():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record({"not": "a full record"})


def test_008_never_lets_approval_request_error_escape():
    bad_record = _pending_record(action_payload={"status": "not-a-real-status"})
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(bad_record)
    try:
        validate_approval_record(bad_record)
    except ApprovalRequestError:
        pytest.fail("ApprovalRequestError must never escape validate_approval_record")
    except ApprovalTransitionError:
        pass


def test_009_two_valid_calls_produce_equal_output():
    first = validate_approval_record(_pending_record())
    second = validate_approval_record(_pending_record())
    assert first == second


def test_010_two_valid_calls_produce_independent_dict_objects():
    first = validate_approval_record(_pending_record())
    second = validate_approval_record(_pending_record())
    assert first is not second


# ---------------------------------------------------------------------------
# 011-020: valid lifecycle records
# ---------------------------------------------------------------------------


def test_011_valid_pending_record_accepted():
    result = validate_approval_record(_pending_record())
    assert result["status"] == "pending"


def test_012_valid_approved_record_accepted():
    result = validate_approval_record(_approved_record())
    assert result["status"] == "approved"


def test_013_valid_rejected_record_accepted():
    result = validate_approval_record(_rejected_record())
    assert result["status"] == "rejected"


def test_014_valid_consumed_record_accepted():
    result = validate_approval_record(_consumed_record())
    assert result["status"] == "consumed"


def test_015_pending_record_with_expires_at_accepted():
    result = validate_approval_record(_pending_record(expires_at=EXPIRES_AT))
    assert result["expires_at"] == EXPIRES_AT


def test_016_approved_record_with_expires_at_accepted():
    result = validate_approval_record(_approved_record(expires_at=EXPIRES_AT))
    assert result["expires_at"] == EXPIRES_AT


def test_017_rejected_record_with_expires_at_accepted():
    result = validate_approval_record(_rejected_record(expires_at=EXPIRES_AT))
    assert result["expires_at"] == EXPIRES_AT


def test_018_consumed_record_with_expires_at_accepted():
    result = validate_approval_record(_consumed_record(expires_at=EXPIRES_AT))
    assert result["expires_at"] == EXPIRES_AT


def test_019_action_payload_with_status_and_confidence_accepted():
    record = _pending_record(action_payload={"status": "escalated", "confidence": "high"})
    result = validate_approval_record(record)
    assert result["action_payload"] == {"status": "escalated", "confidence": "high"}


def test_020_action_payload_with_only_confidence_accepted():
    record = _pending_record(action_payload={"confidence": "high"})
    result = validate_approval_record(record)
    assert result["action_payload"] == {"confidence": "high"}


# ---------------------------------------------------------------------------
# 021-030: canonicalization
# ---------------------------------------------------------------------------


def test_021_id_canonicalized_to_lowercase_hyphenated_form():
    record = _pending_record(id=f" {APPROVAL_ID.upper()} ")
    result = validate_approval_record(record)
    assert result["id"] == APPROVAL_ID


def test_022_investigation_id_canonicalized():
    record = _pending_record(investigation_id=" 22222222-2222-4222-8222-222222222222 ".upper())
    result = validate_approval_record(record)
    assert result["investigation_id"] == INVESTIGATION_ID


def test_023_requested_at_accepted_as_datetime_object():
    dt = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)
    result = validate_approval_record(_pending_record(requested_at=dt))
    assert result["requested_at"] == REQUESTED_AT


def test_024_requested_at_accepted_with_explicit_offset_string():
    result = validate_approval_record(_pending_record(requested_at="2026-08-01T10:00:00+00:00"))
    assert result["requested_at"] == REQUESTED_AT


def test_025_created_at_accepted_as_datetime_object():
    dt = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)
    result = validate_approval_record(_pending_record(created_at=dt))
    assert result["created_at"] == CREATED_AT


def test_026_approved_at_accepted_as_datetime_object():
    dt = datetime(2026, 8, 1, 11, 0, 0, tzinfo=timezone.utc)
    result = validate_approval_record(_approved_record(approved_at=dt))
    assert result["approved_at"] == APPROVED_AT


def test_027_rejected_at_accepted_as_datetime_object():
    dt = datetime(2026, 8, 1, 11, 0, 0, tzinfo=timezone.utc)
    result = validate_approval_record(_rejected_record(rejected_at=dt))
    assert result["rejected_at"] == REJECTED_AT


def test_028_consumed_at_accepted_as_datetime_object():
    dt = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
    result = validate_approval_record(_consumed_record(consumed_at=dt))
    assert result["consumed_at"] == CONSUMED_AT


def test_029_expires_at_accepted_as_datetime_object():
    dt = datetime(2026, 8, 3, 0, 0, 0, tzinfo=timezone.utc)
    result = validate_approval_record(_pending_record(expires_at=dt))
    assert result["expires_at"] == EXPIRES_AT


def test_030_status_accepted_case_insensitively():
    result = validate_approval_record(_pending_record(status="PENDING"))
    assert result["status"] == "pending"


# ---------------------------------------------------------------------------
# 031-050: exact record shape / missing-field
# ---------------------------------------------------------------------------


def test_031_output_key_set_matches_exactly_the_sixteen_fields():
    result = validate_approval_record(_pending_record())
    assert set(result) == set(_ALL_FIELDS)


def test_032_output_key_order_matches_exact_committed_order():
    result = validate_approval_record(_pending_record())
    assert list(result) == list(_ALL_FIELDS)


@pytest.mark.parametrize("missing_field", _ALL_FIELDS)
def test_033_missing_field_raises(missing_field):
    record = _pending_record()
    del record[missing_field]
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(record)


def test_049_unknown_extra_field_raises():
    record = _pending_record(extra_field="unexpected")
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(record)


def test_050_non_mapping_input_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(["not", "a", "mapping"])


# ---------------------------------------------------------------------------
# 051-070: lifecycle validation
# ---------------------------------------------------------------------------


def test_051_invalid_status_value_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(status="not-a-real-status"))


def test_052_pending_with_approved_by_set_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(approved_by="Security Reviewer"))


def test_053_pending_with_approved_at_set_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(approved_at=APPROVED_AT))


def test_054_pending_with_rejected_by_set_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(rejected_by="Security Reviewer"))


def test_055_pending_with_rejected_at_set_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(rejected_at=REJECTED_AT))


def test_056_pending_with_rejection_reason_set_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(rejection_reason=REJECTION_REASON))


def test_057_pending_with_consumed_by_set_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(consumed_by="Update Case Operator"))


def test_058_pending_with_consumed_at_set_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(consumed_at=CONSUMED_AT))


def test_059_approved_missing_approved_by_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_approved_record(approved_by=None))


def test_060_approved_missing_approved_at_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_approved_record(approved_at=None))


def test_061_approved_with_rejected_by_set_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_approved_record(rejected_by="Security Reviewer"))


def test_062_approved_with_consumed_by_set_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_approved_record(consumed_by="Update Case Operator"))


def test_063_rejected_missing_rejected_by_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_rejected_record(rejected_by=None))


def test_064_rejected_missing_rejected_at_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_rejected_record(rejected_at=None))


def test_065_rejected_missing_rejection_reason_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_rejected_record(rejection_reason=None))


def test_066_rejected_with_approved_by_set_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_rejected_record(approved_by="Security Reviewer"))


def test_067_rejected_with_consumed_by_set_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_rejected_record(consumed_by="Update Case Operator"))


def test_068_consumed_missing_approved_by_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_consumed_record(approved_by=None))


def test_069_consumed_missing_consumed_by_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_consumed_record(consumed_by=None))


def test_070_consumed_with_rejected_by_set_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_consumed_record(rejected_by="Security Reviewer"))


# ---------------------------------------------------------------------------
# 071-081: canonical persisted text / trim-equality
# ---------------------------------------------------------------------------


def test_071_approved_by_leading_whitespace_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_approved_record(approved_by=" Security Reviewer"))


def test_072_approved_by_trailing_whitespace_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_approved_record(approved_by="Security Reviewer "))


def test_073_rejected_by_padding_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_rejected_record(rejected_by=" Security Reviewer "))


def test_074_consumed_by_padding_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_consumed_record(consumed_by=" Update Case Operator "))


def test_075_rejection_reason_padding_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_rejected_record(rejection_reason=f" {REJECTION_REASON} "))


def test_076_internal_whitespace_preserved_exactly():
    record = _approved_record(approved_by="Security  Team Reviewer")
    result = validate_approval_record(record)
    assert result["approved_by"] == "Security  Team Reviewer"


def test_077_unicode_casing_preserved_exactly():
    record = _approved_record(approved_by="Straße Reviewer")
    result = validate_approval_record(record)
    assert result["approved_by"] == "Straße Reviewer"


def test_078_blank_approved_by_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_approved_record(approved_by="   "))


def test_079_non_string_approved_by_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_approved_record(approved_by=12345))


def test_080_none_accepted_for_all_optional_identity_fields_when_pending():
    result = validate_approval_record(_pending_record())
    assert result["approved_by"] is None
    assert result["rejected_by"] is None
    assert result["consumed_by"] is None
    assert result["rejection_reason"] is None


def test_081_consumed_records_carried_forward_approved_by_must_be_trimmed():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_consumed_record(approved_by=" Security Reviewer"))


# ---------------------------------------------------------------------------
# 082-092: request-side composition (delegated to core.approval_request)
# ---------------------------------------------------------------------------


def test_082_non_mapping_action_payload_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(action_payload=["not", "a", "mapping"]))


def test_083_unknown_action_payload_field_raises():
    record = _pending_record(action_payload={"status": "escalated", "unexpected": "value"})
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(record)


def test_084_empty_action_payload_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(action_payload={}))


def test_085_blank_requested_by_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(requested_by="   "))


def test_086_padded_requested_by_is_trimmed_and_accepted():
    result = validate_approval_record(_pending_record(requested_by="  analyst-jane  "))
    assert result["requested_by"] == "analyst-jane"


def test_087_malformed_investigation_id_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(investigation_id="not-a-uuid"))


def test_088_action_type_not_in_vocabulary_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(action_type="delete_everything"))


def test_089_null_requested_at_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(requested_at=None))


def test_090_request_side_failure_raises_approval_transition_error_only():
    with pytest.raises(ApprovalTransitionError) as excinfo:
        validate_approval_record(_pending_record(investigation_id="not-a-uuid"))
    assert not isinstance(excinfo.value, ApprovalRequestError)


def test_091_request_side_failure_message_does_not_leak_action_payload_content():
    secret_marker = "top-secret-payload-marker"
    record = _pending_record(action_payload={"status": "escalated", secret_marker: "x"})
    with pytest.raises(ApprovalTransitionError) as excinfo:
        validate_approval_record(record)
    assert secret_marker not in str(excinfo.value)


def test_092_request_side_failure_message_does_not_leak_requested_by_value():
    secret_marker = "confidential-analyst-handle"
    record = _pending_record(requested_by=secret_marker)
    # Force a different, unrelated request-side failure so requested_by
    # itself is never part of the success path or the error message.
    record["action_type"] = "delete_everything"
    with pytest.raises(ApprovalTransitionError) as excinfo:
        validate_approval_record(record)
    assert secret_marker not in str(excinfo.value)


# ---------------------------------------------------------------------------
# 093-105: chronology
# ---------------------------------------------------------------------------


def test_093_created_at_before_requested_at_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(created_at="2026-08-01T09:00:00Z"))


def test_094_created_at_equal_to_requested_at_accepted():
    result = validate_approval_record(_pending_record(created_at=REQUESTED_AT))
    assert result["created_at"] == REQUESTED_AT


def test_095_expires_at_equal_to_requested_at_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(expires_at=REQUESTED_AT))


def test_096_expires_at_after_requested_at_accepted():
    result = validate_approval_record(_pending_record(expires_at=EXPIRES_AT))
    assert result["expires_at"] == EXPIRES_AT


def test_097_approved_at_before_requested_at_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_approved_record(approved_at="2026-08-01T09:00:00Z"))


def test_098_approved_at_equal_to_requested_at_accepted():
    result = validate_approval_record(_approved_record(approved_at=REQUESTED_AT))
    assert result["approved_at"] == REQUESTED_AT


def test_099_rejected_at_before_requested_at_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_rejected_record(rejected_at="2026-08-01T09:00:00Z"))


def test_100_consumed_at_before_approved_at_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_consumed_record(consumed_at=REQUESTED_AT))


def test_101_consumed_at_equal_to_approved_at_accepted():
    result = validate_approval_record(_consumed_record(consumed_at=APPROVED_AT))
    assert result["consumed_at"] == APPROVED_AT


def test_102_approved_at_equal_to_expires_at_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_approved_record(expires_at=APPROVED_AT))


def test_103_consumed_at_equal_to_expires_at_raises():
    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_consumed_record(expires_at=CONSUMED_AT))


def test_104_historically_expired_pending_record_still_structurally_valid():
    record = _pending_record(
        requested_at=OLD_REQUESTED_AT,
        created_at=OLD_CREATED_AT,
        expires_at=OLD_EXPIRES_AT,
    )
    result = validate_approval_record(record)
    assert result["expires_at"] == OLD_EXPIRES_AT


def test_105_historically_expired_approved_record_still_structurally_valid():
    record = _approved_record(
        requested_at=OLD_REQUESTED_AT,
        created_at=OLD_CREATED_AT,
        approved_at=OLD_APPROVED_AT,
        expires_at=OLD_EXPIRES_AT,
    )
    result = validate_approval_record(record)
    assert result["approved_at"] == OLD_APPROVED_AT
    assert result["expires_at"] == OLD_EXPIRES_AT


# ---------------------------------------------------------------------------
# 106-114: non-mutation
# ---------------------------------------------------------------------------


def test_106_input_record_not_mutated():
    record = _pending_record()
    before = copy.deepcopy(record)
    validate_approval_record(record)
    assert record == before


def test_107_nested_action_payload_not_mutated():
    record = _pending_record()
    before_payload = copy.deepcopy(record["action_payload"])
    validate_approval_record(record)
    assert record["action_payload"] == before_payload


def test_108_output_action_payload_is_independent_object():
    record = _pending_record()
    result = validate_approval_record(record)
    assert result["action_payload"] is not record["action_payload"]


def test_109_mutating_one_output_does_not_affect_a_later_call():
    first = validate_approval_record(_pending_record())
    first["status"] = "mutated"
    second = validate_approval_record(_pending_record())
    assert second["status"] == "pending"


def test_110_mutating_one_outputs_nested_payload_does_not_affect_a_later_call():
    first = validate_approval_record(_pending_record())
    first["action_payload"]["status"] = "mutated"
    second = validate_approval_record(_pending_record())
    assert second["action_payload"] == {"status": "escalated"}


def test_111_custom_read_only_mapping_input_accepted():
    record = _CustomMapping(_pending_record())
    result = validate_approval_record(record)
    assert result["status"] == "pending"


def test_112_no_key_added_to_input_mapping_as_side_effect():
    record = _pending_record()
    length_before = len(record)
    validate_approval_record(record)
    assert len(record) == length_before


def test_113_repeated_calls_on_same_input_do_not_leak_state():
    record = _pending_record()
    first = validate_approval_record(record)
    second = validate_approval_record(record)
    assert first == second


def test_114_input_key_insertion_order_preserved_after_call():
    record = _pending_record()
    keys_before = list(record.keys())
    validate_approval_record(record)
    assert list(record.keys()) == keys_before


# ---------------------------------------------------------------------------
# 115-127: output exclusions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "excluded_key",
    [
        "from_status",
        "to_status",
        "set_fields",
        "approval_id",
        "persisted",
        "row_count",
        "affected_rows",
        "transition",
        "reviewed_by",
        "reviewed_at",
        "expected_investigation_id",
        "expected_action_type",
        "now",
    ],
)
def test_115_output_never_contains_transition_or_persistence_shaped_keys(excluded_key):
    result = validate_approval_record(_consumed_record())
    assert excluded_key not in result


# ---------------------------------------------------------------------------
# 128-138: delegation and single-source-of-truth
# ---------------------------------------------------------------------------


def test_128_validate_approval_record_body_calls_the_private_helper_only():
    fn = _function_def(_module_ast(), "validate_approval_record")
    called = _called_names(fn)
    assert called == {"_validate_current_record"}


def test_129_validate_approval_record_body_contains_no_branching_logic():
    fn = _function_def(_module_ast(), "validate_approval_record")
    assert not any(isinstance(node, ast.If) for node in ast.walk(fn))
    assert not any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(fn))


def test_130_private_helper_invoked_exactly_once_via_public_wrapper(monkeypatch):
    import core.approval_transition as module

    call_count = 0
    real = module._validate_current_record

    def _counting_wrapper(current_record):
        nonlocal call_count
        call_count += 1
        return real(current_record)

    monkeypatch.setattr(module, "_validate_current_record", _counting_wrapper)

    validate_approval_record(_pending_record())

    assert call_count == 1


def test_131_private_helper_invoked_exactly_once_through_transition_path(monkeypatch):
    import core.approval_transition as module

    call_count = 0
    real = module._validate_current_record

    def _counting_wrapper(current_record):
        nonlocal call_count
        call_count += 1
        return real(current_record)

    monkeypatch.setattr(module, "_validate_current_record", _counting_wrapper)

    validate_approval_transition(_pending_record(), _approve_request())

    assert call_count == 1


def test_132_direct_and_transition_mediated_validation_agree(monkeypatch):
    import core.approval_transition as module

    captured = {}
    real = module.validate_approval_record

    def _capturing_wrapper(current_record):
        result = real(current_record)
        captured["record"] = result
        return result

    monkeypatch.setattr(module, "validate_approval_record", _capturing_wrapper)

    record = _approved_record()
    validate_approval_transition(record, _consume_request())

    direct = validate_approval_record(record)
    assert direct == captured["record"]


def test_133_validate_approval_record_public_and_helper_still_private():
    import core.approval_transition as module

    assert hasattr(module, "validate_approval_record")
    assert hasattr(module, "_validate_current_record")
    assert not hasattr(module, "validate_current_record")


def test_134_no_new_exception_class_introduced_for_validate_approval_record():
    tree = _module_ast()
    defined_classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    assert defined_classes == ["ApprovalTransitionError"]


def test_135_validate_approval_record_signature_has_exactly_one_parameter():
    signature = inspect.signature(validate_approval_record)
    parameters = list(signature.parameters.values())
    assert len(parameters) == 1
    assert parameters[0].name == "current_record"
    assert parameters[0].kind == inspect.Parameter.POSITIONAL_OR_KEYWORD


def test_136_record_valid_on_its_own_even_when_a_specific_transition_would_fail():
    record = _pending_record()
    result = validate_approval_record(record)
    assert result["status"] == "pending"
    with pytest.raises(ApprovalTransitionError):
        validate_approval_transition(record, {"transition": "approve"})


def test_137_transition_path_and_direct_call_raise_the_same_message():
    bad_record = _pending_record(investigation_id="not-a-uuid")

    with pytest.raises(ApprovalTransitionError) as direct_excinfo:
        validate_approval_record(bad_record)

    with pytest.raises(ApprovalTransitionError) as transition_excinfo:
        validate_approval_transition(bad_record, _approve_request())

    assert str(direct_excinfo.value) == str(transition_excinfo.value)


def test_138_validate_approval_record_body_never_calls_approval_request_directly():
    fn = _function_def(_module_ast(), "validate_approval_record")
    called = _called_names(fn)
    assert "validate_approval_request" not in called
    assert "ApprovalRequestError" not in called


# ---------------------------------------------------------------------------
# 139-158: runtime and source boundary
# ---------------------------------------------------------------------------


def test_139_core_module_does_not_import_supabase_at_module_scope():
    tree = _module_ast()
    top_level_imports = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level_imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top_level_imports.add(node.module)
    assert not any(name == "supabase" or name.startswith("supabase.") for name in top_level_imports)


def test_140_core_module_does_not_import_requests_at_module_scope():
    tree = _module_ast()
    top_level_imports = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level_imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top_level_imports.add(node.module)
    assert "requests" not in top_level_imports


def test_141_core_module_never_calls_subprocess():
    tree = _module_ast()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in ("run", "Popen", "call", "check_call", "check_output"):
            if isinstance(node.value, ast.Name) and node.value.id == "subprocess":
                pytest.fail("subprocess call present in core.approval_transition")


def test_142_core_module_never_references_socket():
    tree = _module_ast()
    names = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
    } | {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
    }
    assert "socket" not in names


def test_143_core_module_never_performs_file_io():
    tree = _module_ast()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            pytest.fail("open() call present in core.approval_transition")


def test_144_validate_approval_record_does_not_touch_the_network(monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden network entry point was called")

    try:
        import requests
    except ImportError:
        requests = None

    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)
    if requests is not None:
        monkeypatch.setattr(requests, "get", _forbidden)
        monkeypatch.setattr(requests, "post", _forbidden)

    result = validate_approval_record(_consumed_record())
    assert result["status"] == "consumed"


def test_145_validate_approval_record_does_not_touch_the_filesystem(monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden filesystem entry point was called")

    monkeypatch.setattr("builtins.open", _forbidden)
    monkeypatch.setattr(Path, "open", _forbidden)

    result = validate_approval_record(_consumed_record())
    assert result["status"] == "consumed"


def test_146_validate_approval_record_does_not_spawn_subprocesses(monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden subprocess entry point was called")

    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)

    result = validate_approval_record(_consumed_record())
    assert result["status"] == "consumed"


def test_147_runtime_guards_do_not_change_the_error_raised_for_invalid_input(monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called")

    monkeypatch.setattr("builtins.open", _forbidden)
    monkeypatch.setattr(Path, "open", _forbidden)
    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)

    with pytest.raises(ApprovalTransitionError):
        validate_approval_record(_pending_record(status="not-a-real-status"))


def test_148_test_module_does_not_import_supabase_at_module_scope():
    tree = _this_module_ast()
    top_level_imports = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level_imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top_level_imports.add(node.module)
    assert not any(name == "supabase" or name.startswith("supabase.") for name in top_level_imports)


def test_149_test_module_does_not_import_requests_at_module_scope():
    tree = _this_module_ast()
    top_level_imports = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level_imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top_level_imports.add(node.module)
    assert "requests" not in top_level_imports


def test_150_test_module_never_invokes_a_slash_command_or_cli_subprocess():
    tree = _this_module_ast()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "Popen", "call", "check_call", "check_output"):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    pytest.fail("subprocess call executed directly in the test module")


def test_151_test_module_never_calls_supabase_execute_sql():
    tree = _this_module_ast()
    identifiers = _referenced_identifiers(tree)
    assert "execute_sql" not in identifiers


def test_152_test_module_never_installs_packages():
    tree = _this_module_ast()
    identifiers = _referenced_identifiers(tree)
    assert "pip" not in identifiers


def test_153_core_module_source_never_references_supabase_identifier():
    tree = _module_ast()
    identifiers = {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    } | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert "supabase" not in identifiers


def test_154_core_module_source_never_imports_requests():
    tree = _module_ast()
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module)
    assert "requests" not in imported


def test_155_validate_approval_record_defined_exactly_once():
    tree = _module_ast()
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "validate_approval_record"
    ]
    assert len(matches) == 1


def test_156_test_module_contains_no_hardcoded_secret_like_identifiers():
    tree = _this_module_ast()
    identifiers = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    for forbidden in ("password", "api_key", "secret_key"):
        assert forbidden not in identifiers


def test_157_test_module_only_imports_expected_modules():
    tree = _this_module_ast()
    top_level_imports = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level_imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top_level_imports.add(node.module.split(".")[0])

    allowed = {
        "ast",
        "copy",
        "inspect",
        "socket",
        "subprocess",
        "urllib",
        "collections",
        "datetime",
        "pathlib",
        "pytest",
        "core",
    }
    assert top_level_imports <= allowed


def test_158_both_lifecycle_and_record_contract_phrases_coexist():
    source = _module_source_text()
    assert "Validated transition plan -- not persisted" in source
    assert "Validated approval record -- not proof of persistence" in source
