"""Tests for core.shadow_execution -- the pure, deterministic Shadow
Execution ("digital twin") simulation for one approved, risk-aware
case-update approval.

No Supabase, file, subprocess, network, or AI/model access occurs anywhere
in this file; every input is a plain in-memory mapping, and every
timestamp is a fixed literal -- never datetime.now(), utcnow(), or
time.time().
"""

import copy

import pytest

from core.shadow_execution import ShadowExecutionError, simulate_case_update

INVESTIGATION_ID = "11111111-1111-4111-8111-111111111111"
OTHER_INVESTIGATION_ID = "22222222-2222-4222-8222-222222222222"
APPROVAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

REQUESTED_AT = "2026-08-01T10:00:00Z"
CREATED_AT = "2026-08-01T10:00:00Z"
APPROVED_AT = "2026-08-01T11:00:00Z"
REJECTED_AT = "2026-08-01T11:00:00Z"
CONSUMED_AT = "2026-08-01T12:00:00Z"
EXPIRES_AT = "2026-08-01T13:00:00Z"
REJECTION_REASON = "insufficient evidence"

SIMULATED_AT = "2026-08-01T12:30:00Z"
SIMULATED_AT_AFTER_EXPIRY = "2026-08-01T14:00:00Z"


def _base_record(**overrides):
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
        "risk_level": "medium",
        "required_approvals": 1,
    }
    record.update(overrides)
    return record


def _approved_record(**overrides):
    record = _base_record(status="approved", approved_by="reviewer-one", approved_at=APPROVED_AT)
    record.update(overrides)
    return record


def _partially_approved_record(**overrides):
    record = _base_record(status="partially_approved", risk_level="high", required_approvals=2)
    record.update(overrides)
    return record


def _rejected_record(**overrides):
    record = _base_record(
        status="rejected",
        rejected_by="reviewer-one",
        rejected_at=REJECTED_AT,
        rejection_reason=REJECTION_REASON,
    )
    record.update(overrides)
    return record


def _consumed_record(**overrides):
    record = _approved_record(status="consumed", consumed_by="operator", consumed_at=CONSUMED_AT)
    record.update(overrides)
    return record


def _context(**overrides):
    context = {
        "investigation_id": INVESTIGATION_ID,
        "status": "investigating",
        "confidence": "low",
    }
    context.update(overrides)
    return context


def _codes(result):
    return [warning["code"] for warning in result["warnings"]]


# ---------------------------------------------------------------------------
# 1-3: pure before/after computation
# ---------------------------------------------------------------------------


def test_001_status_only_change_produces_exact_state_and_diff():
    record = _approved_record(action_payload={"status": "escalated"})
    context = _context(status="investigating", confidence="low")

    result = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)

    assert result["current_state"] == {"status": "investigating", "confidence": "low"}
    assert result["proposed_state"] == {"status": "escalated", "confidence": "low"}
    assert result["changed_fields"] == [{"field": "status", "before": "investigating", "after": "escalated"}]
    assert result["unchanged_fields"] == ["confidence"]


def test_002_confidence_only_increase_preserves_status():
    record = _approved_record(action_payload={"confidence": "high"}, risk_level="low", required_approvals=1)
    context = _context(status="investigating", confidence="low")

    result = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)

    assert result["current_state"] == {"status": "investigating", "confidence": "low"}
    assert result["proposed_state"] == {"status": "investigating", "confidence": "high"}
    assert result["changed_fields"] == [{"field": "confidence", "before": "low", "after": "high"}]
    assert result["unchanged_fields"] == ["status"]
    assert "CONFIDENCE_LOWERED" not in _codes(result)


def test_003_combined_change_produces_two_ordered_changed_fields():
    record = _approved_record(action_payload={"status": "escalated", "confidence": "medium"})
    context = _context(status="investigating", confidence="low")

    result = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)

    assert result["changed_fields"] == [
        {"field": "status", "before": "investigating", "after": "escalated"},
        {"field": "confidence", "before": "low", "after": "medium"},
    ]
    assert result["unchanged_fields"] == []


# ---------------------------------------------------------------------------
# 4: no-op
# ---------------------------------------------------------------------------


def test_004_no_op_action_is_reported_correctly():
    record = _approved_record(action_payload={"status": "investigating"})
    context = _context(status="investigating", confidence="low")

    result = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)

    assert result["changed_fields"] == []
    assert result["unchanged_fields"] == ["status", "confidence"]
    assert "NO_OP_ACTION" in _codes(result)
    assert result["rollback"]["reversible"] == "fully_reversible"


# ---------------------------------------------------------------------------
# 5-8: warning rules
# ---------------------------------------------------------------------------


def test_005_closing_investigation_emits_warning_and_conditional_rollback():
    record = _approved_record(action_payload={"status": "closed"}, risk_level="high", required_approvals=2)
    context = _context(status="investigating", confidence="low")

    result = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)

    assert "CLOSING_INVESTIGATION" in _codes(result)
    assert result["rollback"]["reversible"] == "conditionally_reversible"


def test_006_reopening_investigation_emits_warning():
    record = _approved_record(action_payload={"status": "investigating"}, risk_level="high", required_approvals=2)
    context = _context(status="closed", confidence="low")

    result = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)

    assert "REOPENING_INVESTIGATION" in _codes(result)


def test_007_confidence_lowered_reuses_risk_classification_behavior():
    record = _approved_record(action_payload={"confidence": "low"}, risk_level="medium", required_approvals=1)
    context = _context(status="investigating", confidence="high")

    result = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)

    assert "CONFIDENCE_LOWERED" in _codes(result)


def test_008_combined_warnings_follow_deterministic_fixed_order():
    record = _consumed_record(
        action_payload={"status": "closed", "confidence": "low"},
        investigation_id=OTHER_INVESTIGATION_ID,
        expires_at=EXPIRES_AT,
        risk_level="high",
        required_approvals=2,
    )
    context = _context(investigation_id=INVESTIGATION_ID, status="investigating", confidence="high")

    result = simulate_case_update(
        approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT_AFTER_EXPIRY
    )

    assert _codes(result) == [
        "ALREADY_CONSUMED",
        "NOT_APPROVED",
        "APPROVAL_EXPIRED",
        "STALE_BINDING",
        "CLOSING_INVESTIGATION",
        "CONFIDENCE_LOWERED",
        "COMBINED_FIELD_CHANGE",
        "ROLLBACK_UNCERTAIN",
    ]


# ---------------------------------------------------------------------------
# 9-15: eligibility
# ---------------------------------------------------------------------------


def test_009_approved_unexpired_unconsumed_correctly_bound_is_eligible():
    record = _approved_record(action_payload={"status": "escalated"})
    context = _context(status="investigating", confidence="low")

    result = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)

    assert result["eligible_for_execution"] is True
    blocking_codes = {"ALREADY_CONSUMED", "NOT_APPROVED", "APPROVAL_EXPIRED", "STALE_BINDING"}
    assert not (set(_codes(result)) & blocking_codes)


def test_010_pending_record_is_ineligible_with_not_approved():
    record = _base_record(action_payload={"status": "escalated"})
    context = _context(status="investigating", confidence="low")

    result = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)

    assert result["eligible_for_execution"] is False
    assert "NOT_APPROVED" in _codes(result)
    assert "ALREADY_CONSUMED" not in _codes(result)


def test_011_partially_approved_record_is_ineligible_with_not_approved():
    record = _partially_approved_record(action_payload={"status": "escalated"})
    context = _context(status="investigating", confidence="low")

    result = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)

    assert result["eligible_for_execution"] is False
    assert "NOT_APPROVED" in _codes(result)


def test_012_rejected_record_is_ineligible_with_not_approved():
    record = _rejected_record(action_payload={"status": "escalated"})
    context = _context(status="investigating", confidence="low")

    result = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)

    assert result["eligible_for_execution"] is False
    assert "NOT_APPROVED" in _codes(result)


def test_013_consumed_record_is_ineligible_with_deterministic_warning_order():
    record = _consumed_record(action_payload={"status": "investigating"})
    context = _context(status="investigating", confidence="low")

    result = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)

    assert result["eligible_for_execution"] is False
    assert result["warnings"][0]["code"] == "ALREADY_CONSUMED"
    assert result["warnings"][1]["code"] == "NOT_APPROVED"


def test_014_expired_approved_record_is_ineligible_with_approval_expired():
    record = _approved_record(action_payload={"status": "escalated"}, expires_at=EXPIRES_AT)
    context = _context(status="investigating", confidence="low")

    result = simulate_case_update(
        approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT_AFTER_EXPIRY
    )

    assert result["eligible_for_execution"] is False
    assert "APPROVAL_EXPIRED" in _codes(result)


def test_015_investigation_binding_mismatch_is_ineligible_with_stale_binding():
    record = _approved_record(action_payload={"status": "escalated"}, investigation_id=OTHER_INVESTIGATION_ID)
    context = _context(investigation_id=INVESTIGATION_ID, status="investigating", confidence="low")

    result = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)

    assert result["eligible_for_execution"] is False
    assert "STALE_BINDING" in _codes(result)


# ---------------------------------------------------------------------------
# 16: structural validation failures
# ---------------------------------------------------------------------------


def test_016_malformed_inputs_raise_shadow_execution_error_without_mutation():
    valid_record = _approved_record(action_payload={"status": "escalated"})
    valid_context = _context(status="investigating", confidence="low")

    # Malformed approval record: missing required field.
    malformed_record = _approved_record(action_payload={"status": "escalated"})
    del malformed_record["risk_level"]
    with pytest.raises(ShadowExecutionError):
        simulate_case_update(approval_record=malformed_record, investigation_context=valid_context, simulated_at=SIMULATED_AT)

    # Malformed approval record: unsupported action_type.
    with pytest.raises(ShadowExecutionError):
        simulate_case_update(
            approval_record=_approved_record(action_type="delete_everything", action_payload={"status": "escalated"}),
            investigation_context=valid_context,
            simulated_at=SIMULATED_AT,
        )

    # Malformed investigation context: extra field.
    forged_context = dict(valid_context)
    forged_context["proposed_status"] = "closed"
    with pytest.raises(ShadowExecutionError):
        simulate_case_update(approval_record=valid_record, investigation_context=forged_context, simulated_at=SIMULATED_AT)

    # Malformed investigation context: missing field.
    incomplete_context = dict(valid_context)
    del incomplete_context["confidence"]
    with pytest.raises(ShadowExecutionError):
        simulate_case_update(approval_record=valid_record, investigation_context=incomplete_context, simulated_at=SIMULATED_AT)

    # Malformed investigation context: unsupported status vocabulary.
    with pytest.raises(ShadowExecutionError):
        simulate_case_update(
            approval_record=valid_record,
            investigation_context=_context(status="not_a_real_status"),
            simulated_at=SIMULATED_AT,
        )

    # Malformed investigation context: not structurally a UUID.
    with pytest.raises(ShadowExecutionError):
        simulate_case_update(
            approval_record=valid_record,
            investigation_context=_context(investigation_id="not-a-uuid"),
            simulated_at=SIMULATED_AT,
        )

    # Invalid simulated_at: naive (no timezone) timestamp.
    with pytest.raises(ShadowExecutionError):
        simulate_case_update(approval_record=valid_record, investigation_context=valid_context, simulated_at="2026-08-01T12:00:00")

    # Invalid simulated_at: not a string or datetime.
    with pytest.raises(ShadowExecutionError):
        simulate_case_update(approval_record=valid_record, investigation_context=valid_context, simulated_at=12345)

    # None of the inputs used above were mutated by any failed attempt.
    assert valid_record == _approved_record(action_payload={"status": "escalated"})
    assert valid_context == _context(status="investigating", confidence="low")


# ---------------------------------------------------------------------------
# 17: output safety
# ---------------------------------------------------------------------------


_FORBIDDEN_OUTPUT_KEYS = frozenset({
    "requested_by", "requested_by_normalized", "approved_by", "rejected_by", "consumed_by",
    "reviewer_identity", "reviewer_identity_normalized", "action_payload", "sql", "query",
    "descriptor", "rpc", "credential", "credentials", "service_role", "token", "traceback",
})


def _assert_no_forbidden_keys(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            assert key not in _FORBIDDEN_OUTPUT_KEYS, f"forbidden key present: {key}"
            _assert_no_forbidden_keys(nested)
    elif isinstance(value, list):
        for item in value:
            _assert_no_forbidden_keys(item)


def test_017_result_has_exactly_fifteen_fields_and_no_forbidden_keys():
    record = _approved_record(action_payload={"status": "escalated"})
    context = _context(status="investigating", confidence="low")

    result = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)

    assert set(result) == {
        "simulation_version", "approval_id", "investigation_id", "action_type", "risk_level",
        "required_approvals", "eligible_for_execution", "current_state", "proposed_state",
        "changed_fields", "unchanged_fields", "warnings", "rollback", "simulated_at",
        "mutation_performed",
    }
    assert result["mutation_performed"] is False
    _assert_no_forbidden_keys(result)

    # mutation_performed is false even for an ineligible, blocked report.
    consumed_result = simulate_case_update(
        approval_record=_consumed_record(action_payload={"status": "escalated"}),
        investigation_context=context,
        simulated_at=SIMULATED_AT,
    )
    assert consumed_result["mutation_performed"] is False
    _assert_no_forbidden_keys(consumed_result)


# ---------------------------------------------------------------------------
# 18: determinism and nonmutation
# ---------------------------------------------------------------------------


def test_018_repeated_calls_are_deterministic_and_inputs_remain_unchanged():
    record = _approved_record(action_payload={"status": "closed", "confidence": "low"}, risk_level="high", required_approvals=2)
    context = _context(status="investigating", confidence="high")

    record_snapshot = copy.deepcopy(record)
    context_snapshot = copy.deepcopy(context)

    first = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)
    second = simulate_case_update(approval_record=record, investigation_context=context, simulated_at=SIMULATED_AT)

    assert first == second
    assert _codes(first) == _codes(second)
    assert record == record_snapshot
    assert context == context_snapshot
