"""Tests for core.approval_risk -- the pure, deterministic risk-
classification module used to derive how many distinct approvals a
proposed approval action requires, before any approval row is ever
created.

No Supabase, file, subprocess, network, or AI/model access occurs anywhere
in this file; every input is a plain in-memory value.
"""

import copy

import pytest

from core.approval_risk import (
    RISK_LEVELS,
    REQUIRED_APPROVALS_BY_RISK,
    ApprovalRiskError,
    classify_approval_risk,
    required_approvals_for_risk,
)


# ---------------------------------------------------------------------------
# 1-2: canonical vocabulary and mapping
# ---------------------------------------------------------------------------

def test_001_risk_levels_is_exactly_the_canonical_four_values():
    assert RISK_LEVELS == frozenset({"low", "medium", "high", "critical"})


def test_002_required_approvals_mapping_is_exact():
    assert dict(REQUIRED_APPROVALS_BY_RISK) == {
        "low": 1,
        "medium": 1,
        "high": 2,
        "critical": 2,
    }


# ---------------------------------------------------------------------------
# 3-8: deterministic classification policy
# ---------------------------------------------------------------------------

def test_003_confidence_only_increase_returns_low():
    result = classify_approval_risk(
        action_type="update_investigation_state",
        action_payload={"confidence": "high"},
        current_status="investigating",
        current_confidence="low",
    )
    assert result == "low"


def test_004_confidence_only_decrease_returns_medium():
    result = classify_approval_risk(
        action_type="update_investigation_state",
        action_payload={"confidence": "low"},
        current_status="investigating",
        current_confidence="high",
    )
    assert result == "medium"


def test_005_ordinary_status_update_returns_medium():
    result = classify_approval_risk(
        action_type="update_investigation_state",
        action_payload={"status": "investigating"},
        current_status="open",
        current_confidence="medium",
    )
    assert result == "medium"


def test_006_closing_returns_high():
    result = classify_approval_risk(
        action_type="update_investigation_state",
        action_payload={"status": "closed"},
        current_status="investigating",
        current_confidence="medium",
    )
    assert result == "high"


def test_007_reopening_returns_high():
    result = classify_approval_risk(
        action_type="update_investigation_state",
        action_payload={"status": "investigating"},
        current_status="closed",
        current_confidence="medium",
    )
    assert result == "high"


def test_008_both_fields_return_the_higher_component_risk():
    # status component (closing) = high, confidence component (increase) =
    # low -- the higher of the two, high, must be returned.
    result = classify_approval_risk(
        action_type="update_investigation_state",
        action_payload={"status": "closed", "confidence": "high"},
        current_status="investigating",
        current_confidence="low",
    )
    assert result == "high"


# ---------------------------------------------------------------------------
# 9: critical remains a supported required_approvals_for_risk input
# ---------------------------------------------------------------------------

def test_009_critical_remains_accepted_by_required_approvals_for_risk():
    assert required_approvals_for_risk("critical") == 2


# ---------------------------------------------------------------------------
# 10-13: rejection cases
# ---------------------------------------------------------------------------

def test_010_unsupported_action_type_fails():
    with pytest.raises(ApprovalRiskError):
        classify_approval_risk(
            action_type="delete_investigation",
            action_payload={"status": "closed"},
            current_status="investigating",
            current_confidence="medium",
        )


def test_011_unknown_payload_key_fails():
    with pytest.raises(ApprovalRiskError):
        classify_approval_risk(
            action_type="update_investigation_state",
            action_payload={"status": "closed", "extra": "x"},
            current_status="investigating",
            current_confidence="medium",
        )


def test_012_invalid_current_status_or_confidence_fails():
    with pytest.raises(ApprovalRiskError):
        classify_approval_risk(
            action_type="update_investigation_state",
            action_payload={"status": "closed"},
            current_status="not-a-real-status",
            current_confidence="medium",
        )

    with pytest.raises(ApprovalRiskError):
        classify_approval_risk(
            action_type="update_investigation_state",
            action_payload={"confidence": "high"},
            current_status="investigating",
            current_confidence="extreme",
        )


def test_013_missing_status_and_confidence_fails():
    with pytest.raises(ApprovalRiskError):
        classify_approval_risk(
            action_type="update_investigation_state",
            action_payload={},
            current_status="investigating",
            current_confidence="medium",
        )


# ---------------------------------------------------------------------------
# 14: input non-mutation
# ---------------------------------------------------------------------------

def test_014_inputs_are_not_mutated():
    action_payload = {"status": "closed", "confidence": "high"}
    snapshot = copy.deepcopy(action_payload)

    classify_approval_risk(
        action_type="update_investigation_state",
        action_payload=action_payload,
        current_status="investigating",
        current_confidence="low",
    )

    assert action_payload == snapshot
