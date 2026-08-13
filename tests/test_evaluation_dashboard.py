"""Tests for core.evaluation_dashboard -- the pure, deterministic
audit/evaluation dashboard summary (Block 14, module 2 of 2).

No Supabase, MCP, file, subprocess, network, Hayabusa, or AI/model access
occurs anywhere in this file. No tool is ever executed, and no prior
security-policy function (Block 8/9/10/Mutation-Freeze/evaluation
lab/analyst feedback) is ever called.

This file does not duplicate the 58 tests already covering
core.tamper_evident_audit's own chain-verification behavior (see
tests/test_tamper_evident_audit.py) -- it tests only the dashboard's own
aggregation boundary, reusing verify_audit_chain as a black box.
"""

import copy
import inspect

import core.evaluation_dashboard as dashboard_module
from core.evaluation_dashboard import EvaluationDashboardError, summarize_audit_dashboard
from core.tamper_evident_audit import EVENT_TYPES, create_audit_record

OCCURRED_AT = "2026-01-01T00:00:00Z"


def _record(sequence, event_type, event_summary=None, previous_record_digest=None, event_reference="ref"):
    return create_audit_record(
        sequence=sequence,
        event_type=event_type,
        event_reference=event_reference,
        event_summary=event_summary,
        occurred_at=OCCURRED_AT,
        previous_record_digest=previous_record_digest,
    )


def _chain_of(specs):
    """specs: list of (event_type, event_summary) tuples."""
    records = []
    previous_digest = None
    for i, (event_type, event_summary) in enumerate(specs, start=1):
        record = _record(i, event_type, event_summary, previous_digest)
        records.append(record)
        previous_digest = record["record_digest"]
    return records


def _assert_raises(**kwargs):
    try:
        summarize_audit_dashboard(**kwargs)
        assert False, f"expected EvaluationDashboardError for kwargs={kwargs!r}"
    except EvaluationDashboardError:
        pass


# ---------------------------------------------------------------------------
# Basic aggregation
# ---------------------------------------------------------------------------


def test_001_empty_input():
    result = summarize_audit_dashboard(records=[])
    assert result["audit"]["total_records"] == 0
    assert result["audit"]["verification_outcome"] == "valid"
    assert all(count == 0 for count in result["event_type_counts"].values())


def test_002_one_record():
    records = _chain_of([("investigation_decision", None)])
    result = summarize_audit_dashboard(records=records)
    assert result["event_type_counts"]["investigation_decision"] == 1
    assert result["audit"]["total_records"] == 1


def test_003_counts_by_multiple_event_types():
    records = _chain_of([
        ("investigation_decision", None),
        ("approval_decision", None),
        ("shadow_execution_result", None),
        ("security_policy_decision", {"outcome": "allow"}),
        ("decision_binding_result", None),
        ("security_evaluation_result", {"outcome": "pass"}),
        ("analyst_feedback", {"outcome": "agree"}),
    ])
    result = summarize_audit_dashboard(records=records)
    for event_type in EVENT_TYPES:
        assert result["event_type_counts"][event_type] == 1


def test_004_all_seven_event_type_counters_always_present():
    result = summarize_audit_dashboard(records=[])
    assert set(result["event_type_counts"]) == EVENT_TYPES


def test_005_deterministic_counts():
    records = _chain_of([
        ("security_evaluation_result", {"outcome": "pass"}),
        ("analyst_feedback", {"outcome": "disagree", "error_category": "false_positive"}),
    ])
    first = summarize_audit_dashboard(records=records)
    second = summarize_audit_dashboard(records=records)
    assert first == second


# ---------------------------------------------------------------------------
# Security evaluation counts
# ---------------------------------------------------------------------------


def test_006_evaluation_pass():
    records = _chain_of([("security_evaluation_result", {"outcome": "pass"})])
    result = summarize_audit_dashboard(records=records)
    assert result["evaluation_counts"]["outcome_counts"]["pass"] == 1


def test_007_evaluation_fail():
    records = _chain_of([("security_evaluation_result", {"outcome": "fail"})])
    result = summarize_audit_dashboard(records=records)
    assert result["evaluation_counts"]["outcome_counts"]["fail"] == 1


def test_008_evaluation_not_applicable():
    records = _chain_of([("security_evaluation_result", {"outcome": "not_applicable"})])
    result = summarize_audit_dashboard(records=records)
    assert result["evaluation_counts"]["outcome_counts"]["not_applicable"] == 1


def test_009_evaluation_mixed_outcomes():
    records = _chain_of([
        ("security_evaluation_result", {"outcome": "pass"}),
        ("security_evaluation_result", {"outcome": "pass"}),
        ("security_evaluation_result", {"outcome": "fail"}),
        ("security_evaluation_result", {"outcome": "not_applicable"}),
    ])
    result = summarize_audit_dashboard(records=records)
    counts = result["evaluation_counts"]["outcome_counts"]
    assert counts == {"pass": 2, "fail": 1, "not_applicable": 1}


def test_010_evaluation_case_type_counts():
    records = _chain_of([
        ("security_evaluation_result", {"outcome": "pass", "case_type": "identity_privilege_bypass"}),
        ("security_evaluation_result", {"outcome": "fail", "case_type": "identity_privilege_bypass"}),
        ("security_evaluation_result", {"outcome": "pass", "case_type": "mutation_policy_bypass"}),
    ])
    result = summarize_audit_dashboard(records=records)
    assert result["evaluation_counts"]["case_type_counts"] == {
        "identity_privilege_bypass": 2, "mutation_policy_bypass": 1,
    }


def test_011_evaluation_no_case_type_not_invented():
    records = _chain_of([("security_evaluation_result", {"outcome": "pass"})])
    result = summarize_audit_dashboard(records=records)
    assert result["evaluation_counts"]["case_type_counts"] == {}


def test_012_evaluation_invalid_outcome_rejected():
    records = _chain_of([("security_evaluation_result", {"outcome": "deny"})])
    _assert_raises(records=records)


# ---------------------------------------------------------------------------
# Analyst feedback counts
# ---------------------------------------------------------------------------


def test_013_feedback_agree():
    records = _chain_of([("analyst_feedback", {"outcome": "agree"})])
    result = summarize_audit_dashboard(records=records)
    assert result["feedback_counts"]["decision_counts"]["agree"] == 1


def test_014_feedback_disagree():
    records = _chain_of([("analyst_feedback", {"outcome": "disagree", "error_category": "false_positive"})])
    result = summarize_audit_dashboard(records=records)
    assert result["feedback_counts"]["decision_counts"]["disagree"] == 1


def test_015_feedback_insufficient_evidence():
    records = _chain_of([("analyst_feedback", {"outcome": "insufficient_evidence"})])
    result = summarize_audit_dashboard(records=records)
    assert result["feedback_counts"]["decision_counts"]["insufficient_evidence"] == 1


def test_016_feedback_error_category_counts():
    records = _chain_of([
        ("analyst_feedback", {"outcome": "disagree", "error_category": "false_positive"}),
        ("analyst_feedback", {"outcome": "disagree", "error_category": "false_positive"}),
        ("analyst_feedback", {"outcome": "disagree", "error_category": "missing_evidence"}),
    ])
    result = summarize_audit_dashboard(records=records)
    assert result["feedback_counts"]["error_category_counts"] == {"false_positive": 2, "missing_evidence": 1}


def test_017_feedback_missing_error_category_allowed():
    records = _chain_of([("analyst_feedback", {"outcome": "agree"})])
    result = summarize_audit_dashboard(records=records)
    assert result["feedback_counts"]["error_category_counts"] == {}
    assert result["feedback_counts"]["decision_counts"]["agree"] == 1


def test_018_feedback_invalid_outcome_rejected():
    records = _chain_of([("analyst_feedback", {"outcome": "pass"})])
    _assert_raises(records=records)


# ---------------------------------------------------------------------------
# Policy counts
# ---------------------------------------------------------------------------


def test_019_policy_allow():
    records = _chain_of([("security_policy_decision", {"outcome": "allow"})])
    result = summarize_audit_dashboard(records=records)
    assert result["policy_counts"]["decision_counts"]["allow"] == 1


def test_020_policy_require_approval():
    records = _chain_of([("security_policy_decision", {"outcome": "require_approval"})])
    result = summarize_audit_dashboard(records=records)
    assert result["policy_counts"]["decision_counts"]["require_approval"] == 1


def test_021_policy_deny():
    records = _chain_of([("security_policy_decision", {"outcome": "deny"})])
    result = summarize_audit_dashboard(records=records)
    assert result["policy_counts"]["decision_counts"]["deny"] == 1


def test_022_policy_invalid_outcome_rejected():
    records = _chain_of([("security_policy_decision", {"outcome": "pass"})])
    _assert_raises(records=records)


# ---------------------------------------------------------------------------
# Missing / None event_summary
# ---------------------------------------------------------------------------


def test_023_none_summary_evaluation_event_counted_only_in_event_type():
    records = _chain_of([("security_evaluation_result", None)])
    result = summarize_audit_dashboard(records=records)
    assert result["event_type_counts"]["security_evaluation_result"] == 1
    assert result["evaluation_counts"]["outcome_counts"] == {"pass": 0, "fail": 0, "not_applicable": 0}


def test_024_none_summary_feedback_event_counted_only_in_event_type():
    records = _chain_of([("analyst_feedback", None)])
    result = summarize_audit_dashboard(records=records)
    assert result["event_type_counts"]["analyst_feedback"] == 1
    assert result["feedback_counts"]["decision_counts"] == {"agree": 0, "disagree": 0, "insufficient_evidence": 0}


def test_025_none_summary_policy_event_counted_only_in_event_type():
    records = _chain_of([("security_policy_decision", None)])
    result = summarize_audit_dashboard(records=records)
    assert result["event_type_counts"]["security_policy_decision"] == 1
    assert result["policy_counts"]["decision_counts"] == {"allow": 0, "require_approval": 0, "deny": 0}


def test_026_other_event_types_not_rejected_for_having_outcome():
    # investigation_decision/approval_decision/shadow_execution_result/
    # decision_binding_result are not aggregated further, but their
    # event_summary content is never rejected merely for existing.
    records = _chain_of([("investigation_decision", {"outcome": "supported"})])
    result = summarize_audit_dashboard(records=records)
    assert result["event_type_counts"]["investigation_decision"] == 1


# ---------------------------------------------------------------------------
# Audit status representation
# ---------------------------------------------------------------------------


def test_027_valid_chain_represented():
    records = _chain_of([("investigation_decision", None), ("analyst_feedback", {"outcome": "agree"})])
    result = summarize_audit_dashboard(records=records)
    assert result["audit"]["internal_chain_valid"] is True
    assert result["audit"]["verification_outcome"] == "valid"


def test_028_matching_anchor_represented():
    records = _chain_of([("investigation_decision", None)])
    result = summarize_audit_dashboard(records=records, expected_head_digest=records[-1]["record_digest"])
    assert result["audit"]["trusted_anchor_verified"] is True


def test_029_mismatching_anchor_represented():
    records = _chain_of([("investigation_decision", None)])
    result = summarize_audit_dashboard(records=records, expected_head_digest="sha256:" + "f" * 64)
    assert result["audit"]["trusted_anchor_verified"] is False
    assert result["audit"]["verification_outcome"] == "invalid"


def test_030_digest_invalid_chain_represented_but_still_counted():
    records = _chain_of([("investigation_decision", None), ("analyst_feedback", {"outcome": "agree"})])
    tampered = dict(records[1])
    tampered["event_reference"] = "tampered"
    result = summarize_audit_dashboard(records=[records[0], tampered])

    assert result["audit"]["internal_chain_valid"] is False
    assert result["audit"]["verification_outcome"] == "invalid"
    codes = [rule["code"] for rule in result["audit"]["observed_evidence"]]
    assert "DIGEST_MISMATCH" in codes
    # counts are still derived from the visibly-present, readable records
    assert result["event_type_counts"]["analyst_feedback"] == 1
    assert result["feedback_counts"]["decision_counts"]["agree"] == 1


def test_031_broken_linkage_represented():
    records = _chain_of([("investigation_decision", None), ("analyst_feedback", {"outcome": "agree"})])
    tampered = dict(records[1])
    tampered["previous_record_digest"] = "sha256:" + "1" * 64
    from core.tamper_evident_audit import _recompute_record_digest
    tampered["record_digest"] = _recompute_record_digest({
        "sequence": tampered["sequence"], "event_type": tampered["event_type"],
        "event_reference": tampered["event_reference"], "event_summary": tampered["event_summary"],
        "occurred_at": tampered["occurred_at"], "previous_record_digest": tampered["previous_record_digest"],
        "audit_persisted": False, "execution_performed": False,
    })
    result = summarize_audit_dashboard(records=[records[0], tampered])
    assert result["audit"]["internal_chain_valid"] is False
    codes = [rule["code"] for rule in result["audit"]["observed_evidence"]]
    assert "PREVIOUS_DIGEST_MISMATCH" in codes


def test_032_unreadable_record_rejected_by_dashboard():
    _assert_raises(records=["not-a-record"])


def test_033_unreadable_record_missing_event_type_rejected():
    _assert_raises(records=[{"event_summary": None}])


def test_034_dashboard_translates_top_level_audit_error():
    _assert_raises(records="not-a-list")


def test_035_malformed_expected_head_digest_raises():
    records = _chain_of([("investigation_decision", None)])
    _assert_raises(records=records, expected_head_digest="not-a-digest")


# ---------------------------------------------------------------------------
# Honesty
# ---------------------------------------------------------------------------


def test_036_execution_performed_always_false():
    result = summarize_audit_dashboard(records=[])
    assert result["execution_performed"] is False


def test_037_no_timestamp_field():
    result = summarize_audit_dashboard(records=[])
    assert "generated_at" not in result
    assert "created_at" not in result
    assert "timestamp" not in result


def test_038_no_percentage_or_trend_fields():
    result = summarize_audit_dashboard(records=[])
    forbidden = {"percentage", "rate", "trend", "risk_score"}
    assert forbidden.isdisjoint(result)
    assert forbidden.isdisjoint(result["audit"])


def test_040_result_field_set_exact():
    result = summarize_audit_dashboard(records=[])
    assert set(result) == {
        "dashboard_version", "audit", "event_type_counts", "evaluation_counts",
        "feedback_counts", "policy_counts", "execution_performed",
    }
    assert set(result["audit"]) == {
        "total_records", "verification_outcome", "internal_chain_valid",
        "trusted_anchor_verified", "head_digest", "observed_evidence",
    }


# ---------------------------------------------------------------------------
# Non-mutation
# ---------------------------------------------------------------------------


def test_041_caller_records_list_not_mutated():
    records = _chain_of([("investigation_decision", None), ("analyst_feedback", {"outcome": "agree"})])
    snapshot = copy.deepcopy(records)
    summarize_audit_dashboard(records=records)
    assert records == snapshot


# ---------------------------------------------------------------------------
# Architecture / purity
# ---------------------------------------------------------------------------


def test_042_dashboard_imports_and_calls_verify_audit_chain():
    source = inspect.getsource(dashboard_module)
    assert "from core.tamper_evident_audit import" in source
    assert "verify_audit_chain(" in source


def test_043_dashboard_never_imports_other_blocks():
    full_source = inspect.getsource(dashboard_module)
    source = full_source.split("from __future__", 1)[1]
    forbidden_modules = (
        "core.agent_gateway",
        "core.agent_identity_policy",
        "core.decision_binding",
        "core.mutation_freeze",
        "core.ai_asset_registry",
        "core.analyst_feedback",
    )
    for forbidden in forbidden_modules:
        assert f"import {forbidden}" not in source, f"forbidden import found: {forbidden!r}"
        assert f"from {forbidden}" not in source, f"forbidden import found: {forbidden!r}"


def test_044_dashboard_never_touches_filesystem_network_clock_mcp_database():
    full_source = inspect.getsource(dashboard_module)
    source = full_source.split("from __future__", 1)[1]
    forbidden_substrings = (
        "datetime.now",
        "utcnow",
        "time.time",
        "os.environ",
        "os.getenv",
        "open(",
        "Path(",
        "subprocess",
        "socket",
        "requests",
        "urllib",
        "mcp__",
        "random.",
    )
    for forbidden in forbidden_substrings:
        assert forbidden not in source, f"forbidden substring found: {forbidden!r}"


def test_045_dashboard_does_not_reimplement_chain_verification_logic():
    source = inspect.getsource(dashboard_module)
    forbidden_reimplementation_markers = ("GENESIS_LINK_INVALID", "SEQUENCE_MISMATCH", "PREVIOUS_DIGEST_MISMATCH")
    for marker in forbidden_reimplementation_markers:
        assert marker not in source
