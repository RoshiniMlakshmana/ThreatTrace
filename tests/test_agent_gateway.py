"""Tests for core.agent_gateway -- the pure, deterministic, default-deny
runtime policy engine for the AI Agent Gateway / Runtime Firewall
(Block 8).

No Supabase, MCP, file, subprocess, network, Hayabusa, or AI/model access
occurs anywhere in this file; every input is a plain in-memory value, and
every timestamp is a fixed literal -- never datetime.now(), utcnow(), or
time.time().
"""

import copy
import dataclasses
from types import MappingProxyType

import pytest

import core.agent_gateway as agent_gateway_module
from core.agent_gateway import AgentGatewayError, evaluate_tool_call

APPROVAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
INVESTIGATION_ID = "11111111-1111-4111-8111-111111111111"
EVALUATED_AT = "2026-08-01T12:00:00Z"

_TWELVE_RESULT_FIELDS = {
    "gateway_version", "canonical_tool_name", "operation_class", "decision",
    "eligible_for_execution", "requires_approval", "matched_rules", "safe_argument_summary",
    "blocked_argument_fields", "required_next_action", "evaluated_at", "execution_performed",
}


def _codes(result):
    return [rule["code"] for rule in result["matched_rules"]]


# ---------------------------------------------------------------------------
# 1-3: allow / require_approval decisions
# ---------------------------------------------------------------------------


def test_001_recognized_read_only_tool_is_allowed():
    result = evaluate_tool_call(
        tool_name="load_risk_aware_approval_record",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert result["decision"] == "allow"
    assert result["operation_class"] == "read_only"
    assert result["eligible_for_execution"] is True
    assert result["requires_approval"] is False
    assert _codes(result) == ["READ_ONLY_TOOL_ALLOWED", "EXECUTION_NOT_PERFORMED"]
    assert result["execution_performed"] is False


def test_002_investigation_context_lookup_allowed_and_uuid_never_exposed():
    result = evaluate_tool_call(
        tool_name="load_investigation_approval_context",
        arguments={"investigation_id": INVESTIGATION_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert result["decision"] == "allow"
    assert INVESTIGATION_ID not in str(result)


def test_003_recognized_mutating_tool_requires_approval():
    result = evaluate_tool_call(
        tool_name="apply_approval_consumption",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert result["decision"] == "require_approval"
    assert result["eligible_for_execution"] is False
    assert result["requires_approval"] is True
    assert _codes(result) == ["MUTATION_REQUIRES_APPROVAL", "APPROVAL_MUTATION_RESTRICTED", "EXECUTION_NOT_PERFORMED"]


# ---------------------------------------------------------------------------
# 4-5: unknown and disabled tools
# ---------------------------------------------------------------------------


def test_004_unknown_tool_is_denied():
    unknown_name = "definitely_not_a_registered_tool"
    result = evaluate_tool_call(tool_name=unknown_name, arguments={}, evaluated_at=EVALUATED_AT)

    assert result["decision"] == "deny"
    assert result["canonical_tool_name"] is None
    assert result["operation_class"] is None
    assert "UNKNOWN_TOOL" in _codes(result)
    assert unknown_name not in str(result)


def test_005_disabled_tool_is_denied():
    result = evaluate_tool_call(
        tool_name="load_approval_record",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert result["decision"] == "deny"
    assert _codes(result) == ["TOOL_DISABLED", "EXECUTION_NOT_PERFORMED"]


# ---------------------------------------------------------------------------
# 6-8: policy-denied recognized tools
# ---------------------------------------------------------------------------


def test_006_schema_mutation_denied_and_query_redacted():
    result = evaluate_tool_call(
        tool_name="apply_migration",
        arguments={"name": "add_column", "query": "ALTER TABLE approvals ADD COLUMN x text;"},
        evaluated_at=EVALUATED_AT,
    )

    assert result["decision"] == "deny"
    assert "SCHEMA_MUTATION_DENIED" in _codes(result)
    assert "SENSITIVE_ARGUMENT_SUPPRESSED" in _codes(result)
    assert result["safe_argument_summary"]["query"] == "redacted"
    assert "ALTER TABLE" not in str(result)


def test_007_generic_sql_tool_denied_and_no_sql_exposed():
    result = evaluate_tool_call(
        tool_name="execute_sql",
        arguments={"query": "SELECT * FROM approvals;"},
        evaluated_at=EVALUATED_AT,
    )

    assert result["decision"] == "deny"
    assert "GENERIC_SQL_TOOL_DENIED" in _codes(result)
    assert "SENSITIVE_ARGUMENT_SUPPRESSED" in _codes(result)
    assert "SELECT" not in str(result)


def test_008_external_side_effect_denied_and_no_path_or_auth_exposed():
    result = evaluate_tool_call(
        tool_name="run_evtx_analysis",
        arguments={
            "evtx_file": "sample.evtx",
            "analysis_type": "csv_timeline",
            "output_name": "result.csv",
            "authorization_phrase": "RUN AUTHORIZED HAYABUSA ANALYSIS",
        },
        evaluated_at=EVALUATED_AT,
    )

    assert result["decision"] == "deny"
    assert "EXTERNAL_SIDE_EFFECT_DENIED" in _codes(result)
    assert "sample.evtx" not in str(result)
    assert "result.csv" not in str(result)
    assert "RUN AUTHORIZED HAYABUSA ANALYSIS" not in str(result)


# ---------------------------------------------------------------------------
# 9-13: argument-validation denial rules
# ---------------------------------------------------------------------------


def test_009_missing_required_argument_is_denied():
    result = evaluate_tool_call(tool_name="load_risk_aware_approval_record", arguments={}, evaluated_at=EVALUATED_AT)

    assert result["decision"] == "deny"
    assert "MISSING_ARGUMENT" in _codes(result)


def test_010_unknown_argument_uses_safe_marker():
    result = evaluate_tool_call(
        tool_name="load_risk_aware_approval_record",
        arguments={"approval_id": APPROVAL_ID, "extra_field": "smuggled"},
        evaluated_at=EVALUATED_AT,
    )

    assert result["decision"] == "deny"
    assert "UNKNOWN_ARGUMENT" in _codes(result)
    assert result["blocked_argument_fields"] == ["<unknown>"]
    assert "extra_field" not in str(result)
    assert "smuggled" not in str(result)


def test_011_globally_prohibited_argument_returns_canonical_name_only():
    result = evaluate_tool_call(
        tool_name="load_risk_aware_approval_record",
        arguments={"approval_id": APPROVAL_ID, "risk_level": "high"},
        evaluated_at=EVALUATED_AT,
    )

    assert result["decision"] == "deny"
    assert "PROHIBITED_ARGUMENT" in _codes(result)
    assert result["blocked_argument_fields"] == ["risk_level"]
    assert "high" not in str(result["blocked_argument_fields"])


def test_012_malformed_uuid_is_denied():
    result = evaluate_tool_call(
        tool_name="load_risk_aware_approval_record",
        arguments={"approval_id": "not-a-uuid"},
        evaluated_at=EVALUATED_AT,
    )

    assert result["decision"] == "deny"
    assert "MALFORMED_ARGUMENTS" in _codes(result)


def test_013_nested_oversized_and_invalid_key_type_are_all_malformed():
    nested_result = evaluate_tool_call(
        tool_name="apply_migration",
        arguments={"name": "x", "query": {"nested": "structure"}},
        evaluated_at=EVALUATED_AT,
    )
    assert "MALFORMED_ARGUMENTS" in _codes(nested_result)

    oversized_result = evaluate_tool_call(
        tool_name="execute_sql",
        arguments={"query": "a" * 4097},
        evaluated_at=EVALUATED_AT,
    )
    assert "MALFORMED_ARGUMENTS" in _codes(oversized_result)

    bad_key_result = evaluate_tool_call(
        tool_name="load_risk_aware_approval_record",
        arguments={1: APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )
    assert "MALFORMED_ARGUMENTS" in _codes(bad_key_result)


# ---------------------------------------------------------------------------
# 14-15: deterministic ordering and precedence
# ---------------------------------------------------------------------------


def test_014_argument_rule_ordering_is_deterministic():
    result = evaluate_tool_call(
        tool_name="load_risk_aware_approval_record",
        arguments={"unregistered": "x"},
        evaluated_at=EVALUATED_AT,
    )

    codes = _codes(result)
    assert "MISSING_ARGUMENT" in codes
    assert "UNKNOWN_ARGUMENT" in codes
    assert codes.index("MISSING_ARGUMENT") < codes.index("UNKNOWN_ARGUMENT")


def test_015_argument_denial_prevents_mutation_or_allow_rules():
    result = evaluate_tool_call(
        tool_name="apply_approval_consumption",
        arguments={},
        evaluated_at=EVALUATED_AT,
    )

    codes = _codes(result)
    assert "MISSING_ARGUMENT" in codes
    assert "MUTATION_REQUIRES_APPROVAL" not in codes
    assert "APPROVAL_MUTATION_RESTRICTED" not in codes
    assert "READ_ONLY_TOOL_ALLOWED" not in codes
    assert result["decision"] == "deny"


# ---------------------------------------------------------------------------
# 16-17: result-contract shape
# ---------------------------------------------------------------------------


def test_016_safe_argument_summary_uses_fixed_markers_in_sorted_order():
    result = evaluate_tool_call(
        tool_name="apply_migration",
        arguments={"query": "some query text"},
        evaluated_at=EVALUATED_AT,
    )

    summary = result["safe_argument_summary"]
    assert list(summary) == sorted(summary)
    assert set(summary.values()) <= {"present", "absent", "redacted"}
    assert summary["name"] == "absent"
    assert summary["query"] == "redacted"


def test_017_every_decision_has_exactly_twelve_fields_and_no_execution():
    allow_result = evaluate_tool_call(
        tool_name="load_risk_aware_approval_record", arguments={"approval_id": APPROVAL_ID}, evaluated_at=EVALUATED_AT
    )
    approval_result = evaluate_tool_call(
        tool_name="apply_approval_consumption", arguments={"approval_id": APPROVAL_ID}, evaluated_at=EVALUATED_AT
    )
    deny_result = evaluate_tool_call(tool_name="unregistered_tool", arguments={}, evaluated_at=EVALUATED_AT)

    for result in (allow_result, approval_result, deny_result):
        assert set(result) == _TWELVE_RESULT_FIELDS
        assert result["execution_performed"] is False
    assert allow_result["gateway_version"] == "1"


# ---------------------------------------------------------------------------
# 18: structural validation failures
# ---------------------------------------------------------------------------


def test_018_invalid_structural_inputs_raise_agent_gateway_error_without_mutation():
    valid_arguments = {"approval_id": APPROVAL_ID}
    snapshot = copy.deepcopy(valid_arguments)

    with pytest.raises(AgentGatewayError):
        evaluate_tool_call(tool_name=123, arguments=valid_arguments, evaluated_at=EVALUATED_AT)

    with pytest.raises(AgentGatewayError):
        evaluate_tool_call(tool_name="   ", arguments=valid_arguments, evaluated_at=EVALUATED_AT)

    with pytest.raises(AgentGatewayError):
        evaluate_tool_call(tool_name="load_risk_aware_approval_record", arguments=["not", "a", "mapping"], evaluated_at=EVALUATED_AT)

    with pytest.raises(AgentGatewayError):
        evaluate_tool_call(tool_name="load_risk_aware_approval_record", arguments=valid_arguments, evaluated_at="not-a-timestamp")

    with pytest.raises(AgentGatewayError):
        evaluate_tool_call(tool_name="load_risk_aware_approval_record", arguments=valid_arguments, evaluated_at="2026-08-01T12:00:00")

    assert valid_arguments == snapshot


# ---------------------------------------------------------------------------
# 19: determinism and nonmutation
# ---------------------------------------------------------------------------


def test_019_repeated_calls_are_deterministic_and_inputs_remain_unchanged():
    arguments = {"approval_id": APPROVAL_ID}
    snapshot = copy.deepcopy(arguments)

    first = evaluate_tool_call(tool_name="load_risk_aware_approval_record", arguments=arguments, evaluated_at=EVALUATED_AT)
    second = evaluate_tool_call(tool_name="load_risk_aware_approval_record", arguments=arguments, evaluated_at=EVALUATED_AT)

    assert first == second
    assert arguments == snapshot


# ---------------------------------------------------------------------------
# 20: registry integrity and recursive output safety
# ---------------------------------------------------------------------------


def test_020_registry_is_immutable_exact_and_output_is_recursively_safe():
    registry = agent_gateway_module._REGISTRY
    assert isinstance(registry, MappingProxyType)
    with pytest.raises(TypeError):
        registry["new_tool"] = object()

    for entry in registry.values():
        for field in dataclasses.fields(entry):
            value = getattr(entry, field.name)
            assert not callable(value), f"registry entry field must not be callable: {field.name}"

    # Case-sensitive, exact match only -- no case-folding, no fuzzy matching.
    uppercase_result = evaluate_tool_call(
        tool_name="LOAD_RISK_AWARE_APPROVAL_RECORD", arguments={}, evaluated_at=EVALUATED_AT
    )
    assert uppercase_result["decision"] == "deny"
    assert "UNKNOWN_TOOL" in _codes(uppercase_result)

    near_miss_result = evaluate_tool_call(
        tool_name="load_risk_aware_approval_records", arguments={}, evaluated_at=EVALUATED_AT
    )
    assert near_miss_result["decision"] == "deny"
    assert "UNKNOWN_TOOL" in _codes(near_miss_result)

    forbidden_substrings = (
        "requested_by", "approved_by", "rejected_by", "consumed_by", "credential", "token",
        "Traceback", "AgentGatewayError", "ValueError",
    )
    for result in (
        evaluate_tool_call(tool_name="load_risk_aware_approval_record", arguments={"approval_id": APPROVAL_ID}, evaluated_at=EVALUATED_AT),
        evaluate_tool_call(tool_name="apply_approval_consumption", arguments={"approval_id": APPROVAL_ID}, evaluated_at=EVALUATED_AT),
        evaluate_tool_call(tool_name="execute_sql", arguments={"query": "SELECT 1;"}, evaluated_at=EVALUATED_AT),
    ):
        rendered = str(result)
        for forbidden in forbidden_substrings:
            assert forbidden not in rendered
        assert APPROVAL_ID not in rendered


# ---------------------------------------------------------------------------
# 21: Block 15A checkpoint B2 -- run_bug_bounty_assessment registration
# ---------------------------------------------------------------------------


def test_021_bug_bounty_assessment_tool_registered_exactly_once():
    registry = agent_gateway_module._REGISTRY
    matches = [name for name in registry if name == "run_bug_bounty_assessment"]
    assert matches == ["run_bug_bounty_assessment"]


def test_022_bug_bounty_assessment_tool_is_external_side_effect():
    result = evaluate_tool_call(
        tool_name="run_bug_bounty_assessment",
        arguments={"target": "https://app.example.test/", "testing_profile": "passive"},
        evaluated_at=EVALUATED_AT,
    )
    assert result["operation_class"] == "external_side_effect"


def test_023_bug_bounty_assessment_tool_denied_like_every_other_external_side_effect_tool():
    result = evaluate_tool_call(
        tool_name="run_bug_bounty_assessment",
        arguments={"target": "https://app.example.test/", "testing_profile": "passive"},
        evaluated_at=EVALUATED_AT,
    )
    assert result["decision"] == "deny"
    assert result["eligible_for_execution"] is False
    assert result["requires_approval"] is False
    assert "EXTERNAL_SIDE_EFFECT_DENIED" in _codes(result)
    assert result["execution_performed"] is False


def test_024_bug_bounty_assessment_tool_not_special_cased_to_a_permissive_outcome():
    result = evaluate_tool_call(
        tool_name="run_bug_bounty_assessment",
        arguments={"target": "https://app.example.test/", "testing_profile": "safe_active"},
        evaluated_at=EVALUATED_AT,
    )
    assert result["decision"] != "allow"
    assert result["decision"] != "require_approval"
    assert "MUTATION_REQUIRES_APPROVAL" not in _codes(result)
    assert "READ_ONLY_TOOL_ALLOWED" not in _codes(result)


def test_025_bug_bounty_assessment_tool_addition_does_not_change_unrelated_tool_decisions():
    read_only = evaluate_tool_call(
        tool_name="load_risk_aware_approval_record", arguments={"approval_id": APPROVAL_ID}, evaluated_at=EVALUATED_AT
    )
    mutation = evaluate_tool_call(
        tool_name="apply_approval_consumption", arguments={"approval_id": APPROVAL_ID}, evaluated_at=EVALUATED_AT
    )
    other_external_side_effect = evaluate_tool_call(
        tool_name="run_evtx_analysis",
        arguments={
            "evtx_file": "sample.evtx", "analysis_type": "csv_timeline",
            "output_name": "result.csv", "authorization_phrase": "RUN AUTHORIZED HAYABUSA ANALYSIS",
        },
        evaluated_at=EVALUATED_AT,
    )
    assert read_only["decision"] == "allow"
    assert mutation["decision"] == "require_approval"
    assert other_external_side_effect["decision"] == "deny"


def test_026_bug_bounty_assessment_tool_deterministic_repeated_result():
    arguments = {"target": "https://app.example.test/", "testing_profile": "passive"}
    first = evaluate_tool_call(tool_name="run_bug_bounty_assessment", arguments=arguments, evaluated_at=EVALUATED_AT)
    second = evaluate_tool_call(tool_name="run_bug_bounty_assessment", arguments=arguments, evaluated_at=EVALUATED_AT)
    assert first == second
