"""Tests for core.agent_identity_policy -- the pure, deterministic,
claim-based identity and least-privilege policy engine for Agent Identity
and Least Privilege (Block 9).

No Supabase, MCP, file, subprocess, network, Hayabusa, or AI/model access
occurs anywhere in this file; every input is a plain in-memory value, and
every timestamp is a fixed literal -- never datetime.now(), utcnow(), or
time.time(). No agent is ever authenticated and no tool is ever executed.
"""

import copy
import dataclasses
import json
from types import MappingProxyType

import pytest

import core.agent_identity_policy as agent_identity_policy_module
from core.agent_identity_policy import AgentIdentityPolicyError, evaluate_agent_tool_call

APPROVAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
INVESTIGATION_ID = "11111111-1111-4111-8111-111111111111"
EVALUATED_AT = "2026-08-01T12:00:00Z"

_FIFTEEN_RESULT_FIELDS = {
    "identity_policy_version", "canonical_agent_id", "agent_role", "identity_authenticated",
    "canonical_tool_name", "operation_class", "gateway_decision", "final_decision",
    "eligible_for_execution", "requires_approval", "matched_identity_rules",
    "safe_capability_summary", "required_next_action", "evaluated_at", "execution_performed",
}

_FIVE_SUMMARY_FIELDS = {
    "role", "requested_tool_allowed", "requested_operation_class_permitted",
    "mutation_request_allowed", "allowed_tool_count",
}


def _codes(result):
    return [rule["code"] for rule in result["matched_identity_rules"]]


def _contains_forbidden_text(payload, forbidden_substrings):
    text = json.dumps(payload, default=str)
    return any(fragment in text for fragment in forbidden_substrings)


# ---------------------------------------------------------------------------
# 1: analyst_agent allowed read-only lookup
# ---------------------------------------------------------------------------


def test_001_analyst_agent_allowed_read_only_lookup():
    result = evaluate_agent_tool_call(
        agent_id="analyst_agent",
        tool_name="load_risk_aware_approval_record",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert result["gateway_decision"] == "allow"
    assert result["final_decision"] == "allow"
    assert _codes(result) == ["IDENTITY_POLICY_ALLOWED", "CLAIMED_IDENTITY_NOT_AUTHENTICATED", "EXECUTION_NOT_PERFORMED"]
    assert result["identity_authenticated"] is False
    assert result["execution_performed"] is False


# ---------------------------------------------------------------------------
# 2: observer_agent allowed its own permitted tool
# ---------------------------------------------------------------------------


def test_002_observer_agent_allowed_permitted_tool():
    result = evaluate_agent_tool_call(
        agent_id="observer_agent",
        tool_name="load_investigation_approval_context",
        arguments={"investigation_id": INVESTIGATION_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert result["final_decision"] == "allow"
    assert result["eligible_for_execution"] is True


# ---------------------------------------------------------------------------
# 3: observer_agent denied a tool outside its own allowlist
# ---------------------------------------------------------------------------


def test_003_observer_agent_denied_tool_outside_allowlist():
    result = evaluate_agent_tool_call(
        agent_id="observer_agent",
        tool_name="load_risk_aware_approval_record",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert result["final_decision"] == "deny"
    assert _codes(result) == ["TOOL_NOT_IN_AGENT_ALLOWLIST", "CLAIMED_IDENTITY_NOT_AUTHENTICATED", "EXECUTION_NOT_PERFORMED"]


# ---------------------------------------------------------------------------
# 4: analyst_agent denied mutation request capability
# ---------------------------------------------------------------------------


def test_004_analyst_agent_mutation_request_not_permitted():
    result = evaluate_agent_tool_call(
        agent_id="analyst_agent",
        tool_name="apply_approval_consumption",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert result["gateway_decision"] == "require_approval"
    assert result["final_decision"] == "deny"
    assert _codes(result) == ["MUTATION_REQUEST_NOT_PERMITTED", "CLAIMED_IDENTITY_NOT_AUTHENTICATED", "EXECUTION_NOT_PERFORMED"]


# ---------------------------------------------------------------------------
# 5: coordinator_agent preserves require_approval
# ---------------------------------------------------------------------------


def test_005_coordinator_agent_preserves_require_approval():
    result = evaluate_agent_tool_call(
        agent_id="coordinator_agent",
        tool_name="apply_approval_consumption",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert result["gateway_decision"] == "require_approval"
    assert result["final_decision"] == "require_approval"
    assert result["requires_approval"] is True
    assert _codes(result) == ["GATEWAY_APPROVAL_REQUIRED", "CLAIMED_IDENTITY_NOT_AUTHENTICATED", "EXECUTION_NOT_PERFORMED"]


# ---------------------------------------------------------------------------
# 6: reviewer_agent denied by role operation-class ceiling
# ---------------------------------------------------------------------------


def test_006_reviewer_agent_denied_by_operation_class_ceiling():
    result = evaluate_agent_tool_call(
        agent_id="reviewer_agent",
        tool_name="apply_approval_consumption",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert result["final_decision"] == "deny"
    codes = _codes(result)
    assert codes == ["OPERATION_CLASS_NOT_PERMITTED", "CLAIMED_IDENTITY_NOT_AUTHENTICATED", "EXECUTION_NOT_PERFORMED"]
    assert "MUTATION_REQUEST_NOT_PERMITTED" not in codes
    assert "TOOL_NOT_IN_AGENT_ALLOWLIST" not in codes


# ---------------------------------------------------------------------------
# 7: unknown agent denied without calling the gateway
# ---------------------------------------------------------------------------


def test_007_unknown_agent_denied_without_calling_gateway(monkeypatch):
    calls = []
    original = agent_identity_policy_module.evaluate_tool_call

    def _spy(**kwargs):
        calls.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(agent_identity_policy_module, "evaluate_tool_call", _spy)

    result = evaluate_agent_tool_call(
        agent_id="ghost_agent",
        tool_name="load_risk_aware_approval_record",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert calls == []
    assert result["final_decision"] == "deny"
    assert result["canonical_agent_id"] is None
    assert result["agent_role"] is None
    assert result["canonical_tool_name"] is None
    assert result["gateway_decision"] is None
    assert "ghost_agent" not in json.dumps(result)
    assert _codes(result) == ["UNKNOWN_AGENT", "EXECUTION_NOT_PERFORMED"]


# ---------------------------------------------------------------------------
# 8: disabled_agent denied without calling the gateway
# ---------------------------------------------------------------------------


def test_008_disabled_agent_denied_without_calling_gateway(monkeypatch):
    calls = []
    original = agent_identity_policy_module.evaluate_tool_call

    def _spy(**kwargs):
        calls.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(agent_identity_policy_module, "evaluate_tool_call", _spy)

    result = evaluate_agent_tool_call(
        agent_id="disabled_agent",
        tool_name="load_risk_aware_approval_record",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert calls == []
    assert result["final_decision"] == "deny"
    assert result["agent_role"] is None
    assert result["gateway_decision"] is None
    assert _codes(result) == ["AGENT_DISABLED", "EXECUTION_NOT_PERFORMED"]


# ---------------------------------------------------------------------------
# 9: exact-match, case-sensitive agent matching; no aliases
# ---------------------------------------------------------------------------


def test_009_agent_matching_is_exact_case_sensitive_and_unaliased():
    result = evaluate_agent_tool_call(
        agent_id="Observer_Agent",
        tool_name="load_investigation_approval_context",
        arguments={"investigation_id": INVESTIGATION_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert result["final_decision"] == "deny"
    assert _codes(result) == ["UNKNOWN_AGENT", "EXECUTION_NOT_PERFORMED"]


# ---------------------------------------------------------------------------
# 10: coordinator_agent cannot override a Block 8 deny
# ---------------------------------------------------------------------------


def test_010_coordinator_agent_cannot_override_gateway_denial():
    result = evaluate_agent_tool_call(
        agent_id="coordinator_agent",
        tool_name="execute_sql",
        arguments={"query": "select 1"},
        evaluated_at=EVALUATED_AT,
    )

    assert result["gateway_decision"] == "deny"
    assert result["final_decision"] == "deny"
    codes = _codes(result)
    assert codes == ["GATEWAY_DENIED", "CLAIMED_IDENTITY_NOT_AUTHENTICATED", "EXECUTION_NOT_PERFORMED"]
    assert "IDENTITY_POLICY_ALLOWED" not in codes
    assert "GATEWAY_APPROVAL_REQUIRED" not in codes


# ---------------------------------------------------------------------------
# 11: apply_migration remains denied for every tested enabled agent
# ---------------------------------------------------------------------------


def test_011_apply_migration_denied_for_every_enabled_agent():
    for agent_id in ("observer_agent", "analyst_agent", "coordinator_agent", "reviewer_agent"):
        result = evaluate_agent_tool_call(
            agent_id=agent_id,
            tool_name="apply_migration",
            arguments={"name": "x", "query": "select 1"},
            evaluated_at=EVALUATED_AT,
        )
        assert result["gateway_decision"] == "deny", agent_id
        assert result["final_decision"] == "deny", agent_id
        assert "GATEWAY_DENIED" in _codes(result), agent_id


# ---------------------------------------------------------------------------
# 12: run_evtx_analysis remains denied for every tested enabled agent
# ---------------------------------------------------------------------------


def test_012_run_evtx_analysis_denied_for_every_enabled_agent():
    for agent_id in ("observer_agent", "analyst_agent", "coordinator_agent", "reviewer_agent"):
        result = evaluate_agent_tool_call(
            agent_id=agent_id,
            tool_name="run_evtx_analysis",
            arguments={
                "evtx_file": "x.evtx",
                "analysis_type": "csv-timeline",
                "output_name": "out",
                "authorization_phrase": "AUTHORIZED_TEST",
            },
            evaluated_at=EVALUATED_AT,
        )
        assert result["gateway_decision"] == "deny", agent_id
        assert result["final_decision"] == "deny", agent_id
        assert "GATEWAY_DENIED" in _codes(result), agent_id


# ---------------------------------------------------------------------------
# 13: permitted operation class, tool outside allowlist
# ---------------------------------------------------------------------------


def test_013_permitted_operation_class_but_tool_outside_allowlist():
    result = evaluate_agent_tool_call(
        agent_id="reviewer_agent",
        tool_name="load_investigation_approval_context",
        arguments={"investigation_id": INVESTIGATION_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert result["final_decision"] == "deny"
    assert _codes(result) == ["TOOL_NOT_IN_AGENT_ALLOWLIST", "CLAIMED_IDENTITY_NOT_AUTHENTICATED", "EXECUTION_NOT_PERFORMED"]


# ---------------------------------------------------------------------------
# 14: observer_agent denied by both operation-class and allowlist checks
# ---------------------------------------------------------------------------


def test_014_observer_agent_denied_by_class_and_allowlist_together():
    result = evaluate_agent_tool_call(
        agent_id="observer_agent",
        tool_name="apply_approval_consumption",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert result["final_decision"] == "deny"
    assert _codes(result) == [
        "OPERATION_CLASS_NOT_PERMITTED",
        "TOOL_NOT_IN_AGENT_ALLOWLIST",
        "CLAIMED_IDENTITY_NOT_AUTHENTICATED",
        "EXECUTION_NOT_PERFORMED",
    ]


# ---------------------------------------------------------------------------
# 15: role-ceiling denial takes precedence over mutation-request capability
# ---------------------------------------------------------------------------


def test_015_role_ceiling_denial_takes_precedence_over_mutation_capability():
    result = evaluate_agent_tool_call(
        agent_id="observer_agent",
        tool_name="apply_approval_consumption",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )

    assert result["gateway_decision"] == "require_approval"
    assert result["final_decision"] == "deny"
    assert result["safe_capability_summary"]["mutation_request_allowed"] is None
    assert "MUTATION_REQUEST_NOT_PERMITTED" not in _codes(result)


# ---------------------------------------------------------------------------
# 16: safe_capability_summary shape
# ---------------------------------------------------------------------------


def test_016_safe_capability_summary_exposes_no_full_allowlist():
    result = evaluate_agent_tool_call(
        agent_id="analyst_agent",
        tool_name="load_risk_aware_approval_record",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )

    summary = result["safe_capability_summary"]
    assert set(summary.keys()) == _FIVE_SUMMARY_FIELDS
    assert summary["role"] == "analyst"
    assert isinstance(summary["requested_tool_allowed"], bool)
    assert isinstance(summary["requested_operation_class_permitted"], bool)
    assert isinstance(summary["allowed_tool_count"], int)
    assert "load_risk_aware_approval_record" not in json.dumps(summary)
    assert "allowed_tools" not in summary


# ---------------------------------------------------------------------------
# 17: fifteen-field contract across all three decisions
# ---------------------------------------------------------------------------


def test_017_fifteen_field_contract_for_allow_require_approval_and_deny():
    allow_result = evaluate_agent_tool_call(
        agent_id="analyst_agent",
        tool_name="load_risk_aware_approval_record",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )
    require_approval_result = evaluate_agent_tool_call(
        agent_id="coordinator_agent",
        tool_name="apply_approval_consumption",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )
    deny_result = evaluate_agent_tool_call(
        agent_id="ghost_agent",
        tool_name="load_risk_aware_approval_record",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )

    for result in (allow_result, require_approval_result, deny_result):
        assert set(result.keys()) == _FIFTEEN_RESULT_FIELDS
        assert result["identity_authenticated"] is False
        assert result["execution_performed"] is False


# ---------------------------------------------------------------------------
# 18: structural validation
# ---------------------------------------------------------------------------


def test_018_structural_validation_raises_for_invalid_inputs():
    valid_arguments = {"approval_id": APPROVAL_ID}
    valid_arguments_copy = copy.deepcopy(valid_arguments)

    with pytest.raises(AgentIdentityPolicyError):
        evaluate_agent_tool_call(agent_id=123, tool_name="load_risk_aware_approval_record", arguments=valid_arguments, evaluated_at=EVALUATED_AT)

    with pytest.raises(AgentIdentityPolicyError):
        evaluate_agent_tool_call(agent_id="   ", tool_name="load_risk_aware_approval_record", arguments=valid_arguments, evaluated_at=EVALUATED_AT)

    with pytest.raises(AgentIdentityPolicyError):
        evaluate_agent_tool_call(agent_id="analyst_agent", tool_name=123, arguments=valid_arguments, evaluated_at=EVALUATED_AT)

    with pytest.raises(AgentIdentityPolicyError):
        evaluate_agent_tool_call(agent_id="analyst_agent", tool_name="  ", arguments=valid_arguments, evaluated_at=EVALUATED_AT)

    with pytest.raises(AgentIdentityPolicyError):
        evaluate_agent_tool_call(agent_id="analyst_agent", tool_name="load_risk_aware_approval_record", arguments="not-a-mapping", evaluated_at=EVALUATED_AT)

    with pytest.raises(AgentIdentityPolicyError):
        evaluate_agent_tool_call(agent_id="analyst_agent", tool_name="load_risk_aware_approval_record", arguments=valid_arguments, evaluated_at="not-a-timestamp")

    with pytest.raises(AgentIdentityPolicyError):
        evaluate_agent_tool_call(agent_id="analyst_agent", tool_name="load_risk_aware_approval_record", arguments=valid_arguments, evaluated_at="2026-08-01T12:00:00")

    assert valid_arguments == valid_arguments_copy


# ---------------------------------------------------------------------------
# 19: unsafe and oversized agent IDs raise structurally, never echoed
# ---------------------------------------------------------------------------


def test_019_unsafe_and_oversized_agent_ids_raise_and_are_never_echoed():
    unsafe_ids = [
        "analyst\x01agent",
        "analyst;agent",
        "analyst|agent",
        "analyst`agent`",
        "analyst$(agent)",
        "analyst--agent",
        "analyst/*agent*/",
        "http://analyst-agent",
        "../analyst_agent",
        "analyst/agent",
        "analyst\\agent",
        "a" * 4097,
    ]

    for unsafe_id in unsafe_ids:
        with pytest.raises(AgentIdentityPolicyError) as excinfo:
            evaluate_agent_tool_call(
                agent_id=unsafe_id,
                tool_name="load_risk_aware_approval_record",
                arguments={"approval_id": APPROVAL_ID},
                evaluated_at=EVALUATED_AT,
            )
        assert unsafe_id not in str(excinfo.value)


# ---------------------------------------------------------------------------
# 20: determinism and input nonmutation
# ---------------------------------------------------------------------------


def test_020_deterministic_and_nonmutating():
    arguments = {"approval_id": APPROVAL_ID}
    arguments_copy = copy.deepcopy(arguments)

    first = evaluate_agent_tool_call(
        agent_id="analyst_agent",
        tool_name="load_risk_aware_approval_record",
        arguments=arguments,
        evaluated_at=EVALUATED_AT,
    )
    second = evaluate_agent_tool_call(
        agent_id="analyst_agent",
        tool_name="load_risk_aware_approval_record",
        arguments=arguments,
        evaluated_at=EVALUATED_AT,
    )

    assert first == second
    assert arguments == arguments_copy


# ---------------------------------------------------------------------------
# 21: registry and role map are immutable and internally consistent
# ---------------------------------------------------------------------------


def test_021_registry_and_role_map_are_immutable_and_consistent():
    registry = agent_identity_policy_module._REGISTRY
    ceilings = agent_identity_policy_module._ROLE_OPERATION_CLASS_CEILING

    assert isinstance(registry, MappingProxyType)
    with pytest.raises(TypeError):
        registry["new_agent"] = None

    assert set(registry.keys()) == {
        "observer_agent", "analyst_agent", "coordinator_agent", "reviewer_agent", "disabled_agent",
    }
    assert set(agent_identity_policy_module.ROLES) == {
        "observer", "analyst", "investigation_coordinator", "approval_reviewer", "disabled",
    }

    expected_field_names = {
        "canonical_agent_id", "role", "enabled", "allowed_tools",
        "allowed_operation_classes", "mutation_request_allowed", "description",
    }

    for agent_id, entry in registry.items():
        assert dataclasses.is_dataclass(entry)
        with pytest.raises(dataclasses.FrozenInstanceError):
            entry.enabled = not entry.enabled
        assert {f.name for f in dataclasses.fields(entry)} == expected_field_names
        assert entry.canonical_agent_id == agent_id
        assert isinstance(entry.allowed_tools, frozenset)
        assert isinstance(entry.allowed_operation_classes, frozenset)
        assert entry.allowed_operation_classes <= ceilings[entry.role]
        for field in dataclasses.fields(entry):
            assert not callable(getattr(entry, field.name))


# ---------------------------------------------------------------------------
# 22: recursive output-safety scan across allow, require_approval, deny
# ---------------------------------------------------------------------------


def test_022_output_never_contains_sensitive_or_raw_values():
    forbidden = [
        "ghost_agent_raw_marker",
        APPROVAL_ID,
        INVESTIGATION_ID,
        "select 1",
        "AUTHORIZED_TEST",
        "Traceback",
        "AgentIdentityPolicyError",
        "AgentGatewayError",
        "password",
        "secret",
        "token",
        "mcp__supabase",
    ]

    allow_result = evaluate_agent_tool_call(
        agent_id="analyst_agent",
        tool_name="load_risk_aware_approval_record",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )
    require_approval_result = evaluate_agent_tool_call(
        agent_id="coordinator_agent",
        tool_name="apply_approval_consumption",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )
    deny_result = evaluate_agent_tool_call(
        agent_id="ghost_agent_raw_marker",
        tool_name="load_risk_aware_approval_record",
        arguments={"approval_id": APPROVAL_ID},
        evaluated_at=EVALUATED_AT,
    )
    sql_deny_result = evaluate_agent_tool_call(
        agent_id="coordinator_agent",
        tool_name="execute_sql",
        arguments={"query": "select 1"},
        evaluated_at=EVALUATED_AT,
    )

    for result in (allow_result, require_approval_result, deny_result, sql_deny_result):
        assert not _contains_forbidden_text(result, forbidden)
        assert "allowed_tools" not in json.dumps(result)
