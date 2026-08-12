"""Tests for core.mutation_freeze -- the pure, deterministic Emergency
Mutation Freeze narrowing layer (Block 11).

No Supabase, MCP, file, subprocess, network, Hayabusa, or AI/model access
occurs anywhere in this file; every input is a plain in-memory value, and
every timestamp is a fixed literal -- never datetime.now(), utcnow(), or
time.time(). No tool is ever executed and no Block 8/9 module is ever
called.

Every "Block 9 identity-policy result" used below is a plain, hand-built,
duck-typed dict shaped like `evaluate_agent_tool_call`'s own documented
return value, never a real call into `core.agent_identity_policy`.
"""

import copy

import core.mutation_freeze as mutation_freeze_module
from core.decision_binding import create_decision_binding, verify_decision_binding
from core.mutation_freeze import MutationFreezeError, evaluate_mutation_freeze

EVALUATED_AT = "2026-08-01T12:00:00Z"

_RESULT_FIELDS = {
    "identity_policy_version", "canonical_agent_id", "agent_role", "identity_authenticated",
    "canonical_tool_name", "operation_class", "gateway_decision", "final_decision",
    "eligible_for_execution", "requires_approval", "matched_identity_rules",
    "safe_capability_summary", "required_next_action", "evaluated_at", "execution_performed",
    "matched_freeze_rules",
}


def _identity_result(**overrides):
    base = {
        "identity_policy_version": "1",
        "canonical_agent_id": "coordinator_agent",
        "agent_role": "investigation_coordinator",
        "identity_authenticated": False,
        "canonical_tool_name": "apply_approval_consumption",
        "operation_class": "approval_mutation",
        "gateway_decision": "require_approval",
        "final_decision": "require_approval",
        "eligible_for_execution": False,
        "requires_approval": True,
        "matched_identity_rules": [
            {"code": "GATEWAY_APPROVAL_REQUIRED", "severity": "caution", "message": "m", "affects_decision": True},
        ],
        "safe_capability_summary": {
            "role": "investigation_coordinator",
            "requested_tool_allowed": True,
            "requested_operation_class_permitted": True,
            "mutation_request_allowed": True,
            "allowed_tool_count": 3,
        },
        "required_next_action": "submit_to_approval_workflow",
        "evaluated_at": EVALUATED_AT,
        "execution_performed": False,
    }
    base.update(overrides)
    return base


def _read_only_allow():
    return _identity_result(
        canonical_agent_id="analyst_agent",
        agent_role="analyst",
        canonical_tool_name="load_risk_aware_approval_record",
        operation_class="read_only",
        gateway_decision="allow",
        final_decision="allow",
        eligible_for_execution=True,
        requires_approval=False,
        required_next_action="proceed_to_separate_execution_boundary",
    )


def _state_mutation_require_approval():
    return _identity_result(
        operation_class="state_mutation",
        gateway_decision="require_approval",
        final_decision="require_approval",
    )


def _approval_mutation_require_approval():
    return _identity_result(
        operation_class="approval_mutation",
        gateway_decision="require_approval",
        final_decision="require_approval",
    )


def _schema_mutation_deny():
    return _identity_result(
        operation_class="schema_mutation",
        gateway_decision="deny",
        final_decision="deny",
        eligible_for_execution=False,
        requires_approval=False,
        required_next_action="do_not_execute",
    )


def _external_side_effect_deny():
    return _identity_result(
        operation_class="external_side_effect",
        gateway_decision="deny",
        final_decision="deny",
        eligible_for_execution=False,
        requires_approval=False,
        required_next_action="do_not_execute",
    )


def _prohibited_deny():
    return _identity_result(
        operation_class="prohibited",
        gateway_decision="deny",
        final_decision="deny",
        eligible_for_execution=False,
        requires_approval=False,
        required_next_action="do_not_execute",
    )


def _unknown_agent_deny():
    return _identity_result(
        canonical_agent_id=None,
        agent_role=None,
        canonical_tool_name=None,
        operation_class=None,
        gateway_decision=None,
        final_decision="deny",
        eligible_for_execution=False,
        requires_approval=False,
        matched_identity_rules=[
            {"code": "UNKNOWN_AGENT", "severity": "blocking", "message": "m", "affects_decision": True},
        ],
        safe_capability_summary={
            "role": None, "requested_tool_allowed": False, "requested_operation_class_permitted": False,
            "mutation_request_allowed": None, "allowed_tool_count": None,
        },
        required_next_action="do_not_execute",
    )


def _disabled_agent_deny():
    result = _unknown_agent_deny()
    result["canonical_agent_id"] = "disabled_agent"
    result["matched_identity_rules"] = [
        {"code": "AGENT_DISABLED", "severity": "blocking", "message": "m", "affects_decision": True},
    ]
    return result


def _already_deny_mutation_capable(operation_class):
    return _identity_result(
        operation_class=operation_class,
        gateway_decision="deny",
        final_decision="deny",
        eligible_for_execution=False,
        requires_approval=False,
        matched_identity_rules=[
            {"code": "MUTATION_REQUEST_NOT_PERMITTED", "severity": "blocking", "message": "m", "affects_decision": True},
        ],
        required_next_action="do_not_execute",
    )


# ---------------------------------------------------------------------------
# Normal mode: pure pass-through
# ---------------------------------------------------------------------------


def test_001_normal_mode_preserves_read_only_allow():
    source = _read_only_allow()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="normal")

    assert result["final_decision"] == "allow"
    assert result["eligible_for_execution"] is True
    assert result["requires_approval"] is False
    assert result["required_next_action"] == "proceed_to_separate_execution_boundary"
    assert result["matched_freeze_rules"] == []


def test_002_normal_mode_preserves_state_mutation_require_approval():
    source = _state_mutation_require_approval()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="normal")

    assert result["final_decision"] == "require_approval"
    assert result["eligible_for_execution"] is False
    assert result["requires_approval"] is True
    assert result["matched_freeze_rules"] == []


def test_003_normal_mode_preserves_deny():
    source = _prohibited_deny()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="normal")

    assert result["final_decision"] == "deny"
    assert result["matched_freeze_rules"] == []


def test_004_normal_mode_matched_freeze_rules_always_empty():
    for source in (_read_only_allow(), _state_mutation_require_approval(), _schema_mutation_deny()):
        result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="normal")
        assert result["matched_freeze_rules"] == []


# ---------------------------------------------------------------------------
# Active freeze: narrows mutation-capable classes
# ---------------------------------------------------------------------------


def test_005_freeze_narrows_state_mutation_require_approval_to_deny():
    source = _state_mutation_require_approval()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["final_decision"] == "deny"
    codes = [rule["code"] for rule in result["matched_freeze_rules"]]
    assert codes == ["MUTATION_FREEZE_ACTIVE"]


def test_006_freeze_narrows_approval_mutation_require_approval_to_deny():
    source = _approval_mutation_require_approval()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["final_decision"] == "deny"
    codes = [rule["code"] for rule in result["matched_freeze_rules"]]
    assert codes == ["MUTATION_FREEZE_ACTIVE"]


def test_007_freeze_narrowing_recomputes_derived_fields_consistently():
    source = _state_mutation_require_approval()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["final_decision"] == "deny"
    assert result["eligible_for_execution"] is False
    assert result["requires_approval"] is False
    assert result["required_next_action"] == "do_not_execute"


def test_008_freeze_narrowing_rule_shape_is_exact():
    source = _state_mutation_require_approval()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert len(result["matched_freeze_rules"]) == 1
    rule = result["matched_freeze_rules"][0]
    assert set(rule) == {"code", "severity", "message", "affects_decision"}
    assert rule["code"] == "MUTATION_FREEZE_ACTIVE"
    assert rule["severity"] == "blocking"
    assert rule["affects_decision"] is True
    assert isinstance(rule["message"], str) and rule["message"]


def test_009_freeze_narrows_allow_on_mutation_capable_class_too():
    # Not reachable through the real Block 8/9 registries today, but the
    # narrowing rule itself must not assume final_decision is only ever
    # require_approval for a mutation-capable class.
    source = _identity_result(
        operation_class="state_mutation",
        gateway_decision="allow",
        final_decision="allow",
        eligible_for_execution=True,
        requires_approval=False,
        required_next_action="proceed_to_separate_execution_boundary",
    )
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["final_decision"] == "deny"
    assert [rule["code"] for rule in result["matched_freeze_rules"]] == ["MUTATION_FREEZE_ACTIVE"]


# ---------------------------------------------------------------------------
# Active freeze: classes/outcomes it must NOT affect
# ---------------------------------------------------------------------------


def test_010_freeze_read_only_unaffected_no_rule():
    source = _read_only_allow()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["final_decision"] == "allow"
    assert result["eligible_for_execution"] is True
    assert result["matched_freeze_rules"] == []


def test_011_freeze_already_deny_state_mutation_unaffected_no_rule():
    source = _already_deny_mutation_capable("state_mutation")
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["final_decision"] == "deny"
    assert result["matched_freeze_rules"] == []


def test_012_freeze_already_deny_approval_mutation_unaffected_no_rule():
    source = _already_deny_mutation_capable("approval_mutation")
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["final_decision"] == "deny"
    assert result["matched_freeze_rules"] == []


def test_013_freeze_schema_mutation_unaffected_no_rule():
    source = _schema_mutation_deny()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["final_decision"] == "deny"
    assert result["matched_freeze_rules"] == []


def test_014_freeze_external_side_effect_unaffected_no_rule():
    source = _external_side_effect_deny()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["final_decision"] == "deny"
    assert result["matched_freeze_rules"] == []


def test_015_freeze_prohibited_unaffected_no_rule():
    source = _prohibited_deny()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["final_decision"] == "deny"
    assert result["matched_freeze_rules"] == []


def test_016_freeze_unknown_agent_null_operation_class_unaffected():
    source = _unknown_agent_deny()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["final_decision"] == "deny"
    assert result["operation_class"] is None
    assert result["matched_freeze_rules"] == []


def test_017_freeze_disabled_agent_null_operation_class_unaffected():
    source = _disabled_agent_deny()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["final_decision"] == "deny"
    assert result["operation_class"] is None
    assert result["matched_freeze_rules"] == []


# ---------------------------------------------------------------------------
# Field preservation
# ---------------------------------------------------------------------------


def test_018_gateway_decision_never_changed_by_freeze():
    source = _state_mutation_require_approval()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["final_decision"] == "deny"
    assert result["gateway_decision"] == "require_approval"


def test_019_matched_identity_rules_never_receives_freeze_rule():
    source = _state_mutation_require_approval()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    codes = [rule["code"] for rule in result["matched_identity_rules"]]
    assert "MUTATION_FREEZE_ACTIVE" not in codes
    assert codes == ["GATEWAY_APPROVAL_REQUIRED"]


def test_020_matched_identity_rules_content_preserved():
    source = _state_mutation_require_approval()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["matched_identity_rules"] == source["matched_identity_rules"]


def test_021_safe_capability_summary_content_preserved():
    source = _state_mutation_require_approval()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["safe_capability_summary"] == source["safe_capability_summary"]


def test_022_result_contains_exactly_sixteen_fields():
    result = evaluate_mutation_freeze(identity_policy_result=_read_only_allow(), control_mode="normal")
    assert set(result) == _RESULT_FIELDS
    assert len(result) == 16


def test_023_identity_authenticated_always_false():
    for mode in ("normal", "mutation_freeze"):
        result = evaluate_mutation_freeze(identity_policy_result=_state_mutation_require_approval(), control_mode=mode)
        assert result["identity_authenticated"] is False


def test_024_execution_performed_always_false():
    for mode in ("normal", "mutation_freeze"):
        result = evaluate_mutation_freeze(identity_policy_result=_state_mutation_require_approval(), control_mode=mode)
        assert result["execution_performed"] is False


def test_025_canonical_identity_fields_preserved():
    source = _state_mutation_require_approval()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["canonical_agent_id"] == source["canonical_agent_id"]
    assert result["agent_role"] == source["agent_role"]
    assert result["canonical_tool_name"] == source["canonical_tool_name"]
    assert result["operation_class"] == source["operation_class"]
    assert result["evaluated_at"] == source["evaluated_at"]
    assert result["identity_policy_version"] == source["identity_policy_version"]


# ---------------------------------------------------------------------------
# Determinism and non-mutation
# ---------------------------------------------------------------------------


def test_026_deterministic_repeated_calls():
    source = _state_mutation_require_approval()
    first = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")
    second = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")
    assert first == second


def test_027_caller_input_not_mutated():
    source = _state_mutation_require_approval()
    snapshot = copy.deepcopy(source)

    evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert source == snapshot


def test_028_nested_matched_identity_rules_not_aliased():
    source = _state_mutation_require_approval()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["matched_identity_rules"] is not source["matched_identity_rules"]
    result["matched_identity_rules"].append({"code": "INJECTED"})
    assert len(source["matched_identity_rules"]) == 1


def test_029_nested_safe_capability_summary_not_aliased():
    source = _state_mutation_require_approval()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")

    assert result["safe_capability_summary"] is not source["safe_capability_summary"]
    result["safe_capability_summary"]["role"] = "tampered"
    assert source["safe_capability_summary"]["role"] == "investigation_coordinator"


# ---------------------------------------------------------------------------
# Narrowing-only invariant
# ---------------------------------------------------------------------------


def test_030_never_widens_deny_to_require_approval_or_allow():
    for operation_class in ("state_mutation", "approval_mutation", "schema_mutation", "external_side_effect", "prohibited"):
        source = _identity_result(
            operation_class=operation_class,
            gateway_decision="deny",
            final_decision="deny",
            eligible_for_execution=False,
            requires_approval=False,
            required_next_action="do_not_execute",
        )
        for mode in ("normal", "mutation_freeze"):
            result = evaluate_mutation_freeze(identity_policy_result=source, control_mode=mode)
            assert result["final_decision"] == "deny"


def test_031_never_widens_require_approval_to_allow():
    source = _state_mutation_require_approval()
    for mode in ("normal", "mutation_freeze"):
        result = evaluate_mutation_freeze(identity_policy_result=source, control_mode=mode)
        assert result["final_decision"] in ("require_approval", "deny")
        assert result["final_decision"] != "allow"


def test_032_active_freeze_denial_is_not_an_exception():
    # A legitimate freeze-caused deny is a normal, successful result.
    result = evaluate_mutation_freeze(identity_policy_result=_state_mutation_require_approval(), control_mode="mutation_freeze")
    assert result["final_decision"] == "deny"


# ---------------------------------------------------------------------------
# control_mode validation
# ---------------------------------------------------------------------------


def test_033_invalid_control_mode_values_raise():
    bad_values = ["Normal", " normal ", "MUTATION_FREEZE", "frozen", "", None, 123, [], {}]
    for bad_value in bad_values:
        try:
            evaluate_mutation_freeze(identity_policy_result=_read_only_allow(), control_mode=bad_value)
            assert False, f"expected MutationFreezeError for control_mode={bad_value!r}"
        except MutationFreezeError:
            pass


def test_034_boolean_control_mode_rejected_not_treated_as_alias():
    for bad_value in (True, False):
        try:
            evaluate_mutation_freeze(identity_policy_result=_read_only_allow(), control_mode=bad_value)
            assert False, f"expected MutationFreezeError for control_mode={bad_value!r}"
        except MutationFreezeError:
            pass


# ---------------------------------------------------------------------------
# identity_policy_result structural validation
# ---------------------------------------------------------------------------


def test_035_non_mapping_identity_policy_result_raises():
    for bad_value in (None, "not-a-mapping", ["not", "a", "mapping"], 123):
        try:
            evaluate_mutation_freeze(identity_policy_result=bad_value, control_mode="normal")
            assert False, f"expected MutationFreezeError for identity_policy_result={bad_value!r}"
        except MutationFreezeError:
            pass


def test_036_missing_required_field_raises():
    for field in mutation_freeze_module._REQUIRED_IDENTITY_RESULT_FIELDS:
        source = _read_only_allow()
        del source[field]
        try:
            evaluate_mutation_freeze(identity_policy_result=source, control_mode="normal")
            assert False, f"expected MutationFreezeError for missing field {field!r}"
        except MutationFreezeError:
            pass


def test_037_invalid_final_decision_raises():
    source = _read_only_allow()
    source["final_decision"] = "banana"
    try:
        evaluate_mutation_freeze(identity_policy_result=source, control_mode="normal")
        assert False, "expected MutationFreezeError"
    except MutationFreezeError:
        pass


def test_038_invalid_operation_class_raises():
    source = _read_only_allow()
    source["operation_class"] = "banana"
    try:
        evaluate_mutation_freeze(identity_policy_result=source, control_mode="normal")
        assert False, "expected MutationFreezeError"
    except MutationFreezeError:
        pass


def test_039_identity_authenticated_true_raises():
    source = _read_only_allow()
    source["identity_authenticated"] = True
    try:
        evaluate_mutation_freeze(identity_policy_result=source, control_mode="normal")
        assert False, "expected MutationFreezeError"
    except MutationFreezeError:
        pass


def test_040_execution_performed_true_raises():
    source = _read_only_allow()
    source["execution_performed"] = True
    try:
        evaluate_mutation_freeze(identity_policy_result=source, control_mode="normal")
        assert False, "expected MutationFreezeError"
    except MutationFreezeError:
        pass


def test_041_matched_identity_rules_wrong_type_raises():
    source = _read_only_allow()
    source["matched_identity_rules"] = "not-a-list"
    try:
        evaluate_mutation_freeze(identity_policy_result=source, control_mode="normal")
        assert False, "expected MutationFreezeError"
    except MutationFreezeError:
        pass


def test_042_safe_capability_summary_wrong_type_raises():
    source = _read_only_allow()
    source["safe_capability_summary"] = "not-a-mapping"
    try:
        evaluate_mutation_freeze(identity_policy_result=source, control_mode="normal")
        assert False, "expected MutationFreezeError"
    except MutationFreezeError:
        pass


def test_043_nullable_string_field_wrong_type_raises():
    for field in ("canonical_agent_id", "agent_role", "canonical_tool_name", "gateway_decision"):
        source = _read_only_allow()
        source[field] = 12345
        try:
            evaluate_mutation_freeze(identity_policy_result=source, control_mode="normal")
            assert False, f"expected MutationFreezeError for field {field!r}"
        except MutationFreezeError:
            pass


def test_044_null_operation_class_is_valid_not_an_error():
    source = _unknown_agent_deny()
    result = evaluate_mutation_freeze(identity_policy_result=source, control_mode="mutation_freeze")
    assert result["operation_class"] is None
    assert result["final_decision"] == "deny"


# ---------------------------------------------------------------------------
# Block 11 -> Block 10 integration
#
# These exercise the real core.decision_binding.create_decision_binding /
# verify_decision_binding functions, never a stand-in -- proving the
# integration property that motivated placing this layer between Block 9
# and Block 10, not merely asserting it by inspection.
# ---------------------------------------------------------------------------

_BINDING_ARGUMENTS = {"approval_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
_BINDING_ISSUED_AT = "2026-08-01T12:00:00Z"
_BINDING_EXPIRES_AT = "2026-08-01T12:05:00Z"
_BINDING_VERIFY_AT = "2026-08-01T12:02:00Z"


def test_045_frozen_mutation_cannot_create_decision_binding():
    frozen = evaluate_mutation_freeze(
        identity_policy_result=_state_mutation_require_approval(),
        control_mode="mutation_freeze",
    )
    assert frozen["final_decision"] == "deny"

    binding = create_decision_binding(
        identity_policy_result=frozen,
        arguments=_BINDING_ARGUMENTS,
        issued_at=_BINDING_ISSUED_AT,
        expires_at=_BINDING_EXPIRES_AT,
    )

    assert binding["binding_outcome"] == "refused"
    assert binding["refusal_reason"]["code"] == "IDENTITY_RESULT_DENIED"


def test_046_pre_freeze_binding_invalid_against_fresh_frozen_policy():
    pre_freeze_result = _state_mutation_require_approval()
    binding = create_decision_binding(
        identity_policy_result=pre_freeze_result,
        arguments=_BINDING_ARGUMENTS,
        issued_at=_BINDING_ISSUED_AT,
        expires_at=_BINDING_EXPIRES_AT,
    )
    assert binding["binding_outcome"] == "created"
    assert binding["policy_decision"] == "require_approval"

    fresh_frozen = evaluate_mutation_freeze(
        identity_policy_result=_state_mutation_require_approval(),
        control_mode="mutation_freeze",
    )
    assert fresh_frozen["final_decision"] == "deny"

    result = verify_decision_binding(
        binding=binding,
        fresh_identity_policy_result=fresh_frozen,
        arguments=_BINDING_ARGUMENTS,
        verification_time=_BINDING_VERIFY_AT,
    )

    assert result["verification_outcome"] == "invalid"
    codes = [rule["code"] for rule in result["matched_verification_rules"]]
    assert "POLICY_DECISION_MISMATCH" in codes
    assert "GATEWAY_DECISION_MISMATCH" not in codes


def test_047_read_only_remains_compatible_with_decision_binding():
    frozen = evaluate_mutation_freeze(identity_policy_result=_read_only_allow(), control_mode="mutation_freeze")
    assert frozen["final_decision"] == "allow"
    assert frozen["matched_freeze_rules"] == []

    binding = create_decision_binding(
        identity_policy_result=frozen,
        arguments=_BINDING_ARGUMENTS,
        issued_at=_BINDING_ISSUED_AT,
        expires_at=_BINDING_EXPIRES_AT,
    )
    assert binding["binding_outcome"] == "created"

    fresh = evaluate_mutation_freeze(identity_policy_result=_read_only_allow(), control_mode="mutation_freeze")
    result = verify_decision_binding(
        binding=binding,
        fresh_identity_policy_result=fresh,
        arguments=_BINDING_ARGUMENTS,
        verification_time=_BINDING_VERIFY_AT,
    )

    assert result["verification_outcome"] == "valid"
