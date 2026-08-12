"""Tests for core.decision_binding -- the pure, deterministic, unsigned
Decision-to-Execution Binding correlator for Decision-to-Execution
Binding (Block 10).

No Supabase, MCP, file, subprocess, network, Hayabusa, or AI/model access
occurs anywhere in this file; every input is a plain in-memory value, and
every timestamp is a fixed literal -- never datetime.now(), utcnow(), or
time.time(). No agent is ever authenticated, no tool is ever executed, and
no signature or replay-protection claim is ever made.

This module never calls `core.agent_identity_policy` or
`core.agent_gateway` itself -- every "Block 9 identity-policy result" used
below is a plain, hand-built, duck-typed dict shaped like
`evaluate_agent_tool_call`'s own documented return value, never a real
call into that module.

`approval_reference` is an opaque, caller-defined string in this module's
own contract -- it is never required or assumed to be a UUID, so the
values used below are deliberately non-UUID-shaped to demonstrate that.
"""

import copy
from datetime import datetime, timedelta, timezone

import core.decision_binding as decision_binding_module
from core.decision_binding import (
    MAX_BINDING_LIFETIME_SECONDS,
    create_decision_binding,
    verify_decision_binding,
)

APPROVAL_REFERENCE = "case-2026-0731-review"
OTHER_APPROVAL_REFERENCE = "case-2026-0731-review-v2"

BASE_TIME = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)


def _iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def _plus(seconds):
    return _iso(BASE_TIME + timedelta(seconds=seconds))


ISSUED_AT = _plus(0)
EXPIRES_AT = _plus(300)
VERIFY_AT_WITHIN_WINDOW = _plus(120)
VERIFY_AT_AT_EXPIRY = _plus(300)
VERIFY_AT_AFTER_EXPIRY = _plus(301)

ARGUMENTS = {"approval_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}

_CREATE_RESULT_FIELDS = {
    "decision_binding_version", "binding_outcome", "canonical_agent_id", "agent_role",
    "canonical_tool_name", "gateway_decision", "policy_decision", "argument_digest",
    "approval_reference", "issued_at", "expires_at", "binding_digest", "refusal_reason",
    "identity_authenticated", "execution_performed",
}

_VERIFY_RESULT_FIELDS = {
    "decision_binding_version", "verification_outcome", "canonical_agent_id",
    "canonical_tool_name", "policy_decision", "matched_verification_rules", "verified_at",
    "identity_authenticated", "execution_performed", "replay_protection_provided",
}


def _identity_result(**overrides):
    base = {
        "identity_policy_version": "1",
        "canonical_agent_id": "analyst_agent",
        "agent_role": "analyst",
        "identity_authenticated": False,
        "canonical_tool_name": "load_risk_aware_approval_record",
        "operation_class": "read_only",
        "gateway_decision": "allow",
        "final_decision": "allow",
        "eligible_for_execution": True,
        "requires_approval": False,
        "matched_identity_rules": [],
        "safe_capability_summary": {},
        "required_next_action": "proceed_to_separate_execution_boundary",
        "evaluated_at": ISSUED_AT,
        "execution_performed": False,
    }
    base.update(overrides)
    return base


def _require_approval_identity_result(**overrides):
    base = _identity_result(
        canonical_agent_id="coordinator_agent",
        agent_role="investigation_coordinator",
        canonical_tool_name="apply_approval_consumption",
        gateway_decision="require_approval",
        final_decision="require_approval",
        eligible_for_execution=False,
        requires_approval=True,
    )
    base.update(overrides)
    return base


def _deny_identity_result(**overrides):
    base = _identity_result(
        canonical_agent_id=None,
        agent_role=None,
        canonical_tool_name=None,
        gateway_decision=None,
        final_decision="deny",
        eligible_for_execution=False,
    )
    base.update(overrides)
    return base


def _deny_identity_result_with_populated_fields(**overrides):
    # A real Block 9 deny shape (e.g. TOOL_NOT_IN_AGENT_ALLOWLIST or
    # MUTATION_REQUEST_NOT_PERMITTED) keeps the agent/tool/role fields
    # populated even though final_decision is deny -- unlike
    # _deny_identity_result, which models the UNKNOWN_AGENT/AGENT_DISABLED
    # shape where they are None.
    base = _identity_result(
        canonical_agent_id="analyst_agent",
        agent_role="analyst",
        canonical_tool_name="apply_approval_consumption",
        gateway_decision="require_approval",
        final_decision="deny",
        eligible_for_execution=False,
    )
    base.update(overrides)
    return base


def _created_binding(**create_kwargs):
    kwargs = {
        "identity_policy_result": _identity_result(),
        "arguments": ARGUMENTS,
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
    }
    kwargs.update(create_kwargs)
    return create_decision_binding(**kwargs)


def _verify_codes(result):
    return [rule["code"] for rule in result["matched_verification_rules"]]


# ---------------------------------------------------------------------------
# Successful creation
# ---------------------------------------------------------------------------


def test_001_create_allow_decision_succeeds():
    result = create_decision_binding(
        identity_policy_result=_identity_result(),
        arguments=ARGUMENTS,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
    )

    assert result["binding_outcome"] == "created"
    assert result["policy_decision"] == "allow"
    assert result["canonical_agent_id"] == "analyst_agent"
    assert result["canonical_tool_name"] == "load_risk_aware_approval_record"
    assert result["refusal_reason"] is None
    assert result["identity_authenticated"] is False
    assert result["execution_performed"] is False
    assert set(result) == _CREATE_RESULT_FIELDS


def test_002_create_require_approval_decision_succeeds():
    result = create_decision_binding(
        identity_policy_result=_require_approval_identity_result(),
        arguments=ARGUMENTS,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
    )

    assert result["binding_outcome"] == "created"
    assert result["policy_decision"] == "require_approval"
    assert result["canonical_agent_id"] == "coordinator_agent"


def test_003_create_with_optional_approval_reference():
    result = _created_binding(approval_reference=APPROVAL_REFERENCE)

    assert result["binding_outcome"] == "created"
    assert result["approval_reference"] == APPROVAL_REFERENCE


def test_004_create_result_deterministic_for_identical_input():
    first = _created_binding()
    second = _created_binding()

    assert first == second


def test_006_binding_digest_changes_when_content_changes():
    same_arguments = _created_binding()
    different_arguments = create_decision_binding(
        identity_policy_result=_identity_result(),
        arguments={"approval_id": "ffffffff-ffff-4fff-8fff-ffffffffffff"},
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
    )

    assert same_arguments["binding_digest"] != different_arguments["binding_digest"]
    assert same_arguments["binding_digest"].startswith("sha256:")


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------


def test_007_nested_object_key_order_independence():
    a = create_decision_binding(
        identity_policy_result=_identity_result(),
        arguments={"outer": {"inner_a": 1, "inner_b": 2}},
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
    )
    b = create_decision_binding(
        identity_policy_result=_identity_result(),
        arguments={"outer": {"inner_b": 2, "inner_a": 1}},
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
    )
    assert a["argument_digest"] == b["argument_digest"]


def test_008_list_order_is_significant():
    a = create_decision_binding(
        identity_policy_result=_identity_result(), arguments={"items": [1, 2, 3]}, issued_at=ISSUED_AT, expires_at=EXPIRES_AT,
    )
    b = create_decision_binding(
        identity_policy_result=_identity_result(), arguments={"items": [3, 2, 1]}, issued_at=ISSUED_AT, expires_at=EXPIRES_AT,
    )
    assert a["argument_digest"] != b["argument_digest"]


def test_009_string_values_produce_stable_digest():
    a = create_decision_binding(
        identity_policy_result=_identity_result(), arguments={"note": "hello"}, issued_at=ISSUED_AT, expires_at=EXPIRES_AT,
    )
    b = create_decision_binding(
        identity_policy_result=_identity_result(), arguments={"note": "hello"}, issued_at=ISSUED_AT, expires_at=EXPIRES_AT,
    )
    assert a["argument_digest"] == b["argument_digest"]


def test_010_boolean_values_distinct_from_strings():
    boolean_true = create_decision_binding(
        identity_policy_result=_identity_result(), arguments={"flag": True}, issued_at=ISSUED_AT, expires_at=EXPIRES_AT,
    )
    string_true = create_decision_binding(
        identity_policy_result=_identity_result(), arguments={"flag": "True"}, issued_at=ISSUED_AT, expires_at=EXPIRES_AT,
    )
    assert boolean_true["argument_digest"] != string_true["argument_digest"]


def test_011_null_values_are_handled():
    result = create_decision_binding(
        identity_policy_result=_identity_result(), arguments={"value": None}, issued_at=ISSUED_AT, expires_at=EXPIRES_AT,
    )
    assert result["binding_outcome"] == "created"


def test_012_numeric_int_and_float_are_distinct():
    integer_value = create_decision_binding(
        identity_policy_result=_identity_result(), arguments={"count": 1}, issued_at=ISSUED_AT, expires_at=EXPIRES_AT,
    )
    float_value = create_decision_binding(
        identity_policy_result=_identity_result(), arguments={"count": 1.0}, issued_at=ISSUED_AT, expires_at=EXPIRES_AT,
    )
    assert integer_value["argument_digest"] != float_value["argument_digest"]


def test_013_unicode_values_produce_stable_equal_digest():
    a = create_decision_binding(
        identity_policy_result=_identity_result(), arguments={"label": "Ünïcödé 漢字 🔥"}, issued_at=ISSUED_AT, expires_at=EXPIRES_AT,
    )
    b = create_decision_binding(
        identity_policy_result=_identity_result(), arguments={"label": "Ünïcödé 漢字 🔥"}, issued_at=ISSUED_AT, expires_at=EXPIRES_AT,
    )
    assert a["argument_digest"] == b["argument_digest"]


def test_014_caller_arguments_not_mutated():
    original_arguments = {"nested": {"b": 2, "a": 1}, "list": [1, 2, 3]}
    snapshot = copy.deepcopy(original_arguments)

    create_decision_binding(
        identity_policy_result=_identity_result(),
        arguments=original_arguments,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
    )

    assert original_arguments == snapshot


def test_015_unsupported_value_type_rejected():
    result = create_decision_binding(
        identity_policy_result=_identity_result(),
        arguments={"bad": {1, 2, 3}},
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
    )
    assert result["binding_outcome"] == "refused"
    assert result["refusal_reason"]["code"] == "ARGUMENTS_NOT_CANONICALIZABLE"


def test_016_nan_and_infinity_rejected():
    for bad_value in (float("nan"), float("inf"), float("-inf")):
        result = create_decision_binding(
            identity_policy_result=_identity_result(),
            arguments={"bad": bad_value},
            issued_at=ISSUED_AT,
            expires_at=EXPIRES_AT,
        )
        assert result["binding_outcome"] == "refused"
        assert result["refusal_reason"]["code"] == "ARGUMENTS_NOT_CANONICALIZABLE"


# ---------------------------------------------------------------------------
# Creation refusal
# ---------------------------------------------------------------------------


def test_017_final_deny_decision_refused():
    result = _created_binding(identity_policy_result=_deny_identity_result())

    assert result["binding_outcome"] == "refused"
    assert result["refusal_reason"]["code"] == "IDENTITY_RESULT_DENIED"
    assert result["canonical_agent_id"] is None
    assert result["identity_authenticated"] is False
    assert result["execution_performed"] is False


def test_018_deny_with_populated_agent_tool_fields_refused():
    # Structurally valid deny result where canonical_agent_id, agent_role,
    # and canonical_tool_name are all populated (the real Block 9 shape
    # for e.g. TOOL_NOT_IN_AGENT_ALLOWLIST) -- creation must still refuse
    # purely because final_decision is deny, without needing those fields
    # to be None.
    populated_deny_result = _deny_identity_result_with_populated_fields()
    result = _created_binding(identity_policy_result=populated_deny_result)

    assert result["binding_outcome"] == "refused"
    assert result["refusal_reason"]["code"] == "IDENTITY_RESULT_DENIED"


def test_019_invalid_agent_tool_fields_refused():
    inconsistent_result = _identity_result(final_decision="allow", canonical_agent_id=None)
    result = _created_binding(identity_policy_result=inconsistent_result)

    assert result["binding_outcome"] == "refused"
    assert result["refusal_reason"]["code"] == "INVALID_IDENTITY_RESULT_STRUCTURE"


def test_020_invalid_decision_result_structure_refused():
    malformed_variants = [
        None,
        "not-a-mapping",
        {},
        _identity_result(final_decision="banana"),
        _identity_result(identity_authenticated=True),
        _identity_result(execution_performed=True),
    ]
    for malformed in malformed_variants:
        result = _created_binding(identity_policy_result=malformed)
        assert result["binding_outcome"] == "refused"
        assert result["refusal_reason"]["code"] == "INVALID_IDENTITY_RESULT_STRUCTURE"


def test_021_arguments_not_a_mapping_refused():
    result = _created_binding(arguments=["not", "a", "mapping"])
    assert result["binding_outcome"] == "refused"
    assert result["refusal_reason"]["code"] == "ARGUMENTS_NOT_A_MAPPING"


def test_022_invalid_approval_reference_refused():
    # approval_reference is opaque -- it is never parsed as a UUID -- but
    # it must still be a non-blank string when supplied at all.
    for bad_value in ("", "   ", 12345, ["not", "a", "string"]):
        result = _created_binding(approval_reference=bad_value)
        assert result["binding_outcome"] == "refused"
        assert result["refusal_reason"]["code"] == "INVALID_APPROVAL_REFERENCE"


def test_023_invalid_issued_at_refused():
    result = _created_binding(issued_at="not-a-timestamp")
    assert result["binding_outcome"] == "refused"
    assert result["refusal_reason"]["code"] == "INVALID_ISSUED_AT"


def test_024_invalid_expires_at_refused():
    result = _created_binding(expires_at="not-a-timestamp")
    assert result["binding_outcome"] == "refused"
    assert result["refusal_reason"]["code"] == "INVALID_EXPIRES_AT"


def test_025_expiry_equal_to_issued_refused():
    result = _created_binding(issued_at=ISSUED_AT, expires_at=ISSUED_AT)
    assert result["binding_outcome"] == "refused"
    assert result["refusal_reason"]["code"] == "EXPIRY_NOT_AFTER_ISSUED"


def test_026_expiry_before_issued_refused():
    result = _created_binding(issued_at=ISSUED_AT, expires_at=_plus(-10))
    assert result["binding_outcome"] == "refused"
    assert result["refusal_reason"]["code"] == "EXPIRY_NOT_AFTER_ISSUED"


def test_027_lifetime_exceeds_maximum_refused():
    result = _created_binding(issued_at=ISSUED_AT, expires_at=_plus(MAX_BINDING_LIFETIME_SECONDS + 1))
    assert result["binding_outcome"] == "refused"
    assert result["refusal_reason"]["code"] == "LIFETIME_EXCEEDS_MAXIMUM"


def test_028_lifetime_exactly_at_maximum_is_allowed():
    result = _created_binding(issued_at=ISSUED_AT, expires_at=_plus(MAX_BINDING_LIFETIME_SECONDS))
    assert result["binding_outcome"] == "created"


# ---------------------------------------------------------------------------
# Verification success
# ---------------------------------------------------------------------------


def test_029_verify_exact_same_arguments_is_valid():
    binding = _created_binding()
    result = verify_decision_binding(
        binding=binding,
        fresh_identity_policy_result=_identity_result(),
        arguments=ARGUMENTS,
        verification_time=VERIFY_AT_WITHIN_WINDOW,
    )

    assert result["verification_outcome"] == "valid"
    assert _verify_codes(result) == ["BINDING_VALID", "CLAIMED_IDENTITY_NOT_AUTHENTICATED", "EXECUTION_NOT_PERFORMED", "REPLAY_PROTECTION_NOT_PROVIDED"]
    assert set(result) == _VERIFY_RESULT_FIELDS


def test_030_verify_equivalent_dictionary_ordering_is_valid():
    binding = create_decision_binding(
        identity_policy_result=_identity_result(),
        arguments={"a": 1, "b": 2},
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
    )
    result = verify_decision_binding(
        binding=binding,
        fresh_identity_policy_result=_identity_result(),
        arguments={"b": 2, "a": 1},
        verification_time=VERIFY_AT_WITHIN_WINDOW,
    )

    assert result["verification_outcome"] == "valid"


def test_031_verify_fresh_result_matches_bound_decision():
    binding = _created_binding(approval_reference=APPROVAL_REFERENCE)
    result = verify_decision_binding(
        binding=binding,
        fresh_identity_policy_result=_identity_result(),
        arguments=ARGUMENTS,
        verification_time=VERIFY_AT_WITHIN_WINDOW,
        approval_reference=APPROVAL_REFERENCE,
    )

    assert result["verification_outcome"] == "valid"
    assert result["canonical_agent_id"] == "analyst_agent"
    assert result["canonical_tool_name"] == "load_risk_aware_approval_record"
    assert result["policy_decision"] == "allow"


def test_032_verify_non_expired_binding_is_valid():
    binding = _created_binding()
    result = verify_decision_binding(
        binding=binding,
        fresh_identity_policy_result=_identity_result(),
        arguments=ARGUMENTS,
        verification_time=_plus(299),
    )
    assert result["verification_outcome"] == "valid"


# ---------------------------------------------------------------------------
# Verification failure
# ---------------------------------------------------------------------------


def test_033_verify_changed_agent_is_invalid():
    binding = _created_binding()
    fresh = _identity_result(canonical_agent_id="coordinator_agent")
    result = verify_decision_binding(
        binding=binding, fresh_identity_policy_result=fresh, arguments=ARGUMENTS, verification_time=VERIFY_AT_WITHIN_WINDOW,
    )
    assert result["verification_outcome"] == "invalid"
    assert "AGENT_MISMATCH" in _verify_codes(result)


def test_034_verify_changed_tool_is_invalid():
    binding = _created_binding()
    fresh = _identity_result(canonical_tool_name="load_investigation_approval_context")
    result = verify_decision_binding(
        binding=binding, fresh_identity_policy_result=fresh, arguments=ARGUMENTS, verification_time=VERIFY_AT_WITHIN_WINDOW,
    )
    assert result["verification_outcome"] == "invalid"
    assert "TOOL_MISMATCH" in _verify_codes(result)


def test_035_verify_changed_gateway_decision_is_invalid():
    # Same agent, same tool, same final decision -- only the fresh Block 9
    # result's gateway_decision (Block 8's own decision) differs from what
    # was bound. This must be caught independently of policy_decision.
    binding = _created_binding()
    fresh = _identity_result(gateway_decision="require_approval")
    result = verify_decision_binding(
        binding=binding, fresh_identity_policy_result=fresh, arguments=ARGUMENTS, verification_time=VERIFY_AT_WITHIN_WINDOW,
    )
    assert result["verification_outcome"] == "invalid"
    codes = _verify_codes(result)
    assert "GATEWAY_DECISION_MISMATCH" in codes
    assert "AGENT_MISMATCH" not in codes
    assert "TOOL_MISMATCH" not in codes
    assert "POLICY_DECISION_MISMATCH" not in codes


def test_036_verify_changed_policy_decision_is_invalid():
    binding = _created_binding()
    fresh = _deny_identity_result()
    result = verify_decision_binding(
        binding=binding, fresh_identity_policy_result=fresh, arguments=ARGUMENTS, verification_time=VERIFY_AT_WITHIN_WINDOW,
    )
    assert result["verification_outcome"] == "invalid"
    assert "POLICY_DECISION_MISMATCH" in _verify_codes(result)


def test_037_verify_changed_arguments_is_invalid():
    binding = _created_binding()
    result = verify_decision_binding(
        binding=binding,
        fresh_identity_policy_result=_identity_result(),
        arguments={"approval_id": "ffffffff-ffff-4fff-8fff-ffffffffffff"},
        verification_time=VERIFY_AT_WITHIN_WINDOW,
    )
    assert result["verification_outcome"] == "invalid"
    assert "ARGUMENT_DIGEST_MISMATCH" in _verify_codes(result)


def test_038_verify_nested_argument_change_is_invalid():
    binding = create_decision_binding(
        identity_policy_result=_identity_result(),
        arguments={"outer": {"inner": 1}},
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
    )
    result = verify_decision_binding(
        binding=binding,
        fresh_identity_policy_result=_identity_result(),
        arguments={"outer": {"inner": 2}},
        verification_time=VERIFY_AT_WITHIN_WINDOW,
    )
    assert result["verification_outcome"] == "invalid"
    assert "ARGUMENT_DIGEST_MISMATCH" in _verify_codes(result)


def test_039_verify_changed_approval_reference_is_invalid():
    binding = _created_binding(approval_reference=APPROVAL_REFERENCE)
    result = verify_decision_binding(
        binding=binding,
        fresh_identity_policy_result=_identity_result(),
        arguments=ARGUMENTS,
        verification_time=VERIFY_AT_WITHIN_WINDOW,
        approval_reference=OTHER_APPROVAL_REFERENCE,
    )
    assert result["verification_outcome"] == "invalid"
    assert "APPROVAL_REFERENCE_CHANGED" in _verify_codes(result)


def test_040_verify_corrupted_argument_digest_field_is_invalid():
    binding = _created_binding()
    tampered = copy.deepcopy(binding)
    tampered["argument_digest"] = "sha256:" + "0" * 64

    result = verify_decision_binding(
        binding=tampered, fresh_identity_policy_result=_identity_result(), arguments=ARGUMENTS, verification_time=VERIFY_AT_WITHIN_WINDOW,
    )
    assert result["verification_outcome"] == "invalid"
    assert "BINDING_DIGEST_MISMATCH" in _verify_codes(result)


def test_041_verify_corrupted_binding_field_is_invalid():
    binding = _created_binding()
    tampered = copy.deepcopy(binding)
    tampered["canonical_agent_id"] = "coordinator_agent"

    result = verify_decision_binding(
        binding=tampered, fresh_identity_policy_result=_identity_result(), arguments=ARGUMENTS, verification_time=VERIFY_AT_WITHIN_WINDOW,
    )
    assert result["verification_outcome"] == "invalid"
    assert "BINDING_DIGEST_MISMATCH" in _verify_codes(result)


def test_042_verify_corrupted_binding_digest_is_invalid():
    binding = _created_binding()
    tampered = copy.deepcopy(binding)
    tampered["binding_digest"] = "sha256:" + "f" * 64

    result = verify_decision_binding(
        binding=tampered, fresh_identity_policy_result=_identity_result(), arguments=ARGUMENTS, verification_time=VERIFY_AT_WITHIN_WINDOW,
    )
    assert result["verification_outcome"] == "invalid"
    assert "BINDING_DIGEST_MISMATCH" in _verify_codes(result)


def test_043_verify_expired_binding_is_invalid():
    binding = _created_binding()
    result = verify_decision_binding(
        binding=binding, fresh_identity_policy_result=_identity_result(), arguments=ARGUMENTS, verification_time=VERIFY_AT_AFTER_EXPIRY,
    )
    assert result["verification_outcome"] == "invalid"
    assert "BINDING_EXPIRED" in _verify_codes(result)


def test_044_verify_binding_expired_exactly_at_expiry_boundary():
    binding = _created_binding()
    result = verify_decision_binding(
        binding=binding, fresh_identity_policy_result=_identity_result(), arguments=ARGUMENTS, verification_time=VERIFY_AT_AT_EXPIRY,
    )
    assert result["verification_outcome"] == "invalid"
    assert "BINDING_EXPIRED" in _verify_codes(result)


def test_045_verify_excessive_lifetime_rejected_even_if_self_consistent():
    binding = _created_binding()
    tampered = copy.deepcopy(binding)
    tampered["expires_at"] = _plus(MAX_BINDING_LIFETIME_SECONDS + 100)
    tampered["binding_digest"] = decision_binding_module._recompute_binding_digest(tampered)

    result = verify_decision_binding(
        binding=tampered, fresh_identity_policy_result=_identity_result(), arguments=ARGUMENTS, verification_time=_plus(50),
    )
    assert result["verification_outcome"] == "invalid"
    codes = _verify_codes(result)
    assert "LIFETIME_EXCEEDS_MAXIMUM" in codes
    assert "BINDING_DIGEST_MISMATCH" not in codes


def test_046_verify_malformed_binding_is_invalid():
    malformed_variants = [
        None,
        "not-a-mapping",
        {},
        {**_created_binding(), "decision_binding_version": "99"},
        {**_created_binding(), "binding_outcome": "refused"},
        {**_created_binding(), "policy_decision": "deny"},
    ]
    for malformed in malformed_variants:
        result = verify_decision_binding(
            binding=malformed, fresh_identity_policy_result=_identity_result(), arguments=ARGUMENTS, verification_time=VERIFY_AT_WITHIN_WINDOW,
        )
        assert result["verification_outcome"] == "invalid"
        assert "MALFORMED_BINDING" in _verify_codes(result)
        assert result["canonical_agent_id"] is None


def test_047_verify_malformed_fresh_identity_result_is_invalid():
    binding = _created_binding()
    malformed_variants = [None, "not-a-mapping", {}, _identity_result(final_decision="banana")]
    for malformed in malformed_variants:
        result = verify_decision_binding(
            binding=binding, fresh_identity_policy_result=malformed, arguments=ARGUMENTS, verification_time=VERIFY_AT_WITHIN_WINDOW,
        )
        assert result["verification_outcome"] == "invalid"
        assert "MALFORMED_FRESH_IDENTITY_RESULT" in _verify_codes(result)
        assert result["canonical_agent_id"] == "analyst_agent"


def test_048_verify_malformed_arguments_is_invalid():
    binding = _created_binding()
    result = verify_decision_binding(
        binding=binding, fresh_identity_policy_result=_identity_result(), arguments=["not", "a", "mapping"], verification_time=VERIFY_AT_WITHIN_WINDOW,
    )
    assert result["verification_outcome"] == "invalid"
    assert "MALFORMED_ARGUMENTS" in _verify_codes(result)


def test_049_verify_malformed_verification_time_is_invalid():
    binding = _created_binding()
    result = verify_decision_binding(
        binding=binding, fresh_identity_policy_result=_identity_result(), arguments=ARGUMENTS, verification_time="not-a-timestamp",
    )
    assert result["verification_outcome"] == "invalid"
    assert "MALFORMED_VERIFICATION_TIME" in _verify_codes(result)


# ---------------------------------------------------------------------------
# Honesty fields -- never claim authentication, execution, or replay
# protection, regardless of outcome.
# ---------------------------------------------------------------------------


def test_050_verification_never_claims_authentication_execution_or_replay_protection():
    binding = _created_binding()

    valid_result = verify_decision_binding(
        binding=binding, fresh_identity_policy_result=_identity_result(), arguments=ARGUMENTS, verification_time=VERIFY_AT_WITHIN_WINDOW,
    )
    invalid_result = verify_decision_binding(
        binding=binding, fresh_identity_policy_result=_identity_result(), arguments=ARGUMENTS, verification_time=VERIFY_AT_AFTER_EXPIRY,
    )

    for result in (valid_result, invalid_result):
        assert result["identity_authenticated"] is False
        assert result["execution_performed"] is False
        assert result["replay_protection_provided"] is False

    # Verifying the same still-valid binding twice is not treated as a
    # replay -- this module keeps no state between calls.
    repeated_result = verify_decision_binding(
        binding=binding, fresh_identity_policy_result=_identity_result(), arguments=ARGUMENTS, verification_time=VERIFY_AT_WITHIN_WINDOW,
    )
    assert repeated_result["verification_outcome"] == "valid"
