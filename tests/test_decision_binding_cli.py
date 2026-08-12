"""Tests for core.decision_binding_cli -- the stdin/stdout JSON adapter
around core.decision_binding.create_decision_binding and
core.decision_binding.verify_decision_binding (Block 10).

main() is called directly with in-memory StringIO streams. No Supabase,
MCP, file, subprocess, network, Hayabusa, or AI/model access occurs
anywhere in this file; every input is a plain in-memory JSON object, and
every timestamp is a fixed literal -- never datetime.now(), utcnow(), or
time.time(). No agent is ever authenticated and no tool is ever executed.

This file does not re-verify every Decision Binding core validation case
(see tests/test_decision_binding.py for the 49 core tests) -- it tests
only the CLI's own adapter boundary: envelope dispatch, pass-through,
exit codes, and output/error shape.
"""

import copy
import inspect
import json
from datetime import datetime, timedelta, timezone
from io import StringIO

from core import decision_binding_cli
from core.decision_binding import create_decision_binding as _core_create_decision_binding

BASE_TIME = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)


def _iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def _plus(seconds):
    return _iso(BASE_TIME + timedelta(seconds=seconds))


ISSUED_AT = _plus(0)
EXPIRES_AT = _plus(300)
VERIFY_AT_WITHIN_WINDOW = _plus(120)

ARGUMENTS = {"approval_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}

_CREATE_REQUIRED_FIELDS = (
    "identity_policy_result",
    "arguments",
    "issued_at",
    "expires_at",
)
_VERIFY_REQUIRED_FIELDS = (
    "binding",
    "fresh_identity_policy_result",
    "arguments",
    "verification_time",
)


def _identity_result(**overrides):
    base = {
        "canonical_agent_id": "analyst_agent",
        "agent_role": "analyst",
        "canonical_tool_name": "load_risk_aware_approval_record",
        "gateway_decision": "allow",
        "final_decision": "allow",
        "identity_authenticated": False,
        "execution_performed": False,
    }
    base.update(overrides)
    return base


def _build_binding(**create_kwargs):
    kwargs = {
        "identity_policy_result": _identity_result(),
        "arguments": dict(ARGUMENTS),
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        "approval_reference": None,
    }
    kwargs.update(create_kwargs)
    return _core_create_decision_binding(**kwargs)


def _create_envelope(**overrides):
    envelope = {
        "operation": "create",
        "identity_policy_result": _identity_result(),
        "arguments": dict(ARGUMENTS),
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        "approval_reference": None,
    }
    envelope.update(overrides)
    return envelope


def _verify_envelope(binding=None, **overrides):
    if binding is None:
        binding = _build_binding()
    envelope = {
        "operation": "verify",
        "binding": binding,
        "fresh_identity_policy_result": _identity_result(),
        "arguments": dict(ARGUMENTS),
        "verification_time": VERIFY_AT_WITHIN_WINDOW,
        "approval_reference": None,
    }
    envelope.update(overrides)
    return envelope


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = decision_binding_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _assert_no_forbidden_content(rendered):
    forbidden = (
        "Traceback",
        "DecisionBindingError",
        "AgentGatewayError",
        "AgentIdentityPolicyError",
        "ValueError",
        "RuntimeError",
        "KeyError",
    )
    for text in forbidden:
        assert text not in rendered


# ---------------------------------------------------------------------------
# Create success paths
# ---------------------------------------------------------------------------


def test_001_create_valid_request_succeeds():
    exit_code, stdout, stderr = _run(json.dumps(_create_envelope()))

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert result["binding_outcome"] == "created"
    assert result["canonical_agent_id"] == "analyst_agent"
    assert result["issued_at"] is not None
    assert result["identity_authenticated"] is False
    assert result["execution_performed"] is False


def test_002_create_with_null_approval_reference():
    exit_code, stdout, stderr = _run(json.dumps(_create_envelope(approval_reference=None)))

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert result["binding_outcome"] == "created"
    assert result["approval_reference"] is None


def test_003_create_with_opaque_non_uuid_approval_reference():
    exit_code, stdout, stderr = _run(
        json.dumps(_create_envelope(approval_reference="case-review-A"))
    )

    assert exit_code == 0
    result = json.loads(stdout)
    assert result["binding_outcome"] == "created"
    assert result["approval_reference"] == "case-review-A"


def test_004_create_key_order_independence():
    envelope = _create_envelope()
    forward = json.dumps(envelope)
    reordered = json.dumps(dict(reversed(list(envelope.items()))))

    exit_code1, stdout1, _ = _run(forward)
    exit_code2, stdout2, _ = _run(reordered)

    assert exit_code1 == 0
    assert exit_code2 == 0
    assert json.loads(stdout1) == json.loads(stdout2)


def test_005_create_refused_outcome_is_exit_zero():
    denied_identity_result = _identity_result(
        canonical_agent_id=None,
        agent_role=None,
        canonical_tool_name=None,
        gateway_decision=None,
        final_decision="deny",
    )
    exit_code, stdout, stderr = _run(
        json.dumps(_create_envelope(identity_policy_result=denied_identity_result))
    )

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert result["binding_outcome"] == "refused"
    assert result["refusal_reason"]["code"] == "IDENTITY_RESULT_DENIED"


# ---------------------------------------------------------------------------
# Verify success paths
# ---------------------------------------------------------------------------


def test_006_verify_valid_verification_succeeds():
    exit_code, stdout, stderr = _run(json.dumps(_verify_envelope()))

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert result["verification_outcome"] == "valid"
    assert result["identity_authenticated"] is False
    assert result["execution_performed"] is False
    assert result["replay_protection_provided"] is False


def test_007_verify_invalid_result_still_exits_zero():
    fresh = _identity_result(canonical_agent_id="coordinator_agent")
    exit_code, stdout, stderr = _run(json.dumps(_verify_envelope(fresh_identity_policy_result=fresh)))

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert result["verification_outcome"] == "invalid"
    codes = [rule["code"] for rule in result["matched_verification_rules"]]
    assert "AGENT_MISMATCH" in codes


def test_008_verify_approval_reference_passed_through():
    binding = _build_binding(approval_reference="case-review-A")

    matching_exit, matching_stdout, _ = _run(
        json.dumps(_verify_envelope(binding=binding, approval_reference="case-review-A"))
    )
    assert matching_exit == 0
    assert json.loads(matching_stdout)["verification_outcome"] == "valid"

    differing_exit, differing_stdout, _ = _run(
        json.dumps(_verify_envelope(binding=binding, approval_reference="case-review-B"))
    )
    assert differing_exit == 0
    differing_result = json.loads(differing_stdout)
    assert differing_result["verification_outcome"] == "invalid"
    codes = [rule["code"] for rule in differing_result["matched_verification_rules"]]
    assert "APPROVAL_REFERENCE_CHANGED" in codes


def test_009_verify_key_order_independence():
    envelope = _verify_envelope()
    forward = json.dumps(envelope)
    reordered = json.dumps(dict(reversed(list(envelope.items()))))

    exit_code1, stdout1, _ = _run(forward)
    exit_code2, stdout2, _ = _run(reordered)

    assert exit_code1 == 0
    assert exit_code2 == 0
    assert json.loads(stdout1) == json.loads(stdout2)


# ---------------------------------------------------------------------------
# Input / envelope failures
# ---------------------------------------------------------------------------


def test_010_malformed_json_input():
    exit_code, stdout, stderr = _run("{not valid json")

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Decision binding CLI validation failed:")
    _assert_no_forbidden_content(stderr)


def test_011_non_object_top_level_json_rejected():
    for bad_payload in (json.dumps([1, 2, 3]), json.dumps("just a string"), json.dumps(None)):
        exit_code, stdout, stderr = _run(bad_payload)
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("Decision binding CLI validation failed:")
        _assert_no_forbidden_content(stderr)


def test_012_missing_or_unknown_operation_rejected():
    missing_op = _create_envelope()
    del missing_op["operation"]
    exit_code1, stdout1, stderr1 = _run(json.dumps(missing_op))
    assert exit_code1 == 2
    assert stdout1 == ""

    for bad_operation in ("delete", "", 123, None):
        exit_code2, stdout2, stderr2 = _run(json.dumps(_create_envelope(operation=bad_operation)))
        assert exit_code2 == 2
        assert stdout2 == ""
        assert "operation" in stderr2


def test_013_create_missing_required_field_rejected():
    for field in _CREATE_REQUIRED_FIELDS:
        envelope = _create_envelope()
        del envelope[field]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2
        assert stdout == ""
        assert "Decision binding CLI validation failed:" in stderr
        _assert_no_forbidden_content(stderr)


def test_014_create_missing_approval_reference_key_rejected():
    envelope = _create_envelope()
    del envelope["approval_reference"]
    exit_code, stdout, stderr = _run(json.dumps(envelope))

    assert exit_code == 2
    assert stdout == ""
    assert "approval_reference" in stderr


def test_015_create_extra_field_rejected():
    envelope = _create_envelope()
    envelope["unexpected_field"] = "nope"
    exit_code, stdout, stderr = _run(json.dumps(envelope))

    assert exit_code == 2
    assert stdout == ""
    assert "unexpected_field" in stderr


def test_016_verify_missing_required_field_rejected():
    for field in _VERIFY_REQUIRED_FIELDS:
        envelope = _verify_envelope()
        del envelope[field]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2
        assert stdout == ""
        assert "Decision binding CLI validation failed:" in stderr
        _assert_no_forbidden_content(stderr)


def test_017_verify_missing_approval_reference_key_rejected():
    envelope = _verify_envelope()
    del envelope["approval_reference"]
    exit_code, stdout, stderr = _run(json.dumps(envelope))

    assert exit_code == 2
    assert stdout == ""
    assert "approval_reference" in stderr


def test_018_verify_extra_field_rejected():
    envelope = _verify_envelope()
    envelope["unexpected_field"] = "nope"
    exit_code, stdout, stderr = _run(json.dumps(envelope))

    assert exit_code == 2
    assert stdout == ""
    assert "unexpected_field" in stderr


# ---------------------------------------------------------------------------
# Adapter / security boundary behavior
# ---------------------------------------------------------------------------


def test_019_cli_module_never_touches_block8_block9_clock_or_external_systems():
    # Only the executable code is inspected, not the module docstring --
    # the docstring itself names core.agent_gateway/core.agent_identity_policy
    # to explain that this module never imports them, which would otherwise
    # trip this same substring check.
    full_source = inspect.getsource(decision_binding_cli)
    source = full_source.split("from __future__", 1)[1]
    forbidden_substrings = (
        "agent_gateway",
        "agent_identity_policy",
        "evaluate_tool_call",
        "evaluate_agent_tool_call",
        "datetime.now",
        "utcnow",
        "time.time",
        "supabase",
        "mcp",
        "subprocess",
        "socket",
        "requests",
        "urllib",
    )
    for forbidden in forbidden_substrings:
        assert forbidden not in source


def test_020_supplied_structures_are_not_mutated():
    original_arguments = {"nested": {"b": 2, "a": 1}}
    snapshot = copy.deepcopy(original_arguments)
    binding = _build_binding(arguments=original_arguments)
    binding_snapshot = copy.deepcopy(binding)

    _run(json.dumps(_create_envelope(arguments=original_arguments)))
    assert original_arguments == snapshot

    _run(json.dumps(_verify_envelope(binding=binding, arguments=original_arguments)))
    assert original_arguments == snapshot
    assert binding == binding_snapshot


def test_021_deterministic_sorted_json_output():
    raw_input = json.dumps(_create_envelope())

    exit_code1, stdout1, _ = _run(raw_input)
    exit_code2, stdout2, _ = _run(raw_input)

    assert exit_code1 == 0
    assert stdout1 == stdout2
    result = json.loads(stdout1)
    assert list(result) == sorted(result)
    reserialized = json.dumps(result, sort_keys=True, ensure_ascii=False) + "\n"
    assert reserialized == stdout1


def test_022_stdout_contains_exactly_one_json_line():
    exit_code, stdout, _ = _run(json.dumps(_create_envelope()))
    assert exit_code == 0
    assert stdout.endswith("\n")
    assert stdout.count("\n") == 1

    exit_code2, stdout2, _ = _run(json.dumps(_verify_envelope()))
    assert exit_code2 == 0
    assert stdout2.endswith("\n")
    assert stdout2.count("\n") == 1


def test_023_no_traceback_or_exception_class_leaked_on_errors():
    error_payloads = (
        "{not valid json",
        json.dumps([1, 2, 3]),
        json.dumps(_create_envelope(operation="bogus")),
    )
    for payload in error_payloads:
        _, stdout, stderr = _run(payload)
        assert stdout == ""
        _assert_no_forbidden_content(stderr)


def test_024_exact_delegation_kwargs_for_create(monkeypatch):
    captured = {}
    original = decision_binding_cli.create_decision_binding

    def spy(**kwargs):
        captured.update(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(decision_binding_cli, "create_decision_binding", spy)

    exit_code, stdout, stderr = _run(json.dumps(_create_envelope()))

    assert exit_code == 0
    assert set(captured) == {"identity_policy_result", "arguments", "issued_at", "expires_at", "approval_reference"}
    assert captured["arguments"] == ARGUMENTS
    assert captured["issued_at"] == ISSUED_AT
    assert captured["expires_at"] == EXPIRES_AT


def test_025_exact_delegation_kwargs_for_verify(monkeypatch):
    captured = {}
    original = decision_binding_cli.verify_decision_binding

    def spy(**kwargs):
        captured.update(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(decision_binding_cli, "verify_decision_binding", spy)

    exit_code, stdout, stderr = _run(json.dumps(_verify_envelope()))

    assert exit_code == 0
    assert set(captured) == {
        "binding", "fresh_identity_policy_result", "arguments", "verification_time", "approval_reference",
    }
    assert captured["arguments"] == ARGUMENTS
    assert captured["verification_time"] == VERIFY_AT_WITHIN_WINDOW


def test_026_unexpected_internal_failure_is_exit_one(monkeypatch):
    def _boom(**kwargs):
        raise RuntimeError("secret internal detail XYZ123")

    monkeypatch.setattr(decision_binding_cli, "create_decision_binding", _boom)
    exit_code, stdout, stderr = _run(json.dumps(_create_envelope()))

    assert exit_code == 1
    assert stdout == ""
    assert stderr.startswith("Decision binding CLI internal error:")
    assert "secret internal detail" not in stderr
    _assert_no_forbidden_content(stderr)


def test_027_honesty_fields_preserved_verbatim_for_both_operations():
    create_exit, create_stdout, _ = _run(json.dumps(_create_envelope()))
    assert create_exit == 0
    create_result = json.loads(create_stdout)
    assert create_result["identity_authenticated"] is False
    assert create_result["execution_performed"] is False

    verify_exit, verify_stdout, _ = _run(json.dumps(_verify_envelope()))
    assert verify_exit == 0
    verify_result = json.loads(verify_stdout)
    assert verify_result["identity_authenticated"] is False
    assert verify_result["execution_performed"] is False
    assert verify_result["replay_protection_provided"] is False
