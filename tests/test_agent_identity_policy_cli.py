"""Tests for core.agent_identity_policy_cli -- the stdin/stdout JSON
adapter around core.agent_identity_policy.evaluate_agent_tool_call.

main() is called directly with in-memory StringIO streams. No Supabase,
MCP, file, subprocess, network, Hayabusa, or AI/model access occurs
anywhere in this file; every input is a plain in-memory JSON object, and
every timestamp is a fixed literal -- never datetime.now(), utcnow(), or
time.time(). No agent is ever authenticated and no tool is ever executed.
"""

import copy
import json
from io import StringIO

from core import agent_identity_policy_cli

APPROVAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
EVALUATED_AT = "2026-08-01T12:00:00Z"

_FIFTEEN_RESULT_FIELDS = {
    "identity_policy_version", "canonical_agent_id", "agent_role", "identity_authenticated",
    "canonical_tool_name", "operation_class", "gateway_decision", "final_decision",
    "eligible_for_execution", "requires_approval", "matched_identity_rules",
    "safe_capability_summary", "required_next_action", "evaluated_at", "execution_performed",
}


def _envelope(**overrides):
    envelope = {
        "agent_id": "analyst_agent",
        "tool_name": "load_risk_aware_approval_record",
        "arguments": {"approval_id": APPROVAL_ID},
        "evaluated_at": EVALUATED_AT,
    }
    envelope.update(overrides)
    return envelope


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = agent_identity_policy_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _assert_no_forbidden_content(rendered):
    forbidden = (
        "requested_by", "approved_by", "rejected_by", "consumed_by", "credential", "token",
        "password", "secret", "Traceback", "AgentIdentityPolicyError", "AgentGatewayError",
        "ValueError", "RuntimeError", "mcp__supabase", "descriptor",
    )
    for text in forbidden:
        assert text not in rendered


# ---------------------------------------------------------------------------
# 1: allow result
# ---------------------------------------------------------------------------


def test_001_allow_result():
    exit_code, stdout, stderr = _run(json.dumps(_envelope()))

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert set(result) == _FIFTEEN_RESULT_FIELDS
    assert result["final_decision"] == "allow"
    assert result["gateway_decision"] == "allow"
    assert result["eligible_for_execution"] is True
    assert result["requires_approval"] is False
    assert result["identity_authenticated"] is False
    assert result["execution_performed"] is False


# ---------------------------------------------------------------------------
# 2: require-approval result
# ---------------------------------------------------------------------------


def test_002_require_approval_result_is_not_treated_as_error():
    exit_code, stdout, stderr = _run(
        json.dumps(_envelope(
            agent_id="coordinator_agent",
            tool_name="apply_approval_consumption",
            arguments={"approval_id": APPROVAL_ID},
        ))
    )

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert result["final_decision"] == "require_approval"
    assert result["gateway_decision"] == "require_approval"
    assert result["eligible_for_execution"] is False
    assert result["requires_approval"] is True
    assert result["identity_authenticated"] is False
    assert result["execution_performed"] is False


# ---------------------------------------------------------------------------
# 3: deny results
# ---------------------------------------------------------------------------


def test_003_deny_results_are_not_treated_as_errors():
    unknown_agent_id = "ghost_agent"
    exit_code, stdout, stderr = _run(json.dumps(_envelope(agent_id=unknown_agent_id)))
    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert result["final_decision"] == "deny"
    assert result["eligible_for_execution"] is False
    assert result["requires_approval"] is False
    assert result["identity_authenticated"] is False
    assert result["execution_performed"] is False
    assert unknown_agent_id not in stdout

    exit_code2, stdout2, stderr2 = _run(json.dumps(_envelope(
        agent_id="analyst_agent",
        tool_name="apply_approval_consumption",
        arguments={"approval_id": APPROVAL_ID},
    )))
    assert exit_code2 == 0
    assert stderr2 == ""
    result2 = json.loads(stdout2)
    assert result2["final_decision"] == "deny"
    assert result2["identity_authenticated"] is False
    assert result2["execution_performed"] is False

    exit_code3, stdout3, stderr3 = _run(json.dumps(_envelope(
        agent_id="coordinator_agent",
        tool_name="execute_sql",
        arguments={"query": "SELECT * FROM approvals;"},
    )))
    assert exit_code3 == 0
    assert stderr3 == ""
    result3 = json.loads(stdout3)
    assert result3["final_decision"] == "deny"
    assert result3["eligible_for_execution"] is False
    assert result3["requires_approval"] is False
    assert "SELECT" not in stdout3


# ---------------------------------------------------------------------------
# 4: exact delegation envelope
# ---------------------------------------------------------------------------


def test_004_exact_delegation_envelope(monkeypatch):
    captured = {}
    original = agent_identity_policy_cli.evaluate_agent_tool_call

    def spy(**kwargs):
        captured.update(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(agent_identity_policy_cli, "evaluate_agent_tool_call", spy)

    exit_code, stdout, stderr = _run(json.dumps(_envelope()))

    assert exit_code == 0
    assert set(captured) == {"agent_id", "tool_name", "arguments", "evaluated_at"}
    assert captured["agent_id"] == "analyst_agent"
    assert captured["tool_name"] == "load_risk_aware_approval_record"
    assert captured["arguments"] == {"approval_id": APPROVAL_ID}
    assert captured["evaluated_at"] == EVALUATED_AT

    captured.clear()
    forbidden_envelope = _envelope()
    forbidden_envelope["role"] = "analyst"
    exit_code2, stdout2, stderr2 = _run(json.dumps(forbidden_envelope))
    assert exit_code2 == 2
    assert stdout2 == ""
    assert captured == {}

    forbidden_envelope2 = _envelope()
    forbidden_envelope2["identity_authenticated"] = True
    exit_code3, stdout3, stderr3 = _run(json.dumps(forbidden_envelope2))
    assert exit_code3 == 2
    assert stdout3 == ""
    assert captured == {}


# ---------------------------------------------------------------------------
# 5: deterministic success serialization
# ---------------------------------------------------------------------------


def test_005_deterministic_success_serialization():
    raw_input = json.dumps(_envelope())

    exit_code1, stdout1, _stderr1 = _run(raw_input)
    exit_code2, stdout2, _stderr2 = _run(raw_input)

    assert exit_code1 == 0
    assert exit_code2 == 0
    assert stdout1 == stdout2
    assert stdout1.endswith("\n")
    assert stdout1.count("\n") == 1

    result = json.loads(stdout1)
    assert list(result) == sorted(result)
    reserialized = json.dumps(result, sort_keys=True, ensure_ascii=False) + "\n"
    assert reserialized == stdout1


# ---------------------------------------------------------------------------
# 6: malformed JSON and non-object input
# ---------------------------------------------------------------------------


def test_006_malformed_json_and_non_object_input():
    exit_code, stdout, stderr = _run("{not valid json")
    assert exit_code == 2
    assert stdout == ""
    assert stderr != ""
    assert "Traceback" not in stderr
    assert "JSONDecodeError" not in stderr

    for non_object_payload in ([1, 2, 3], "just a string", 42, None):
        exit_code_n, stdout_n, stderr_n = _run(json.dumps(non_object_payload))
        assert exit_code_n == 2
        assert stdout_n == ""
        assert "JSON object" in stderr_n
        assert "Traceback" not in stderr_n


# ---------------------------------------------------------------------------
# 7: missing, extra, and structural validation failures
# ---------------------------------------------------------------------------


def test_007_missing_extra_and_structural_validation_failures():
    for missing_field in ("agent_id", "tool_name", "arguments", "evaluated_at"):
        envelope = _envelope()
        del envelope[missing_field]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2, missing_field
        assert stdout == "", missing_field
        assert "Traceback" not in stderr, missing_field

    extra_envelope = _envelope()
    extra_envelope["extra_field"] = "unexpected"
    exit_code, stdout, stderr = _run(json.dumps(extra_envelope))
    assert exit_code == 2
    assert stdout == ""
    assert "Traceback" not in stderr

    exit_code, stdout, stderr = _run(json.dumps(_envelope(agent_id="   ")))
    assert exit_code == 2
    assert stdout == ""
    assert "Agent identity policy validation failed:" in stderr
    assert "AgentIdentityPolicyError" not in stderr

    unsafe_agent_id = "analyst;agent"
    exit_code, stdout, stderr = _run(json.dumps(_envelope(agent_id=unsafe_agent_id)))
    assert exit_code == 2
    assert stdout == ""
    assert "Agent identity policy validation failed:" in stderr
    assert unsafe_agent_id not in stderr

    exit_code, stdout, stderr = _run(json.dumps(_envelope(tool_name=123)))
    assert exit_code == 2
    assert stdout == ""
    assert "Agent identity policy validation failed:" in stderr

    exit_code, stdout, stderr = _run(json.dumps(_envelope(tool_name="   ")))
    assert exit_code == 2
    assert stdout == ""
    assert "Agent identity policy validation failed:" in stderr

    exit_code, stdout, stderr = _run(json.dumps(_envelope(arguments=["not", "a", "mapping"])))
    assert exit_code == 2
    assert stdout == ""
    assert "Agent identity policy validation failed:" in stderr
    assert APPROVAL_ID not in stderr

    exit_code, stdout, stderr = _run(json.dumps(_envelope(evaluated_at="not-a-timestamp")))
    assert exit_code == 2
    assert stdout == ""
    assert "Agent identity policy validation failed:" in stderr

    exit_code, stdout, stderr = _run(json.dumps(_envelope(evaluated_at="2026-08-01T12:00:00")))
    assert exit_code == 2
    assert stdout == ""
    assert "Agent identity policy validation failed:" in stderr


# ---------------------------------------------------------------------------
# 8: unexpected error, nonmutation, and recursive output safety
# ---------------------------------------------------------------------------


def test_008_unexpected_error_nonmutation_and_output_safety(monkeypatch):
    def _boom(**kwargs):
        raise RuntimeError("secret internal detail XYZ123")

    monkeypatch.setattr(agent_identity_policy_cli, "evaluate_agent_tool_call", _boom)
    exit_code, stdout, stderr = _run(json.dumps(_envelope()))

    assert exit_code == 1
    assert stdout == ""
    assert stderr == "Agent identity policy validation failed.\n"
    assert "secret internal detail" not in stderr
    assert "RuntimeError" not in stderr
    assert "Traceback" not in stderr

    monkeypatch.undo()

    record = {"approval_id": APPROVAL_ID}
    snapshot = copy.deepcopy(record)
    raw_input = json.dumps(_envelope(arguments=record))
    _run(raw_input)
    _run(raw_input)
    assert record == snapshot

    for envelope in (
        _envelope(),
        _envelope(
            agent_id="coordinator_agent",
            tool_name="apply_approval_consumption",
            arguments={"approval_id": APPROVAL_ID},
        ),
        _envelope(agent_id="ghost_agent"),
        _envelope(agent_id="coordinator_agent", tool_name="execute_sql", arguments={"query": "SELECT 1;"}),
        _envelope(
            agent_id="coordinator_agent",
            tool_name="run_evtx_analysis",
            arguments={
                "evtx_file": "sample.evtx",
                "analysis_type": "csv_timeline",
                "output_name": "result.csv",
                "authorization_phrase": "RUN AUTHORIZED HAYABUSA ANALYSIS",
            },
        ),
    ):
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        _assert_no_forbidden_content(stdout)
        assert APPROVAL_ID not in stdout
        assert "SELECT 1" not in stdout
        assert "sample.evtx" not in stdout
        assert "RUN AUTHORIZED HAYABUSA ANALYSIS" not in stdout
        assert "ghost_agent" not in stdout
        result = json.loads(stdout)
        assert "allowed_tools" not in json.dumps(result["safe_capability_summary"])
