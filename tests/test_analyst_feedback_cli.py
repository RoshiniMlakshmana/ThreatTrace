"""Tests for core.analyst_feedback_cli -- the stdin/stdout JSON adapter
around core.analyst_feedback.create_analyst_feedback (Block 13).

main() is called directly with in-memory StringIO streams. No Supabase,
MCP, file, subprocess, network, Hayabusa, or AI/model access occurs
anywhere in this file; every input is a plain in-memory JSON object, and
every timestamp is a fixed literal -- never datetime.now(), utcnow(), or
time.time(). No tool is ever executed.

This file does not re-verify every core.analyst_feedback validation case
(see tests/test_analyst_feedback.py for the 60 core tests) -- it tests
only the CLI's own adapter boundary: envelope dispatch, pass-through,
exit codes, and output/error shape.
"""

import inspect
import json
from io import StringIO

from core import analyst_feedback_cli

SUBMITTED_AT = "2026-01-01T00:00:00Z"

_RESULT_FIELDS = {
    "feedback_version", "target_type", "target_reference", "analyst_decision", "error_category",
    "rationale", "evidence_reference", "corrected_value", "submitted_at", "feedback_persisted",
    "automatic_learning_performed",
}


def _envelope(**overrides):
    envelope = {
        "operation": "create",
        "target_type": "investigation_decision",
        "target_reference": "investigation-123",
        "analyst_decision": "agree",
        "error_category": None,
        "rationale": None,
        "evidence_reference": None,
        "corrected_value": None,
        "submitted_at": SUBMITTED_AT,
    }
    envelope.update(overrides)
    return envelope


def _disagree_envelope(**overrides):
    envelope = _envelope(
        analyst_decision="disagree",
        error_category="false_positive",
        rationale="The supporting evidence does not establish this classification.",
    )
    envelope.update(overrides)
    return envelope


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = analyst_feedback_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _assert_no_forbidden_content(rendered):
    forbidden = (
        "Traceback",
        "AnalystFeedbackError",
        "ValueError",
        "RuntimeError",
        "KeyError",
    )
    for text in forbidden:
        assert text not in rendered


# ---------------------------------------------------------------------------
# Successful create
# ---------------------------------------------------------------------------


def test_001_agree_creates_successfully():
    exit_code, stdout, stderr = _run(json.dumps(_envelope()))

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert set(result) == _RESULT_FIELDS
    assert result["analyst_decision"] == "agree"


def test_002_disagree_with_error_category_and_rationale_creates_successfully():
    exit_code, stdout, stderr = _run(json.dumps(_disagree_envelope()))

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert result["analyst_decision"] == "disagree"
    assert result["error_category"] == "false_positive"
    assert result["rationale"]


def test_003_insufficient_evidence_creates_successfully():
    exit_code, stdout, _ = _run(json.dumps(_envelope(analyst_decision="insufficient_evidence")))
    assert exit_code == 0
    result = json.loads(stdout)
    assert result["analyst_decision"] == "insufficient_evidence"


def test_004_investigation_decision_target_type():
    exit_code, stdout, _ = _run(json.dumps(_envelope(target_type="investigation_decision")))
    assert exit_code == 0
    assert json.loads(stdout)["target_type"] == "investigation_decision"


def test_005_security_policy_decision_target_type():
    exit_code, stdout, _ = _run(json.dumps(_envelope(
        target_type="security_policy_decision",
        target_reference="gateway:apply_approval_consumption:call-1",
        corrected_value="deny",
    )))
    assert exit_code == 0
    result = json.loads(stdout)
    assert result["target_type"] == "security_policy_decision"
    assert result["corrected_value"] == "deny"


def test_006_evaluation_result_target_type():
    exit_code, stdout, _ = _run(json.dumps(_envelope(
        target_type="evaluation_result",
        target_reference="evaluate:emergency_freeze_bypass:identity_agent:coordinator_agent",
        corrected_value="fail",
    )))
    assert exit_code == 0
    result = json.loads(stdout)
    assert result["target_type"] == "evaluation_result"
    assert result["corrected_value"] == "fail"


def test_007_corrected_value_passed_through():
    exit_code, stdout, _ = _run(json.dumps(_envelope(corrected_value="contradicted")))
    assert exit_code == 0
    assert json.loads(stdout)["corrected_value"] == "contradicted"


def test_008_evidence_reference_passed_through():
    exit_code, stdout, _ = _run(json.dumps(_envelope(evidence_reference=["evidence-1", "evidence-2"])))
    assert exit_code == 0
    assert json.loads(stdout)["evidence_reference"] == ["evidence-1", "evidence-2"]


# ---------------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------------


def test_009_exit_zero_for_handled_result():
    exit_code, _, _ = _run(json.dumps(_envelope()))
    assert exit_code == 0


def test_010_stdout_contains_exactly_one_sorted_json_line():
    exit_code, stdout, _ = _run(json.dumps(_envelope()))
    assert exit_code == 0
    assert stdout.endswith("\n")
    assert stdout.count("\n") == 1
    result = json.loads(stdout)
    reserialized = json.dumps(result, sort_keys=True, ensure_ascii=False) + "\n"
    assert reserialized == stdout


def test_011_deterministic_repeated_success_serialization():
    raw_input = json.dumps(_envelope())
    _, stdout1, _ = _run(raw_input)
    _, stdout2, _ = _run(raw_input)
    assert stdout1 == stdout2


def test_012_no_stderr_on_handled_result():
    for envelope in (_envelope(), _disagree_envelope(), _envelope(analyst_decision="insufficient_evidence")):
        exit_code, _, stderr = _run(json.dumps(envelope))
        assert exit_code == 0
        assert stderr == ""


def test_013_honesty_fields_preserved_false():
    for envelope in (_envelope(), _disagree_envelope()):
        _, stdout, _ = _run(json.dumps(envelope))
        result = json.loads(stdout)
        assert result["feedback_persisted"] is False
        assert result["automatic_learning_performed"] is False


# ---------------------------------------------------------------------------
# Envelope failures
# ---------------------------------------------------------------------------


def test_014_malformed_json_input():
    exit_code, stdout, stderr = _run("{not valid json")
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Analyst feedback CLI validation failed:")
    _assert_no_forbidden_content(stderr)


def test_015_top_level_list_rejected():
    exit_code, stdout, stderr = _run(json.dumps([1, 2, 3]))
    assert exit_code == 2
    assert stdout == ""


def test_016_top_level_string_rejected():
    exit_code, stdout, stderr = _run(json.dumps("just a string"))
    assert exit_code == 2
    assert stdout == ""


def test_017_top_level_null_rejected():
    exit_code, stdout, stderr = _run(json.dumps(None))
    assert exit_code == 2
    assert stdout == ""


def test_018_missing_operation_rejected():
    envelope = _envelope()
    del envelope["operation"]
    exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert stdout == ""


def test_019_unknown_operation_rejected():
    exit_code, stdout, stderr = _run(json.dumps(_envelope(operation="delete")))
    assert exit_code == 2
    assert stdout == ""
    assert "operation" in stderr


def test_020_missing_required_field_rejected():
    for field in ("target_type", "target_reference", "analyst_decision", "error_category",
                  "rationale", "evidence_reference", "corrected_value", "submitted_at"):
        envelope = _envelope()
        del envelope[field]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2, f"field={field}"
        assert stdout == ""
        assert field in stderr


def test_021_extra_field_rejected():
    envelope = _envelope()
    envelope["unexpected_field"] = "nope"
    exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert stdout == ""
    assert "unexpected_field" in stderr


def test_022_key_order_independence():
    envelope = _envelope()
    forward = json.dumps(envelope)
    reordered = json.dumps(dict(reversed(list(envelope.items()))))

    exit_code1, stdout1, _ = _run(forward)
    exit_code2, stdout2, _ = _run(reordered)

    assert exit_code1 == 0
    assert exit_code2 == 0
    assert json.loads(stdout1) == json.loads(stdout2)


# ---------------------------------------------------------------------------
# Typed core validation failures surfaced through the CLI
# ---------------------------------------------------------------------------


def test_023_invalid_target_type_exit_two():
    exit_code, stdout, stderr = _run(json.dumps(_envelope(target_type="approval_request")))
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Analyst feedback CLI validation failed:")
    _assert_no_forbidden_content(stderr)


def test_024_invalid_analyst_decision_exit_two():
    exit_code, stdout, stderr = _run(json.dumps(_envelope(analyst_decision="deny")))
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Analyst feedback CLI validation failed:")


def test_025_disagree_missing_error_category_exit_two():
    exit_code, stdout, stderr = _run(json.dumps(_envelope(
        analyst_decision="disagree", rationale="some rationale text",
    )))
    assert exit_code == 2
    assert stdout == ""


def test_026_disagree_missing_rationale_exit_two():
    exit_code, stdout, stderr = _run(json.dumps(_envelope(
        analyst_decision="disagree", error_category="false_positive",
    )))
    assert exit_code == 2
    assert stdout == ""


def test_027_invalid_corrected_value_for_target_type_exit_two():
    exit_code, stdout, stderr = _run(json.dumps(_envelope(
        target_type="investigation_decision", corrected_value="allow",
    )))
    assert exit_code == 2
    assert stdout == ""


def test_028_malformed_submitted_at_exit_two():
    exit_code, stdout, stderr = _run(json.dumps(_envelope(submitted_at="not-a-timestamp")))
    assert exit_code == 2
    assert stdout == ""
    _assert_no_forbidden_content(stderr)


# ---------------------------------------------------------------------------
# Unexpected internal failure
# ---------------------------------------------------------------------------


def test_029_unexpected_internal_failure_is_exit_one(monkeypatch):
    def _boom(**kwargs):
        raise RuntimeError("secret internal detail XYZ123")

    monkeypatch.setattr(analyst_feedback_cli, "create_analyst_feedback", _boom)
    exit_code, stdout, stderr = _run(json.dumps(_envelope()))

    assert exit_code == 1
    assert stdout == ""
    assert stderr.startswith("Analyst feedback CLI internal error:")
    assert "secret internal detail" not in stderr
    _assert_no_forbidden_content(stderr)


def test_030_no_traceback_leakage_across_error_paths():
    error_payloads = (
        "{not valid json",
        json.dumps([1, 2, 3]),
        json.dumps(_envelope(operation="bogus")),
        json.dumps(_envelope(target_type="not_real")),
        json.dumps(_envelope(submitted_at=None)),
    )
    for payload in error_payloads:
        _, stdout, stderr = _run(payload)
        assert stdout == ""
        _assert_no_forbidden_content(stderr)


# ---------------------------------------------------------------------------
# Structural purity
# ---------------------------------------------------------------------------


def test_031_cli_never_touches_filesystem_network_clock_mcp_database():
    full_source = inspect.getsource(analyst_feedback_cli)
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


def test_032_cli_never_imports_other_blocks_directly():
    full_source = inspect.getsource(analyst_feedback_cli)
    source = full_source.split("from __future__", 1)[1]
    forbidden_imports = (
        "core.agent_gateway",
        "core.agent_identity_policy",
        "core.decision_binding",
        "core.mutation_freeze",
        "core.ai_asset_registry",
    )
    for forbidden in forbidden_imports:
        assert forbidden not in source, f"forbidden import found: {forbidden!r}"
    assert "from core.analyst_feedback import" in source
