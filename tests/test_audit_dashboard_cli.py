"""Tests for core.audit_dashboard_cli -- the stdin/stdout JSON adapter
around core.tamper_evident_audit's create_audit_record/verify_audit_chain
and core.evaluation_dashboard's summarize_audit_dashboard (Block 14).

main() is called directly with in-memory StringIO streams. No Supabase,
MCP, file, subprocess, network, Hayabusa, or AI/model access occurs
anywhere in this file; every input is a plain in-memory JSON object, and
every timestamp is a fixed literal -- never datetime.now(), utcnow(), or
time.time(). No tool is ever executed.

This file does not re-verify every core validation case (see
tests/test_tamper_evident_audit.py and tests/test_evaluation_dashboard.py
for the 102 core tests) -- it tests only the CLI's own adapter boundary:
envelope dispatch, pass-through, exit codes, and output/error shape.
"""

import inspect
import json
from io import StringIO

from core import audit_dashboard_cli
from core.tamper_evident_audit import create_audit_record as _core_create_audit_record

OCCURRED_AT = "2026-01-01T00:00:00Z"
OCCURRED_AT_2 = "2026-01-01T00:05:00Z"

_CREATE_RESULT_FIELDS = {
    "audit_version", "sequence", "event_type", "event_reference", "event_summary",
    "occurred_at", "previous_record_digest", "audit_persisted", "execution_performed",
    "record_digest",
}
_VERIFY_RESULT_FIELDS = {
    "verification_version", "verification_outcome", "internal_chain_valid",
    "trusted_anchor_verified", "record_count", "head_digest", "observed_evidence",
    "execution_performed",
}
_DASHBOARD_RESULT_FIELDS = {
    "dashboard_version", "audit", "event_type_counts", "evaluation_counts",
    "feedback_counts", "policy_counts", "execution_performed",
}


def _create_envelope(**overrides):
    envelope = {
        "operation": "create",
        "sequence": 1,
        "event_type": "security_evaluation_result",
        "event_reference": "evaluate:emergency_freeze_bypass:identity_agent:coordinator_agent",
        "event_summary": {"outcome": "pass", "case_type": "emergency_freeze_bypass"},
        "occurred_at": OCCURRED_AT,
        "previous_record_digest": None,
    }
    envelope.update(overrides)
    return envelope


def _verify_envelope(records=None, **overrides):
    envelope = {
        "operation": "verify",
        "records": records if records is not None else [],
        "expected_head_digest": None,
    }
    envelope.update(overrides)
    return envelope


def _dashboard_envelope(records=None, **overrides):
    envelope = {
        "operation": "dashboard",
        "records": records if records is not None else [],
        "expected_head_digest": None,
    }
    envelope.update(overrides)
    return envelope


def _real_record(sequence, event_type="analyst_feedback", event_summary=None, previous_record_digest=None):
    return _core_create_audit_record(
        sequence=sequence, event_type=event_type, event_reference="ref",
        event_summary=event_summary, occurred_at=OCCURRED_AT, previous_record_digest=previous_record_digest,
    )


def _real_chain(length):
    records = [_real_record(1)]
    for i in range(2, length + 1):
        records.append(_real_record(i, previous_record_digest=records[-1]["record_digest"]))
    return records


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = audit_dashboard_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _assert_no_forbidden_content(rendered):
    forbidden = ("Traceback", "AuditRecordError", "EvaluationDashboardError", "ValueError", "RuntimeError", "KeyError")
    for text in forbidden:
        assert text not in rendered


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


def test_001_create_genesis_record():
    exit_code, stdout, stderr = _run(json.dumps(_create_envelope()))
    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert set(result) == _CREATE_RESULT_FIELDS
    assert result["sequence"] == 1
    assert result["previous_record_digest"] is None


def test_002_create_chained_record():
    genesis_exit, genesis_stdout, _ = _run(json.dumps(_create_envelope()))
    assert genesis_exit == 0
    genesis = json.loads(genesis_stdout)

    exit_code, stdout, _ = _run(json.dumps(_create_envelope(
        sequence=2, event_type="analyst_feedback", event_reference="investigation-123",
        event_summary={"outcome": "agree"}, occurred_at=OCCURRED_AT_2,
        previous_record_digest=genesis["record_digest"],
    )))
    assert exit_code == 0
    result = json.loads(stdout)
    assert result["sequence"] == 2
    assert result["previous_record_digest"] == genesis["record_digest"]


def test_003_create_event_summary_null():
    exit_code, stdout, _ = _run(json.dumps(_create_envelope(event_summary=None)))
    assert exit_code == 0
    assert json.loads(stdout)["event_summary"] is None


def test_004_create_event_summary_populated():
    exit_code, stdout, _ = _run(json.dumps(_create_envelope(
        event_summary={"outcome": "disagree", "error_category": "false_positive"},
    )))
    assert exit_code == 0
    assert json.loads(stdout)["event_summary"] == {"outcome": "disagree", "error_category": "false_positive"}


def test_005_create_every_representative_event_family():
    event_types = (
        "investigation_decision", "approval_decision", "shadow_execution_result",
        "security_policy_decision", "decision_binding_result", "security_evaluation_result",
        "analyst_feedback",
    )
    for event_type in event_types:
        exit_code, stdout, _ = _run(json.dumps(_create_envelope(event_type=event_type, event_summary=None)))
        assert exit_code == 0, f"event_type={event_type}"
        assert json.loads(stdout)["event_type"] == event_type


def test_006_create_key_order_independence():
    envelope = _create_envelope()
    forward = json.dumps(envelope)
    reordered = json.dumps(dict(reversed(list(envelope.items()))))

    exit_code1, stdout1, _ = _run(forward)
    exit_code2, stdout2, _ = _run(reordered)

    assert exit_code1 == 0
    assert exit_code2 == 0
    assert json.loads(stdout1) == json.loads(stdout2)


def test_007_create_output_digest_preserved():
    exit_code, stdout, _ = _run(json.dumps(_create_envelope()))
    result = json.loads(stdout)
    assert result["record_digest"].startswith("sha256:")
    assert len(result["record_digest"]) == len("sha256:") + 64


def test_008_create_audit_persisted_false():
    _, stdout, _ = _run(json.dumps(_create_envelope()))
    assert json.loads(stdout)["audit_persisted"] is False


def test_009_create_execution_performed_false():
    _, stdout, _ = _run(json.dumps(_create_envelope()))
    assert json.loads(stdout)["execution_performed"] is False


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def test_010_verify_empty_list():
    exit_code, stdout, stderr = _run(json.dumps(_verify_envelope(records=[])))
    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert set(result) == _VERIFY_RESULT_FIELDS
    assert result["verification_outcome"] == "valid"
    assert result["record_count"] == 0


def test_011_verify_valid_genesis():
    records = _real_chain(1)
    exit_code, stdout, _ = _run(json.dumps(_verify_envelope(records=records)))
    assert exit_code == 0
    assert json.loads(stdout)["verification_outcome"] == "valid"


def test_012_verify_valid_multi_record_chain():
    records = _real_chain(3)
    exit_code, stdout, _ = _run(json.dumps(_verify_envelope(records=records)))
    assert exit_code == 0
    result = json.loads(stdout)
    assert result["verification_outcome"] == "valid"
    assert result["record_count"] == 3


def test_013_verify_invalid_digest_chain_exit_zero():
    records = _real_chain(2)
    tampered = dict(records[1])
    tampered["event_reference"] = "tampered"
    exit_code, stdout, stderr = _run(json.dumps(_verify_envelope(records=[records[0], tampered])))
    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert result["verification_outcome"] == "invalid"
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "DIGEST_MISMATCH" in codes


def test_014_verify_broken_previous_link_exit_zero():
    records = _real_chain(2)
    tampered = dict(records[1])
    tampered["previous_record_digest"] = "sha256:" + "b" * 64
    from core.tamper_evident_audit import _recompute_record_digest
    tampered["record_digest"] = _recompute_record_digest({
        "sequence": tampered["sequence"], "event_type": tampered["event_type"],
        "event_reference": tampered["event_reference"], "event_summary": tampered["event_summary"],
        "occurred_at": tampered["occurred_at"], "previous_record_digest": tampered["previous_record_digest"],
        "audit_persisted": False, "execution_performed": False,
    })
    exit_code, stdout, _ = _run(json.dumps(_verify_envelope(records=[records[0], tampered])))
    assert exit_code == 0
    result = json.loads(stdout)
    assert result["verification_outcome"] == "invalid"
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "PREVIOUS_DIGEST_MISMATCH" in codes


def test_015_verify_sequence_mismatch_exit_zero():
    records = _real_chain(2)
    tampered = dict(records[1])
    tampered["sequence"] = 9
    from core.tamper_evident_audit import _recompute_record_digest
    tampered["record_digest"] = _recompute_record_digest({
        "sequence": 9, "event_type": tampered["event_type"], "event_reference": tampered["event_reference"],
        "event_summary": tampered["event_summary"], "occurred_at": tampered["occurred_at"],
        "previous_record_digest": tampered["previous_record_digest"], "audit_persisted": False,
        "execution_performed": False,
    })
    exit_code, stdout, _ = _run(json.dumps(_verify_envelope(records=[records[0], tampered])))
    assert exit_code == 0
    result = json.loads(stdout)
    assert result["verification_outcome"] == "invalid"
    codes = [rule["code"] for rule in result["observed_evidence"]]
    assert "SEQUENCE_MISMATCH" in codes


def test_016_verify_no_anchor():
    records = _real_chain(1)
    exit_code, stdout, _ = _run(json.dumps(_verify_envelope(records=records)))
    assert exit_code == 0
    assert json.loads(stdout)["trusted_anchor_verified"] is None


def test_017_verify_matching_anchor():
    records = _real_chain(1)
    exit_code, stdout, _ = _run(json.dumps(_verify_envelope(
        records=records, expected_head_digest=records[-1]["record_digest"],
    )))
    assert exit_code == 0
    result = json.loads(stdout)
    assert result["trusted_anchor_verified"] is True
    assert result["verification_outcome"] == "valid"


def test_018_verify_mismatching_anchor():
    records = _real_chain(1)
    exit_code, stdout, _ = _run(json.dumps(_verify_envelope(
        records=records, expected_head_digest="sha256:" + "c" * 64,
    )))
    assert exit_code == 0
    result = json.loads(stdout)
    assert result["trusted_anchor_verified"] is False
    assert result["verification_outcome"] == "invalid"


def test_019_verify_execution_performed_false():
    _, stdout, _ = _run(json.dumps(_verify_envelope(records=[])))
    assert json.loads(stdout)["execution_performed"] is False


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------


def test_020_dashboard_empty():
    exit_code, stdout, stderr = _run(json.dumps(_dashboard_envelope(records=[])))
    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert set(result) == _DASHBOARD_RESULT_FIELDS
    assert result["audit"]["total_records"] == 0


def test_021_dashboard_valid_chain():
    records = _real_chain(2)
    exit_code, stdout, _ = _run(json.dumps(_dashboard_envelope(records=records)))
    assert exit_code == 0
    result = json.loads(stdout)
    assert result["audit"]["verification_outcome"] == "valid"


def test_022_dashboard_evaluation_counts():
    records = [_real_record(1, event_type="security_evaluation_result", event_summary={"outcome": "pass"})]
    exit_code, stdout, _ = _run(json.dumps(_dashboard_envelope(records=records)))
    assert exit_code == 0
    result = json.loads(stdout)
    assert result["evaluation_counts"]["outcome_counts"]["pass"] == 1


def test_023_dashboard_feedback_counts():
    records = [_real_record(1, event_type="analyst_feedback", event_summary={"outcome": "disagree", "error_category": "false_positive"})]
    exit_code, stdout, _ = _run(json.dumps(_dashboard_envelope(records=records)))
    assert exit_code == 0
    result = json.loads(stdout)
    assert result["feedback_counts"]["decision_counts"]["disagree"] == 1
    assert result["feedback_counts"]["error_category_counts"]["false_positive"] == 1


def test_024_dashboard_policy_counts():
    records = [_real_record(1, event_type="security_policy_decision", event_summary={"outcome": "deny"})]
    exit_code, stdout, _ = _run(json.dumps(_dashboard_envelope(records=records)))
    assert exit_code == 0
    result = json.loads(stdout)
    assert result["policy_counts"]["decision_counts"]["deny"] == 1


def test_025_dashboard_invalid_chain_surfaced():
    records = _real_chain(2)
    tampered = dict(records[1])
    tampered["event_reference"] = "tampered"
    exit_code, stdout, stderr = _run(json.dumps(_dashboard_envelope(records=[records[0], tampered])))
    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert result["audit"]["verification_outcome"] == "invalid"
    assert result["audit"]["internal_chain_valid"] is False


def test_026_dashboard_matching_anchor():
    records = _real_chain(1)
    exit_code, stdout, _ = _run(json.dumps(_dashboard_envelope(
        records=records, expected_head_digest=records[-1]["record_digest"],
    )))
    assert exit_code == 0
    assert json.loads(stdout)["audit"]["trusted_anchor_verified"] is True


def test_027_dashboard_mismatching_anchor():
    records = _real_chain(1)
    exit_code, stdout, _ = _run(json.dumps(_dashboard_envelope(
        records=records, expected_head_digest="sha256:" + "d" * 64,
    )))
    assert exit_code == 0
    assert json.loads(stdout)["audit"]["trusted_anchor_verified"] is False


def test_028_dashboard_all_seven_event_counters_preserved():
    exit_code, stdout, _ = _run(json.dumps(_dashboard_envelope(records=[])))
    assert exit_code == 0
    counts = json.loads(stdout)["event_type_counts"]
    assert set(counts) == {
        "investigation_decision", "approval_decision", "shadow_execution_result",
        "security_policy_decision", "decision_binding_result", "security_evaluation_result",
        "analyst_feedback",
    }


def test_029_dashboard_execution_performed_false():
    _, stdout, _ = _run(json.dumps(_dashboard_envelope(records=[])))
    assert json.loads(stdout)["execution_performed"] is False


# ---------------------------------------------------------------------------
# Envelope failures
# ---------------------------------------------------------------------------


def test_030_malformed_json():
    exit_code, stdout, stderr = _run("{not valid json")
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Audit dashboard CLI validation failed:")
    _assert_no_forbidden_content(stderr)


def test_031_top_level_list_string_null_rejected():
    for bad_payload in (json.dumps([1, 2, 3]), json.dumps("just a string"), json.dumps(None)):
        exit_code, stdout, stderr = _run(bad_payload)
        assert exit_code == 2
        assert stdout == ""


def test_032_missing_operation_rejected():
    envelope = _create_envelope()
    del envelope["operation"]
    exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert stdout == ""


def test_033_unknown_operation_rejected():
    exit_code, stdout, stderr = _run(json.dumps(_create_envelope(operation="delete")))
    assert exit_code == 2
    assert stdout == ""
    assert "operation" in stderr


def test_034_create_missing_key_rejected():
    for field in ("sequence", "event_type", "event_reference", "event_summary", "occurred_at", "previous_record_digest"):
        envelope = _create_envelope()
        del envelope[field]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2, f"field={field}"
        assert field in stderr


def test_035_create_extra_key_rejected():
    envelope = _create_envelope()
    envelope["unexpected_field"] = "nope"
    exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert "unexpected_field" in stderr


def test_036_verify_missing_key_rejected():
    for field in ("records", "expected_head_digest"):
        envelope = _verify_envelope()
        del envelope[field]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2, f"field={field}"
        assert field in stderr


def test_037_verify_extra_key_rejected():
    envelope = _verify_envelope()
    envelope["unexpected_field"] = "nope"
    exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert "unexpected_field" in stderr


def test_038_dashboard_missing_key_rejected():
    for field in ("records", "expected_head_digest"):
        envelope = _dashboard_envelope()
        del envelope[field]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2, f"field={field}"
        assert field in stderr


def test_039_dashboard_extra_key_rejected():
    envelope = _dashboard_envelope()
    envelope["unexpected_field"] = "nope"
    exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert "unexpected_field" in stderr


# ---------------------------------------------------------------------------
# Core validation errors surfaced through the CLI
# ---------------------------------------------------------------------------


def test_040_invalid_event_type_exit_two():
    exit_code, stdout, stderr = _run(json.dumps(_create_envelope(event_type="not_a_real_type")))
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Audit dashboard CLI validation failed:")
    _assert_no_forbidden_content(stderr)


def test_041_malformed_digest_exit_two():
    exit_code, stdout, stderr = _run(json.dumps(_create_envelope(
        sequence=2, previous_record_digest="not-a-digest",
    )))
    assert exit_code == 2
    assert stdout == ""


def test_042_malformed_records_top_level_exit_two():
    exit_code, stdout, stderr = _run(json.dumps(_verify_envelope(records="not-a-list")))
    assert exit_code == 2
    assert stdout == ""
    _assert_no_forbidden_content(stderr)


def test_043_invalid_dashboard_aggregation_vocabulary_exit_two():
    records = [_real_record(1, event_type="security_evaluation_result", event_summary={"outcome": "deny"})]
    exit_code, stdout, stderr = _run(json.dumps(_dashboard_envelope(records=records)))
    assert exit_code == 2
    assert stdout == ""
    _assert_no_forbidden_content(stderr)


# ---------------------------------------------------------------------------
# Unexpected internal failure
# ---------------------------------------------------------------------------


def test_044_unexpected_internal_failure_is_exit_one(monkeypatch):
    def _boom(**kwargs):
        raise RuntimeError("secret internal detail XYZ123")

    monkeypatch.setattr(audit_dashboard_cli, "create_audit_record", _boom)
    exit_code, stdout, stderr = _run(json.dumps(_create_envelope()))

    assert exit_code == 1
    assert stdout == ""
    assert stderr.startswith("Audit dashboard CLI internal error:")
    assert "secret internal detail" not in stderr
    _assert_no_forbidden_content(stderr)


def test_045_no_traceback_leakage_across_error_paths():
    error_payloads = (
        "{not valid json",
        json.dumps([1, 2, 3]),
        json.dumps(_create_envelope(operation="bogus")),
        json.dumps(_create_envelope(event_type="not_real")),
        json.dumps(_verify_envelope(records="not-a-list")),
    )
    for payload in error_payloads:
        _, stdout, stderr = _run(payload)
        assert stdout == ""
        _assert_no_forbidden_content(stderr)


# ---------------------------------------------------------------------------
# Structural purity
# ---------------------------------------------------------------------------


def test_046_cli_never_touches_filesystem_network_clock_mcp_database():
    full_source = inspect.getsource(audit_dashboard_cli)
    source = full_source.split("from __future__", 1)[1]
    forbidden_substrings = (
        "datetime.now", "utcnow", "time.time", "os.environ", "os.getenv",
        "open(", "Path(", "subprocess", "socket", "requests", "urllib", "mcp__", "random.",
    )
    for forbidden in forbidden_substrings:
        assert forbidden not in source, f"forbidden substring found: {forbidden!r}"


def test_047_cli_never_imports_other_blocks_or_reimplements_logic():
    full_source = inspect.getsource(audit_dashboard_cli)
    source = full_source.split("from __future__", 1)[1]
    forbidden_modules = (
        "core.agent_gateway", "core.agent_identity_policy", "core.decision_binding",
        "core.mutation_freeze", "core.ai_asset_registry", "core.analyst_feedback",
    )
    for forbidden in forbidden_modules:
        assert f"import {forbidden}" not in source
        assert f"from {forbidden}" not in source

    forbidden_reimplementation_markers = (
        "hashlib.sha256", "GENESIS_LINK_INVALID", "DIGEST_MISMATCH",
    )
    for marker in forbidden_reimplementation_markers:
        assert marker not in source, f"forbidden reimplementation marker found: {marker!r}"

    assert "from core.tamper_evident_audit import" in source
    assert "from core.evaluation_dashboard import" in source
