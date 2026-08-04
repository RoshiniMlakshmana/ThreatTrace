"""Tests for core.shadow_execution_cli -- the stdin/stdout JSON adapter
around core.shadow_execution.simulate_case_update.

main() is called directly with in-memory StringIO streams. No Supabase,
file, subprocess, network, AI-model, or other external access occurs
anywhere in this file; every input is a plain in-memory JSON object, and
every timestamp is a fixed literal -- never datetime.now(), utcnow(), or
time.time().
"""

import copy
import json
from io import StringIO

from core import shadow_execution_cli
from core.shadow_execution import WARNING_CODES

INVESTIGATION_ID = "11111111-1111-4111-8111-111111111111"
APPROVAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

REQUESTED_AT = "2026-08-01T10:00:00Z"
CREATED_AT = "2026-08-01T10:00:00Z"
APPROVED_AT = "2026-08-01T11:00:00Z"
CONSUMED_AT = "2026-08-01T12:00:00Z"

SIMULATED_AT = "2026-08-01T12:30:00Z"

_RESULT_FIELDS = {
    "simulation_version", "approval_id", "investigation_id", "action_type", "risk_level",
    "required_approvals", "eligible_for_execution", "current_state", "proposed_state",
    "changed_fields", "unchanged_fields", "warnings", "rollback", "simulated_at",
    "mutation_performed",
}

_FORBIDDEN_KEYS = frozenset({
    "requested_by", "requested_by_normalized", "approved_by", "rejected_by", "consumed_by",
    "reviewer_identity", "reviewer_identity_normalized", "action_payload", "sql", "query",
    "descriptor", "rpc", "credential", "credentials", "service_role", "token", "traceback",
})


def _approved_record(**overrides):
    record = {
        "id": APPROVAL_ID,
        "investigation_id": INVESTIGATION_ID,
        "action_type": "update_investigation_state",
        "action_payload": {"status": "escalated"},
        "requested_by": "analyst-jane",
        "requested_at": REQUESTED_AT,
        "status": "approved",
        "approved_by": "reviewer-one",
        "approved_at": APPROVED_AT,
        "rejected_by": None,
        "rejected_at": None,
        "rejection_reason": None,
        "expires_at": None,
        "consumed_by": None,
        "consumed_at": None,
        "created_at": CREATED_AT,
        "risk_level": "medium",
        "required_approvals": 1,
    }
    record.update(overrides)
    return record


def _pending_record(**overrides):
    record = _approved_record(status="pending", approved_by=None, approved_at=None)
    record.update(overrides)
    return record


def _consumed_record(**overrides):
    record = _approved_record(status="consumed", consumed_by="operator", consumed_at=CONSUMED_AT)
    record.update(overrides)
    return record


def _context(**overrides):
    context = {"investigation_id": INVESTIGATION_ID, "status": "investigating", "confidence": "low"}
    context.update(overrides)
    return context


def _envelope(**overrides):
    envelope = {
        "approval_record": _approved_record(),
        "investigation_context": _context(),
        "simulated_at": SIMULATED_AT,
    }
    envelope.update(overrides)
    return envelope


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = shadow_execution_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _assert_no_forbidden_keys(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            assert key not in _FORBIDDEN_KEYS, f"forbidden key present: {key}"
            _assert_no_forbidden_keys(nested)
    elif isinstance(value, list):
        for item in value:
            _assert_no_forbidden_keys(item)


# ---------------------------------------------------------------------------
# 1: eligible success
# ---------------------------------------------------------------------------


def test_001_eligible_success():
    exit_code, stdout, stderr = _run(json.dumps(_envelope()))

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert set(result) == _RESULT_FIELDS
    assert result["eligible_for_execution"] is True
    assert result["mutation_performed"] is False


# ---------------------------------------------------------------------------
# 2: exact delegation envelope
# ---------------------------------------------------------------------------


def test_002_exact_delegation_envelope(monkeypatch):
    captured = {}
    original = shadow_execution_cli.simulate_case_update

    def spy(**kwargs):
        captured.update(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(shadow_execution_cli, "simulate_case_update", spy)

    exit_code, stdout, stderr = _run(json.dumps(_envelope()))

    assert exit_code == 0
    assert stderr == ""
    assert set(captured) == {"approval_record", "investigation_context", "simulated_at"}
    assert captured["approval_record"] == _approved_record()
    assert captured["investigation_context"] == _context()
    assert captured["simulated_at"] == SIMULATED_AT

    # A derived/forbidden top-level field is rejected before simulation is
    # ever attempted -- the spy is never even called.
    captured.clear()
    forbidden_envelope = _envelope()
    forbidden_envelope["approval_id"] = APPROVAL_ID
    exit_code2, stdout2, stderr2 = _run(json.dumps(forbidden_envelope))

    assert exit_code2 == 2
    assert stdout2 == ""
    assert captured == {}


# ---------------------------------------------------------------------------
# 3: ineligible report remains successful
# ---------------------------------------------------------------------------


def test_003_ineligible_report_remains_successful():
    exit_code, stdout, stderr = _run(json.dumps(_envelope(approval_record=_pending_record())))

    assert exit_code == 0
    assert stderr == ""
    result = json.loads(stdout)
    assert result["eligible_for_execution"] is False
    assert "NOT_APPROVED" in [warning["code"] for warning in result["warnings"]]
    assert result["mutation_performed"] is False

    exit_code2, stdout2, stderr2 = _run(json.dumps(_envelope(approval_record=_consumed_record())))

    assert exit_code2 == 0
    assert stderr2 == ""
    result2 = json.loads(stdout2)
    assert result2["eligible_for_execution"] is False
    assert "ALREADY_CONSUMED" in [warning["code"] for warning in result2["warnings"]]
    assert result2["mutation_performed"] is False


# ---------------------------------------------------------------------------
# 4: combined change serialization
# ---------------------------------------------------------------------------


def test_004_combined_change_serialization():
    record = _approved_record(
        action_payload={"status": "closed", "confidence": "low"}, risk_level="high", required_approvals=2
    )
    context = _context(status="investigating", confidence="high")

    exit_code, stdout, stderr = _run(json.dumps(_envelope(approval_record=record, investigation_context=context)))

    assert exit_code == 0
    assert stderr == ""
    assert stdout.endswith("\n")
    assert stdout.count("\n") == 1

    result = json.loads(stdout)
    assert result["changed_fields"] == [
        {"field": "status", "before": "investigating", "after": "closed"},
        {"field": "confidence", "before": "high", "after": "low"},
    ]

    codes = [warning["code"] for warning in result["warnings"]]
    assert codes == [code for code in WARNING_CODES if code in codes]

    reserialized = json.dumps(result, sort_keys=True, ensure_ascii=False) + "\n"
    assert reserialized == stdout


# ---------------------------------------------------------------------------
# 5: malformed JSON and non-object input
# ---------------------------------------------------------------------------


def test_005_malformed_json_and_non_object_input():
    exit_code, stdout, stderr = _run("{not valid json")

    assert exit_code == 2
    assert stdout == ""
    assert stderr != ""
    assert "Traceback" not in stderr
    assert "JSONDecodeError" not in stderr

    exit_code2, stdout2, stderr2 = _run(json.dumps([1, 2, 3]))

    assert exit_code2 == 2
    assert stdout2 == ""
    assert "JSON object" in stderr2
    assert "Traceback" not in stderr2


# ---------------------------------------------------------------------------
# 6: missing and extra envelope fields
# ---------------------------------------------------------------------------


def test_006_missing_and_extra_envelope_fields():
    envelope_missing = _envelope()
    del envelope_missing["simulated_at"]
    exit_code, stdout, stderr = _run(json.dumps(envelope_missing))

    assert exit_code == 2
    assert stdout == ""
    assert "Traceback" not in stderr

    envelope_extra = _envelope()
    envelope_extra["extra_field"] = "unexpected"
    exit_code2, stdout2, stderr2 = _run(json.dumps(envelope_extra))

    assert exit_code2 == 2
    assert stdout2 == ""
    assert "Traceback" not in stderr2

    envelope_forbidden = _envelope()
    envelope_forbidden["eligible_for_execution"] = True
    exit_code3, stdout3, stderr3 = _run(json.dumps(envelope_forbidden))

    assert exit_code3 == 2
    assert stdout3 == ""
    assert "Traceback" not in stderr3


# ---------------------------------------------------------------------------
# 7: structural simulation validation failure
# ---------------------------------------------------------------------------


def test_007_structural_simulation_validation_failure():
    malformed_record = _approved_record()
    del malformed_record["risk_level"]
    exit_code, stdout, stderr = _run(json.dumps(_envelope(approval_record=malformed_record)))

    assert exit_code == 2
    assert stdout == ""
    assert "Shadow execution validation failed:" in stderr
    assert "Traceback" not in stderr
    assert "ShadowExecutionError" not in stderr

    exit_code2, stdout2, stderr2 = _run(
        json.dumps(_envelope(investigation_context=_context(status="not_a_real_status")))
    )

    assert exit_code2 == 2
    assert stdout2 == ""
    assert "Shadow execution validation failed:" in stderr2
    assert "Traceback" not in stderr2

    exit_code3, stdout3, stderr3 = _run(json.dumps(_envelope(simulated_at="2026-08-01T12:00:00")))

    assert exit_code3 == 2
    assert stdout3 == ""
    assert "Shadow execution validation failed:" in stderr3
    assert "Traceback" not in stderr3


# ---------------------------------------------------------------------------
# 8: deterministic output and nonmutation
# ---------------------------------------------------------------------------


def test_008_deterministic_output_and_nonmutation():
    record = _approved_record(
        action_payload={"status": "closed", "confidence": "low"}, risk_level="high", required_approvals=2
    )
    context = _context(status="investigating", confidence="high")
    raw_input = json.dumps(_envelope(approval_record=record, investigation_context=context))

    record_snapshot = copy.deepcopy(record)
    context_snapshot = copy.deepcopy(context)

    exit_code1, stdout1, _stderr1 = _run(raw_input)
    exit_code2, stdout2, _stderr2 = _run(raw_input)

    assert exit_code1 == 0
    assert exit_code2 == 0
    assert stdout1 == stdout2

    result = json.loads(stdout1)
    reserialized = json.dumps(result, sort_keys=True, ensure_ascii=False) + "\n"
    assert reserialized == stdout1

    assert record == record_snapshot
    assert context == context_snapshot

    _assert_no_forbidden_keys(result)
