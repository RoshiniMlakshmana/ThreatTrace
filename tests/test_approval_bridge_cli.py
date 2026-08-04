"""Tests for core.approval_bridge_cli -- the stdin/stdout JSON adapter
around core.approval_bridge's two-phase prepare/verify approval bridge.

main() is called directly with in-memory StringIO streams, exactly
matching the established convention already used by
tests/test_approval_transition_cli.py and
tests/test_approval_request_cli.py. No Supabase, file, subprocess,
network, AI-model, or other external access occurs anywhere in this file;
every input is a plain in-memory JSON object.
"""

import ast
import json
import socket
import subprocess
from io import StringIO
from pathlib import Path

import pytest

from core import approval_bridge_cli
from core import approval_transition_cli
import core.approval_transition as approval_transition

APPROVAL_ID = "51111111-1111-4111-8111-111111111111"
INVESTIGATION_ID = "41111111-1111-4111-8111-111111111111"

REQUESTED_AT = "2026-08-01T15:45:00Z"
EXPIRES_AT = "2026-08-02T15:45:00Z"
CREATED_AT = "2026-08-01T15:46:00Z"
APPROVED_AT = "2026-08-01T16:00:00Z"
CONSUMED_AT = "2026-08-01T17:00:00Z"


def _validated_request(**overrides):
    request = {
        "investigation_id": INVESTIGATION_ID,
        "action_type": "update_investigation_state",
        "action_payload": {"status": "escalated", "confidence": "high"},
        "requested_by": "Roshini Analyst",
        "requested_at": REQUESTED_AT,
    }
    request.update(overrides)
    return request


def _pending_row(**overrides):
    row = {
        "id": APPROVAL_ID,
        "investigation_id": INVESTIGATION_ID,
        "action_type": "update_investigation_state",
        "action_payload": {"status": "escalated", "confidence": "high"},
        "requested_by": "Roshini Analyst",
        "requested_at": REQUESTED_AT,
        "status": "pending",
        "approved_by": None,
        "approved_at": None,
        "rejected_by": None,
        "rejected_at": None,
        "rejection_reason": None,
        "expires_at": EXPIRES_AT,
        "consumed_by": None,
        "consumed_at": None,
        "created_at": CREATED_AT,
    }
    row.update(overrides)
    return row


def _approved_record(**overrides):
    record = _pending_row(status="approved", approved_by="Security Reviewer", approved_at=APPROVED_AT)
    record.update(overrides)
    return record


# Fixed, deterministic default reviewed_at -- strictly after REQUESTED_AT
# and strictly before EXPIRES_AT for the shared _pending_row() window, so
# _genuine_approve_plan never falls through to validate_approval_
# transition's own wall-clock (datetime.now(timezone.utc)) generation
# path. Matches the same logical timestamp used for this purpose in
# tests/test_approval_persistence.py and tests/test_approval_bridge.py.
REVIEWED_AT = "2026-08-01T16:00:00Z"


def _genuine_approve_plan(record, reviewed_by="Security Reviewer", reviewed_at=REVIEWED_AT):
    return approval_transition.validate_approval_transition(
        record, {"transition": "approve", "reviewed_by": reviewed_by, "reviewed_at": reviewed_at}
    )


def _genuine_consume_plan(record, consumed_by="Update Case Operator", consumed_at=CONSUMED_AT):
    return approval_transition.validate_approval_transition(
        record,
        {
            "transition": "consume",
            "consumed_by": consumed_by,
            "expected_investigation_id": record["investigation_id"],
            "expected_action_type": "update_investigation_state",
            "consumed_at": consumed_at,
        },
    )


def _apply_set_fields(record, set_fields):
    updated = dict(record)
    updated.update(set_fields)
    return updated


def _consumption_row_for(record, plan):
    row = _apply_set_fields(record, plan["set_fields"])
    payload = record["action_payload"]
    row["investigation_status"] = payload.get("status", "escalated")
    row["investigation_confidence"] = payload.get("confidence", "high")
    row["investigation_updated_at"] = CONSUMED_AT
    return row


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = approval_bridge_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _prepare_envelope(operation, operation_input):
    return {"phase": "prepare", "operation": operation, "input": operation_input}


def _verify_envelope(operation, operation_input, prepared_descriptor, executor_response):
    return {
        "phase": "verify",
        "operation": operation,
        "input": operation_input,
        "prepared_descriptor": prepared_descriptor,
        "executor_response": executor_response,
    }


def _module_source_text():
    with open(approval_bridge_cli.__file__, "r", encoding="utf-8") as handle:
        return handle.read()


def _this_module_ast():
    return ast.parse(Path(__file__).read_text(encoding="utf-8"))


def _top_level_imports(tree):
    names = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
    return names


# ---------------------------------------------------------------------------
# 1-10: basic contract and success behavior
# ---------------------------------------------------------------------------


def test_001_module_imports():
    assert approval_bridge_cli is not None


def test_002_main_exists():
    assert callable(approval_bridge_cli.main)


def test_003_prepare_works_for_all_four_operations():
    exit_code, stdout, _stderr = _run(
        json.dumps(_prepare_envelope("insert_pending_approval", {"validated_request": _validated_request(), "expires_at": None}))
    )
    assert exit_code == 0
    assert json.loads(stdout)["descriptor"]["operation"] == "insert"

    exit_code, stdout, _stderr = _run(
        json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID}))
    )
    assert exit_code == 0
    assert json.loads(stdout)["descriptor"]["operation"] == "select"

    pending = _pending_row()
    plan = _genuine_approve_plan(pending)
    exit_code, stdout, _stderr = _run(
        json.dumps(_prepare_envelope("apply_approval_review_transition", {"current_record": pending, "transition_plan": plan}))
    )
    assert exit_code == 0
    assert json.loads(stdout)["descriptor"]["operation"] == "update"

    approved = _approved_record()
    consume_plan = _genuine_consume_plan(approved)
    exit_code, stdout, _stderr = _run(
        json.dumps(_prepare_envelope("apply_approval_consumption", {"current_record": approved, "transition_plan": consume_plan}))
    )
    assert exit_code == 0
    assert json.loads(stdout)["descriptor"]["operation"] == "rpc"


def test_004_verify_works_for_all_four_operations():
    validated_request = _validated_request()
    exit_code, stdout, _stderr = _run(json.dumps(_prepare_envelope("insert_pending_approval", {"validated_request": validated_request, "expires_at": None})))
    descriptor = json.loads(stdout)["descriptor"]
    exit_code, stdout, _stderr = _run(
        json.dumps(_verify_envelope("insert_pending_approval", {"validated_request": validated_request, "expires_at": None}, descriptor, {"kind": "rows", "rows": [_pending_row(expires_at=None)]}))
    )
    assert exit_code == 0
    assert json.loads(stdout)["result"]["status"] == "pending"

    exit_code, stdout, _stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    descriptor = json.loads(stdout)["descriptor"]
    exit_code, stdout, _stderr = _run(
        json.dumps(_verify_envelope("load_approval_record", {"approval_id": APPROVAL_ID}, descriptor, {"kind": "rows", "rows": [_pending_row()]}))
    )
    assert exit_code == 0
    assert json.loads(stdout)["result"]["id"] == APPROVAL_ID

    pending = _pending_row()
    plan = _genuine_approve_plan(pending)
    review_input = {"current_record": pending, "transition_plan": plan}
    exit_code, stdout, _stderr = _run(json.dumps(_prepare_envelope("apply_approval_review_transition", review_input)))
    descriptor = json.loads(stdout)["descriptor"]
    row = _apply_set_fields(pending, plan["set_fields"])
    exit_code, stdout, _stderr = _run(
        json.dumps(_verify_envelope("apply_approval_review_transition", review_input, descriptor, {"kind": "rows", "rows": [row]}))
    )
    assert exit_code == 0
    assert json.loads(stdout)["result"]["updated_record"]["status"] == "approved"

    approved = _approved_record()
    consume_plan = _genuine_consume_plan(approved)
    consume_input = {"current_record": approved, "transition_plan": consume_plan}
    exit_code, stdout, _stderr = _run(json.dumps(_prepare_envelope("apply_approval_consumption", consume_input)))
    descriptor = json.loads(stdout)["descriptor"]
    consume_row = _consumption_row_for(approved, consume_plan)
    exit_code, stdout, _stderr = _run(
        json.dumps(_verify_envelope("apply_approval_consumption", consume_input, descriptor, {"kind": "rows", "rows": [consume_row]}))
    )
    assert exit_code == 0
    assert json.loads(stdout)["result"]["updated_record"]["status"] == "consumed"


def test_005_success_exits_zero():
    exit_code, _stdout, _stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    assert exit_code == 0


def test_006_success_output_is_one_json_object():
    _exit_code, stdout, _stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    decoder = json.JSONDecoder()
    parsed, end_index = decoder.raw_decode(stdout)
    assert isinstance(parsed, dict)
    assert stdout[end_index:].strip() == ""


def test_007_success_goes_only_to_stdout():
    _exit_code, stdout, stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    assert stdout != ""
    assert stderr == ""


def test_008_stderr_empty_on_success():
    _exit_code, _stdout, stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    assert stderr == ""


def test_009_json_serialization_is_deterministic():
    _exit_code, stdout_a, _stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    _exit_code, stdout_b, _stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    assert stdout_a == stdout_b
    parsed = json.loads(stdout_a)
    assert list(parsed.keys()) == sorted(parsed.keys())


def test_010_unicode_is_preserved():
    validated_request = _validated_request(requested_by="analyst-café-注意")
    _exit_code, stdout, _stderr = _run(
        json.dumps(_prepare_envelope("insert_pending_approval", {"validated_request": validated_request, "expires_at": None}), ensure_ascii=False)
    )
    assert "café" in stdout
    assert "\\u" not in stdout


# ---------------------------------------------------------------------------
# 11-21: malformed input and envelope rejection
# ---------------------------------------------------------------------------


def test_011_malformed_json_exits_2():
    exit_code, stdout, _stderr = _run("not json")
    assert exit_code == 2
    assert stdout == ""


def test_012_non_object_json_exits_2():
    exit_code, stdout, _stderr = _run(json.dumps(["not", "an", "object"]))
    assert exit_code == 2
    assert stdout == ""


def test_013_multiple_json_values_fail():
    exit_code, stdout, _stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})) + " {}")
    assert exit_code == 2
    assert stdout == ""


def test_014_trailing_garbage_fails():
    exit_code, stdout, _stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})) + " garbage")
    assert exit_code == 2
    assert stdout == ""


def test_015_unknown_phase_fails():
    exit_code, stdout, _stderr = _run(json.dumps({"phase": "bogus", "operation": "load_approval_record", "input": {}}))
    assert exit_code == 2
    assert stdout == ""


def test_016_unknown_operation_fails():
    exit_code, stdout, _stderr = _run(json.dumps(_prepare_envelope("bogus_operation", {})))
    assert exit_code == 2
    assert stdout == ""


def test_017_missing_envelope_key_fails():
    envelope = _prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})
    del envelope["input"]
    exit_code, stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert stdout == ""


def test_018_unknown_envelope_key_fails():
    envelope = _prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})
    envelope["extra"] = "value"
    exit_code, stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    assert stdout == ""


def test_019_reordered_envelope_keys_fail():
    envelope = {"operation": "load_approval_record", "phase": "prepare", "input": {"approval_id": APPROVAL_ID}}
    exit_code, stdout, _stderr = _run(json.dumps(envelope, sort_keys=False))
    assert exit_code == 2
    assert stdout == ""


def test_020_invalid_operation_input_fails():
    exit_code, stdout, _stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": "not-a-uuid"})))
    assert exit_code == 2
    assert stdout == ""


def test_021_descriptor_mismatch_fails():
    _exit_code, stdout, _stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    descriptor = json.loads(stdout)["descriptor"]
    tampered = dict(descriptor)
    tampered["limit"] = 999
    exit_code, stdout, stderr = _run(
        json.dumps(_verify_envelope("load_approval_record", {"approval_id": APPROVAL_ID}, tampered, {"kind": "rows", "rows": [_pending_row()]}))
    )
    assert exit_code == 2
    assert stdout == ""
    error = json.loads(stderr)
    assert error["error"]["code"] == "approval_bridge_error"


# ---------------------------------------------------------------------------
# 22-30: error codes and exit behavior
# ---------------------------------------------------------------------------


def test_022_approval_not_found_error_code():
    exit_code, stdout, _stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    descriptor = json.loads(stdout)["descriptor"]
    exit_code, stdout, stderr = _run(
        json.dumps(_verify_envelope("load_approval_record", {"approval_id": APPROVAL_ID}, descriptor, {"kind": "rows", "rows": []}))
    )
    assert exit_code == 2
    assert stdout == ""
    error = json.loads(stderr)
    assert error["error"]["code"] == "approval_not_found"


def test_023_approval_conflict_error_code():
    approved = _approved_record()
    consume_plan = _genuine_consume_plan(approved)
    consume_input = {"current_record": approved, "transition_plan": consume_plan}
    _exit_code, stdout, _stderr = _run(json.dumps(_prepare_envelope("apply_approval_consumption", consume_input)))
    descriptor = json.loads(stdout)["descriptor"]
    exit_code, stdout, stderr = _run(
        json.dumps(_verify_envelope("apply_approval_consumption", consume_input, descriptor, {"kind": "rows", "rows": []}))
    )
    assert exit_code == 2
    assert stdout == ""
    error = json.loads(stderr)
    assert error["error"]["code"] == "approval_conflict"


def test_024_approval_response_error_code():
    _exit_code, stdout, _stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    descriptor = json.loads(stdout)["descriptor"]
    malformed_row = _pending_row()
    del malformed_row["id"]
    exit_code, stdout, stderr = _run(
        json.dumps(_verify_envelope("load_approval_record", {"approval_id": APPROVAL_ID}, descriptor, {"kind": "rows", "rows": [malformed_row]}))
    )
    assert exit_code == 2
    assert stdout == ""
    error = json.loads(stderr)
    assert error["error"]["code"] == "approval_response_error"


def test_025_approval_transport_error_code():
    _exit_code, stdout, _stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    descriptor = json.loads(stdout)["descriptor"]
    exit_code, stdout, stderr = _run(
        json.dumps(_verify_envelope("load_approval_record", {"approval_id": APPROVAL_ID}, descriptor, {"kind": "transport_error"}))
    )
    assert exit_code == 1
    assert stdout == ""
    error = json.loads(stderr)
    assert error["error"]["code"] == "approval_transport_error"


def test_026_approval_persistence_error_code():
    exit_code, stdout, stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": "not-a-uuid"})))
    assert exit_code == 2
    assert stdout == ""
    error = json.loads(stderr)
    assert error["error"]["code"] == "approval_persistence_error"


def test_027_approval_bridge_error_code():
    exit_code, stdout, stderr = _run(json.dumps(_prepare_envelope("bogus_operation", {})))
    assert exit_code == 2
    assert stdout == ""
    error = json.loads(stderr)
    assert error["error"]["code"] == "approval_bridge_error"


def test_028_unexpected_exception_becomes_internal_error(monkeypatch):
    import core.approval_bridge_cli as cli_module

    def _broken_prepare(operation, operation_input):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli_module, "prepare_approval_operation", _broken_prepare)
    exit_code, stdout, stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    assert exit_code == 1
    assert stdout == ""
    error = json.loads(stderr)
    assert error["error"]["code"] == "internal_error"


def test_029_unexpected_exception_content_is_hidden(monkeypatch):
    import core.approval_bridge_cli as cli_module
    secret_marker = "top-secret-internal-detail"

    def _broken_prepare(operation, operation_input):
        raise RuntimeError(secret_marker)

    monkeypatch.setattr(cli_module, "prepare_approval_operation", _broken_prepare)
    _exit_code, _stdout, stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    assert secret_marker not in stderr
    assert "RuntimeError" not in stderr


def test_030_no_traceback_is_emitted(monkeypatch):
    import core.approval_bridge_cli as cli_module

    def _broken_prepare(operation, operation_input):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli_module, "prepare_approval_operation", _broken_prepare)
    _exit_code, _stdout, stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    assert "Traceback" not in stderr
    assert "File \"" not in stderr


# ---------------------------------------------------------------------------
# 31-38: error output shape, redaction, and boundaries
# ---------------------------------------------------------------------------


def test_031_error_output_is_one_json_object():
    _exit_code, _stdout, stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": "not-a-uuid"})))
    decoder = json.JSONDecoder()
    parsed, end_index = decoder.raw_decode(stderr)
    assert isinstance(parsed, dict)
    assert stderr[end_index:].strip() == ""


def test_032_error_output_goes_only_to_stderr():
    exit_code, stdout, stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": "not-a-uuid"})))
    assert stdout == ""
    assert stderr != ""


def test_033_no_record_or_payload_value_leaks():
    secret_marker = "confidential-analyst-name"
    validated_request = _validated_request(requested_by=secret_marker, investigation_id="not-a-uuid")
    _exit_code, _stdout, stderr = _run(
        json.dumps(_prepare_envelope("insert_pending_approval", {"validated_request": validated_request, "expires_at": None}))
    )
    assert secret_marker not in stderr


def test_034_no_raw_mcp_error_can_be_supplied():
    _exit_code, stdout, _stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    descriptor = json.loads(stdout)["descriptor"]
    envelope = _verify_envelope(
        "load_approval_record",
        {"approval_id": APPROVAL_ID},
        descriptor,
        {"kind": "transport_error", "message": "raw postgres connection refused at 10.0.0.1"},
    )
    exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert exit_code == 2
    error = json.loads(stderr)
    assert error["error"]["code"] == "approval_bridge_error"
    assert "10.0.0.1" not in stderr


def test_035_cli_performs_no_file_network_database_mcp_access(monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called")

    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)

    exit_code, _stdout, _stderr = _run(json.dumps(_prepare_envelope("load_approval_record", {"approval_id": APPROVAL_ID})))
    assert exit_code == 0


def test_036_cli_invokes_no_slash_command():
    source = _module_source_text()
    assert "SlashCommand" not in source
    assert "/update-case" not in source


def test_037_cli_does_not_execute_sql():
    source = _module_source_text()
    for forbidden_sql_keyword in ("SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM"):
        assert forbidden_sql_keyword not in source


def test_038_existing_validator_clis_remain_unchanged():
    import core.approval_request_cli as approval_request_cli
    import core.approval_transition_cli as approval_transition_cli

    assert callable(approval_request_cli.main)
    assert callable(approval_transition_cli.main)


# ---------------------------------------------------------------------------
# Step 39 regression: the real core.approval_transition_cli boundary
# (its own sort_keys=True JSON output, parsed back with json.loads) must
# hand off cleanly into core.approval_bridge_cli's prepare phase, with no
# manual reordering in between -- exactly as /review-approval and
# /apply-case-update do in production. main() is called directly (never
# subprocess), per this file's own established convention.
# ---------------------------------------------------------------------------


def _run_transition_cli(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = approval_transition_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def test_regression_007_real_transition_cli_approve_output_into_bridge_prepare():
    pending = _pending_row()
    transition_exit, transition_stdout, transition_stderr = _run_transition_cli(
        json.dumps({
            "current_record": pending,
            "transition_request": {"transition": "approve", "reviewed_by": "Security Reviewer", "reviewed_at": REVIEWED_AT},
        })
    )
    assert transition_exit == 0
    assert transition_stderr == ""
    plan = json.loads(transition_stdout)

    bridge_exit, bridge_stdout, bridge_stderr = _run(
        json.dumps(_prepare_envelope("apply_approval_review_transition", {"current_record": pending, "transition_plan": plan}))
    )
    assert bridge_exit == 0
    assert bridge_stderr == ""
    assert "approval_persistence_error" not in bridge_stderr
    assert "Traceback" not in bridge_stderr
    result = json.loads(bridge_stdout)
    assert set(result) == {"phase", "operation", "descriptor"}
    assert result["descriptor"]["operation"] == "update"


def test_regression_008_real_transition_cli_reject_output_into_bridge_prepare():
    pending = _pending_row()
    transition_exit, transition_stdout, transition_stderr = _run_transition_cli(
        json.dumps({
            "current_record": pending,
            "transition_request": {
                "transition": "reject",
                "reviewed_by": "Security Reviewer",
                "rejection_reason": "Needs more evidence before approval.",
                "reviewed_at": REVIEWED_AT,
            },
        })
    )
    assert transition_exit == 0
    assert transition_stderr == ""
    plan = json.loads(transition_stdout)

    bridge_exit, bridge_stdout, bridge_stderr = _run(
        json.dumps(_prepare_envelope("apply_approval_review_transition", {"current_record": pending, "transition_plan": plan}))
    )
    assert bridge_exit == 0
    assert bridge_stderr == ""
    assert "approval_persistence_error" not in bridge_stderr
    assert "Traceback" not in bridge_stderr
    result = json.loads(bridge_stdout)
    assert set(result) == {"phase", "operation", "descriptor"}
    assert result["descriptor"]["operation"] == "update"


def test_regression_009_real_transition_cli_consume_output_into_bridge_prepare():
    approved = _approved_record()
    transition_exit, transition_stdout, transition_stderr = _run_transition_cli(
        json.dumps({
            "current_record": approved,
            "transition_request": {
                "transition": "consume",
                "consumed_by": "Update Case Operator",
                "expected_investigation_id": approved["investigation_id"],
                "expected_action_type": "update_investigation_state",
                "consumed_at": CONSUMED_AT,
            },
        })
    )
    assert transition_exit == 0
    assert transition_stderr == ""
    plan = json.loads(transition_stdout)

    bridge_exit, bridge_stdout, bridge_stderr = _run(
        json.dumps(_prepare_envelope("apply_approval_consumption", {"current_record": approved, "transition_plan": plan}))
    )
    assert bridge_exit == 0
    assert bridge_stderr == ""
    assert "approval_persistence_error" not in bridge_stderr
    assert "Traceback" not in bridge_stderr
    result = json.loads(bridge_stdout)
    assert set(result) == {"phase", "operation", "descriptor"}
    assert result["descriptor"]["operation"] == "rpc"


def test_regression_010_approve_descriptor_identical_across_sort_keys_round_trip():
    pending = _pending_row()
    plan = _genuine_approve_plan(pending)
    round_tripped_plan = json.loads(json.dumps(plan, sort_keys=True))

    exit_a, stdout_a, _ = _run(
        json.dumps(_prepare_envelope("apply_approval_review_transition", {"current_record": pending, "transition_plan": plan}))
    )
    exit_b, stdout_b, _ = _run(
        json.dumps(_prepare_envelope("apply_approval_review_transition", {"current_record": pending, "transition_plan": round_tripped_plan}))
    )
    assert exit_a == 0
    assert exit_b == 0
    assert json.loads(stdout_a)["descriptor"] == json.loads(stdout_b)["descriptor"]


def test_regression_011_reject_descriptor_identical_across_sort_keys_round_trip():
    pending = _pending_row()
    plan = approval_transition.validate_approval_transition(
        pending,
        {
            "transition": "reject",
            "reviewed_by": "Security Reviewer",
            "rejection_reason": "Needs more evidence before approval.",
            "reviewed_at": REVIEWED_AT,
        },
    )
    round_tripped_plan = json.loads(json.dumps(plan, sort_keys=True))

    exit_a, stdout_a, _ = _run(
        json.dumps(_prepare_envelope("apply_approval_review_transition", {"current_record": pending, "transition_plan": plan}))
    )
    exit_b, stdout_b, _ = _run(
        json.dumps(_prepare_envelope("apply_approval_review_transition", {"current_record": pending, "transition_plan": round_tripped_plan}))
    )
    assert exit_a == 0
    assert exit_b == 0
    assert json.loads(stdout_a)["descriptor"] == json.loads(stdout_b)["descriptor"]


def test_regression_012_consume_descriptor_identical_across_sort_keys_round_trip():
    approved = _approved_record()
    plan = _genuine_consume_plan(approved)
    round_tripped_plan = json.loads(json.dumps(plan, sort_keys=True))

    exit_a, stdout_a, _ = _run(
        json.dumps(_prepare_envelope("apply_approval_consumption", {"current_record": approved, "transition_plan": plan}))
    )
    exit_b, stdout_b, _ = _run(
        json.dumps(_prepare_envelope("apply_approval_consumption", {"current_record": approved, "transition_plan": round_tripped_plan}))
    )
    assert exit_a == 0
    assert exit_b == 0
    assert json.loads(stdout_a)["descriptor"] == json.loads(stdout_b)["descriptor"]


# ---------------------------------------------------------------------------
# Block 6, Step 4: risk-aware operations through the real bridge CLI
# ---------------------------------------------------------------------------


def test_multi_review_cli_risk_aware_insert_prepare_and_verify():
    request = {
        "investigation_id": INVESTIGATION_ID,
        "action_type": "update_investigation_state",
        "action_payload": {"status": "closed"},
        "requested_by": "Roshini Analyst",
        "requested_at": REQUESTED_AT,
    }
    current_investigation = {"status": "investigating", "confidence": "medium"}
    operation_input = {"request": request, "current_investigation": current_investigation, "expires_at": None}

    prepare_exit, prepare_stdout, prepare_stderr = _run(
        json.dumps(_prepare_envelope("insert_risk_aware_pending_approval", operation_input))
    )
    assert prepare_exit == 0
    assert prepare_stderr == ""
    prepared = json.loads(prepare_stdout)
    assert prepared["descriptor"]["values"]["risk_level"] == "high"
    assert prepared["descriptor"]["values"]["required_approvals"] == 2

    inserted_row = {
        "id": APPROVAL_ID,
        "investigation_id": INVESTIGATION_ID,
        "action_type": "update_investigation_state",
        "action_payload": {"status": "closed"},
        "requested_by": "Roshini Analyst",
        "requested_at": REQUESTED_AT,
        "status": "pending",
        "approved_by": None,
        "approved_at": None,
        "rejected_by": None,
        "rejected_at": None,
        "rejection_reason": None,
        "expires_at": None,
        "consumed_by": None,
        "consumed_at": None,
        "created_at": REQUESTED_AT,
        "risk_level": "high",
        "required_approvals": 2,
    }
    verify_exit, verify_stdout, verify_stderr = _run(
        json.dumps(_verify_envelope(
            "insert_risk_aware_pending_approval", operation_input, prepared["descriptor"],
            {"kind": "rows", "rows": [inserted_row]},
        ))
    )
    assert verify_exit == 0
    assert verify_stderr == ""
    result = json.loads(verify_stdout)
    assert result["result"]["risk_level"] == "high"
    assert result["result"]["required_approvals"] == 2


def test_multi_review_cli_record_and_review_lookup():
    operation_input = {"approval_id": APPROVAL_ID}

    record_prepare_exit, record_prepare_stdout, record_prepare_stderr = _run(
        json.dumps(_prepare_envelope("load_risk_aware_approval_record", operation_input))
    )
    assert record_prepare_exit == 0
    assert record_prepare_stderr == ""
    record_prepared = json.loads(record_prepare_stdout)

    risk_aware_row = dict(_pending_row(), risk_level="high", required_approvals=2)
    record_verify_exit, record_verify_stdout, record_verify_stderr = _run(
        json.dumps(_verify_envelope(
            "load_risk_aware_approval_record", operation_input, record_prepared["descriptor"],
            {"kind": "rows", "rows": [risk_aware_row]},
        ))
    )
    assert record_verify_exit == 0
    assert record_verify_stderr == ""
    assert json.loads(record_verify_stdout)["result"]["risk_level"] == "high"

    review_prepare_exit, review_prepare_stdout, review_prepare_stderr = _run(
        json.dumps(_prepare_envelope("load_approval_reviews", operation_input))
    )
    assert review_prepare_exit == 0
    assert review_prepare_stderr == ""
    review_prepared = json.loads(review_prepare_stdout)
    assert review_prepared["descriptor"]["table"] == "approval_reviews"

    # Genuinely zero reviews is a valid success through the real CLI too.
    review_verify_exit, review_verify_stdout, review_verify_stderr = _run(
        json.dumps(_verify_envelope(
            "load_approval_reviews", operation_input, review_prepared["descriptor"], {"kind": "rows", "rows": []},
        ))
    )
    assert review_verify_exit == 0
    assert review_verify_stderr == ""
    assert json.loads(review_verify_stdout)["result"] == []


def test_multi_review_cli_apply_prepare():
    record = dict(_pending_row(), risk_level="high", required_approvals=2, expires_at=None)
    plan = approval_transition.validate_multi_review_transition(
        record, [], {"decision": "approve", "reviewed_by": "Reviewer One"}, reviewed_at=REVIEWED_AT
    )
    # Real JSON serialization boundary: sort_keys=True round trip, exactly
    # like the plan this real CLI would actually receive from a future
    # multi-review transition CLI.
    round_tripped_plan = json.loads(json.dumps(plan, sort_keys=True))

    operation_input = {"current_record": record, "existing_reviews": [], "transition_plan": round_tripped_plan}
    prepare_exit, prepare_stdout, prepare_stderr = _run(
        json.dumps(_prepare_envelope("apply_multi_review_transition", operation_input))
    )
    assert prepare_exit == 0
    assert prepare_stderr == ""
    result = json.loads(prepare_stdout)
    assert result["descriptor"]["operation"] == "rpc"
    assert result["descriptor"]["function"] == "record_approval_review_and_promote_status"


def test_multi_review_cli_canonical_conflict_verify():
    record = dict(_pending_row(), risk_level="high", required_approvals=2, expires_at=None)
    plan = approval_transition.validate_multi_review_transition(
        record, [], {"decision": "approve", "reviewed_by": "Reviewer One"}, reviewed_at=REVIEWED_AT
    )
    operation_input = {"current_record": record, "existing_reviews": [], "transition_plan": plan}

    prepare_exit, prepare_stdout, prepare_stderr = _run(
        json.dumps(_prepare_envelope("apply_multi_review_transition", operation_input))
    )
    assert prepare_exit == 0
    prepared = json.loads(prepare_stdout)

    verify_exit, verify_stdout, verify_stderr = _run(
        json.dumps(_verify_envelope(
            "apply_multi_review_transition", operation_input, prepared["descriptor"], {"kind": "rows", "rows": []},
        ))
    )
    assert verify_exit == 2
    assert verify_stdout == ""
    error = json.loads(verify_stderr)
    assert error["error"]["code"] == "approval_conflict"


# ---------------------------------------------------------------------------
# Block 6, Step 9: trusted investigation-context lookup through the real
# bridge CLI
# ---------------------------------------------------------------------------


def test_investigation_context_cli_prepare_and_verify():
    operation_input = {"investigation_id": INVESTIGATION_ID}

    prepare_exit, prepare_stdout, prepare_stderr = _run(
        json.dumps(_prepare_envelope("load_investigation_approval_context", operation_input))
    )
    assert prepare_exit == 0
    assert prepare_stderr == ""
    prepared = json.loads(prepare_stdout)
    assert prepared["phase"] == "prepare"
    assert prepared["operation"] == "load_investigation_approval_context"
    assert prepared["descriptor"]["table"] == "investigations"
    # No SQL of any kind is ever constructed inside the bridge -- the
    # descriptor is a plain data structure, never a query string.
    assert "query" not in prepared["descriptor"]
    assert "sql" not in prepared["descriptor"]

    row = {"investigation_id": INVESTIGATION_ID, "status": "investigating", "confidence": "medium"}
    verify_exit, verify_stdout, verify_stderr = _run(
        json.dumps(_verify_envelope(
            "load_investigation_approval_context", operation_input, prepared["descriptor"],
            {"kind": "rows", "rows": [row]},
        ))
    )
    assert verify_exit == 0
    assert verify_stderr == ""
    result = json.loads(verify_stdout)
    assert result["phase"] == "verify"
    assert result["operation"] == "load_investigation_approval_context"
    assert result["result"] == {
        "investigation_id": INVESTIGATION_ID, "status": "investigating", "confidence": "medium",
    }

    # Deterministic: the exact same envelope, run again, produces
    # byte-identical output through the real JSON serialization boundary.
    prepare_exit_again, prepare_stdout_again, _prepare_stderr_again = _run(
        json.dumps(_prepare_envelope("load_investigation_approval_context", operation_input))
    )
    assert prepare_exit_again == 0
    assert prepare_stdout_again == prepare_stdout

    # A zero-row lookup fails as a deterministic "not found" conflict,
    # never a traceback.
    not_found_exit, not_found_stdout, not_found_stderr = _run(
        json.dumps(_verify_envelope(
            "load_investigation_approval_context", operation_input, prepared["descriptor"],
            {"kind": "rows", "rows": []},
        ))
    )
    assert not_found_exit == 2
    assert not_found_stdout == ""
    not_found_error = json.loads(not_found_stderr)
    assert not_found_error["error"]["code"] == "approval_not_found"
    assert "Traceback" not in not_found_stderr


# ---------------------------------------------------------------------------
# Test-module source boundary (self-check)
# ---------------------------------------------------------------------------


def test_static_test_module_does_not_import_supabase_or_requests_at_module_scope():
    tree = _this_module_ast()
    imports = _top_level_imports(tree)
    assert not any(name == "supabase" or name.startswith("supabase.") for name in imports)
    assert "requests" not in imports


def test_static_test_module_never_calls_subprocess_directly():
    tree = _this_module_ast()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "Popen", "call", "check_call", "check_output"):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    pytest.fail("subprocess call executed directly in the test module")
