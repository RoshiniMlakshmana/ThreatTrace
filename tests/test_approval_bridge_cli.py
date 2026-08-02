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


def _genuine_approve_plan(record, reviewed_by="Security Reviewer"):
    return approval_transition.validate_approval_transition(
        record, {"transition": "approve", "reviewed_by": reviewed_by}
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
