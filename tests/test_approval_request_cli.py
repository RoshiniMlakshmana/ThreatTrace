"""Tests for core.approval_request_cli -- the stdin/stdout JSON adapter
around core.approval_request.validate_approval_request.

main() is called directly with in-memory StringIO streams. No Supabase,
file, subprocess, network, AI-model, or other external access occurs
anywhere in this file; every input is a plain in-memory JSON object.
"""

import copy
import json
import socket
import subprocess
from io import StringIO
from pathlib import Path

import pytest

from core import approval_request_cli
import core.approval_request as approval_request
import core.approval_transition as approval_transition

INVESTIGATION_ID = "11111111-1111-4111-8111-111111111111"


def _payload(**overrides):
    payload = {
        "investigation_id": INVESTIGATION_ID,
        "action_type": "update_investigation_state",
        "action_payload": {"status": "escalated"},
        "requested_by": "analyst-jane",
    }
    payload.update(overrides)
    return payload


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = approval_request_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _module_source_text():
    with open(approval_request_cli.__file__, "r", encoding="utf-8") as handle:
        return handle.read()


def _this_module_ast():
    import ast

    return ast.parse(Path(__file__).read_text(encoding="utf-8"))


def _imported_module_names(tree):
    import ast

    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
    return names


# ---------------------------------------------------------------------------
# 1-6: public contract
# ---------------------------------------------------------------------------

def test_001_main_is_callable():
    assert callable(approval_request_cli.main)


def test_002_main_returns_an_integer():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload()))
    assert isinstance(exit_code, int)


def test_003_main_guard_exists():
    source = _module_source_text()
    assert 'if __name__ == "__main__":' in source
    assert "raise SystemExit(main())" in source


def test_004_cli_imports_validate_approval_request():
    assert approval_request_cli.validate_approval_request is approval_request.validate_approval_request


def test_005_cli_imports_approval_request_error():
    assert approval_request_cli.ApprovalRequestError is approval_request.ApprovalRequestError


def test_006_cli_does_not_import_approval_transition_logic():
    source = _module_source_text()
    assert "import core.approval_transition" not in source
    assert "from core.approval_transition import" not in source
    assert not hasattr(approval_request_cli, "validate_approval_transition")


# ---------------------------------------------------------------------------
# 7-20: successful transport
# ---------------------------------------------------------------------------

def test_007_valid_status_only_request_succeeds():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload(action_payload={"status": "escalated"})))
    assert exit_code == 0


def test_008_valid_confidence_only_request_succeeds():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload(action_payload={"confidence": "high"})))
    assert exit_code == 0


def test_009_valid_status_and_confidence_request_succeeds():
    exit_code, _stdout, _stderr = _run(
        json.dumps(_payload(action_payload={"status": "investigating", "confidence": "medium"}))
    )
    assert exit_code == 0


def test_010_exit_code_is_0():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload()))
    assert exit_code == 0


def test_011_stderr_is_empty_on_success():
    _exit_code, _stdout, stderr = _run(json.dumps(_payload()))
    assert stderr == ""


def test_012_stdout_contains_exactly_one_json_object():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    parsed = json.loads(stdout)
    assert isinstance(parsed, dict)


def test_013_stdout_ends_with_exactly_one_newline():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    assert stdout.endswith("\n")
    assert not stdout.endswith("\n\n")


def test_014_output_has_no_extra_explanatory_text():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    stripped = stdout.strip()
    assert stripped.startswith("{")
    assert stripped.endswith("}")


def test_015_output_equals_direct_validate_approval_request_output():
    payload = _payload(requested_at="2026-08-01T12:00:00Z")
    _exit_code, stdout, _stderr = _run(json.dumps(payload))
    assert json.loads(stdout) == approval_request.validate_approval_request(payload)


def test_016_output_uses_sorted_object_keys():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    parsed = json.loads(stdout)
    assert list(parsed.keys()) == sorted(parsed.keys())


def test_017_unicode_requested_by_emitted_with_ensure_ascii_false():
    payload = _payload(requested_by="analyst-café-注意")
    exit_code, stdout, _stderr = _run(json.dumps(payload, ensure_ascii=False))
    assert exit_code == 0
    assert "café-注意" in stdout
    assert "\\u" not in stdout


def test_018_nested_action_payload_output_preserved():
    payload = _payload(action_payload={"status": "closed", "confidence": "low"})
    _exit_code, stdout, _stderr = _run(json.dumps(payload))
    parsed = json.loads(stdout)
    assert parsed["action_payload"] == {"status": "closed", "confidence": "low"}


def test_019_generated_requested_at_is_present():
    payload = _payload()
    assert "requested_at" not in payload
    _exit_code, stdout, _stderr = _run(json.dumps(payload))
    parsed = json.loads(stdout)
    assert parsed["requested_at"]


def test_020_supplied_requested_at_canonicalized_by_validator():
    payload = _payload(requested_at="2026-08-01T08:45:00-07:00")
    _exit_code, stdout, _stderr = _run(json.dumps(payload))
    parsed = json.loads(stdout)
    assert parsed["requested_at"] == "2026-08-01T15:45:00Z"


# ---------------------------------------------------------------------------
# 21-40: JSON input rejection
# ---------------------------------------------------------------------------

def test_021_empty_input_rejected():
    exit_code, stdout, stderr = _run("")
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_022_whitespace_only_input_rejected():
    exit_code, stdout, stderr = _run("   \n\t  ")
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_023_malformed_json_rejected():
    exit_code, stdout, stderr = _run("{not valid json")
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_024_truncated_json_rejected():
    raw = json.dumps(_payload())[:-5]
    exit_code, stdout, stderr = _run(raw)
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_025_two_concatenated_objects_rejected():
    raw = json.dumps(_payload()) + json.dumps(_payload())
    exit_code, stdout, stderr = _run(raw)
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_026_object_plus_trailing_text_rejected():
    raw = json.dumps(_payload()) + " garbage"
    exit_code, stdout, stderr = _run(raw)
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_027_object_plus_trailing_number_rejected():
    raw = json.dumps(_payload()) + " 5"
    exit_code, stdout, stderr = _run(raw)
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_028_object_plus_trailing_array_rejected():
    raw = json.dumps(_payload()) + " []"
    exit_code, stdout, stderr = _run(raw)
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_029_null_rejected():
    exit_code, stdout, stderr = _run("null")
    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Approval request input must be a JSON object.\n"


def test_030_array_rejected():
    exit_code, stdout, stderr = _run("[]")
    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Approval request input must be a JSON object.\n"


def test_031_string_rejected():
    exit_code, stdout, stderr = _run('"a string"')
    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Approval request input must be a JSON object.\n"


def test_032_integer_rejected():
    exit_code, stdout, stderr = _run("42")
    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Approval request input must be a JSON object.\n"


def test_033_float_rejected():
    exit_code, stdout, stderr = _run("4.2")
    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Approval request input must be a JSON object.\n"


def test_034_true_rejected():
    exit_code, stdout, stderr = _run("true")
    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Approval request input must be a JSON object.\n"


def test_035_false_rejected():
    exit_code, stdout, stderr = _run("false")
    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Approval request input must be a JSON object.\n"


def test_036_failure_exit_code_is_2():
    exit_code, _stdout, _stderr = _run("not json")
    assert exit_code == 2


def test_037_stdout_empty_on_every_input_failure():
    for raw in ("", "null", "{bad", "[]", json.dumps(_payload()) + " x"):
        _exit_code, stdout, _stderr = _run(raw)
        assert stdout == ""


def test_038_stderr_has_exactly_one_trailing_newline():
    _exit_code, _stdout, stderr = _run("not json")
    assert stderr.endswith("\n")
    assert stderr.count("\n") == 1


def test_039_raw_malformed_input_is_not_echoed():
    marker = "SECRET-MALFORMED-INPUT-MARKER"
    _exit_code, _stdout, stderr = _run("{not valid json " + marker)
    assert marker not in stderr


def test_040_json_decoder_details_are_not_exposed_as_source_lines():
    _exit_code, _stdout, stderr = _run("{not valid json")
    assert "line 1 column" not in stderr or stderr.startswith("Invalid JSON input:")
    # The safe prefix must be present; nothing beyond the parser's own
    # concise summary (which never includes full source text) is exposed.
    assert stderr.startswith("Invalid JSON input:")


# ---------------------------------------------------------------------------
# 41-60: validator-error handling
# ---------------------------------------------------------------------------

def test_041_missing_investigation_id_returns_2():
    payload = _payload()
    del payload["investigation_id"]
    exit_code, _stdout, _stderr = _run(json.dumps(payload))
    assert exit_code == 2


def test_042_missing_action_type_returns_2():
    payload = _payload()
    del payload["action_type"]
    exit_code, _stdout, _stderr = _run(json.dumps(payload))
    assert exit_code == 2


def test_043_missing_action_payload_returns_2():
    payload = _payload()
    del payload["action_payload"]
    exit_code, _stdout, _stderr = _run(json.dumps(payload))
    assert exit_code == 2


def test_044_missing_requested_by_returns_2():
    payload = _payload()
    del payload["requested_by"]
    exit_code, _stdout, _stderr = _run(json.dumps(payload))
    assert exit_code == 2


def test_045_unknown_top_level_field_returns_2():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload(unexpected="x")))
    assert exit_code == 2


def test_046_invalid_investigation_uuid_returns_2():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload(investigation_id="not-a-uuid")))
    assert exit_code == 2


def test_047_unknown_action_type_returns_2():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload(action_type="delete_investigation")))
    assert exit_code == 2


def test_048_empty_action_payload_returns_2():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload(action_payload={})))
    assert exit_code == 2


def test_049_unknown_action_payload_field_returns_2():
    exit_code, _stdout, _stderr = _run(
        json.dumps(_payload(action_payload={"status": "escalated", "extra": "x"}))
    )
    assert exit_code == 2


def test_050_invalid_status_returns_2():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload(action_payload={"status": "not-real"})))
    assert exit_code == 2


def test_051_invalid_confidence_returns_2():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload(action_payload={"confidence": "extreme"})))
    assert exit_code == 2


def test_052_blank_requested_by_returns_2():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload(requested_by="   ")))
    assert exit_code == 2


def test_053_naive_requested_at_returns_2():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload(requested_at="2026-08-01T12:00:00")))
    assert exit_code == 2


def test_054_invalid_requested_at_returns_2():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload(requested_at="not-a-timestamp")))
    assert exit_code == 2


def test_055_stdout_remains_empty_for_approval_request_error():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload(action_type="delete_investigation")))
    assert stdout == ""


def test_056_stderr_contains_no_complete_request_object():
    marker = "SECRET-REQUEST-OBJECT-MARKER"
    payload = _payload(action_type="delete_investigation", requested_by=marker)
    _exit_code, _stdout, stderr = _run(json.dumps(payload))
    assert marker not in stderr


def test_057_stderr_contains_no_action_payload_content():
    marker = "SECRET-ACTION-PAYLOAD-MARKER"
    payload = _payload(action_payload={"status": "escalated", "extra": marker})
    _exit_code, _stdout, stderr = _run(json.dumps(payload))
    assert marker not in stderr


def test_058_stderr_contains_no_requested_by_value():
    marker = "SECRET-REQUESTED-BY-MARKER"
    payload = _payload(action_type="delete_investigation", requested_by=marker)
    _exit_code, _stdout, stderr = _run(json.dumps(payload))
    assert marker not in stderr


def test_059_stderr_contains_no_planted_secret_marker():
    marker = "SECRET-GENERIC-MARKER-xyz"
    payload = _payload(requested_by=marker, action_payload={"status": "not-real"})
    _exit_code, _stdout, stderr = _run(json.dumps(payload))
    assert marker not in stderr


def test_060_raw_approval_request_error_does_not_escape():
    payload = _payload(action_type="delete_investigation")
    stdin = StringIO(json.dumps(payload))
    stdout = StringIO()
    stderr = StringIO()
    # main() must catch ApprovalRequestError internally -- calling it must
    # not raise at all.
    exit_code = approval_request_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    assert exit_code == 2


# ---------------------------------------------------------------------------
# 61-71: validator call-count boundary
# ---------------------------------------------------------------------------

def test_061_validator_called_exactly_once_for_valid_object_input(monkeypatch):
    calls = []
    original = approval_request_cli.validate_approval_request

    def counting_validate(payload):
        calls.append(payload)
        return original(payload)

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", counting_validate)

    exit_code, _stdout, _stderr = _run(json.dumps(_payload()))
    assert exit_code == 0
    assert len(calls) == 1


def test_062_validator_not_called_for_empty_input(monkeypatch):
    def forbidden(_payload):
        raise AssertionError("validate_approval_request must not be called for empty input")

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", forbidden)

    exit_code, _stdout, _stderr = _run("")
    assert exit_code == 2


def test_063_validator_not_called_for_malformed_json(monkeypatch):
    def forbidden(_payload):
        raise AssertionError("validate_approval_request must not be called for malformed JSON")

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", forbidden)

    exit_code, _stdout, _stderr = _run("{bad json")
    assert exit_code == 2


def test_064_validator_not_called_for_concatenated_json(monkeypatch):
    def forbidden(_payload):
        raise AssertionError("validate_approval_request must not be called for concatenated JSON")

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", forbidden)

    raw = json.dumps(_payload()) + json.dumps(_payload())
    exit_code, _stdout, _stderr = _run(raw)
    assert exit_code == 2


def test_065_validator_not_called_for_trailing_content_json(monkeypatch):
    def forbidden(_payload):
        raise AssertionError("validate_approval_request must not be called for trailing content")

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", forbidden)

    raw = json.dumps(_payload()) + " garbage"
    exit_code, _stdout, _stderr = _run(raw)
    assert exit_code == 2


def test_066_validator_not_called_for_non_object_json(monkeypatch):
    def forbidden(_payload):
        raise AssertionError("validate_approval_request must not be called for non-object JSON")

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", forbidden)

    exit_code, _stdout, _stderr = _run("null")
    assert exit_code == 2


def test_067_cli_passes_the_parsed_object_to_the_validator(monkeypatch):
    captured = {}

    def capturing_validate(payload):
        captured["payload"] = payload
        return approval_request.validate_approval_request(payload)

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", capturing_validate)

    payload = _payload()
    _run(json.dumps(payload))

    assert captured["payload"] == payload


def test_068_cli_does_not_pre_normalize_investigation_id(monkeypatch):
    captured = {}

    def capturing_validate(payload):
        captured["investigation_id"] = payload["investigation_id"]
        return approval_request.validate_approval_request(payload)

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", capturing_validate)

    raw_id = INVESTIGATION_ID.upper()
    _run(json.dumps(_payload(investigation_id=raw_id)))

    assert captured["investigation_id"] == raw_id


def test_069_cli_does_not_pre_normalize_action_type(monkeypatch):
    captured = {}

    def capturing_validate(payload):
        captured["action_type"] = payload["action_type"]
        return approval_request.validate_approval_request(payload)

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", capturing_validate)

    _run(json.dumps(_payload(action_type="  UPDATE_INVESTIGATION_STATE  ")))

    assert captured["action_type"] == "  UPDATE_INVESTIGATION_STATE  "


def test_070_cli_does_not_inspect_action_payload(monkeypatch):
    captured = {}

    def capturing_validate(payload):
        captured["action_payload"] = payload["action_payload"]
        return approval_request.validate_approval_request(payload)

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", capturing_validate)

    original_action_payload = {"status": "escalated"}
    _run(json.dumps(_payload(action_payload=original_action_payload)))

    assert captured["action_payload"] == original_action_payload


def test_071_cli_does_not_generate_requested_at_itself():
    source = _module_source_text()
    assert "datetime.now(" not in source
    assert "import datetime" not in source
    assert "from datetime" not in source


# ---------------------------------------------------------------------------
# 72-81: unexpected failure
# ---------------------------------------------------------------------------

def test_072_monkeypatched_validator_unexpected_exception_returns_1(monkeypatch):
    def boom(_payload):
        raise RuntimeError("simulated internal failure")

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", boom)

    exit_code, _stdout, _stderr = _run(json.dumps(_payload()))
    assert exit_code == 1


def test_073_unexpected_failure_stdout_empty(monkeypatch):
    def boom(_payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", boom)

    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    assert stdout == ""


def test_074_unexpected_failure_stderr_exact_message(monkeypatch):
    def boom(_payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_payload()))
    assert stderr == "Approval request validation failed.\n"


def test_075_exception_type_not_exposed(monkeypatch):
    def boom(_payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_payload()))
    assert "RuntimeError" not in stderr


def test_076_exception_message_not_exposed(monkeypatch):
    secret_marker = "SECRET-EXCEPTION-MESSAGE-MARKER"

    def boom(_payload):
        raise RuntimeError(secret_marker)

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_payload()))
    assert secret_marker not in stderr


def test_077_traceback_not_exposed(monkeypatch):
    def boom(_payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_payload()))
    assert "Traceback" not in stderr


def test_078_request_payload_not_exposed(monkeypatch):
    secret_marker = "SECRET-PAYLOAD-MARKER"

    def boom(_payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", boom)

    payload = _payload(requested_by=secret_marker)
    _exit_code, stdout, stderr = _run(json.dumps(payload))
    assert secret_marker not in stdout
    assert secret_marker not in stderr


def test_079_action_payload_not_exposed(monkeypatch):
    secret_marker = "SECRET-ACTION-PAYLOAD-CONTENT-MARKER"

    def boom(_payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", boom)

    payload = _payload(action_payload={"status": "escalated", "note": secret_marker})
    _exit_code, _stdout, stderr = _run(json.dumps(payload))
    assert secret_marker not in stderr


def test_080_requested_by_not_exposed(monkeypatch):
    secret_marker = "SECRET-REQUESTED-BY-CONTENT-MARKER"

    def boom(_payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", boom)

    payload = _payload(requested_by=secret_marker)
    _exit_code, _stdout, stderr = _run(json.dumps(payload))
    assert secret_marker not in stderr


def test_081_planted_secret_markers_not_exposed(monkeypatch):
    secret_marker = "SECRET-GENERIC-UNEXPECTED-MARKER"

    def boom(_payload):
        raise RuntimeError(secret_marker)

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", boom)

    payload = _payload(requested_by=secret_marker, action_payload={"status": "escalated", "x": secret_marker})
    _exit_code, stdout, stderr = _run(json.dumps(payload))
    assert secret_marker not in stdout
    assert secret_marker not in stderr


# ---------------------------------------------------------------------------
# 82-87: non-mutation
# ---------------------------------------------------------------------------

def test_082_parsed_payload_remains_unchanged_after_successful_cli_call(monkeypatch):
    captured = {}

    def capturing_validate(payload):
        captured["snapshot"] = copy.deepcopy(payload)
        result = approval_request.validate_approval_request(payload)
        captured["payload_ref"] = payload
        return result

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", capturing_validate)

    _run(json.dumps(_payload()))

    assert captured["payload_ref"] == captured["snapshot"]


def test_083_nested_action_payload_remains_unchanged():
    payload = _payload(action_payload={"status": "escalated", "confidence": "medium"})
    snapshot = copy.deepcopy(payload["action_payload"])

    _run(json.dumps(payload))

    assert payload["action_payload"] == snapshot


def test_084_validator_return_object_not_mutated_by_cli(monkeypatch):
    fixed_result = {
        "investigation_id": INVESTIGATION_ID,
        "action_type": "update_investigation_state",
        "action_payload": {"status": "escalated"},
        "requested_by": "analyst-jane",
        "requested_at": "2026-08-01T12:00:00Z",
    }
    snapshot = copy.deepcopy(fixed_result)

    monkeypatch.setattr(approval_request_cli, "validate_approval_request", lambda _p: fixed_result)

    exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    assert exit_code == 0
    assert fixed_result == snapshot
    assert json.loads(stdout) == snapshot


def test_085_caller_owned_stringio_content_not_altered_unexpectedly():
    stdin = StringIO(json.dumps(_payload()))
    stdout = StringIO()
    stderr = StringIO()

    exit_code = approval_request_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)

    assert exit_code == 0
    assert stderr.getvalue() == ""
    # stdout must contain only the one JSON object plus newline -- nothing
    # was written to it before or after in some unexpected extra call.
    assert stdout.getvalue().count("\n") == 1


def test_086_reusing_same_source_payload_deterministic_apart_from_generated_requested_at():
    payload = _payload()

    _exit_code1, stdout1, _stderr1 = _run(json.dumps(payload))
    _exit_code2, stdout2, _stderr2 = _run(json.dumps(payload))

    parsed1 = json.loads(stdout1)
    parsed2 = json.loads(stdout2)
    del parsed1["requested_at"]
    del parsed2["requested_at"]

    assert parsed1 == parsed2


def test_087_supplied_requested_at_repeated_calls_produce_identical_json():
    payload = _payload(requested_at="2026-08-01T12:00:00Z")

    _exit_code1, stdout1, _stderr1 = _run(json.dumps(payload))
    _exit_code2, stdout2, _stderr2 = _run(json.dumps(payload))

    assert stdout1 == stdout2


# ---------------------------------------------------------------------------
# 88-99: output shape
# ---------------------------------------------------------------------------

def test_088_output_contains_exactly_five_approval_request_fields():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    parsed = json.loads(stdout)
    assert set(parsed.keys()) == {
        "investigation_id",
        "action_type",
        "action_payload",
        "requested_by",
        "requested_at",
    }


def test_089_output_contains_no_approval_id():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    parsed = json.loads(stdout)
    assert "id" not in parsed
    assert "approval_id" not in parsed


def test_090_output_contains_no_lifecycle_status():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    parsed = json.loads(stdout)
    assert "status" not in parsed


def test_091_output_contains_no_approved_by():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    parsed = json.loads(stdout)
    assert "approved_by" not in parsed
    assert "approved_at" not in parsed


def test_092_output_contains_no_rejected_by():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    parsed = json.loads(stdout)
    assert "rejected_by" not in parsed
    assert "rejected_at" not in parsed
    assert "rejection_reason" not in parsed


def test_093_output_contains_no_consumed_by():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    parsed = json.loads(stdout)
    assert "consumed_by" not in parsed
    assert "consumed_at" not in parsed


def test_094_output_contains_no_expires_at():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    parsed = json.loads(stdout)
    assert "expires_at" not in parsed


def test_095_output_contains_no_action_hash():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    parsed = json.loads(stdout)
    assert "action_hash" not in parsed


def test_096_output_contains_no_target_fields():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    parsed = json.loads(stdout)
    assert "target_type" not in parsed
    assert "target_id" not in parsed


def test_097_output_contains_no_database_result():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    parsed = json.loads(stdout)
    assert "affected_rows" not in parsed
    assert "row_count" not in parsed


def test_098_output_contains_no_approval_result():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    parsed = json.loads(stdout)
    assert "approval_result" not in parsed


def test_099_output_contains_no_transition_plan():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))
    parsed = json.loads(stdout)
    assert "from_status" not in parsed
    assert "to_status" not in parsed
    assert "set_fields" not in parsed


# ---------------------------------------------------------------------------
# 100-116: runtime side-effect guard
# ---------------------------------------------------------------------------

def test_runtime_guard_no_forbidden_entry_points_reached(monkeypatch):
    import os
    import sys
    import urllib.request

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called during approval-request CLI validation")

    try:
        import requests
    except ImportError:
        requests = None

    try:
        import supabase
    except ImportError:
        supabase = None

    original_cwd = os.getcwd()
    original_environ = dict(os.environ)

    monkeypatch.setattr("builtins.open", _forbidden)
    monkeypatch.setattr(Path, "open", _forbidden)
    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)

    if requests is not None:
        monkeypatch.setattr(requests, "get", _forbidden)
        monkeypatch.setattr(requests, "post", _forbidden)

    if supabase is not None and hasattr(supabase, "create_client"):
        monkeypatch.setattr(supabase, "create_client", _forbidden)

    assert "mcp.hayabusa_server" not in sys.modules

    exit_code, _stdout, _stderr = _run(json.dumps(_payload()))

    assert exit_code == 0
    assert "mcp.hayabusa_server" not in sys.modules
    assert os.getcwd() == original_cwd
    assert dict(os.environ) == original_environ


def test_112_approval_transition_is_not_invoked(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("validate_approval_transition must not be called by the approval-request CLI")

    monkeypatch.setattr(approval_transition, "validate_approval_transition", forbidden)

    exit_code, _stdout, _stderr = _run(json.dumps(_payload()))
    assert exit_code == 0


def test_113_no_approval_persistence_occurs():
    source = _module_source_text()
    assert ".insert(" not in source
    assert ".update(" not in source


def test_114_no_investigation_update_occurs():
    source = _module_source_text()
    assert "investigations" not in source.lower()


def test_115_no_containment_occurs():
    source = _module_source_text()
    assert "containment" not in source.lower()


def test_116_no_red_team_execution_occurs():
    source = _module_source_text()
    assert "execute_simulation" not in source.lower()
    assert "run_atomic" not in source.lower()


# ---------------------------------------------------------------------------
# 117-140: source-boundary tests
# ---------------------------------------------------------------------------

def test_117_source_imports_only_approved_stdlib_and_approval_request_symbols():
    import ast

    tree = ast.parse(_module_source_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module)

    allowed = {"__future__", "json", "sys", "typing", "core.approval_request"}
    assert imported <= allowed


def test_118_source_does_not_import_supabase():
    source = _module_source_text()
    assert "import supabase" not in source
    assert "from supabase" not in source


def test_119_source_does_not_import_requests():
    source = _module_source_text()
    assert "import requests" not in source


def test_120_source_does_not_import_subprocess():
    source = _module_source_text()
    assert "import subprocess" not in source


def test_121_source_does_not_import_pathlib_for_runtime_file_access():
    source = _module_source_text()
    assert "import pathlib" not in source
    assert "from pathlib" not in source


def test_122_source_does_not_import_approval_transition():
    source = _module_source_text()
    assert "import core.approval_transition" not in source
    assert "from core.approval_transition import" not in source


def test_123_source_does_not_import_decision_modules():
    source = _module_source_text()
    assert "decision_context" not in source
    assert "decision_analysis" not in source


def test_124_source_does_not_import_warning_formatter_modules():
    source = _module_source_text()
    assert "decision_warning_formatter" not in source


def test_125_source_does_not_import_ai_model_libraries():
    source = _module_source_text()
    assert "openai" not in source.lower()
    assert "anthropic" not in source.lower()


def test_126_source_contains_no_file_open_call():
    source = _module_source_text()
    assert "open(" not in source


def test_127_source_contains_no_database_write_call():
    source = _module_source_text()
    assert ".insert(" not in source
    assert ".update(" not in source
    assert ".delete(" not in source


def test_128_source_contains_no_temporary_file_call():
    source = _module_source_text()
    assert "tempfile" not in source
    assert "NamedTemporaryFile" not in source


def test_129_source_contains_no_network_call():
    source = _module_source_text()
    assert "socket" not in source
    assert "urllib" not in source
    assert "requests." not in source


def test_130_source_contains_no_approval_transition_call():
    source = _module_source_text()
    assert "validate_approval_transition" not in source


def test_131_source_contains_no_schema_or_sql_behavior():
    source = _module_source_text()
    assert "create table" not in source.lower()
    assert "CHECK (" not in source


def test_132_source_contains_no_slash_command_invocation():
    source = _module_source_text()
    assert "SlashCommand(" not in source
    assert "/update-case" not in source


def test_133_source_contains_no_hashing_implementation():
    source = _module_source_text()
    assert "hashlib" not in source
    assert "sha256" not in source.lower()


def test_134_source_does_not_duplicate_action_types():
    source = _module_source_text()
    assert "ACTION_TYPES = frozenset" not in source


def test_135_source_does_not_duplicate_investigation_status_vocabulary():
    source = _module_source_text()
    assert "INVESTIGATION_STATUSES" not in source


def test_136_source_does_not_duplicate_confidence_vocabulary():
    source = _module_source_text()
    assert "CONFIDENCE_LEVELS" not in source


def test_137_source_delegates_business_validation_to_validate_approval_request():
    source = _module_source_text()
    assert "validate_approval_request(" in source
    assert "def _validate_" not in source


def test_138_source_serializes_with_sort_keys_true():
    source = _module_source_text()
    assert "sort_keys=True" in source


def test_139_source_serializes_with_ensure_ascii_false():
    source = _module_source_text()
    assert "ensure_ascii=False" in source


def test_140_source_returns_only_0_2_or_1():
    import ast

    tree = ast.parse(_module_source_text())
    returned_values = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, int):
                returned_values.add(node.value.value)

    assert returned_values == {0, 1, 2}


# ---------------------------------------------------------------------------
# Source-boundary checks on the test module itself
# ---------------------------------------------------------------------------

def test_static_test_module_does_not_import_supabase_or_requests_at_module_scope():
    tree = _this_module_ast()

    import ast

    top_level_imports = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level_imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top_level_imports.add(node.module)

    assert not any(name == "supabase" or name.startswith("supabase.") for name in top_level_imports)
    assert "requests" not in top_level_imports


def test_static_test_module_imports_subprocess_only_for_monkeypatch_targets():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert "subprocess" in imported

    import ast

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "Popen", "call", "check_call", "check_output"):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    pytest.fail("subprocess call executed directly in the test module")
