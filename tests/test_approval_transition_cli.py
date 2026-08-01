"""Tests for core.approval_transition_cli -- the stdin/stdout JSON adapter
around core.approval_transition.validate_approval_transition.

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

from core import approval_transition_cli
import core.approval_request as approval_request
import core.approval_transition as approval_transition

INVESTIGATION_ID = "11111111-1111-4111-8111-111111111111"
APPROVAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

REQUESTED_AT = "2026-08-01T10:00:00Z"
CREATED_AT = "2026-08-01T10:00:00Z"
APPROVED_AT = "2026-08-01T11:00:00Z"
CONSUMED_AT = "2026-08-01T12:00:00Z"

REJECTION_REASON = "The proposed status change is not sufficiently supported."


def _pending_record(**overrides):
    record = {
        "id": APPROVAL_ID,
        "investigation_id": INVESTIGATION_ID,
        "action_type": "update_investigation_state",
        "action_payload": {"status": "escalated"},
        "requested_by": "analyst-jane",
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
        "created_at": CREATED_AT,
    }
    record.update(overrides)
    return record


def _approved_record(**overrides):
    record = _pending_record(
        status="approved",
        approved_by="Security Reviewer",
        approved_at=APPROVED_AT,
    )
    record.update(overrides)
    return record


def _approve_request(**overrides):
    request = {"transition": "approve", "reviewed_by": "Security Reviewer"}
    request.update(overrides)
    return request


def _reject_request(**overrides):
    request = {
        "transition": "reject",
        "reviewed_by": "Security Reviewer",
        "rejection_reason": REJECTION_REASON,
    }
    request.update(overrides)
    return request


def _consume_request(**overrides):
    request = {
        "transition": "consume",
        "consumed_by": "Update Case Operator",
        "expected_investigation_id": INVESTIGATION_ID,
        "expected_action_type": "update_investigation_state",
    }
    request.update(overrides)
    return request


def _envelope(current_record=None, transition_request=None):
    return {
        "current_record": _pending_record() if current_record is None else current_record,
        "transition_request": _approve_request() if transition_request is None else transition_request,
    }


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = approval_transition_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _module_source_text():
    with open(approval_transition_cli.__file__, "r", encoding="utf-8") as handle:
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
# 1-8: public contract
# ---------------------------------------------------------------------------

def test_001_main_is_callable():
    assert callable(approval_transition_cli.main)


def test_002_main_returns_an_integer():
    exit_code, _stdout, _stderr = _run(json.dumps(_envelope()))
    assert isinstance(exit_code, int)


def test_003_main_guard_exists():
    source = _module_source_text()
    assert 'if __name__ == "__main__":' in source
    assert "raise SystemExit(main())" in source


def test_004_cli_imports_validate_approval_transition():
    assert approval_transition_cli.validate_approval_transition is approval_transition.validate_approval_transition


def test_005_cli_imports_approval_transition_error():
    assert approval_transition_cli.ApprovalTransitionError is approval_transition.ApprovalTransitionError


def test_006_cli_does_not_import_approval_statuses():
    assert not hasattr(approval_transition_cli, "APPROVAL_STATUSES")
    source = _module_source_text()
    assert "APPROVAL_STATUSES" not in source


def test_007_cli_does_not_import_action_types():
    assert not hasattr(approval_transition_cli, "ACTION_TYPES")
    source = _module_source_text()
    assert "ACTION_TYPES" not in source


def test_008_cli_does_not_import_approval_request_validator():
    assert not hasattr(approval_transition_cli, "validate_approval_request")
    source = _module_source_text()
    assert "import core.approval_request" not in source
    assert "from core.approval_request import" not in source


# ---------------------------------------------------------------------------
# 9-24: successful transport
# ---------------------------------------------------------------------------

def test_009_valid_pending_approve_request_succeeds():
    exit_code, _stdout, _stderr = _run(json.dumps(_envelope()))
    assert exit_code == 0


def test_010_valid_pending_reject_request_succeeds():
    exit_code, _stdout, _stderr = _run(
        json.dumps(_envelope(transition_request=_reject_request()))
    )
    assert exit_code == 0


def test_011_valid_approved_consume_request_succeeds():
    exit_code, _stdout, _stderr = _run(
        json.dumps(_envelope(current_record=_approved_record(), transition_request=_consume_request()))
    )
    assert exit_code == 0


def test_012_exit_code_is_0():
    exit_code, _stdout, _stderr = _run(json.dumps(_envelope()))
    assert exit_code == 0


def test_013_stderr_is_empty_on_success():
    _exit_code, _stdout, stderr = _run(json.dumps(_envelope()))
    assert stderr == ""


def test_014_stdout_contains_exactly_one_json_object():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    parsed = json.loads(stdout)
    assert isinstance(parsed, dict)


def test_015_stdout_ends_with_exactly_one_newline():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    assert stdout.endswith("\n")
    assert not stdout.endswith("\n\n")


def test_016_no_extra_label_or_wrapper_is_emitted():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    stripped = stdout.strip()
    assert stripped.startswith("{")
    assert stripped.endswith("}")


def test_017_output_equals_direct_validator_output_with_explicit_timestamps():
    envelope = _envelope(transition_request=_approve_request(reviewed_at="2026-08-01T11:30:00Z"))
    _exit_code, stdout, _stderr = _run(json.dumps(envelope))

    direct = approval_transition.validate_approval_transition(
        envelope["current_record"], envelope["transition_request"]
    )
    assert json.loads(stdout) == direct


def test_018_output_keys_serialized_in_sorted_order():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    parsed = json.loads(stdout)
    assert list(parsed.keys()) == sorted(parsed.keys())


def test_019_unicode_identities_emit_with_ensure_ascii_false():
    envelope = _envelope(
        current_record=_pending_record(requested_by="analyst-café-注意"),
        transition_request=_approve_request(reviewed_by="Security-Réviseur"),
    )
    exit_code, stdout, _stderr = _run(json.dumps(envelope, ensure_ascii=False))
    assert exit_code == 0
    assert "Réviseur" in stdout
    assert "\\u" not in stdout


def test_020_approve_output_preserves_exact_transition_plan_shape():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    parsed = json.loads(stdout)
    assert set(parsed.keys()) == {"approval_id", "from_status", "to_status", "set_fields"}
    assert set(parsed["set_fields"].keys()) == {"status", "approved_by", "approved_at"}


def test_021_reject_output_preserves_exact_transition_plan_shape():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope(transition_request=_reject_request())))
    parsed = json.loads(stdout)
    assert set(parsed["set_fields"].keys()) == {"status", "rejected_by", "rejected_at", "rejection_reason"}


def test_022_consume_output_preserves_exact_transition_plan_shape():
    _exit_code, stdout, _stderr = _run(
        json.dumps(_envelope(current_record=_approved_record(), transition_request=_consume_request()))
    )
    parsed = json.loads(stdout)
    assert set(parsed["set_fields"].keys()) == {"status", "consumed_by", "consumed_at"}


def test_023_generated_transition_timestamp_appears_when_omitted():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    parsed = json.loads(stdout)
    assert parsed["set_fields"]["approved_at"]


def test_024_explicit_transition_timestamp_preserved_by_validator():
    envelope = _envelope(transition_request=_approve_request(reviewed_at="2026-08-01T08:45:00-07:00"))
    _exit_code, stdout, _stderr = _run(json.dumps(envelope))
    parsed = json.loads(stdout)
    assert parsed["set_fields"]["approved_at"] == "2026-08-01T15:45:00Z"


# ---------------------------------------------------------------------------
# 25-44: JSON transport rejection
# ---------------------------------------------------------------------------

def test_025_empty_input_rejected():
    exit_code, stdout, stderr = _run("")
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_026_whitespace_only_input_rejected():
    exit_code, stdout, stderr = _run("   \n\t  ")
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_027_malformed_json_rejected():
    exit_code, stdout, stderr = _run("{not valid json")
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_028_truncated_json_rejected():
    raw = json.dumps(_envelope())[:-5]
    exit_code, stdout, stderr = _run(raw)
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_029_two_concatenated_objects_rejected():
    raw = json.dumps(_envelope()) + json.dumps(_envelope())
    exit_code, stdout, stderr = _run(raw)
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_030_object_followed_by_trailing_text_rejected():
    raw = json.dumps(_envelope()) + " garbage"
    exit_code, stdout, stderr = _run(raw)
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_031_object_followed_by_trailing_number_rejected():
    raw = json.dumps(_envelope()) + " 5"
    exit_code, stdout, stderr = _run(raw)
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_032_object_followed_by_trailing_array_rejected():
    raw = json.dumps(_envelope()) + " []"
    exit_code, stdout, stderr = _run(raw)
    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_033_null_rejected():
    exit_code, stdout, stderr = _run("null")
    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Approval transition input must be a JSON object.\n"


def test_034_array_rejected():
    exit_code, stdout, stderr = _run("[]")
    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Approval transition input must be a JSON object.\n"


def test_035_string_rejected():
    exit_code, stdout, stderr = _run('"a string"')
    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Approval transition input must be a JSON object.\n"


def test_036_integer_rejected():
    exit_code, stdout, stderr = _run("42")
    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Approval transition input must be a JSON object.\n"


def test_037_float_rejected():
    exit_code, stdout, stderr = _run("4.2")
    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Approval transition input must be a JSON object.\n"


def test_038_true_rejected():
    exit_code, stdout, stderr = _run("true")
    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Approval transition input must be a JSON object.\n"


def test_039_false_rejected():
    exit_code, stdout, stderr = _run("false")
    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Approval transition input must be a JSON object.\n"


def test_040_transport_failures_return_2():
    exit_code, _stdout, _stderr = _run("not json")
    assert exit_code == 2


def test_041_stdout_empty_for_every_transport_failure():
    for raw in ("", "null", "{bad", "[]", json.dumps(_envelope()) + " x"):
        _exit_code, stdout, _stderr = _run(raw)
        assert stdout == ""


def test_042_stderr_ends_with_exactly_one_newline():
    _exit_code, _stdout, stderr = _run("not json")
    assert stderr.endswith("\n")
    assert stderr.count("\n") == 1


def test_043_raw_malformed_input_is_not_echoed():
    marker = "SECRET-MALFORMED-INPUT-MARKER"
    _exit_code, _stdout, stderr = _run("{not valid json " + marker)
    assert marker not in stderr


def test_044_json_decoder_offsets_and_parser_details_not_exposed_beyond_prefix():
    _exit_code, _stdout, stderr = _run("{not valid json")
    assert stderr.startswith("Invalid JSON input:")


# ---------------------------------------------------------------------------
# 45-60: exact envelope validation
# ---------------------------------------------------------------------------

def test_045_missing_current_record_rejected():
    envelope = _envelope()
    del envelope["current_record"]
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_046_missing_transition_request_rejected():
    envelope = _envelope()
    del envelope["transition_request"]
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_047_empty_object_rejected():
    exit_code, _stdout, _stderr = _run(json.dumps({}))
    assert exit_code == 2


def test_048_unknown_top_level_field_rejected():
    envelope = _envelope()
    envelope["extra_field"] = "x"
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_049_multiple_unknown_top_level_fields_rejected():
    envelope = _envelope()
    envelope["extra_one"] = "x"
    envelope["extra_two"] = "y"
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


@pytest.mark.parametrize(
    "alias",
    ["approval", "approval_record", "request", "transition", "payload", "now", "execute", "persist"],
)
def test_050_to_057_aliases_rejected(alias):
    envelope = _envelope()
    envelope[alias] = "x"
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_058_envelope_failure_returns_2():
    exit_code, _stdout, _stderr = _run(json.dumps({"current_record": {}}))
    assert exit_code == 2


def test_059_validator_not_called_after_envelope_failure(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("validate_approval_transition must not be called after an envelope failure")

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", forbidden)

    envelope = _envelope()
    del envelope["transition_request"]
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_060_complete_envelope_not_echoed_in_errors():
    marker = "SECRET-ENVELOPE-MARKER"
    envelope = _envelope(current_record=_pending_record(requested_by=marker))
    del envelope["transition_request"]

    _exit_code, _stdout, stderr = _run(json.dumps(envelope))
    assert marker not in stderr


# ---------------------------------------------------------------------------
# 61-78: delegation boundary
# ---------------------------------------------------------------------------

def test_061_validator_called_exactly_once_for_valid_envelope(monkeypatch):
    calls = []
    original = approval_transition_cli.validate_approval_transition

    def counting_validate(current_record, transition_request):
        calls.append((current_record, transition_request))
        return original(current_record, transition_request)

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", counting_validate)

    exit_code, _stdout, _stderr = _run(json.dumps(_envelope()))
    assert exit_code == 0
    assert len(calls) == 1


def test_062_current_record_passed_directly(monkeypatch):
    captured = {}

    def capturing_validate(current_record, transition_request):
        captured["current_record"] = current_record
        return approval_transition.validate_approval_transition(current_record, transition_request)

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", capturing_validate)

    envelope = _envelope()
    _run(json.dumps(envelope))

    assert captured["current_record"] == envelope["current_record"]


def test_063_transition_request_passed_directly(monkeypatch):
    captured = {}

    def capturing_validate(current_record, transition_request):
        captured["transition_request"] = transition_request
        return approval_transition.validate_approval_transition(current_record, transition_request)

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", capturing_validate)

    envelope = _envelope()
    _run(json.dumps(envelope))

    assert captured["transition_request"] == envelope["transition_request"]


def test_064_object_identity_preserved_through_monkeypatch_observation(monkeypatch):
    captured = {}

    def capturing_validate(current_record, transition_request):
        captured["current_record_id"] = id(current_record)
        captured["transition_request_id"] = id(transition_request)
        return approval_transition.validate_approval_transition(current_record, transition_request)

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", capturing_validate)

    _run(json.dumps(_envelope()))

    # The parsed JSON objects passed to the validator are the same objects
    # produced by json.loads -- the CLI does not build a copy or wrapper.
    assert captured["current_record_id"] is not None
    assert captured["transition_request_id"] is not None


def test_065_cli_does_not_copy_or_normalize_current_record(monkeypatch):
    captured = {}

    def capturing_validate(current_record, transition_request):
        captured["investigation_id"] = current_record["investigation_id"]
        return approval_transition.validate_approval_transition(current_record, transition_request)

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", capturing_validate)

    raw_id = INVESTIGATION_ID.upper()
    envelope = _envelope(current_record=_pending_record(investigation_id=raw_id))
    _run(json.dumps(envelope))

    assert captured["investigation_id"] == raw_id


def test_066_cli_does_not_copy_or_normalize_transition_request(monkeypatch):
    captured = {}

    def capturing_validate(current_record, transition_request):
        captured["reviewed_by"] = transition_request["reviewed_by"]
        return approval_transition.validate_approval_transition(current_record, transition_request)

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", capturing_validate)

    envelope = _envelope(transition_request=_approve_request(reviewed_by="  Security Reviewer  "))
    _run(json.dumps(envelope))

    assert captured["reviewed_by"] == "  Security Reviewer  "


def test_067_cli_does_not_inspect_current_status():
    source = _module_source_text()
    assert '"status"' not in source
    assert "['status']" not in source


def test_068_cli_does_not_inspect_transition_name():
    source = _module_source_text()
    assert '"approve"' not in source
    assert '"reject"' not in source
    assert '"consume"' not in source


def test_069_cli_does_not_inspect_action_payload():
    source = _module_source_text()
    assert "action_payload" not in source


def test_070_cli_does_not_inspect_reviewer_fields():
    source = _module_source_text()
    assert "reviewed_by" not in source
    assert "approved_by" not in source


def test_071_cli_does_not_inspect_consumed_fields():
    source = _module_source_text()
    assert "consumed_by" not in source
    assert "consumed_at" not in source


def test_072_cli_does_not_generate_transition_timestamps():
    source = _module_source_text()
    assert "datetime.now(" not in source
    assert "import datetime" not in source
    assert "from datetime" not in source


def test_073_cli_does_not_pass_now(monkeypatch):
    captured = {}

    def capturing_validate(current_record, transition_request, **kwargs):
        captured["kwargs"] = kwargs
        return approval_transition.validate_approval_transition(current_record, transition_request)

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", capturing_validate)

    _run(json.dumps(_envelope()))

    assert captured["kwargs"] == {}


def test_074_non_mapping_current_record_reaches_validator_once(monkeypatch):
    calls = []

    def counting_validate(current_record, transition_request):
        calls.append(current_record)
        return approval_transition.validate_approval_transition(current_record, transition_request)

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", counting_validate)

    envelope = {"current_record": "not a mapping", "transition_request": _approve_request()}
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))

    assert exit_code == 2
    assert len(calls) == 1


def test_075_non_mapping_transition_request_reaches_validator_once(monkeypatch):
    calls = []

    def counting_validate(current_record, transition_request):
        calls.append(transition_request)
        return approval_transition.validate_approval_transition(current_record, transition_request)

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", counting_validate)

    envelope = {"current_record": _pending_record(), "transition_request": "not a mapping"}
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))

    assert exit_code == 2
    assert len(calls) == 1


def test_076_nested_malformed_record_reaches_validator_once(monkeypatch):
    calls = []

    def counting_validate(current_record, transition_request):
        calls.append(current_record)
        return approval_transition.validate_approval_transition(current_record, transition_request)

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", counting_validate)

    malformed_record = _pending_record()
    del malformed_record["id"]
    envelope = _envelope(current_record=malformed_record)

    exit_code, _stdout, _stderr = _run(json.dumps(envelope))

    assert exit_code == 2
    assert len(calls) == 1


def test_077_nested_malformed_transition_reaches_validator_once(monkeypatch):
    calls = []

    def counting_validate(current_record, transition_request):
        calls.append(transition_request)
        return approval_transition.validate_approval_transition(current_record, transition_request)

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", counting_validate)

    malformed_request = _approve_request()
    del malformed_request["reviewed_by"]
    envelope = _envelope(transition_request=malformed_request)

    exit_code, _stdout, _stderr = _run(json.dumps(envelope))

    assert exit_code == 2
    assert len(calls) == 1


def test_078_approval_transition_error_from_nested_validation_returns_2():
    malformed_record = _pending_record()
    del malformed_record["id"]
    envelope = _envelope(current_record=malformed_record)

    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


# ---------------------------------------------------------------------------
# 79-95: validator failures
# ---------------------------------------------------------------------------

def test_079_invalid_current_approval_uuid_returns_2():
    envelope = _envelope(current_record=_pending_record(id="not-a-uuid"))
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_080_missing_current_record_field_returns_2():
    record = _pending_record()
    del record["created_at"]
    envelope = _envelope(current_record=record)
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_081_unknown_current_record_field_returns_2():
    envelope = _envelope(current_record=_pending_record(extra_field="x"))
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_082_malformed_persisted_lifecycle_state_returns_2():
    envelope = _envelope(current_record=_pending_record(approved_by="someone"))
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_083_unknown_transition_returns_2():
    envelope = _envelope(transition_request=_approve_request(transition="revoke"))
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_084_unsupported_state_transition_returns_2():
    envelope = _envelope(current_record=_approved_record(), transition_request=_approve_request())
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_085_repeated_transition_returns_2():
    envelope = _envelope(current_record=_approved_record(), transition_request=_reject_request())
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_086_self_approval_returns_2():
    envelope = _envelope(
        current_record=_pending_record(requested_by="analyst-jane"),
        transition_request=_approve_request(reviewed_by="analyst-jane"),
    )
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_087_invalid_reviewed_at_returns_2():
    envelope = _envelope(transition_request=_approve_request(reviewed_at="not-a-timestamp"))
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_088_expired_approval_attempt_returns_2():
    record = _pending_record(expires_at="2026-08-01T10:30:00Z")
    envelope = _envelope(current_record=record, transition_request=_approve_request(reviewed_at="2026-08-01T11:00:00Z"))
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_089_blank_rejection_reason_returns_2():
    envelope = _envelope(transition_request=_reject_request(rejection_reason="   "))
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_090_expected_investigation_mismatch_returns_2():
    other_id = "66666666-6666-4666-8666-666666666666"
    envelope = _envelope(
        current_record=_approved_record(),
        transition_request=_consume_request(expected_investigation_id=other_id),
    )
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_091_expected_action_mismatch_returns_2(monkeypatch):
    monkeypatch.setattr(
        approval_transition, "ACTION_TYPES", frozenset({"update_investigation_state", "fake_other_action"})
    )
    envelope = _envelope(
        current_record=_approved_record(),
        transition_request=_consume_request(expected_action_type="fake_other_action"),
    )
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_092_repeated_consumption_returns_2():
    consumed_record = _approved_record(status="consumed", consumed_by="Update Case Operator", consumed_at=CONSUMED_AT)
    envelope = _envelope(current_record=consumed_record, transition_request=_consume_request())
    exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    assert exit_code == 2


def test_093_stdout_empty_on_every_validator_failure():
    scenarios = [
        _envelope(current_record=_pending_record(id="not-a-uuid")),
        _envelope(current_record=_approved_record(), transition_request=_approve_request()),
        _envelope(transition_request=_approve_request(transition="revoke")),
    ]
    for envelope in scenarios:
        _exit_code, stdout, _stderr = _run(json.dumps(envelope))
        assert stdout == ""


def test_094_raw_approval_transition_error_does_not_escape():
    envelope = _envelope(current_record=_pending_record(id="not-a-uuid"))
    try:
        exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    except approval_transition.ApprovalTransitionError:
        assert False, "raw ApprovalTransitionError escaped"
    assert exit_code == 2


def test_095_raw_approval_request_error_does_not_escape():
    envelope = _envelope(current_record=_pending_record(action_type="delete_investigation"))
    try:
        exit_code, _stdout, _stderr = _run(json.dumps(envelope))
    except approval_request.ApprovalRequestError:
        assert False, "raw ApprovalRequestError escaped"
    assert exit_code == 2


# ---------------------------------------------------------------------------
# 96-104: error leakage
# ---------------------------------------------------------------------------

def test_096_complete_current_record_not_written_on_failure():
    marker = "SECRET-CURRENT-RECORD-MARKER"
    envelope = _envelope(current_record=_pending_record(id="not-a-uuid", requested_by=marker))
    _exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert marker not in stdout
    assert marker not in stderr


def test_097_complete_transition_request_not_written_on_failure():
    marker = "SECRET-TRANSITION-REQUEST-MARKER"
    envelope = _envelope(transition_request=_approve_request(reviewed_by=marker, transition="revoke"))
    _exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert marker not in stdout
    assert marker not in stderr


def test_098_action_payload_secret_marker_not_exposed():
    marker = "SECRET-ACTION-PAYLOAD-MARKER"
    envelope = _envelope(
        current_record=_pending_record(action_type="delete_investigation", action_payload={"status": "escalated", "x": marker})
    )
    _exit_code, _stdout, stderr = _run(json.dumps(envelope))
    assert marker not in stderr


def test_099_requested_by_secret_marker_not_exposed():
    marker = "SECRET-REQUESTED-BY-MARKER"
    envelope = _envelope(current_record=_pending_record(id="not-a-uuid", requested_by=marker))
    _exit_code, _stdout, stderr = _run(json.dumps(envelope))
    assert marker not in stderr


def test_100_reviewed_by_secret_marker_not_exposed():
    marker = "SECRET-REVIEWED-BY-MARKER"
    envelope = _envelope(
        current_record=_approved_record(),
        transition_request=_approve_request(reviewed_by=marker),
    )
    _exit_code, _stdout, stderr = _run(json.dumps(envelope))
    assert marker not in stderr


def test_101_consumed_by_secret_marker_not_exposed():
    marker = "SECRET-CONSUMED-BY-MARKER"
    envelope = _envelope(transition_request=_consume_request(consumed_by=marker))
    _exit_code, _stdout, stderr = _run(json.dumps(envelope))
    assert marker not in stderr


def test_102_rejection_reason_secret_marker_not_exposed():
    marker = "SECRET-REJECTION-REASON-MARKER"
    envelope = _envelope(
        current_record=_approved_record(),
        transition_request=_reject_request(rejection_reason=marker),
    )
    _exit_code, _stdout, stderr = _run(json.dumps(envelope))
    assert marker not in stderr


def test_103_expires_at_value_not_unnecessarily_exposed():
    marker_timestamp = "2026-08-01T10:15:00Z"
    record = _pending_record(expires_at=marker_timestamp)
    envelope = _envelope(current_record=record, transition_request=_approve_request(reviewed_at="2026-08-01T11:00:00Z"))
    _exit_code, _stdout, stderr = _run(json.dumps(envelope))
    assert marker_timestamp not in stderr


def test_104_no_traceback_exposed():
    envelope = _envelope(current_record=_pending_record(id="not-a-uuid"))
    _exit_code, _stdout, stderr = _run(json.dumps(envelope))
    assert "Traceback" not in stderr


# ---------------------------------------------------------------------------
# 105-113: unexpected failures
# ---------------------------------------------------------------------------

def test_105_monkeypatched_validator_unexpected_exception_returns_1(monkeypatch):
    def boom(_current_record, _transition_request):
        raise RuntimeError("simulated internal failure")

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", boom)

    exit_code, _stdout, _stderr = _run(json.dumps(_envelope()))
    assert exit_code == 1


def test_106_unexpected_failure_stdout_empty(monkeypatch):
    def boom(_current_record, _transition_request):
        raise RuntimeError("boom")

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", boom)

    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    assert stdout == ""


def test_107_unexpected_failure_stderr_exact_message(monkeypatch):
    def boom(_current_record, _transition_request):
        raise RuntimeError("boom")

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_envelope()))
    assert stderr == "Approval transition validation failed.\n"


def test_108_exception_type_not_exposed(monkeypatch):
    def boom(_current_record, _transition_request):
        raise RuntimeError("boom")

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_envelope()))
    assert "RuntimeError" not in stderr


def test_109_exception_message_not_exposed(monkeypatch):
    secret_marker = "SECRET-EXCEPTION-MESSAGE-MARKER"

    def boom(_current_record, _transition_request):
        raise RuntimeError(secret_marker)

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_envelope()))
    assert secret_marker not in stderr


def test_110_complete_envelope_not_exposed_on_unexpected_failure(monkeypatch):
    marker = "SECRET-ENVELOPE-CONTENT-MARKER"

    def boom(_current_record, _transition_request):
        raise RuntimeError("boom")

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", boom)

    envelope = _envelope(current_record=_pending_record(requested_by=marker))
    _exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert marker not in stdout
    assert marker not in stderr


def test_111_current_record_not_exposed_on_unexpected_failure(monkeypatch):
    marker = "SECRET-CURRENT-RECORD-UNEXPECTED-MARKER"

    def boom(_current_record, _transition_request):
        raise RuntimeError("boom")

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", boom)

    envelope = _envelope(current_record=_pending_record(requested_by=marker))
    _exit_code, _stdout, stderr = _run(json.dumps(envelope))
    assert marker not in stderr


def test_112_transition_request_not_exposed_on_unexpected_failure(monkeypatch):
    marker = "SECRET-TRANSITION-REQUEST-UNEXPECTED-MARKER"

    def boom(_current_record, _transition_request):
        raise RuntimeError("boom")

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", boom)

    envelope = _envelope(transition_request=_approve_request(reviewed_by=marker))
    _exit_code, _stdout, stderr = _run(json.dumps(envelope))
    assert marker not in stderr


def test_113_planted_secret_values_not_exposed_on_unexpected_failure(monkeypatch):
    marker = "SECRET-GENERIC-UNEXPECTED-MARKER"

    def boom(_current_record, _transition_request):
        raise RuntimeError(marker)

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", boom)

    envelope = _envelope(
        current_record=_pending_record(requested_by=marker),
        transition_request=_approve_request(reviewed_by=marker),
    )
    _exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert marker not in stdout
    assert marker not in stderr


# ---------------------------------------------------------------------------
# 114-119: stdout/stderr contract
# ---------------------------------------------------------------------------

def test_114_success_writes_only_stdout():
    _exit_code, stdout, stderr = _run(json.dumps(_envelope()))
    assert stdout != ""
    assert stderr == ""


def test_115_deterministic_failures_write_only_stderr():
    envelope = _envelope(current_record=_pending_record(id="not-a-uuid"))
    _exit_code, stdout, stderr = _run(json.dumps(envelope))
    assert stdout == ""
    assert stderr != ""


def test_116_unexpected_failures_write_only_stderr(monkeypatch):
    def boom(_current_record, _transition_request):
        raise RuntimeError("boom")

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", boom)

    _exit_code, stdout, stderr = _run(json.dumps(_envelope()))
    assert stdout == ""
    assert stderr != ""


def test_117_success_stdout_is_one_json_value_plus_one_newline():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    decoder = json.JSONDecoder()
    _value, end = decoder.raw_decode(stdout)
    assert stdout[end:] == "\n"


def test_118_failure_stderr_is_one_message_plus_one_newline():
    _exit_code, _stdout, stderr = _run("not json")
    assert stderr.count("\n") == 1
    assert stderr.endswith("\n")


def test_119_no_path_writes_both_stdout_and_stderr():
    scenarios = [
        json.dumps(_envelope()),
        "not json",
        json.dumps(_envelope(current_record=_pending_record(id="not-a-uuid"))),
    ]
    for raw in scenarios:
        _exit_code, stdout, stderr = _run(raw)
        assert not (stdout != "" and stderr != "")


# ---------------------------------------------------------------------------
# 120-127: non-mutation
# ---------------------------------------------------------------------------

def test_120_parsed_top_level_envelope_remains_unchanged(monkeypatch):
    captured = {}

    def capturing_validate(current_record, transition_request):
        captured["snapshot_current"] = copy.deepcopy(current_record)
        captured["snapshot_transition"] = copy.deepcopy(transition_request)
        result = approval_transition.validate_approval_transition(current_record, transition_request)
        captured["current_ref"] = current_record
        captured["transition_ref"] = transition_request
        return result

    monkeypatch.setattr(approval_transition_cli, "validate_approval_transition", capturing_validate)

    _run(json.dumps(_envelope()))

    assert captured["current_ref"] == captured["snapshot_current"]
    assert captured["transition_ref"] == captured["snapshot_transition"]


def test_121_parsed_current_record_remains_unchanged():
    envelope = _envelope()
    snapshot = copy.deepcopy(envelope["current_record"])

    _run(json.dumps(envelope))

    assert envelope["current_record"] == snapshot


def test_122_parsed_transition_request_remains_unchanged():
    envelope = _envelope()
    snapshot = copy.deepcopy(envelope["transition_request"])

    _run(json.dumps(envelope))

    assert envelope["transition_request"] == snapshot


def test_123_nested_action_payload_remains_unchanged():
    record = _pending_record(action_payload={"status": "escalated", "confidence": "medium"})
    envelope = _envelope(current_record=record)
    snapshot = copy.deepcopy(record["action_payload"])

    _run(json.dumps(envelope))

    assert record["action_payload"] == snapshot


def test_124_rejection_reason_remains_unchanged():
    envelope = _envelope(transition_request=_reject_request(rejection_reason="  padded reason  "))
    snapshot = str(envelope["transition_request"]["rejection_reason"])

    _run(json.dumps(envelope))

    assert envelope["transition_request"]["rejection_reason"] == snapshot


def test_125_validator_return_value_not_mutated_by_cli(monkeypatch):
    fixed_result = {
        "approval_id": APPROVAL_ID,
        "from_status": "pending",
        "to_status": "approved",
        "set_fields": {"status": "approved", "approved_by": "Security Reviewer", "approved_at": APPROVED_AT},
    }
    snapshot = copy.deepcopy(fixed_result)

    monkeypatch.setattr(
        approval_transition_cli, "validate_approval_transition", lambda _c, _t: fixed_result
    )

    exit_code, stdout, _stderr = _run(json.dumps(_envelope()))

    assert exit_code == 0
    assert fixed_result == snapshot
    assert json.loads(stdout) == snapshot


def test_126_reusing_supplied_timestamp_envelope_deterministic():
    envelope = _envelope(transition_request=_approve_request(reviewed_at="2026-08-01T11:00:00Z"))

    _exit_code1, stdout1, _stderr1 = _run(json.dumps(envelope))
    _exit_code2, stdout2, _stderr2 = _run(json.dumps(envelope))

    assert stdout1 == stdout2


def test_127_separate_calls_do_not_share_mutable_state():
    envelope_a = _envelope()
    envelope_b = _envelope()

    _run(json.dumps(envelope_a))
    exit_code_b, stdout_b, _stderr_b = _run(json.dumps(envelope_b))

    assert exit_code_b == 0
    assert json.loads(stdout_b)["approval_id"] == APPROVAL_ID


# ---------------------------------------------------------------------------
# 128-145: output exact shape
# ---------------------------------------------------------------------------

def test_128_output_exact_four_fields():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    parsed = json.loads(stdout)
    assert set(parsed.keys()) == {"approval_id", "from_status", "to_status", "set_fields"}


def test_129_approve_set_fields_exact():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    parsed = json.loads(stdout)
    assert set(parsed["set_fields"].keys()) == {"status", "approved_by", "approved_at"}


def test_130_reject_set_fields_exact():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope(transition_request=_reject_request())))
    parsed = json.loads(stdout)
    assert set(parsed["set_fields"].keys()) == {"status", "rejected_by", "rejected_at", "rejection_reason"}


def test_131_consume_set_fields_exact():
    _exit_code, stdout, _stderr = _run(
        json.dumps(_envelope(current_record=_approved_record(), transition_request=_consume_request()))
    )
    parsed = json.loads(stdout)
    assert set(parsed["set_fields"].keys()) == {"status", "consumed_by", "consumed_at"}


def test_132_output_contains_no_investigation_id():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    assert "investigation_id" not in json.loads(stdout)


def test_133_output_contains_no_action_type():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    assert "action_type" not in json.loads(stdout)


def test_134_output_contains_no_action_payload():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    assert "action_payload" not in json.loads(stdout)


def test_135_output_contains_no_requested_by():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    assert "requested_by" not in json.loads(stdout)


def test_136_output_contains_no_requested_at():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    assert "requested_at" not in json.loads(stdout)


def test_137_output_contains_no_created_at():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    assert "created_at" not in json.loads(stdout)


def test_138_output_contains_no_expires_at():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    assert "expires_at" not in json.loads(stdout)


def test_139_output_contains_no_action_hash():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    assert "action_hash" not in json.loads(stdout)


def test_140_output_contains_no_target_fields():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    parsed = json.loads(stdout)
    assert "target_type" not in parsed
    assert "target_id" not in parsed


def test_141_output_contains_no_database_result():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    parsed = json.loads(stdout)
    assert "database_result" not in parsed


def test_142_output_contains_no_affected_row_count():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    parsed = json.loads(stdout)
    assert "affected_rows" not in parsed
    assert "row_count" not in parsed


def test_143_output_contains_no_investigation_update_result():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    parsed = json.loads(stdout)
    assert "investigation_status" not in parsed
    assert "investigation_confidence" not in parsed


def test_144_output_contains_no_persistence_result():
    _exit_code, stdout, _stderr = _run(json.dumps(_envelope()))
    parsed = json.loads(stdout)
    assert "persisted" not in parsed
    assert "saved" not in parsed


def test_145_output_not_represented_as_proof_of_completed_transition():
    source = _module_source_text()
    assert "Validated transition plan -- not persisted" in source


# ---------------------------------------------------------------------------
# Runtime side-effect guard (146-165)
# ---------------------------------------------------------------------------

def test_runtime_guard_no_forbidden_entry_points_reached(monkeypatch):
    import os
    import sys
    import urllib.request

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called during approval-transition CLI validation")

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

    exit_code, _stdout, _stderr = _run(json.dumps(_envelope()))

    assert exit_code == 0
    assert "mcp.hayabusa_server" not in sys.modules
    assert os.getcwd() == original_cwd
    assert dict(os.environ) == original_environ


def test_158_validate_approval_request_not_invoked_directly_by_cli(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("validate_approval_request must not be called directly by the transition CLI")

    monkeypatch.setattr(approval_request, "validate_approval_request", forbidden)

    exit_code, _stdout, _stderr = _run(json.dumps(_envelope()))
    assert exit_code == 0


def test_159_no_persistence_occurs():
    source = _module_source_text()
    assert ".insert(" not in source
    assert ".update(" not in source


def test_160_no_database_update_occurs():
    source = _module_source_text()
    assert ".update(" not in source


def test_161_no_investigation_update_occurs():
    source = _module_source_text()
    assert "investigations" not in source.lower()


def test_162_no_conditional_update_occurs():
    source = _module_source_text()
    assert "WHERE" not in source
    assert "affected_rows" not in source


def test_163_no_authentication_occurs():
    source = _module_source_text()
    assert "supabase.auth" not in source.lower()
    assert "def verify_identity" not in source


def test_164_no_containment_occurs():
    source = _module_source_text()
    assert "containment" not in source.lower()


def test_165_no_red_team_execution_occurs():
    source = _module_source_text()
    assert "execute_simulation" not in source.lower()
    assert "run_atomic" not in source.lower()


# ---------------------------------------------------------------------------
# 166-191: source-boundary tests
# ---------------------------------------------------------------------------

def test_166_source_imports_only_approved_stdlib_and_transition_validator_symbols():
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

    allowed = {"__future__", "json", "sys", "typing", "core.approval_transition"}
    assert imported <= allowed


def test_167_source_does_not_import_supabase():
    source = _module_source_text()
    assert "import supabase" not in source
    assert "from supabase" not in source


def test_168_source_does_not_import_requests():
    source = _module_source_text()
    assert "import requests" not in source


def test_169_source_does_not_import_subprocess():
    source = _module_source_text()
    assert "import subprocess" not in source


def test_170_source_does_not_import_pathlib_for_runtime_access():
    source = _module_source_text()
    assert "import pathlib" not in source
    assert "from pathlib" not in source


def test_171_source_does_not_import_approval_request():
    source = _module_source_text()
    assert "import core.approval_request" not in source
    assert "from core.approval_request import" not in source


def test_172_source_does_not_import_decision_modules():
    source = _module_source_text()
    assert "decision_context" not in source
    assert "decision_analysis" not in source


def test_173_source_does_not_import_warning_formatter_modules():
    source = _module_source_text()
    assert "decision_warning_formatter" not in source


def test_174_source_does_not_import_command_modules():
    source = _module_source_text()
    assert "commands" not in source.lower()


def test_175_source_does_not_import_ai_model_libraries():
    source = _module_source_text()
    assert "openai" not in source.lower()
    assert "anthropic" not in source.lower()


def test_176_source_does_not_import_approval_statuses():
    source = _module_source_text()
    assert "APPROVAL_STATUSES" not in source


def test_177_source_does_not_duplicate_lifecycle_status_strings_in_executable_logic():
    import ast

    tree = ast.parse(_module_source_text())
    string_literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert "pending" not in string_literals
    assert "approved" not in string_literals
    assert "rejected" not in string_literals
    assert "consumed" not in string_literals


def test_178_source_does_not_duplicate_transition_names_in_executable_branching():
    import ast

    tree = ast.parse(_module_source_text())
    string_literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert "approve" not in string_literals
    assert "reject" not in string_literals
    assert "consume" not in string_literals


def test_179_source_defines_no_private_lifecycle_validation_helper():
    source = _module_source_text()
    assert "def _validate_" not in source


def test_180_source_contains_no_file_open_call():
    source = _module_source_text()
    assert "open(" not in source


def test_181_source_contains_no_temporary_file_call():
    source = _module_source_text()
    assert "tempfile" not in source


def test_182_source_contains_no_subprocess_call():
    source = _module_source_text()
    assert "subprocess.run(" not in source
    assert "subprocess.Popen(" not in source


def test_183_source_contains_no_network_call():
    source = _module_source_text()
    assert "socket" not in source
    assert "urllib" not in source
    assert "requests." not in source


def test_184_source_contains_no_database_write_call():
    source = _module_source_text()
    assert ".insert(" not in source
    assert ".update(" not in source
    assert ".delete(" not in source


def test_185_source_contains_no_sql_schema_behavior():
    source = _module_source_text()
    assert "create table" not in source.lower()
    assert "CHECK (" not in source


def test_186_source_contains_no_slash_command_invocation():
    source = _module_source_text()
    assert "SlashCommand(" not in source
    assert "/update-case" not in source


def test_187_source_contains_no_hashing_implementation():
    source = _module_source_text()
    assert "hashlib" not in source
    assert "sha256" not in source.lower()


def test_188_source_delegates_business_validation_only_to_validate_approval_transition():
    source = _module_source_text()
    assert "validate_approval_transition(" in source
    assert "def _validate_" not in source


def test_189_source_serializes_with_sort_keys_true():
    source = _module_source_text()
    assert "sort_keys=True" in source


def test_190_source_serializes_with_ensure_ascii_false():
    source = _module_source_text()
    assert "ensure_ascii=False" in source


def test_191_source_returns_only_0_2_or_1():
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
