"""Tests for core.decision_context_cli -- the stdin/stdout JSON adapter
around core.decision_context.validate_decision_context.

main() is called directly with in-memory StringIO streams. No Supabase,
file, subprocess, network, AI-model, or other external access occurs
anywhere in this file; every input is a plain in-memory mapping.
"""

import copy
import json
import socket
import subprocess
from io import StringIO
from pathlib import Path

import pytest

from core import decision_context_cli
import core.decision_analysis as decision_analysis
import core.decision_context as decision_context

INVESTIGATION_ID = "11111111-1111-4111-8111-111111111111"
OTHER_INVESTIGATION_ID = "66666666-6666-4666-8666-666666666666"
EVID_A = "22222222-2222-4222-8222-222222222222"
EVID_B = "33333333-3333-4333-8333-333333333333"
EVID_C = "44444444-4444-4444-8444-444444444444"


def _investigation(**overrides):
    investigation = {"id": INVESTIGATION_ID, "status": "open", "confidence": "medium"}
    investigation.update(overrides)
    return investigation


def _evidence_record(evidence_id, **overrides):
    record = {
        "id": evidence_id,
        "investigation_id": INVESTIGATION_ID,
        "trust_level": "high",
        "confidence": "medium",
        "assertion_type": "observation",
        "supports_hypothesis": True,
    }
    record.update(overrides)
    return record


def _payload(**overrides):
    payload = {
        "investigation_id": INVESTIGATION_ID,
        "investigation": _investigation(),
        "supporting_evidence_ids": [EVID_A],
        "contradicting_evidence_ids": [EVID_B],
        "evidence_records": [
            _evidence_record(EVID_A),
            _evidence_record(EVID_B, supports_hypothesis=False),
        ],
    }
    payload.update(overrides)
    return payload


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = decision_context_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _module_source_text():
    with open(decision_context_cli.__file__, "r", encoding="utf-8") as handle:
        return handle.read()


def _iter_all_values(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield key
            yield from _iter_all_values(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_all_values(item)
    else:
        yield obj


# ---------------------------------------------------------------------------
# 1-4: baseline valid requests
# ---------------------------------------------------------------------------

def test_01_valid_supporting_only_request_returns_0():
    payload = _payload(
        contradicting_evidence_ids=[],
        evidence_records=[_evidence_record(EVID_A)],
    )

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 0


def test_02_valid_contradicting_only_request_returns_0():
    payload = _payload(
        supporting_evidence_ids=[],
        evidence_records=[_evidence_record(EVID_B, supports_hypothesis=False)],
    )

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 0


def test_03_valid_mixed_request_returns_0():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload()))

    assert exit_code == 0


def test_04_valid_empty_evidence_request_returns_0():
    payload = _payload(
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[],
        evidence_records=[],
    )

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 0


# ---------------------------------------------------------------------------
# 5-14: success shape, ordering, and transport details
# ---------------------------------------------------------------------------

def test_05_success_stdout_contains_exactly_one_json_object():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    parsed = json.loads(stdout)
    assert isinstance(parsed, dict)


def test_06_success_stdout_ends_with_exactly_one_newline():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    assert stdout.endswith("\n")
    assert not stdout.endswith("\n\n")


def test_07_success_stderr_is_empty():
    _exit_code, _stdout, stderr = _run(json.dumps(_payload()))

    assert stderr == ""


def test_08_success_output_equals_validate_decision_context_output():
    payload = _payload()

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    assert json.loads(stdout) == decision_context.validate_decision_context(payload)


def test_09_success_json_uses_deterministic_key_ordering():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    parsed = json.loads(stdout)
    assert list(parsed.keys()) == sorted(parsed.keys())


def test_10_evidence_list_order_preserved():
    payload = _payload(
        supporting_evidence_ids=[EVID_C, EVID_A],
        contradicting_evidence_ids=[EVID_B],
        evidence_records=[
            _evidence_record(EVID_A),
            _evidence_record(EVID_B, supports_hypothesis=False),
            _evidence_record(EVID_C),
        ],
    )

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    parsed = json.loads(stdout)
    assert [item["id"] for item in parsed["supporting_evidence"]] == [EVID_C, EVID_A]


def test_11_warning_list_order_preserved():
    payload = _payload(
        supporting_evidence_ids=[EVID_A],
        contradicting_evidence_ids=[EVID_B],
        evidence_records=[
            _evidence_record(EVID_A, trust_level="unknown"),
            _evidence_record(EVID_B, supports_hypothesis=None),
        ],
    )

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    parsed = json.loads(stdout)
    direct = decision_context.validate_decision_context(payload)
    assert parsed["warnings"] == direct["warnings"]


def test_12_unicode_in_ignored_field_does_not_break_parsing():
    payload = _payload(
        evidence_records=[
            _evidence_record(EVID_A, analyst_note="café-hôte-注意"),
            _evidence_record(EVID_B, supports_hypothesis=False),
        ]
    )

    exit_code, stdout, _stderr = _run(json.dumps(payload, ensure_ascii=False))

    assert exit_code == 0
    parsed = json.loads(stdout)
    assert "analyst_note" not in json.dumps(parsed)


def test_13_leading_whitespace_accepted():
    exit_code, _stdout, _stderr = _run("   \n\t" + json.dumps(_payload()))

    assert exit_code == 0


def test_14_trailing_whitespace_accepted():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload()) + "   \n")

    assert exit_code == 0


# ---------------------------------------------------------------------------
# 15-27: rejected raw input
# ---------------------------------------------------------------------------

def test_15_empty_stdin_rejected():
    exit_code, stdout, stderr = _run("")

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_16_whitespace_only_stdin_rejected():
    exit_code, stdout, stderr = _run("   \n\t  ")

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_17_malformed_json_rejected():
    exit_code, stdout, stderr = _run("{not valid json")

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_18_truncated_json_rejected():
    raw = json.dumps(_payload())[:-5]

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_19_json_null_rejected():
    exit_code, stdout, stderr = _run("null")

    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Decision context input must be a JSON object.\n"


def test_20_json_string_rejected():
    exit_code, stdout, stderr = _run('"a string"')

    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Decision context input must be a JSON object.\n"


def test_21_json_number_rejected():
    exit_code, stdout, stderr = _run("42")

    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Decision context input must be a JSON object.\n"


def test_22_json_boolean_rejected():
    exit_code, stdout, stderr = _run("true")

    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Decision context input must be a JSON object.\n"


def test_23_json_array_rejected():
    exit_code, stdout, stderr = _run("[]")

    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Decision context input must be a JSON object.\n"


def test_24_two_json_objects_rejected():
    raw = json.dumps(_payload()) + json.dumps(_payload())

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_25_object_followed_by_json_string_rejected():
    raw = json.dumps(_payload()) + ' "trailing"'

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_26_object_followed_by_json_number_rejected():
    raw = json.dumps(_payload()) + " 5"

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_27_object_followed_by_trailing_text_rejected():
    raw = json.dumps(_payload()) + " garbage"

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


# ---------------------------------------------------------------------------
# 28-39: decision-context validation failures surfaced as exit code 2
# ---------------------------------------------------------------------------

def test_28_validation_failure_returns_exit_code_2():
    payload = _payload()
    del payload["investigation"]

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_29_validation_failure_leaves_stdout_empty():
    payload = _payload()
    del payload["investigation"]

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    assert stdout == ""


def test_30_validation_failure_writes_one_stderr_line():
    payload = _payload()
    del payload["investigation"]

    _exit_code, _stdout, stderr = _run(json.dumps(payload))

    assert stderr.count("\n") == 1


def test_31_decision_context_error_message_safely_surfaced():
    payload = _payload()
    del payload["investigation"]

    _exit_code, _stdout, stderr = _run(json.dumps(payload))

    assert stderr.startswith("Decision context validation failed:")
    assert "investigation" in stderr


def test_32_invalid_investigation_uuid_returns_2():
    payload = _payload(investigation_id="not-a-uuid")

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_33_investigation_id_mismatch_returns_2():
    payload = _payload(investigation=_investigation(id=OTHER_INVESTIGATION_ID))

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_34_missing_evidence_record_returns_2():
    payload = _payload(evidence_records=[_evidence_record(EVID_B, supports_hypothesis=False)])

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_35_cross_investigation_evidence_returns_2():
    payload = _payload(
        evidence_records=[
            _evidence_record(EVID_A, investigation_id=OTHER_INVESTIGATION_ID),
            _evidence_record(EVID_B, supports_hypothesis=False),
        ]
    )

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_36_group_overlap_returns_2():
    payload = _payload(
        supporting_evidence_ids=[EVID_A],
        contradicting_evidence_ids=[EVID_A],
        evidence_records=[_evidence_record(EVID_A)],
    )

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_37_invalid_trust_level_returns_2():
    payload = _payload(
        evidence_records=[
            _evidence_record(EVID_A, trust_level="super-trusted"),
            _evidence_record(EVID_B, supports_hypothesis=False),
        ]
    )

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_38_invalid_assertion_type_returns_2():
    payload = _payload(
        evidence_records=[
            _evidence_record(EVID_A, assertion_type="not-a-type"),
            _evidence_record(EVID_B, supports_hypothesis=False),
        ]
    )

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_39_invalid_supports_hypothesis_integer_returns_2():
    payload = _payload(
        evidence_records=[
            _evidence_record(EVID_A, supports_hypothesis=1),
            _evidence_record(EVID_B, supports_hypothesis=False),
        ]
    )

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


# ---------------------------------------------------------------------------
# 40-46: unexpected internal failure handling and error redaction
# ---------------------------------------------------------------------------

def test_40_unexpected_validator_exception_returns_1(monkeypatch):
    def boom(_payload):
        raise RuntimeError("simulated internal failure")

    monkeypatch.setattr(decision_context_cli, "validate_decision_context", boom)

    exit_code, _stdout, _stderr = _run(json.dumps(_payload()))

    assert exit_code == 1


def test_41_unexpected_failure_stdout_empty(monkeypatch):
    def boom(_payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(decision_context_cli, "validate_decision_context", boom)

    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    assert stdout == ""


def test_42_unexpected_failure_stderr_exact_message(monkeypatch):
    def boom(_payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(decision_context_cli, "validate_decision_context", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_payload()))

    assert stderr == "Decision context validation failed.\n"


def test_43_unexpected_failure_exposes_no_exception_text(monkeypatch):
    secret_marker = "super-secret-internal-detail-xyz"

    def boom(_payload):
        raise RuntimeError(secret_marker)

    monkeypatch.setattr(decision_context_cli, "validate_decision_context", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_payload()))

    assert secret_marker not in stderr
    assert "RuntimeError" not in stderr


def test_44_no_traceback_appears(monkeypatch):
    def boom(_payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(decision_context_cli, "validate_decision_context", boom)

    _exit_code, _stdout, unexpected_stderr = _run(json.dumps(_payload()))

    payload = _payload()
    del payload["investigation"]
    _exit_code2, _stdout2, validation_stderr = _run(json.dumps(payload))

    assert "Traceback" not in unexpected_stderr
    assert "Traceback" not in validation_stderr


def test_45_input_payload_is_not_echoed():
    marker = "SECRET-INPUT-MARKER-abc123"
    payload = _payload(
        evidence_records=[
            _evidence_record(EVID_A, trust_level="super-trusted", analyst_note=marker),
            _evidence_record(EVID_B, supports_hypothesis=False),
        ]
    )

    _exit_code, stdout, stderr = _run(json.dumps(payload))

    assert marker not in stdout
    assert marker not in stderr


def test_46_nested_evidence_details_not_leaked_in_errors():
    marker = "SECRET-NESTED-DETAIL-xyz789"
    payload = _payload(
        evidence_records=[
            _evidence_record(
                EVID_A,
                trust_level="super-trusted",
                details={"raw": marker},
                provenance={"collector": marker},
            ),
            _evidence_record(EVID_B, supports_hypothesis=False),
        ]
    )

    _exit_code, stdout, stderr = _run(json.dumps(payload))

    assert marker not in stdout
    assert marker not in stderr


# ---------------------------------------------------------------------------
# 47-52: call integrity and non-mutation
# ---------------------------------------------------------------------------

def test_47_validator_called_exactly_once_on_valid_input(monkeypatch):
    calls = []
    original = decision_context_cli.validate_decision_context

    def counting_validate(payload):
        calls.append(payload)
        return original(payload)

    monkeypatch.setattr(decision_context_cli, "validate_decision_context", counting_validate)

    exit_code, _stdout, _stderr = _run(json.dumps(_payload()))

    assert exit_code == 0
    assert len(calls) == 1


def test_48_validator_not_called_for_malformed_json(monkeypatch):
    def forbidden(_payload):
        raise AssertionError("validate_decision_context must not be called for malformed JSON")

    monkeypatch.setattr(decision_context_cli, "validate_decision_context", forbidden)

    exit_code, _stdout, _stderr = _run("{not valid json")

    assert exit_code == 2


def test_49_validator_not_called_for_non_object_json(monkeypatch):
    def forbidden(_payload):
        raise AssertionError("validate_decision_context must not be called for non-object JSON")

    monkeypatch.setattr(decision_context_cli, "validate_decision_context", forbidden)

    exit_code, _stdout, _stderr = _run("null")

    assert exit_code == 2


def test_50_validator_not_called_for_multiple_json_values(monkeypatch):
    def forbidden(_payload):
        raise AssertionError("validate_decision_context must not be called for multiple JSON values")

    monkeypatch.setattr(decision_context_cli, "validate_decision_context", forbidden)

    raw = json.dumps(_payload()) + json.dumps(_payload())
    exit_code, _stdout, _stderr = _run(raw)

    assert exit_code == 2


def test_51_validator_return_value_not_mutated(monkeypatch):
    fixed_result = {
        "investigation": {"id": INVESTIGATION_ID, "status": "open", "confidence": "medium"},
        "supporting_evidence": [],
        "contradicting_evidence": [],
        "warnings": [],
    }
    snapshot = copy.deepcopy(fixed_result)

    monkeypatch.setattr(decision_context_cli, "validate_decision_context", lambda _payload: fixed_result)

    exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    assert exit_code == 0
    assert fixed_result == snapshot
    assert json.loads(stdout) == snapshot


def test_52_decoded_input_mapping_is_passed_to_validator(monkeypatch):
    captured = {}

    def capturing_validate(payload):
        captured["payload"] = payload
        return decision_context.validate_decision_context(payload)

    monkeypatch.setattr(decision_context_cli, "validate_decision_context", capturing_validate)

    payload = _payload()
    _exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert captured["payload"] == payload


# ---------------------------------------------------------------------------
# 53-58: no decision-analysis, no advisory computation
# ---------------------------------------------------------------------------

def test_53_no_decision_analysis_validator_call_occurs(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("validate_decision_analysis must not be called by the decision-context CLI")

    monkeypatch.setattr(decision_analysis, "validate_decision_analysis", forbidden)

    exit_code, _stdout, _stderr = _run(json.dumps(_payload()))

    assert exit_code == 0


def test_54_no_decision_status_is_generated():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    parsed = json.loads(stdout)
    assert "decision_status" not in set(_iter_all_values(parsed))
    assert "decision_status" not in json.dumps(parsed)


def test_55_no_current_assessment_is_generated():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    assert "current_assessment" not in stdout


def test_56_no_reasoning_collections_are_generated():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    for field_name in (
        "unresolved_assumptions",
        "evidence_gaps",
        "strengthen_conditions",
        "weaken_conditions",
        "reversal_conditions",
        "recommended_next_evidence",
        "limitations",
    ):
        assert field_name not in stdout


def test_57_no_confidence_calculation_occurs():
    payload = _payload(
        investigation=_investigation(confidence="unknown"),
        evidence_records=[
            _evidence_record(EVID_A, confidence="low"),
            _evidence_record(EVID_B, supports_hypothesis=False, confidence="high"),
        ],
    )

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    parsed = json.loads(stdout)
    assert parsed["investigation"]["confidence"] == "unknown"
    assert parsed["supporting_evidence"][0]["confidence"] == "low"
    assert parsed["contradicting_evidence"][0]["confidence"] == "high"


def test_58_no_trust_modification_occurs():
    payload = _payload(
        evidence_records=[
            _evidence_record(EVID_A, trust_level="low"),
            _evidence_record(EVID_B, supports_hypothesis=False, trust_level="unknown"),
        ]
    )

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    parsed = json.loads(stdout)
    assert parsed["supporting_evidence"][0]["trust_level"] == "low"
    assert parsed["contradicting_evidence"][0]["trust_level"] == "unknown"


# ---------------------------------------------------------------------------
# 59-69: static source-pattern security assertions
# ---------------------------------------------------------------------------

def test_59_no_supabase_access_occurs():
    source = _module_source_text()

    assert "import supabase" not in source
    assert "from supabase" not in source
    assert "mcp__supabase" not in source.lower()
    assert ".table(" not in source


def test_60_no_file_access_occurs():
    source = _module_source_text()

    assert "open(" not in source
    assert "Path(" not in source
    assert "pathlib" not in source
    assert "os.path" not in source


def test_61_no_temporary_file_is_created():
    source = _module_source_text()

    assert "tempfile" not in source
    assert "NamedTemporaryFile" not in source
    assert "mkstemp" not in source


def test_62_no_subprocess_occurs():
    source = _module_source_text()

    assert "import subprocess" not in source
    assert "subprocess.run(" not in source
    assert "subprocess.Popen(" not in source
    assert "subprocess.call(" not in source
    assert "Popen(" not in source


def test_63_no_network_access_occurs():
    source = _module_source_text()

    assert "socket" not in source
    assert "urllib" not in source
    assert "requests" not in source


def test_64_no_ai_or_model_call_occurs():
    source = _module_source_text()

    assert "openai" not in source.lower()
    assert "anthropic" not in source.lower()
    assert "messages.create(" not in source
    assert "chat.completions" not in source


def test_65_no_persistence_occurs():
    source = _module_source_text()

    assert ".insert(" not in source
    assert ".update(" not in source
    assert ".delete(" not in source
    assert "commit(" not in source


def test_66_no_attack_mapping_occurs():
    source = _module_source_text()

    assert "attack_mapping" not in source.lower()
    assert "mitre" not in source.lower()
    assert "technique_id" not in source.lower()


def test_67_no_hashing_occurs():
    source = _module_source_text()

    assert "hashlib" not in source
    assert "sha256" not in source.lower()
    assert "md5" not in source.lower()


def test_68_no_approval_or_audit_behavior_occurs():
    source = _module_source_text()

    assert "approval" not in source.lower()
    assert "audit" not in source.lower()
    assert "reviewer" not in source.lower()


def test_69_no_containment_or_execution_behavior_occurs():
    source = _module_source_text()

    assert "containment" not in source.lower()
    assert "execute_simulation" not in source.lower()
    assert "run_atomic" not in source.lower()


# ---------------------------------------------------------------------------
# 70-80: transport contract, boundaries, and non-mutation
# ---------------------------------------------------------------------------

def test_70_main_uses_supplied_streams_correctly(capsys):
    exit_code, stdout, stderr = _run(json.dumps(_payload()))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert exit_code == 0
    assert stdout != ""


def test_71_main_guard_exists():
    source = _module_source_text()

    assert 'if __name__ == "__main__":' in source
    assert "raise SystemExit(main())" in source


def test_72_cli_imports_validate_decision_context_from_core_decision_context():
    assert decision_context_cli.validate_decision_context is decision_context.validate_decision_context


def test_73_cli_does_not_redefine_context_controlled_vocabularies():
    source = _module_source_text()

    assert "WARNING_CODES" not in source
    assert "INVESTIGATION_STATUSES" not in source
    assert not hasattr(decision_context_cli, "WARNING_CODES")
    assert not hasattr(decision_context_cli, "INVESTIGATION_STATUSES")


def test_74_cli_does_not_duplicate_warning_generation_rules():
    source = _module_source_text()

    assert "_collect_warnings" not in source
    assert "EVIDENCE_TRUST_UNKNOWN" not in source


def test_75_cli_uses_ensure_ascii_false():
    source = _module_source_text()

    assert "ensure_ascii=False" in source


def test_76_cli_uses_sort_keys_true():
    source = _module_source_text()

    assert "sort_keys=True" in source


def test_77_cli_appends_one_newline():
    source = _module_source_text()

    assert 'stdout.write("\\n")' in source


def test_78_main_returns_an_int_exit_code():
    for raw in (json.dumps(_payload()), "not json", json.dumps([1, 2])):
        exit_code, _stdout, _stderr = _run(raw)
        assert isinstance(exit_code, int)


def test_79_decoded_input_not_mutated_after_call(monkeypatch):
    captured = {}

    def capturing_validate(payload):
        captured["snapshot"] = copy.deepcopy(payload)
        result = decision_context.validate_decision_context(payload)
        captured["payload_ref"] = payload
        return result

    monkeypatch.setattr(decision_context_cli, "validate_decision_context", capturing_validate)

    payload = _payload()
    _run(json.dumps(payload))

    assert captured["payload_ref"] == captured["snapshot"]


def test_80_serialized_output_contains_no_details_or_provenance_fields():
    payload = _payload(
        evidence_records=[
            _evidence_record(EVID_A, details={"command_line": "whoami"}, provenance={"collector": "x"}),
            _evidence_record(EVID_B, supports_hypothesis=False),
        ]
    )

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    parsed = json.loads(stdout)
    assert "details" not in json.dumps(parsed)
    assert "provenance" not in json.dumps(parsed)


# ---------------------------------------------------------------------------
# Runtime side-effect guard: forbidden entry points must never be reached
# ---------------------------------------------------------------------------

def test_runtime_guard_no_forbidden_entry_points_reached(monkeypatch):
    import sys
    import urllib.request

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called during decision-context CLI validation")

    # Import optional third-party modules *before* patching socket.socket:
    # some of them (e.g. requests -> urllib3 -> PySocks) subclass
    # socket.socket at import time, which would break if the class were
    # already replaced with a plain forbidden callable.
    try:
        import requests
    except ImportError:
        requests = None

    try:
        import supabase
    except ImportError:
        supabase = None

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
