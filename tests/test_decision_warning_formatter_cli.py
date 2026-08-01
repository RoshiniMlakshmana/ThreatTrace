"""Tests for core.decision_warning_formatter_cli -- the stdin/stdout JSON
adapter around core.decision_warning_formatter.format_decision_warnings.

main() is called directly with in-memory StringIO streams. No Supabase,
file, subprocess, network, AI-model, or other external access occurs
anywhere in this file; every input is a plain in-memory JSON array.
"""

import copy
import json
import socket
import subprocess
from io import StringIO
from pathlib import Path

import pytest

from core import decision_warning_formatter_cli
import core.decision_analysis as decision_analysis
import core.decision_analysis_cli as decision_analysis_cli
import core.decision_context as decision_context
import core.decision_context_cli as decision_context_cli
import core.decision_warning_formatter as decision_warning_formatter

EVID_A = "11111111-1111-4111-8111-111111111111"
EVID_B = "22222222-2222-4222-8222-222222222222"

ALL_CODES = (
    "EVIDENCE_TRUST_UNKNOWN",
    "EVIDENCE_TRUST_LOW",
    "EVIDENCE_CONFIDENCE_UNKNOWN",
    "EVIDENCE_IS_INTERPRETATION",
    "EVIDENCE_IS_HYPOTHESIS",
    "EVIDENCE_IS_RECOMMENDATION",
    "SUPPORTS_HYPOTHESIS_CONFLICT",
    "SUPPORTS_HYPOTHESIS_UNSPECIFIED",
)

EXPECTED_EXPLANATIONS = {
    "EVIDENCE_TRUST_UNKNOWN": "Source trust for this evidence has not been recorded.",
    "EVIDENCE_TRUST_LOW": "Source trust for this evidence is recorded as low.",
    "EVIDENCE_CONFIDENCE_UNKNOWN": "Confidence for this evidence has not been recorded.",
    "EVIDENCE_IS_INTERPRETATION": "This evidence is recorded as an interpretation, not a direct observation.",
    "EVIDENCE_IS_HYPOTHESIS": "This evidence is recorded as a hypothesis, not a direct observation.",
    "EVIDENCE_IS_RECOMMENDATION": "This evidence is recorded as a recommendation, not a direct observation.",
    "SUPPORTS_HYPOTHESIS_CONFLICT": "This evidence's stored supports_hypothesis value conflicts with its assigned group.",
    "SUPPORTS_HYPOTHESIS_UNSPECIFIED": "This evidence's supports_hypothesis value was not specified.",
}


def _warning(evidence_id=EVID_A, code="EVIDENCE_TRUST_LOW"):
    return {"evidence_id": evidence_id, "code": code}


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = decision_warning_formatter_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _module_source_text():
    with open(decision_warning_formatter_cli.__file__, "r", encoding="utf-8") as handle:
        return handle.read()


# ---------------------------------------------------------------------------
# 1-4: baseline valid requests
# ---------------------------------------------------------------------------

def test_001_empty_warning_array_returns_exit_0():
    exit_code, stdout, _stderr = _run("[]")

    assert exit_code == 0
    assert json.loads(stdout) == []


def test_002_one_valid_warning_returns_exit_0():
    exit_code, _stdout, _stderr = _run(json.dumps([_warning()]))

    assert exit_code == 0


def test_003_all_eight_warning_codes_return_exit_0():
    warnings = [_warning(EVID_A, code) for code in ALL_CODES]

    exit_code, stdout, _stderr = _run(json.dumps(warnings))

    assert exit_code == 0
    assert len(json.loads(stdout)) == 8


def test_004_multiple_valid_warnings_return_exit_0():
    warnings = [
        _warning(EVID_A, "EVIDENCE_TRUST_LOW"),
        _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS"),
    ]

    exit_code, _stdout, _stderr = _run(json.dumps(warnings))

    assert exit_code == 0


# ---------------------------------------------------------------------------
# 5-14: success shape, ordering, and transport details
# ---------------------------------------------------------------------------

def test_005_success_stdout_contains_exactly_one_json_array():
    _exit_code, stdout, _stderr = _run(json.dumps([_warning()]))

    parsed = json.loads(stdout)
    assert isinstance(parsed, list)


def test_006_success_stdout_ends_with_exactly_one_newline():
    _exit_code, stdout, _stderr = _run(json.dumps([_warning()]))

    assert stdout.endswith("\n")
    assert not stdout.endswith("\n\n")


def test_007_success_stderr_is_empty():
    _exit_code, _stdout, stderr = _run(json.dumps([_warning()]))

    assert stderr == ""


def test_008_success_output_equals_direct_format_decision_warnings_output():
    warnings = [_warning(EVID_A, "EVIDENCE_TRUST_LOW"), _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS")]

    _exit_code, stdout, _stderr = _run(json.dumps(warnings))

    assert json.loads(stdout) == decision_warning_formatter.format_decision_warnings(warnings)


def test_009_json_output_uses_deterministic_object_key_ordering():
    _exit_code, stdout, _stderr = _run(json.dumps([_warning()]))

    parsed = json.loads(stdout)
    assert list(parsed[0].keys()) == sorted(parsed[0].keys())


def test_010_warning_array_order_is_preserved():
    warnings = [
        _warning(EVID_B, "EVIDENCE_TRUST_LOW"),
        _warning(EVID_A, "EVIDENCE_CONFIDENCE_UNKNOWN"),
        _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS"),
    ]

    _exit_code, stdout, _stderr = _run(json.dumps(warnings))

    parsed = json.loads(stdout)
    assert [(item["evidence_id"], item["code"]) for item in parsed] == [
        (EVID_B, "EVIDENCE_TRUST_LOW"),
        (EVID_A, "EVIDENCE_CONFIDENCE_UNKNOWN"),
        (EVID_B, "EVIDENCE_IS_HYPOTHESIS"),
    ]


def test_011_fixed_explanation_text_is_preserved_exactly():
    warnings = [_warning(EVID_A, code) for code in ALL_CODES]

    _exit_code, stdout, _stderr = _run(json.dumps(warnings))

    parsed = json.loads(stdout)
    for item in parsed:
        assert item["explanation"] == EXPECTED_EXPLANATIONS[item["code"]]


def test_012_unicode_handling_uses_ensure_ascii_false(monkeypatch):
    unicode_result = [
        {"evidence_id": EVID_A, "code": "EVIDENCE_TRUST_LOW", "explanation": "café-hôte-注意"}
    ]
    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", lambda _w: unicode_result)

    exit_code, stdout, _stderr = _run(json.dumps([_warning()]))

    assert exit_code == 0
    assert "café-hôte-注意" in stdout
    assert "\\u" not in stdout


def test_013_leading_whitespace_accepted():
    exit_code, _stdout, _stderr = _run("   \n\t" + json.dumps([_warning()]))

    assert exit_code == 0


def test_014_trailing_whitespace_accepted():
    exit_code, _stdout, _stderr = _run(json.dumps([_warning()]) + "   \n")

    assert exit_code == 0


# ---------------------------------------------------------------------------
# 15-28: rejected raw input
# ---------------------------------------------------------------------------

def test_015_empty_stdin_rejected():
    exit_code, stdout, stderr = _run("")

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_016_whitespace_only_stdin_rejected():
    exit_code, stdout, stderr = _run("   \n\t  ")

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_017_malformed_json_rejected():
    exit_code, stdout, stderr = _run("[not valid json")

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_018_truncated_json_rejected():
    raw = json.dumps([_warning()])[:-3]

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_019_json_null_rejected():
    exit_code, stdout, stderr = _run("null")

    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Decision warning formatter input must be a JSON array.\n"


def test_020_json_object_rejected():
    exit_code, stdout, stderr = _run(json.dumps(_warning()))

    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Decision warning formatter input must be a JSON array.\n"


def test_021_json_string_rejected():
    exit_code, stdout, stderr = _run('"a string"')

    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Decision warning formatter input must be a JSON array.\n"


def test_022_json_number_rejected():
    exit_code, stdout, stderr = _run("42")

    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Decision warning formatter input must be a JSON array.\n"


def test_023_json_boolean_rejected():
    exit_code, stdout, stderr = _run("true")

    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Decision warning formatter input must be a JSON array.\n"


def test_024_two_json_arrays_rejected():
    raw = json.dumps([_warning()]) + json.dumps([_warning()])

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_025_array_followed_by_json_object_rejected():
    raw = json.dumps([_warning()]) + " {}"

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_026_array_followed_by_json_string_rejected():
    raw = json.dumps([_warning()]) + ' "trailing"'

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_027_array_followed_by_json_number_rejected():
    raw = json.dumps([_warning()]) + " 5"

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_028_array_followed_by_trailing_text_rejected():
    raw = json.dumps([_warning()]) + " garbage"

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


# ---------------------------------------------------------------------------
# 29-41: formatting validation failures surfaced as exit code 2
# ---------------------------------------------------------------------------

def test_029_formatting_validation_failure_returns_exit_2():
    warnings = [_warning(evidence_id="not-a-uuid")]

    exit_code, _stdout, _stderr = _run(json.dumps(warnings))

    assert exit_code == 2


def test_030_validation_failure_leaves_stdout_empty():
    warnings = [_warning(evidence_id="not-a-uuid")]

    _exit_code, stdout, _stderr = _run(json.dumps(warnings))

    assert stdout == ""


def test_031_validation_failure_writes_exactly_one_stderr_line():
    warnings = [_warning(evidence_id="not-a-uuid")]

    _exit_code, _stdout, stderr = _run(json.dumps(warnings))

    assert stderr.count("\n") == 1


def test_032_decision_warning_format_error_message_safely_surfaced():
    warnings = [_warning(evidence_id="not-a-uuid")]

    _exit_code, _stdout, stderr = _run(json.dumps(warnings))

    assert stderr.startswith("Decision warning formatting failed:")
    assert "evidence_id" in stderr


def test_033_warning_entry_not_a_mapping_returns_2():
    exit_code, _stdout, _stderr = _run(json.dumps(["not a mapping"]))

    assert exit_code == 2


def test_034_missing_evidence_id_returns_2():
    warning = _warning()
    del warning["evidence_id"]

    exit_code, _stdout, _stderr = _run(json.dumps([warning]))

    assert exit_code == 2


def test_035_missing_code_returns_2():
    warning = _warning()
    del warning["code"]

    exit_code, _stdout, _stderr = _run(json.dumps([warning]))

    assert exit_code == 2


def test_036_extra_warning_field_returns_2():
    warning = _warning()
    warning["extra_field"] = "unexpected"

    exit_code, _stdout, _stderr = _run(json.dumps([warning]))

    assert exit_code == 2


def test_037_invalid_evidence_uuid_returns_2():
    exit_code, _stdout, _stderr = _run(json.dumps([_warning(evidence_id="not-a-uuid")]))

    assert exit_code == 2


def test_038_unknown_warning_code_returns_2():
    exit_code, _stdout, _stderr = _run(json.dumps([_warning(code="NOT_A_REAL_CODE")]))

    assert exit_code == 2


def test_039_lowercase_warning_code_returns_2():
    exit_code, _stdout, _stderr = _run(json.dumps([_warning(code="evidence_trust_low")]))

    assert exit_code == 2


def test_040_duplicate_warning_pair_returns_2():
    warnings = [_warning(EVID_A, "EVIDENCE_TRUST_LOW"), _warning(EVID_A, "EVIDENCE_TRUST_LOW")]

    exit_code, _stdout, _stderr = _run(json.dumps(warnings))

    assert exit_code == 2


def test_041_duplicate_after_uuid_canonicalization_returns_2():
    warnings = [
        _warning(f"{{{EVID_A}}}", "EVIDENCE_TRUST_LOW"),
        _warning(EVID_A, "EVIDENCE_TRUST_LOW"),
    ]

    exit_code, _stdout, _stderr = _run(json.dumps(warnings))

    assert exit_code == 2


# ---------------------------------------------------------------------------
# 42-49: unexpected internal failure handling and error redaction
# ---------------------------------------------------------------------------

def test_042_unexpected_formatter_exception_returns_1(monkeypatch):
    def boom(_warnings):
        raise RuntimeError("simulated internal failure")

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", boom)

    exit_code, _stdout, _stderr = _run(json.dumps([_warning()]))

    assert exit_code == 1


def test_043_unexpected_failure_stdout_empty(monkeypatch):
    def boom(_warnings):
        raise RuntimeError("boom")

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", boom)

    _exit_code, stdout, _stderr = _run(json.dumps([_warning()]))

    assert stdout == ""


def test_044_unexpected_failure_stderr_exact_message(monkeypatch):
    def boom(_warnings):
        raise RuntimeError("boom")

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", boom)

    _exit_code, _stdout, stderr = _run(json.dumps([_warning()]))

    assert stderr == "Decision warning formatting failed.\n"


def test_045_unexpected_failure_exposes_no_exception_text(monkeypatch):
    secret_marker = "super-secret-internal-detail-xyz"

    def boom(_warnings):
        raise RuntimeError(secret_marker)

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", boom)

    _exit_code, _stdout, stderr = _run(json.dumps([_warning()]))

    assert secret_marker not in stderr
    assert "RuntimeError" not in stderr


def test_046_no_traceback_appears(monkeypatch):
    def boom(_warnings):
        raise RuntimeError("boom")

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", boom)

    _exit_code, _stdout, unexpected_stderr = _run(json.dumps([_warning()]))

    _exit_code2, _stdout2, validation_stderr = _run(json.dumps([_warning(evidence_id="not-a-uuid")]))

    assert "Traceback" not in unexpected_stderr
    assert "Traceback" not in validation_stderr


def test_047_input_payload_is_not_echoed(monkeypatch):
    def boom(_warnings):
        raise RuntimeError("boom")

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", boom)

    warnings = [_warning(EVID_A, "EVIDENCE_TRUST_LOW"), _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS")]
    _exit_code, stdout, stderr = _run(json.dumps(warnings))

    assert EVID_A not in stdout
    assert EVID_A not in stderr
    assert EVID_B not in stderr


def test_048_evidence_id_not_leaked_on_unexpected_failure(monkeypatch):
    def boom(_warnings):
        raise RuntimeError("boom")

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", boom)

    _exit_code, _stdout, stderr = _run(json.dumps([_warning(EVID_A, "EVIDENCE_TRUST_LOW")]))

    assert EVID_A not in stderr


def test_049_warning_code_not_leaked_on_unexpected_failure(monkeypatch):
    def boom(_warnings):
        raise RuntimeError("boom")

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", boom)

    _exit_code, _stdout, stderr = _run(json.dumps([_warning(EVID_A, "EVIDENCE_IS_HYPOTHESIS")]))

    assert "EVIDENCE_IS_HYPOTHESIS" not in stderr


# ---------------------------------------------------------------------------
# 50-57: call integrity and non-mutation
# ---------------------------------------------------------------------------

def test_050_formatter_called_exactly_once_on_valid_input(monkeypatch):
    calls = []
    original = decision_warning_formatter_cli.format_decision_warnings

    def counting_format(warnings):
        calls.append(warnings)
        return original(warnings)

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", counting_format)

    exit_code, _stdout, _stderr = _run(json.dumps([_warning()]))

    assert exit_code == 0
    assert len(calls) == 1


def test_051_formatter_not_called_for_malformed_json(monkeypatch):
    def forbidden(_warnings):
        raise AssertionError("format_decision_warnings must not be called for malformed JSON")

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", forbidden)

    exit_code, _stdout, _stderr = _run("[not valid json")

    assert exit_code == 2


def test_052_formatter_not_called_for_non_array_json(monkeypatch):
    def forbidden(_warnings):
        raise AssertionError("format_decision_warnings must not be called for non-array JSON")

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", forbidden)

    exit_code, _stdout, _stderr = _run("null")

    assert exit_code == 2


def test_053_formatter_not_called_for_multiple_json_values(monkeypatch):
    def forbidden(_warnings):
        raise AssertionError("format_decision_warnings must not be called for multiple JSON values")

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", forbidden)

    raw = json.dumps([_warning()]) + json.dumps([_warning()])
    exit_code, _stdout, _stderr = _run(raw)

    assert exit_code == 2


def test_054_formatter_return_value_not_mutated(monkeypatch):
    fixed_result = [
        {"evidence_id": EVID_A, "code": "EVIDENCE_TRUST_LOW", "explanation": "fixed explanation"}
    ]
    snapshot = copy.deepcopy(fixed_result)

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", lambda _w: fixed_result)

    exit_code, stdout, _stderr = _run(json.dumps([_warning()]))

    assert exit_code == 0
    assert fixed_result == snapshot
    assert json.loads(stdout) == snapshot


def test_055_decoded_warning_list_is_passed_to_formatter(monkeypatch):
    captured = {}

    def capturing_format(warnings):
        captured["warnings"] = warnings
        return decision_warning_formatter.format_decision_warnings(warnings)

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", capturing_format)

    warnings = [_warning(EVID_A, "EVIDENCE_TRUST_LOW"), _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS")]
    _exit_code, _stdout, _stderr = _run(json.dumps(warnings))

    assert captured["warnings"] == warnings


def test_056_input_list_not_mutated(monkeypatch):
    captured = {}

    def capturing_format(warnings):
        captured["snapshot"] = copy.deepcopy(warnings)
        result = decision_warning_formatter.format_decision_warnings(warnings)
        captured["warnings_ref"] = warnings
        return result

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", capturing_format)

    warnings = [_warning(EVID_A, "EVIDENCE_TRUST_LOW"), _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS")]
    _run(json.dumps(warnings))

    assert captured["warnings_ref"] == captured["snapshot"]


def test_057_nested_warning_mappings_not_mutated():
    warnings = [_warning(EVID_A, "EVIDENCE_TRUST_LOW")]
    snapshot = copy.deepcopy(warnings)

    _run(json.dumps(warnings))

    assert warnings == snapshot


# ---------------------------------------------------------------------------
# 58-70: count/order integrity and no generated/derived fields
# ---------------------------------------------------------------------------

def test_058_output_warning_count_equals_formatter_output_count():
    warnings = [_warning(EVID_A, "EVIDENCE_TRUST_LOW"), _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS")]

    _exit_code, stdout, _stderr = _run(json.dumps(warnings))

    assert len(json.loads(stdout)) == len(decision_warning_formatter.format_decision_warnings(warnings))


def test_059_no_warning_is_added():
    warnings = [_warning(EVID_A, "EVIDENCE_TRUST_LOW")]

    _exit_code, stdout, _stderr = _run(json.dumps(warnings))

    assert len(json.loads(stdout)) == 1


def test_060_no_warning_is_removed():
    warnings = [
        _warning(EVID_A, "EVIDENCE_TRUST_LOW"),
        _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS"),
        _warning(EVID_A, "EVIDENCE_CONFIDENCE_UNKNOWN"),
    ]

    _exit_code, stdout, _stderr = _run(json.dumps(warnings))

    assert len(json.loads(stdout)) == 3


def test_061_no_warning_is_reordered():
    warnings = [
        _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS"),
        _warning(EVID_A, "EVIDENCE_TRUST_LOW"),
    ]

    _exit_code, stdout, _stderr = _run(json.dumps(warnings))

    parsed = json.loads(stdout)
    assert [item["evidence_id"] for item in parsed] == [EVID_B, EVID_A]


def test_062_no_context_validator_call_occurs(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("validate_decision_context must not be called by the warning formatter CLI")

    monkeypatch.setattr(decision_context, "validate_decision_context", forbidden)

    exit_code, _stdout, _stderr = _run(json.dumps([_warning()]))

    assert exit_code == 0


def test_063_no_analysis_validator_call_occurs(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("validate_decision_analysis must not be called by the warning formatter CLI")

    monkeypatch.setattr(decision_analysis, "validate_decision_analysis", forbidden)

    exit_code, _stdout, _stderr = _run(json.dumps([_warning()]))

    assert exit_code == 0


def test_064_no_decision_context_cli_call_occurs(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("decision_context_cli.main must not be called by the warning formatter CLI")

    monkeypatch.setattr(decision_context_cli, "main", forbidden)

    exit_code, _stdout, _stderr = _run(json.dumps([_warning()]))

    assert exit_code == 0


def test_065_no_decision_analysis_cli_call_occurs(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("decision_analysis_cli.main must not be called by the warning formatter CLI")

    monkeypatch.setattr(decision_analysis_cli, "main", forbidden)

    exit_code, _stdout, _stderr = _run(json.dumps([_warning()]))

    assert exit_code == 0


def test_066_no_warning_generation_occurs():
    exit_code, stdout, _stderr = _run("[]")

    assert exit_code == 0
    assert json.loads(stdout) == []


def test_067_no_decision_status_generated():
    _exit_code, stdout, _stderr = _run(json.dumps([_warning()]))

    assert "decision_status" not in stdout


def test_068_no_confidence_generated():
    _exit_code, stdout, _stderr = _run(json.dumps([_warning()]))

    parsed = json.loads(stdout)
    assert "confidence" not in parsed[0]


def test_069_no_trust_modification_occurs():
    _exit_code, stdout, _stderr = _run(json.dumps([_warning()]))

    parsed = json.loads(stdout)
    assert "trust_level" not in parsed[0]


def test_070_no_evidence_metadata_generated():
    _exit_code, stdout, _stderr = _run(json.dumps([_warning()]))

    parsed = json.loads(stdout)
    assert "assertion_type" not in parsed[0]
    assert "supports_hypothesis" not in parsed[0]


# ---------------------------------------------------------------------------
# 71-81: static source-pattern security assertions
# ---------------------------------------------------------------------------

def test_071_no_supabase_access():
    source = _module_source_text()

    assert "import supabase" not in source
    assert "from supabase" not in source
    assert "mcp__supabase" not in source.lower()
    assert ".table(" not in source


def test_072_no_file_access():
    source = _module_source_text()

    assert "open(" not in source
    assert "Path(" not in source
    assert "pathlib" not in source
    assert "os.path" not in source


def test_073_no_temporary_file_creation():
    source = _module_source_text()

    assert "tempfile" not in source
    assert "NamedTemporaryFile" not in source
    assert "mkstemp" not in source


def test_074_no_subprocess():
    source = _module_source_text()

    assert "import subprocess" not in source
    assert "subprocess.run(" not in source
    assert "subprocess.Popen(" not in source
    assert "Popen(" not in source


def test_075_no_network_access():
    source = _module_source_text()

    assert "socket" not in source
    assert "urllib" not in source
    assert "requests" not in source


def test_076_no_ai_or_model_call():
    source = _module_source_text()

    assert "openai" not in source.lower()
    assert "anthropic" not in source.lower()
    assert "messages.create(" not in source
    assert "chat.completions" not in source


def test_077_no_persistence():
    source = _module_source_text()

    assert ".insert(" not in source
    assert ".update(" not in source
    assert ".delete(" not in source
    assert "commit(" not in source


def test_078_no_attack_mapping():
    source = _module_source_text()

    assert "attack_mapping" not in source.lower()
    assert "mitre" not in source.lower()
    assert "technique_id" not in source.lower()


def test_079_no_hashing():
    source = _module_source_text()

    assert "hashlib" not in source
    assert "sha256" not in source.lower()
    assert "md5" not in source.lower()


def test_080_no_approval_or_audit_behavior():
    source = _module_source_text()

    assert "approval" not in source.lower()
    assert "audit" not in source.lower()
    assert "reviewer" not in source.lower()


def test_081_no_containment_or_execution_behavior():
    source = _module_source_text()

    assert "containment" not in source.lower()
    assert "execute_simulation" not in source.lower()
    assert "run_atomic" not in source.lower()


# ---------------------------------------------------------------------------
# 82-96: transport contract, imports, and output-shape boundaries
# ---------------------------------------------------------------------------

def test_082_main_uses_supplied_streams_correctly(capsys):
    exit_code, stdout, stderr = _run(json.dumps([_warning()]))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert exit_code == 0
    assert stdout != ""


def test_083_main_guard_exists():
    source = _module_source_text()

    assert 'if __name__ == "__main__":' in source
    assert "raise SystemExit(main())" in source


def test_084_cli_imports_format_decision_warnings_from_core_decision_warning_formatter():
    assert (
        decision_warning_formatter_cli.format_decision_warnings
        is decision_warning_formatter.format_decision_warnings
    )


def test_085_cli_imports_decision_warning_format_error_from_formatter_module():
    assert (
        decision_warning_formatter_cli.DecisionWarningFormatError
        is decision_warning_formatter.DecisionWarningFormatError
    )


def test_086_cli_does_not_import_decision_context():
    source = _module_source_text()

    assert "import core.decision_context" not in source
    assert "from core.decision_context import" not in source


def test_087_cli_does_not_import_decision_analysis():
    source = _module_source_text()

    assert "import core.decision_analysis" not in source
    assert "from core.decision_analysis import" not in source


def test_088_cli_does_not_redefine_warning_code_vocabulary():
    source = _module_source_text()

    for code in ALL_CODES:
        assert code not in source
    assert not hasattr(decision_warning_formatter_cli, "_WARNING_EXPLANATIONS")


def test_089_cli_does_not_duplicate_explanation_mappings():
    source = _module_source_text()

    for explanation_text in EXPECTED_EXPLANATIONS.values():
        assert explanation_text not in source


def test_090_cli_uses_ensure_ascii_false():
    source = _module_source_text()

    assert "ensure_ascii=False" in source


def test_091_cli_uses_sort_keys_true():
    source = _module_source_text()

    assert "sort_keys=True" in source


def test_092_cli_appends_exactly_one_newline():
    source = _module_source_text()

    assert 'stdout.write("\\n")' in source


def test_093_main_returns_an_integer_exit_code():
    for raw in (json.dumps([_warning()]), "not json", json.dumps({"a": 1})):
        exit_code, _stdout, _stderr = _run(raw)
        assert isinstance(exit_code, int)


def test_094_serialized_output_contains_exactly_three_fields_per_item():
    warnings = [_warning(EVID_A, "EVIDENCE_TRUST_LOW"), _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS")]

    _exit_code, stdout, _stderr = _run(json.dumps(warnings))

    parsed = json.loads(stdout)
    for item in parsed:
        assert set(item.keys()) == {"evidence_id", "code", "explanation"}


def test_095_serialized_output_contains_no_details_or_provenance():
    _exit_code, stdout, _stderr = _run(json.dumps([_warning()]))

    assert "details" not in stdout
    assert "provenance" not in stdout


def test_096_serialized_output_contains_no_free_form_variable_explanation():
    _exit_code1, stdout1, _stderr1 = _run(json.dumps([_warning(EVID_A, "EVIDENCE_TRUST_LOW")]))
    _exit_code2, stdout2, _stderr2 = _run(json.dumps([_warning(EVID_B, "EVIDENCE_TRUST_LOW")]))

    assert json.loads(stdout1)[0]["explanation"] == json.loads(stdout2)[0]["explanation"]


# ---------------------------------------------------------------------------
# Runtime side-effect guard: forbidden entry points must never be reached
# ---------------------------------------------------------------------------

def test_runtime_guard_no_forbidden_entry_points_reached(monkeypatch):
    import sys
    import urllib.request

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called during warning formatter CLI validation")

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

    # core.decision_context_cli / core.decision_analysis_cli / core.decision_context /
    # core.decision_analysis are not checked against sys.modules here: other test
    # files in the same pytest session legitimately import them, so their presence
    # is unrelated to this module and order-dependent. This CLI's avoidance of
    # importing them is verified statically instead (see the source-boundary tests
    # above).
    assert "mcp.hayabusa_server" not in sys.modules

    exit_code, _stdout, _stderr = _run(json.dumps([_warning()]))

    assert exit_code == 0
    assert "mcp.hayabusa_server" not in sys.modules


# ---------------------------------------------------------------------------
# Source-boundary checks: no import of either validator or either CLI
# ---------------------------------------------------------------------------

def test_source_does_not_import_decision_validators_or_clis():
    source = _module_source_text()

    assert "import core.decision_context" not in source
    assert "from core.decision_context import" not in source
    assert "import core.decision_analysis" not in source
    assert "from core.decision_analysis import" not in source
    assert "decision_context_cli" not in source
    assert "decision_analysis_cli" not in source
