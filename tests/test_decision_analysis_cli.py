"""Tests for core.decision_analysis_cli -- the stdin/stdout JSON adapter
around core.decision_analysis.validate_decision_analysis.

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

from core import decision_analysis_cli
import core.decision_analysis as decision_analysis
import core.decision_context as decision_context

INVESTIGATION_ID = "11111111-1111-4111-8111-111111111111"
EVID_A = "22222222-2222-4222-8222-222222222222"
EVID_B = "33333333-3333-4333-8333-333333333333"
EVID_C = "44444444-4444-4444-8444-444444444444"


def _payload(**overrides):
    payload = {
        "investigation_id": INVESTIGATION_ID,
        "current_assessment": "The activity is consistent with phishing-driven initial access.",
        "decision_status": "supported",
        "supporting_evidence_ids": [EVID_A],
        "contradicting_evidence_ids": [],
    }
    payload.update(overrides)
    return payload


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = decision_analysis_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _module_source_text():
    with open(decision_analysis_cli.__file__, "r", encoding="utf-8") as handle:
        return handle.read()


# ---------------------------------------------------------------------------
# 1-8: baseline valid analyses
# ---------------------------------------------------------------------------

def test_001_valid_supported_analysis_returns_0():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload(decision_status="supported")))

    assert exit_code == 0


def test_002_valid_partially_supported_analysis_returns_0():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload(decision_status="partially_supported")))

    assert exit_code == 0


def test_003_valid_contradicted_analysis_returns_0():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload(decision_status="contradicted")))

    assert exit_code == 0


def test_004_valid_inconclusive_analysis_returns_0():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload(decision_status="inconclusive")))

    assert exit_code == 0


def test_005_valid_insufficient_evidence_analysis_returns_0():
    payload = _payload(
        decision_status="insufficient_evidence",
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[],
    )

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 0


def test_006_valid_analysis_with_supporting_evidence_returns_0():
    payload = _payload(supporting_evidence_ids=[EVID_A, EVID_C], contradicting_evidence_ids=[])

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 0


def test_007_valid_analysis_with_contradicting_evidence_returns_0():
    payload = _payload(supporting_evidence_ids=[], contradicting_evidence_ids=[EVID_B])

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 0


def test_008_valid_analysis_with_all_seven_advisory_collections_returns_0():
    payload = _payload(
        unresolved_assumptions=["assumption one"],
        evidence_gaps=["gap one"],
        strengthen_conditions=["strengthen one"],
        weaken_conditions=["weaken one"],
        reversal_conditions=["reversal one"],
        recommended_next_evidence=["next evidence one"],
        limitations=["limitation one"],
    )

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 0


# ---------------------------------------------------------------------------
# 9-19: success shape, ordering, and transport details
# ---------------------------------------------------------------------------

def test_009_success_stdout_contains_exactly_one_json_object():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    parsed = json.loads(stdout)
    assert isinstance(parsed, dict)


def test_010_success_stdout_ends_with_exactly_one_newline():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    assert stdout.endswith("\n")
    assert not stdout.endswith("\n\n")


def test_011_success_stderr_is_empty():
    _exit_code, _stdout, stderr = _run(json.dumps(_payload()))

    assert stderr == ""


def test_012_success_output_equals_validate_decision_analysis_output():
    payload = _payload(generated_at="2026-08-01T12:00:00Z")

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    assert json.loads(stdout) == decision_analysis.validate_decision_analysis(payload)


def test_013_success_json_uses_deterministic_key_ordering():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    parsed = json.loads(stdout)
    assert list(parsed.keys()) == sorted(parsed.keys())


def test_014_supporting_evidence_id_order_preserved():
    payload = _payload(supporting_evidence_ids=[EVID_C, EVID_A], contradicting_evidence_ids=[])

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    parsed = json.loads(stdout)
    assert parsed["supporting_evidence_ids"] == [EVID_C, EVID_A]


def test_015_contradicting_evidence_id_order_preserved():
    payload = _payload(supporting_evidence_ids=[], contradicting_evidence_ids=[EVID_C, EVID_B])

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    parsed = json.loads(stdout)
    assert parsed["contradicting_evidence_ids"] == [EVID_C, EVID_B]


def test_016_condition_list_order_preserved():
    payload = _payload(evidence_gaps=["gap-three", "gap-one", "gap-two"])

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    parsed = json.loads(stdout)
    assert parsed["evidence_gaps"] == ["gap-three", "gap-one", "gap-two"]


def test_017_unicode_assessment_text_preserved_with_ensure_ascii_false():
    payload = _payload(current_assessment="café-hôte-注意 assessment")

    exit_code, stdout, _stderr = _run(json.dumps(payload, ensure_ascii=False))

    assert exit_code == 0
    assert "café-hôte-注意" in stdout
    assert "\\u" not in stdout


def test_018_leading_whitespace_accepted():
    exit_code, _stdout, _stderr = _run("   \n\t" + json.dumps(_payload()))

    assert exit_code == 0


def test_019_trailing_whitespace_accepted():
    exit_code, _stdout, _stderr = _run(json.dumps(_payload()) + "   \n")

    assert exit_code == 0


# ---------------------------------------------------------------------------
# 20-32: rejected raw input
# ---------------------------------------------------------------------------

def test_020_empty_stdin_rejected():
    exit_code, stdout, stderr = _run("")

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_021_whitespace_only_stdin_rejected():
    exit_code, stdout, stderr = _run("   \n\t  ")

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_022_malformed_json_rejected():
    exit_code, stdout, stderr = _run("{not valid json")

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_023_truncated_json_rejected():
    raw = json.dumps(_payload())[:-5]

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_024_json_null_rejected():
    exit_code, stdout, stderr = _run("null")

    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Decision analysis input must be a JSON object.\n"


def test_025_json_string_rejected():
    exit_code, stdout, stderr = _run('"a string"')

    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Decision analysis input must be a JSON object.\n"


def test_026_json_number_rejected():
    exit_code, stdout, stderr = _run("42")

    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Decision analysis input must be a JSON object.\n"


def test_027_json_boolean_rejected():
    exit_code, stdout, stderr = _run("true")

    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Decision analysis input must be a JSON object.\n"


def test_028_json_array_rejected():
    exit_code, stdout, stderr = _run("[]")

    assert exit_code == 2
    assert stdout == ""
    assert stderr == "Decision analysis input must be a JSON object.\n"


def test_029_two_json_objects_rejected():
    raw = json.dumps(_payload()) + json.dumps(_payload())

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_030_object_followed_by_json_string_rejected():
    raw = json.dumps(_payload()) + ' "trailing"'

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_031_object_followed_by_json_number_rejected():
    raw = json.dumps(_payload()) + " 5"

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


def test_032_object_followed_by_trailing_text_rejected():
    raw = json.dumps(_payload()) + " garbage"

    exit_code, stdout, stderr = _run(raw)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.startswith("Invalid JSON input:")


# ---------------------------------------------------------------------------
# 33-52: decision-analysis validation failures surfaced as exit code 2
# ---------------------------------------------------------------------------

def test_033_validation_failure_returns_exit_code_2():
    payload = _payload()
    del payload["current_assessment"]

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_034_validation_failure_leaves_stdout_empty():
    payload = _payload()
    del payload["current_assessment"]

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    assert stdout == ""


def test_035_validation_failure_writes_one_stderr_line():
    payload = _payload()
    del payload["current_assessment"]

    _exit_code, _stdout, stderr = _run(json.dumps(payload))

    assert stderr.count("\n") == 1


def test_036_decision_analysis_error_message_safely_surfaced():
    payload = _payload()
    del payload["current_assessment"]

    _exit_code, _stdout, stderr = _run(json.dumps(payload))

    assert stderr.startswith("Decision analysis validation failed:")
    assert "current_assessment" in stderr


def test_037_missing_investigation_id_returns_2():
    payload = _payload()
    del payload["investigation_id"]

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_038_invalid_investigation_uuid_returns_2():
    payload = _payload(investigation_id="not-a-uuid")

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_039_non_null_hypothesis_id_returns_2():
    payload = _payload(hypothesis_id="77777777-7777-4777-8777-777777777777")

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_040_missing_current_assessment_returns_2():
    payload = _payload()
    del payload["current_assessment"]

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_041_blank_current_assessment_returns_2():
    payload = _payload(current_assessment="   ")

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_042_missing_decision_status_returns_2():
    payload = _payload()
    del payload["decision_status"]

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_043_unsupported_decision_status_returns_2():
    payload = _payload(decision_status="maybe")

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_044_malformed_supporting_evidence_uuid_returns_2():
    payload = _payload(supporting_evidence_ids=["not-a-uuid"])

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_045_malformed_contradicting_evidence_uuid_returns_2():
    payload = _payload(supporting_evidence_ids=[], contradicting_evidence_ids=["not-a-uuid"])

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_046_duplicate_supporting_evidence_id_returns_2():
    payload = _payload(supporting_evidence_ids=[EVID_A, EVID_A])

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_047_duplicate_contradicting_evidence_id_returns_2():
    payload = _payload(supporting_evidence_ids=[], contradicting_evidence_ids=[EVID_B, EVID_B])

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_048_evidence_list_overlap_returns_2():
    payload = _payload(supporting_evidence_ids=[EVID_A], contradicting_evidence_ids=[EVID_A])

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_049_malformed_condition_collection_returns_2():
    payload = _payload(evidence_gaps="not a list")

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_050_blank_condition_entry_returns_2():
    payload = _payload(evidence_gaps=["   "])

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_051_duplicate_condition_entry_returns_2():
    payload = _payload(evidence_gaps=["same entry", "same entry"])

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


def test_052_invalid_generated_at_returns_2():
    payload = _payload(generated_at="not-a-timestamp")

    exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert exit_code == 2


# ---------------------------------------------------------------------------
# 53-60: unexpected internal failure handling and error redaction
# ---------------------------------------------------------------------------

def test_053_unexpected_validator_exception_returns_1(monkeypatch):
    def boom(_payload):
        raise RuntimeError("simulated internal failure")

    monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", boom)

    exit_code, _stdout, _stderr = _run(json.dumps(_payload()))

    assert exit_code == 1


def test_054_unexpected_failure_stdout_empty(monkeypatch):
    def boom(_payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", boom)

    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    assert stdout == ""


def test_055_unexpected_failure_stderr_exact_message(monkeypatch):
    def boom(_payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_payload()))

    assert stderr == "Decision analysis validation failed.\n"


def test_056_unexpected_failure_exposes_no_exception_text(monkeypatch):
    secret_marker = "super-secret-internal-detail-xyz"

    def boom(_payload):
        raise RuntimeError(secret_marker)

    monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", boom)

    _exit_code, _stdout, stderr = _run(json.dumps(_payload()))

    assert secret_marker not in stderr
    assert "RuntimeError" not in stderr


def test_057_no_traceback_appears(monkeypatch):
    def boom(_payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", boom)

    _exit_code, _stdout, unexpected_stderr = _run(json.dumps(_payload()))

    payload = _payload()
    del payload["current_assessment"]
    _exit_code2, _stdout2, validation_stderr = _run(json.dumps(payload))

    assert "Traceback" not in unexpected_stderr
    assert "Traceback" not in validation_stderr


def test_058_input_payload_is_not_echoed():
    marker = "SECRET-INPUT-MARKER-abc123"
    payload = _payload(current_assessment=marker, decision_status="maybe")

    _exit_code, stdout, stderr = _run(json.dumps(payload))

    assert marker not in stdout
    assert marker not in stderr


def test_059_assessment_text_not_leaked_on_unexpected_failure(monkeypatch):
    marker = "SECRET-ASSESSMENT-TEXT-xyz789"

    def boom(_payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", boom)

    payload = _payload(current_assessment=marker)
    _exit_code, stdout, stderr = _run(json.dumps(payload))

    assert marker not in stdout
    assert marker not in stderr


def test_060_condition_list_content_not_leaked_on_unexpected_failure(monkeypatch):
    marker = "SECRET-CONDITION-CONTENT-uvw456"

    def boom(_payload):
        raise RuntimeError("boom")

    monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", boom)

    payload = _payload(evidence_gaps=[marker])
    _exit_code, stdout, stderr = _run(json.dumps(payload))

    assert marker not in stdout
    assert marker not in stderr


# ---------------------------------------------------------------------------
# 61-67: call integrity and non-mutation
# ---------------------------------------------------------------------------

def test_061_validator_called_exactly_once_on_valid_input(monkeypatch):
    calls = []
    original = decision_analysis_cli.validate_decision_analysis

    def counting_validate(payload):
        calls.append(payload)
        return original(payload)

    monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", counting_validate)

    exit_code, _stdout, _stderr = _run(json.dumps(_payload()))

    assert exit_code == 0
    assert len(calls) == 1


def test_062_validator_not_called_for_malformed_json(monkeypatch):
    def forbidden(_payload):
        raise AssertionError("validate_decision_analysis must not be called for malformed JSON")

    monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", forbidden)

    exit_code, _stdout, _stderr = _run("{not valid json")

    assert exit_code == 2


def test_063_validator_not_called_for_non_object_json(monkeypatch):
    def forbidden(_payload):
        raise AssertionError("validate_decision_analysis must not be called for non-object JSON")

    monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", forbidden)

    exit_code, _stdout, _stderr = _run("null")

    assert exit_code == 2


def test_064_validator_not_called_for_multiple_json_values(monkeypatch):
    def forbidden(_payload):
        raise AssertionError("validate_decision_analysis must not be called for multiple JSON values")

    monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", forbidden)

    raw = json.dumps(_payload()) + json.dumps(_payload())
    exit_code, _stdout, _stderr = _run(raw)

    assert exit_code == 2


def test_065_validator_return_value_not_mutated(monkeypatch):
    fixed_result = {
        "investigation_id": INVESTIGATION_ID,
        "hypothesis_id": None,
        "current_assessment": "fixed assessment",
        "decision_status": "supported",
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
        "unresolved_assumptions": [],
        "evidence_gaps": [],
        "strengthen_conditions": [],
        "weaken_conditions": [],
        "reversal_conditions": [],
        "recommended_next_evidence": [],
        "limitations": [],
        "generated_at": "2026-08-01T12:00:00Z",
    }
    snapshot = copy.deepcopy(fixed_result)

    monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", lambda _payload: fixed_result)

    exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    assert exit_code == 0
    assert fixed_result == snapshot
    assert json.loads(stdout) == snapshot


def test_066_decoded_mapping_is_passed_to_validator(monkeypatch):
    captured = {}

    def capturing_validate(payload):
        captured["payload"] = payload
        return decision_analysis.validate_decision_analysis(payload)

    monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", capturing_validate)

    payload = _payload()
    _exit_code, _stdout, _stderr = _run(json.dumps(payload))

    assert captured["payload"] == payload


# ---------------------------------------------------------------------------
# 67-79: no decision-context call, and no generated/derived fields
# ---------------------------------------------------------------------------

def test_067_no_decision_context_validator_call_occurs(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("validate_decision_context must not be called by the decision-analysis CLI")

    monkeypatch.setattr(decision_context, "validate_decision_context", forbidden)

    exit_code, _stdout, _stderr = _run(json.dumps(_payload()))

    assert exit_code == 0


def test_068_caller_supplied_decision_status_preserved():
    for status in ("supported", "partially_supported", "contradicted", "inconclusive"):
        _exit_code, stdout, _stderr = _run(json.dumps(_payload(decision_status=status)))
        assert json.loads(stdout)["decision_status"] == status


def test_069_evidence_count_does_not_alter_decision_status():
    payload_no_evidence = _payload(
        decision_status="supported",
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[],
    )
    payload_with_evidence = _payload(
        decision_status="supported",
        supporting_evidence_ids=[EVID_A, EVID_C],
        contradicting_evidence_ids=[EVID_B],
    )

    _exit_code1, stdout1, _stderr1 = _run(json.dumps(payload_no_evidence))
    _exit_code2, stdout2, _stderr2 = _run(json.dumps(payload_with_evidence))

    assert json.loads(stdout1)["decision_status"] == "supported"
    assert json.loads(stdout2)["decision_status"] == "supported"


def test_070_condition_count_does_not_alter_decision_status():
    payload_no_conditions = _payload(decision_status="contradicted")
    payload_with_conditions = _payload(
        decision_status="contradicted",
        unresolved_assumptions=["one", "two", "three"],
        evidence_gaps=["gap"],
    )

    _exit_code1, stdout1, _stderr1 = _run(json.dumps(payload_no_conditions))
    _exit_code2, stdout2, _stderr2 = _run(json.dumps(payload_with_conditions))

    assert json.loads(stdout1)["decision_status"] == "contradicted"
    assert json.loads(stdout2)["decision_status"] == "contradicted"


def test_071_hypothesis_id_remains_none():
    payload_without = _payload()
    payload_with_null = _payload(hypothesis_id=None)

    _exit_code1, stdout1, _stderr1 = _run(json.dumps(payload_without))
    _exit_code2, stdout2, _stderr2 = _run(json.dumps(payload_with_null))

    assert json.loads(stdout1)["hypothesis_id"] is None
    assert json.loads(stdout2)["hypothesis_id"] is None


def test_072_generated_at_created_when_omitted():
    payload = _payload()
    assert "generated_at" not in payload

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    parsed = json.loads(stdout)
    assert isinstance(parsed["generated_at"], str)
    assert parsed["generated_at"].endswith("Z")


def test_073_supplied_generated_at_canonicalized_by_validator():
    payload = _payload(generated_at="2026-08-01T08:45:00-07:00")

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    assert json.loads(stdout)["generated_at"] == "2026-08-01T15:45:00Z"


def test_074_cli_does_not_regenerate_a_validator_returned_generated_at(monkeypatch):
    fixed_result = {
        "investigation_id": INVESTIGATION_ID,
        "hypothesis_id": None,
        "current_assessment": "fixed assessment",
        "decision_status": "supported",
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
        "unresolved_assumptions": [],
        "evidence_gaps": [],
        "strengthen_conditions": [],
        "weaken_conditions": [],
        "reversal_conditions": [],
        "recommended_next_evidence": [],
        "limitations": [],
        "generated_at": "FIXED-TIMESTAMP-MARKER",
    }

    monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", lambda _payload: fixed_result)

    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    assert json.loads(stdout)["generated_at"] == "FIXED-TIMESTAMP-MARKER"


def test_075_no_confidence_field_generated():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    assert "confidence" not in json.loads(stdout)


def test_076_no_trust_level_field_generated():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    assert "trust_level" not in json.loads(stdout)


def test_077_no_investigation_status_generated():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    parsed = json.loads(stdout)
    assert "investigation" not in parsed
    assert "status" not in parsed


def test_078_no_context_warning_generated():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    assert "warnings" not in json.loads(stdout)


def test_079_no_evidence_metadata_generated():
    payload = _payload(supporting_evidence_ids=[EVID_A], contradicting_evidence_ids=[EVID_B])

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    parsed = json.loads(stdout)
    for evidence_id in parsed["supporting_evidence_ids"] + parsed["contradicting_evidence_ids"]:
        assert isinstance(evidence_id, str)


# ---------------------------------------------------------------------------
# 80-90: static source-pattern security assertions
# ---------------------------------------------------------------------------

def test_080_no_supabase_access_occurs():
    source = _module_source_text()

    assert "import supabase" not in source
    assert "from supabase" not in source
    assert "mcp__supabase" not in source.lower()
    assert ".table(" not in source


def test_081_no_file_access_occurs():
    source = _module_source_text()

    assert "open(" not in source
    assert "Path(" not in source
    assert "pathlib" not in source
    assert "os.path" not in source


def test_082_no_temporary_file_is_created():
    source = _module_source_text()

    assert "tempfile" not in source
    assert "NamedTemporaryFile" not in source
    assert "mkstemp" not in source


def test_083_no_subprocess_occurs():
    source = _module_source_text()

    assert "import subprocess" not in source
    assert "subprocess.run(" not in source
    assert "subprocess.Popen(" not in source
    assert "subprocess.call(" not in source
    assert "Popen(" not in source


def test_084_no_network_access_occurs():
    source = _module_source_text()

    assert "socket" not in source
    assert "urllib" not in source
    assert "requests" not in source


def test_085_no_ai_or_model_call_occurs():
    source = _module_source_text()

    assert "openai" not in source.lower()
    assert "anthropic" not in source.lower()
    assert "messages.create(" not in source
    assert "chat.completions" not in source


def test_086_no_persistence_occurs():
    source = _module_source_text()

    assert ".insert(" not in source
    assert ".update(" not in source
    assert ".delete(" not in source
    assert "commit(" not in source


def test_087_no_attack_mapping_occurs():
    source = _module_source_text()

    assert "attack_mapping" not in source.lower()
    assert "mitre" not in source.lower()
    assert "technique_id" not in source.lower()


def test_088_no_evidence_hashing_occurs():
    source = _module_source_text()

    assert "hashlib" not in source
    assert "sha256" not in source.lower()
    assert "md5" not in source.lower()


def test_089_no_approval_or_audit_behavior_occurs():
    source = _module_source_text()

    assert "approval" not in source.lower()
    assert "audit" not in source.lower()
    assert "reviewer" not in source.lower()


def test_090_no_containment_or_execution_behavior_occurs():
    source = _module_source_text()

    assert "containment" not in source.lower()
    assert "execute_simulation" not in source.lower()
    assert "run_atomic" not in source.lower()


# ---------------------------------------------------------------------------
# 91-103: transport contract, boundaries, and non-mutation
# ---------------------------------------------------------------------------

def test_091_main_uses_supplied_streams_correctly(capsys):
    exit_code, stdout, stderr = _run(json.dumps(_payload()))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert exit_code == 0
    assert stdout != ""


def test_092_main_guard_exists():
    source = _module_source_text()

    assert 'if __name__ == "__main__":' in source
    assert "raise SystemExit(main())" in source


def test_093_cli_imports_validate_decision_analysis_from_core_decision_analysis():
    assert decision_analysis_cli.validate_decision_analysis is decision_analysis.validate_decision_analysis


def test_094_cli_does_not_import_validate_decision_context():
    source = _module_source_text()

    assert "from core.decision_context import" not in source
    assert "import core.decision_context" not in source
    assert not hasattr(decision_analysis_cli, "validate_decision_context")


def test_095_cli_does_not_redefine_decision_status_vocabulary():
    source = _module_source_text()

    assert "DECISION_STATUSES" not in source
    assert not hasattr(decision_analysis_cli, "DECISION_STATUSES")


def test_096_cli_does_not_duplicate_condition_validation():
    source = _module_source_text()

    assert "_validate_condition_list" not in source
    assert "_CONDITION_FIELDS" not in source


def test_097_cli_uses_ensure_ascii_false():
    source = _module_source_text()

    assert "ensure_ascii=False" in source


def test_098_cli_uses_sort_keys_true():
    source = _module_source_text()

    assert "sort_keys=True" in source


def test_099_cli_appends_exactly_one_newline():
    source = _module_source_text()

    assert 'stdout.write("\\n")' in source


def test_100_main_returns_an_integer_exit_code():
    for raw in (json.dumps(_payload()), "not json", json.dumps([1, 2])):
        exit_code, _stdout, _stderr = _run(raw)
        assert isinstance(exit_code, int)


def test_101_input_mapping_and_nested_lists_not_mutated(monkeypatch):
    captured = {}

    def capturing_validate(payload):
        captured["snapshot"] = copy.deepcopy(payload)
        result = decision_analysis.validate_decision_analysis(payload)
        captured["payload_ref"] = payload
        return result

    monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", capturing_validate)

    payload = _payload(evidence_gaps=["gap-one", "gap-two"])
    _run(json.dumps(payload))

    assert captured["payload_ref"] == captured["snapshot"]


def test_102_serialized_output_contains_no_context_metadata():
    _exit_code, stdout, _stderr = _run(json.dumps(_payload()))

    for forbidden_key in ("warnings", "trust_level", "confidence", "assertion_type", "supports_hypothesis", "investigation"):
        assert forbidden_key not in json.loads(stdout)


def test_103_serialized_output_contains_no_complete_evidence_records():
    payload = _payload(supporting_evidence_ids=[EVID_A], contradicting_evidence_ids=[EVID_B])

    _exit_code, stdout, _stderr = _run(json.dumps(payload))

    parsed = json.loads(stdout)
    assert all(isinstance(item, str) for item in parsed["supporting_evidence_ids"])
    assert all(isinstance(item, str) for item in parsed["contradicting_evidence_ids"])


# ---------------------------------------------------------------------------
# Runtime side-effect guard: forbidden entry points must never be reached
# ---------------------------------------------------------------------------

def test_runtime_guard_no_forbidden_entry_points_reached(monkeypatch):
    import sys
    import urllib.request

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called during decision-analysis CLI validation")

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
