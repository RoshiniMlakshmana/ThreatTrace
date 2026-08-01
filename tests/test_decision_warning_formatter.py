"""Tests for core.decision_warning_formatter -- the pure, deterministic
formatter that attaches fixed explanation text to already-produced
decision-context warning objects.

No Supabase, file, subprocess, network, or AI/model access occurs anywhere
in this file; every input is a plain in-memory mapping.
"""

import copy
import socket
import subprocess
from pathlib import Path

import pytest

from core.decision_warning_formatter import (
    DecisionWarningFormatError,
    format_decision_warnings,
)

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


def _module_source_text():
    import core.decision_warning_formatter as module

    with open(module.__file__, "r", encoding="utf-8") as handle:
        return handle.read()


# ---------------------------------------------------------------------------
# 1-11: baseline formatting, codes, ordering, duplicates
# ---------------------------------------------------------------------------

def test_001_empty_warning_list_returns_empty_list():
    assert format_decision_warnings([]) == []


def test_002_one_valid_warning_formats_correctly():
    result = format_decision_warnings([_warning()])

    assert result == [
        {
            "evidence_id": EVID_A,
            "code": "EVIDENCE_TRUST_LOW",
            "explanation": EXPECTED_EXPLANATIONS["EVIDENCE_TRUST_LOW"],
        }
    ]


def test_003_all_eight_warning_codes_format_correctly():
    for code in ALL_CODES:
        result = format_decision_warnings([_warning(code=code)])
        assert result[0]["code"] == code


def test_004_every_explanation_matches_required_text_exactly():
    for code in ALL_CODES:
        result = format_decision_warnings([_warning(code=code)])
        assert result[0]["explanation"] == EXPECTED_EXPLANATIONS[code]


def test_005_output_object_contains_exactly_three_fields():
    result = format_decision_warnings([_warning()])

    assert set(result[0].keys()) == {"evidence_id", "code", "explanation"}


def test_006_multiple_warnings_preserve_input_order():
    warnings = [
        _warning(EVID_B, "EVIDENCE_TRUST_LOW"),
        _warning(EVID_A, "EVIDENCE_CONFIDENCE_UNKNOWN"),
        _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS"),
    ]

    result = format_decision_warnings(warnings)

    assert [(item["evidence_id"], item["code"]) for item in result] == [
        (EVID_B, "EVIDENCE_TRUST_LOW"),
        (EVID_A, "EVIDENCE_CONFIDENCE_UNKNOWN"),
        (EVID_B, "EVIDENCE_IS_HYPOTHESIS"),
    ]


def test_007_context_validator_warning_precedence_preserved_unchanged():
    # Simulates a plausible decision_context.py output order (supporting
    # evidence warnings, then contradicting evidence warnings) -- the
    # formatter must not recompute or resort this sequence.
    warnings = [
        _warning(EVID_A, "EVIDENCE_TRUST_UNKNOWN"),
        _warning(EVID_A, "SUPPORTS_HYPOTHESIS_UNSPECIFIED"),
        _warning(EVID_B, "EVIDENCE_IS_RECOMMENDATION"),
        _warning(EVID_B, "SUPPORTS_HYPOTHESIS_CONFLICT"),
    ]

    result = format_decision_warnings(warnings)

    assert [item["code"] for item in result] == [
        "EVIDENCE_TRUST_UNKNOWN",
        "SUPPORTS_HYPOTHESIS_UNSPECIFIED",
        "EVIDENCE_IS_RECOMMENDATION",
        "SUPPORTS_HYPOTHESIS_CONFLICT",
    ]


def test_008_same_evidence_id_with_different_codes_accepted():
    warnings = [
        _warning(EVID_A, "EVIDENCE_TRUST_LOW"),
        _warning(EVID_A, "EVIDENCE_IS_HYPOTHESIS"),
    ]

    result = format_decision_warnings(warnings)

    assert len(result) == 2


def test_009_same_code_for_different_evidence_ids_accepted():
    warnings = [
        _warning(EVID_A, "EVIDENCE_TRUST_LOW"),
        _warning(EVID_B, "EVIDENCE_TRUST_LOW"),
    ]

    result = format_decision_warnings(warnings)

    assert len(result) == 2


def test_010_exact_duplicate_pair_rejected():
    warnings = [
        _warning(EVID_A, "EVIDENCE_TRUST_LOW"),
        _warning(EVID_A, "EVIDENCE_TRUST_LOW"),
    ]

    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings(warnings)


def test_011_duplicate_detected_after_uuid_canonicalization():
    warnings = [
        _warning("{11111111-1111-4111-8111-111111111111}", "EVIDENCE_TRUST_LOW"),
        _warning("11111111-1111-4111-8111-111111111111", "EVIDENCE_TRUST_LOW"),
    ]

    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings(warnings)


# ---------------------------------------------------------------------------
# 12-29: input-shape and field validation
# ---------------------------------------------------------------------------

def test_012_warnings_must_be_a_list():
    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings({"evidence_id": EVID_A, "code": "EVIDENCE_TRUST_LOW"})


def test_013_tuple_input_rejected():
    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings((_warning(),))


def test_014_none_input_rejected():
    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings(None)


def test_015_warning_entry_must_be_a_mapping():
    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings(["not a mapping"])


def test_016_missing_evidence_id_rejected():
    warning = _warning()
    del warning["evidence_id"]

    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings([warning])


def test_017_missing_code_rejected():
    warning = _warning()
    del warning["code"]

    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings([warning])


def test_018_extra_warning_field_rejected():
    warning = _warning()
    warning["extra_field"] = "unexpected"

    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings([warning])


def test_019_blank_evidence_id_rejected():
    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings([_warning(evidence_id="   ")])


def test_020_non_string_evidence_id_rejected():
    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings([_warning(evidence_id=12345)])


def test_021_malformed_evidence_uuid_rejected():
    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings([_warning(evidence_id="not-a-uuid")])


def test_022_evidence_uuid_canonicalized():
    result = format_decision_warnings(
        [_warning(evidence_id="11111111-1111-4111-8111-111111111111".upper())]
    )

    assert result[0]["evidence_id"] == EVID_A


def test_023_brace_wrapped_valid_uuid_canonicalized():
    result = format_decision_warnings([_warning(evidence_id=f"{{{EVID_A}}}")])

    assert result[0]["evidence_id"] == EVID_A


def test_024_whitespace_around_evidence_uuid_trimmed():
    result = format_decision_warnings([_warning(evidence_id=f"  {EVID_A}  ")])

    assert result[0]["evidence_id"] == EVID_A


def test_025_blank_code_rejected():
    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings([_warning(code="   ")])


def test_026_non_string_code_rejected():
    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings([_warning(code=123)])


def test_027_unknown_code_rejected():
    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings([_warning(code="NOT_A_REAL_CODE")])


def test_028_lowercase_warning_code_rejected():
    with pytest.raises(DecisionWarningFormatError):
        format_decision_warnings([_warning(code="evidence_trust_low")])


def test_029_warning_code_with_surrounding_whitespace_is_trimmed_and_accepted():
    # Chosen rule: codes are trimmed of surrounding whitespace before
    # exact (case-sensitive) vocabulary matching, but never lowercased.
    result = format_decision_warnings([_warning(code="  EVIDENCE_TRUST_LOW  ")])

    assert result[0]["code"] == "EVIDENCE_TRUST_LOW"


# ---------------------------------------------------------------------------
# 30-38: non-mutation, independence, determinism, order/count integrity
# ---------------------------------------------------------------------------

def test_030_input_list_not_mutated():
    warnings = [_warning(EVID_A, "EVIDENCE_TRUST_LOW"), _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS")]
    snapshot = copy.deepcopy(warnings)

    format_decision_warnings(warnings)

    assert warnings == snapshot


def test_031_input_warning_mappings_not_mutated():
    warning = _warning()
    snapshot = copy.deepcopy(warning)

    format_decision_warnings([warning])

    assert warning == snapshot


def test_032_returned_list_is_independent():
    warnings = [_warning()]

    result = format_decision_warnings(warnings)
    result.append({"evidence_id": EVID_B, "code": "EVIDENCE_TRUST_LOW", "explanation": "injected"})

    second_result = format_decision_warnings(warnings)
    assert len(second_result) == 1


def test_033_returned_dictionaries_are_independent():
    warnings = [_warning()]

    result = format_decision_warnings(warnings)
    result[0]["code"] = "MUTATED"

    second_result = format_decision_warnings(warnings)
    assert second_result[0]["code"] == "EVIDENCE_TRUST_LOW"


def test_034_mutating_returned_explanation_does_not_affect_a_fresh_call():
    warnings = [_warning()]

    result = format_decision_warnings(warnings)
    result[0]["explanation"] = "mutated explanation"

    second_result = format_decision_warnings(warnings)
    assert second_result[0]["explanation"] == EXPECTED_EXPLANATIONS["EVIDENCE_TRUST_LOW"]


def test_035_deterministic_repeated_output():
    warnings = [_warning(EVID_A, "EVIDENCE_TRUST_LOW"), _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS")]

    first = format_decision_warnings(warnings)
    second = format_decision_warnings(warnings)

    assert first == second


def test_036_no_warning_is_added():
    warnings = [_warning(EVID_A, "EVIDENCE_TRUST_LOW"), _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS")]

    result = format_decision_warnings(warnings)

    assert len(result) == len(warnings)


def test_037_no_warning_is_removed():
    warnings = [
        _warning(EVID_A, "EVIDENCE_TRUST_LOW"),
        _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS"),
        _warning(EVID_A, "EVIDENCE_CONFIDENCE_UNKNOWN"),
    ]

    result = format_decision_warnings(warnings)

    assert len(result) == 3


def test_038_no_warning_is_reordered():
    warnings = [
        _warning(EVID_B, "EVIDENCE_IS_HYPOTHESIS"),
        _warning(EVID_A, "EVIDENCE_TRUST_LOW"),
    ]

    result = format_decision_warnings(warnings)

    assert [item["evidence_id"] for item in result] == [EVID_B, EVID_A]


# ---------------------------------------------------------------------------
# 39-48: no forbidden fields or generated content in output
# ---------------------------------------------------------------------------

def test_039_no_evidence_metadata_copied():
    result = format_decision_warnings([_warning()])

    forbidden = ("details", "provenance", "source", "trust_level", "confidence", "assertion_type", "supports_hypothesis")
    assert not any(key in result[0] for key in forbidden)


def test_040_no_trust_level_field_generated():
    result = format_decision_warnings([_warning()])
    assert "trust_level" not in result[0]


def test_041_no_confidence_field_generated():
    result = format_decision_warnings([_warning()])
    assert "confidence" not in result[0]


def test_042_no_assertion_type_field_generated():
    result = format_decision_warnings([_warning()])
    assert "assertion_type" not in result[0]


def test_043_no_supports_hypothesis_field_generated():
    result = format_decision_warnings([_warning()])
    assert "supports_hypothesis" not in result[0]


def test_044_no_decision_status_generated():
    result = format_decision_warnings([_warning()])
    assert "decision_status" not in result[0]


def test_045_no_current_assessment_generated():
    result = format_decision_warnings([_warning()])
    assert "current_assessment" not in result[0]


def test_046_no_investigation_metadata_generated():
    result = format_decision_warnings([_warning()])
    assert "investigation" not in result[0]
    assert "status" not in result[0]


def test_047_no_recommendation_generated():
    result = format_decision_warnings([_warning()])
    assert "recommendation" not in result[0]
    assert "recommended_next_evidence" not in result[0]


def test_048_no_model_written_or_variable_explanation_generated():
    first = format_decision_warnings([_warning(EVID_A, "EVIDENCE_TRUST_LOW")])
    second = format_decision_warnings([_warning(EVID_B, "EVIDENCE_TRUST_LOW")])

    assert first[0]["explanation"] == second[0]["explanation"]


# ---------------------------------------------------------------------------
# 49-53: advisory language / no maliciousness inference
# ---------------------------------------------------------------------------

_MALICIOUSNESS_WORDS = ("malicious", "attack", "compromise", "suspicious", "adversary", "threat actor")


def test_049_evidence_trust_unknown_text_does_not_imply_maliciousness():
    text = EXPECTED_EXPLANATIONS["EVIDENCE_TRUST_UNKNOWN"].lower()
    assert not any(word in text for word in _MALICIOUSNESS_WORDS)


def test_050_evidence_trust_low_text_does_not_imply_maliciousness():
    text = EXPECTED_EXPLANATIONS["EVIDENCE_TRUST_LOW"].lower()
    assert not any(word in text for word in _MALICIOUSNESS_WORDS)


def test_051_interpretation_hypothesis_recommendation_texts_distinguish_from_observation():
    for code in ("EVIDENCE_IS_INTERPRETATION", "EVIDENCE_IS_HYPOTHESIS", "EVIDENCE_IS_RECOMMENDATION"):
        assert "not a direct observation" in EXPECTED_EXPLANATIONS[code]


def test_052_conflict_warning_states_only_a_metadata_conflict():
    text = EXPECTED_EXPLANATIONS["SUPPORTS_HYPOTHESIS_CONFLICT"].lower()
    assert "conflicts" in text
    assert not any(word in text for word in _MALICIOUSNESS_WORDS)


def test_053_unspecified_warning_states_only_that_value_was_not_specified():
    text = EXPECTED_EXPLANATIONS["SUPPORTS_HYPOTHESIS_UNSPECIFIED"]
    assert "was not specified" in text


# ---------------------------------------------------------------------------
# 54-64: static source-pattern security assertions
# ---------------------------------------------------------------------------

def test_054_no_supabase_access():
    source = _module_source_text()

    assert "import supabase" not in source
    assert "from supabase" not in source
    assert "mcp__supabase" not in source.lower()
    assert ".table(" not in source


def test_055_no_file_access():
    source = _module_source_text()

    assert "open(" not in source
    assert "Path(" not in source
    assert "pathlib" not in source
    assert "os.path" not in source


def test_056_no_temporary_file_creation():
    source = _module_source_text()

    assert "tempfile" not in source
    assert "NamedTemporaryFile" not in source
    assert "mkstemp" not in source


def test_057_no_subprocess():
    source = _module_source_text()

    assert "import subprocess" not in source
    assert "subprocess.run(" not in source
    assert "subprocess.Popen(" not in source
    assert "Popen(" not in source


def test_058_no_network_access():
    source = _module_source_text()

    assert "socket" not in source
    assert "urllib" not in source
    assert "requests" not in source


def test_059_no_ai_or_model_call():
    source = _module_source_text()

    assert "openai" not in source.lower()
    assert "anthropic" not in source.lower()
    assert "messages.create(" not in source
    assert "chat.completions" not in source


def test_060_no_persistence():
    source = _module_source_text()

    assert ".insert(" not in source
    assert ".update(" not in source
    assert ".delete(" not in source
    assert "commit(" not in source


def test_061_no_attack_mapping():
    source = _module_source_text()

    assert "attack_mapping" not in source.lower()
    assert "mitre" not in source.lower()
    assert "technique_id" not in source.lower()


def test_062_no_hashing():
    source = _module_source_text()

    assert "hashlib" not in source
    assert "sha256" not in source.lower()
    assert "md5" not in source.lower()


def test_063_no_approval_or_audit_behavior():
    source = _module_source_text()

    assert "approval" not in source.lower()
    assert "audit" not in source.lower()
    assert "reviewer" not in source.lower()


def test_064_no_containment_or_execution_behavior():
    source = _module_source_text()

    assert "containment" not in source.lower()
    assert "execute_simulation" not in source.lower()
    assert "run_atomic" not in source.lower()


# ---------------------------------------------------------------------------
# 65-70: no validator invocation, imports, and return-type contract
# ---------------------------------------------------------------------------

def test_065_no_decision_context_validator_call(monkeypatch):
    import core.decision_context as decision_context

    def forbidden(*_args, **_kwargs):
        raise AssertionError("validate_decision_context must not be called by the warning formatter")

    monkeypatch.setattr(decision_context, "validate_decision_context", forbidden)

    result = format_decision_warnings([_warning()])

    assert len(result) == 1


def test_066_no_decision_analysis_validator_call(monkeypatch):
    import core.decision_analysis as decision_analysis

    def forbidden(*_args, **_kwargs):
        raise AssertionError("validate_decision_analysis must not be called by the warning formatter")

    monkeypatch.setattr(decision_analysis, "validate_decision_analysis", forbidden)

    result = format_decision_warnings([_warning()])

    assert len(result) == 1


def test_067_module_uses_only_standard_library_imports():
    source = _module_source_text()

    import_lines = [
        line.strip()
        for line in source.splitlines()
        if line.strip().startswith("import ") or line.strip().startswith("from ")
    ]

    allowed_prefixes = ("from __future__", "import uuid", "from collections.abc", "from typing")
    assert import_lines
    for line in import_lines:
        assert line.startswith(allowed_prefixes), line


def test_068_function_returns_a_list():
    assert isinstance(format_decision_warnings([_warning()]), list)


def test_069_every_returned_item_is_a_new_dictionary():
    warning = _warning()
    result = format_decision_warnings([warning])

    assert isinstance(result[0], dict)
    assert result[0] is not warning


def test_070_exception_class_subclasses_value_error():
    assert issubclass(DecisionWarningFormatError, ValueError)


# ---------------------------------------------------------------------------
# Runtime side-effect guard: forbidden entry points must never be reached
# ---------------------------------------------------------------------------

def test_runtime_guard_no_forbidden_entry_points_reached(monkeypatch):
    import sys
    import urllib.request

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called during warning formatting")

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

    # core.decision_context_cli / core.decision_analysis_cli are not
    # checked against sys.modules here: other test files in the same
    # pytest session legitimately import them, so their presence in
    # sys.modules is unrelated to this module and order-dependent. The
    # formatter's own avoidance of importing either CLI is verified
    # statically instead, in test_source_does_not_import_decision_context_or_decision_analysis.
    assert "mcp.hayabusa_server" not in sys.modules

    result = format_decision_warnings([_warning()])

    assert len(result) == 1
    assert "mcp.hayabusa_server" not in sys.modules


# ---------------------------------------------------------------------------
# Source-boundary checks: no import of either validator or either CLI
# ---------------------------------------------------------------------------

def test_source_does_not_import_decision_context_or_decision_analysis():
    source = _module_source_text()

    assert "import core.decision_context" not in source
    assert "from core.decision_context import" not in source
    assert "import core.decision_analysis" not in source
    assert "from core.decision_analysis import" not in source
    assert "decision_context_cli" not in source
    assert "decision_analysis_cli" not in source
