"""Tests for core.decision_analysis -- the pure, deterministic validator for
one advisory "What Would Change My Decision?" analysis object.

No Supabase, file, subprocess, network, or AI/model access occurs anywhere
in this file; every input is a plain in-memory dict.
"""

import copy
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.decision_analysis import DecisionAnalysisError, validate_decision_analysis

INVESTIGATION_ID = "11111111-1111-4111-8111-111111111111"
EVIDENCE_ID_A = "22222222-2222-4222-8222-222222222222"
EVIDENCE_ID_B = "33333333-3333-4333-8333-333333333333"
EVIDENCE_ID_C = "44444444-4444-4444-8444-444444444444"


def _payload(**overrides):
    payload = {
        "investigation_id": INVESTIGATION_ID,
        "current_assessment": "Observed PowerShell execution is consistent with scripted automation.",
        "decision_status": "supported",
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# 1-5: valid decision_status values
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "status",
    ["supported", "partially_supported", "contradicted", "inconclusive", "insufficient_evidence"],
)
def test_valid_decision_status_accepted(status):
    result = validate_decision_analysis(_payload(decision_status=status))

    assert result["decision_status"] == status


# ---------------------------------------------------------------------------
# 6-10: investigation_id
# ---------------------------------------------------------------------------

def test_missing_investigation_id_rejected():
    payload = _payload()
    del payload["investigation_id"]

    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(payload)


def test_blank_investigation_id_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(investigation_id="   "))


def test_non_string_investigation_id_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(investigation_id=12345))


def test_malformed_investigation_uuid_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(investigation_id="not-a-uuid"))


def test_investigation_uuid_canonicalized():
    result = validate_decision_analysis(
        _payload(investigation_id="{11111111-1111-4111-8111-111111111111}")
    )

    assert result["investigation_id"] == INVESTIGATION_ID


# ---------------------------------------------------------------------------
# 11-13: hypothesis_id
# ---------------------------------------------------------------------------

def test_omitted_hypothesis_id_becomes_none():
    result = validate_decision_analysis(_payload())

    assert result["hypothesis_id"] is None


def test_explicit_hypothesis_id_none_accepted():
    result = validate_decision_analysis(_payload(hypothesis_id=None))

    assert result["hypothesis_id"] is None


@pytest.mark.parametrize("value", ["some-id", EVIDENCE_ID_A, 123])
def test_non_null_hypothesis_id_rejected(value):
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(hypothesis_id=value))


# ---------------------------------------------------------------------------
# 14-17: current_assessment
# ---------------------------------------------------------------------------

def test_missing_current_assessment_rejected():
    payload = _payload()
    del payload["current_assessment"]

    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(payload)


def test_blank_current_assessment_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(current_assessment="   "))


def test_non_string_current_assessment_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(current_assessment=42))


def test_current_assessment_trimmed():
    result = validate_decision_analysis(_payload(current_assessment="  padded text  "))

    assert result["current_assessment"] == "padded text"


# ---------------------------------------------------------------------------
# 18-21: decision_status validation
# ---------------------------------------------------------------------------

def test_missing_decision_status_rejected():
    payload = _payload()
    del payload["decision_status"]

    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(payload)


def test_blank_decision_status_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(decision_status="   "))


def test_unsupported_decision_status_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(decision_status="definitely_not_valid"))


def test_decision_status_canonicalized_to_lowercase():
    result = validate_decision_analysis(_payload(decision_status="SUPPORTED"))

    assert result["decision_status"] == "supported"


# ---------------------------------------------------------------------------
# 22-37: evidence-ID collections
# ---------------------------------------------------------------------------

def test_supporting_evidence_omitted_becomes_empty_list():
    result = validate_decision_analysis(_payload())

    assert result["supporting_evidence_ids"] == []


def test_contradicting_evidence_omitted_becomes_empty_list():
    result = validate_decision_analysis(_payload())

    assert result["contradicting_evidence_ids"] == []


def test_supporting_evidence_must_be_a_list():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(supporting_evidence_ids="not-a-list"))


def test_contradicting_evidence_must_be_a_list():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(contradicting_evidence_ids="not-a-list"))


def test_supporting_evidence_entry_must_be_a_string():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(supporting_evidence_ids=[12345]))


def test_contradicting_evidence_entry_must_be_a_string():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(contradicting_evidence_ids=[12345]))


def test_malformed_supporting_evidence_uuid_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(supporting_evidence_ids=["not-a-uuid"]))


def test_malformed_contradicting_evidence_uuid_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(contradicting_evidence_ids=["not-a-uuid"]))


def test_evidence_uuids_canonicalized():
    result = validate_decision_analysis(
        _payload(supporting_evidence_ids=[f"{{{EVIDENCE_ID_A}}}"])
    )

    assert result["supporting_evidence_ids"] == [EVIDENCE_ID_A]


def test_duplicate_supporting_evidence_id_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(
            _payload(supporting_evidence_ids=[EVIDENCE_ID_A, EVIDENCE_ID_A])
        )


def test_duplicate_contradicting_evidence_id_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(
            _payload(contradicting_evidence_ids=[EVIDENCE_ID_A, EVIDENCE_ID_A])
        )


def test_duplicate_ids_detected_after_canonicalization():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(
            _payload(supporting_evidence_ids=[EVIDENCE_ID_A, f"{{{EVIDENCE_ID_A}}}"])
        )


def test_same_evidence_id_in_both_lists_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(
            _payload(
                supporting_evidence_ids=[EVIDENCE_ID_A],
                contradicting_evidence_ids=[EVIDENCE_ID_A],
            )
        )


def test_empty_supporting_list_accepted():
    result = validate_decision_analysis(_payload(supporting_evidence_ids=[]))

    assert result["supporting_evidence_ids"] == []


def test_empty_contradicting_list_accepted():
    result = validate_decision_analysis(_payload(contradicting_evidence_ids=[]))

    assert result["contradicting_evidence_ids"] == []


def test_both_evidence_lists_empty_with_insufficient_evidence_accepted():
    result = validate_decision_analysis(
        _payload(
            decision_status="insufficient_evidence",
            supporting_evidence_ids=[],
            contradicting_evidence_ids=[],
        )
    )

    assert result["decision_status"] == "insufficient_evidence"
    assert result["supporting_evidence_ids"] == []
    assert result["contradicting_evidence_ids"] == []


# ---------------------------------------------------------------------------
# 38-46: condition collections
# ---------------------------------------------------------------------------

_CONDITION_FIELDS = [
    "unresolved_assumptions",
    "evidence_gaps",
    "strengthen_conditions",
    "weaken_conditions",
    "reversal_conditions",
    "recommended_next_evidence",
    "limitations",
]


@pytest.mark.parametrize("field", _CONDITION_FIELDS)
def test_condition_field_omitted_becomes_empty_list(field):
    result = validate_decision_analysis(_payload())

    assert result[field] == []


@pytest.mark.parametrize("field", _CONDITION_FIELDS)
def test_condition_value_none_rejected(field):
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(**{field: None}))


@pytest.mark.parametrize("field", _CONDITION_FIELDS)
def test_condition_collection_must_be_a_list(field):
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(**{field: "not-a-list"}))


def test_condition_entry_must_be_a_string():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(evidence_gaps=[123]))


def test_blank_condition_entry_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(evidence_gaps=["   "]))


def test_condition_entries_trimmed():
    result = validate_decision_analysis(_payload(evidence_gaps=["  padded gap  "]))

    assert result["evidence_gaps"] == ["padded gap"]


def test_duplicate_condition_text_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(
            _payload(evidence_gaps=["missing process ancestry", "missing process ancestry"])
        )


def test_duplicate_condition_detected_after_trimming():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(
            _payload(evidence_gaps=["missing process ancestry", "  missing process ancestry  "])
        )


def test_condition_order_preserved():
    result = validate_decision_analysis(
        _payload(evidence_gaps=["first gap", "second gap", "third gap"])
    )

    assert result["evidence_gaps"] == ["first gap", "second gap", "third gap"]


# ---------------------------------------------------------------------------
# 47-57: generated_at
# ---------------------------------------------------------------------------

def test_missing_generated_at_creates_utc_z_timestamp():
    result = validate_decision_analysis(_payload())

    assert result["generated_at"].endswith("Z")


def test_generated_at_none_creates_utc_z_timestamp():
    result = validate_decision_analysis(_payload(generated_at=None))

    assert result["generated_at"].endswith("Z")


def test_supplied_generated_at_canonicalized_to_utc_z():
    result = validate_decision_analysis(_payload(generated_at="2026-07-31T20:15:30+00:00"))

    assert result["generated_at"] == "2026-07-31T20:15:30Z"


def test_offset_timestamp_converted_correctly():
    result = validate_decision_analysis(_payload(generated_at="2026-07-31T15:15:30-05:00"))

    assert result["generated_at"] == "2026-07-31T20:15:30Z"


def test_timezone_naive_generated_at_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(generated_at="2026-07-31T20:15:30"))


def test_malformed_generated_at_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(generated_at="not-a-timestamp"))


def test_injected_aware_now_produces_deterministic_output():
    fixed_now = datetime(2026, 6, 15, 9, 30, 0, tzinfo=timezone.utc)

    result = validate_decision_analysis(_payload(), now=fixed_now)

    assert result["generated_at"] == "2026-06-15T09:30:00Z"


def test_naive_now_rejected():
    naive_now = datetime(2026, 6, 15, 9, 30, 0)

    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(), now=naive_now)


def test_supplied_generated_at_takes_precedence_over_now():
    fixed_now = datetime(2026, 6, 15, 9, 30, 0, tzinfo=timezone.utc)

    result = validate_decision_analysis(
        _payload(generated_at="2026-07-31T20:15:30Z"), now=fixed_now
    )

    assert result["generated_at"] == "2026-07-31T20:15:30Z"


def test_repeated_validation_preserves_generated_at_exactly():
    first = validate_decision_analysis(_payload())
    second = validate_decision_analysis(first)

    assert second["generated_at"] == first["generated_at"]


def test_complete_normalized_object_is_idempotent():
    first = validate_decision_analysis(
        _payload(
            supporting_evidence_ids=[EVIDENCE_ID_A],
            contradicting_evidence_ids=[EVIDENCE_ID_B],
            evidence_gaps=["missing process ancestry"],
        )
    )
    second = validate_decision_analysis(first)

    assert second == first


# ---------------------------------------------------------------------------
# 58: unknown top-level field
# ---------------------------------------------------------------------------

def test_unknown_top_level_field_rejected():
    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(_payload(totally_unknown_field="x"))


# ---------------------------------------------------------------------------
# 59-63: non-mutation and independent copies
# ---------------------------------------------------------------------------

def test_original_input_not_mutated():
    payload = _payload(
        supporting_evidence_ids=[EVIDENCE_ID_A],
        evidence_gaps=["missing process ancestry"],
    )
    snapshot = copy.deepcopy(payload)

    validate_decision_analysis(payload)

    assert payload == snapshot


def test_original_nested_evidence_lists_not_mutated():
    evidence_list = [EVIDENCE_ID_A]
    payload = _payload(supporting_evidence_ids=evidence_list)

    validate_decision_analysis(payload)

    assert evidence_list == [EVIDENCE_ID_A]


def test_original_condition_lists_not_mutated():
    condition_list = ["missing process ancestry"]
    payload = _payload(evidence_gaps=condition_list)

    validate_decision_analysis(payload)

    assert condition_list == ["missing process ancestry"]


def test_returned_evidence_lists_are_independent_copies():
    payload = _payload(supporting_evidence_ids=[EVIDENCE_ID_A])

    result = validate_decision_analysis(payload)
    result["supporting_evidence_ids"].append(EVIDENCE_ID_B)

    assert payload["supporting_evidence_ids"] == [EVIDENCE_ID_A]


def test_returned_condition_lists_are_independent_copies():
    payload = _payload(evidence_gaps=["missing process ancestry"])

    result = validate_decision_analysis(payload)
    result["evidence_gaps"].append("another gap")

    assert payload["evidence_gaps"] == ["missing process ancestry"]


# ---------------------------------------------------------------------------
# 64-73: output shape and forbidden fields
# ---------------------------------------------------------------------------

def test_output_contains_exactly_allowed_normalized_fields():
    result = validate_decision_analysis(_payload())

    assert set(result.keys()) == {
        "investigation_id",
        "hypothesis_id",
        "current_assessment",
        "decision_status",
        "supporting_evidence_ids",
        "contradicting_evidence_ids",
        "unresolved_assumptions",
        "evidence_gaps",
        "strengthen_conditions",
        "weaken_conditions",
        "reversal_conditions",
        "recommended_next_evidence",
        "limitations",
        "generated_at",
    }


def test_output_contains_no_confidence():
    assert "confidence" not in validate_decision_analysis(_payload())


def test_output_contains_no_trust_level():
    assert "trust_level" not in validate_decision_analysis(_payload())


@pytest.mark.parametrize("field", ["severity", "risk", "likelihood"])
def test_output_contains_no_severity_risk_or_likelihood(field):
    assert field not in validate_decision_analysis(_payload())


def test_output_contains_no_supports_hypothesis():
    assert "supports_hypothesis" not in validate_decision_analysis(_payload())


def test_output_contains_no_attack_fields():
    result = validate_decision_analysis(_payload())

    assert not any("attack" in key.lower() or "technique" in key.lower() for key in result)


def test_output_contains_no_evidence_hash():
    result = validate_decision_analysis(_payload())

    assert "evidence_hash" not in result
    assert not any("hash" in key.lower() for key in result)


def test_output_contains_no_approval_fields():
    result = validate_decision_analysis(_payload())

    assert not any("approval" in key.lower() or "reviewer" in key.lower() for key in result)


def test_output_contains_no_audit_fields():
    result = validate_decision_analysis(_payload())

    assert not any("audit" in key.lower() for key in result)


def test_output_contains_no_execution_or_containment_fields():
    result = validate_decision_analysis(_payload())

    assert not any(
        "execution" in key.lower() or "containment" in key.lower() for key in result
    )


# ---------------------------------------------------------------------------
# 74-79: no external side effects (source inspection)
# ---------------------------------------------------------------------------

def _module_source_text():
    import core.decision_analysis as module

    with open(module.__file__, "r", encoding="utf-8") as handle:
        return handle.read()


def test_no_file_access_in_source():
    source = _module_source_text()

    assert "open(" not in source
    assert "pathlib" not in source
    assert "Path(" not in source


def test_no_supabase_reference_in_source():
    source = _module_source_text()

    assert "import supabase" not in source.lower()
    assert "from supabase" not in source.lower()


def test_no_subprocess_reference_in_source():
    source = _module_source_text()

    assert "import subprocess" not in source
    assert "subprocess.run(" not in source
    assert "subprocess.Popen(" not in source
    assert "subprocess.call(" not in source


def test_no_network_reference_in_source():
    source = _module_source_text()

    assert "socket" not in source
    assert "requests" not in source
    assert "urllib" not in source


def test_no_ai_or_model_reference_in_source():
    source = _module_source_text()

    assert "openai" not in source.lower()
    assert "anthropic" not in source.lower()
    assert "model.generate" not in source.lower()


def test_no_persistence_reference_in_source():
    source = _module_source_text()

    assert "insert" not in source.lower()
    assert "import supabase" not in source.lower()
    assert "from supabase" not in source.lower()
    assert "mcp__supabase" not in source.lower()
    assert ".table(" not in source


# ---------------------------------------------------------------------------
# 80: validator does not calculate or replace decision_status
# ---------------------------------------------------------------------------

def test_validator_does_not_calculate_or_replace_decision_status():
    result = validate_decision_analysis(
        _payload(decision_status="insufficient_evidence", supporting_evidence_ids=[EVIDENCE_ID_A, EVIDENCE_ID_B, EVIDENCE_ID_C])
    )

    # Even with three pieces of supporting evidence, the caller-supplied
    # status is preserved verbatim -- the validator never infers a
    # "stronger" status from the evidence count.
    assert result["decision_status"] == "insufficient_evidence"


# ---------------------------------------------------------------------------
# Runtime side-effect guards
# ---------------------------------------------------------------------------

def test_validator_never_touches_forbidden_entry_points(monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called during decision-analysis validation")

    # Import optional third-party modules before patching socket.socket:
    # some of them subclass socket.socket at import time.
    import urllib.request

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

    result = validate_decision_analysis(
        _payload(
            supporting_evidence_ids=[EVIDENCE_ID_A],
            contradicting_evidence_ids=[EVIDENCE_ID_B],
            evidence_gaps=["missing process ancestry"],
        )
    )

    assert result["decision_status"] == "supported"
