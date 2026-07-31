"""Tests for core.evidence_normalizer -- the shared, dependency-free evidence
normalization contract used ahead of insertion into the `evidence` table.

No Supabase, Hayabusa, subprocess, or network access occurs anywhere in this
file; every input is a plain in-memory dict or datetime.
"""

import copy
from datetime import datetime, timedelta, timezone

import pytest

from core.evidence_normalizer import EvidenceValidationError, normalize_evidence


def _minimal_payload(**overrides):
    payload = {
        "investigation_id": "inv-1",
        "evidence_type": "note",
        "source": "analyst",
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# 1-2: end-to-end valid payloads
# ---------------------------------------------------------------------------

def test_valid_analyst_observation():
    payload = {
        "investigation_id": "  inv-123  ",
        "evidence_type": "process_execution",
        "source": "SOC analyst manual review",
        "source_type": "Analyst",
        "assertion_type": "Observation",
        "trust_level": "High",
        "confidence": "Medium",
        "observed_at": "2024-01-01T12:00:00+00:00",
        "supports_hypothesis": True,
    }

    result = normalize_evidence(payload)

    assert result["investigation_id"] == "inv-123"
    assert result["evidence_type"] == "process_execution"
    assert result["source"] == "SOC analyst manual review"
    assert result["source_type"] == "analyst"
    assert result["assertion_type"] == "observation"
    assert result["trust_level"] == "high"
    assert result["confidence"] == "medium"
    assert result["observed_at"] == "2024-01-01T12:00:00Z"
    assert result["supports_hypothesis"] is True
    assert result["details"] == {}
    assert result["provenance"] == {}
    assert "id" not in result
    assert "created_at" not in result


def test_valid_hayabusa_evidence():
    payload = {
        "investigation_id": "inv-456",
        "evidence_type": "csv_timeline_event",
        "source": "hayabusa csv_timeline",
        "source_type": "hayabusa",
        "assertion_type": "observation",
        "event_id": 4688,
        "host_name": " WIN-HOST ",
        "process_name": "powershell.exe",
        "file_hash": "ABC123DEF456",
        "details": {"rule_title": "sample rule"},
    }

    result = normalize_evidence(payload)

    assert result["source_type"] == "hayabusa"
    assert result["event_id"] == "4688"
    assert result["host_name"] == "WIN-HOST"
    assert result["process_name"] == "powershell.exe"
    assert result["file_hash"] == "abc123def456"
    assert result["details"] == {"rule_title": "sample rule"}


# ---------------------------------------------------------------------------
# 3: input mapping is not mutated
# ---------------------------------------------------------------------------

def test_input_mapping_not_mutated():
    payload = _minimal_payload(details={"a": 1}, host_name="  HOST  ")
    snapshot = copy.deepcopy(payload)

    normalize_evidence(payload)

    assert payload == snapshot


# ---------------------------------------------------------------------------
# 4-6: required field handling
# ---------------------------------------------------------------------------

def test_required_strings_trimmed():
    payload = {
        "investigation_id": "  inv-1  ",
        "evidence_type": "  note  ",
        "source": "  analyst  ",
    }

    result = normalize_evidence(payload)

    assert result["investigation_id"] == "inv-1"
    assert result["evidence_type"] == "note"
    assert result["source"] == "analyst"


@pytest.mark.parametrize("missing_field", ["investigation_id", "evidence_type", "source"])
def test_missing_required_field_rejected(missing_field):
    payload = _minimal_payload()
    del payload[missing_field]

    with pytest.raises(EvidenceValidationError):
        normalize_evidence(payload)


@pytest.mark.parametrize("blank_field", ["investigation_id", "evidence_type", "source"])
def test_blank_required_field_rejected(blank_field):
    payload = _minimal_payload()
    payload[blank_field] = "   "

    with pytest.raises(EvidenceValidationError):
        normalize_evidence(payload)


# ---------------------------------------------------------------------------
# 7-12: controlled vocabulary handling
# ---------------------------------------------------------------------------

def test_controlled_values_normalized_to_lowercase():
    payload = _minimal_payload(
        source_type="HAYABUSA",
        assertion_type="Interpretation",
        trust_level="LOW",
        confidence="High",
    )

    result = normalize_evidence(payload)

    assert result["source_type"] == "hayabusa"
    assert result["assertion_type"] == "interpretation"
    assert result["trust_level"] == "low"
    assert result["confidence"] == "high"


def test_missing_controlled_values_default_to_unknown():
    result = normalize_evidence(_minimal_payload())

    assert result["source_type"] == "unknown"
    assert result["assertion_type"] == "unknown"
    assert result["trust_level"] == "unknown"
    assert result["confidence"] == "unknown"


@pytest.mark.parametrize("field", ["source_type", "assertion_type", "trust_level", "confidence"])
def test_invalid_controlled_value_rejected(field):
    payload = _minimal_payload(**{field: "not_a_real_value"})

    with pytest.raises(EvidenceValidationError):
        normalize_evidence(payload)


# ---------------------------------------------------------------------------
# 13: blank optional strings become None
# ---------------------------------------------------------------------------

def test_blank_optional_strings_become_none():
    payload = _minimal_payload(source_identifier="   ", host_name="")

    result = normalize_evidence(payload)

    assert result["source_identifier"] is None
    assert result["host_name"] is None


# ---------------------------------------------------------------------------
# 14-15: event_id / file_hash normalization
# ---------------------------------------------------------------------------

def test_numeric_event_id_becomes_string():
    payload = _minimal_payload(event_id=4624)

    result = normalize_evidence(payload)

    assert result["event_id"] == "4624"


def test_file_hash_becomes_lowercase():
    payload = _minimal_payload(file_hash="  DEADBEEF  ")

    result = normalize_evidence(payload)

    assert result["file_hash"] == "deadbeef"


# ---------------------------------------------------------------------------
# 16-20: details / provenance handling
# ---------------------------------------------------------------------------

def test_details_defaults_to_empty_dict():
    result = normalize_evidence(_minimal_payload())
    assert result["details"] == {}


def test_provenance_defaults_to_empty_dict():
    result = normalize_evidence(_minimal_payload())
    assert result["provenance"] == {}


def test_details_must_be_mapping():
    payload = _minimal_payload(details=["not", "a", "mapping"])

    with pytest.raises(EvidenceValidationError):
        normalize_evidence(payload)


def test_provenance_must_be_mapping():
    payload = _minimal_payload(provenance="not a mapping")

    with pytest.raises(EvidenceValidationError):
        normalize_evidence(payload)


def test_details_and_provenance_independently_copied():
    details = {"nested": {"a": 1}}
    provenance = {"tool": "test"}
    payload = _minimal_payload(details=details, provenance=provenance)

    result = normalize_evidence(payload)

    assert result["details"] == details
    assert result["details"] is not details
    result["details"]["nested"]["a"] = 999
    assert details["nested"]["a"] == 1

    assert result["provenance"] == provenance
    assert result["provenance"] is not provenance


# ---------------------------------------------------------------------------
# 21-22: supports_hypothesis
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [True, False, None])
def test_supports_hypothesis_accepts_true_false_none(value):
    payload = _minimal_payload(supports_hypothesis=value)

    result = normalize_evidence(payload)

    assert result["supports_hypothesis"] is value


@pytest.mark.parametrize("value", ["true", 1, 0, "yes"])
def test_non_boolean_supports_hypothesis_rejected(value):
    payload = _minimal_payload(supports_hypothesis=value)

    with pytest.raises(EvidenceValidationError):
        normalize_evidence(payload)


# ---------------------------------------------------------------------------
# 23-27: timestamp handling
# ---------------------------------------------------------------------------

def test_timezone_aware_datetime_normalized_to_utc_z():
    aware = datetime(2024, 1, 1, 7, 0, 0, tzinfo=timezone(timedelta(hours=-5)))
    payload = _minimal_payload(observed_at=aware)

    result = normalize_evidence(payload)

    assert result["observed_at"] == "2024-01-01T12:00:00Z"


def test_valid_iso8601_timestamp_normalized_to_utc_z():
    payload = _minimal_payload(observed_at="2024-01-01T07:00:00-05:00")

    result = normalize_evidence(payload)

    assert result["observed_at"] == "2024-01-01T12:00:00Z"


def test_timezone_naive_datetime_rejected():
    naive = datetime(2024, 1, 1, 12, 0, 0)
    payload = _minimal_payload(observed_at=naive)

    with pytest.raises(EvidenceValidationError):
        normalize_evidence(payload)


def test_invalid_timestamp_rejected():
    payload = _minimal_payload(observed_at="not-a-timestamp")

    with pytest.raises(EvidenceValidationError):
        normalize_evidence(payload)


def test_fixed_now_produces_deterministic_ingested_at():
    fixed_now = datetime(2024, 6, 15, 9, 30, 0, tzinfo=timezone.utc)

    result = normalize_evidence(_minimal_payload(), now=fixed_now)

    assert result["ingested_at"] == "2024-06-15T09:30:00Z"


# ---------------------------------------------------------------------------
# 28-30: rejected top-level fields
# ---------------------------------------------------------------------------

def test_unknown_top_level_field_rejected():
    payload = _minimal_payload(totally_unknown_field="x")

    with pytest.raises(EvidenceValidationError):
        normalize_evidence(payload)


def test_database_generated_id_rejected():
    payload = _minimal_payload(id="should-not-be-here")

    with pytest.raises(EvidenceValidationError):
        normalize_evidence(payload)


def test_database_generated_created_at_rejected():
    payload = _minimal_payload(created_at="2024-01-01T00:00:00Z")

    with pytest.raises(EvidenceValidationError):
        normalize_evidence(payload)


# ---------------------------------------------------------------------------
# bonus: documented "payload must be a mapping" behavior
# ---------------------------------------------------------------------------

def test_payload_must_be_mapping():
    with pytest.raises(EvidenceValidationError):
        normalize_evidence(["not", "a", "mapping"])
