"""Tests for core.source_trust_policy -- the deterministic, advisory
source-trust recommendation policy.

No Supabase, Hayabusa, subprocess, or network access occurs anywhere in
this file; every input is a plain in-memory dict.
"""

import copy

import pytest

from core.source_trust_policy import SourceTrustPolicyError, assess_source_trust


def _evidence(**overrides):
    payload = {
        "source_type": "hayabusa",
        "assertion_type": "observation",
        "source_identifier": "case-1234",
        "source_location": "evidence/evtx/sample.evtx",
        "observed_at": "2024-01-01T00:00:00Z",
        "provenance": {},
    }
    payload.update(overrides)
    return payload


def _full_provenance(**overrides):
    provenance = {
        "collector": "hayabusa_server",
        "collection_method": "run_evtx_analysis:csv_timeline",
        "source_reference": "evidence/evtx/sample.evtx",
        "captured_at": "2024-01-01T00:00:00Z",
        "integrity_verified": True,
        "corroborated_by": ["evidence-2"],
    }
    provenance.update(overrides)
    return provenance


# ---------------------------------------------------------------------------
# 1-4: Hayabusa / query_result trust ceilings
# ---------------------------------------------------------------------------

def test_verified_corroborated_hayabusa_derived_fact_recommends_high():
    evidence = _evidence(assertion_type="derived_fact", provenance=_full_provenance())

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] == "high"


def test_hayabusa_without_integrity_or_corroboration_does_not_recommend_high():
    provenance = _full_provenance(integrity_verified=None, corroborated_by=None)
    del provenance["integrity_verified"]
    del provenance["corroborated_by"]
    evidence = _evidence(provenance=provenance)

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] != "high"


def test_internal_query_result_does_not_become_high_merely_because_internal():
    provenance = _full_provenance()
    del provenance["integrity_verified"]
    del provenance["corroborated_by"]
    evidence = _evidence(source_type="query_result", provenance=provenance)

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] != "high"


def test_corroborated_query_result_with_verified_integrity_can_recommend_high():
    evidence = _evidence(source_type="query_result", provenance=_full_provenance())

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] == "high"


# ---------------------------------------------------------------------------
# 5-7: threat_intelligence ceiling
# ---------------------------------------------------------------------------

def test_uncorroborated_external_threat_intelligence_capped_at_low():
    provenance = _full_provenance()
    del provenance["corroborated_by"]
    evidence = _evidence(source_type="threat_intelligence", provenance=provenance)

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] == "low"


def test_corroborated_external_threat_intelligence_can_recommend_medium():
    evidence = _evidence(source_type="threat_intelligence", provenance=_full_provenance())

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] == "medium"


def test_external_threat_intelligence_can_never_recommend_high():
    evidence = _evidence(source_type="threat_intelligence", provenance=_full_provenance())

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] != "high"


# ---------------------------------------------------------------------------
# 8-9: analyst source is not special-cased
# ---------------------------------------------------------------------------

def test_analyst_observation_receives_no_automatic_trust_increase():
    evidence = _evidence(source_type="analyst", source_identifier=None, provenance={})

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] == "unknown"


def test_verified_corroborated_analyst_observation_can_recommend_high():
    evidence = _evidence(source_type="analyst", provenance=_full_provenance())

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] == "high"


# ---------------------------------------------------------------------------
# 10-12: interpretive assertions are capped
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("assertion_type", ["interpretation", "hypothesis", "recommendation"])
def test_interpretive_assertion_capped_at_low(assertion_type):
    evidence = _evidence(
        source_type="threat_hunter",
        assertion_type=assertion_type,
        provenance=_full_provenance(),
    )

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] == "low"


# ---------------------------------------------------------------------------
# 13-14: unknown source
# ---------------------------------------------------------------------------

def test_unknown_source_recommends_unknown():
    evidence = _evidence(source_type="unknown", provenance=_full_provenance())

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] == "unknown"


def test_unknown_source_claiming_high_produces_elevated_trust_reason_code():
    evidence = _evidence(source_type="unknown", trust_level="high", provenance=_full_provenance())

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] == "unknown"
    assert "UNKNOWN_SOURCE_CLAIMS_ELEVATED_TRUST" in result["reason_codes"]
    assert result["conflicts_with_supplied_trust_level"] is True


# ---------------------------------------------------------------------------
# 15-16: missing identity / collection method force unknown
# ---------------------------------------------------------------------------

def test_missing_identity_recommends_unknown():
    provenance = _full_provenance()
    del provenance["collector"]
    evidence = _evidence(source_identifier=None, provenance=provenance)

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] == "unknown"
    assert "MISSING_SOURCE_IDENTITY" in result["reason_codes"]


def test_missing_collection_method_recommends_unknown():
    provenance = _full_provenance()
    del provenance["collection_method"]
    evidence = _evidence(provenance=provenance)

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] == "unknown"
    assert "MISSING_COLLECTION_METHOD" in result["reason_codes"]


# ---------------------------------------------------------------------------
# 17-18: missing reference / timestamp prevent medium
# ---------------------------------------------------------------------------

def test_missing_reference_prevents_medium():
    provenance = _full_provenance()
    del provenance["source_reference"]
    evidence = _evidence(source_location=None, provenance=provenance)

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] == "low"
    assert "MISSING_SOURCE_REFERENCE" in result["reason_codes"]


def test_missing_timestamp_prevents_medium():
    provenance = _full_provenance()
    del provenance["captured_at"]
    evidence = _evidence(observed_at=None, provenance=provenance)

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] == "low"
    assert "MISSING_TIMESTAMP" in result["reason_codes"]


# ---------------------------------------------------------------------------
# 19-20: integrity failure vs. integrity absence
# ---------------------------------------------------------------------------

def test_explicit_integrity_failure_caps_trust_at_low():
    evidence = _evidence(provenance=_full_provenance(integrity_verified=False))

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] == "low"
    assert "INTEGRITY_CHECK_FAILED" in result["reason_codes"]


def test_missing_integrity_differs_from_explicit_integrity_failure():
    provenance_missing = _full_provenance()
    del provenance_missing["integrity_verified"]
    evidence_missing = _evidence(provenance=provenance_missing)

    evidence_failed = _evidence(provenance=_full_provenance(integrity_verified=False))

    result_missing = assess_source_trust(evidence_missing)
    result_failed = assess_source_trust(evidence_failed)

    assert result_missing["recommended_trust_level"] == "medium"
    assert "INTEGRITY_NOT_RECORDED" in result_missing["reason_codes"]

    assert result_failed["recommended_trust_level"] == "low"
    assert "INTEGRITY_CHECK_FAILED" in result_failed["reason_codes"]


# ---------------------------------------------------------------------------
# 21: corroboration reason code
# ---------------------------------------------------------------------------

def test_corroboration_produces_corroboration_present():
    evidence = _evidence(provenance=_full_provenance())

    result = assess_source_trust(evidence)

    assert "CORROBORATION_PRESENT" in result["reason_codes"]


# ---------------------------------------------------------------------------
# 22-24: supplied trust_level conflict behavior
# ---------------------------------------------------------------------------

def test_matching_supplied_trust_produces_no_conflict():
    evidence = _evidence(assertion_type="derived_fact", trust_level="high", provenance=_full_provenance())

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] == "high"
    assert result["conflicts_with_supplied_trust_level"] is False
    assert "SUPPLIED_TRUST_MATCHES_RECOMMENDATION" in result["reason_codes"]


def test_conflicting_supplied_trust_produces_a_conflict():
    provenance = _full_provenance()
    del provenance["integrity_verified"]
    del provenance["corroborated_by"]
    evidence = _evidence(trust_level="high", provenance=provenance)

    result = assess_source_trust(evidence)

    assert result["recommended_trust_level"] != "high"
    assert result["conflicts_with_supplied_trust_level"] is True
    assert "SUPPLIED_TRUST_DIFFERS_FROM_RECOMMENDATION" in result["reason_codes"]


@pytest.mark.parametrize("supplied", [None, "", "   ", "unknown"])
def test_missing_or_unknown_supplied_trust_produces_null_conflict(supplied):
    evidence = _evidence(provenance=_full_provenance())
    if supplied is None:
        evidence.pop("trust_level", None)
    else:
        evidence["trust_level"] = supplied

    result = assess_source_trust(evidence)

    assert result["conflicts_with_supplied_trust_level"] is None
    assert "SUPPLIED_TRUST_MATCHES_RECOMMENDATION" not in result["reason_codes"]
    assert "SUPPLIED_TRUST_DIFFERS_FROM_RECOMMENDATION" not in result["reason_codes"]


# ---------------------------------------------------------------------------
# 25-33: structural validation
# ---------------------------------------------------------------------------

def test_invalid_source_type_rejected():
    evidence = _evidence(source_type="not_a_real_type")

    with pytest.raises(SourceTrustPolicyError):
        assess_source_trust(evidence)


def test_invalid_assertion_type_rejected():
    evidence = _evidence(assertion_type="not_a_real_type")

    with pytest.raises(SourceTrustPolicyError):
        assess_source_trust(evidence)


def test_invalid_supplied_trust_level_rejected():
    evidence = _evidence(trust_level="definitely_not_valid")

    with pytest.raises(SourceTrustPolicyError):
        assess_source_trust(evidence)


def test_non_mapping_evidence_rejected():
    with pytest.raises(SourceTrustPolicyError):
        assess_source_trust(["not", "a", "mapping"])


def test_non_mapping_provenance_rejected():
    evidence = _evidence(provenance="not a mapping")

    with pytest.raises(SourceTrustPolicyError):
        assess_source_trust(evidence)


@pytest.mark.parametrize(
    "field,value",
    [
        ("collector", 123),
        ("collection_method", 123),
        ("source_reference", 123),
        ("captured_at", 123),
        ("integrity_verified", "yes"),
    ],
)
def test_invalid_provenance_field_types_rejected(field, value):
    evidence = _evidence(provenance={field: value})

    with pytest.raises(SourceTrustPolicyError):
        assess_source_trust(evidence)


@pytest.mark.parametrize("field", ["collector", "collection_method", "source_reference", "captured_at"])
def test_empty_provenance_strings_rejected_when_supplied(field):
    evidence = _evidence(provenance={field: "   "})

    with pytest.raises(SourceTrustPolicyError):
        assess_source_trust(evidence)


@pytest.mark.parametrize("value", ["not-a-list", [123], [""], ["  "]])
def test_invalid_corroborated_by_entries_rejected(value):
    evidence = _evidence(provenance={"corroborated_by": value})

    with pytest.raises(SourceTrustPolicyError):
        assess_source_trust(evidence)


@pytest.mark.parametrize("value", ["not-a-list", [123], [""], ["  "]])
def test_invalid_transformation_steps_entries_rejected(value):
    evidence = _evidence(provenance={"transformation_steps": value})

    with pytest.raises(SourceTrustPolicyError):
        assess_source_trust(evidence)


# ---------------------------------------------------------------------------
# 34-36: purity and determinism
# ---------------------------------------------------------------------------

def test_input_and_nested_provenance_not_mutated():
    evidence = _evidence(provenance=_full_provenance())
    snapshot = copy.deepcopy(evidence)

    assess_source_trust(evidence)

    assert evidence == snapshot


def test_reason_code_ordering_is_deterministic():
    evidence = _evidence(source_type="threat_intelligence", trust_level="high", provenance={})

    first = assess_source_trust(evidence)
    second = assess_source_trust(evidence)

    assert first["reason_codes"] == second["reason_codes"]

    canonical_order = [
        "SOURCE_TYPE_UNKNOWN",
        "MISSING_SOURCE_IDENTITY",
        "MISSING_SOURCE_REFERENCE",
        "MISSING_COLLECTION_METHOD",
        "MISSING_TIMESTAMP",
        "INTEGRITY_NOT_RECORDED",
        "INTEGRITY_VERIFIED",
        "INTEGRITY_CHECK_FAILED",
        "INTERPRETIVE_ASSERTION",
        "EXTERNAL_SOURCE_UNCORROBORATED",
        "EXTERNAL_SOURCE_MAX_MEDIUM",
        "CORROBORATION_PRESENT",
        "SUPPLIED_TRUST_MATCHES_RECOMMENDATION",
        "SUPPLIED_TRUST_DIFFERS_FROM_RECOMMENDATION",
        "UNKNOWN_SOURCE_CLAIMS_ELEVATED_TRUST",
    ]
    expected = [code for code in canonical_order if code in first["reason_codes"]]
    assert first["reason_codes"] == expected


def test_reason_codes_contain_no_duplicates():
    evidence = _evidence(source_type="threat_intelligence", trust_level="high", provenance={})

    result = assess_source_trust(evidence)

    assert len(result["reason_codes"]) == len(set(result["reason_codes"]))
