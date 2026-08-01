"""Tests for core.decision_context -- the pure validator that checks
already-loaded investigation/evidence mappings and builds a summarized
context bundle for a future "What Would Change My Decision?" preview.

No Supabase, file, subprocess, network, or AI/model access occurs anywhere
in this file; every input is a plain in-memory mapping.
"""

import copy
import socket
import subprocess
from pathlib import Path

import pytest

from core.decision_context import DecisionContextError, validate_decision_context

INVESTIGATION_ID = "11111111-1111-4111-8111-111111111111"
EVID_A = "22222222-2222-4222-8222-222222222222"
EVID_B = "33333333-3333-4333-8333-333333333333"
EVID_C = "44444444-4444-4444-8444-444444444444"
EVID_D = "55555555-5555-4555-8555-555555555555"
OTHER_INVESTIGATION_ID = "66666666-6666-4666-8666-666666666666"


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
        "contradicting_evidence_ids": [],
        "evidence_records": [_evidence_record(EVID_A)],
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# 1-4: baseline valid contexts
# ---------------------------------------------------------------------------

def test_01_valid_supporting_only_context():
    result = validate_decision_context(_payload())

    assert result["supporting_evidence"][0]["id"] == EVID_A
    assert result["contradicting_evidence"] == []


def test_02_valid_contradicting_only_context():
    payload = _payload(
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[EVID_A],
        evidence_records=[_evidence_record(EVID_A, supports_hypothesis=False)],
    )

    result = validate_decision_context(payload)

    assert result["contradicting_evidence"][0]["id"] == EVID_A
    assert result["supporting_evidence"] == []


def test_03_valid_mixed_context():
    payload = _payload(
        supporting_evidence_ids=[EVID_A],
        contradicting_evidence_ids=[EVID_B],
        evidence_records=[
            _evidence_record(EVID_A),
            _evidence_record(EVID_B, supports_hypothesis=False),
        ],
    )

    result = validate_decision_context(payload)

    assert [e["id"] for e in result["supporting_evidence"]] == [EVID_A]
    assert [e["id"] for e in result["contradicting_evidence"]] == [EVID_B]


def test_04_valid_empty_evidence_context():
    payload = _payload(
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[],
        evidence_records=[],
    )

    result = validate_decision_context(payload)

    assert result["supporting_evidence"] == []
    assert result["contradicting_evidence"] == []
    assert result["warnings"] == []


# ---------------------------------------------------------------------------
# 5-10: top-level / investigation_id structural checks
# ---------------------------------------------------------------------------

def test_05_input_is_not_a_mapping():
    with pytest.raises(DecisionContextError):
        validate_decision_context(["not", "a", "mapping"])


def test_06_unknown_top_level_field_rejected():
    payload = _payload()
    payload["totally_unknown_field"] = "x"

    with pytest.raises(DecisionContextError):
        validate_decision_context(payload)


def test_07_missing_investigation_id():
    payload = _payload()
    del payload["investigation_id"]

    with pytest.raises(DecisionContextError):
        validate_decision_context(payload)


def test_08_blank_investigation_id():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(investigation_id="   "))


def test_09_non_string_investigation_id():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(investigation_id=12345))


def test_10_malformed_investigation_uuid():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(investigation_id="not-a-uuid"))


# ---------------------------------------------------------------------------
# 11-16: investigation mapping
# ---------------------------------------------------------------------------

def test_11_investigation_mapping_missing():
    payload = _payload()
    del payload["investigation"]

    with pytest.raises(DecisionContextError):
        validate_decision_context(payload)


def test_12_investigation_is_not_a_mapping():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(investigation="not-a-mapping"))


def test_13_investigation_id_missing():
    investigation = _investigation()
    del investigation["id"]

    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(investigation=investigation))


def test_14_investigation_id_malformed():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(investigation=_investigation(id="not-a-uuid")))


def test_15_investigation_id_canonicalized():
    payload = _payload(
        investigation_id=INVESTIGATION_ID,
        investigation=_investigation(id=f"{{{INVESTIGATION_ID}}}"),
    )

    result = validate_decision_context(payload)

    assert result["investigation"]["id"] == INVESTIGATION_ID


def test_16_investigation_id_mismatch():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(investigation=_investigation(id=OTHER_INVESTIGATION_ID)))


# ---------------------------------------------------------------------------
# 17-21: investigation status
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "status", ["open", "investigating", "awaiting_evidence", "escalated", "closed"]
)
def test_17_each_valid_investigation_status(status):
    result = validate_decision_context(_payload(investigation=_investigation(status=status)))

    assert result["investigation"]["status"] == status


def test_18_status_canonicalized_to_lowercase():
    result = validate_decision_context(_payload(investigation=_investigation(status="OPEN")))

    assert result["investigation"]["status"] == "open"


def test_19_missing_investigation_status():
    investigation = _investigation()
    del investigation["status"]

    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(investigation=investigation))


def test_20_non_string_investigation_status():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(investigation=_investigation(status=123)))


def test_21_invalid_investigation_status():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(investigation=_investigation(status="bogus_status")))


# ---------------------------------------------------------------------------
# 22-25: investigation confidence
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("confidence", ["low", "medium", "high", "unknown"])
def test_22_each_valid_investigation_confidence(confidence):
    result = validate_decision_context(_payload(investigation=_investigation(confidence=confidence)))

    assert result["investigation"]["confidence"] == confidence


def test_23_investigation_confidence_canonicalized():
    result = validate_decision_context(_payload(investigation=_investigation(confidence="HIGH")))

    assert result["investigation"]["confidence"] == "high"


def test_24_missing_investigation_confidence():
    investigation = _investigation()
    del investigation["confidence"]

    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(investigation=investigation))


def test_25_invalid_investigation_confidence():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(investigation=_investigation(confidence="bogus")))


# ---------------------------------------------------------------------------
# 26-38: evidence selection lists
# ---------------------------------------------------------------------------

def test_26_supporting_ids_must_be_a_list():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(supporting_evidence_ids="not-a-list"))


def test_27_contradicting_ids_must_be_a_list():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(contradicting_evidence_ids="not-a-list"))


def test_28_supporting_entry_must_be_a_string():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(supporting_evidence_ids=[12345]))


def test_29_contradicting_entry_must_be_a_string():
    with pytest.raises(DecisionContextError):
        validate_decision_context(
            _payload(contradicting_evidence_ids=[12345], supporting_evidence_ids=[])
        )


def test_30_malformed_supporting_evidence_uuid():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(supporting_evidence_ids=["not-a-uuid"]))


def test_31_malformed_contradicting_evidence_uuid():
    with pytest.raises(DecisionContextError):
        validate_decision_context(
            _payload(contradicting_evidence_ids=["not-a-uuid"], supporting_evidence_ids=[])
        )


def test_32_evidence_ids_canonicalized():
    payload = _payload(
        supporting_evidence_ids=[f"{{{EVID_A}}}"],
        evidence_records=[_evidence_record(EVID_A)],
    )

    result = validate_decision_context(payload)

    assert result["supporting_evidence"][0]["id"] == EVID_A


def test_33_duplicate_supporting_id():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(supporting_evidence_ids=[EVID_A, EVID_A]))


def test_34_duplicate_contradicting_id():
    with pytest.raises(DecisionContextError):
        validate_decision_context(
            _payload(
                supporting_evidence_ids=[],
                contradicting_evidence_ids=[EVID_A, EVID_A],
                evidence_records=[_evidence_record(EVID_A, supports_hypothesis=False)],
            )
        )


def test_35_duplicate_detected_after_canonicalization():
    with pytest.raises(DecisionContextError):
        validate_decision_context(
            _payload(supporting_evidence_ids=[EVID_A, f"{{{EVID_A}}}"])
        )


def test_36_group_overlap():
    with pytest.raises(DecisionContextError):
        validate_decision_context(
            _payload(
                supporting_evidence_ids=[EVID_A],
                contradicting_evidence_ids=[EVID_A],
                evidence_records=[_evidence_record(EVID_A)],
            )
        )


def test_37_empty_supporting_selection_valid():
    payload = _payload(
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[EVID_A],
        evidence_records=[_evidence_record(EVID_A, supports_hypothesis=False)],
    )

    result = validate_decision_context(payload)

    assert result["supporting_evidence"] == []


def test_38_empty_contradicting_selection_valid():
    result = validate_decision_context(_payload(contradicting_evidence_ids=[]))

    assert result["contradicting_evidence"] == []


# ---------------------------------------------------------------------------
# 39-50: evidence_records shape, exactness, and ownership
# ---------------------------------------------------------------------------

def test_39_evidence_records_must_be_a_list():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(evidence_records="not-a-list"))


def test_40_evidence_record_must_be_a_mapping():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(evidence_records=["not-a-mapping"]))


def test_41_evidence_record_id_missing():
    record = _evidence_record(EVID_A)
    del record["id"]

    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(evidence_records=[record]))


def test_42_evidence_record_id_malformed():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(evidence_records=[_evidence_record("not-a-uuid")]))


def test_43_evidence_record_id_canonicalized():
    payload = _payload(evidence_records=[_evidence_record(f"{{{EVID_A}}}")])

    result = validate_decision_context(payload)

    assert result["supporting_evidence"][0]["id"] == EVID_A


def test_44_duplicate_evidence_records():
    with pytest.raises(DecisionContextError):
        validate_decision_context(
            _payload(evidence_records=[_evidence_record(EVID_A), _evidence_record(f"{{{EVID_A}}}")])
        )


def test_45_missing_requested_evidence_record():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(evidence_records=[]))


def test_46_unrequested_evidence_record_rejected():
    with pytest.raises(DecisionContextError):
        validate_decision_context(
            _payload(evidence_records=[_evidence_record(EVID_A), _evidence_record(EVID_B, supports_hypothesis=False)])
        )


def test_47_exact_record_set_equality_accepted():
    payload = _payload(
        supporting_evidence_ids=[EVID_A],
        contradicting_evidence_ids=[EVID_B],
        evidence_records=[_evidence_record(EVID_A), _evidence_record(EVID_B, supports_hypothesis=False)],
    )

    result = validate_decision_context(payload)

    assert len(result["supporting_evidence"]) == 1
    assert len(result["contradicting_evidence"]) == 1


def test_48_evidence_investigation_id_missing():
    record = _evidence_record(EVID_A)
    del record["investigation_id"]

    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(evidence_records=[record]))


def test_49_evidence_investigation_id_malformed():
    with pytest.raises(DecisionContextError):
        validate_decision_context(
            _payload(evidence_records=[_evidence_record(EVID_A, investigation_id="not-a-uuid")])
        )


def test_50_cross_investigation_evidence_rejected():
    with pytest.raises(DecisionContextError):
        validate_decision_context(
            _payload(evidence_records=[_evidence_record(EVID_A, investigation_id=OTHER_INVESTIGATION_ID)])
        )


# ---------------------------------------------------------------------------
# 51-59: controlled metadata validation
# ---------------------------------------------------------------------------

def test_51_evidence_trust_level_missing():
    record = _evidence_record(EVID_A)
    del record["trust_level"]

    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(evidence_records=[record]))


def test_52_evidence_trust_level_invalid():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(evidence_records=[_evidence_record(EVID_A, trust_level="bogus")]))


def test_53_evidence_trust_level_canonicalized():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, trust_level="HIGH")])
    )

    assert result["supporting_evidence"][0]["trust_level"] == "high"


def test_54_evidence_confidence_missing():
    record = _evidence_record(EVID_A)
    del record["confidence"]

    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(evidence_records=[record]))


def test_55_evidence_confidence_invalid():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(evidence_records=[_evidence_record(EVID_A, confidence="bogus")]))


def test_56_evidence_confidence_canonicalized():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, confidence="MEDIUM")])
    )

    assert result["supporting_evidence"][0]["confidence"] == "medium"


def test_57_evidence_assertion_type_missing():
    record = _evidence_record(EVID_A)
    del record["assertion_type"]

    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(evidence_records=[record]))


def test_58_evidence_assertion_type_invalid():
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(evidence_records=[_evidence_record(EVID_A, assertion_type="bogus")]))


def test_59_evidence_assertion_type_canonicalized():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, assertion_type="OBSERVATION")])
    )

    assert result["supporting_evidence"][0]["assertion_type"] == "observation"


# ---------------------------------------------------------------------------
# 60-65: supports_hypothesis type validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [True, False, None])
def test_60_62_supports_hypothesis_accepts_true_false_none(value):
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, supports_hypothesis=value)])
    )

    assert result["supporting_evidence"][0]["supports_hypothesis"] is value


@pytest.mark.parametrize("value", [0, 1])
def test_63_64_supports_hypothesis_integer_rejected(value):
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(evidence_records=[_evidence_record(EVID_A, supports_hypothesis=value)]))


@pytest.mark.parametrize("value", ["true", "yes", 3.5])
def test_65_other_invalid_supports_hypothesis_rejected(value):
    with pytest.raises(DecisionContextError):
        validate_decision_context(_payload(evidence_records=[_evidence_record(EVID_A, supports_hypothesis=value)]))


# ---------------------------------------------------------------------------
# 66-73: ordering and column exclusion
# ---------------------------------------------------------------------------

def test_66_supporting_output_follows_supporting_id_order():
    payload = _payload(
        supporting_evidence_ids=[EVID_B, EVID_A],
        evidence_records=[_evidence_record(EVID_A), _evidence_record(EVID_B)],
    )

    result = validate_decision_context(payload)

    assert [e["id"] for e in result["supporting_evidence"]] == [EVID_B, EVID_A]


def test_67_contradicting_output_follows_contradicting_id_order():
    payload = _payload(
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[EVID_B, EVID_A],
        evidence_records=[
            _evidence_record(EVID_A, supports_hypothesis=False),
            _evidence_record(EVID_B, supports_hypothesis=False),
        ],
    )

    result = validate_decision_context(payload)

    assert [e["id"] for e in result["contradicting_evidence"]] == [EVID_B, EVID_A]


def test_68_evidence_record_input_order_does_not_override_selected_order():
    payload = _payload(
        supporting_evidence_ids=[EVID_B, EVID_A],
        evidence_records=[_evidence_record(EVID_A), _evidence_record(EVID_B)],
    )

    result = validate_decision_context(payload)

    assert [e["id"] for e in result["supporting_evidence"]] == [EVID_B, EVID_A]


def test_69_extra_investigation_columns_ignored():
    investigation = _investigation()
    investigation["title"] = "Example Investigation"
    investigation["description"] = "Example description"
    investigation["created_at"] = "2026-01-01T00:00:00Z"

    result = validate_decision_context(_payload(investigation=investigation))

    assert set(result["investigation"].keys()) == {"id", "status", "confidence"}


def test_70_extra_evidence_columns_ignored():
    record = _evidence_record(EVID_A)
    record["source"] = "analyst notes"
    record["event_id"] = "4104"

    result = validate_decision_context(_payload(evidence_records=[record]))

    assert set(result["supporting_evidence"][0].keys()) == {
        "id", "trust_level", "confidence", "assertion_type", "supports_hypothesis",
    }


def test_71_details_excluded_from_output():
    record = _evidence_record(EVID_A)
    record["details"] = {"hayabusa_row": {"EventID": "4104"}}

    result = validate_decision_context(_payload(evidence_records=[record]))

    assert "details" not in result["supporting_evidence"][0]


def test_72_provenance_excluded_from_output():
    record = _evidence_record(EVID_A)
    record["provenance"] = {"collector": "test"}

    result = validate_decision_context(_payload(evidence_records=[record]))

    assert "provenance" not in result["supporting_evidence"][0]


def test_73_evidence_summary_contains_exactly_five_fields():
    result = validate_decision_context(_payload())

    assert set(result["supporting_evidence"][0].keys()) == {
        "id", "trust_level", "confidence", "assertion_type", "supports_hypothesis",
    }


# ---------------------------------------------------------------------------
# 74-91: warning triggers
# ---------------------------------------------------------------------------

def test_74_matching_supporting_metadata_produces_no_conflict_warning():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, supports_hypothesis=True)])
    )

    assert not any(w["code"] == "SUPPORTS_HYPOTHESIS_CONFLICT" for w in result["warnings"])


def test_75_matching_contradicting_metadata_produces_no_conflict_warning():
    payload = _payload(
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[EVID_A],
        evidence_records=[_evidence_record(EVID_A, supports_hypothesis=False)],
    )

    result = validate_decision_context(payload)

    assert not any(w["code"] == "SUPPORTS_HYPOTHESIS_CONFLICT" for w in result["warnings"])


def test_76_supporting_record_with_false_produces_conflict_warning():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, supports_hypothesis=False)])
    )

    assert {"evidence_id": EVID_A, "code": "SUPPORTS_HYPOTHESIS_CONFLICT"} in result["warnings"]


def test_77_contradicting_record_with_true_produces_conflict_warning():
    payload = _payload(
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[EVID_A],
        evidence_records=[_evidence_record(EVID_A, supports_hypothesis=True)],
    )

    result = validate_decision_context(payload)

    assert {"evidence_id": EVID_A, "code": "SUPPORTS_HYPOTHESIS_CONFLICT"} in result["warnings"]


def test_78_none_produces_unspecified_warning():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, supports_hypothesis=None)])
    )

    assert {"evidence_id": EVID_A, "code": "SUPPORTS_HYPOTHESIS_UNSPECIFIED"} in result["warnings"]


def test_79_none_does_not_produce_conflict_warning():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, supports_hypothesis=None)])
    )

    assert not any(w["code"] == "SUPPORTS_HYPOTHESIS_CONFLICT" for w in result["warnings"])


def test_80_unknown_trust_warning():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, trust_level="unknown")])
    )

    assert {"evidence_id": EVID_A, "code": "EVIDENCE_TRUST_UNKNOWN"} in result["warnings"]


def test_81_low_trust_warning():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, trust_level="low")])
    )

    assert {"evidence_id": EVID_A, "code": "EVIDENCE_TRUST_LOW"} in result["warnings"]


@pytest.mark.parametrize("trust_level", ["medium", "high"])
def test_82_83_medium_and_high_trust_produce_no_trust_warning(trust_level):
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, trust_level=trust_level)])
    )

    assert not any(w["code"].startswith("EVIDENCE_TRUST") for w in result["warnings"])


def test_84_unknown_confidence_warning():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, confidence="unknown")])
    )

    assert {"evidence_id": EVID_A, "code": "EVIDENCE_CONFIDENCE_UNKNOWN"} in result["warnings"]


@pytest.mark.parametrize("confidence", ["low", "medium", "high"])
def test_85_known_confidence_produces_no_confidence_warning(confidence):
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, confidence=confidence)])
    )

    assert not any(w["code"] == "EVIDENCE_CONFIDENCE_UNKNOWN" for w in result["warnings"])


def test_86_interpretation_warning():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, assertion_type="interpretation")])
    )

    assert {"evidence_id": EVID_A, "code": "EVIDENCE_IS_INTERPRETATION"} in result["warnings"]


def test_87_hypothesis_warning():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, assertion_type="hypothesis")])
    )

    assert {"evidence_id": EVID_A, "code": "EVIDENCE_IS_HYPOTHESIS"} in result["warnings"]


def test_88_recommendation_warning():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, assertion_type="recommendation")])
    )

    assert {"evidence_id": EVID_A, "code": "EVIDENCE_IS_RECOMMENDATION"} in result["warnings"]


def test_89_observation_produces_no_assertion_warning():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, assertion_type="observation")])
    )

    assertion_codes = {"EVIDENCE_IS_INTERPRETATION", "EVIDENCE_IS_HYPOTHESIS", "EVIDENCE_IS_RECOMMENDATION"}
    assert not any(w["code"] in assertion_codes for w in result["warnings"])


def test_90_derived_fact_produces_no_assertion_warning():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, assertion_type="derived_fact")])
    )

    assertion_codes = {"EVIDENCE_IS_INTERPRETATION", "EVIDENCE_IS_HYPOTHESIS", "EVIDENCE_IS_RECOMMENDATION"}
    assert not any(w["code"] in assertion_codes for w in result["warnings"])


def test_91_unknown_assertion_type_produces_no_assertion_warning():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, assertion_type="unknown")])
    )

    assertion_codes = {"EVIDENCE_IS_INTERPRETATION", "EVIDENCE_IS_HYPOTHESIS", "EVIDENCE_IS_RECOMMENDATION"}
    assert not any(w["code"] in assertion_codes for w in result["warnings"])


# ---------------------------------------------------------------------------
# 92-98: warning precedence, ordering, and shape
# ---------------------------------------------------------------------------

def test_92_multiple_warnings_for_one_evidence_record():
    result = validate_decision_context(
        _payload(
            evidence_records=[
                _evidence_record(EVID_A, trust_level="low", assertion_type="interpretation", supports_hypothesis=False)
            ]
        )
    )

    codes = [w["code"] for w in result["warnings"] if w["evidence_id"] == EVID_A]
    assert codes == ["EVIDENCE_TRUST_LOW", "EVIDENCE_IS_INTERPRETATION", "SUPPORTS_HYPOTHESIS_CONFLICT"]


def test_93_fixed_warning_precedence():
    result = validate_decision_context(
        _payload(
            evidence_records=[
                _evidence_record(
                    EVID_A,
                    trust_level="unknown",
                    confidence="unknown",
                    assertion_type="hypothesis",
                    supports_hypothesis=None,
                )
            ]
        )
    )

    codes = [w["code"] for w in result["warnings"]]
    assert codes == [
        "EVIDENCE_TRUST_UNKNOWN",
        "EVIDENCE_CONFIDENCE_UNKNOWN",
        "EVIDENCE_IS_HYPOTHESIS",
        "SUPPORTS_HYPOTHESIS_UNSPECIFIED",
    ]


def test_94_supporting_warnings_precede_contradicting_warnings():
    payload = _payload(
        supporting_evidence_ids=[EVID_A],
        contradicting_evidence_ids=[EVID_B],
        evidence_records=[
            _evidence_record(EVID_A, trust_level="low"),
            _evidence_record(EVID_B, trust_level="low", supports_hypothesis=False),
        ],
    )

    result = validate_decision_context(payload)

    evidence_ids_in_order = [w["evidence_id"] for w in result["warnings"]]
    assert evidence_ids_in_order.index(EVID_A) < evidence_ids_in_order.index(EVID_B)


def test_95_evidence_warning_order_follows_selected_id_order():
    payload = _payload(
        supporting_evidence_ids=[EVID_B, EVID_A],
        evidence_records=[
            _evidence_record(EVID_A, trust_level="low"),
            _evidence_record(EVID_B, trust_level="low"),
        ],
    )

    result = validate_decision_context(payload)

    evidence_ids_in_order = [w["evidence_id"] for w in result["warnings"]]
    assert evidence_ids_in_order == [EVID_B, EVID_A]


def test_96_warning_objects_contain_exactly_evidence_id_and_code():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, trust_level="low")])
    )

    for warning in result["warnings"]:
        assert set(warning.keys()) == {"evidence_id", "code"}


def test_97_no_duplicate_warning_objects():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, trust_level="low", assertion_type="interpretation")])
    )

    seen = [(w["evidence_id"], w["code"]) for w in result["warnings"]]
    assert len(seen) == len(set(seen))


def test_98_warning_output_deterministic():
    payload = _payload(evidence_records=[_evidence_record(EVID_A, trust_level="low")])

    first = validate_decision_context(payload)
    second = validate_decision_context(payload)

    assert first["warnings"] == second["warnings"]


# ---------------------------------------------------------------------------
# 99-105: non-mutation and independence
# ---------------------------------------------------------------------------

def test_99_original_payload_not_mutated():
    payload = _payload()
    snapshot = copy.deepcopy(payload)

    validate_decision_context(payload)

    assert payload == snapshot


def test_100_investigation_mapping_not_mutated():
    investigation = _investigation()
    payload = _payload(investigation=investigation)
    snapshot = copy.deepcopy(investigation)

    validate_decision_context(payload)

    assert investigation == snapshot


def test_101_evidence_mappings_not_mutated():
    record = _evidence_record(EVID_A)
    payload = _payload(evidence_records=[record])
    snapshot = copy.deepcopy(record)

    validate_decision_context(payload)

    assert record == snapshot


def test_102_supporting_and_contradicting_id_lists_not_mutated():
    supporting = [EVID_A]
    contradicting = []
    payload = _payload(supporting_evidence_ids=supporting, contradicting_evidence_ids=contradicting)

    validate_decision_context(payload)

    assert supporting == [EVID_A]
    assert contradicting == []


def test_103_returned_investigation_summary_is_independent():
    result = validate_decision_context(_payload())

    result["investigation"]["status"] = "closed"

    second_result = validate_decision_context(_payload())
    assert second_result["investigation"]["status"] == "open"


def test_104_returned_evidence_summaries_are_independent():
    payload = _payload()

    result = validate_decision_context(payload)
    result["supporting_evidence"][0]["trust_level"] = "low"

    second_result = validate_decision_context(payload)
    assert second_result["supporting_evidence"][0]["trust_level"] == "high"


def test_105_returned_warnings_are_independent():
    payload = _payload(evidence_records=[_evidence_record(EVID_A, trust_level="low")])

    result = validate_decision_context(payload)
    result["warnings"].append({"evidence_id": "injected", "code": "EVIDENCE_TRUST_LOW"})

    second_result = validate_decision_context(payload)
    assert len(second_result["warnings"]) == 1


# ---------------------------------------------------------------------------
# 106: output shape
# ---------------------------------------------------------------------------

def test_106_output_contains_exactly_defined_bundle_fields():
    result = validate_decision_context(_payload())

    assert set(result.keys()) == {
        "investigation", "supporting_evidence", "contradicting_evidence", "warnings",
    }


# ---------------------------------------------------------------------------
# 107-116: nothing generated beyond the bundle
# ---------------------------------------------------------------------------

def test_107_no_decision_status_generated():
    assert "decision_status" not in validate_decision_context(_payload())


def test_108_no_current_assessment_generated():
    assert "current_assessment" not in validate_decision_context(_payload())


def test_109_no_hypothesis_id_generated():
    assert "hypothesis_id" not in validate_decision_context(_payload())


def test_110_no_assumptions_generated():
    assert "unresolved_assumptions" not in validate_decision_context(_payload())


def test_111_no_evidence_gaps_generated():
    assert "evidence_gaps" not in validate_decision_context(_payload())


def test_112_no_strengthen_weaken_reversal_conditions_generated():
    result = validate_decision_context(_payload())

    for field in ("strengthen_conditions", "weaken_conditions", "reversal_conditions"):
        assert field not in result


def test_113_no_recommended_next_evidence_generated():
    assert "recommended_next_evidence" not in validate_decision_context(_payload())


def test_114_no_confidence_calculation():
    # Investigation confidence is passed through unchanged, never derived from evidence.
    result = validate_decision_context(_payload(investigation=_investigation(confidence="unknown")))

    assert result["investigation"]["confidence"] == "unknown"


def test_115_no_trust_modification():
    result = validate_decision_context(
        _payload(evidence_records=[_evidence_record(EVID_A, trust_level="low")])
    )

    assert result["supporting_evidence"][0]["trust_level"] == "low"


def test_116_no_full_evidence_content_copied():
    record = _evidence_record(EVID_A)
    record["details"] = {"hayabusa_row": {"EventID": "4104"}}
    record["provenance"] = {"collector": "test"}
    record["source"] = "analyst notes"

    result = validate_decision_context(_payload(evidence_records=[record]))

    summary = result["supporting_evidence"][0]
    assert "details" not in summary
    assert "provenance" not in summary
    assert "source" not in summary


# ---------------------------------------------------------------------------
# 117-126: no external side effects (source inspection)
# ---------------------------------------------------------------------------

def _module_source_text():
    import core.decision_context as module

    with open(module.__file__, "r", encoding="utf-8") as handle:
        return handle.read()


def test_117_no_supabase_access_in_source():
    source = _module_source_text()

    assert "import supabase" not in source.lower()
    assert "from supabase" not in source.lower()
    assert ".table(" not in source


def test_118_no_file_access_in_source():
    source = _module_source_text()

    assert "open(" not in source
    assert "pathlib" not in source
    assert "Path(" not in source


def test_119_no_subprocess_in_source():
    source = _module_source_text()

    assert "import subprocess" not in source
    assert "subprocess.run(" not in source
    assert "subprocess.Popen(" not in source


def test_120_no_network_access_in_source():
    source = _module_source_text()

    assert "socket" not in source
    assert "requests" not in source
    assert "urllib" not in source


def test_121_no_ai_or_model_call_in_source():
    source = _module_source_text()

    assert "openai" not in source.lower()
    assert "anthropic" not in source.lower()


def test_122_no_persistence_behavior_in_source():
    source = _module_source_text()

    assert "insert" not in source.lower()
    assert "update(" not in source.lower()


def test_123_no_attack_mapping_in_source():
    result = validate_decision_context(_payload())

    assert not any("attack" in key.lower() or "technique" in key.lower() for key in result)


def test_124_no_evidence_hashing_in_source():
    source = _module_source_text()

    assert "hashlib" not in source
    result = validate_decision_context(_payload())
    assert not any("hash" in key.lower() for key in result)


def test_125_no_approval_or_audit_behavior():
    result = validate_decision_context(_payload())

    assert not any("approval" in key.lower() or "audit" in key.lower() for key in result)


def test_126_no_containment_or_execution_behavior():
    result = validate_decision_context(_payload())

    assert not any("containment" in key.lower() or "execution" in key.lower() for key in result)


# ---------------------------------------------------------------------------
# Runtime side-effect guards
# ---------------------------------------------------------------------------

def test_validator_never_touches_forbidden_entry_points(monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called during decision-context validation")

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

    result = validate_decision_context(
        _payload(
            supporting_evidence_ids=[EVID_A],
            contradicting_evidence_ids=[EVID_B],
            evidence_records=[
                _evidence_record(EVID_A, trust_level="low"),
                _evidence_record(EVID_B, supports_hypothesis=False),
            ],
        )
    )

    assert len(result["supporting_evidence"]) == 1
    assert len(result["contradicting_evidence"]) == 1
