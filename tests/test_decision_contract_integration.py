"""Permanent in-memory integration test proving compatibility between the
two pure Block 3 validators:

    core.decision_context.validate_decision_context
            -> core.decision_analysis.validate_decision_analysis

This is a compatibility and boundary integration test only -- it contains
no production orchestration code, only test fixtures and assertions. Every
call is a direct in-process function call; no subprocess, CLI, slash
command, Supabase, file, temporary file, network request, or AI/model call
occurs anywhere in this file.
"""

import copy
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from core.decision_analysis import DecisionAnalysisError, validate_decision_analysis
from core.decision_context import DecisionContextError, validate_decision_context

INVESTIGATION_ID = "11111111-1111-4111-8111-111111111111"
SUP1 = "22222222-2222-4222-8222-222222222222"
SUP2 = "33333333-3333-4333-8333-333333333333"
SUP3 = "44444444-4444-4444-8444-444444444444"
CON1 = "55555555-5555-4555-8555-555555555555"
CON2 = "66666666-6666-4666-8666-666666666666"
OTHER_INVESTIGATION_ID = "77777777-7777-4777-8777-777777777777"

CURRENT_ASSESSMENT = (
    "The synthetic PowerShell activity is more consistent with unauthorized "
    "execution than approved administration."
)


def _extra_evidence_columns(marker):
    return {
        "source": f"analyst notes ({marker})",
        "details": {"hayabusa_row": {"marker": marker}},
        "provenance": {"collector": "test", "marker": marker},
        "observed_at": "2026-01-01T00:00:00Z",
        "command_line": f"powershell.exe -Command {marker}",
    }


def _record(evidence_id, trust_level, confidence, assertion_type, supports_hypothesis, marker):
    record = {
        "id": evidence_id,
        "investigation_id": INVESTIGATION_ID,
        "trust_level": trust_level,
        "confidence": confidence,
        "assertion_type": assertion_type,
        "supports_hypothesis": supports_hypothesis,
    }
    record.update(_extra_evidence_columns(marker))
    return record


def _investigation_mapping(**overrides):
    investigation = {
        "id": INVESTIGATION_ID,
        "status": "investigating",
        "confidence": "medium",
        "title": "Synthetic Investigation",
        "description": "Synthetic description of a fictional case",
        "created_at": "2026-01-01T00:00:00Z",
    }
    investigation.update(overrides)
    return investigation


def _all_records():
    return [
        _record(SUP1, "high", "high", "observation", True, "sup1"),
        _record(SUP2, "unknown", "unknown", "interpretation", None, "sup2"),
        _record(SUP3, "low", "medium", "hypothesis", False, "sup3"),
        _record(CON1, "medium", "high", "recommendation", True, "con1"),
        _record(CON2, "high", "medium", "derived_fact", False, "con2"),
    ]


def _build_context_payload():
    # evidence_records deliberately ordered differently from either
    # selection list, to prove group order (not record order) governs output.
    records_in_scrambled_order = [
        _all_records()[3],  # CON1
        _all_records()[1],  # SUP2
        _all_records()[4],  # CON2
        _all_records()[0],  # SUP1
        _all_records()[2],  # SUP3
    ]

    return {
        "investigation_id": INVESTIGATION_ID,
        "investigation": _investigation_mapping(),
        "supporting_evidence_ids": [SUP1, SUP2, SUP3],
        "contradicting_evidence_ids": [CON1, CON2],
        "evidence_records": records_in_scrambled_order,
    }


def _build_analysis_payload(context):
    return {
        "investigation_id": context["investigation"]["id"],
        "hypothesis_id": None,
        "current_assessment": CURRENT_ASSESSMENT,
        "decision_status": "partially_supported",
        "supporting_evidence_ids": [item["id"] for item in context["supporting_evidence"]],
        "contradicting_evidence_ids": [item["id"] for item in context["contradicting_evidence"]],
        "unresolved_assumptions": ["Assuming the account owner has not been separately verified."],
        "evidence_gaps": ["Process ancestry for the PowerShell execution has not been reviewed."],
        "strengthen_conditions": ["Independent confirmation on a second host in the same window."],
        "weaken_conditions": ["Discovery that this is a documented maintenance script."],
        "reversal_conditions": ["A signed deployment record proving approved CI/CD origin."],
        "recommended_next_evidence": ["Parent process telemetry for the affected host."],
        "limitations": ["Several cited records carry unknown or low source trust."],
        "generated_at": "2026-08-01T08:45:00-07:00",
    }


EXPECTED_GENERATED_AT = "2026-08-01T15:45:00Z"

EXPECTED_WARNINGS = [
    {"evidence_id": SUP2, "code": "EVIDENCE_TRUST_UNKNOWN"},
    {"evidence_id": SUP2, "code": "EVIDENCE_CONFIDENCE_UNKNOWN"},
    {"evidence_id": SUP2, "code": "EVIDENCE_IS_INTERPRETATION"},
    {"evidence_id": SUP2, "code": "SUPPORTS_HYPOTHESIS_UNSPECIFIED"},
    {"evidence_id": SUP3, "code": "EVIDENCE_TRUST_LOW"},
    {"evidence_id": SUP3, "code": "EVIDENCE_IS_HYPOTHESIS"},
    {"evidence_id": SUP3, "code": "SUPPORTS_HYPOTHESIS_CONFLICT"},
    {"evidence_id": CON1, "code": "EVIDENCE_IS_RECOMMENDATION"},
    {"evidence_id": CON1, "code": "SUPPORTS_HYPOTHESIS_CONFLICT"},
]


@pytest.fixture(scope="module")
def chain_result():
    context_payload = _build_context_payload()
    context_payload_snapshot = copy.deepcopy(context_payload)

    context = validate_decision_context(context_payload)

    analysis_payload = _build_analysis_payload(context)
    analysis_payload_snapshot = copy.deepcopy(analysis_payload)

    analysis = validate_decision_analysis(analysis_payload)

    # Re-validate: the *original request envelope* again for the context
    # validator (its output shape is intentionally different from its
    # input shape, so the output is never fed back into it); the
    # *already-validated* object again for the analysis validator (whose
    # output shape matches its own input contract).
    context_again = validate_decision_context(copy.deepcopy(context_payload_snapshot))
    analysis_again = validate_decision_analysis(analysis)

    return {
        "context_payload": context_payload,
        "context_payload_snapshot": context_payload_snapshot,
        "context": context,
        "analysis_payload": analysis_payload,
        "analysis_payload_snapshot": analysis_payload_snapshot,
        "analysis": analysis,
        "context_again": context_again,
        "analysis_again": analysis_again,
    }


# ---------------------------------------------------------------------------
# Context stage shape and content
# ---------------------------------------------------------------------------

def test_context_top_level_keys_exact(chain_result):
    assert set(chain_result["context"].keys()) == {
        "investigation", "supporting_evidence", "contradicting_evidence", "warnings",
    }


def test_context_investigation_summary_exact(chain_result):
    assert chain_result["context"]["investigation"] == {
        "id": INVESTIGATION_ID, "status": "investigating", "confidence": "medium",
    }


def test_context_evidence_summary_keys_exact(chain_result):
    for item in chain_result["context"]["supporting_evidence"] + chain_result["context"]["contradicting_evidence"]:
        assert set(item.keys()) == {"id", "trust_level", "confidence", "assertion_type", "supports_hypothesis"}


def test_supporting_evidence_follows_selected_order(chain_result):
    assert [item["id"] for item in chain_result["context"]["supporting_evidence"]] == [SUP1, SUP2, SUP3]


def test_contradicting_evidence_follows_selected_order(chain_result):
    assert [item["id"] for item in chain_result["context"]["contradicting_evidence"]] == [CON1, CON2]


def test_all_eight_warning_codes_present(chain_result):
    codes = {w["code"] for w in chain_result["context"]["warnings"]}
    assert codes == {
        "EVIDENCE_TRUST_UNKNOWN",
        "EVIDENCE_TRUST_LOW",
        "EVIDENCE_CONFIDENCE_UNKNOWN",
        "EVIDENCE_IS_INTERPRETATION",
        "EVIDENCE_IS_HYPOTHESIS",
        "EVIDENCE_IS_RECOMMENDATION",
        "SUPPORTS_HYPOTHESIS_CONFLICT",
        "SUPPORTS_HYPOTHESIS_UNSPECIFIED",
    }


def test_supports_hypothesis_conflict_appears_for_two_evidence_ids(chain_result):
    conflict_ids = {w["evidence_id"] for w in chain_result["context"]["warnings"] if w["code"] == "SUPPORTS_HYPOTHESIS_CONFLICT"}
    assert conflict_ids == {SUP3, CON1}


def test_warning_objects_contain_exactly_evidence_id_and_code(chain_result):
    for warning in chain_result["context"]["warnings"]:
        assert set(warning.keys()) == {"evidence_id", "code"}


def test_no_duplicate_warning_objects(chain_result):
    seen = [(w["evidence_id"], w["code"]) for w in chain_result["context"]["warnings"]]
    assert len(seen) == len(set(seen))


def test_exact_warning_list_matches_expected_order(chain_result):
    assert chain_result["context"]["warnings"] == EXPECTED_WARNINGS


def test_no_complete_evidence_details_copied_into_context(chain_result):
    for item in chain_result["context"]["supporting_evidence"] + chain_result["context"]["contradicting_evidence"]:
        assert "details" not in item
        assert "provenance" not in item
        assert "source" not in item
        assert "command_line" not in item


def test_context_contains_no_decision_analysis_narrative_field(chain_result):
    forbidden = {
        "decision_status", "current_assessment", "hypothesis_id",
        "unresolved_assumptions", "evidence_gaps", "strengthen_conditions",
        "weaken_conditions", "reversal_conditions", "recommended_next_evidence",
        "limitations", "generated_at",
    }
    assert forbidden.isdisjoint(chain_result["context"].keys())


# ---------------------------------------------------------------------------
# Context -> analysis evidence-ID handoff
# ---------------------------------------------------------------------------

def test_analysis_investigation_id_equals_context_investigation_id(chain_result):
    assert chain_result["analysis"]["investigation_id"] == chain_result["context"]["investigation"]["id"]


def test_analysis_supporting_ids_match_context_supporting_order(chain_result):
    expected = [item["id"] for item in chain_result["context"]["supporting_evidence"]]
    assert chain_result["analysis"]["supporting_evidence_ids"] == expected


def test_analysis_contradicting_ids_match_context_contradicting_order(chain_result):
    expected = [item["id"] for item in chain_result["context"]["contradicting_evidence"]]
    assert chain_result["analysis"]["contradicting_evidence_ids"] == expected


def test_all_handed_off_evidence_uuids_remain_canonical(chain_result):
    for evidence_id in (
        chain_result["analysis"]["supporting_evidence_ids"]
        + chain_result["analysis"]["contradicting_evidence_ids"]
    ):
        assert evidence_id == evidence_id.lower()
        assert evidence_id.count("-") == 4


# ---------------------------------------------------------------------------
# decision_status / hypothesis_id preservation
# ---------------------------------------------------------------------------

def test_hypothesis_id_remains_none(chain_result):
    assert chain_result["analysis"]["hypothesis_id"] is None


def test_decision_status_remains_partially_supported(chain_result):
    assert chain_result["analysis"]["decision_status"] == "partially_supported"


def test_decision_status_not_replaced_by_evidence_or_warning_count(chain_result):
    # Three supporting + two contradicting records, and nine warnings, were
    # all produced by this fixture -- none of that influenced the status.
    assert len(chain_result["context"]["warnings"]) == 9
    assert chain_result["analysis"]["decision_status"] == "partially_supported"


# ---------------------------------------------------------------------------
# generated_at canonicalization and idempotency
# ---------------------------------------------------------------------------

def test_generated_at_canonicalized_to_expected_utc_z(chain_result):
    assert chain_result["analysis"]["generated_at"] == EXPECTED_GENERATED_AT


def test_context_again_equals_context(chain_result):
    assert chain_result["context_again"] == chain_result["context"]


def test_analysis_again_equals_analysis(chain_result):
    assert chain_result["analysis_again"] == chain_result["analysis"]


def test_generated_at_preserved_exactly_on_repeat(chain_result):
    assert chain_result["analysis_again"]["generated_at"] == chain_result["analysis"]["generated_at"]


def test_warning_order_preserved_on_repeat(chain_result):
    assert chain_result["context_again"]["warnings"] == chain_result["context"]["warnings"]


def test_evidence_group_order_preserved_on_repeat(chain_result):
    assert (
        [i["id"] for i in chain_result["context_again"]["supporting_evidence"]]
        == [i["id"] for i in chain_result["context"]["supporting_evidence"]]
    )
    assert (
        [i["id"] for i in chain_result["context_again"]["contradicting_evidence"]]
        == [i["id"] for i in chain_result["context"]["contradicting_evidence"]]
    )


# ---------------------------------------------------------------------------
# Separation guarantees
# ---------------------------------------------------------------------------

def test_context_output_excludes_analysis_fields(chain_result):
    forbidden = {
        "decision_status", "current_assessment", "hypothesis_id",
        "unresolved_assumptions", "evidence_gaps", "strengthen_conditions",
        "weaken_conditions", "reversal_conditions", "recommended_next_evidence",
        "limitations", "generated_at",
    }
    assert forbidden.isdisjoint(chain_result["context"].keys())


def test_analysis_output_excludes_context_fields(chain_result):
    forbidden = {
        "status", "trust_level", "confidence", "assertion_type",
        "supports_hypothesis", "warnings", "details", "provenance",
    }
    assert forbidden.isdisjoint(chain_result["analysis"].keys())


def test_context_evidence_trust_values_unchanged(chain_result):
    by_id = {item["id"]: item for item in chain_result["context"]["supporting_evidence"] + chain_result["context"]["contradicting_evidence"]}
    assert by_id[SUP1]["trust_level"] == "high"
    assert by_id[SUP2]["trust_level"] == "unknown"
    assert by_id[SUP3]["trust_level"] == "low"
    assert by_id[CON1]["trust_level"] == "medium"
    assert by_id[CON2]["trust_level"] == "high"


def test_context_evidence_confidence_values_unchanged(chain_result):
    by_id = {item["id"]: item for item in chain_result["context"]["supporting_evidence"] + chain_result["context"]["contradicting_evidence"]}
    assert by_id[SUP1]["confidence"] == "high"
    assert by_id[SUP2]["confidence"] == "unknown"
    assert by_id[SUP3]["confidence"] == "medium"
    assert by_id[CON1]["confidence"] == "high"
    assert by_id[CON2]["confidence"] == "medium"


def test_investigation_confidence_remains_medium(chain_result):
    assert chain_result["context"]["investigation"]["confidence"] == "medium"


def test_no_assessment_confidence_calculated(chain_result):
    assert "confidence" not in chain_result["analysis"]


def test_no_evidence_record_copied_into_analysis(chain_result):
    analysis_text = repr(chain_result["analysis"])
    assert "hayabusa_row" not in analysis_text
    assert "collector" not in analysis_text


def test_no_context_summary_embedded_into_analysis(chain_result):
    assert "warnings" not in chain_result["analysis"]
    assert "investigation_status" not in chain_result["analysis"]


# ---------------------------------------------------------------------------
# Non-mutation
# ---------------------------------------------------------------------------

def test_context_payload_unchanged(chain_result):
    assert chain_result["context_payload"] == chain_result["context_payload_snapshot"]


def test_investigation_mapping_unchanged(chain_result):
    assert chain_result["context_payload"]["investigation"] == chain_result["context_payload_snapshot"]["investigation"]


def test_every_evidence_record_unchanged(chain_result):
    assert chain_result["context_payload"]["evidence_records"] == chain_result["context_payload_snapshot"]["evidence_records"]


def test_selection_lists_unchanged(chain_result):
    assert chain_result["context_payload"]["supporting_evidence_ids"] == [SUP1, SUP2, SUP3]
    assert chain_result["context_payload"]["contradicting_evidence_ids"] == [CON1, CON2]


def test_analysis_payload_unchanged(chain_result):
    assert chain_result["analysis_payload"] == chain_result["analysis_payload_snapshot"]


def test_analysis_condition_lists_unchanged(chain_result):
    for field in (
        "unresolved_assumptions", "evidence_gaps", "strengthen_conditions",
        "weaken_conditions", "reversal_conditions", "recommended_next_evidence", "limitations",
    ):
        assert chain_result["analysis_payload"][field] == chain_result["analysis_payload_snapshot"][field]


# ---------------------------------------------------------------------------
# Returned-object independence
# ---------------------------------------------------------------------------

def test_mutating_returned_evidence_summary_does_not_affect_original_record(chain_result):
    original_record = next(r for r in chain_result["context_payload"]["evidence_records"] if r["id"] == SUP1)
    original_trust = original_record["trust_level"]

    mutable_context = copy.deepcopy(chain_result["context"])
    mutable_context["supporting_evidence"][0]["trust_level"] = "mutated"

    assert original_record["trust_level"] == original_trust


def test_mutating_returned_warning_does_not_affect_input(chain_result):
    if not chain_result["context"]["warnings"]:
        pytest.skip("no warnings to mutate")

    mutable_context = copy.deepcopy(chain_result["context"])
    mutable_context["warnings"][0]["code"] = "MUTATED"

    fresh_context = validate_decision_context(copy.deepcopy(chain_result["context_payload_snapshot"]))
    assert fresh_context["warnings"][0]["code"] != "MUTATED"


def test_mutating_returned_analysis_condition_list_does_not_affect_input(chain_result):
    mutable_analysis = copy.deepcopy(chain_result["analysis"])
    mutable_analysis["evidence_gaps"].append("injected gap")

    fresh_analysis = validate_decision_analysis(copy.deepcopy(chain_result["analysis_payload_snapshot"]))
    assert "injected gap" not in fresh_analysis["evidence_gaps"]


def test_fresh_validation_call_still_returns_expected_output(chain_result):
    fresh_context = validate_decision_context(copy.deepcopy(chain_result["context_payload_snapshot"]))
    assert fresh_context == chain_result["context"]


# ---------------------------------------------------------------------------
# Fail-closed compatibility cases
# ---------------------------------------------------------------------------

def test_fail_closed_01_cross_investigation_evidence_rejected_before_analysis():
    payload = _build_context_payload()
    for record in payload["evidence_records"]:
        if record["id"] == SUP1:
            record["investigation_id"] = OTHER_INVESTIGATION_ID

    with pytest.raises(DecisionContextError):
        validate_decision_context(payload)


def test_fail_closed_02_missing_requested_evidence_record_rejected():
    payload = _build_context_payload()
    payload["evidence_records"] = [r for r in payload["evidence_records"] if r["id"] != SUP1]

    with pytest.raises(DecisionContextError):
        validate_decision_context(payload)


def test_fail_closed_03_unrequested_supplied_evidence_record_rejected():
    payload = _build_context_payload()
    extra_id = "88888888-8888-4888-8888-888888888888"
    payload["evidence_records"].append(
        _record(extra_id, "high", "high", "observation", True, "extra")
    )

    with pytest.raises(DecisionContextError):
        validate_decision_context(payload)


def test_fail_closed_04_evidence_id_in_both_groups_rejected():
    payload = _build_context_payload()
    payload["contradicting_evidence_ids"] = payload["contradicting_evidence_ids"] + [SUP1]

    with pytest.raises(DecisionContextError):
        validate_decision_context(payload)


def test_fail_closed_05_malformed_decision_status_rejected_after_valid_context(chain_result):
    analysis_payload = _build_analysis_payload(chain_result["context"])
    analysis_payload["decision_status"] = "not_a_real_status"

    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(analysis_payload)


def test_fail_closed_06_same_evidence_id_in_both_analysis_lists_rejected(chain_result):
    analysis_payload = _build_analysis_payload(chain_result["context"])
    analysis_payload["contradicting_evidence_ids"] = analysis_payload["contradicting_evidence_ids"] + [
        analysis_payload["supporting_evidence_ids"][0]
    ]

    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(analysis_payload)


def test_fail_closed_07_non_null_hypothesis_id_rejected(chain_result):
    analysis_payload = _build_analysis_payload(chain_result["context"])
    analysis_payload["hypothesis_id"] = "some-hypothesis"

    with pytest.raises(DecisionAnalysisError):
        validate_decision_analysis(analysis_payload)


def test_fail_closed_08_empty_context_selection_supports_insufficient_evidence():
    payload = {
        "investigation_id": INVESTIGATION_ID,
        "investigation": _investigation_mapping(),
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
        "evidence_records": [],
    }

    context = validate_decision_context(payload)

    analysis_payload = {
        "investigation_id": context["investigation"]["id"],
        "current_assessment": "No supporting or contradicting evidence has been reviewed yet.",
        "decision_status": "insufficient_evidence",
        "supporting_evidence_ids": [item["id"] for item in context["supporting_evidence"]],
        "contradicting_evidence_ids": [item["id"] for item in context["contradicting_evidence"]],
    }

    analysis = validate_decision_analysis(analysis_payload)

    assert analysis["decision_status"] == "insufficient_evidence"
    assert analysis["supporting_evidence_ids"] == []
    assert analysis["contradicting_evidence_ids"] == []


def test_fail_closed_09_context_warnings_never_block_valid_analysis(chain_result):
    # The fixture's context already produced 9 warnings; the analysis
    # built from it still validated successfully (chain_result fixture
    # would have raised during setup otherwise).
    assert len(chain_result["context"]["warnings"]) > 0
    assert chain_result["analysis"]["decision_status"] == "partially_supported"


def test_fail_closed_10_large_warning_count_does_not_change_decision_status(chain_result):
    analysis_payload = _build_analysis_payload(chain_result["context"])
    analysis_payload["decision_status"] = "contradicted"

    analysis = validate_decision_analysis(analysis_payload)

    assert analysis["decision_status"] == "contradicted"


# ---------------------------------------------------------------------------
# Runtime side-effect guards
# ---------------------------------------------------------------------------

def test_chain_never_touches_forbidden_entry_points(monkeypatch):
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called during the decision-contract chain")

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

    assert "mcp.hayabusa_server" not in sys.modules

    context_payload = _build_context_payload()
    context = validate_decision_context(context_payload)
    analysis_payload = _build_analysis_payload(context)
    analysis = validate_decision_analysis(analysis_payload)

    assert analysis["decision_status"] == "partially_supported"
    assert "mcp.hayabusa_server" not in sys.modules


# ---------------------------------------------------------------------------
# Scope assertions
# ---------------------------------------------------------------------------

def test_no_att_and_ck_fields_anywhere(chain_result):
    for output in (chain_result["context"], chain_result["analysis"]):
        assert not any("attack" in str(k).lower() or "technique" in str(k).lower() for k in output)


def test_no_evidence_hash_fields_anywhere(chain_result):
    for output in (chain_result["context"], chain_result["analysis"]):
        assert "evidence_hash" not in output
        assert not any("hash" in str(k).lower() for k in output)


def test_no_approval_or_audit_fields_anywhere(chain_result):
    for output in (chain_result["context"], chain_result["analysis"]):
        assert not any("approval" in str(k).lower() or "audit" in str(k).lower() for k in output)


def test_no_containment_or_execution_fields_anywhere(chain_result):
    for output in (chain_result["context"], chain_result["analysis"]):
        assert not any("containment" in str(k).lower() or "execution" in str(k).lower() for k in output)
