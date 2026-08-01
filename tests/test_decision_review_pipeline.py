"""Permanent synthetic end-to-end integration test for the decision-review
pipeline: core.decision_context_cli -> core.decision_warning_formatter_cli ->
core.decision_analysis_cli, driven entirely by fixed in-memory synthetic
investigation/evidence mappings.

This module never executes the /decision-review slash command, never calls
Supabase, and never uses subprocess to invoke any CLI -- each CLI's main()
is called directly with fresh io.StringIO streams, exactly like the CLIs'
own dedicated test suites. All orchestration ("the pipeline") is test-only
glue that mirrors the read-only, fail-closed sequence described in
.claude/commands/decision-review.md; none of it is production code.
"""

import copy
import io
import json
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

import core.decision_analysis_cli as decision_analysis_cli
import core.decision_context_cli as decision_context_cli
import core.decision_warning_formatter_cli as decision_warning_formatter_cli

# ---------------------------------------------------------------------------
# Synthetic identifiers
# ---------------------------------------------------------------------------

INVESTIGATION_ID = "11111111-1111-4111-8111-111111111111"
SUP1 = "21111111-1111-4111-8111-111111111111"
SUP2 = "22222222-2222-4222-8222-222222222222"
SUP3 = "23333333-3333-4333-8333-333333333333"
CON1 = "24444444-4444-4444-8444-444444444444"
CON2 = "25555555-5555-4555-8555-555555555555"

EXPECTED_WARNING_SEQUENCE = (
    (SUP2, "EVIDENCE_TRUST_UNKNOWN"),
    (SUP2, "EVIDENCE_CONFIDENCE_UNKNOWN"),
    (SUP2, "EVIDENCE_IS_INTERPRETATION"),
    (SUP2, "SUPPORTS_HYPOTHESIS_UNSPECIFIED"),
    (SUP3, "EVIDENCE_TRUST_LOW"),
    (SUP3, "EVIDENCE_IS_HYPOTHESIS"),
    (SUP3, "SUPPORTS_HYPOTHESIS_CONFLICT"),
    (CON1, "EVIDENCE_IS_RECOMMENDATION"),
    (CON1, "SUPPORTS_HYPOTHESIS_CONFLICT"),
)

# Independently hardcoded (not imported from core.decision_warning_formatter)
# committed fixed explanation text, per code.
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

REASONING_FIELDS = (
    "unresolved_assumptions",
    "evidence_gaps",
    "strengthen_conditions",
    "weaken_conditions",
    "reversal_conditions",
    "recommended_next_evidence",
    "limitations",
)

_SECRET_MARKERS = (
    "SUPPORTING-DETAIL-MUST-NOT-LEAK",
    "SUPPORTING-PROVENANCE-MUST-NOT-LEAK",
    "INTERPRETATION-DETAIL-MUST-NOT-LEAK",
    "INTERPRETATION-PROVENANCE-MUST-NOT-LEAK",
    "HYPOTHESIS-DETAIL-MUST-NOT-LEAK",
    "HYPOTHESIS-PROVENANCE-MUST-NOT-LEAK",
    "RECOMMENDATION-DETAIL-MUST-NOT-LEAK",
    "RECOMMENDATION-PROVENANCE-MUST-NOT-LEAK",
    "DERIVED-DETAIL-MUST-NOT-LEAK",
    "DERIVED-PROVENANCE-MUST-NOT-LEAK",
)


# ---------------------------------------------------------------------------
# Synthetic fixture builders (fresh objects every call -- never shared,
# mutable module state)
# ---------------------------------------------------------------------------

def _analyst_request():
    return {
        "investigation_id": INVESTIGATION_ID,
        "supporting_evidence_ids": [SUP1, SUP2, SUP3],
        "contradicting_evidence_ids": [CON1, CON2],
        "current_assessment": (
            "The synthetic PowerShell activity is more consistent with unauthorized "
            "execution than approved administration."
        ),
        "decision_status": "partially_supported",
        "unresolved_assumptions": ["Whether the PowerShell execution was approved by an administrator."],
        "evidence_gaps": ["No endpoint process tree is available for the selected activity."],
        "strengthen_conditions": [
            "A matching endpoint process tree showing an unapproved parent process would strengthen the assessment."
        ],
        "weaken_conditions": ["A verified change ticket authorizing the command would weaken the assessment."],
        "reversal_conditions": [
            "Confirmed administrative approval and matching maintenance records would reverse the assessment."
        ],
        "recommended_next_evidence": ["Collect the endpoint process tree and the relevant change-management record."],
        "limitations": ["This synthetic review uses summarized evidence metadata rather than raw event content."],
    }


def _investigation_row(investigation_id=INVESTIGATION_ID):
    return {
        "id": investigation_id,
        "status": "investigating",
        "confidence": "medium",
        "title": "Synthetic PowerShell Review",
        "description": "Extra database field that must not enter the context summary.",
        "created_at": "2026-08-01T15:00:00Z",
        "updated_at": "2026-08-01T15:30:00Z",
    }


def _evidence_record(evidence_id, investigation_id=INVESTIGATION_ID, **overrides):
    record = {
        "id": evidence_id,
        "investigation_id": investigation_id,
        "trust_level": "high",
        "confidence": "high",
        "assertion_type": "observation",
        "supports_hypothesis": True,
        "source": "synthetic-source",
        "details": {"secret_marker": "UNUSED"},
        "provenance": {"secret_marker": "UNUSED"},
    }
    record.update(overrides)
    return record


def _evidence_records():
    sup1 = _evidence_record(
        SUP1,
        trust_level="high",
        confidence="high",
        assertion_type="observation",
        supports_hypothesis=True,
        source="synthetic-edr",
        details={"secret_marker": "SUPPORTING-DETAIL-MUST-NOT-LEAK"},
        provenance={"secret_marker": "SUPPORTING-PROVENANCE-MUST-NOT-LEAK"},
    )
    sup2 = _evidence_record(
        SUP2,
        trust_level="unknown",
        confidence="unknown",
        assertion_type="interpretation",
        supports_hypothesis=None,
        source="synthetic-analyst-note",
        details={"secret_marker": "INTERPRETATION-DETAIL-MUST-NOT-LEAK"},
        provenance={"secret_marker": "INTERPRETATION-PROVENANCE-MUST-NOT-LEAK"},
    )
    sup3 = _evidence_record(
        SUP3,
        trust_level="low",
        confidence="medium",
        assertion_type="hypothesis",
        supports_hypothesis=False,
        source="synthetic-hypothesis",
        details={"secret_marker": "HYPOTHESIS-DETAIL-MUST-NOT-LEAK"},
        provenance={"secret_marker": "HYPOTHESIS-PROVENANCE-MUST-NOT-LEAK"},
    )
    con1 = _evidence_record(
        CON1,
        trust_level="medium",
        confidence="high",
        assertion_type="recommendation",
        supports_hypothesis=True,
        source="synthetic-recommendation",
        details={"secret_marker": "RECOMMENDATION-DETAIL-MUST-NOT-LEAK"},
        provenance={"secret_marker": "RECOMMENDATION-PROVENANCE-MUST-NOT-LEAK"},
    )
    con2 = _evidence_record(
        CON2,
        trust_level="high",
        confidence="medium",
        assertion_type="derived_fact",
        supports_hypothesis=False,
        source="synthetic-change-record",
        details={"secret_marker": "DERIVED-DETAIL-MUST-NOT-LEAK"},
        provenance={"secret_marker": "DERIVED-PROVENANCE-MUST-NOT-LEAK"},
    )
    # Deliberately different order from the selection lists (SUP1, SUP2, SUP3, CON1, CON2).
    return [con2, sup2, con1, sup1, sup3]


# ---------------------------------------------------------------------------
# Local, test-only CLI invocation helper
# ---------------------------------------------------------------------------

def _run_cli(main_func, payload):
    """Invoke a CLI main() directly with fresh StringIO streams.

    Never uses subprocess, never writes a temporary file, never touches the
    network. For a claimed success (exit code 0), independently verifies
    that stdout contains exactly one JSON value followed only by
    whitespace, using json.JSONDecoder.raw_decode rather than trusting a
    bare json.loads call to have rejected trailing content.
    """
    stdin = io.StringIO(json.dumps(payload))
    stdout = io.StringIO()
    stderr = io.StringIO()

    exit_code = main_func(stdin=stdin, stdout=stdout, stderr=stderr)

    raw_stdout = stdout.getvalue()
    raw_stderr = stderr.getvalue()
    decoded = None

    if exit_code == 0:
        assert raw_stderr == "", f"success path must write no stderr, got: {raw_stderr!r}"
        assert raw_stdout != "", "success path must write non-empty stdout"
        decoder = json.JSONDecoder()
        value, end = decoder.raw_decode(raw_stdout)
        remainder = raw_stdout[end:]
        assert remainder.strip() == "", (
            f"stdout contained trailing non-whitespace content after one JSON value: {remainder!r}"
        )
        decoded = value

    return exit_code, raw_stdout, raw_stderr, decoded


# ---------------------------------------------------------------------------
# Test-only pipeline orchestration (mirrors the command's own described
# sequence; not production code)
# ---------------------------------------------------------------------------

class PipelineResult:
    def __init__(self):
        self.context_exit = None
        self.context_stdout = ""
        self.context_stderr = ""
        self.context = None

        self.warning_exit = None
        self.warning_stdout = ""
        self.warning_stderr = ""
        self.formatted_warnings = None

        self.analysis_exit = None
        self.analysis_stdout = ""
        self.analysis_stderr = ""
        self.analysis = None

        self.combined = None


def _build_analysis_payload(request, validated_context):
    return {
        "investigation_id": validated_context["investigation"]["id"],
        "hypothesis_id": None,
        "current_assessment": request["current_assessment"],
        "decision_status": request["decision_status"],
        "supporting_evidence_ids": [item["id"] for item in validated_context["supporting_evidence"]],
        "contradicting_evidence_ids": [item["id"] for item in validated_context["contradicting_evidence"]],
        "unresolved_assumptions": list(request.get("unresolved_assumptions", [])),
        "evidence_gaps": list(request.get("evidence_gaps", [])),
        "strengthen_conditions": list(request.get("strengthen_conditions", [])),
        "weaken_conditions": list(request.get("weaken_conditions", [])),
        "reversal_conditions": list(request.get("reversal_conditions", [])),
        "recommended_next_evidence": list(request.get("recommended_next_evidence", [])),
        "limitations": list(request.get("limitations", [])),
    }


def _run_pipeline(request, investigation_row, evidence_records):
    result = PipelineResult()

    context_payload = {
        "investigation_id": request["investigation_id"],
        "investigation": investigation_row,
        "supporting_evidence_ids": request["supporting_evidence_ids"],
        "contradicting_evidence_ids": request["contradicting_evidence_ids"],
        "evidence_records": evidence_records,
    }
    exit_code, stdout, stderr, decoded = _run_cli(decision_context_cli.main, context_payload)
    result.context_exit, result.context_stdout, result.context_stderr = exit_code, stdout, stderr
    if exit_code != 0:
        return result
    result.context = decoded

    exit_code, stdout, stderr, decoded = _run_cli(
        decision_warning_formatter_cli.main, result.context["warnings"]
    )
    result.warning_exit, result.warning_stdout, result.warning_stderr = exit_code, stdout, stderr
    if exit_code != 0:
        return result
    result.formatted_warnings = decoded

    analysis_payload = _build_analysis_payload(request, result.context)
    exit_code, stdout, stderr, decoded = _run_cli(decision_analysis_cli.main, analysis_payload)
    result.analysis_exit, result.analysis_stdout, result.analysis_stderr = exit_code, stdout, stderr
    if exit_code != 0:
        return result
    result.analysis = decoded

    result.combined = {
        "context": result.context,
        "formatted_warnings": result.formatted_warnings,
        "analysis": result.analysis,
    }
    return result


# ---------------------------------------------------------------------------
# Fixtures (function-scoped: fresh, independently-owned objects for every
# test -- never a shared module-scoped object that a test could mutate)
# ---------------------------------------------------------------------------

@pytest.fixture
def analyst_request():
    return _analyst_request()


@pytest.fixture
def investigation_row():
    return _investigation_row()


@pytest.fixture
def evidence_records():
    return _evidence_records()


@pytest.fixture
def happy_path(analyst_request, investigation_row, evidence_records):
    request_snapshot = copy.deepcopy(analyst_request)
    investigation_snapshot = copy.deepcopy(investigation_row)
    evidence_snapshot = copy.deepcopy(evidence_records)

    result = _run_pipeline(analyst_request, investigation_row, evidence_records)

    assert analyst_request == request_snapshot
    assert investigation_row == investigation_snapshot
    assert evidence_records == evidence_snapshot

    return result


# ---------------------------------------------------------------------------
# 1-10: three-stage happy path shape and ordering
# ---------------------------------------------------------------------------

def test_h01_complete_three_stage_pipeline_succeeds(happy_path):
    assert happy_path.context_exit == 0
    assert happy_path.warning_exit == 0
    assert happy_path.analysis_exit == 0
    assert happy_path.combined is not None


def test_h02_context_cli_runs_before_warning_cli(happy_path):
    assert happy_path.context is not None
    assert happy_path.formatted_warnings is not None


def test_h03_warning_cli_runs_before_analysis_cli(happy_path):
    assert happy_path.formatted_warnings is not None
    assert happy_path.analysis is not None


def test_h04_every_cli_receives_exactly_one_json_value(happy_path):
    # _run_cli's raw_decode-based assertion already enforces this for every
    # stage that reached exit code 0; re-assert the shared invariant here.
    for stdout in (happy_path.context_stdout, happy_path.warning_stdout, happy_path.analysis_stdout):
        decoder = json.JSONDecoder()
        _value, end = decoder.raw_decode(stdout)
        assert stdout[end:].strip() == ""


def test_h05_every_successful_cli_writes_empty_stderr(happy_path):
    assert happy_path.context_stderr == ""
    assert happy_path.warning_stderr == ""
    assert happy_path.analysis_stderr == ""


def test_h06_context_output_has_exact_shape(happy_path):
    assert set(happy_path.context.keys()) == {
        "investigation",
        "supporting_evidence",
        "contradicting_evidence",
        "warnings",
    }


def test_h07_context_investigation_summary_has_exact_shape(happy_path):
    assert set(happy_path.context["investigation"].keys()) == {"id", "status", "confidence"}


def test_h08_supporting_group_order_preserved(happy_path):
    assert [item["id"] for item in happy_path.context["supporting_evidence"]] == [SUP1, SUP2, SUP3]


def test_h09_contradicting_group_order_preserved(happy_path):
    assert [item["id"] for item in happy_path.context["contradicting_evidence"]] == [CON1, CON2]


def test_h10_evidence_record_input_order_does_not_control_output_group_order(happy_path):
    # _evidence_records() supplies [con2, sup2, con1, sup1, sup3] -- a
    # deliberately different order than the selection lists.
    assert [item["id"] for item in happy_path.context["supporting_evidence"]] != [SUP2, SUP1, SUP3]
    assert [item["id"] for item in happy_path.context["supporting_evidence"]] == [SUP1, SUP2, SUP3]


# ---------------------------------------------------------------------------
# 11-20: warnings
# ---------------------------------------------------------------------------

def test_h11_all_nine_warnings_appear(happy_path):
    assert len(happy_path.context["warnings"]) == 9


def test_h12_warning_sequence_is_exact(happy_path):
    actual = [(w["evidence_id"], w["code"]) for w in happy_path.context["warnings"]]
    assert actual == list(EXPECTED_WARNING_SEQUENCE)


def test_h13_all_eight_warning_codes_appear(happy_path):
    codes = {w["code"] for w in happy_path.context["warnings"]}
    expected_codes = {
        "EVIDENCE_TRUST_UNKNOWN",
        "EVIDENCE_TRUST_LOW",
        "EVIDENCE_CONFIDENCE_UNKNOWN",
        "EVIDENCE_IS_INTERPRETATION",
        "EVIDENCE_IS_HYPOTHESIS",
        "EVIDENCE_IS_RECOMMENDATION",
        "SUPPORTS_HYPOTHESIS_CONFLICT",
        "SUPPORTS_HYPOTHESIS_UNSPECIFIED",
    }
    assert codes == expected_codes


def test_h14_conflict_warning_appears_twice_for_distinct_evidence_ids(happy_path):
    conflict_ids = [w["evidence_id"] for w in happy_path.context["warnings"] if w["code"] == "SUPPORTS_HYPOTHESIS_CONFLICT"]
    assert conflict_ids == [SUP3, CON1]


def test_h15_warning_formatter_receives_only_context_warnings(happy_path):
    assert len(happy_path.formatted_warnings) == len(happy_path.context["warnings"])


def test_h16_warning_formatter_preserves_warning_count(happy_path):
    assert len(happy_path.formatted_warnings) == 9


def test_h17_warning_formatter_preserves_warning_order(happy_path):
    actual = [(w["evidence_id"], w["code"]) for w in happy_path.formatted_warnings]
    assert actual == list(EXPECTED_WARNING_SEQUENCE)


def test_h18_warning_formatter_preserves_evidence_ids(happy_path):
    for context_warning, formatted_warning in zip(happy_path.context["warnings"], happy_path.formatted_warnings):
        assert context_warning["evidence_id"] == formatted_warning["evidence_id"]


def test_h19_warning_formatter_preserves_warning_codes(happy_path):
    for context_warning, formatted_warning in zip(happy_path.context["warnings"], happy_path.formatted_warnings):
        assert context_warning["code"] == formatted_warning["code"]


def test_h20_fixed_explanation_text_is_exact(happy_path):
    for warning in happy_path.formatted_warnings:
        assert warning["explanation"] == EXPECTED_EXPLANATIONS[warning["code"]]


# ---------------------------------------------------------------------------
# 21-32: analysis handoff and preservation
# ---------------------------------------------------------------------------

def test_h21_analysis_investigation_id_comes_from_validated_context(happy_path):
    assert happy_path.analysis["investigation_id"] == happy_path.context["investigation"]["id"]


def test_h22_analysis_supporting_ids_come_from_validated_context(happy_path):
    expected = [item["id"] for item in happy_path.context["supporting_evidence"]]
    assert happy_path.analysis["supporting_evidence_ids"] == expected


def test_h23_analysis_contradicting_ids_come_from_validated_context(happy_path):
    expected = [item["id"] for item in happy_path.context["contradicting_evidence"]]
    assert happy_path.analysis["contradicting_evidence_ids"] == expected


def test_h24_analysis_does_not_reuse_raw_request_lists_as_object_references(analyst_request, investigation_row, evidence_records):
    request_snapshot_supporting_id = id(analyst_request["supporting_evidence_ids"])
    request_snapshot_contradicting_id = id(analyst_request["contradicting_evidence_ids"])

    result = _run_pipeline(analyst_request, investigation_row, evidence_records)

    assert result.analysis is not None
    # The analysis payload's evidence-ID lists must be freshly rebuilt lists,
    # not the same list objects the raw request supplied.
    assert id(result.analysis["supporting_evidence_ids"]) != request_snapshot_supporting_id
    assert id(result.analysis["contradicting_evidence_ids"]) != request_snapshot_contradicting_id


def test_h25_hypothesis_id_remains_none(happy_path):
    assert happy_path.analysis["hypothesis_id"] is None


def test_h26_analyst_current_assessment_preserved(happy_path, analyst_request):
    assert happy_path.analysis["current_assessment"] == analyst_request["current_assessment"]


def test_h27_analyst_decision_status_preserved(happy_path):
    assert happy_path.analysis["decision_status"] == "partially_supported"


def test_h28_warning_count_does_not_alter_decision_status(happy_path):
    assert len(happy_path.context["warnings"]) == 9
    assert happy_path.analysis["decision_status"] == "partially_supported"


def test_h29_evidence_count_does_not_alter_decision_status(happy_path):
    assert len(happy_path.analysis["supporting_evidence_ids"]) == 3
    assert len(happy_path.analysis["contradicting_evidence_ids"]) == 2
    assert happy_path.analysis["decision_status"] == "partially_supported"


def test_h30_all_seven_reasoning_collections_preserved(happy_path, analyst_request):
    for field in REASONING_FIELDS:
        assert happy_path.analysis[field] == analyst_request[field]


def test_h31_generated_at_generated_by_validator(happy_path, analyst_request):
    assert "generated_at" not in analyst_request
    assert happy_path.analysis["generated_at"]


def test_h32_generated_at_is_utc_z_formatted(happy_path):
    generated_at = happy_path.analysis["generated_at"]
    assert isinstance(generated_at, str)
    assert generated_at.strip() != ""
    assert generated_at.endswith("Z")
    parsed = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timezone.utc.utcoffset(parsed)


# ---------------------------------------------------------------------------
# 33-45: combined result and leakage boundaries
# ---------------------------------------------------------------------------

def test_h33_combined_result_contains_exact_three_sections(happy_path):
    assert set(happy_path.combined.keys()) == {"context", "formatted_warnings", "analysis"}


def test_h34_combined_result_is_json_serializable(happy_path):
    serialized = json.dumps(happy_path.combined)
    assert isinstance(serialized, str)
    assert json.loads(serialized) == happy_path.combined


def test_h35_no_details_leak(happy_path):
    serialized = json.dumps(happy_path.combined)
    assert "details" not in serialized
    for marker in _SECRET_MARKERS:
        assert marker not in serialized


def test_h36_no_provenance_leak(happy_path):
    serialized = json.dumps(happy_path.combined)
    assert "provenance" not in serialized


def test_h37_no_source_or_command_line_metadata_leak(happy_path):
    serialized = json.dumps(happy_path.combined)
    assert "synthetic-edr" not in serialized
    assert "synthetic-analyst-note" not in serialized
    assert "command_line" not in serialized
    assert "source_location" not in serialized


def test_h38_no_raw_investigation_extra_fields_leak(happy_path):
    serialized = json.dumps(happy_path.combined)
    assert "Synthetic PowerShell Review" not in serialized
    assert "Extra database field" not in serialized
    assert "created_at" not in serialized
    assert "updated_at" not in serialized


def test_h39_no_raw_evidence_row_is_embedded(happy_path, evidence_records):
    serialized = json.dumps(happy_path.combined)
    for record in evidence_records:
        assert json.dumps(record) not in serialized


def test_h40_no_approval_result_generated(happy_path):
    # Analyst-authored reasoning text may legitimately mention "approval"
    # (e.g. "whether the PowerShell execution was approved by an
    # administrator") -- that is exactly the kind of assumption the analyst
    # is expected to record, not an approval *result* this command produced.
    # Check for structured approval-result fields instead of the bare word.
    for section in happy_path.combined.values():
        assert "approval_status" not in section
        assert "approved_by" not in section
        assert "approval_id" not in section
    for evidence_summary in happy_path.context["supporting_evidence"] + happy_path.context["contradicting_evidence"]:
        assert "approval_status" not in evidence_summary
        assert "approved_by" not in evidence_summary


def test_h41_no_persistence_result_generated(happy_path):
    serialized = json.dumps(happy_path.combined).lower()
    assert "persisted" not in serialized
    assert "inserted" not in serialized


def test_h42_no_containment_result_generated(happy_path):
    serialized = json.dumps(happy_path.combined).lower()
    assert "containment" not in serialized
    assert "contained" not in serialized


def test_h43_no_execution_result_generated(happy_path):
    serialized = json.dumps(happy_path.combined).lower()
    assert "executed" not in serialized
    assert "execution_result" not in serialized


def test_h44_investigation_confidence_remains_separate_from_decision_status(happy_path):
    assert happy_path.context["investigation"]["confidence"] == "medium"
    assert happy_path.analysis["decision_status"] == "partially_supported"
    assert happy_path.context["investigation"]["confidence"] != happy_path.analysis["decision_status"]


def test_h45_evidence_confidence_remains_separate_from_trust_level(happy_path):
    sup2_summary = next(item for item in happy_path.context["supporting_evidence"] if item["id"] == SUP2)
    assert sup2_summary["confidence"] == "unknown"
    assert sup2_summary["trust_level"] == "unknown"
    sup3_summary = next(item for item in happy_path.context["supporting_evidence"] if item["id"] == SUP3)
    assert sup3_summary["confidence"] == "medium"
    assert sup3_summary["trust_level"] == "low"
    assert sup3_summary["confidence"] != sup3_summary["trust_level"]


# ---------------------------------------------------------------------------
# Empty-evidence pipeline
# ---------------------------------------------------------------------------

def _empty_evidence_request():
    return {
        "investigation_id": INVESTIGATION_ID,
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
        "current_assessment": "Insufficient evidence exists to support or contradict a hypothesis.",
        "decision_status": "insufficient_evidence",
    }


def test_e01_context_cli_succeeds_with_no_evidence():
    request = _empty_evidence_request()
    investigation_row = _investigation_row()

    result = _run_pipeline(request, investigation_row, [])

    assert result.context_exit == 0


def test_e02_no_evidence_summaries_appear():
    request = _empty_evidence_request()
    result = _run_pipeline(request, _investigation_row(), [])

    assert result.context["supporting_evidence"] == []
    assert result.context["contradicting_evidence"] == []


def test_e03_warnings_is_empty_list():
    request = _empty_evidence_request()
    result = _run_pipeline(request, _investigation_row(), [])

    assert result.context["warnings"] == []


def test_e04_warning_formatter_cli_succeeds_with_empty_array():
    request = _empty_evidence_request()
    result = _run_pipeline(request, _investigation_row(), [])

    assert result.warning_exit == 0


def test_e05_formatted_warnings_is_empty_list():
    request = _empty_evidence_request()
    result = _run_pipeline(request, _investigation_row(), [])

    assert result.formatted_warnings == []


def test_e06_analysis_cli_succeeds():
    request = _empty_evidence_request()
    result = _run_pipeline(request, _investigation_row(), [])

    assert result.analysis_exit == 0


def test_e07_evidence_id_lists_remain_empty():
    request = _empty_evidence_request()
    result = _run_pipeline(request, _investigation_row(), [])

    assert result.analysis["supporting_evidence_ids"] == []
    assert result.analysis["contradicting_evidence_ids"] == []


def test_e08_all_seven_omitted_collections_normalize_to_empty_list():
    request = _empty_evidence_request()
    for field in REASONING_FIELDS:
        assert field not in request

    result = _run_pipeline(request, _investigation_row(), [])

    for field in REASONING_FIELDS:
        assert result.analysis[field] == []


def test_e09_decision_status_remains_insufficient_evidence():
    request = _empty_evidence_request()
    result = _run_pipeline(request, _investigation_row(), [])

    assert result.analysis["decision_status"] == "insufficient_evidence"


def test_e10_no_stage_invents_evidence_or_reasoning():
    request = _empty_evidence_request()
    result = _run_pipeline(request, _investigation_row(), [])

    assert result.combined is not None
    assert result.context["supporting_evidence"] == []
    assert result.context["contradicting_evidence"] == []
    for field in REASONING_FIELDS:
        assert result.analysis[field] == []


# ---------------------------------------------------------------------------
# Canonical-handoff scenario
# ---------------------------------------------------------------------------

def _noncanonical_request():
    return {
        "investigation_id": INVESTIGATION_ID.upper(),
        "supporting_evidence_ids": [SUP1.upper(), f"  {SUP2}  ", f"{{{SUP3}}}"],
        "contradicting_evidence_ids": [CON1.upper(), f"  {CON2}  "],
        "current_assessment": "Canonical-handoff synthetic assessment.",
        "decision_status": "inconclusive",
    }


def test_c01_context_output_contains_canonical_uuids():
    request = _noncanonical_request()
    result = _run_pipeline(request, _investigation_row(), _evidence_records())

    assert result.context_exit == 0
    assert result.context["investigation"]["id"] == INVESTIGATION_ID
    assert [item["id"] for item in result.context["supporting_evidence"]] == [SUP1, SUP2, SUP3]
    assert [item["id"] for item in result.context["contradicting_evidence"]] == [CON1, CON2]


def test_c02_analysis_ids_rebuilt_from_canonical_context_output():
    request = _noncanonical_request()
    result = _run_pipeline(request, _investigation_row(), _evidence_records())

    assert result.analysis_exit == 0
    assert result.analysis["supporting_evidence_ids"] == [SUP1, SUP2, SUP3]
    assert result.analysis["contradicting_evidence_ids"] == [CON1, CON2]
    assert result.analysis["investigation_id"] == INVESTIGATION_ID


def test_c03_analysis_contains_no_noncanonical_raw_request_id():
    request = _noncanonical_request()
    result = _run_pipeline(request, _investigation_row(), _evidence_records())

    # Note: these synthetic UUIDs use only digits, so .upper() is a no-op
    # and would equal the canonical form -- the whitespace-padded and
    # brace-wrapped forms are the only noncanonical variants that actually
    # differ syntactically from the canonical UUID string for this fixture.
    serialized = json.dumps(result.analysis)
    assert f"{{{SUP3}}}" not in serialized
    assert f"  {SUP2}  " not in serialized
    assert f"  {CON2}  " not in serialized


def test_c04_raw_request_is_not_mutated():
    request = _noncanonical_request()
    snapshot = copy.deepcopy(request)

    _run_pipeline(request, _investigation_row(), _evidence_records())

    assert request == snapshot


# ---------------------------------------------------------------------------
# Fail-closed: context-stage validation failures (exit code 2)
# ---------------------------------------------------------------------------

def _forbidden_main(*_args, **_kwargs):
    raise AssertionError("a later pipeline stage must not be called after an earlier stage failed")


def test_f01_context_stage_malformed_investigation_id_returns_2(monkeypatch):
    monkeypatch.setattr(decision_warning_formatter_cli, "main", _forbidden_main)
    monkeypatch.setattr(decision_analysis_cli, "main", _forbidden_main)

    request = _analyst_request()
    request["investigation_id"] = "not-a-uuid"

    result = _run_pipeline(request, _investigation_row(), _evidence_records())

    assert result.context_exit == 2
    assert result.warning_exit is None
    assert result.analysis_exit is None
    assert result.combined is None


def test_f02_context_stage_missing_selected_evidence_record_returns_2(monkeypatch):
    monkeypatch.setattr(decision_warning_formatter_cli, "main", _forbidden_main)
    monkeypatch.setattr(decision_analysis_cli, "main", _forbidden_main)

    request = _analyst_request()
    records = [record for record in _evidence_records() if record["id"] != SUP1]

    result = _run_pipeline(request, _investigation_row(), records)

    assert result.context_exit == 2
    assert result.combined is None


def test_f03_context_stage_cross_investigation_evidence_returns_2(monkeypatch):
    monkeypatch.setattr(decision_warning_formatter_cli, "main", _forbidden_main)
    monkeypatch.setattr(decision_analysis_cli, "main", _forbidden_main)

    request = _analyst_request()
    records = _evidence_records()
    for record in records:
        if record["id"] == SUP1:
            record["investigation_id"] = "66666666-6666-4666-8666-666666666666"

    result = _run_pipeline(request, _investigation_row(), records)

    assert result.context_exit == 2
    assert result.combined is None


def test_f04_context_stage_overlapping_evidence_groups_returns_2(monkeypatch):
    monkeypatch.setattr(decision_warning_formatter_cli, "main", _forbidden_main)
    monkeypatch.setattr(decision_analysis_cli, "main", _forbidden_main)

    request = _analyst_request()
    request["contradicting_evidence_ids"] = [SUP1, CON2]

    result = _run_pipeline(request, _investigation_row(), _evidence_records())

    assert result.context_exit == 2
    assert result.combined is None


def test_f05_context_stage_invalid_evidence_trust_level_returns_2(monkeypatch):
    monkeypatch.setattr(decision_warning_formatter_cli, "main", _forbidden_main)
    monkeypatch.setattr(decision_analysis_cli, "main", _forbidden_main)

    request = _analyst_request()
    records = _evidence_records()
    for record in records:
        if record["id"] == SUP1:
            record["trust_level"] = "super-trusted"

    result = _run_pipeline(request, _investigation_row(), records)

    assert result.context_exit == 2
    assert result.combined is None


def test_f06_context_unexpected_failure_returns_1_and_stops(monkeypatch):
    import core.decision_context as decision_context

    def boom(_payload):
        raise RuntimeError("simulated internal failure with secret marker XYZ123")

    monkeypatch.setattr(decision_context_cli, "validate_decision_context", boom)
    monkeypatch.setattr(decision_warning_formatter_cli, "main", _forbidden_main)
    monkeypatch.setattr(decision_analysis_cli, "main", _forbidden_main)

    request = _analyst_request()
    result = _run_pipeline(request, _investigation_row(), _evidence_records())

    assert result.context_exit == 1
    assert result.context_stderr == "Decision context validation failed.\n"
    assert "XYZ123" not in result.context_stderr
    assert "RuntimeError" not in result.context_stderr
    assert result.combined is None


# ---------------------------------------------------------------------------
# Fail-closed: warning-stage failures
# ---------------------------------------------------------------------------

def _get_valid_context():
    """Run only Stage 1 (context CLI) and return its parsed output.

    Deliberately does not proceed to Stage 2/3 -- callers that only need a
    valid context to build a Stage-2 or Stage-3 test scenario should use
    this instead of the full _run_pipeline, so that an unrelated
    monkeypatch on a later stage's main() cannot be triggered merely by
    obtaining a valid context.
    """
    context_payload = {
        "investigation_id": INVESTIGATION_ID,
        "investigation": _investigation_row(),
        "supporting_evidence_ids": [SUP1, SUP2, SUP3],
        "contradicting_evidence_ids": [CON1, CON2],
        "evidence_records": _evidence_records(),
    }
    exit_code, _stdout, _stderr, decoded = _run_cli(decision_context_cli.main, context_payload)
    assert exit_code == 0
    return decoded


def test_f07_warning_stage_unknown_code_returns_2(monkeypatch):
    monkeypatch.setattr(decision_analysis_cli, "main", _forbidden_main)

    validated_context = _get_valid_context()

    tampered_warnings = copy.deepcopy(validated_context["warnings"])
    tampered_warnings[0]["code"] = "NOT_A_REAL_CODE"

    exit_code, _stdout, _stderr, _decoded = _run_cli(decision_warning_formatter_cli.main, tampered_warnings)

    assert exit_code == 2


def test_f08_warning_stage_unexpected_failure_returns_1(monkeypatch):
    monkeypatch.setattr(decision_analysis_cli, "main", _forbidden_main)

    def boom(_warnings):
        raise RuntimeError("simulated formatter failure with secret marker ABC789")

    validated_context = _get_valid_context()

    monkeypatch.setattr(decision_warning_formatter_cli, "format_decision_warnings", boom)

    exit_code, _stdout, stderr, _decoded = _run_cli(
        decision_warning_formatter_cli.main, validated_context["warnings"]
    )

    assert exit_code == 1
    assert stderr == "Decision warning formatting failed.\n"
    assert "ABC789" not in stderr


# ---------------------------------------------------------------------------
# Fail-closed: analysis-stage failures
# ---------------------------------------------------------------------------

def _good_context_and_warnings():
    request = _analyst_request()
    result = _run_pipeline(request, _investigation_row(), _evidence_records())
    assert result.context_exit == 0
    assert result.warning_exit == 0
    return request, result


def test_f09_analysis_stage_unsupported_decision_status_returns_2():
    request, result = _good_context_and_warnings()
    payload = _build_analysis_payload(request, result.context)
    payload["decision_status"] = "maybe"

    exit_code, _stdout, _stderr, _decoded = _run_cli(decision_analysis_cli.main, payload)

    assert exit_code == 2


def test_f10_analysis_stage_overlapping_evidence_ids_returns_2():
    request, result = _good_context_and_warnings()
    payload = _build_analysis_payload(request, result.context)
    payload["contradicting_evidence_ids"] = list(payload["supporting_evidence_ids"])

    exit_code, _stdout, _stderr, _decoded = _run_cli(decision_analysis_cli.main, payload)

    assert exit_code == 2


def test_f11_analysis_stage_non_null_hypothesis_id_returns_2():
    request, result = _good_context_and_warnings()
    payload = _build_analysis_payload(request, result.context)
    payload["hypothesis_id"] = INVESTIGATION_ID

    exit_code, _stdout, _stderr, _decoded = _run_cli(decision_analysis_cli.main, payload)

    assert exit_code == 2


def test_f12_analysis_stage_failure_does_not_produce_a_mislabeled_combined_result():
    request, result = _good_context_and_warnings()
    payload = _build_analysis_payload(request, result.context)
    payload["decision_status"] = "maybe"

    exit_code, _stdout, _stderr, decoded = _run_cli(decision_analysis_cli.main, payload)

    assert exit_code == 2
    assert decoded is None
    # A caller must never assemble {"context": ..., "formatted_warnings": ...,
    # "analysis": ...} using a None/missing analysis result as if it were valid.


def test_f13_analysis_stage_unexpected_failure_returns_1():
    request, result = _good_context_and_warnings()
    payload = _build_analysis_payload(request, result.context)

    def boom(_payload):
        raise RuntimeError("simulated analysis failure with secret marker DEF456 and assessment leak")

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(decision_analysis_cli, "validate_decision_analysis", boom)
        exit_code, _stdout, stderr, decoded = _run_cli(decision_analysis_cli.main, payload)

    assert exit_code == 1
    assert stderr == "Decision analysis validation failed.\n"
    assert "DEF456" not in stderr
    assert request["current_assessment"] not in stderr
    assert decoded is None


# ---------------------------------------------------------------------------
# Non-mutation requirements
# ---------------------------------------------------------------------------

def test_m01_analyst_request_not_mutated_by_pipeline():
    request = _analyst_request()
    snapshot = copy.deepcopy(request)

    _run_pipeline(request, _investigation_row(), _evidence_records())

    assert request == snapshot


def test_m02_investigation_row_not_mutated_by_pipeline():
    request = _analyst_request()
    investigation_row = _investigation_row()
    snapshot = copy.deepcopy(investigation_row)

    _run_pipeline(request, investigation_row, _evidence_records())

    assert investigation_row == snapshot


def test_m03_evidence_record_list_not_mutated_by_pipeline():
    request = _analyst_request()
    records = _evidence_records()
    snapshot = copy.deepcopy(records)

    _run_pipeline(request, _investigation_row(), records)

    assert records == snapshot


def test_m04_every_nested_evidence_mapping_not_mutated():
    request = _analyst_request()
    records = _evidence_records()
    snapshot = copy.deepcopy(records)

    _run_pipeline(request, _investigation_row(), records)

    for original, expected in zip(records, snapshot):
        assert original == expected


def test_m05_details_mappings_not_mutated():
    request = _analyst_request()
    records = _evidence_records()
    details_snapshot = [copy.deepcopy(record["details"]) for record in records]

    _run_pipeline(request, _investigation_row(), records)

    for record, expected_details in zip(records, details_snapshot):
        assert record["details"] == expected_details


def test_m06_provenance_mappings_not_mutated():
    request = _analyst_request()
    records = _evidence_records()
    provenance_snapshot = [copy.deepcopy(record["provenance"]) for record in records]

    _run_pipeline(request, _investigation_row(), records)

    for record, expected_provenance in zip(records, provenance_snapshot):
        assert record["provenance"] == expected_provenance


def test_m07_context_payload_not_mutated_by_context_cli():
    context_payload = {
        "investigation_id": INVESTIGATION_ID,
        "investigation": _investigation_row(),
        "supporting_evidence_ids": [SUP1, SUP2, SUP3],
        "contradicting_evidence_ids": [CON1, CON2],
        "evidence_records": _evidence_records(),
    }
    snapshot = copy.deepcopy(context_payload)

    _run_cli(decision_context_cli.main, context_payload)

    assert context_payload == snapshot


def test_m08_warning_array_not_mutated_by_formatter():
    request = _analyst_request()
    result = _run_pipeline(request, _investigation_row(), _evidence_records())
    warnings_snapshot = copy.deepcopy(result.context["warnings"])

    _run_cli(decision_warning_formatter_cli.main, result.context["warnings"])

    assert result.context["warnings"] == warnings_snapshot


def test_m09_analysis_payload_not_mutated_by_analysis_cli():
    request = _analyst_request()
    result = _run_pipeline(request, _investigation_row(), _evidence_records())
    payload = _build_analysis_payload(request, result.context)
    snapshot = copy.deepcopy(payload)

    _run_cli(decision_analysis_cli.main, payload)

    assert payload == snapshot


def test_m10_every_reasoning_collection_not_mutated():
    request = _analyst_request()
    reasoning_snapshot = {field: copy.deepcopy(request[field]) for field in REASONING_FIELDS}

    _run_pipeline(request, _investigation_row(), _evidence_records())

    for field in REASONING_FIELDS:
        assert request[field] == reasoning_snapshot[field]


# ---------------------------------------------------------------------------
# Output independence
# ---------------------------------------------------------------------------

def test_o01_mutating_returned_context_evidence_summary_does_not_affect_original_row():
    request = _analyst_request()
    records = _evidence_records()
    records_snapshot = copy.deepcopy(records)

    result = _run_pipeline(request, _investigation_row(), records)
    result.context["supporting_evidence"][0]["trust_level"] = "mutated"

    assert records == records_snapshot


def test_o02_mutating_formatted_warning_does_not_affect_context_warning():
    request = _analyst_request()
    result = _run_pipeline(request, _investigation_row(), _evidence_records())
    context_warnings_snapshot = copy.deepcopy(result.context["warnings"])

    result.formatted_warnings[0]["code"] = "MUTATED"

    assert result.context["warnings"] == context_warnings_snapshot


def test_o03_mutating_analysis_reasoning_list_does_not_affect_analyst_request():
    request = _analyst_request()
    request_snapshot = copy.deepcopy(request)

    result = _run_pipeline(request, _investigation_row(), _evidence_records())
    result.analysis["evidence_gaps"].append("mutated entry")

    assert request == request_snapshot


def test_o04_fresh_pipeline_call_reproduces_equivalent_context_and_warning_output():
    request_a = _analyst_request()
    request_b = _analyst_request()

    result_a = _run_pipeline(request_a, _investigation_row(), _evidence_records())
    result_b = _run_pipeline(request_b, _investigation_row(), _evidence_records())

    assert result_a.context == result_b.context
    assert result_a.formatted_warnings == result_b.formatted_warnings


def test_o05_generated_at_may_differ_but_other_analysis_fields_match():
    request_a = _analyst_request()
    request_b = _analyst_request()

    result_a = _run_pipeline(request_a, _investigation_row(), _evidence_records())
    result_b = _run_pipeline(request_b, _investigation_row(), _evidence_records())

    analysis_a = dict(result_a.analysis)
    analysis_b = dict(result_b.analysis)
    del analysis_a["generated_at"]
    del analysis_b["generated_at"]

    assert analysis_a == analysis_b


# ---------------------------------------------------------------------------
# Runtime side-effect guard
# ---------------------------------------------------------------------------

def test_runtime_guard_full_pipeline_succeeds_with_forbidden_entry_points(monkeypatch):
    import os
    import sys
    import urllib.request

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a forbidden entry point was called during the decision-review pipeline")

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

    request = _analyst_request()
    result = _run_pipeline(request, _investigation_row(), _evidence_records())

    assert result.context_exit == 0
    assert result.warning_exit == 0
    assert result.analysis_exit == 0
    assert "mcp.hayabusa_server" not in sys.modules
    assert os.getcwd() == original_cwd
    assert dict(os.environ) == original_environ


# ---------------------------------------------------------------------------
# Static source-boundary checks
# ---------------------------------------------------------------------------

def _this_module_ast():
    import ast

    source = Path(__file__).read_text(encoding="utf-8")
    return ast.parse(source)


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


def _top_level_imported_module_names(tree):
    """Only imports at module scope -- excludes imports nested inside a
    function body, such as the runtime guard's conditional, try/except
    `import requests` / `import supabase` used purely to obtain a
    monkeypatch target when those optional packages happen to be
    installed (the same established pattern used by every other CLI's
    runtime-guard test in this project)."""
    import ast

    names = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
    return names


def test_static_module_does_not_import_supabase_or_requests_at_module_scope():
    tree = _this_module_ast()
    imported = _top_level_imported_module_names(tree)

    assert not any(name == "supabase" or name.startswith("supabase.") for name in imported)
    assert "requests" not in imported


def test_static_module_does_not_import_ai_model_libraries():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)

    for forbidden in ("openai", "anthropic"):
        assert forbidden not in imported


def test_static_module_imports_subprocess_only_for_monkeypatch_targets():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert "subprocess" in imported

    import ast

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "Popen", "call", "check_call", "check_output"):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    pytest.fail("subprocess call executed directly in the test module")


def test_static_module_does_not_write_repository_files_or_create_temp_files():
    import ast

    tree = _this_module_ast()
    imported = _imported_module_names(tree)

    assert "tempfile" not in imported
    assert "shutil" not in imported

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in ("write_text", "write_bytes", "unlink", "remove", "rename")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            positional_mode = node.args[1] if len(node.args) > 1 else None
            if isinstance(positional_mode, ast.Constant) and isinstance(positional_mode.value, str):
                assert "w" not in positional_mode.value
                assert "a" not in positional_mode.value


def test_static_module_does_not_invoke_a_slash_command():
    # AST-based (not raw substring search): a raw substring search would
    # trivially "find" these names inside this very test's own assertion
    # strings. Checking actual Call nodes avoids that self-referential
    # false positive.
    import ast

    tree = _this_module_ast()
    forbidden_call_names = {"SlashCommand", "run_slash_command", "invoke_slash_command"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in forbidden_call_names:
                pytest.fail(f"forbidden call found: {node.func.id}")
            if isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_call_names:
                pytest.fail(f"forbidden call found: {node.func.attr}")
