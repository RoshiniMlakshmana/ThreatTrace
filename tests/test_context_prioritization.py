"""Tests for core.context_prioritization -- the pure, deterministic
organization-context operational prioritization layer (Block 15B,
checkpoint A).

No network, filesystem, environment-variable, subprocess, clock,
randomness, database/Supabase, MCP, or LLM/model access occurs anywhere
in this file. Every input is a plain in-memory mapping.
"""

from __future__ import annotations

import copy
import inspect

import pytest

import core.context_prioritization as context_prioritization
from core.context_prioritization import (
    ContextPrioritizationError,
    prioritize_finding,
)

# ---------------------------------------------------------------------------
# Fixtures. The default finding/context are chosen so every scoring
# dimension is at a neutral (zero-modifier) value -- individual tests
# then change exactly one field to observe its isolated contribution.
# ---------------------------------------------------------------------------


def _finding(**overrides):
    finding = {
        "finding_version": "1",
        "finding_id": "BB15A-0000000000000000",
        "target": "https://app.example.test/",
        "affected_path": "/",
        "affected_parameter": None,
        "title": "Example finding",
        "finding_status": "validated",
        "vulnerability_class": "security_header_misconfiguration",
        "owasp_category": "A05:2021 Security Misconfiguration",
        "cwe": "CWE-693",
        "technical_severity": "medium",
        "confidence": "high",
        "evidence": [{"evidence_version": "1"}],
        "validation": {"method": "deterministic_header_presence_check", "confirmed": True},
        "reproduction_summary": "Requested / and observed X.",
        "remediation": "Add the missing header.",
        "detection_opportunity": "Alert on missing header.",
        "human_approval_required": True,
        "assessment_performed": True,
        "network_requests_performed": 1,
        "execution_performed": False,
    }
    finding.update(overrides)
    return finding


def _context(**overrides):
    context = {
        "context_version": "1",
        "industry": "general",
        "environment": "staging",
        "asset_criticality": "medium",
        "exposure": "restricted",
        "data_sensitivity": "internal",
        "detection_coverage": "partial",
        "compensating_controls": "partial",
        "threat_activity": "emerging",
        "regulatory_relevance": "potential",
    }
    context.update(overrides)
    return context


def _reason_codes(result):
    return [reason["code"] for reason in result["priority_reasons"]]


# ---------------------------------------------------------------------------
# Context validation
# ---------------------------------------------------------------------------


class TestContextValidation:
    def test_001_exact_context_key_set_accepted(self):
        result = prioritize_finding(finding=_finding(), context=_context())
        assert set(result["context"].keys()) == {
            "context_version", "industry", "environment", "asset_criticality", "exposure",
            "data_sensitivity", "detection_coverage", "compensating_controls",
            "threat_activity", "regulatory_relevance",
        }

    @pytest.mark.parametrize("missing_key", [
        "context_version", "industry", "environment", "asset_criticality", "exposure",
        "data_sensitivity", "detection_coverage", "compensating_controls",
        "threat_activity", "regulatory_relevance",
    ])
    def test_002_missing_each_required_context_field_rejected(self, missing_key):
        context = _context()
        del context[missing_key]
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=context)

    def test_003_extra_context_field_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=_context(extra_field="not allowed"))

    def test_004_wrong_context_version_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=_context(context_version="2"))

    def test_005_context_not_a_mapping_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context="not a mapping")

    @pytest.mark.parametrize("industry", sorted(context_prioritization.INDUSTRIES))
    def test_006_each_valid_industry_accepted(self, industry):
        result = prioritize_finding(finding=_finding(), context=_context(industry=industry))
        assert result["context"]["industry"] == industry

    def test_007_unrecognized_industry_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=_context(industry="crypto_startup"))

    @pytest.mark.parametrize("environment", sorted(context_prioritization.ENVIRONMENTS))
    def test_008_each_valid_environment_accepted(self, environment):
        result = prioritize_finding(finding=_finding(), context=_context(environment=environment))
        assert result["context"]["environment"] == environment

    def test_009_unrecognized_environment_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=_context(environment="prod"))

    @pytest.mark.parametrize("value", sorted(context_prioritization.ASSET_CRITICALITIES))
    def test_010_each_valid_asset_criticality_accepted(self, value):
        result = prioritize_finding(finding=_finding(), context=_context(asset_criticality=value))
        assert result["context"]["asset_criticality"] == value

    def test_011_unrecognized_asset_criticality_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=_context(asset_criticality="extreme"))

    @pytest.mark.parametrize("value", sorted(context_prioritization.EXPOSURES))
    def test_012_each_valid_exposure_accepted(self, value):
        result = prioritize_finding(finding=_finding(), context=_context(exposure=value))
        assert result["context"]["exposure"] == value

    def test_013_unrecognized_exposure_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=_context(exposure="public_internet"))

    @pytest.mark.parametrize("value", sorted(context_prioritization.DATA_SENSITIVITIES))
    def test_014_each_valid_data_sensitivity_accepted(self, value):
        result = prioritize_finding(finding=_finding(), context=_context(data_sensitivity=value))
        assert result["context"]["data_sensitivity"] == value

    def test_015_unrecognized_data_sensitivity_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=_context(data_sensitivity="top_secret"))

    @pytest.mark.parametrize("value", sorted(context_prioritization.DETECTION_COVERAGES))
    def test_016_each_valid_detection_coverage_accepted(self, value):
        result = prioritize_finding(finding=_finding(), context=_context(detection_coverage=value))
        assert result["context"]["detection_coverage"] == value

    def test_017_unrecognized_detection_coverage_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=_context(detection_coverage="full"))

    @pytest.mark.parametrize("value", sorted(context_prioritization.COMPENSATING_CONTROLS_LEVELS))
    def test_018_each_valid_compensating_controls_accepted(self, value):
        result = prioritize_finding(finding=_finding(), context=_context(compensating_controls=value))
        assert result["context"]["compensating_controls"] == value

    def test_019_unrecognized_compensating_controls_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=_context(compensating_controls="waf_only"))

    @pytest.mark.parametrize("value", sorted(context_prioritization.THREAT_ACTIVITIES))
    def test_020_each_valid_threat_activity_accepted(self, value):
        result = prioritize_finding(finding=_finding(), context=_context(threat_activity=value))
        assert result["context"]["threat_activity"] == value

    def test_021_unrecognized_threat_activity_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=_context(threat_activity="imminent"))

    @pytest.mark.parametrize("value", sorted(context_prioritization.REGULATORY_RELEVANCES))
    def test_022_each_valid_regulatory_relevance_accepted(self, value):
        result = prioritize_finding(finding=_finding(), context=_context(regulatory_relevance=value))
        assert result["context"]["regulatory_relevance"] == value

    def test_023_unrecognized_regulatory_relevance_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=_context(regulatory_relevance="pci"))

    def test_024_wrong_type_for_context_field_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=_context(asset_criticality=4))

    def test_025_blank_string_context_field_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=_context(environment="   "))

    def test_026_context_values_not_trimmed(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=_context(environment=" production "))

    def test_027_context_values_not_lowercased(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(), context=_context(environment="PRODUCTION"))

    def test_028_deterministic_identical_output(self):
        first = prioritize_finding(finding=_finding(), context=_context())
        second = prioritize_finding(finding=_finding(), context=_context())
        assert first == second


# ---------------------------------------------------------------------------
# Finding validation
# ---------------------------------------------------------------------------


class TestFindingValidation:
    def test_029_valid_block_15a_shaped_finding_accepted(self):
        result = prioritize_finding(finding=_finding(), context=_context())
        assert result["finding_id"] == "BB15A-0000000000000000"

    def test_030_wrong_finding_version_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(finding_version="2"), context=_context())

    def test_031_missing_finding_id_rejected(self):
        finding = _finding()
        del finding["finding_id"]
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=finding, context=_context())

    def test_032_blank_finding_id_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(finding_id="   "), context=_context())

    def test_033_unsupported_finding_status_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(finding_status="confirmed_exploit"), context=_context())

    def test_034_unsupported_technical_severity_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(technical_severity="catastrophic"), context=_context())

    def test_035_unsupported_confidence_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=_finding(confidence="certain"), context=_context())

    @pytest.mark.parametrize("field", ["vulnerability_class", "evidence", "validation", "owasp_category", "cwe"])
    def test_036_required_truth_bearing_fields_missing_rejected(self, field):
        finding = _finding()
        del finding[field]
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=finding, context=_context())

    def test_037_malformed_top_level_finding_type_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=["not", "a", "mapping"], context=_context())

    def test_038_none_finding_rejected(self):
        with pytest.raises(ContextPrioritizationError):
            prioritize_finding(finding=None, context=_context())

    def test_039_owasp_category_and_cwe_may_be_none_and_still_present(self):
        finding = _finding(owasp_category=None, cwe=None)
        result = prioritize_finding(finding=finding, context=_context())
        assert result["finding_id"] == finding["finding_id"]


# ---------------------------------------------------------------------------
# Score tests -- one weight at a time
# ---------------------------------------------------------------------------


class TestIndividualScoreWeights:
    def test_040_neutral_baseline_has_zero_raw_modifier(self):
        result = prioritize_finding(finding=_finding(), context=_context())
        assert result["priority_score"]["raw_modifier"] == 0
        assert result["priority_score"]["applied_modifier"] == 0
        assert result["priority_score"]["final"] == result["priority_score"]["base"]

    def test_041_production_environment_plus_one(self):
        result = prioritize_finding(finding=_finding(), context=_context(environment="production"))
        assert result["priority_score"]["raw_modifier"] == 1
        assert "PRODUCTION_ENVIRONMENT" in _reason_codes(result)

    @pytest.mark.parametrize("environment", ["development", "test", "sandbox"])
    def test_042_isolated_environments_minus_one(self, environment):
        result = prioritize_finding(finding=_finding(), context=_context(environment=environment))
        assert result["priority_score"]["raw_modifier"] == -1
        assert "ISOLATED_ENVIRONMENT" in _reason_codes(result)

    def test_043_staging_environment_neutral(self):
        result = prioritize_finding(finding=_finding(), context=_context(environment="staging"))
        assert result["priority_score"]["raw_modifier"] == 0
        assert "PRODUCTION_ENVIRONMENT" not in _reason_codes(result)
        assert "ISOLATED_ENVIRONMENT" not in _reason_codes(result)

    def test_044_critical_asset_plus_one(self):
        result = prioritize_finding(finding=_finding(), context=_context(asset_criticality="critical"))
        assert result["priority_score"]["raw_modifier"] == 1
        assert "CRITICAL_ASSET" in _reason_codes(result)

    def test_045_low_asset_criticality_minus_one(self):
        result = prioritize_finding(finding=_finding(), context=_context(asset_criticality="low"))
        assert result["priority_score"]["raw_modifier"] == -1
        assert "LOW_CRITICALITY_ASSET" in _reason_codes(result)

    @pytest.mark.parametrize("value", ["medium", "high"])
    def test_046_medium_and_high_asset_criticality_neutral(self, value):
        result = prioritize_finding(finding=_finding(), context=_context(asset_criticality=value))
        assert result["priority_score"]["raw_modifier"] == 0

    def test_047_internet_facing_exposure_plus_one(self):
        result = prioritize_finding(finding=_finding(), context=_context(exposure="internet_facing"))
        assert result["priority_score"]["raw_modifier"] == 1
        assert "INTERNET_EXPOSED" in _reason_codes(result)

    @pytest.mark.parametrize("value", ["internal", "restricted", "partner"])
    def test_048_other_exposures_neutral(self, value):
        result = prioritize_finding(finding=_finding(), context=_context(exposure=value))
        assert result["priority_score"]["raw_modifier"] == 0

    @pytest.mark.parametrize("value", ["confidential", "restricted"])
    def test_049_sensitive_data_plus_one(self, value):
        result = prioritize_finding(finding=_finding(), context=_context(data_sensitivity=value))
        assert result["priority_score"]["raw_modifier"] == 1
        assert "SENSITIVE_DATA" in _reason_codes(result)

    @pytest.mark.parametrize("value", ["public", "internal"])
    def test_050_non_sensitive_data_neutral(self, value):
        result = prioritize_finding(finding=_finding(), context=_context(data_sensitivity=value))
        assert result["priority_score"]["raw_modifier"] == 0

    def test_051_no_detection_coverage_plus_one(self):
        result = prioritize_finding(finding=_finding(), context=_context(detection_coverage="none"))
        assert result["priority_score"]["raw_modifier"] == 1
        assert "NO_DETECTION_COVERAGE" in _reason_codes(result)

    def test_052_strong_detection_coverage_never_lowers_priority(self):
        result = prioritize_finding(finding=_finding(), context=_context(detection_coverage="strong"))
        assert result["priority_score"]["raw_modifier"] == 0

    def test_053_strong_compensating_controls_minus_one(self):
        result = prioritize_finding(finding=_finding(), context=_context(compensating_controls="strong"))
        assert result["priority_score"]["raw_modifier"] == -1
        assert "STRONG_COMPENSATING_CONTROLS" in _reason_codes(result)

    @pytest.mark.parametrize("value", ["none", "partial"])
    def test_054_non_strong_compensating_controls_neutral(self, value):
        result = prioritize_finding(finding=_finding(), context=_context(compensating_controls=value))
        assert result["priority_score"]["raw_modifier"] == 0

    def test_055_active_threat_activity_plus_one(self):
        result = prioritize_finding(finding=_finding(), context=_context(threat_activity="active"))
        assert result["priority_score"]["raw_modifier"] == 1
        assert "ACTIVE_THREAT_ACTIVITY" in _reason_codes(result)

    def test_056_none_observed_threat_activity_never_lowers_priority(self):
        result = prioritize_finding(finding=_finding(), context=_context(threat_activity="none_observed"))
        assert result["priority_score"]["raw_modifier"] == 0

    def test_057_direct_regulatory_relevance_plus_one(self):
        result = prioritize_finding(finding=_finding(), context=_context(regulatory_relevance="direct"))
        assert result["priority_score"]["raw_modifier"] == 1
        assert "DIRECT_REGULATORY_RELEVANCE" in _reason_codes(result)

    @pytest.mark.parametrize("value", ["none", "potential"])
    def test_058_non_direct_regulatory_relevance_neutral(self, value):
        result = prioritize_finding(finding=_finding(), context=_context(regulatory_relevance=value))
        assert result["priority_score"]["raw_modifier"] == 0

    def test_059_candidate_finding_status_minus_one(self):
        result = prioritize_finding(finding=_finding(finding_status="candidate"), context=_context())
        assert result["priority_score"]["raw_modifier"] == -1
        assert "CANDIDATE_FINDING" in _reason_codes(result)

    def test_060_observation_finding_status_minus_two(self):
        result = prioritize_finding(finding=_finding(finding_status="observation"), context=_context())
        assert result["priority_score"]["raw_modifier"] == -2
        assert "OBSERVATION_FINDING" in _reason_codes(result)

    def test_061_validated_finding_status_neutral(self):
        result = prioritize_finding(finding=_finding(finding_status="validated"), context=_context())
        assert result["priority_score"]["raw_modifier"] == 0
        assert "VALIDATED_FINDING" in _reason_codes(result)

    def test_062_low_confidence_minus_one(self):
        result = prioritize_finding(finding=_finding(confidence="low"), context=_context())
        assert result["priority_score"]["raw_modifier"] == -1
        assert "LOW_CONFIDENCE" in _reason_codes(result)

    @pytest.mark.parametrize("value", ["medium", "high"])
    def test_063_medium_and_high_confidence_neutral(self, value):
        result = prioritize_finding(finding=_finding(confidence=value), context=_context())
        assert result["priority_score"]["raw_modifier"] == 0

    @pytest.mark.parametrize("industry", sorted(context_prioritization.INDUSTRIES))
    def test_064_industry_always_contributes_zero(self, industry):
        result = prioritize_finding(finding=_finding(), context=_context(industry=industry))
        assert result["priority_score"]["raw_modifier"] == 0


# ---------------------------------------------------------------------------
# Clamp tests
# ---------------------------------------------------------------------------


class TestClampBehavior:
    def _worst_context(self):
        return _context(
            environment="sandbox", asset_criticality="low", exposure="internal",
            data_sensitivity="public", detection_coverage="strong", compensating_controls="strong",
            threat_activity="none_observed", regulatory_relevance="none",
        )

    def _best_context(self):
        return _context(
            environment="production", asset_criticality="critical", exposure="internet_facing",
            data_sensitivity="restricted", detection_coverage="none", compensating_controls="none",
            threat_activity="active", regulatory_relevance="direct",
        )

    def test_065_many_raising_conditions_applied_modifier_never_exceeds_two(self):
        result = prioritize_finding(finding=_finding(finding_status="validated"), context=self._best_context())
        assert result["priority_score"]["applied_modifier"] == 2
        assert result["priority_score"]["raw_modifier"] > 2

    def test_066_many_lowering_conditions_applied_modifier_never_below_minus_one(self):
        result = prioritize_finding(finding=_finding(finding_status="observation"), context=self._worst_context())
        assert result["priority_score"]["applied_modifier"] == -1
        assert result["priority_score"]["raw_modifier"] < -1

    def test_067_critical_technical_finding_never_below_high(self):
        result = prioritize_finding(
            finding=_finding(technical_severity="critical", finding_status="observation"),
            context=self._worst_context(),
        )
        assert result["priority_score"]["final"] >= 3
        assert result["operational_priority"] in ("high", "critical")

    def test_068_low_technical_finding_never_above_high(self):
        result = prioritize_finding(
            finding=_finding(technical_severity="low", finding_status="validated"),
            context=self._best_context(),
        )
        assert result["priority_score"]["final"] <= 3
        assert result["operational_priority"] in ("low", "medium", "high")

    @pytest.mark.parametrize("severity", sorted(context_prioritization.TECHNICAL_SEVERITIES))
    def test_069_final_score_always_in_range(self, severity):
        for ctx in (self._worst_context(), self._best_context(), _context()):
            result = prioritize_finding(finding=_finding(technical_severity=severity), context=ctx)
            assert 1 <= result["priority_score"]["final"] <= 4


# ---------------------------------------------------------------------------
# Same finding / different context (exact worked scenarios)
# ---------------------------------------------------------------------------


class TestSameFindingDifferentContext:
    def _scenario_finding(self):
        return _finding(finding_status="validated", technical_severity="medium", confidence="high")

    def test_070_scenario_a_raised_to_critical(self):
        finding = self._scenario_finding()
        context = _context(
            environment="production", asset_criticality="critical", exposure="internet_facing",
            data_sensitivity="restricted", detection_coverage="none", compensating_controls="none",
            threat_activity="active", regulatory_relevance="direct",
        )
        result = prioritize_finding(finding=finding, context=context)
        assert result["priority_score"] == {"base": 2, "raw_modifier": 7, "applied_modifier": 2, "final": 4}
        assert result["operational_priority"] == "critical"
        assert result["priority_direction"] == "raised"

    def test_071_scenario_b_lowered_to_low(self):
        finding = self._scenario_finding()
        context = _context(
            environment="development", asset_criticality="low", exposure="internal",
            data_sensitivity="public", detection_coverage="strong", compensating_controls="strong",
            threat_activity="none_observed", regulatory_relevance="none",
        )
        result = prioritize_finding(finding=finding, context=context)
        assert result["priority_score"] == {"base": 2, "raw_modifier": -3, "applied_modifier": -1, "final": 1}
        assert result["operational_priority"] == "low"
        assert result["priority_direction"] == "lowered"

    def test_072_scenario_c_industry_never_changes_result(self):
        finding = self._scenario_finding()
        shared_context_fields = dict(
            environment="production", asset_criticality="high", exposure="partner",
            data_sensitivity="confidential", detection_coverage="partial", compensating_controls="none",
            threat_activity="emerging", regulatory_relevance="potential",
        )
        financial_result = prioritize_finding(
            finding=finding, context=_context(industry="financial_services", **shared_context_fields)
        )
        general_result = prioritize_finding(
            finding=finding, context=_context(industry="general", **shared_context_fields)
        )
        assert financial_result["priority_score"] == general_result["priority_score"]
        assert financial_result["operational_priority"] == general_result["operational_priority"]

    def test_073_same_input_deterministic_repeat(self):
        finding = self._scenario_finding()
        context = _context(environment="production")
        first = prioritize_finding(finding=finding, context=context)
        second = prioritize_finding(finding=finding, context=context)
        assert first == second


# ---------------------------------------------------------------------------
# Candidate vs. validated
# ---------------------------------------------------------------------------


class TestCandidateVersusValidated:
    def _high_context(self):
        return _context(
            environment="production", asset_criticality="critical", exposure="internet_facing",
            data_sensitivity="restricted", detection_coverage="none", compensating_controls="none",
            threat_activity="active", regulatory_relevance="direct",
        )

    def test_074_candidate_finding_status_remains_candidate(self):
        result = prioritize_finding(
            finding=_finding(finding_status="candidate", technical_severity="medium"),
            context=self._high_context(),
        )
        assert result["finding_status"] == "candidate"

    def test_075_validated_finding_status_remains_validated(self):
        result = prioritize_finding(
            finding=_finding(finding_status="validated", technical_severity="medium"),
            context=self._high_context(),
        )
        assert result["finding_status"] == "validated"

    def test_076_candidate_penalty_appears_as_minus_one(self):
        result = prioritize_finding(
            finding=_finding(finding_status="candidate", technical_severity="medium"),
            context=self._high_context(),
        )
        reasons_by_code = {r["code"]: r["modifier"] for r in result["priority_reasons"]}
        assert reasons_by_code["CANDIDATE_FINDING"] == -1

    def test_077_high_context_candidate_can_reach_critical_operational_priority(self):
        result = prioritize_finding(
            finding=_finding(finding_status="candidate", technical_severity="medium"),
            context=self._high_context(),
        )
        assert result["operational_priority"] == "critical"
        assert result["finding_status"] == "candidate"

    def test_078_candidate_and_validated_differ_only_by_the_status_modifier(self):
        candidate_result = prioritize_finding(
            finding=_finding(finding_status="candidate", technical_severity="medium"),
            context=self._high_context(),
        )
        validated_result = prioritize_finding(
            finding=_finding(finding_status="validated", technical_severity="medium"),
            context=self._high_context(),
        )
        assert (
            validated_result["priority_score"]["raw_modifier"]
            - candidate_result["priority_score"]["raw_modifier"]
        ) == 1


# ---------------------------------------------------------------------------
# Observation
# ---------------------------------------------------------------------------


class TestObservation:
    def test_079_observation_receives_minus_two_nominal_modifier(self):
        result = prioritize_finding(finding=_finding(finding_status="observation"), context=_context())
        reasons_by_code = {r["code"]: r["modifier"] for r in result["priority_reasons"]}
        assert reasons_by_code["OBSERVATION_FINDING"] == -2

    def test_080_observation_clamp_floor_still_minus_one_overall(self):
        result = prioritize_finding(
            finding=_finding(finding_status="observation", technical_severity="high"),
            context=_context(),
        )
        assert result["priority_score"]["applied_modifier"] == -1

    def test_081_observation_reduces_at_most_one_band(self):
        result = prioritize_finding(
            finding=_finding(finding_status="observation", technical_severity="high"),
            context=_context(),
        )
        assert result["priority_score"]["final"] == result["priority_score"]["base"] - 1

    def test_082_observation_finding_status_never_mutated_to_candidate(self):
        finding = _finding(finding_status="observation")
        prioritize_finding(finding=finding, context=_context())
        assert finding["finding_status"] == "observation"


# ---------------------------------------------------------------------------
# Unknown context
# ---------------------------------------------------------------------------


class TestUnknownContext:
    @pytest.mark.parametrize("field", ["detection_coverage", "compensating_controls", "threat_activity", "regulatory_relevance"])
    def test_083_each_unknown_capable_field_contributes_zero(self, field):
        result = prioritize_finding(finding=_finding(), context=_context(**{field: "unknown"}))
        assert result["priority_score"]["raw_modifier"] == 0

    @pytest.mark.parametrize("field", ["detection_coverage", "compensating_controls", "threat_activity", "regulatory_relevance"])
    def test_084_unknown_value_preserved_in_output_context(self, field):
        result = prioritize_finding(finding=_finding(), context=_context(**{field: "unknown"}))
        assert result["context"][field] == "unknown"

    @pytest.mark.parametrize("field", ["detection_coverage", "compensating_controls", "threat_activity", "regulatory_relevance"])
    def test_085_single_unknown_field_marks_incomplete(self, field):
        result = prioritize_finding(finding=_finding(), context=_context(**{field: "unknown"}))
        assert result["context_completeness"] == "incomplete"
        assert "CONTEXT_INCOMPLETE" in _reason_codes(result)

    def test_086_no_unknown_fields_marks_complete(self):
        result = prioritize_finding(finding=_finding(), context=_context())
        assert result["context_completeness"] == "complete"
        assert "CONTEXT_INCOMPLETE" not in _reason_codes(result)

    def test_087_multiple_unknowns_produce_exactly_one_context_incomplete(self):
        context = _context(
            detection_coverage="unknown", compensating_controls="unknown",
            threat_activity="unknown", regulatory_relevance="unknown",
        )
        result = prioritize_finding(finding=_finding(), context=context)
        assert _reason_codes(result).count("CONTEXT_INCOMPLETE") == 1

    def test_088_all_unknowns_still_zero_raw_modifier_from_those_fields(self):
        context = _context(
            detection_coverage="unknown", compensating_controls="unknown",
            threat_activity="unknown", regulatory_relevance="unknown",
        )
        result = prioritize_finding(finding=_finding(), context=context)
        assert result["priority_score"]["raw_modifier"] == 0

    def test_089_unknown_detection_coverage_not_treated_as_strong(self):
        unknown_result = prioritize_finding(finding=_finding(), context=_context(detection_coverage="unknown"))
        strong_result = prioritize_finding(finding=_finding(), context=_context(detection_coverage="strong"))
        assert unknown_result["priority_score"]["raw_modifier"] == strong_result["priority_score"]["raw_modifier"]
        assert unknown_result["context_completeness"] != strong_result["context_completeness"]

    def test_090_unknown_threat_activity_not_treated_as_none_observed_favorably(self):
        result = prioritize_finding(finding=_finding(), context=_context(threat_activity="unknown"))
        assert "ACTIVE_THREAT_ACTIVITY" not in _reason_codes(result)
        assert result["priority_score"]["raw_modifier"] == 0

    def test_091_unknown_regulatory_relevance_not_treated_as_none(self):
        unknown_result = prioritize_finding(finding=_finding(), context=_context(regulatory_relevance="unknown"))
        none_result = prioritize_finding(finding=_finding(), context=_context(regulatory_relevance="none"))
        assert unknown_result["context_completeness"] == "incomplete"
        assert none_result["context_completeness"] == "complete"


# ---------------------------------------------------------------------------
# Reason tests
# ---------------------------------------------------------------------------


class TestReasons:
    def test_092_reason_object_exact_key_set(self):
        result = prioritize_finding(finding=_finding(), context=_context(environment="production"))
        for reason in result["priority_reasons"]:
            assert set(reason.keys()) == {"code", "modifier", "message"}

    def test_093_reason_order_is_fixed(self):
        finding = _finding(finding_status="candidate", confidence="low")
        context = _context(
            environment="production", asset_criticality="critical", exposure="internet_facing",
            data_sensitivity="restricted", detection_coverage="none", compensating_controls="strong",
            threat_activity="active", regulatory_relevance="direct",
        )
        result = prioritize_finding(finding=finding, context=context)
        codes = _reason_codes(result)
        expected_order = [
            "CANDIDATE_FINDING", "LOW_CONFIDENCE", "PRODUCTION_ENVIRONMENT", "CRITICAL_ASSET",
            "INTERNET_EXPOSED", "SENSITIVE_DATA", "NO_DETECTION_COVERAGE", "STRONG_COMPENSATING_CONTROLS",
            "ACTIVE_THREAT_ACTIVITY", "DIRECT_REGULATORY_RELEVANCE",
        ]
        assert codes == expected_order

    def test_094_fixed_messages_are_deterministic_strings(self):
        result_1 = prioritize_finding(finding=_finding(), context=_context(environment="production"))
        result_2 = prioritize_finding(finding=_finding(), context=_context(environment="production"))
        assert result_1["priority_reasons"] == result_2["priority_reasons"]

    def test_095_no_duplicate_codes(self):
        result = prioritize_finding(
            finding=_finding(finding_status="observation"),
            context=_context(environment="production", detection_coverage="unknown"),
        )
        codes = _reason_codes(result)
        assert len(codes) == len(set(codes))

    def test_096_no_untriggered_codes_present(self):
        # The neutral baseline finding is "validated," which itself always
        # triggers VALIDATED_FINDING (modifier 0) -- no *other* code should
        # ever appear given an otherwise fully neutral context.
        result = prioritize_finding(finding=_finding(), context=_context())
        assert result["priority_reasons"] == [
            {
                "code": "VALIDATED_FINDING",
                "modifier": 0,
                "message": "The finding has been deterministically validated within its implemented check.",
            }
        ]

    def test_097_raw_modifier_equals_sum_of_scoring_reason_modifiers(self):
        finding = _finding(finding_status="candidate", confidence="low")
        context = _context(environment="production", asset_criticality="critical", detection_coverage="unknown")
        result = prioritize_finding(finding=finding, context=context)
        assert result["priority_score"]["raw_modifier"] == sum(r["modifier"] for r in result["priority_reasons"])

    def test_098_context_incomplete_excluded_from_numeric_effect(self):
        result = prioritize_finding(finding=_finding(), context=_context(threat_activity="unknown"))
        reasons_by_code = {r["code"]: r["modifier"] for r in result["priority_reasons"]}
        assert reasons_by_code["CONTEXT_INCOMPLETE"] == 0

    def test_099_validated_finding_reason_is_zero(self):
        result = prioritize_finding(finding=_finding(finding_status="validated"), context=_context())
        reasons_by_code = {r["code"]: r["modifier"] for r in result["priority_reasons"]}
        assert reasons_by_code["VALIDATED_FINDING"] == 0

    def test_100_exactly_fifteen_codes_in_fixed_vocabulary(self):
        assert len(context_prioritization._REASON_ORDER) == 15
        assert set(context_prioritization._REASON_ORDER) == set(context_prioritization._REASON_MODIFIER)


# ---------------------------------------------------------------------------
# Priority score invariants
# ---------------------------------------------------------------------------


class TestPriorityScoreInvariants:
    @pytest.mark.parametrize("severity,expected_base", [
        ("low", 1), ("medium", 2), ("high", 3), ("critical", 4),
    ])
    def test_101_base_determined_only_by_technical_severity(self, severity, expected_base):
        result = prioritize_finding(finding=_finding(technical_severity=severity), context=_context())
        assert result["priority_score"]["base"] == expected_base

    def test_102_applied_modifier_equals_clamped_raw_modifier(self):
        finding = _finding(finding_status="candidate")
        context = _context(environment="production", asset_criticality="critical", exposure="internet_facing")
        result = prioritize_finding(finding=finding, context=context)
        raw = result["priority_score"]["raw_modifier"]
        assert result["priority_score"]["applied_modifier"] == max(-1, min(2, raw))

    def test_103_final_equals_clamped_base_plus_applied_modifier(self):
        finding = _finding(technical_severity="high", finding_status="candidate")
        context = _context(compensating_controls="strong")
        result = prioritize_finding(finding=finding, context=context)
        base = result["priority_score"]["base"]
        applied = result["priority_score"]["applied_modifier"]
        assert result["priority_score"]["final"] == max(1, min(4, base + applied))

    @pytest.mark.parametrize("final,expected_priority", [
        (1, "low"), (2, "medium"), (3, "high"), (4, "critical"),
    ])
    def test_104_operational_priority_maps_exactly_from_final(self, final, expected_priority):
        assert context_prioritization._ORDINAL_PRIORITY[final] == expected_priority

    def test_105_priority_direction_raised_when_final_greater_than_base(self):
        result = prioritize_finding(finding=_finding(technical_severity="low"), context=_context(environment="production"))
        assert result["priority_direction"] == "raised"

    def test_106_priority_direction_lowered_when_final_less_than_base(self):
        result = prioritize_finding(
            finding=_finding(technical_severity="high", finding_status="observation"), context=_context(),
        )
        assert result["priority_direction"] == "lowered"

    def test_107_priority_direction_unchanged_when_final_equals_base(self):
        result = prioritize_finding(finding=_finding(), context=_context())
        assert result["priority_direction"] == "unchanged"


# ---------------------------------------------------------------------------
# Technical truth preservation
# ---------------------------------------------------------------------------


class TestTechnicalTruthPreservation:
    def test_108_finding_status_unchanged_after_call(self):
        finding = _finding(finding_status="candidate")
        snapshot = copy.deepcopy(finding)
        prioritize_finding(finding=finding, context=_context())
        assert finding["finding_status"] == snapshot["finding_status"]

    def test_109_technical_severity_unchanged_after_call(self):
        finding = _finding(technical_severity="high")
        snapshot = copy.deepcopy(finding)
        prioritize_finding(finding=finding, context=_context())
        assert finding["technical_severity"] == snapshot["technical_severity"]

    def test_110_confidence_unchanged_after_call(self):
        finding = _finding(confidence="low")
        snapshot = copy.deepcopy(finding)
        prioritize_finding(finding=finding, context=_context())
        assert finding["confidence"] == snapshot["confidence"]

    def test_111_vulnerability_class_unchanged_after_call(self):
        finding = _finding()
        snapshot = copy.deepcopy(finding)
        prioritize_finding(finding=finding, context=_context())
        assert finding["vulnerability_class"] == snapshot["vulnerability_class"]

    def test_112_evidence_unchanged_after_call(self):
        finding = _finding()
        snapshot = copy.deepcopy(finding)
        prioritize_finding(finding=finding, context=_context())
        assert finding["evidence"] == snapshot["evidence"]

    def test_113_owasp_category_unchanged_after_call(self):
        finding = _finding()
        snapshot = copy.deepcopy(finding)
        prioritize_finding(finding=finding, context=_context())
        assert finding["owasp_category"] == snapshot["owasp_category"]

    def test_114_cwe_unchanged_after_call(self):
        finding = _finding()
        snapshot = copy.deepcopy(finding)
        prioritize_finding(finding=finding, context=_context())
        assert finding["cwe"] == snapshot["cwe"]

    def test_115_validation_unchanged_after_call(self):
        finding = _finding()
        snapshot = copy.deepcopy(finding)
        prioritize_finding(finding=finding, context=_context())
        assert finding["validation"] == snapshot["validation"]

    def test_116_full_finding_deep_equality_preserved(self):
        finding = _finding()
        snapshot = copy.deepcopy(finding)
        prioritize_finding(finding=finding, context=_context())
        assert finding == snapshot

    def test_117_result_does_not_reproduce_entire_finding(self):
        result = prioritize_finding(finding=_finding(), context=_context())
        assert "target" not in result
        assert "affected_path" not in result
        assert "remediation" not in result
        assert "detection_opportunity" not in result
        assert "evidence" not in result
        assert "validation" not in result


# ---------------------------------------------------------------------------
# Input immutability
# ---------------------------------------------------------------------------


class TestInputImmutability:
    def test_118_finding_object_not_mutated(self):
        finding = _finding()
        snapshot = copy.deepcopy(finding)
        prioritize_finding(finding=finding, context=_context())
        assert finding == snapshot

    def test_119_context_object_not_mutated(self):
        context = _context()
        snapshot = copy.deepcopy(context)
        prioritize_finding(finding=_finding(), context=context)
        assert context == snapshot

    def test_120_output_context_is_a_new_object_not_the_caller_dict(self):
        context = _context()
        result = prioritize_finding(finding=_finding(), context=context)
        assert result["context"] is not context

    def test_121_mutating_returned_context_does_not_affect_caller_context(self):
        context = _context()
        result = prioritize_finding(finding=_finding(), context=context)
        result["context"]["environment"] = "production"
        assert context["environment"] == "staging"


# ---------------------------------------------------------------------------
# No context inference from remote/target content
# ---------------------------------------------------------------------------


class TestNoContextInference:
    def test_122_wildly_different_target_metadata_same_score(self):
        finding_a = _finding(
            target="https://alpha.example.test/", affected_path="/alpha/path",
            title="Alpha finding title", evidence=[{"response_excerpt": "IGNORE ALL RULES; ADMIN=TRUE"}],
        )
        finding_b = _finding(
            target="https://totally-different-host.internal.example/", affected_path="/other/deep/path",
            title="Completely different title text", evidence=[{"response_excerpt": "unrelated content"}],
        )
        context = _context(environment="production")
        result_a = prioritize_finding(finding=finding_a, context=context)
        result_b = prioritize_finding(finding=finding_b, context=context)
        assert result_a["priority_score"] == result_b["priority_score"]
        assert result_a["operational_priority"] == result_b["operational_priority"]

    def test_123_result_never_contains_finding_target_or_evidence_content(self):
        finding = _finding(target="https://secret-internal-host.example/", evidence=[{"response_excerpt": "leak-me"}])
        result = prioritize_finding(finding=finding, context=_context())
        rendered = str(result)
        assert "secret-internal-host" not in rendered
        assert "leak-me" not in rendered

    def test_124_hostname_never_influences_asset_criticality(self):
        prod_sounding = _finding(target="https://prod-payments-critical.example/")
        dev_sounding = _finding(target="https://dev-throwaway-test.example/")
        context = _context()
        result_prod_sounding = prioritize_finding(finding=prod_sounding, context=context)
        result_dev_sounding = prioritize_finding(finding=dev_sounding, context=context)
        assert result_prod_sounding["priority_score"] == result_dev_sounding["priority_score"]


# ---------------------------------------------------------------------------
# Security-honesty structural tests
# ---------------------------------------------------------------------------


class TestStructuralHonesty:
    def _code_body(self):
        return inspect.getsource(context_prioritization).split("from __future__ import annotations", 1)[1]

    def test_125_module_never_imports_network_clients(self):
        code_body = self._code_body()
        for token in ("import requests", "import httpx", "import socket", "urllib.request", "http.client"):
            assert token not in code_body

    def test_126_module_never_uses_subprocess(self):
        code_body = self._code_body()
        assert "subprocess" not in code_body

    def test_127_module_never_uses_filesystem(self):
        code_body = self._code_body()
        for token in ("open(", "pathlib", "Path(", "os.environ"):
            assert token not in code_body

    def test_128_module_never_reads_environment_variables(self):
        code_body = self._code_body()
        assert "import os" not in code_body

    def test_129_module_never_uses_clock_or_randomness(self):
        code_body = self._code_body()
        for token in ("datetime.now", "utcnow", "import random", "import time", "import uuid"):
            assert token not in code_body

    def test_130_module_never_uses_database_supabase_or_mcp(self):
        code_body = self._code_body()
        for token in ("supabase", "mcp__", "execute_sql"):
            assert token not in code_body

    def test_131_module_never_invokes_llm_or_model(self):
        code_body = self._code_body()
        for token in ("openai", "anthropic", "model.generate", "llm"):
            assert token.lower() not in code_body.lower()

    def test_132_module_never_imports_bug_bounty_assessment_or_adapter(self):
        code_body = self._code_body()
        assert "bug_bounty_assessment" not in code_body
        assert "bug_bounty_http" not in code_body
        assert "import adapters" not in code_body

    def test_133_module_never_imports_bug_bounty_findings(self):
        code_body = self._code_body()
        assert "import core.bug_bounty_findings" not in code_body
        assert "from core.bug_bounty_findings" not in code_body

    def test_134_public_symbols_are_exactly_expected(self):
        public_functions = sorted(
            name for name in vars(context_prioritization)
            if not name.startswith("_")
            and inspect.isfunction(getattr(context_prioritization, name))
            and getattr(getattr(context_prioritization, name), "__module__", None) == context_prioritization.__name__
        )
        assert public_functions == ["prioritize_finding"]

    def test_135_error_is_a_value_error(self):
        assert issubclass(ContextPrioritizationError, ValueError)

    def test_136_human_review_required_always_true(self):
        result = prioritize_finding(finding=_finding(), context=_context())
        assert result["human_review_required"] is True

    def test_137_execution_performed_always_false(self):
        result = prioritize_finding(finding=_finding(), context=_context())
        assert result["execution_performed"] is False

    def test_138_result_contains_no_cvss_or_ai_score_language(self):
        result = prioritize_finding(finding=_finding(), context=_context())
        rendered = str(result).lower()
        for forbidden in ("cvss", "ai risk score", "probability of compromise", "compliance verdict"):
            assert forbidden not in rendered

    def test_139_exact_thirteen_top_level_result_fields(self):
        result = prioritize_finding(finding=_finding(), context=_context())
        assert set(result.keys()) == {
            "prioritization_version", "finding_id", "technical_severity", "finding_status", "confidence",
            "context", "priority_score", "operational_priority", "priority_direction",
            "priority_reasons", "context_completeness", "human_review_required", "execution_performed",
        }


# ---------------------------------------------------------------------------
# Research-useful preservation
# ---------------------------------------------------------------------------


class TestResearchUsefulPreservation:
    def test_140_base_and_final_both_present_for_ablation(self):
        result = prioritize_finding(finding=_finding(), context=_context(environment="production"))
        assert "base" in result["priority_score"]
        assert "final" in result["priority_score"]

    def test_141_different_context_changes_raw_and_applied_and_final(self):
        finding = _finding()
        neutral_result = prioritize_finding(finding=finding, context=_context())
        raised_result = prioritize_finding(
            finding=finding,
            context=_context(environment="production", asset_criticality="critical", exposure="internet_facing"),
        )
        assert raised_result["priority_score"]["raw_modifier"] != neutral_result["priority_score"]["raw_modifier"]
        assert raised_result["priority_score"]["final"] != neutral_result["priority_score"]["final"]
        assert raised_result["priority_direction"] != neutral_result["priority_direction"]

    def test_142_technical_truth_fields_unchanged_across_different_contexts(self):
        finding = _finding()
        result_neutral = prioritize_finding(finding=finding, context=_context())
        result_raised = prioritize_finding(
            finding=finding, context=_context(environment="production", asset_criticality="critical"),
        )
        assert result_neutral["technical_severity"] == result_raised["technical_severity"]
        assert result_neutral["finding_status"] == result_raised["finding_status"]
        assert result_neutral["confidence"] == result_raised["confidence"]
