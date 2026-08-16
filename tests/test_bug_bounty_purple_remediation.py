"""Tests for core.bug_bounty_purple_remediation -- the bounded Purple
Team remediation recommendation boundary. Pure, no I/O anywhere in
this file."""

from __future__ import annotations

import pytest

from core.bug_bounty_purple_remediation import (
    RECOMMENDATION_VERSION,
    PurpleRemediationError,
    build_purple_remediation_recommendation,
)

_RESULT_FIELDS = {
    "recommendation_version", "finding_id", "recommendations", "based_on",
    "outcome", "human_review_required", "execution_performed",
}


def _finding(**overrides):
    finding = {"finding_id": "CF-1", "remediation": None, "detection_opportunity": None}
    finding.update(overrides)
    return finding


class TestContract:
    def test_001_result_has_exact_fields(self):
        result = build_purple_remediation_recommendation(
            canonical_finding=_finding(), ti_result=None, hunt_result=None,
            detection_result=None, red_validation_result=None,
        )
        assert set(result.keys()) == _RESULT_FIELDS

    def test_002_execution_performed_always_false(self):
        result = build_purple_remediation_recommendation(
            canonical_finding=_finding(), ti_result=None, hunt_result=None,
            detection_result=None, red_validation_result=None,
        )
        assert result["execution_performed"] is False

    def test_003_outcome_always_recommendation_created(self):
        result = build_purple_remediation_recommendation(
            canonical_finding=_finding(), ti_result=None, hunt_result=None,
            detection_result=None, red_validation_result=None,
        )
        assert result["outcome"] == "recommendation_created"

    def test_004_version_is_1(self):
        result = build_purple_remediation_recommendation(
            canonical_finding=_finding(), ti_result=None, hunt_result=None,
            detection_result=None, red_validation_result=None,
        )
        assert result["recommendation_version"] == RECOMMENDATION_VERSION == "1"

    def test_005_rejects_non_mapping(self):
        with pytest.raises(PurpleRemediationError):
            build_purple_remediation_recommendation(
                canonical_finding="not a finding", ti_result=None, hunt_result=None,
                detection_result=None, red_validation_result=None,
            )

    def test_006_never_claims_remediation_applied(self):
        # Regression guard: the outcome this module produces must never
        # be (or become) the literal string "applied" -- only a
        # recommendation was created, never remediation performed.
        result = build_purple_remediation_recommendation(
            canonical_finding=_finding(), ti_result=None, hunt_result=None,
            detection_result=None, red_validation_result=None,
        )
        assert result["outcome"] != "applied"
        assert result["outcome"] == "recommendation_created"


class TestRecommendationContent:
    def test_007_real_remediation_text_included_verbatim(self):
        result = build_purple_remediation_recommendation(
            canonical_finding=_finding(remediation="Add a CSP header with an appropriate policy."),
            ti_result=None, hunt_result=None, detection_result=None, red_validation_result=None,
        )
        assert "Add a CSP header with an appropriate policy." in result["recommendations"]

    def test_008_detection_opportunity_included_when_no_rule_generated(self):
        result = build_purple_remediation_recommendation(
            canonical_finding=_finding(detection_opportunity="Alert on missing header responses."),
            ti_result=None, hunt_result=None, detection_result={"outcome": "not_applicable"}, red_validation_result=None,
        )
        assert "Alert on missing header responses." in result["recommendations"]

    def test_009_detection_opportunity_omitted_when_rule_already_generated(self):
        result = build_purple_remediation_recommendation(
            canonical_finding=_finding(detection_opportunity="Alert on missing header responses."),
            ti_result=None, hunt_result=None, detection_result={"outcome": "candidate_ready"}, red_validation_result=None,
        )
        assert "Alert on missing header responses." not in result["recommendations"]

    def test_010_telemetry_gap_produces_instrumentation_recommendation(self):
        result = build_purple_remediation_recommendation(
            canonical_finding=_finding(), ti_result=None,
            hunt_result={"outcome": "telemetry_gap", "missing_telemetry": ["web_server"]},
            detection_result=None, red_validation_result=None,
        )
        assert any("web_server" in r for r in result["recommendations"])

    def test_011_red_unavailable_produces_manual_retest_recommendation(self):
        result = build_purple_remediation_recommendation(
            canonical_finding=_finding(), ti_result=None, hunt_result=None, detection_result=None,
            red_validation_result={"outcome": "controlled_validation_unavailable"},
        )
        assert any("manual retest" in r.lower() for r in result["recommendations"])

    def test_012_red_validated_does_not_trigger_manual_retest_text(self):
        result = build_purple_remediation_recommendation(
            canonical_finding=_finding(), ti_result=None, hunt_result=None, detection_result=None,
            red_validation_result={"outcome": "validated"},
        )
        assert not any("manual retest" in r.lower() for r in result["recommendations"])

    def test_013_never_empty_recommendations_list(self):
        result = build_purple_remediation_recommendation(
            canonical_finding=_finding(), ti_result=None, hunt_result=None, detection_result=None, red_validation_result=None,
        )
        assert len(result["recommendations"]) >= 1

    def test_014_based_on_reflects_real_upstream_availability(self):
        result = build_purple_remediation_recommendation(
            canonical_finding=_finding(), ti_result={"outcome": "no_relevant_intel"}, hunt_result=None,
            detection_result={"outcome": "not_applicable"}, red_validation_result=None,
        )
        assert result["based_on"] == {
            "ti_reviewed": True, "hunt_reviewed": False, "detection_reviewed": True, "red_validation_reviewed": False,
        }

    def test_015_never_derives_text_from_title_keywords(self):
        # Recommendations must come only from real remediation/
        # detection_opportunity fields or the fixed template strings --
        # never from inspecting the finding's title.
        result = build_purple_remediation_recommendation(
            canonical_finding=_finding(finding_id="CF-2"), ti_result=None, hunt_result=None,
            detection_result=None, red_validation_result=None,
        )
        assert "manual analyst review" in result["recommendations"][0].lower()
