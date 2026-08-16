"""Tests for core.bug_bounty_threat_hunt_review -- the bounded Threat
Hunt feasibility boundary. Reuses the real, unmodified
core.detection_telemetry.evaluate_telemetry_feasibility -- no I/O
anywhere in this file."""

from __future__ import annotations

import pytest

from core.bug_bounty_threat_hunt_review import (
    OUTCOMES,
    REVIEW_VERSION,
    ThreatHuntReviewError,
    review_threat_hunt_for_finding,
)

_RESULT_FIELDS = {
    "review_version", "finding_id", "hunt_hypothesis", "required_telemetry", "available_telemetry",
    "missing_telemetry", "outcome", "stage_evaluated", "human_review_required", "execution_performed",
}


def _finding(**overrides):
    finding = {"finding_id": "CF-1", "title": "Missing CSP header", "vulnerability_class": "security_header_misconfiguration"}
    finding.update(overrides)
    return finding


class TestContract:
    def test_001_result_has_exact_fields(self):
        result = review_threat_hunt_for_finding(canonical_finding=_finding(), available_telemetry=[])
        assert set(result.keys()) == _RESULT_FIELDS

    def test_002_execution_performed_always_false(self):
        result = review_threat_hunt_for_finding(canonical_finding=_finding(), available_telemetry=[])
        assert result["execution_performed"] is False

    def test_003_stage_evaluated_always_true(self):
        result = review_threat_hunt_for_finding(canonical_finding=_finding(), available_telemetry=[])
        assert result["stage_evaluated"] is True

    def test_004_version_is_1(self):
        result = review_threat_hunt_for_finding(canonical_finding=_finding(), available_telemetry=[])
        assert result["review_version"] == REVIEW_VERSION == "1"

    def test_005_rejects_non_mapping(self):
        with pytest.raises(ThreatHuntReviewError):
            review_threat_hunt_for_finding(canonical_finding="not a finding", available_telemetry=[])

    def test_006_rejects_missing_finding_id(self):
        with pytest.raises(ThreatHuntReviewError):
            review_threat_hunt_for_finding(canonical_finding={"title": "x"}, available_telemetry=[])

    def test_007_outcome_always_in_closed_vocabulary(self):
        result = review_threat_hunt_for_finding(canonical_finding=_finding(), available_telemetry=[])
        assert result["outcome"] in OUTCOMES


class TestTelemetryFeasibility:
    def test_008_no_telemetry_is_telemetry_gap(self):
        result = review_threat_hunt_for_finding(canonical_finding=_finding(), available_telemetry=[])
        assert result["outcome"] == "telemetry_gap"

    def test_009_matching_telemetry_is_hunt_candidate_created(self):
        result = review_threat_hunt_for_finding(
            canonical_finding=_finding(), available_telemetry=["web_server", "http_proxy"],
        )
        assert result["outcome"] == "hunt_candidate_created"

    def test_010_partial_telemetry_still_hunt_candidate_created(self):
        result = review_threat_hunt_for_finding(canonical_finding=_finding(), available_telemetry=["web_server"])
        assert result["outcome"] == "hunt_candidate_created"

    def test_011_missing_telemetry_reported_honestly(self):
        result = review_threat_hunt_for_finding(canonical_finding=_finding(), available_telemetry=[])
        assert set(result["missing_telemetry"]) == set(result["required_telemetry"])

    def test_012_no_fake_hunt_execution_claim_never_made(self):
        # Regression guard: no outcome value in the closed vocabulary
        # may claim a hunt was actually executed against real telemetry
        # -- only that one was scoped/planned/gap-blocked.
        assert OUTCOMES == {"hunt_candidate_created", "telemetry_gap", "not_applicable"}
        assert not any("executed" in outcome for outcome in OUTCOMES)

    def test_013_required_telemetry_derived_from_vulnerability_class_not_title(self):
        result_a = review_threat_hunt_for_finding(
            canonical_finding=_finding(title="Anything I want here", vulnerability_class="input_reflection"),
            available_telemetry=[],
        )
        result_b = review_threat_hunt_for_finding(
            canonical_finding=_finding(title="A totally different title", vulnerability_class="input_reflection"),
            available_telemetry=[],
        )
        assert result_a["required_telemetry"] == result_b["required_telemetry"]

    def test_014_unknown_vulnerability_class_gets_default_telemetry(self):
        result = review_threat_hunt_for_finding(
            canonical_finding=_finding(vulnerability_class="totally_unknown_class"), available_telemetry=[],
        )
        assert result["required_telemetry"] == ("web_server",)

    def test_015_hunt_hypothesis_references_the_real_finding_title(self):
        result = review_threat_hunt_for_finding(canonical_finding=_finding(title="XYZ Finding"), available_telemetry=[])
        assert "XYZ Finding" in result["hunt_hypothesis"]

    def test_016_available_telemetry_echoed_unchanged(self):
        result = review_threat_hunt_for_finding(canonical_finding=_finding(), available_telemetry=["web_server"])
        assert result["available_telemetry"] == ["web_server"]

    def test_017_reuses_real_evaluate_telemetry_feasibility_not_reimplemented(self):
        import inspect

        import core.bug_bounty_threat_hunt_review as module
        source = inspect.getsource(module)
        assert "from core.detection_telemetry import evaluate_telemetry_feasibility" in source
        assert "def evaluate_telemetry_feasibility" not in source
