"""Focused tests for core.detection_telemetry -- the pure, deterministic
telemetry feasibility evaluator (Block 15H-I).
"""

from __future__ import annotations

import pytest

from core.detection_telemetry import (
    TELEMETRY_DECISIONS,
    DetectionTelemetryError,
    evaluate_telemetry_feasibility,
)


class TestTelemetryFeasibility:
    def test_001_all_required_available_generates_rule(self):
        result = evaluate_telemetry_feasibility(
            required_telemetry_candidates=["process_creation", "network_connection"],
            available_telemetry=["process_creation", "network_connection", "dns"],
        )
        assert result["telemetry_available"] == "true"
        assert result["decision"] == "GENERATE_RULE"
        assert result["missing_sources"] == []

    def test_002_none_available_is_telemetry_gap(self):
        result = evaluate_telemetry_feasibility(
            required_telemetry_candidates=["process_creation"], available_telemetry=[],
        )
        assert result["telemetry_available"] == "false"
        assert result["decision"] == "TELEMETRY_GAP"

    def test_003_partial_coverage(self):
        result = evaluate_telemetry_feasibility(
            required_telemetry_candidates=["process_creation", "network_connection"],
            available_telemetry=["process_creation"],
        )
        assert result["telemetry_available"] == "partial"
        assert result["decision"] == "PARTIAL_COVERAGE"
        assert result["missing_sources"] == ["network_connection"]

    def test_004_empty_required_candidates_is_telemetry_gap(self):
        result = evaluate_telemetry_feasibility(required_telemetry_candidates=[], available_telemetry=["process_creation"])
        assert result["decision"] == "TELEMETRY_GAP"
        assert any("no basis" in item.lower() for item in result["limitations"])

    def test_005_never_fabricates_useful_rule_when_absent(self):
        result = evaluate_telemetry_feasibility(required_telemetry_candidates=["waf"], available_telemetry=["dns"])
        assert result["decision"] == "TELEMETRY_GAP"

    def test_006_recommended_sources_mirrors_missing(self):
        result = evaluate_telemetry_feasibility(
            required_telemetry_candidates=["process_creation", "registry"], available_telemetry=["process_creation"],
        )
        assert result["recommended_sources"] == ["registry"]

    def test_007_org_context_echoed_never_verified(self):
        result = evaluate_telemetry_feasibility(
            required_telemetry_candidates=["process_creation"], available_telemetry=["process_creation"],
            siem="Splunk", edr="CrowdStrike", cloud_provider="AWS", environment="production", industry="technology",
        )
        assert result["siem"] == "Splunk"
        assert result["environment"] == "production"

    def test_008_invalid_telemetry_type_raises(self):
        with pytest.raises(DetectionTelemetryError):
            evaluate_telemetry_feasibility(required_telemetry_candidates=["not_a_real_type"], available_telemetry=[])

    def test_009_duplicate_telemetry_type_raises(self):
        with pytest.raises(DetectionTelemetryError):
            evaluate_telemetry_feasibility(
                required_telemetry_candidates=["process_creation", "process_creation"], available_telemetry=[],
            )

    def test_010_invalid_environment_raises(self):
        with pytest.raises(DetectionTelemetryError):
            evaluate_telemetry_feasibility(required_telemetry_candidates=[], available_telemetry=[], environment="metaverse")

    def test_011_invalid_industry_raises(self):
        with pytest.raises(DetectionTelemetryError):
            evaluate_telemetry_feasibility(required_telemetry_candidates=[], available_telemetry=[], industry="fictional")

    def test_012_all_decisions_reachable(self):
        assert TELEMETRY_DECISIONS == {"GENERATE_RULE", "TELEMETRY_GAP", "PARTIAL_COVERAGE"}

    def test_013_deterministic_given_same_input(self):
        first = evaluate_telemetry_feasibility(required_telemetry_candidates=["dns"], available_telemetry=["dns"])
        second = evaluate_telemetry_feasibility(required_telemetry_candidates=["dns"], available_telemetry=["dns"])
        assert first == second

    def test_014_blank_siem_raises(self):
        with pytest.raises(DetectionTelemetryError):
            evaluate_telemetry_feasibility(required_telemetry_candidates=[], available_telemetry=[], siem="   ")

    def test_015_optional_fields_default_to_none(self):
        result = evaluate_telemetry_feasibility(required_telemetry_candidates=[], available_telemetry=[])
        assert result["siem"] is None
        assert result["edr"] is None
        assert result["cloud_provider"] is None
        assert result["environment"] is None
        assert result["industry"] is None
