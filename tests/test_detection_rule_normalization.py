"""Focused tests for core.detection_rule_normalization (Block 15H-I)."""

from __future__ import annotations

import pytest

from core.detection_rule_normalization import (
    DetectionRuleNormalizationError,
    normalize_detection_rule_fields,
)


def _rule(**overrides):
    rule = {
        "cve": ["cve-2026-0001", "CVE-2026-0001"], "cwe": ["cwe-89"],
        "attack": {"tactic": [], "technique": ["t1190"], "subtechnique": ["T1190.001"]},
        "required_telemetry": ["network_connection", "process_creation", "process_creation"],
        "detection_objective": "  Detect   SQL injection   attempts  ",
        "trigger_type": "threat_intelligence", "rule_format": "Sigma",
        "affected_technology": ["Acme Widget", "acme widget"],
    }
    rule.update(overrides)
    return rule


class TestNormalization:
    def test_001_cve_deduplicated_and_uppercased(self):
        result = normalize_detection_rule_fields(rule=_rule())
        assert result["cve"] == ["CVE-2026-0001"]

    def test_002_cwe_uppercased(self):
        result = normalize_detection_rule_fields(rule=_rule())
        assert result["cwe"] == ["CWE-89"]

    def test_003_technique_and_subtechnique_kept_separate(self):
        result = normalize_detection_rule_fields(rule=_rule())
        assert result["attack_technique"] == ["T1190"]
        assert result["attack_subtechnique"] == ["T1190.001"]
        assert result["attack_technique"] != result["attack_subtechnique"]

    def test_004_telemetry_deduplicated_sorted(self):
        result = normalize_detection_rule_fields(rule=_rule())
        assert result["required_telemetry"] == ["network_connection", "process_creation"]

    def test_005_behavior_signature_whitespace_collapsed_lowercase(self):
        result = normalize_detection_rule_fields(rule=_rule())
        assert result["behavior_signature"] == "detect sql injection attempts"

    def test_006_rule_format_lowercased(self):
        result = normalize_detection_rule_fields(rule=_rule())
        assert result["rule_format"] == "sigma"

    def test_007_affected_technology_deduplicated_case_insensitive(self):
        result = normalize_detection_rule_fields(rule=_rule())
        assert result["affected_technology"] == ["acme widget"]

    def test_008_different_technique_and_subtechnique_not_conflated(self):
        rule = _rule(attack={"tactic": [], "technique": ["T1190"], "subtechnique": []})
        result = normalize_detection_rule_fields(rule=rule)
        assert result["attack_technique"] == ["T1190"]
        assert result["attack_subtechnique"] == []

    def test_009_empty_cve_cwe_yield_empty_lists_never_invented(self):
        rule = _rule(cve=[], cwe=[])
        result = normalize_detection_rule_fields(rule=rule)
        assert result["cve"] == []
        assert result["cwe"] == []

    def test_010_missing_detection_objective_raises(self):
        rule = _rule(detection_objective="   ")
        with pytest.raises(DetectionRuleNormalizationError):
            normalize_detection_rule_fields(rule=rule)

    def test_011_non_mapping_rule_raises(self):
        with pytest.raises(DetectionRuleNormalizationError):
            normalize_detection_rule_fields(rule="not-a-mapping")

    def test_012_malformed_attack_shape_raises(self):
        rule = _rule(attack={"technique": []})
        with pytest.raises(DetectionRuleNormalizationError):
            normalize_detection_rule_fields(rule=dict(rule, attack={}))

    def test_013_deterministic_given_same_input(self):
        rule = _rule()
        first = normalize_detection_rule_fields(rule=rule)
        second = normalize_detection_rule_fields(rule=rule)
        assert first == second

    def test_014_never_mutates_input(self):
        import copy
        rule = _rule()
        snapshot = copy.deepcopy(rule)
        normalize_detection_rule_fields(rule=rule)
        assert rule == snapshot

    def test_015_exact_output_contract_fields(self):
        result = normalize_detection_rule_fields(rule=_rule())
        assert set(result.keys()) == {
            "cve", "cwe", "attack_technique", "attack_subtechnique", "required_telemetry",
            "behavior_signature", "trigger_type", "rule_format", "affected_technology",
        }
