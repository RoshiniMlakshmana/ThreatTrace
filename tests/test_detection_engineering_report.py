"""Focused tests for core.detection_engineering_report (Block 15H-I)."""

from __future__ import annotations

import pytest

from core.detection_engineering_report import (
    DetectionEngineeringReportError,
    build_detection_engineering_report,
)
from core.detection_rule import build_detection_rule
from core.detection_rule_deduplication import check_rule_duplicate
from core.detection_trigger import build_bug_bounty_trigger


def _trigger():
    return build_bug_bounty_trigger(canonical_finding={
        "finding_id": "CF-abc123", "title": "Missing CSP header", "vulnerability_class": "security_header_misconfiguration",
        "cwe": "CWE-693", "owasp_category": "A05:2021", "cve": [], "tools_used": ["http_assessor"],
        "confidence": "high", "evidence_digests": ["sha256:" + "a" * 64], "limitations": [],
    })


def _rule(**overrides):
    draft = {
        "rule_draft_id": "RD-1", "rule_format": "sigma", "title": "Detect missing CSP",
        "description": "Flags responses missing CSP.", "generic_rule_content": "detection: selection",
        "context_tuned_rule_content": None, "false_positive_considerations": [], "required_telemetry": ["http_proxy"],
    }
    draft.update(overrides)
    return build_detection_rule(validated_rule_draft=draft, trigger=_trigger())


def _telemetry_result(trigger_id, decision):
    return {
        "trigger_id": trigger_id,
        "result": {
            "telemetry_feasibility_version": "1", "required_sources": [], "available_sources": [],
            "missing_sources": [], "recommended_sources": [], "telemetry_available": "true",
            "decision": decision, "siem": None, "edr": None, "cloud_provider": None,
            "environment": None, "industry": None, "limitations": [],
        },
    }


class TestDetectionEngineeringReport:
    def test_001_basic_report(self):
        rule = _rule()
        result = build_detection_engineering_report(
            triggers=[_trigger()], telemetry_feasibility_results=[_telemetry_result("DT-1", "GENERATE_RULE")],
            rules=[rule], dedup_results=[check_rule_duplicate(candidate_rule=rule, existing_rules=[])],
            rules_requested=1,
        )
        assert result["rules_generated"] == 1
        assert result["rules_rejected"] == 0

    def test_002_rules_rejected_computed(self):
        rule = _rule()
        result = build_detection_engineering_report(
            triggers=[_trigger()], telemetry_feasibility_results=[], rules=[rule],
            dedup_results=[check_rule_duplicate(candidate_rule=rule, existing_rules=[])], rules_requested=3,
        )
        assert result["rules_rejected"] == 2

    def test_003_telemetry_gap_count(self):
        result = build_detection_engineering_report(
            triggers=[], telemetry_feasibility_results=[_telemetry_result("DT-1", "TELEMETRY_GAP"), _telemetry_result("DT-2", "GENERATE_RULE")],
            rules=[], dedup_results=[], rules_requested=0,
        )
        assert result["telemetry_gap_count"] == 1
        assert result["telemetry_gap_trigger_ids"] == ["DT-1"]

    def test_004_deployment_state_always_not_deployed(self):
        rule = _rule()
        result = build_detection_engineering_report(
            triggers=[], telemetry_feasibility_results=[], rules=[rule], dedup_results=[], rules_requested=1,
        )
        assert result["deployment_state_distribution"] == {"NOT_DEPLOYED": 1}

    def test_005_validation_status_distribution(self):
        rule = _rule()
        result = build_detection_engineering_report(
            triggers=[], telemetry_feasibility_results=[], rules=[rule], dedup_results=[], rules_requested=1,
        )
        assert result["validation_status_distribution"] == {"draft": 1}

    def test_006_human_approval_state_distribution(self):
        rule = _rule()
        result = build_detection_engineering_report(
            triggers=[], telemetry_feasibility_results=[], rules=[rule], dedup_results=[], rules_requested=1,
        )
        assert result["human_approval_state_distribution"] == {"pending": 1}

    def test_007_formats_generated(self):
        rule = _rule(rule_format="yara")
        result = build_detection_engineering_report(
            triggers=[], telemetry_feasibility_results=[], rules=[rule], dedup_results=[], rules_requested=1,
        )
        assert result["formats_generated"] == ["yara"]

    def test_008_cve_cwe_owasp_context_collected(self):
        rule = _rule()
        result = build_detection_engineering_report(
            triggers=[], telemetry_feasibility_results=[], rules=[rule], dedup_results=[], rules_requested=1,
        )
        assert "CWE-693" in result["cwe_context"]

    def test_009_context_tuned_rule_count(self):
        rule = _rule(context_tuned_rule_content="tuned")
        result = build_detection_engineering_report(
            triggers=[], telemetry_feasibility_results=[], rules=[rule], dedup_results=[], rules_requested=1,
        )
        assert result["context_tuned_rule_count"] == 1

    def test_010_dedup_summary(self):
        rule = _rule()
        dedup = check_rule_duplicate(candidate_rule=rule, existing_rules=[])
        result = build_detection_engineering_report(
            triggers=[], telemetry_feasibility_results=[], rules=[rule], dedup_results=[dedup], rules_requested=1,
        )
        assert result["deduplication_summary"]["new_rule"] == 1

    def test_011_zero_rules_generated_is_valid(self):
        result = build_detection_engineering_report(
            triggers=[], telemetry_feasibility_results=[], rules=[], dedup_results=[], rules_requested=0,
        )
        assert result["rules_generated"] == 0

    def test_012_negative_rules_requested_raises(self):
        with pytest.raises(DetectionEngineeringReportError):
            build_detection_engineering_report(
                triggers=[], telemetry_feasibility_results=[], rules=[], dedup_results=[], rules_requested=-1,
            )

    def test_013_invalid_rules_entry_raises(self):
        with pytest.raises(DetectionEngineeringReportError):
            build_detection_engineering_report(
                triggers=[], telemetry_feasibility_results=[], rules=["not-a-mapping"], dedup_results=[], rules_requested=0,
            )

    def test_014_evidence_references_collected(self):
        rule = _rule()
        result = build_detection_engineering_report(
            triggers=[], telemetry_feasibility_results=[], rules=[rule], dedup_results=[], rules_requested=1,
        )
        assert result["evidence_references"] == ["sha256:" + "a" * 64]

    def test_015_trigger_summary_by_type(self):
        result = build_detection_engineering_report(
            triggers=[_trigger()], telemetry_feasibility_results=[], rules=[], dedup_results=[], rules_requested=0,
        )
        assert result["trigger_summary"]["by_type"] == {"bug_bounty": 1}

    def test_016_deterministic_given_same_input(self):
        rule = _rule()
        first = build_detection_engineering_report(triggers=[], telemetry_feasibility_results=[], rules=[rule], dedup_results=[], rules_requested=1)
        second = build_detection_engineering_report(triggers=[], telemetry_feasibility_results=[], rules=[rule], dedup_results=[], rules_requested=1)
        assert first == second
