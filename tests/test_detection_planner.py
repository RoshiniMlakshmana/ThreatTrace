"""Focused tests for core.detection_planner -- the pure, deterministic
LLM-generated Detection Plan validator (Block 15H-I).
"""

from __future__ import annotations

import pytest

from core.detection_planner import (
    PLAN_REQUIRED_FIELDS,
    RULE_FORMATS,
    DetectionPlannerError,
    validate_detection_plan,
)
from core.detection_trigger import build_bug_bounty_trigger


def _trigger(**overrides):
    finding = {
        "finding_id": "CF-abc123", "title": "Missing Content-Security-Policy header",
        "vulnerability_class": "security_header_misconfiguration", "cwe": "CWE-693",
        "owasp_category": "A05:2021 Security Misconfiguration", "cve": [],
        "tools_used": ["http_assessor", "zap"], "confidence": "high",
        "evidence_digests": ["sha256:" + "a" * 64], "limitations": [],
    }
    finding.update(overrides)
    return build_bug_bounty_trigger(canonical_finding=finding)


def _telemetry_feasibility(decision="GENERATE_RULE", available_sources=None, **overrides):
    available_sources = available_sources if available_sources is not None else ["http_proxy", "web_server"]
    result = {
        "telemetry_feasibility_version": "1",
        "required_sources": ["http_proxy"], "available_sources": available_sources,
        "missing_sources": [], "recommended_sources": [],
        "telemetry_available": {"GENERATE_RULE": "true", "TELEMETRY_GAP": "false", "PARTIAL_COVERAGE": "partial"}[decision],
        "decision": decision, "siem": None, "edr": None, "cloud_provider": None,
        "environment": None, "industry": None, "limitations": [],
    }
    result.update(overrides)
    return result


def _rule_draft(**overrides):
    draft = {
        "rule_draft_id": "RD-1", "rule_format": "sigma", "title": "Detect missing CSP responses",
        "description": "Flags HTTP responses lacking a Content-Security-Policy header.",
        "generic_rule_content": "detection:\n  selection:\n    http.response.headers.csp: null",
        "context_tuned_rule_content": None,
        "false_positive_considerations": ["Static asset responses may legitimately omit CSP."],
        "required_telemetry": ["http_proxy"],
    }
    draft.update(overrides)
    return draft


def _plan(**overrides):
    plan = {
        "plan_version": "1", "plan_id": "PLAN-1", "trigger": _trigger(),
        "telemetry_feasibility": _telemetry_feasibility(),
        "detection_objective": "Detect responses missing a Content-Security-Policy header.",
        "proposed_rules": [_rule_draft()], "telemetry_recommendation": None,
    }
    plan.update(overrides)
    return plan


class TestValidPlan:
    def test_001_valid_plan_passes(self):
        result = validate_detection_plan(plan=_plan())
        assert result["rule_count"] == 1
        assert result["human_review_required"] is True
        assert result["execution_performed"] is False

    def test_002_exact_output_contract_fields(self):
        result = validate_detection_plan(plan=_plan())
        assert set(result.keys()) == {
            "plan_validation_version", "plan_id", "trigger", "telemetry_feasibility", "detection_objective",
            "proposed_rules", "telemetry_recommendation", "rule_count", "human_review_required", "execution_performed",
        }

    def test_003_zero_rules_for_generate_rule_case_still_valid(self):
        result = validate_detection_plan(plan=_plan(proposed_rules=[]))
        assert result["rule_count"] == 0


class TestTelemetryGapEnforcement:
    def test_004_telemetry_gap_with_rules_rejected(self):
        with pytest.raises(DetectionPlannerError):
            validate_detection_plan(plan=_plan(
                telemetry_feasibility=_telemetry_feasibility(decision="TELEMETRY_GAP", available_sources=[]),
                proposed_rules=[_rule_draft(required_telemetry=[])],
            ))

    def test_005_telemetry_gap_with_no_rules_accepted(self):
        result = validate_detection_plan(plan=_plan(
            telemetry_feasibility=_telemetry_feasibility(decision="TELEMETRY_GAP", available_sources=[]),
            proposed_rules=[], telemetry_recommendation="Instrument HTTP proxy logging to enable this detection.",
        ))
        assert result["rule_count"] == 0
        assert result["telemetry_recommendation"] is not None

    def test_006_partial_coverage_with_rules_accepted(self):
        result = validate_detection_plan(plan=_plan(telemetry_feasibility=_telemetry_feasibility(decision="PARTIAL_COVERAGE")))
        assert result["rule_count"] == 1


class TestUnsupportedFormatAndTelemetry:
    def test_007_unsupported_rule_format_rejected(self):
        with pytest.raises(DetectionPlannerError):
            validate_detection_plan(plan=_plan(proposed_rules=[_rule_draft(rule_format="powershell_script")]))

    def test_008_unsupported_telemetry_type_rejected(self):
        with pytest.raises(DetectionPlannerError):
            validate_detection_plan(plan=_plan(proposed_rules=[_rule_draft(required_telemetry=["not_a_real_type"])]))

    def test_009_telemetry_not_reported_available_rejected(self):
        with pytest.raises(DetectionPlannerError):
            validate_detection_plan(plan=_plan(proposed_rules=[_rule_draft(required_telemetry=["process_creation"])]))

    def test_010_all_four_formats_individually_accepted(self):
        for fmt in RULE_FORMATS:
            result = validate_detection_plan(plan=_plan(proposed_rules=[_rule_draft(rule_format=fmt)]))
            assert result["proposed_rules"][0]["rule_format"] == fmt


class TestEvidenceAndTriggerBinding:
    def test_011_missing_evidence_binding_via_malformed_trigger_rejected(self):
        bad_plan = _plan()
        bad_plan["trigger"] = dict(bad_plan["trigger"])
        del bad_plan["trigger"]["evidence_references"]
        with pytest.raises(DetectionPlannerError):
            validate_detection_plan(plan=bad_plan)

    def test_012_unapproved_trigger_type_rejected(self):
        bad_plan = _plan()
        bad_plan["trigger"] = dict(bad_plan["trigger"], trigger_type="offensive_exploitation")
        with pytest.raises(DetectionPlannerError):
            validate_detection_plan(plan=bad_plan)


class TestDeploymentAndRawCommandRejection:
    def test_013_no_deployment_field_possible_extra_field_rejected(self):
        bad_plan = _plan()
        bad_plan["deployment_state"] = "deployed"
        with pytest.raises(DetectionPlannerError):
            validate_detection_plan(plan=bad_plan)

    def test_014_no_approval_field_possible_extra_field_rejected(self):
        bad_plan = _plan()
        bad_plan["human_approval_state"] = "approved"
        with pytest.raises(DetectionPlannerError):
            validate_detection_plan(plan=bad_plan)

    def test_015_no_raw_command_field_possible_in_rule_draft(self):
        bad_plan = _plan(proposed_rules=[dict(_rule_draft(), shell_command="rm -rf /")])
        with pytest.raises(DetectionPlannerError):
            validate_detection_plan(plan=bad_plan)

    def test_016_rule_draft_contract_has_no_deployment_or_approval_fields(self):
        from core.detection_planner import _RULE_DRAFT_REQUIRED_FIELDS
        forbidden = {"deployment_state", "human_approval_state", "shell_command", "raw_command"}
        assert forbidden.isdisjoint(set(_RULE_DRAFT_REQUIRED_FIELDS))


class TestStructuralValidation:
    def test_017_missing_plan_field_raises(self):
        bad = _plan()
        del bad["detection_objective"]
        with pytest.raises(DetectionPlannerError):
            validate_detection_plan(plan=bad)

    def test_018_blank_detection_objective_raises(self):
        with pytest.raises(DetectionPlannerError):
            validate_detection_plan(plan=_plan(detection_objective="   "))

    def test_019_duplicate_rule_draft_id_raises(self):
        with pytest.raises(DetectionPlannerError):
            validate_detection_plan(plan=_plan(proposed_rules=[_rule_draft(), _rule_draft()]))

    def test_020_context_tuned_content_optional_null_allowed(self):
        result = validate_detection_plan(plan=_plan())
        assert result["proposed_rules"][0]["context_tuned_rule_content"] is None

    def test_021_context_tuned_content_when_present_preserved(self):
        result = validate_detection_plan(plan=_plan(proposed_rules=[_rule_draft(context_tuned_rule_content="tuned logic here")]))
        assert result["proposed_rules"][0]["context_tuned_rule_content"] == "tuned logic here"

    def test_022_never_mutates_input(self):
        import copy
        plan = _plan()
        snapshot = copy.deepcopy(plan)
        validate_detection_plan(plan=plan)
        assert plan == snapshot

    def test_023_deterministic_given_same_input(self):
        plan = _plan()
        first = validate_detection_plan(plan=plan)
        second = validate_detection_plan(plan=plan)
        assert first == second

    def test_024_exact_plan_required_fields(self):
        assert PLAN_REQUIRED_FIELDS == (
            "plan_version", "plan_id", "trigger", "telemetry_feasibility",
            "detection_objective", "proposed_rules", "telemetry_recommendation",
        )
