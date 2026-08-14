"""Focused tests for core.detection_rule -- the pure, deterministic
Detection Rule contract (Block 15H-I).
"""

from __future__ import annotations

import pytest

from core.detection_rule import (
    DEPLOYMENT_STATES,
    RULE_REQUIRED_FIELDS,
    VALIDATION_STATUSES,
    DetectionRuleError,
    apply_validation_result,
    build_detection_rule,
)
from core.detection_trigger import build_bug_bounty_trigger, build_threat_intelligence_trigger


def _bug_bounty_trigger():
    return build_bug_bounty_trigger(canonical_finding={
        "finding_id": "CF-abc123", "title": "Missing CSP header", "vulnerability_class": "security_header_misconfiguration",
        "cwe": "CWE-693", "owasp_category": "A05:2021", "cve": [], "tools_used": ["http_assessor"],
        "confidence": "high", "evidence_digests": ["sha256:" + "a" * 64], "limitations": [],
    })


def _ti_trigger():
    return build_threat_intelligence_trigger(ti_record={
        "intel_id": "TI-0001", "title": "Example vuln", "cve": ["CVE-2026-0001"], "cwe": ["CWE-89"], "owasp": [],
        "affected_products": ["Acme"], "evidence_references": ["https://example.test"], "limitations": [],
        "behavioral_indicators": [], "attack": {"tactic": [], "technique": ["T1190"], "subtechnique": []},
        "confidence": "high", "exploitation_status": "unknown", "corroboration_state": "authoritative_source",
    })


def _rule_draft(**overrides):
    draft = {
        "rule_draft_id": "RD-1", "rule_format": "sigma", "title": "Detect missing CSP",
        "description": "Flags responses without a CSP header.",
        "generic_rule_content": "detection: selection", "context_tuned_rule_content": None,
        "false_positive_considerations": ["Static assets may omit CSP legitimately."],
        "required_telemetry": ["http_proxy"],
    }
    draft.update(overrides)
    return draft


class TestBuildDetectionRule:
    def test_001_builds_valid_rule(self):
        rule = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger())
        assert rule["deployment_state"] == "NOT_DEPLOYED"
        assert rule["validation_status"] == "draft"
        assert rule["human_approval_state"] == "pending"

    def test_002_deployment_state_always_not_deployed(self):
        rule = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger())
        assert rule["deployment_state"] == "NOT_DEPLOYED"
        import inspect
        assert "deployment_state" not in inspect.signature(build_detection_rule).parameters

    def test_003_bug_bounty_trigger_populates_source_finding_ids(self):
        rule = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger())
        assert rule["source_finding_ids"] == ["CF-abc123"]
        assert rule["source_intel_ids"] == []

    def test_004_ti_trigger_populates_source_intel_ids(self):
        rule = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_ti_trigger())
        assert rule["source_intel_ids"] == ["TI-0001"]
        assert rule["source_finding_ids"] == []
        assert rule["cve"] == ["CVE-2026-0001"]
        assert rule["attack"]["technique"] == ["T1190"]

    def test_005_context_tuned_rule_null_when_not_provided(self):
        rule = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger())
        assert rule["context_tuned_rule"] is None

    def test_006_context_tuned_rule_preserved_when_provided(self):
        rule = build_detection_rule(
            validated_rule_draft=_rule_draft(context_tuned_rule_content="tuned for Splunk"), trigger=_bug_bounty_trigger(),
        )
        assert rule["context_tuned_rule"] == "tuned for Splunk"

    def test_007_data_source_echoed(self):
        rule = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger(), data_source="Splunk")
        assert rule["data_source"] == "Splunk"

    def test_008_data_source_defaults_to_none(self):
        rule = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger())
        assert rule["data_source"] is None

    def test_009_confidence_equals_evidence_confidence_at_build_time(self):
        rule = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger())
        assert rule["confidence"] == rule["evidence_confidence"]

    def test_010_exact_output_contract_fields(self):
        rule = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger())
        assert set(rule.keys()) == set(RULE_REQUIRED_FIELDS)

    def test_011_invalid_trigger_type_raises(self):
        bad_trigger = dict(_bug_bounty_trigger(), trigger_type="offensive_exploitation")
        with pytest.raises(DetectionRuleError):
            build_detection_rule(validated_rule_draft=_rule_draft(), trigger=bad_trigger)

    def test_012_blank_title_raises(self):
        with pytest.raises(DetectionRuleError):
            build_detection_rule(validated_rule_draft=_rule_draft(title="  "), trigger=_bug_bounty_trigger())

    def test_013_deterministic_detection_id(self):
        first = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger())
        second = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger())
        assert first["detection_id"] == second["detection_id"]

    def test_014_never_mutates_input(self):
        import copy
        draft = _rule_draft()
        trigger = _bug_bounty_trigger()
        draft_snapshot, trigger_snapshot = copy.deepcopy(draft), copy.deepcopy(trigger)
        build_detection_rule(validated_rule_draft=draft, trigger=trigger)
        assert draft == draft_snapshot
        assert trigger == trigger_snapshot


class TestApplyValidationResult:
    def test_015_advances_validation_status(self):
        rule = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger())
        updated = apply_validation_result(rule=rule, validation_status="syntax_validated")
        assert updated["validation_status"] == "syntax_validated"

    def test_016_never_touches_deployment_or_approval_state(self):
        rule = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger())
        updated = apply_validation_result(rule=rule, validation_status="syntax_validated")
        assert updated["deployment_state"] == "NOT_DEPLOYED"
        assert updated["human_approval_state"] == "pending"

    def test_017_invalid_validation_status_raises(self):
        rule = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger())
        with pytest.raises(DetectionRuleError):
            apply_validation_result(rule=rule, validation_status="production_ready")

    def test_018_limitations_addendum_appended(self):
        rule = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger())
        updated = apply_validation_result(
            rule=rule, validation_status="syntax_validated", known_limitations_addendum="Structural validation only.",
        )
        assert "Structural validation only." in updated["known_limitations"]

    def test_019_original_rule_never_mutated(self):
        import copy
        rule = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger())
        snapshot = copy.deepcopy(rule)
        apply_validation_result(rule=rule, validation_status="syntax_validated")
        assert rule == snapshot

    def test_020_all_five_validation_statuses_valid(self):
        rule = build_detection_rule(validated_rule_draft=_rule_draft(), trigger=_bug_bounty_trigger())
        for status in VALIDATION_STATUSES:
            updated = apply_validation_result(rule=rule, validation_status=status)
            assert updated["validation_status"] == status

    def test_021_deployment_states_closed_vocabulary(self):
        assert DEPLOYMENT_STATES == {"NOT_DEPLOYED", "DEPLOYED"}
