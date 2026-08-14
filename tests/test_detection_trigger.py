"""Focused tests for core.detection_trigger -- the pure, deterministic
Detection Trigger contract (Block 15H-I).
"""

from __future__ import annotations

import pytest

from core.detection_trigger import (
    TRIGGER_REQUIRED_FIELDS,
    TRIGGER_TYPES,
    DetectionTriggerError,
    build_bug_bounty_trigger,
    build_manual_trigger,
    build_threat_intelligence_trigger,
    validate_detection_trigger,
)


def _canonical_finding(**overrides):
    finding = {
        "finding_id": "CF-abc123", "title": "Missing Content-Security-Policy header",
        "vulnerability_class": "security_header_misconfiguration", "cwe": "CWE-693",
        "owasp_category": "A05:2021 Security Misconfiguration", "cve": [],
        "tools_used": ["http_assessor", "zap"], "confidence": "high",
        "evidence_digests": ["sha256:" + "a" * 64], "limitations": [],
    }
    finding.update(overrides)
    return finding


def _ti_record(**overrides):
    record = {
        "intel_id": "TI-0001", "title": "Example vulnerability", "cve": ["CVE-2026-0001"], "cwe": ["CWE-89"],
        "owasp": [], "affected_products": ["Acme Widget"], "evidence_references": ["https://example.test"],
        "limitations": [], "behavioral_indicators": ["suspicious outbound connection to known C2 infrastructure"],
        "attack": {"tactic": ["TA0001"], "technique": ["T1190"], "subtechnique": []},
        "confidence": "high", "exploitation_status": "exploited_in_wild", "corroboration_state": "authoritative_source",
    }
    record.update(overrides)
    return record


class TestBugBountyTrigger:
    def test_001_builds_valid_trigger(self):
        trigger = build_bug_bounty_trigger(canonical_finding=_canonical_finding())
        assert trigger["trigger_type"] == "bug_bounty"
        assert trigger["source_ids"] == ["CF-abc123"]
        assert trigger["cwe"] == ["CWE-693"]
        assert trigger["human_review_required"] is True

    def test_002_missing_finding_id_raises(self):
        bad = _canonical_finding()
        del bad["finding_id"]
        with pytest.raises(DetectionTriggerError):
            build_bug_bounty_trigger(canonical_finding=bad)

    def test_003_no_cwe_yields_empty_list(self):
        trigger = build_bug_bounty_trigger(canonical_finding=_canonical_finding(cwe=None))
        assert trigger["cwe"] == []

    def test_004_low_confidence_never_inflated(self):
        trigger = build_bug_bounty_trigger(canonical_finding=_canonical_finding(confidence=None))
        assert trigger["confidence"] == "low"

    def test_005_telemetry_candidates_derived_from_vulnerability_class(self):
        trigger = build_bug_bounty_trigger(canonical_finding=_canonical_finding())
        assert "http_proxy" in trigger["required_telemetry_candidates"] or "web_server" in trigger["required_telemetry_candidates"]

    def test_006_attack_always_empty_never_invented(self):
        trigger = build_bug_bounty_trigger(canonical_finding=_canonical_finding())
        assert trigger["attack"] == {"tactic": [], "technique": [], "subtechnique": []}

    def test_007_limitations_note_bug_bounty_origin(self):
        trigger = build_bug_bounty_trigger(canonical_finding=_canonical_finding())
        assert any("Bug Bounty" in item for item in trigger["limitations"])


class TestThreatIntelligenceTrigger:
    def test_008_builds_valid_trigger(self):
        trigger = build_threat_intelligence_trigger(ti_record=_ti_record())
        assert trigger["trigger_type"] == "threat_intelligence"
        assert trigger["source_ids"] == ["TI-0001"]
        assert trigger["cve"] == ["CVE-2026-0001"]
        assert trigger["attack"]["technique"] == ["T1190"]

    def test_009_missing_intel_id_raises(self):
        bad = _ti_record()
        del bad["intel_id"]
        with pytest.raises(DetectionTriggerError):
            build_threat_intelligence_trigger(ti_record=bad)

    def test_010_behavioral_indicators_become_security_behavior(self):
        trigger = build_threat_intelligence_trigger(ti_record=_ti_record())
        assert trigger["security_behavior"] is not None
        assert "C2" in trigger["security_behavior"]

    def test_011_no_behavioral_indicators_yields_null_security_behavior(self):
        trigger = build_threat_intelligence_trigger(ti_record=_ti_record(behavioral_indicators=[]))
        assert trigger["security_behavior"] is None

    def test_012_exploited_in_wild_yields_process_and_network_telemetry_candidates(self):
        trigger = build_threat_intelligence_trigger(ti_record=_ti_record())
        assert "process_creation" in trigger["required_telemetry_candidates"]
        assert "network_connection" in trigger["required_telemetry_candidates"]

    def test_013_unknown_exploitation_status_yields_no_candidates(self):
        trigger = build_threat_intelligence_trigger(ti_record=_ti_record(exploitation_status="unknown"))
        assert trigger["required_telemetry_candidates"] == []

    def test_014_single_source_corroboration_adds_limitation_caveat(self):
        trigger = build_threat_intelligence_trigger(ti_record=_ti_record(corroboration_state="single_source"))
        assert any("single_source" in item for item in trigger["limitations"])

    def test_015_authoritative_source_no_extra_caveat(self):
        trigger = build_threat_intelligence_trigger(ti_record=_ti_record(corroboration_state="authoritative_source"))
        assert not any("corroboration_state" in item for item in trigger["limitations"])

    def test_016_malformed_attack_shape_raises(self):
        bad = _ti_record(attack={"tactic": []})
        with pytest.raises(DetectionTriggerError):
            build_threat_intelligence_trigger(ti_record=bad)


class TestManualTrigger:
    def test_017_valid_manual_trigger(self):
        trigger = build_manual_trigger(
            source_ids=["analyst-note-1"], evidence_references=[], security_behavior="Unusual PowerShell encoded command",
            vulnerability_context=None, cve=[], cwe=[], owasp=[],
            attack={"tactic": [], "technique": ["T1059.001"], "subtechnique": []},
            affected_technology=["Windows"], required_telemetry_candidates=["process_creation"],
            confidence="medium", limitations=[],
        )
        assert trigger["trigger_type"] == "manual"
        assert trigger["attack"]["technique"] == ["T1059.001"]

    def test_018_requires_at_least_one_of_behavior_or_context(self):
        with pytest.raises(DetectionTriggerError):
            build_manual_trigger(
                source_ids=["x"], evidence_references=[], security_behavior=None, vulnerability_context=None,
                cve=[], cwe=[], owasp=[], attack={"tactic": [], "technique": [], "subtechnique": []},
                affected_technology=[], required_telemetry_candidates=[], confidence="low", limitations=[],
            )

    def test_019_empty_source_ids_raises(self):
        with pytest.raises(DetectionTriggerError):
            build_manual_trigger(
                source_ids=[], evidence_references=[], security_behavior="x", vulnerability_context=None,
                cve=[], cwe=[], owasp=[], attack={"tactic": [], "technique": [], "subtechnique": []},
                affected_technology=[], required_telemetry_candidates=[], confidence="low", limitations=[],
            )

    def test_020_invalid_confidence_raises(self):
        with pytest.raises(DetectionTriggerError):
            build_manual_trigger(
                source_ids=["x"], evidence_references=[], security_behavior="x", vulnerability_context=None,
                cve=[], cwe=[], owasp=[], attack={"tactic": [], "technique": [], "subtechnique": []},
                affected_technology=[], required_telemetry_candidates=[], confidence="extreme", limitations=[],
            )


class TestValidateDetectionTrigger:
    def test_021_round_trip_valid(self):
        built = build_bug_bounty_trigger(canonical_finding=_canonical_finding())
        revalidated = validate_detection_trigger(trigger=built)
        assert revalidated == built

    def test_022_unrecognized_trigger_type_raises(self):
        built = build_bug_bounty_trigger(canonical_finding=_canonical_finding())
        bad = dict(built, trigger_type="offensive_exploitation")
        with pytest.raises(DetectionTriggerError):
            validate_detection_trigger(trigger=bad)

    def test_023_missing_field_raises(self):
        built = build_bug_bounty_trigger(canonical_finding=_canonical_finding())
        del built["cve"]
        with pytest.raises(DetectionTriggerError):
            validate_detection_trigger(trigger=built)

    def test_024_extra_field_raises(self):
        built = build_bug_bounty_trigger(canonical_finding=_canonical_finding())
        built["unexpected"] = "x"
        with pytest.raises(DetectionTriggerError):
            validate_detection_trigger(trigger=built)

    def test_025_human_review_required_must_be_true(self):
        built = build_bug_bounty_trigger(canonical_finding=_canonical_finding())
        bad = dict(built, human_review_required=False)
        with pytest.raises(DetectionTriggerError):
            validate_detection_trigger(trigger=bad)

    def test_026_exact_three_trigger_types(self):
        assert TRIGGER_TYPES == {"bug_bounty", "threat_intelligence", "manual"}

    def test_027_exact_output_contract_fields(self):
        built = build_bug_bounty_trigger(canonical_finding=_canonical_finding())
        assert set(built.keys()) == set(TRIGGER_REQUIRED_FIELDS)

    def test_028_trigger_id_deterministic(self):
        first = build_bug_bounty_trigger(canonical_finding=_canonical_finding())
        second = build_bug_bounty_trigger(canonical_finding=_canonical_finding())
        assert first["trigger_id"] == second["trigger_id"]

    def test_029_never_mutates_input(self):
        import copy
        finding = _canonical_finding()
        snapshot = copy.deepcopy(finding)
        build_bug_bounty_trigger(canonical_finding=finding)
        assert finding == snapshot
