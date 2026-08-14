"""Focused tests for core.detection_rule_deduplication (Block 15H-I)."""

from __future__ import annotations

import pytest

from core.detection_rule import build_detection_rule
from core.detection_rule_deduplication import (
    DUPLICATE_STATUSES,
    DetectionRuleDeduplicationError,
    check_rule_duplicate,
    compute_rule_fingerprints,
)
from core.detection_trigger import build_threat_intelligence_trigger


def _trigger(**overrides):
    record = {
        "intel_id": "TI-0001", "title": "Example vuln", "cve": ["CVE-2026-0001"], "cwe": ["CWE-89"], "owasp": [],
        "affected_products": ["Acme Widget"], "evidence_references": ["https://example.test"], "limitations": [],
        "behavioral_indicators": [], "attack": {"tactic": [], "technique": ["T1190"], "subtechnique": []},
        "confidence": "high", "exploitation_status": "unknown", "corroboration_state": "authoritative_source",
    }
    record.update(overrides)
    return build_threat_intelligence_trigger(ti_record=record)


def _rule_draft(**overrides):
    draft = {
        "rule_draft_id": "RD-1", "rule_format": "sigma", "title": "Detect SQLi",
        "description": "Flags SQL injection attempts", "generic_rule_content": "detection: selection",
        "context_tuned_rule_content": None, "false_positive_considerations": [],
        "required_telemetry": ["network_connection"],
    }
    draft.update(overrides)
    return draft


def _rule(**overrides):
    trigger = overrides.pop("trigger", None) or _trigger()
    draft = overrides.pop("draft_overrides", {})
    return build_detection_rule(validated_rule_draft=_rule_draft(**draft), trigger=trigger)


class TestFingerprints:
    def test_001_identical_rules_share_full_fingerprint(self):
        a, b = _rule(), _rule()
        fa, fb = compute_rule_fingerprints(rule=a), compute_rule_fingerprints(rule=b)
        assert fa["full_fingerprint"] == fb["full_fingerprint"]

    def test_002_different_telemetry_changes_full_but_not_identity(self):
        a = _rule()
        b = _rule(draft_overrides={"required_telemetry": ["dns"]})
        fa, fb = compute_rule_fingerprints(rule=a), compute_rule_fingerprints(rule=b)
        assert fa["full_fingerprint"] != fb["full_fingerprint"]
        assert fa["identity_fingerprint"] == fb["identity_fingerprint"]

    def test_003_invalid_rule_raises(self):
        with pytest.raises(DetectionRuleDeduplicationError):
            compute_rule_fingerprints(rule={"bad": "shape"})


class TestCheckRuleDuplicate:
    def test_004_no_existing_rules_is_new_rule(self):
        result = check_rule_duplicate(candidate_rule=_rule(), existing_rules=[])
        assert result["status"] == "new_rule"
        assert result["matched_detection_id"] is None

    def test_005_exact_duplicate_is_existing_rule_match(self):
        existing = _rule()
        candidate = _rule()
        result = check_rule_duplicate(candidate_rule=candidate, existing_rules=[existing])
        assert result["status"] == "existing_rule_match"
        assert result["matched_detection_id"] == existing["detection_id"]

    def test_006_same_behavior_different_title_still_matches(self):
        # Title is never part of either fingerprint.
        existing = _rule(draft_overrides={"title": "Original Title"})
        candidate = _rule(draft_overrides={"title": "Completely Different Title"})
        result = check_rule_duplicate(candidate_rule=candidate, existing_rules=[existing])
        assert result["status"] == "existing_rule_match"

    def test_007_same_title_different_telemetry_is_update_candidate(self):
        existing = _rule(draft_overrides={"title": "Same Title", "required_telemetry": ["network_connection"]})
        candidate = _rule(draft_overrides={"title": "Same Title", "required_telemetry": ["dns"]})
        result = check_rule_duplicate(candidate_rule=candidate, existing_rules=[existing])
        assert result["status"] == "update_candidate"
        assert result["matched_detection_id"] == existing["detection_id"]

    def test_008_same_cve_same_attack_is_at_least_update_candidate(self):
        existing = _rule()
        candidate = _rule(draft_overrides={"generic_rule_content": "detection: different logic"})
        result = check_rule_duplicate(candidate_rule=candidate, existing_rules=[existing])
        assert result["status"] in ("existing_rule_match", "update_candidate")

    def test_009_same_cve_meaningfully_different_behavior_is_new_rule_or_update(self):
        existing_trigger = _trigger(cve=["CVE-2026-0001"], attack={"tactic": [], "technique": ["T1190"], "subtechnique": []})
        different_behavior_trigger = _trigger(
            cve=["CVE-2026-0001"], attack={"tactic": [], "technique": ["T1078"], "subtechnique": []},
        )
        existing = _rule(trigger=existing_trigger)
        candidate = _rule(trigger=different_behavior_trigger)
        result = check_rule_duplicate(candidate_rule=candidate, existing_rules=[existing])
        # Different ATT&CK technique changes the identity fingerprint itself.
        assert result["status"] == "new_rule"

    def test_010_different_rule_format_is_new_rule_even_with_same_everything_else(self):
        existing = _rule(draft_overrides={"rule_format": "sigma"})
        candidate = _rule(draft_overrides={"rule_format": "splunk_spl"})
        result = check_rule_duplicate(candidate_rule=candidate, existing_rules=[existing])
        assert result["status"] == "new_rule"

    def test_011_never_deduplicates_on_title_alone(self):
        existing = _rule(
            trigger=_trigger(cve=["CVE-2026-9999"]), draft_overrides={"title": "Identical Title"},
        )
        candidate = _rule(
            trigger=_trigger(cve=["CVE-2026-1111"]), draft_overrides={"title": "Identical Title"},
        )
        result = check_rule_duplicate(candidate_rule=candidate, existing_rules=[existing])
        assert result["status"] == "new_rule"

    def test_012_source_history_never_mutated_on_existing_rule(self):
        import copy
        existing = _rule()
        snapshot = copy.deepcopy(existing)
        check_rule_duplicate(candidate_rule=_rule(), existing_rules=[existing])
        assert existing == snapshot

    def test_013_invalid_existing_rules_entry_raises(self):
        with pytest.raises(DetectionRuleDeduplicationError):
            check_rule_duplicate(candidate_rule=_rule(), existing_rules=["not-a-mapping"])

    def test_014_existing_rule_missing_detection_id_raises(self):
        bad = dict(_rule())
        del bad["detection_id"]
        with pytest.raises(DetectionRuleDeduplicationError):
            check_rule_duplicate(candidate_rule=_rule(), existing_rules=[bad])

    def test_015_all_statuses_are_closed_vocabulary(self):
        assert DUPLICATE_STATUSES == {"existing_rule_match", "update_candidate", "new_rule"}

    def test_016_deterministic_given_same_input(self):
        existing = _rule()
        candidate = _rule()
        first = check_rule_duplicate(candidate_rule=candidate, existing_rules=[existing])
        second = check_rule_duplicate(candidate_rule=candidate, existing_rules=[existing])
        assert first == second
