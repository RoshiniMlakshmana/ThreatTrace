"""Compatibility test (Block 15G-CD, section W): can a canonical Final
Bug Bounty Report finding be consumed by the existing Context
Prioritization -> Security Handoff pipeline without changing that
pipeline's own lifecycle?

This is deliberately a single, focused compatibility test, not a full
Purple Team workflow execution -- it maps one canonical finding's
already-real fields into `core.context_prioritization`/
`core.security_handoff`'s own pre-existing, unmodified contracts, and
proves the result is accepted and starts the Handoff's normal lifecycle
exactly where every other case already starts (`threat_intel_review`).
No source in either module is touched by this test or by this
checkpoint.
"""

from __future__ import annotations

from core.bug_bounty_evidence_normalization import EVIDENCE_REQUIRED_FIELDS
from core.bug_bounty_final_report import build_final_bug_bounty_report
from core.bug_bounty_finding_correlation import correlate_bug_bounty_evidence
from core.context_prioritization import prioritize_finding
from core.security_handoff import STAGES as HANDOFF_STAGES
from core.security_handoff import create_security_handoff_case

_SCOPE = "http://localhost:3000"


def _evidence_record(**overrides):
    record = {field: None for field in EVIDENCE_REQUIRED_FIELDS}
    record.update({
        "evidence_id": "EV-0000000000000001",
        "source_tool": "http_assessor",
        "source_observation_id": "BB15A-abc123",
        "observation_type": "web_configuration",
        "host": "localhost", "port": 3000, "scheme": "http", "url": "http://localhost:3000/", "path": "/",
        "title": "Missing Content-Security-Policy header",
        "vulnerability_class": "security_header_misconfiguration",
        "cwe": "CWE-693", "owasp_category": "A05:2021 Security Misconfiguration",
        "cve": [], "technical_severity": "medium", "confidence": "high",
        "validation_state": "tool_confirmed",
        "sanitized_evidence": "Response did not include a Content-Security-Policy header.",
        "source_reference": "sha256:" + "a" * 64,
        "scope_reference": _SCOPE,
        "first_observed": "2026-08-14T12:00:00Z", "last_observed": "2026-08-14T12:00:00Z",
        "execution_performed": False, "evidence_digest": "sha256:" + "b" * 64,
    })
    record.update(overrides)
    return record


def _canonical_finding_to_block15a_shape(finding: dict) -> dict:
    """The small, honest mapping this compatibility test exists to
    prove works -- a canonical finding's already-real fields, reshaped
    into core.bug_bounty_findings/core.context_prioritization's own
    pre-existing minimal contract. Never invents a field: finding_status
    is deliberately "candidate" (never "validated"), matching this
    checkpoint's own status: "requires_human_review" honesty -- nothing
    here claims a stronger confirmation than the canonical finding
    itself claims."""
    return {
        "finding_version": "1",
        "finding_id": finding["finding_id"],
        "finding_status": "candidate",
        "technical_severity": finding["technical_severity"],
        "confidence": finding["confidence"],
        "vulnerability_class": finding["vulnerability_class"],
        "owasp_category": finding["owasp_category"],
        "cwe": finding["cwe"],
        "evidence": [{"evidence_digest": digest} for digest in finding["evidence_digests"]],
        "validation": {"method": None, "confirmed": False},
    }


def _context(**overrides):
    context = {
        "context_version": "1", "industry": "technology", "environment": "production",
        "asset_criticality": "medium", "exposure": "internal", "data_sensitivity": "internal",
        "detection_coverage": "unknown", "compensating_controls": "unknown",
        "threat_activity": "unknown", "regulatory_relevance": "unknown",
    }
    context.update(overrides)
    return context


class TestFinalReportHandoffCompatibility:
    def test_001_canonical_finding_feeds_context_prioritization_and_handoff(self):
        record = _evidence_record()
        correlation_result = correlate_bug_bounty_evidence(evidence_records=[record])
        report = build_final_bug_bounty_report(
            correlation_result=correlation_result, evidence_records=[record],
            target="http://localhost:3000/", scope=_SCOPE, testing_profile="safe_dast",
            assessment_started_at="2026-08-14T12:00:00Z", assessment_completed_at="2026-08-14T12:05:00Z",
            tools_requested=["http_assessor"], tools_permitted=["http_assessor"],
            tools_executed=["http_assessor"], tools_unavailable=[],
        )
        assert len(report["canonical_findings"]) == 1
        canonical_finding = report["canonical_findings"][0]

        block15a_finding = _canonical_finding_to_block15a_shape(canonical_finding)
        prioritization = prioritize_finding(finding=block15a_finding, context=_context())
        assert prioritization["finding_id"] == canonical_finding["finding_id"]
        assert prioritization["technical_severity"] == canonical_finding["technical_severity"]

        case = create_security_handoff_case(finding=block15a_finding, prioritization=prioritization)

        # The Handoff lifecycle starts exactly where every other case
        # already starts -- proving this integration point changes
        # nothing about core.security_handoff's own behavior.
        assert case["current_stage"] == "threat_intel_review"
        assert case["required_role"] == "threat_intelligence"
        assert case["current_stage"] in HANDOFF_STAGES
        assert case["finding_reference"]["finding_id"] == canonical_finding["finding_id"]
        assert case["finding_reference"]["technical_severity"] == canonical_finding["technical_severity"]
        assert case["execution_performed"] is False
        assert case["human_review_required"] is True

    def test_002_handoff_stage_vocabulary_unchanged_by_this_checkpoint(self):
        # Exactly the six pre-existing Handoff stages -- Block 15G-CD
        # never adds a "bug_bounty" stage here (unlike the Governor's
        # own deliberately separate "bug_bounty_assessment" operational
        # stage from Block 15G-B.2 -- see core.security_governor's own
        # docstring on that distinction).
        assert HANDOFF_STAGES == {
            "threat_intel_review", "threat_hunt", "detection_engineering",
            "red_validation", "purple_remediation", "human_review",
        }
