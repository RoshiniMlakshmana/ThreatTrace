"""Focused tests for core.bug_bounty_final_report -- the pure,
deterministic Final Bug Bounty Report builder (Block 15G-CD).

Uses the real `core.bug_bounty_finding_correlation.
correlate_bug_bounty_evidence` to produce genuinely valid, self-
consistent `correlation_result` fixtures (a real integration point, not
a hand-mocked shape) -- no network, filesystem, clock, or LLM access
occurs anywhere in this file.
"""

from __future__ import annotations

import pytest

from core.bug_bounty_evidence_normalization import EVIDENCE_REQUIRED_FIELDS
from core.bug_bounty_final_report import (
    STATUS_VALUES,
    UNSUPPORTED_TEST_CATEGORIES,
    BugBountyFinalReportError,
    build_final_bug_bounty_report,
)
from core.bug_bounty_finding_correlation import correlate_bug_bounty_evidence

_SCOPE = "http://localhost:3000"


def _record(**overrides):
    record = {field: None for field in EVIDENCE_REQUIRED_FIELDS}
    record.update({
        "evidence_id": "EV-0000000000000001",
        "source_tool": "http_assessor",
        "source_observation_id": "obs-1",
        "observation_type": "web_configuration",
        "host": "localhost", "port": 3000, "scheme": "http", "url": "http://localhost:3000/", "path": "/",
        "cve": [], "validation_state": "unvalidated", "scope_reference": _SCOPE,
        "first_observed": "2026-08-14T00:00:00Z", "last_observed": "2026-08-14T00:00:00Z",
        "execution_performed": False, "evidence_digest": "sha256:" + "0" * 64,
    })
    record.update(overrides)
    return record


def _base_kwargs(**overrides):
    kwargs = {
        "target": "http://localhost:3000/",
        "scope": _SCOPE,
        "testing_profile": "safe_dast",
        "assessment_started_at": "2026-08-14T12:00:00Z",
        "assessment_completed_at": "2026-08-14T12:05:00Z",
        "tools_requested": ["http_assessor", "nmap", "nuclei", "zap"],
        "tools_permitted": ["http_assessor", "nmap", "nuclei", "zap"],
        "tools_executed": ["http_assessor", "nmap", "nuclei", "zap"],
        "tools_unavailable": [],
    }
    kwargs.update(overrides)
    return kwargs


def _report_for(records, **kwargs):
    correlation_result = correlate_bug_bounty_evidence(evidence_records=records)
    return build_final_bug_bounty_report(correlation_result=correlation_result, evidence_records=records, **_base_kwargs(**kwargs))


# ---------------------------------------------------------------------------
# Canonical finding / informational observation counts
# ---------------------------------------------------------------------------


class TestCanonicalAndInformational:
    def test_001_real_finding_becomes_canonical(self):
        record = _record(evidence_id="EV-a", evidence_digest="sha256:" + "1" * 64, technical_severity="medium", cwe="CWE-693")
        report = _report_for([record])
        assert len(report["canonical_findings"]) == 1
        assert report["informational_observations"] == []

    def test_002_bare_port_observation_becomes_informational_not_canonical(self):
        record = _record(
            evidence_id="EV-a", evidence_digest="sha256:" + "2" * 64, source_tool="nmap",
            observation_type="service", technical_severity=None, vulnerability_class=None, cwe=None, cve=[], path=None,
        )
        report = _report_for([record])
        assert report["canonical_findings"] == []
        assert len(report["informational_observations"]) == 1

    def test_003_mixed_batch_separated_correctly(self):
        real = _record(evidence_id="EV-real", evidence_digest="sha256:" + "3" * 64, technical_severity="high", cwe="CWE-79")
        informational = _record(
            evidence_id="EV-info", evidence_digest="sha256:" + "4" * 64, source_tool="nmap",
            observation_type="service", technical_severity=None, vulnerability_class=None, cwe=None, cve=[], path=None,
        )
        report = _report_for([real, informational])
        assert len(report["canonical_findings"]) == 1
        assert len(report["informational_observations"]) == 1

    def test_004_canonical_finding_status_always_requires_human_review(self):
        record = _record(evidence_id="EV-a", evidence_digest="sha256:" + "5" * 64, technical_severity="critical", cwe="CWE-89")
        report = _report_for([record])
        assert report["canonical_findings"][0]["status"] == "requires_human_review"
        assert report["canonical_findings"][0]["status"] in STATUS_VALUES

    def test_005_canonical_finding_human_validation_always_required(self):
        record = _record(evidence_id="EV-a", evidence_digest="sha256:" + "6" * 64, technical_severity="high", cwe="CWE-79")
        report = _report_for([record])
        assert report["canonical_findings"][0]["human_validation_required"] is True

    def test_006_no_false_execution_claims(self):
        record = _record(evidence_id="EV-a", evidence_digest="sha256:" + "7" * 64, technical_severity="high", cwe="CWE-79")
        report = _report_for([record])
        assert report["execution_performed"] is False

    def test_007_finding_never_fabricates_cve_mitre_or_references(self):
        record = _record(evidence_id="EV-a", evidence_digest="sha256:" + "8" * 64, technical_severity="high", cwe="CWE-79", cve=[])
        report = _report_for([record])
        finding = report["canonical_findings"][0]
        assert finding["cve"] == []
        assert finding["mitre_attack_mapping"] is None
        assert finding["references"] == []

    def test_008_finding_preserves_real_cve_when_present(self):
        record = _record(evidence_id="EV-a", evidence_digest="sha256:" + "9" * 64, technical_severity="high", cwe="CWE-79", cve=["CVE-2021-1234"])
        report = _report_for([record])
        assert report["canonical_findings"][0]["cve"] == ["CVE-2021-1234"]

    def test_009_evidence_sources_and_tool_observations_preserved(self):
        record = _record(
            evidence_id="EV-a", evidence_digest="sha256:" + "10" * 32, technical_severity="high", cwe="CWE-79",
            title="XSS finding", sanitized_evidence="reflected in response",
        )
        report = _report_for([record])
        finding = report["canonical_findings"][0]
        assert finding["evidence_sources"][0]["source_tool"] == "http_assessor"
        assert finding["tool_observations"][0]["title"] == "XSS finding"
        assert finding["sanitized_proof"] == "reflected in response"


# ---------------------------------------------------------------------------
# Duplicate count / correlation summary
# ---------------------------------------------------------------------------


class TestDuplicateAndCorrelationSummary:
    def test_010_duplicate_evidence_count_propagated(self):
        a = _record(evidence_id="EV-a", evidence_digest="sha256:" + "11" * 32)
        b = _record(evidence_id="EV-b", evidence_digest="sha256:" + "11" * 32)  # exact duplicate digest
        report = _report_for([a, b])
        assert report["duplicate_evidence_count"] == 1
        assert report["correlation_summary"]["duplicate_evidence_count"] == 1

    def test_011_correlation_summary_total_input_records(self):
        records = [_record(evidence_id=f"EV-{i}", evidence_digest="sha256:" + str(i) * 64, path=f"/p{i}") for i in range(3)]
        report = _report_for(records)
        assert report["correlation_summary"]["total_input_records"] == 3

    def test_012_multi_tool_corroborated_count(self):
        a = _record(evidence_id="EV-a", evidence_digest="sha256:" + "12" * 32, source_tool="http_assessor", cwe="CWE-1", path="/")
        b = _record(evidence_id="EV-b", evidence_digest="sha256:" + "13" * 32, source_tool="zap", cwe="CWE-1", path="/")
        report = _report_for([a, b])
        assert report["correlation_summary"]["multi_tool_corroborated_count"] == 1


# ---------------------------------------------------------------------------
# Unavailable tools / limitations / unsupported categories
# ---------------------------------------------------------------------------


class TestUnavailableToolsAndLimitations:
    def test_013_tools_unavailable_propagated(self):
        report = _report_for([], tools_unavailable=["burp_dast"])
        assert report["tools_unavailable"] == ["burp_dast"]
        assert "burp_dast" in report["executive_summary"]["tools_not_available"]

    def test_014_limitations_always_present(self):
        report = _report_for([])
        assert len(report["limitations"]) > 0
        assert any("exploit" in item.lower() for item in report["limitations"])

    def test_015_unsupported_test_categories_fixed_and_present(self):
        report = _report_for([])
        assert report["unsupported_test_categories"] == list(UNSUPPORTED_TEST_CATEGORIES)
        assert "authenticated_testing" in report["unsupported_test_categories"]
        assert "controlled_validation" in report["unsupported_test_categories"]

    def test_016_safety_summary_never_claims_destructive_capability(self):
        report = _report_for([])
        assert report["safety_summary"]["destructive_testing_implemented"] is False
        assert report["safety_summary"]["active_exploitation_implemented"] is False

    def test_017_no_false_human_approval_claims(self):
        # Even with zero findings, no field claims any human approval
        # already occurred.
        report = _report_for([])
        assert report["human_review_items"] == []
        for finding in report["canonical_findings"]:
            assert finding["human_validation_required"] is True


# ---------------------------------------------------------------------------
# Executive summary honesty
# ---------------------------------------------------------------------------


class TestExecutiveSummaryHonesty:
    def test_018_never_claims_system_secure(self):
        report = _report_for([])
        assert "secure" not in report["executive_summary"]["summary_text"].lower()

    def test_019_zero_findings_does_not_imply_no_vulnerabilities(self):
        report = _report_for([])
        assert report["executive_summary"]["canonical_finding_count"] == 0
        assert "absence of a scanner match does not establish absence" in report["executive_summary"]["summary_text"].lower()

    def test_020_severity_breakdown_counts_correctly(self):
        high = _record(evidence_id="EV-h", evidence_digest="sha256:" + "14" * 32, technical_severity="high", cwe="CWE-1", path="/h")
        low = _record(evidence_id="EV-l", evidence_digest="sha256:" + "15" * 32, technical_severity="low", cwe="CWE-2", path="/l")
        report = _report_for([high, low])
        assert report["executive_summary"]["severity_breakdown"]["high"] == 1
        assert report["executive_summary"]["severity_breakdown"]["low"] == 1

    def test_021_strongest_findings_ranked_by_severity(self):
        low = _record(evidence_id="EV-l", evidence_digest="sha256:" + "16" * 32, technical_severity="low", cwe="CWE-2", path="/l")
        critical = _record(evidence_id="EV-c", evidence_digest="sha256:" + "17" * 32, technical_severity="critical", cwe="CWE-3", path="/c")
        report = _report_for([low, critical])
        assert report["executive_summary"]["strongest_findings"][0]["technical_severity"] == "critical"


# ---------------------------------------------------------------------------
# Governor reference / evidence integrity
# ---------------------------------------------------------------------------


class TestGovernorAndEvidenceIntegrity:
    def test_022_governor_reference_echoed(self):
        report = _report_for([], governor_reference={"decision": "allow", "stage": "bug_bounty_assessment"})
        assert report["governor_summary"] == {"decision": "allow", "stage": "bug_bounty_assessment"}

    def test_023_governor_reference_defaults_to_none(self):
        report = _report_for([])
        assert report["governor_summary"] is None

    def test_024_evidence_integrity_summary_present(self):
        report = _report_for([])
        assert report["evidence_integrity_summary"]["evidence_digest_algorithm"] == "sha256"
        assert "non-repudiation" in report["evidence_integrity_summary"]["note"]


# ---------------------------------------------------------------------------
# Output contract / determinism
# ---------------------------------------------------------------------------


class TestOutputContractAndDeterminism:
    def test_025_exact_top_level_contract_fields(self):
        report = _report_for([])
        assert set(report.keys()) == {
            "report_id", "report_version", "target", "scope", "testing_profile",
            "assessment_started_at", "assessment_completed_at", "tools_requested", "tools_permitted",
            "tools_executed", "tools_unavailable", "executive_summary", "canonical_findings",
            "informational_observations", "duplicate_evidence_count", "correlation_summary",
            "human_review_items", "limitations", "unsupported_test_categories", "safety_summary",
            "governor_summary", "evidence_integrity_summary", "execution_performed",
        }

    def test_026_deterministic_given_same_input(self):
        record = _record(evidence_id="EV-a", evidence_digest="sha256:" + "18" * 32, technical_severity="high", cwe="CWE-1")
        first = _report_for([record])
        second = _report_for([record])
        assert first == second

    def test_027_report_id_stable_format(self):
        report = _report_for([])
        assert report["report_id"].startswith("RPT-")
        assert len(report["report_id"]) == len("RPT-") + 16


# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------


class TestStructuralValidation:
    def test_028_invalid_correlation_result_raises(self):
        with pytest.raises(BugBountyFinalReportError):
            build_final_bug_bounty_report(correlation_result={"bad": "shape"}, evidence_records=[], **_base_kwargs())

    def test_029_blank_target_raises(self):
        correlation_result = correlate_bug_bounty_evidence(evidence_records=[])
        with pytest.raises(BugBountyFinalReportError):
            build_final_bug_bounty_report(
                correlation_result=correlation_result, evidence_records=[], **_base_kwargs(target="   "),
            )

    def test_030_non_string_list_tools_raises(self):
        correlation_result = correlate_bug_bounty_evidence(evidence_records=[])
        with pytest.raises(BugBountyFinalReportError):
            build_final_bug_bounty_report(
                correlation_result=correlation_result, evidence_records=[], **_base_kwargs(tools_executed="not-a-list"),
            )

    def test_031_group_referencing_unknown_evidence_id_raises(self):
        record = _record(evidence_id="EV-a", evidence_digest="sha256:" + "19" * 32)
        correlation_result = correlate_bug_bounty_evidence(evidence_records=[record])
        with pytest.raises(BugBountyFinalReportError):
            build_final_bug_bounty_report(correlation_result=correlation_result, evidence_records=[], **_base_kwargs())


# ---------------------------------------------------------------------------
# End-to-end benchmark compatibility: real normalize -> correlate ->
# final report -> evaluate_benchmark, using the real ZAP/Burp DAST path
# fix and vulnerability_class fix together (Step 6 of the Docker Juice
# Shop accuracy exercise). The objective this checkpoint is structural
# validity of every canonical vulnerability finding, never a better
# benchmark score.
# ---------------------------------------------------------------------------


class TestBenchmarkStructuralCompatibility:
    @staticmethod
    def _zap_only_source_results():
        from core.bug_bounty_evidence_normalization import normalize_bug_bounty_evidence

        zap_result = {
            "tool_result_version": "1", "tool_id": "zap", "request_id": "REQ-1", "target": "http://juice-shop:3000",
            "status": "completed", "capability": "passive_only",
            "observations": [
                {
                    "tool_id": "zap", "observation_type": "dast_observation", "rule_id": "10038",
                    "title": "Content Security Policy (CSP) Header Not Set", "risk": "Medium", "confidence": "High",
                    "url": "http://juice-shop:3000", "path": None, "parameter": None, "method": "GET",
                    "cwe": "CWE-693", "owasp_category": None, "evidence_reference": "zap_alert_sha256:" + "7" * 64,
                    "sanitized_evidence": None,
                },
                {
                    "tool_id": "zap", "observation_type": "dast_observation", "rule_id": "10098",
                    "title": "Cross-Domain Misconfiguration", "risk": "Medium", "confidence": "Medium",
                    "url": "http://juice-shop:3000", "path": None, "parameter": None, "method": "GET",
                    "cwe": "CWE-264", "owasp_category": None, "evidence_reference": "zap_alert_sha256:" + "8" * 64,
                    "sanitized_evidence": "Access-Control-Allow-Origin: *",
                },
                {
                    "tool_id": "zap", "observation_type": "dast_observation", "rule_id": "10096",
                    "title": "Timestamp Disclosure - Unix", "risk": "Low", "confidence": "Low",
                    "url": "http://juice-shop:3000", "path": None, "parameter": None, "method": "GET",
                    "cwe": "CWE-497", "owasp_category": None, "evidence_reference": "zap_alert_sha256:" + "9" * 64,
                    "sanitized_evidence": "1666666667",
                },
            ],
            "execution_performed": True,
        }
        return normalize_bug_bounty_evidence(
            source_results=[{"source_tool": "zap", "result": zap_result}],
            scope_reference="http://juice-shop:3000", observed_at="2026-08-15T00:00:00Z",
        )

    def test_032_every_real_zap_canonical_finding_is_benchmark_structurally_valid(self):
        # Real, unmodified evaluate_benchmark() and build_baseline_ground_truth()
        # -- the exact defect from Step 5 (INVALID_FINDING: vulnerability_class
        # must be a non-blank string) must no longer occur for any of these
        # three real ZAP finding shapes, none of which had a closed CWE
        # mapping other than the CSP one.
        from core.benchmark_evaluation import evaluate_benchmark
        from core.juice_shop_ground_truth import build_baseline_ground_truth

        records = self._zap_only_source_results()
        correlation_result = correlate_bug_bounty_evidence(evidence_records=records)
        report = build_final_bug_bounty_report(
            correlation_result=correlation_result, evidence_records=records, **_base_kwargs(),
        )
        canonical_findings = report["canonical_findings"]
        assert len(canonical_findings) == 3  # CWE-693, CWE-264, CWE-497 -- three distinct categories, no merge

        benchmark_findings = [
            {
                "finding_id": cf["finding_id"],
                "vulnerability_class": cf["vulnerability_class"],
                "affected_path": cf["path"],
                "title": cf["title"],
                "technical_severity": cf["technical_severity"],
                "evidence": [
                    {"observation": obs.get("sanitized_evidence") or obs.get("title"), "evidence_digest": digest}
                    for digest, obs in zip(cf["evidence_digests"], cf["tool_observations"])
                ],
            }
            for cf in canonical_findings
        ]
        # This must not raise -- every finding is structurally valid input.
        # None of these three zap-only findings actually matches a ground
        # truth case here: JS-CSP-MISSING's match_hint requires the exact
        # hyphenated "Content-Security-Policy" substring (the real HTTP
        # header name, as http_assessor's own evidence text says it) --
        # ZAP's title uses spaces ("Content Security Policy (CSP) ..."),
        # so it never satisfies match_hint on its own. This is a separate,
        # genuine limitation of match_hint tuning, not something Step 6
        # was asked to fix -- the objective here is structural validity,
        # not a better benchmark score. All three become valid unmatched
        # findings, never a false positive, never a raised error.
        result = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=benchmark_findings)
        assert result["true_positive_count"] == 0
        assert result["false_positive_count"] == 0
        assert result["unmatched_finding_count"] == 3

    def test_033_generic_fallback_findings_land_in_unmatched_not_false_positive(self):
        from core.benchmark_evaluation import evaluate_benchmark
        from core.juice_shop_ground_truth import build_baseline_ground_truth

        records = self._zap_only_source_results()
        correlation_result = correlate_bug_bounty_evidence(evidence_records=records)
        report = build_final_bug_bounty_report(
            correlation_result=correlation_result, evidence_records=records, **_base_kwargs(),
        )
        generic_findings = [cf for cf in report["canonical_findings"] if cf["vulnerability_class"] == "dast_observation"]
        assert len(generic_findings) == 2  # Cross-Domain Misconfiguration, Timestamp Disclosure

        benchmark_findings = [
            {
                "finding_id": cf["finding_id"], "vulnerability_class": cf["vulnerability_class"],
                "affected_path": cf["path"], "title": cf["title"], "technical_severity": cf["technical_severity"],
                "evidence": [{"observation": cf["title"], "evidence_digest": cf["evidence_digests"][0]}],
            }
            for cf in generic_findings
        ]
        result = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=benchmark_findings)
        assert result["true_positive_count"] == 0
        assert result["false_positive_count"] == 0
        assert result["unmatched_finding_count"] == 2
