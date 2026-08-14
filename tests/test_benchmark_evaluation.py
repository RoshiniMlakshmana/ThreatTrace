"""Tests for core.benchmark_evaluation -- the pure, deterministic Bug
Bounty benchmark evaluator (Block 15F-A).

No network, filesystem, environment-variable, subprocess, clock,
randomness, database/Supabase, MCP, or LLM/model access occurs anywhere
in this file. Every input is a plain in-memory mapping. No real Juice
Shop assessment is run here -- the "real baseline" tests use a
sanitized, hand-transcribed in-memory representation of the six real
findings observed during Block 15F-A0, never a live HTTP call.
"""

from __future__ import annotations

import copy

import pytest

from core.benchmark_evaluation import BenchmarkEvaluationError, evaluate_benchmark
from core.juice_shop_ground_truth import build_baseline_ground_truth

DIGEST = "sha256:" + "a" * 64


def _case(**overrides):
    case = {
        "case_id": "T-CASE-1",
        "category": "SECURITY_HEADER_PRESENCE",
        "detector_capability": "security_header_misconfiguration",
        "expected_detection": True,
        "expected_observation": "A header is missing.",
        "expected_severity": "medium",
        "evidence_requirement": {"affected_path": "/", "match_hint": None},
    }
    case.update(overrides)
    return case


def _ground_truth(*cases, target="Test Target", target_version_or_digest=DIGEST):
    return {
        "ground_truth_version": "1",
        "target": target,
        "target_origin": "http://localhost:3000",
        "target_version_or_digest": target_version_or_digest,
        "supported_cases": list(cases),
        "unsupported_categories": ["sql_injection"],
        "out_of_scope_categories": ["brute_force"],
    }


def _evidence(observation="An observation.", digest=DIGEST):
    return {
        "evidence_version": "1",
        "tool": "test",
        "method": "GET",
        "scoped_url": "http://localhost:3000/",
        "status_code": 200,
        "selected_headers": {},
        "response_excerpt": None,
        "observation": observation,
        "evidence_digest": digest,
    }


def _finding(**overrides):
    finding = {
        "finding_id": "BB15A-0000000000000001",
        "vulnerability_class": "security_header_misconfiguration",
        "affected_path": "/",
        "title": "Missing Content-Security-Policy header",
        "technical_severity": "medium",
        "evidence": [_evidence(observation="Response did not include a Content-Security-Policy header.")],
    }
    finding.update(overrides)
    return finding


# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------


class TestGroundTruthValidation:
    def test_001_ground_truth_not_a_mapping_raises(self):
        with pytest.raises(BenchmarkEvaluationError):
            evaluate_benchmark(ground_truth="nope", findings=[])

    def test_002_missing_supported_cases_raises(self):
        gt = _ground_truth(_case())
        del gt["supported_cases"]
        with pytest.raises(BenchmarkEvaluationError):
            evaluate_benchmark(ground_truth=gt, findings=[])

    def test_003_empty_supported_cases_raises(self):
        with pytest.raises(BenchmarkEvaluationError):
            evaluate_benchmark(ground_truth=_ground_truth(), findings=[])

    def test_004_supported_cases_not_a_list_raises(self):
        gt = _ground_truth(_case())
        gt["supported_cases"] = "nope"
        with pytest.raises(BenchmarkEvaluationError):
            evaluate_benchmark(ground_truth=gt, findings=[])

    def test_005_case_missing_required_field_raises(self):
        bad_case = _case()
        del bad_case["detector_capability"]
        with pytest.raises(BenchmarkEvaluationError):
            evaluate_benchmark(ground_truth=_ground_truth(bad_case), findings=[])

    def test_006_case_malformed_evidence_requirement_raises(self):
        bad_case = _case(evidence_requirement={"affected_path": "/"})
        with pytest.raises(BenchmarkEvaluationError):
            evaluate_benchmark(ground_truth=_ground_truth(bad_case), findings=[])

    def test_007_case_non_bool_expected_detection_raises(self):
        bad_case = _case(expected_detection="true")
        with pytest.raises(BenchmarkEvaluationError):
            evaluate_benchmark(ground_truth=_ground_truth(bad_case), findings=[])

    def test_008_duplicate_case_id_raises(self):
        with pytest.raises(BenchmarkEvaluationError):
            evaluate_benchmark(
                ground_truth=_ground_truth(_case(case_id="DUP"), _case(case_id="DUP")), findings=[],
            )

    def test_009_findings_not_a_list_raises(self):
        with pytest.raises(BenchmarkEvaluationError):
            evaluate_benchmark(ground_truth=_ground_truth(_case()), findings="nope")

    def test_010_finding_missing_required_field_raises(self):
        bad_finding = _finding()
        del bad_finding["vulnerability_class"]
        with pytest.raises(BenchmarkEvaluationError):
            evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[bad_finding])

    def test_011_finding_blank_finding_id_raises(self):
        with pytest.raises(BenchmarkEvaluationError):
            evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[_finding(finding_id="  ")])

    def test_012_finding_evidence_not_a_list_raises(self):
        with pytest.raises(BenchmarkEvaluationError):
            evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[_finding(evidence="nope")])

    def test_013_finding_evidence_item_not_a_mapping_raises(self):
        with pytest.raises(BenchmarkEvaluationError):
            evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[_finding(evidence=["nope"])])

    def test_014_empty_findings_list_is_valid(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[])
        assert result["false_negative_count"] == 1


# ---------------------------------------------------------------------------
# TP / FN (positive cases)
# ---------------------------------------------------------------------------


class TestPositiveCases:
    def test_015_perfect_positive_detection_is_tp(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[_finding()])
        assert result["true_positive_count"] == 1
        assert result["false_negative_count"] == 0
        assert result["case_results"][0]["outcome"] == "TP"

    def test_016_missed_positive_is_fn(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[])
        assert result["false_negative_count"] == 1
        assert result["true_positive_count"] == 0
        assert result["case_results"][0]["outcome"] == "FN"

    def test_017_wrong_vulnerability_class_is_fn(self):
        finding = _finding(vulnerability_class="cors_misconfiguration")
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[finding])
        assert result["false_negative_count"] == 1

    def test_018_wrong_path_is_fn(self):
        finding = _finding(affected_path="/other")
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[finding])
        assert result["false_negative_count"] == 1

    def test_019_match_hint_present_in_title_matches(self):
        case = _case(evidence_requirement={"affected_path": "/", "match_hint": "Content-Security-Policy"})
        result = evaluate_benchmark(ground_truth=_ground_truth(case), findings=[_finding()])
        assert result["true_positive_count"] == 1

    def test_020_match_hint_present_in_evidence_observation_matches(self):
        case = _case(evidence_requirement={"affected_path": "/", "match_hint": "did not include"})
        result = evaluate_benchmark(ground_truth=_ground_truth(case), findings=[_finding()])
        assert result["true_positive_count"] == 1

    def test_021_match_hint_absent_from_both_is_fn(self):
        case = _case(evidence_requirement={"affected_path": "/", "match_hint": "X-Frame-Options"})
        result = evaluate_benchmark(ground_truth=_ground_truth(case), findings=[_finding()])
        assert result["false_negative_count"] == 1

    def test_022_case_id_tracked_in_case_results(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case(case_id="MY-CASE")), findings=[_finding()])
        assert result["case_results"][0]["case_id"] == "MY-CASE"

    def test_023_matched_finding_id_recorded(self):
        finding = _finding(finding_id="BB15A-ABC")
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[finding])
        assert result["case_results"][0]["matched_finding_id"] == "BB15A-ABC"

    def test_024_multiple_positive_cases_independent_outcomes(self):
        case_a = _case(case_id="A", evidence_requirement={"affected_path": "/", "match_hint": None})
        case_b = _case(
            case_id="B", detector_capability="cors_misconfiguration",
            evidence_requirement={"affected_path": "/", "match_hint": None},
        )
        result = evaluate_benchmark(ground_truth=_ground_truth(case_a, case_b), findings=[_finding()])
        outcomes = {c["case_id"]: c["outcome"] for c in result["case_results"]}
        assert outcomes == {"A": "TP", "B": "FN"}


# ---------------------------------------------------------------------------
# FP / TN (negative cases)
# ---------------------------------------------------------------------------


class TestNegativeCases:
    def _negative_case(self, **overrides):
        case = _case(
            case_id="T-NEG", expected_detection=False, expected_severity=None,
            expected_observation="Should not be flagged.",
        )
        case.update(overrides)
        return case

    def test_025_negative_correctly_silent_is_tn(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(self._negative_case()), findings=[])
        assert result["true_negative_count"] == 1
        assert result["false_positive_count"] == 0
        assert result["case_results"][0]["outcome"] == "TN"

    def test_026_negative_wrongly_flagged_is_fp(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(self._negative_case()), findings=[_finding()])
        assert result["false_positive_count"] == 1
        assert result["true_negative_count"] == 0
        assert result["case_results"][0]["outcome"] == "FP"

    def test_027_negative_case_unrelated_finding_present_is_still_tn(self):
        unrelated = _finding(
            vulnerability_class="cors_misconfiguration", finding_id="BB15A-OTHER",
            title="Notable CORS response headers observed",
            evidence=[_evidence(observation="Access-Control-Allow-Origin: *")],
        )
        result = evaluate_benchmark(ground_truth=_ground_truth(self._negative_case()), findings=[unrelated])
        assert result["true_negative_count"] == 1

    def test_028_negative_case_with_match_hint_disambiguates(self):
        case = self._negative_case(evidence_requirement={"affected_path": "/", "match_hint": "X-Frame-Options"})
        # A CSP finding at the same path must NOT trigger this X-Frame-Options negative case.
        result = evaluate_benchmark(ground_truth=_ground_truth(case), findings=[_finding()])
        assert result["true_negative_count"] == 1


# ---------------------------------------------------------------------------
# Precision / recall / F1 / null denominators
# ---------------------------------------------------------------------------


class TestMetrics:
    def test_029_precision_recall_f1_all_correct(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[_finding()])
        assert result["precision"] == pytest.approx(1.0)
        assert result["recall"] == pytest.approx(1.0)
        assert result["f1"] == pytest.approx(1.0)

    def test_030_recall_none_when_no_positive_and_no_negative_match(self):
        neg_case = _case(
            case_id="N", expected_detection=False, expected_severity=None,
            expected_observation="none expected",
        )
        result = evaluate_benchmark(ground_truth=_ground_truth(neg_case), findings=[])
        assert result["true_positive_count"] == 0
        assert result["false_negative_count"] == 0
        assert result["recall"] is None

    def test_031_precision_none_when_no_tp_and_no_fp(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[])
        assert result["true_positive_count"] == 0
        assert result["false_positive_count"] == 0
        assert result["precision"] is None

    def test_032_f1_none_when_precision_none(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[])
        assert result["precision"] is None
        assert result["f1"] is None

    def test_033_precision_with_fp_only_no_tp_is_zero(self):
        neg_case = _case(
            case_id="N", expected_detection=False, expected_severity=None,
            expected_observation="none expected",
        )
        result = evaluate_benchmark(ground_truth=_ground_truth(neg_case), findings=[_finding()])
        assert result["true_positive_count"] == 0
        assert result["false_positive_count"] == 1
        assert result["precision"] == pytest.approx(0.0)

    def test_034_partial_precision_and_recall(self):
        case_tp = _case(case_id="TP-CASE")
        case_fn = _case(
            case_id="FN-CASE", detector_capability="cors_misconfiguration",
            evidence_requirement={"affected_path": "/", "match_hint": None},
        )
        neg_fp = _case(
            case_id="FP-CASE", expected_detection=False, expected_severity=None,
            expected_observation="none expected",
            detector_capability="http_method_observation",
            evidence_requirement={"affected_path": "/", "match_hint": None},
        )
        extra_finding = _finding(
            finding_id="BB15A-EXTRA", vulnerability_class="http_method_observation",
            title="Potentially state-changing HTTP methods advertised",
            evidence=[_evidence(observation="Advertised HTTP methods included: DELETE.")],
        )
        result = evaluate_benchmark(
            ground_truth=_ground_truth(case_tp, case_fn, neg_fp), findings=[_finding(), extra_finding],
        )
        assert result["true_positive_count"] == 1
        assert result["false_negative_count"] == 1
        assert result["false_positive_count"] == 1
        assert result["precision"] == pytest.approx(0.5)
        assert result["recall"] == pytest.approx(0.5)
        assert result["f1"] == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Unmatched findings
# ---------------------------------------------------------------------------


class TestUnmatchedFindings:
    def test_035_finding_matching_no_case_is_unmatched(self):
        unrelated = _finding(
            finding_id="BB15A-UNRELATED", vulnerability_class="redirect_observation", affected_path="/foo",
            title="Redirect observed", evidence=[_evidence(observation="redirected")],
        )
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[_finding(), unrelated])
        assert result["unmatched_finding_count"] == 1
        assert result["unmatched_findings"][0]["finding_id"] == "BB15A-UNRELATED"

    def test_036_unmatched_finding_never_auto_classified_as_fp(self):
        unrelated = _finding(finding_id="BB15A-UNRELATED", vulnerability_class="redirect_observation")
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[unrelated])
        assert result["false_positive_count"] == 0

    def test_037_unmatched_findings_compact_identifiers_only(self):
        unrelated = _finding(finding_id="BB15A-UNRELATED", vulnerability_class="redirect_observation")
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[unrelated])
        assert set(result["unmatched_findings"][0].keys()) == {"finding_id", "vulnerability_class", "affected_path"}

    def test_038_matched_finding_not_counted_as_unmatched(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[_finding()])
        assert result["unmatched_finding_count"] == 0


# ---------------------------------------------------------------------------
# Severity agreement
# ---------------------------------------------------------------------------


class TestSeverityAgreement:
    def test_039_exact_severity_match(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case(expected_severity="medium")), findings=[_finding(technical_severity="medium")])
        assert result["severity_agreement"]["comparable_count"] == 1
        assert result["severity_agreement"]["exact_match_count"] == 1
        assert result["severity_agreement"]["rate"] == pytest.approx(1.0)

    def test_040_severity_mismatch(self):
        result = evaluate_benchmark(
            ground_truth=_ground_truth(_case(expected_severity="high")), findings=[_finding(technical_severity="medium")],
        )
        assert result["severity_agreement"]["comparable_count"] == 1
        assert result["severity_agreement"]["exact_match_count"] == 0
        assert result["severity_agreement"]["rate"] == pytest.approx(0.0)

    def test_041_severity_comparable_only_counts_tp(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[])
        assert result["severity_agreement"]["comparable_count"] == 0
        assert result["severity_agreement"]["rate"] is None

    def test_042_negative_case_never_counted_in_severity_agreement(self):
        neg_case = _case(
            case_id="N", expected_detection=False, expected_severity=None,
            expected_observation="none expected",
        )
        result = evaluate_benchmark(ground_truth=_ground_truth(neg_case), findings=[_finding()])
        assert result["severity_agreement"]["comparable_count"] == 0


# ---------------------------------------------------------------------------
# Evidence completeness
# ---------------------------------------------------------------------------


class TestEvidenceCompleteness:
    def test_043_complete_finding_counted(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[_finding()])
        assert result["evidence_completeness"]["complete_count"] == 1
        assert result["evidence_completeness"]["rate"] == pytest.approx(1.0)

    def test_044_empty_evidence_list_is_incomplete(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[_finding(evidence=[])])
        assert result["evidence_completeness"]["complete_count"] == 0

    def test_045_blank_observation_is_incomplete(self):
        finding = _finding(evidence=[_evidence(observation="   ")])
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[finding])
        assert result["evidence_completeness"]["complete_count"] == 0

    def test_046_malformed_digest_is_incomplete(self):
        finding = _finding(evidence=[_evidence(digest="not-a-digest")])
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[finding])
        assert result["evidence_completeness"]["complete_count"] == 0

    def test_047_rate_none_when_zero_findings(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[])
        assert result["evidence_completeness"]["finding_count"] == 0
        assert result["evidence_completeness"]["rate"] is None


# ---------------------------------------------------------------------------
# Supported detection coverage
# ---------------------------------------------------------------------------


class TestSupportedDetectionCoverage:
    def test_048_full_coverage(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[_finding()])
        coverage = result["supported_detection_coverage"]
        assert coverage["detected_positive_cases"] == 1
        assert coverage["positive_supported_cases"] == 1
        assert coverage["rate"] == pytest.approx(1.0)

    def test_049_zero_coverage(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[])
        assert result["supported_detection_coverage"]["rate"] == pytest.approx(0.0)

    def test_050_no_positive_cases_rate_none(self):
        neg_case = _case(
            case_id="N", expected_detection=False, expected_severity=None,
            expected_observation="none expected",
        )
        result = evaluate_benchmark(ground_truth=_ground_truth(neg_case), findings=[])
        assert result["supported_detection_coverage"]["positive_supported_cases"] == 0
        assert result["supported_detection_coverage"]["rate"] is None


# ---------------------------------------------------------------------------
# No fuzzy matching / duplicate handling / determinism / immutability
# ---------------------------------------------------------------------------


class TestNoFuzzyMatchingAndDuplicates:
    def test_051_match_hint_is_exact_substring_not_fuzzy(self):
        case = _case(evidence_requirement={"affected_path": "/", "match_hint": "Content Security Policy"})
        # Real title has a hyphenated "Content-Security-Policy" -- a fuzzy
        # matcher might consider these equivalent; this deterministic
        # substring check must not.
        result = evaluate_benchmark(ground_truth=_ground_truth(case), findings=[_finding()])
        assert result["false_negative_count"] == 1

    def test_052_case_sensitive_matching(self):
        case = _case(evidence_requirement={"affected_path": "/", "match_hint": "content-security-policy"})
        result = evaluate_benchmark(ground_truth=_ground_truth(case), findings=[_finding()])
        assert result["false_negative_count"] == 1

    def test_053_duplicate_findings_do_not_double_count_tp(self):
        finding_a = _finding(finding_id="BB15A-AAA")
        finding_b = _finding(finding_id="BB15A-BBB")
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[finding_a, finding_b])
        assert result["true_positive_count"] == 1

    def test_054_duplicate_case_id_across_calls_raises_consistently(self):
        gt = _ground_truth(_case(case_id="X"), _case(case_id="X", detector_capability="cors_misconfiguration"))
        with pytest.raises(BenchmarkEvaluationError):
            evaluate_benchmark(ground_truth=gt, findings=[])

    def test_055_deterministic_output(self):
        gt = _ground_truth(_case())
        findings = [_finding()]
        first = evaluate_benchmark(ground_truth=gt, findings=findings)
        second = evaluate_benchmark(ground_truth=gt, findings=findings)
        assert first == second

    def test_056_ground_truth_never_mutated(self):
        gt = _ground_truth(_case())
        snapshot = copy.deepcopy(gt)
        evaluate_benchmark(ground_truth=gt, findings=[_finding()])
        assert gt == snapshot

    def test_057_findings_never_mutated(self):
        findings = [_finding()]
        snapshot = copy.deepcopy(findings)
        evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=findings)
        assert findings == snapshot

    def test_058_output_holds_no_reference_to_input_lists(self):
        gt = _ground_truth(_case())
        result = evaluate_benchmark(ground_truth=gt, findings=[_finding()])
        gt["supported_cases"].append({"tampered": True})
        assert len(result["case_results"]) == 1


# ---------------------------------------------------------------------------
# Output contract
# ---------------------------------------------------------------------------


class TestOutputContract:
    def test_059_benchmark_version_is_one(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[])
        assert result["benchmark_version"] == "1"

    def test_060_execution_performed_always_false(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[])
        assert result["execution_performed"] is False

    def test_061_target_echoed(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case(), target="My Target"), findings=[])
        assert result["target"] == "My Target"

    def test_062_target_version_or_digest_echoed(self):
        result = evaluate_benchmark(
            ground_truth=_ground_truth(_case(), target_version_or_digest="sha256:" + "c" * 64), findings=[],
        )
        assert result["target_version_or_digest"] == "sha256:" + "c" * 64

    def test_063_supported_ground_truth_count_matches_case_count(self):
        result = evaluate_benchmark(
            ground_truth=_ground_truth(_case(case_id="A"), _case(case_id="B")), findings=[],
        )
        assert result["supported_ground_truth_count"] == 2

    def test_064_positive_and_negative_case_counts(self):
        neg_case = _case(
            case_id="N", expected_detection=False, expected_severity=None,
            expected_observation="none expected",
        )
        result = evaluate_benchmark(ground_truth=_ground_truth(_case(), neg_case), findings=[])
        assert result["positive_case_count"] == 1
        assert result["negative_case_count"] == 1

    def test_065_never_calls_this_overall_accuracy(self):
        result = evaluate_benchmark(ground_truth=_ground_truth(_case()), findings=[_finding()])
        rendered = " ".join(str(key) for key in result.keys())
        assert "overall_accuracy" not in rendered
        assert "accuracy" not in rendered


# ---------------------------------------------------------------------------
# REAL BASELINE -- Block 15F-A0 sanitized findings vs. the real ground truth
# ---------------------------------------------------------------------------


def _real_baseline_findings():
    """A sanitized, hand-transcribed representation of the six real
    findings observed in Block 15F-A0 against the live local Juice Shop
    container. No live HTTP call is made here -- this is a fixed,
    in-memory fixture only.
    """
    return [
        {
            "finding_id": "BB15A-274dac151a39e6a5",
            "vulnerability_class": "security_header_misconfiguration",
            "affected_path": "/",
            "title": "Missing Content-Security-Policy header",
            "technical_severity": "medium",
            "evidence": [_evidence(observation="Response did not include a Content-Security-Policy header.")],
        },
        {
            "finding_id": "BB15A-bd399b0d338e8c91",
            "vulnerability_class": "exposed_metadata",
            "affected_path": "/robots.txt",
            "title": "/robots.txt is present and publicly accessible",
            "technical_severity": "low",
            "evidence": [_evidence(observation="/robots.txt returned HTTP 200.")],
        },
        {
            "finding_id": "BB15A-cbeb1c6ab17bf423",
            "vulnerability_class": "exposed_metadata",
            "affected_path": "/sitemap.xml",
            "title": "/sitemap.xml is present and publicly accessible",
            "technical_severity": "low",
            "evidence": [_evidence(observation="/sitemap.xml returned HTTP 200.")],
        },
        {
            "finding_id": "BB15A-5409acafb495b8bf",
            "vulnerability_class": "exposed_metadata",
            "affected_path": "/.well-known/security.txt",
            "title": "/.well-known/security.txt is present and publicly accessible",
            "technical_severity": "low",
            "evidence": [_evidence(observation="/.well-known/security.txt returned HTTP 200.")],
        },
        {
            "finding_id": "BB15A-88908ee92f34917f",
            "vulnerability_class": "http_method_observation",
            "affected_path": "/",
            "title": "Potentially state-changing HTTP methods advertised",
            "technical_severity": "low",
            "evidence": [_evidence(observation="Advertised HTTP methods included: DELETE, PATCH, PUT.")],
        },
        {
            "finding_id": "BB15A-1ba9e220759091c8",
            "vulnerability_class": "cors_misconfiguration",
            "affected_path": "/",
            "title": "Notable CORS response headers observed",
            "technical_severity": "low",
            "evidence": [_evidence(observation="Access-Control-Allow-Origin: *")],
        },
    ]


class TestRealBaseline:
    def test_066_real_baseline_true_positive_count_is_five(self):
        result = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
        assert result["true_positive_count"] == 5

    def test_067_real_baseline_false_positive_count_is_one(self):
        result = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
        assert result["false_positive_count"] == 1

    def test_068_real_baseline_false_negative_count_is_zero(self):
        result = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
        assert result["false_negative_count"] == 0

    def test_069_real_baseline_true_negative_count_is_three(self):
        result = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
        assert result["true_negative_count"] == 3

    def test_070_real_baseline_precision(self):
        result = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
        assert result["precision"] == pytest.approx(5 / 6)

    def test_071_real_baseline_recall_is_one(self):
        result = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
        assert result["recall"] == pytest.approx(1.0)

    def test_072_real_baseline_f1(self):
        result = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
        expected_f1 = 2 * (5 / 6) * 1.0 / ((5 / 6) + 1.0)
        assert result["f1"] == pytest.approx(expected_f1)
        assert result["f1"] == pytest.approx(0.9090909091, abs=1e-9)

    def test_073_real_baseline_sitemap_is_the_fp(self):
        result = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
        fp_cases = [c for c in result["case_results"] if c["outcome"] == "FP"]
        assert len(fp_cases) == 1
        assert fp_cases[0]["case_id"] == "JS-SITEMAP-SPA-FALLBACK"
        assert fp_cases[0]["matched_finding_id"] == "BB15A-cbeb1c6ab17bf423"

    def test_074_real_baseline_no_unmatched_findings(self):
        result = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
        assert result["unmatched_finding_count"] == 0

    def test_075_real_baseline_supported_ground_truth_count_is_nine(self):
        result = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
        assert result["supported_ground_truth_count"] == 9

    def test_076_real_baseline_severity_agreement_full(self):
        result = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
        assert result["severity_agreement"]["comparable_count"] == 5
        assert result["severity_agreement"]["exact_match_count"] == 5
        assert result["severity_agreement"]["rate"] == pytest.approx(1.0)

    def test_077_real_baseline_evidence_completeness_full(self):
        result = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
        assert result["evidence_completeness"]["finding_count"] == 6
        assert result["evidence_completeness"]["complete_count"] == 6
        assert result["evidence_completeness"]["rate"] == pytest.approx(1.0)

    def test_078_real_baseline_supported_detection_coverage(self):
        result = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
        coverage = result["supported_detection_coverage"]
        assert coverage["detected_positive_cases"] == 5
        assert coverage["positive_supported_cases"] == 5
        assert coverage["rate"] == pytest.approx(1.0)

    def test_079_real_baseline_deterministic(self):
        first = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
        second = evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
        assert first == second

    def test_080_real_baseline_never_raises(self):
        # A false positive existing in the real baseline must never
        # itself cause an exception -- it is a normal, informative result.
        evaluate_benchmark(ground_truth=build_baseline_ground_truth(), findings=_real_baseline_findings())
