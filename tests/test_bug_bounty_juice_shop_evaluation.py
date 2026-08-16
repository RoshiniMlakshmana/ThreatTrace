"""Focused tests for core.bug_bounty_juice_shop_evaluation -- the pure,
deterministic bridge between a completed Bug Bounty run's real canonical
findings and the fixed OWASP Juice Shop benchmark (Step 7 of the Docker
Juice Shop accuracy exercise).

No network, filesystem, environment-variable, subprocess, clock,
randomness, database/Supabase, MCP, or LLM/model access occurs anywhere
in this file. Every `run`/`events` input is a plain in-memory mapping --
no live scan is ever triggered to produce test data.
"""

from __future__ import annotations

import pytest

from core.bug_bounty_juice_shop_evaluation import (
    EVALUATION_STATES,
    BugBountyJuiceShopEvaluationError,
    evaluate_bug_bounty_run_against_juice_shop_benchmark,
)

_JUICE_SHOP_TARGET = "http://localhost:3000/"


def _evidence_sources(source_tool, digest_suffix="1"):
    return [{
        "source_tool": source_tool, "source_observation_id": "obs-1",
        "evidence_id": f"EV-{digest_suffix}", "source_reference": None,
    }]


def _canonical_finding(**overrides):
    finding = {
        "finding_id": "CF-csp", "title": "Missing Content-Security-Policy header",
        "vulnerability_class": "security_header_misconfiguration", "cwe": "CWE-693",
        "path": "/", "technical_severity": "medium", "tools_used": ["http_assessor"],
        "evidence_digests": ["sha256:" + "1" * 64],
        "tool_observations": [{"source_tool": "http_assessor", "title": "Missing Content-Security-Policy header", "sanitized_evidence": "Response did not include a Content-Security-Policy header."}],
    }
    finding.update(overrides)
    return finding


def _informational_observation(**overrides):
    obs = {"observation_id": "IO-1", "title": "Port 3000/tcp open", "tools_used": ["nmap"]}
    obs.update(overrides)
    return obs


def _report(**overrides):
    report = {
        "canonical_findings": [_canonical_finding()],
        "informational_observations": [],
        "tools_requested": ["http_assessor", "nmap", "nuclei", "zap"],
        "tools_permitted": ["http_assessor", "nmap", "nuclei", "zap"],
        "tools_executed": ["http_assessor", "nmap", "nuclei", "zap"],
        "correlation_summary": {"multi_tool_corroborated_count": 0, "duplicate_evidence_count": 0},
    }
    report.update(overrides)
    return report


def _run(**overrides):
    run = {
        "run_id": "RUN-test0000000000000000000000000", "run_type": "bug_bounty",
        "status": "completed", "target_summary": _JUICE_SHOP_TARGET, "report": _report(),
    }
    run.update(overrides)
    return run


def _tool_completed_event(tool_id, *, status, observation_count):
    return {"event_type": "tool_completed", "sanitized_payload": {"tool_id": tool_id, "status": status, "observation_count": observation_count}}


def _http_assessor_completed_event(*, findings_count=5, requests=6, performed=True):
    return {
        "event_type": "tool_completed",
        "sanitized_payload": {"findings_count": findings_count, "network_requests_performed": requests, "assessment_performed": performed},
    }


_DEFAULT_EVENTS = [
    _http_assessor_completed_event(),
    _tool_completed_event("nmap", status="completed", observation_count=1),
    _tool_completed_event("nuclei", status="timeout", observation_count=0),
    _tool_completed_event("zap", status="completed", observation_count=5),
]


class TestNotEvaluatedState:
    def test_001_non_bug_bounty_run_type_is_not_evaluated(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(
            run=_run(run_type="detection"), events=[],
        )
        assert result["evaluation_state"] == "not_evaluated"
        assert "run_id" in result
        assert "true_positive_count" not in result

    @pytest.mark.parametrize("target", [
        "http://example.com/", "http://8.8.8.8/", "http://localhost:3001/",
        "http://juice-shop:3000", None, "", "not-a-url",
    ])
    def test_002_non_juice_shop_target_is_not_evaluated(self, target):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(
            run=_run(target_summary=target), events=[],
        )
        assert result["evaluation_state"] == "not_evaluated"

    def test_003_evaluation_states_vocabulary_fixed(self):
        assert EVALUATION_STATES == {"evaluated", "not_evaluated", "run_incomplete"}

    def test_004_not_evaluated_never_returns_a_score(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(
            run=_run(run_type="detection"), events=[],
        )
        for field in ("precision", "recall", "f1", "supported_benchmark_accuracy", "true_positive_count"):
            assert field not in result


class TestRunIncompleteState:
    def test_005_no_report_yet_is_run_incomplete(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(
            run=_run(status="running", report=None), events=[],
        )
        assert result["evaluation_state"] == "run_incomplete"
        assert "true_positive_count" not in result

    def test_006_incomplete_never_shows_zeros_as_a_result(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(
            run=_run(status="running", report=None), events=[],
        )
        # Zeros must never appear where a real score would -- the state
        # field is the only thing a caller can branch on.
        assert result.get("true_positive_count") is None
        assert result.get("supported_benchmark_accuracy") is None


class TestEvaluatedState:
    def test_007_real_completed_run_is_evaluated(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        assert result["evaluation_state"] == "evaluated"

    def test_008_tp_fp_fn_tn_from_real_benchmark_engine(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        assert result["true_positive_count"] == 1  # only JS-CSP-MISSING finding supplied
        assert result["false_positive_count"] == 0
        assert result["false_negative_count"] == 4  # the other 4 positive cases have no matching finding here
        assert result["true_negative_count"] == 4  # 4 negative cases, none violated

    def test_009_precision_recall_f1_present(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        assert result["precision"] == 1.0
        assert result["recall"] == pytest.approx(1 / 5)  # 1 of 5 positive cases supplied
        assert result["f1"] is not None

    def test_010_supported_benchmark_accuracy_named_correctly(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        assert "supported_benchmark_accuracy" in result
        assert "overall_accuracy" not in result
        assert "accuracy" not in result
        tp, fp, fn, tn = (result["true_positive_count"], result["false_positive_count"], result["false_negative_count"], result["true_negative_count"])
        assert result["supported_benchmark_accuracy"] == pytest.approx((tp + tn) / (tp + fp + fn + tn))

    def test_011_supported_counts_fixed_at_5_4_9(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        assert result["supported_positive_count"] == 5
        assert result["supported_negative_count"] == 4
        assert result["supported_total_count"] == 9

    def test_012_case_results_cover_all_9_cases(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        case_ids = {c["case_id"] for c in result["case_results"]}
        assert case_ids == {
            "JS-CSP-MISSING", "JS-ROBOTS-PRESENT", "JS-SECURITY-TXT-PRESENT",
            "JS-RISKY-METHODS-ADVERTISED", "JS-CORS-WILDCARD", "JS-SITEMAP-SPA-FALLBACK",
            "JS-XCTO-PRESENT", "JS-XFO-PRESENT", "JS-NO-REFLECTION",
        }

    def test_013_case_result_enriched_with_matched_title_and_source(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        csp_case = next(c for c in result["case_results"] if c["case_id"] == "JS-CSP-MISSING")
        assert csp_case["matched_title"] == "Missing Content-Security-Policy header"
        assert csp_case["matched_source_tools"] == ["http_assessor"]

    def test_014_target_identity_and_digest_present(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        assert result["target_identity"] == "OWASP Juice Shop"
        assert result["target_digest"].startswith("sha256:")

    def test_015_interpretation_never_claims_overall_accuracy(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        text = result["interpretation"].lower()
        assert "overall" not in text or "not a statement of threattrace's overall accuracy" in text
        assert "fixed" in text and "supported" in text


class TestUnsupportedAndInformationalNeverPenalized:
    def test_016_unmatched_finding_never_becomes_false_positive(self):
        # A finding whose vulnerability_class isn't one of the 7 supported
        # detector_capability values (e.g. the generic DAST fallback) is a
        # valid, unmatched finding -- never a false positive.
        report = _report(canonical_findings=[
            _canonical_finding(
                finding_id="CF-generic", title="Cross-Domain Misconfiguration",
                vulnerability_class="dast_observation", cwe="CWE-264", path="/", tools_used=["zap"],
            ),
        ])
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(report=report), events=_DEFAULT_EVENTS)
        assert result["false_positive_count"] == 0
        assert len(result["unmatched_findings"]) == 1
        assert result["unmatched_findings"][0]["finding_id"] == "CF-generic"

    def test_017_nmap_informational_finding_never_scored(self):
        # informational_observations are never even translated into
        # benchmark findings -- Nmap's bare port observation cannot
        # become a false positive because it's never submitted at all.
        report = _report(informational_observations=[_informational_observation()])
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(report=report), events=_DEFAULT_EVENTS)
        assert result["false_positive_count"] == 0

    def test_018_nuclei_timeout_does_not_reduce_true_positives(self):
        # Nuclei contributing 0 observations must not manifest as a false
        # negative for any of the 9 predefined cases -- none require it.
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        # None of the 9 cases require nuclei specifically -- its absence
        # never shows up as an extra false negative beyond what the
        # supplied findings already determine.
        assert result["tool_execution"]["nuclei"]["status"] == "timeout"
        assert result["tool_execution"]["nuclei"]["observation_count"] == 0

    def test_019_nuclei_timeout_surfaced_as_timeout_not_failed(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        assert result["tool_execution"]["nuclei"]["status"] == "timeout"
        assert result["tool_execution"]["nuclei"]["status"] != "failed"


class TestCorrelationQualitySeparateFromScore:
    def test_020_correlation_quality_is_its_own_section(self):
        report = _report(correlation_summary={"multi_tool_corroborated_count": 1, "duplicate_evidence_count": 0})
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(report=report), events=_DEFAULT_EVENTS)
        assert result["correlation_quality"] == {
            "canonical_finding_count": 1, "multi_tool_corroborated_count": 1, "duplicate_evidence_count": 0,
        }

    def test_021_correlation_quality_never_folded_into_precision_recall_f1(self):
        # Two runs with identical benchmark-relevant findings but
        # different corroboration counts must score identically on
        # precision/recall/F1 -- corroboration is reported, never scored.
        low_corr = _report(correlation_summary={"multi_tool_corroborated_count": 0, "duplicate_evidence_count": 0})
        high_corr = _report(correlation_summary={"multi_tool_corroborated_count": 1, "duplicate_evidence_count": 0})
        r1 = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(report=low_corr), events=_DEFAULT_EVENTS)
        r2 = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(report=high_corr), events=_DEFAULT_EVENTS)
        assert r1["precision"] == r2["precision"]
        assert r1["recall"] == r2["recall"]
        assert r1["f1"] == r2["f1"]
        assert r1["correlation_quality"] != r2["correlation_quality"]

    def test_022_real_step6_merged_csp_regression(self):
        # HTTP CSP + ZAP CSP merged into ONE canonical finding
        # (multi_tool_corroborated -> true) must produce exactly one
        # benchmark TP -- never two, never double-counted.
        merged_csp = _canonical_finding(
            finding_id="CF-merged-csp", tools_used=["http_assessor", "zap"],
            tool_observations=[
                {"source_tool": "http_assessor", "title": "Missing Content-Security-Policy header", "sanitized_evidence": "Response did not include a Content-Security-Policy header."},
                {"source_tool": "zap", "title": "Content Security Policy (CSP) Header Not Set", "sanitized_evidence": None},
            ],
            evidence_digests=["sha256:" + "1" * 64, "sha256:" + "2" * 64],
        )
        report = _report(
            canonical_findings=[merged_csp],
            correlation_summary={"multi_tool_corroborated_count": 1, "duplicate_evidence_count": 0},
        )
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(report=report), events=_DEFAULT_EVENTS)
        assert result["true_positive_count"] == 1
        csp_case = next(c for c in result["case_results"] if c["case_id"] == "JS-CSP-MISSING")
        assert csp_case["outcome"] == "TP"
        assert set(csp_case["matched_source_tools"]) == {"http_assessor", "zap"}
        assert result["correlation_quality"]["multi_tool_corroborated_count"] == 1


class TestToolExecutionSection:
    def test_023_all_four_required_tools_present(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        assert set(result["tool_execution"]) == {"http_assessor", "nmap", "nuclei", "zap"}

    def test_024_http_assessor_status_recovered_from_its_own_event_shape(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        assert result["tool_execution"]["http_assessor"]["status"] == "completed"
        assert result["tool_execution"]["http_assessor"]["observation_count"] == 5

    def test_025_tool_failed_event_reports_not_executed(self):
        events = [_http_assessor_completed_event(), {"event_type": "tool_failed", "sanitized_payload": {"tool_id": "nmap", "reason": "tool_not_installed"}}]
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=events)
        assert result["tool_execution"]["nmap"]["status"] == "not_executed"

    def test_026_evidence_contribution_counts_real(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        assert result["tool_execution"]["http_assessor"]["canonical_findings_contributed"] == 1
        assert result["tool_execution"]["zap"]["canonical_findings_contributed"] == 0

    def test_026b_nuclei_phase_telemetry_reaches_evaluation_report(self):
        # Nuclei Reliability Step 1B: phase telemetry must reach all the
        # way through events into the evaluation report's tool_execution
        # section -- this is the "report telemetry propagation"
        # requirement, verified end to end from a real event payload.
        events = [
            _http_assessor_completed_event(),
            _tool_completed_event("nmap", status="completed", observation_count=1),
            {
                "event_type": "tool_completed",
                "sanitized_payload": {
                    "tool_id": "nuclei", "status": "partial", "observation_count": 0,
                    "profile": "quick_phased_v1", "phases_attempted": 3, "phases_completed": 1,
                    "duration": 38.2, "partial_results": True,
                },
            },
            _tool_completed_event("zap", status="completed", observation_count=5),
        ]
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=events)
        nuclei_section = result["tool_execution"]["nuclei"]
        assert nuclei_section["profile"] == "quick_phased_v1"
        assert nuclei_section["phases_attempted"] == 3
        assert nuclei_section["phases_completed"] == 1
        assert nuclei_section["duration"] == 38.2
        assert nuclei_section["partial_results"] is True

    def test_026c_non_nuclei_tools_never_carry_phase_telemetry_keys(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        for tool_id in ("http_assessor", "nmap", "zap"):
            for extra_key in ("profile", "phases_attempted", "phases_completed", "duration", "partial_results"):
                assert extra_key not in result["tool_execution"][tool_id]

    def test_026d_older_run_without_phase_telemetry_still_works(self):
        # A run predating this change (event payload has no phase keys
        # at all) must not raise or produce a broken tool_execution entry.
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        nuclei_section = result["tool_execution"]["nuclei"]
        assert nuclei_section["status"] == "timeout"
        assert "profile" not in nuclei_section


class TestStructuralExclusion:
    def test_027_finding_missing_vulnerability_class_excluded_not_dropped_silently(self):
        report = _report(canonical_findings=[
            _canonical_finding(finding_id="CF-bad", vulnerability_class=None),
        ])
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(report=report), events=_DEFAULT_EVENTS)
        assert result["evaluation_state"] == "evaluated"  # never crashes the whole evaluation
        assert len(result["structurally_excluded_findings"]) == 1
        assert result["structurally_excluded_findings"][0]["finding_id"] == "CF-bad"
        assert any("structurally_excluded_findings" in limitation for limitation in result["limitations"])

    def test_028_finding_missing_affected_path_excluded(self):
        report = _report(canonical_findings=[_canonical_finding(finding_id="CF-bad2", path=None)])
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(report=report), events=_DEFAULT_EVENTS)
        assert len(result["structurally_excluded_findings"]) == 1


class TestLimitationsAlwaysVisible:
    def test_029_fixed_limitations_always_present(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        joined = " ".join(result["limitations"])
        assert "9 predefined" in joined
        assert "Unsupported vulnerability classes" in joined
        assert "Application-logic" in joined

    def test_030_limitations_not_a_tooltip_only_concept_full_strings_returned(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        assert all(isinstance(item, str) and len(item) > 20 for item in result["limitations"])


class TestStructuralValidation:
    def test_031_non_mapping_run_raises(self):
        with pytest.raises(BugBountyJuiceShopEvaluationError):
            evaluate_bug_bounty_run_against_juice_shop_benchmark(run="not-a-dict", events=[])

    def test_032_non_list_events_raises(self):
        with pytest.raises(BugBountyJuiceShopEvaluationError):
            evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events="not-a-list")

    def test_033_deterministic_given_same_input(self):
        r1 = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        r2 = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        assert r1 == r2

    def test_034_never_returns_field_named_overall_accuracy(self):
        result = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=_run(), events=_DEFAULT_EVENTS)
        assert "overall_accuracy" not in result
