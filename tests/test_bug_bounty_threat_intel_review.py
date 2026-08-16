"""Tests for core.bug_bounty_threat_intel_review -- the bounded,
per-finding Threat Intelligence review boundary.

NO real network access occurs anywhere in this file -- `nvd_fetch` is
always an injected fake."""

from __future__ import annotations

import pytest

from core.bug_bounty_threat_intel_review import (
    OUTCOMES,
    REVIEW_VERSION,
    ThreatIntelReviewError,
    review_threat_intelligence_for_finding,
)

_RESULT_FIELDS = {
    "review_version", "finding_id", "queried_cve", "outcome", "real_query_performed",
    "references", "stage_evaluated", "human_review_required", "execution_performed",
}


def _finding(**overrides):
    finding = {"finding_id": "CF-1", "cve": []}
    finding.update(overrides)
    return finding


def _never_call(**kwargs):
    raise AssertionError("nvd_fetch must never be called for a finding with no CVE")


class TestContract:
    def test_001_result_has_exact_fields(self):
        result = review_threat_intelligence_for_finding(canonical_finding=_finding(), nvd_fetch=_never_call)
        assert set(result.keys()) == _RESULT_FIELDS

    def test_002_execution_performed_always_false(self):
        result = review_threat_intelligence_for_finding(canonical_finding=_finding(), nvd_fetch=_never_call)
        assert result["execution_performed"] is False

    def test_003_stage_evaluated_always_true(self):
        result = review_threat_intelligence_for_finding(canonical_finding=_finding(), nvd_fetch=_never_call)
        assert result["stage_evaluated"] is True

    def test_004_version_is_1(self):
        result = review_threat_intelligence_for_finding(canonical_finding=_finding(), nvd_fetch=_never_call)
        assert result["review_version"] == REVIEW_VERSION == "1"

    def test_005_rejects_non_mapping(self):
        with pytest.raises(ThreatIntelReviewError):
            review_threat_intelligence_for_finding(canonical_finding="not a finding", nvd_fetch=_never_call)

    def test_006_rejects_missing_finding_id(self):
        with pytest.raises(ThreatIntelReviewError):
            review_threat_intelligence_for_finding(canonical_finding={"cve": []}, nvd_fetch=_never_call)


class TestNoCveCase:
    def test_007_empty_cve_list_is_no_relevant_intel(self):
        result = review_threat_intelligence_for_finding(canonical_finding=_finding(cve=[]), nvd_fetch=_never_call)
        assert result["outcome"] == "no_relevant_intel"

    def test_008_missing_cve_key_is_no_relevant_intel(self):
        finding = {"finding_id": "CF-1"}
        result = review_threat_intelligence_for_finding(canonical_finding=finding, nvd_fetch=_never_call)
        assert result["outcome"] == "no_relevant_intel"

    def test_009_no_network_call_ever_attempted(self):
        # _never_call raises AssertionError if invoked -- reaching this
        # line without a raise IS the assertion.
        review_threat_intelligence_for_finding(canonical_finding=_finding(cve=[]), nvd_fetch=_never_call)

    def test_010_real_query_performed_is_false(self):
        result = review_threat_intelligence_for_finding(canonical_finding=_finding(cve=[]), nvd_fetch=_never_call)
        assert result["real_query_performed"] is False

    def test_011_queried_cve_is_none(self):
        result = review_threat_intelligence_for_finding(canonical_finding=_finding(cve=[]), nvd_fetch=_never_call)
        assert result["queried_cve"] is None

    def test_012_no_relevant_intel_never_treated_as_error(self):
        # A successful, honest evaluation -- never an exception.
        result = review_threat_intelligence_for_finding(canonical_finding=_finding(cve=[]), nvd_fetch=_never_call)
        assert result["outcome"] in OUTCOMES


class TestGenuineCveCase:
    def test_013_hit_is_reviewed_relevant_with_real_reference(self):
        def fake_fetch(*, limit, keyword_search=None):
            return {"status": "completed", "records": [
                {"cve": [keyword_search], "source_reference": f"https://nvd.nist.gov/vuln/detail/{keyword_search}"},
            ]}

        result = review_threat_intelligence_for_finding(
            canonical_finding=_finding(cve=["CVE-2021-44228"]), nvd_fetch=fake_fetch,
        )
        assert result["outcome"] == "reviewed_relevant"
        assert result["real_query_performed"] is True
        assert result["references"] == ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]

    def test_014_only_first_cve_queried(self):
        calls = []

        def fake_fetch(*, limit, keyword_search=None):
            calls.append(keyword_search)
            return {"status": "completed", "records": []}

        review_threat_intelligence_for_finding(
            canonical_finding=_finding(cve=["CVE-2021-1", "CVE-2021-2"]), nvd_fetch=fake_fetch,
        )
        assert calls == ["CVE-2021-1"]

    def test_015_query_uses_exact_cve_id_not_free_text(self):
        captured = {}

        def fake_fetch(*, limit, keyword_search=None):
            captured["keyword_search"] = keyword_search
            return {"status": "completed", "records": []}

        review_threat_intelligence_for_finding(canonical_finding=_finding(cve=["CVE-2021-44228"]), nvd_fetch=fake_fetch)
        assert captured["keyword_search"] == "CVE-2021-44228"

    def test_016_miss_is_reviewed_no_match_distinct_from_no_relevant_intel(self):
        def fake_fetch(*, limit, keyword_search=None):
            return {"status": "completed", "records": []}

        result = review_threat_intelligence_for_finding(canonical_finding=_finding(cve=["CVE-2021-1"]), nvd_fetch=fake_fetch)
        assert result["outcome"] == "reviewed_no_match"
        assert result["real_query_performed"] is True

    def test_017_non_matching_record_ignored(self):
        def fake_fetch(*, limit, keyword_search=None):
            return {"status": "completed", "records": [{"cve": ["CVE-9999-9999"], "source_reference": "x"}]}

        result = review_threat_intelligence_for_finding(canonical_finding=_finding(cve=["CVE-2021-1"]), nvd_fetch=fake_fetch)
        assert result["outcome"] == "reviewed_no_match"

    def test_018_unreachable_source_is_reviewed_no_match_not_a_crash(self):
        def fake_fetch(*, limit, keyword_search=None):
            return {"status": "unavailable", "records": []}

        result = review_threat_intelligence_for_finding(canonical_finding=_finding(cve=["CVE-2021-1"]), nvd_fetch=fake_fetch)
        assert result["outcome"] == "reviewed_no_match"

    def test_019_nvd_fetch_exception_never_propagates(self):
        def raising_fetch(*, limit, keyword_search=None):
            raise RuntimeError("simulated network failure")

        result = review_threat_intelligence_for_finding(canonical_finding=_finding(cve=["CVE-2021-1"]), nvd_fetch=raising_fetch)
        assert result["outcome"] == "reviewed_no_match"

    def test_020_never_claims_success_with_threat_found_language(self):
        # Regression guard: this module's own docstring/summary must
        # never conflate "stage completed" with "threat found."
        import inspect

        import core.bug_bounty_threat_intel_review as module
        source = inspect.getsource(module)
        assert "completed successfully with threat found" not in source
