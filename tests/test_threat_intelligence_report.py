"""Focused tests for core.threat_intelligence_report (Block 15H-I)."""

from __future__ import annotations

import pytest

from core.threat_intelligence import compute_corroboration
from core.threat_intelligence_report import (
    ThreatIntelligenceReportError,
    build_threat_intelligence_report,
)


def _record(**overrides):
    record = {
        "intel_version": "1", "intel_id": "TI-0001", "source_type": "public_osint",
        "source_name": "Example Feed", "source_reference": "https://example.test/feed/1",
        "title": "Example vulnerability report", "summary": None,
        "published_at": None, "modified_at": None, "observed_at": None,
        "cve": ["CVE-2026-0001"], "cwe": [], "owasp": [], "affected_products": [], "affected_versions": [],
        "ioc": {"ip": [], "domain": [], "url": [], "file_hash": []},
        "actor": None, "campaign": None, "attack": {"tactic": [], "technique": [], "subtechnique": []},
        "behavioral_indicators": [], "exploitation_status": "unknown", "known_exploited": False, "epss_score": None,
        "confidence": "medium", "corroboration_state": "single_source",
        "evidence_references": ["https://example.test/feed/1"],
        "source_reliability": "medium", "information_credibility": "medium", "limitations": [],
    }
    record.update(overrides)
    return record


def _fetch_result(status="completed", records=None, source_reference="https://example.test"):
    return {
        "status": status, "records": records or [], "records_available": len(records or []),
        "source_reference": source_reference, "error_detail": None, "execution_performed": True,
    }


class TestThreatIntelligenceReport:
    def test_001_sources_split_successful_and_unavailable(self):
        result = build_threat_intelligence_report(
            source_fetch_results=[
                {"source_name": "cisa_kev", "result": _fetch_result(status="completed")},
                {"source_name": "taxii", "result": _fetch_result(status="not_evaluated", source_reference=None)},
            ],
            corroborated_records=[], retrieved_at="2026-08-14T00:00:00Z",
        )
        assert result["sources_successful"] == ["cisa_kev"]
        assert result["sources_unavailable"] == ["taxii"]
        assert result["sources_queried"] == ["cisa_kev", "taxii"]

    def test_002_records_ingested_counted_from_successful_sources_only(self):
        records = [_record(intel_id="TI-A"), _record(intel_id="TI-B")]
        result = build_threat_intelligence_report(
            source_fetch_results=[{"source_name": "cisa_kev", "result": _fetch_result(records=records)}],
            corroborated_records=records, retrieved_at="t",
        )
        assert result["records_ingested"] == 2

    def test_003_duplicates_removed_counts_exact_intel_id_repeats_only(self):
        records = [_record(intel_id="TI-A"), _record(intel_id="TI-A")]
        result = build_threat_intelligence_report(
            source_fetch_results=[], corroborated_records=records, retrieved_at="t",
        )
        assert result["duplicates_removed"] == 1
        assert result["records_normalized"] == 1

    def test_004_cross_source_corroboration_never_counted_as_duplicate(self):
        kev = _record(intel_id="TI-KEV-CVE-2026-0001", source_type="cisa_kev", cve=["CVE-2026-0001"])
        nvd = _record(intel_id="TI-NVD-CVE-2026-0001", source_type="nvd_cve", cve=["CVE-2026-0001"])
        corroborated = compute_corroboration(records=[kev, nvd])
        result = build_threat_intelligence_report(source_fetch_results=[], corroborated_records=corroborated, retrieved_at="t")
        assert result["duplicates_removed"] == 0
        assert result["records_normalized"] == 2

    def test_005_cve_summary_unique(self):
        records = [_record(intel_id="TI-A", cve=["CVE-2026-0001"]), _record(intel_id="TI-B", cve=["CVE-2026-0001", "CVE-2026-0002"])]
        result = build_threat_intelligence_report(source_fetch_results=[], corroborated_records=records, retrieved_at="t")
        assert result["cve_summary"]["total_unique_cve"] == 2

    def test_006_kev_summary_only_known_exploited(self):
        exploited = _record(intel_id="TI-A", known_exploited=True, cve=["CVE-2026-0001"])
        not_exploited = _record(intel_id="TI-B", known_exploited=False, cve=["CVE-2026-0002"])
        result = build_threat_intelligence_report(
            source_fetch_results=[], corroborated_records=[exploited, not_exploited], retrieved_at="t",
        )
        assert result["kev_summary"]["known_exploited_count"] == 1
        assert result["kev_summary"]["cve_ids"] == ["CVE-2026-0001"]

    def test_007_high_priority_summary_authoritative_or_exploited(self):
        record = _record(intel_id="TI-A", corroboration_state="authoritative_source")
        result = build_threat_intelligence_report(source_fetch_results=[], corroborated_records=[record], retrieved_at="t")
        assert len(result["high_priority_summary"]) == 1

    def test_008_low_priority_single_source_not_in_high_priority(self):
        record = _record(intel_id="TI-A", corroboration_state="single_source", known_exploited=False)
        result = build_threat_intelligence_report(source_fetch_results=[], corroborated_records=[record], retrieved_at="t")
        assert result["high_priority_summary"] == []

    def test_009_corroboration_state_distribution(self):
        records = [_record(intel_id="TI-A", corroboration_state="single_source"), _record(intel_id="TI-B", corroboration_state="corroborated")]
        result = build_threat_intelligence_report(source_fetch_results=[], corroborated_records=records, retrieved_at="t")
        assert result["corroboration_state_distribution"] == {"single_source": 1, "corroborated": 1}

    def test_010_limitations_note_unavailable_sources(self):
        result = build_threat_intelligence_report(
            source_fetch_results=[{"source_name": "misp", "result": _fetch_result(status="not_evaluated", source_reference=None)}],
            corroborated_records=[], retrieved_at="t",
        )
        assert any("misp" in item for item in result["limitations"])

    def test_011_retrieved_at_echoed(self):
        result = build_threat_intelligence_report(source_fetch_results=[], corroborated_records=[], retrieved_at="2026-08-14T12:00:00Z")
        assert result["retrieved_at"] == "2026-08-14T12:00:00Z"

    def test_012_zero_records_is_valid_not_error(self):
        result = build_threat_intelligence_report(source_fetch_results=[], corroborated_records=[], retrieved_at="t")
        assert result["records_ingested"] == 0
        assert result["records_normalized"] == 0

    def test_013_invalid_source_fetch_results_raises(self):
        with pytest.raises(ThreatIntelligenceReportError):
            build_threat_intelligence_report(source_fetch_results="not-a-list", corroborated_records=[], retrieved_at="t")

    def test_014_invalid_corroborated_records_raises(self):
        with pytest.raises(ThreatIntelligenceReportError):
            build_threat_intelligence_report(source_fetch_results=[], corroborated_records=[{"bad": "shape"}], retrieved_at="t")

    def test_015_source_references_collected(self):
        result = build_threat_intelligence_report(
            source_fetch_results=[{"source_name": "cisa_kev", "result": _fetch_result(source_reference="https://cisa.test/kev")}],
            corroborated_records=[], retrieved_at="t",
        )
        assert "https://cisa.test/kev" in result["source_references"]

    def test_016_deterministic_given_same_input(self):
        records = [_record(intel_id="TI-A")]
        first = build_threat_intelligence_report(source_fetch_results=[], corroborated_records=records, retrieved_at="t")
        second = build_threat_intelligence_report(source_fetch_results=[], corroborated_records=records, retrieved_at="t")
        assert first == second

    def test_017_never_mutates_input(self):
        import copy
        records = [_record(intel_id="TI-A")]
        snapshot = copy.deepcopy(records)
        build_threat_intelligence_report(source_fetch_results=[], corroborated_records=records, retrieved_at="t")
        assert records == snapshot
