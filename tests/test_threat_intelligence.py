"""Focused tests for core.threat_intelligence -- the pure, deterministic
normalized Threat Intelligence contract + corroboration model (Block 15H-I).

No network, filesystem, environment-variable, subprocess, clock,
randomness, database/Supabase, MCP, or LLM/model access occurs anywhere
in this file.
"""

from __future__ import annotations

import pytest

from core.threat_intelligence import (
    AUTHORITATIVE_SOURCES,
    TI_RECORD_REQUIRED_FIELDS,
    ThreatIntelligenceError,
    compute_corroboration,
    validate_threat_intelligence_record,
)


def _record(**overrides):
    record = {
        "intel_version": "1", "intel_id": "TI-0001", "source_type": "public_osint",
        "source_name": "Example Feed", "source_reference": "https://example.test/feed/1",
        "title": "Example vulnerability report", "summary": None,
        "published_at": "2026-08-01T00:00:00Z", "modified_at": None, "observed_at": "2026-08-14T00:00:00Z",
        "cve": ["CVE-2026-0001"], "cwe": [], "owasp": [], "affected_products": [], "affected_versions": [],
        "ioc": {"ip": [], "domain": [], "url": [], "file_hash": []},
        "actor": None, "campaign": None,
        "attack": {"tactic": [], "technique": [], "subtechnique": []},
        "behavioral_indicators": [],
        "exploitation_status": "unknown", "known_exploited": False, "epss_score": None,
        "confidence": "medium", "corroboration_state": "single_source",
        "evidence_references": ["https://example.test/feed/1"],
        "source_reliability": "medium", "information_credibility": "medium",
        "limitations": [],
    }
    record.update(overrides)
    return record


# ---------------------------------------------------------------------------
# Record normalization -- KEV-style / CVE-NVD-style / EPSS-style / malformed
# ---------------------------------------------------------------------------


class TestRecordNormalization:
    def test_001_valid_record_normalized(self):
        result = validate_threat_intelligence_record(record=_record())
        assert result["intel_id"] == "TI-0001"
        assert result["cve"] == ["CVE-2026-0001"]

    def test_002_kev_style_record(self):
        record = _record(
            source_type="cisa_kev", source_name="CISA KEV", known_exploited=True,
            exploitation_status="exploited_in_wild", confidence="high",
            source_reliability="high", information_credibility="high",
        )
        result = validate_threat_intelligence_record(record=record)
        assert result["known_exploited"] is True
        assert result["source_type"] == "cisa_kev"

    def test_003_nvd_cve_style_record(self):
        record = _record(
            source_type="nvd_cve", source_name="NVD", cwe=["CWE-89"], owasp=["A03:2021"],
        )
        result = validate_threat_intelligence_record(record=record)
        assert result["cwe"] == ["CWE-89"]

    def test_004_epss_style_record(self):
        record = _record(source_type="epss", source_name="FIRST EPSS", epss_score=0.87421)
        result = validate_threat_intelligence_record(record=record)
        assert result["epss_score"] == pytest.approx(0.87421)

    def test_005_epss_score_out_of_range_rejected(self):
        with pytest.raises(ThreatIntelligenceError):
            validate_threat_intelligence_record(record=_record(epss_score=1.5))

    def test_006_taxii_source_type_accepted(self):
        result = validate_threat_intelligence_record(record=_record(source_type="taxii", source_name="Example TAXII"))
        assert result["source_type"] == "taxii"

    def test_007_misp_source_type_accepted(self):
        result = validate_threat_intelligence_record(record=_record(source_type="misp", source_name="Example MISP"))
        assert result["source_type"] == "misp"

    def test_008_opencti_source_type_accepted(self):
        result = validate_threat_intelligence_record(record=_record(source_type="opencti", source_name="Example OpenCTI"))
        assert result["source_type"] == "opencti"

    def test_009_telegram_public_osint_source_type_accepted(self):
        result = validate_threat_intelligence_record(record=_record(source_type="telegram_public_osint", source_name="Public channel"))
        assert result["source_type"] == "telegram_public_osint"

    def test_010_malformed_missing_field_raises(self):
        bad = _record()
        del bad["cve"]
        with pytest.raises(ThreatIntelligenceError):
            validate_threat_intelligence_record(record=bad)

    def test_011_unknown_extra_field_raises(self):
        bad = _record(unexpected="x")
        with pytest.raises(ThreatIntelligenceError):
            validate_threat_intelligence_record(record=bad)

    def test_012_unrecognized_source_type_raises(self):
        with pytest.raises(ThreatIntelligenceError):
            validate_threat_intelligence_record(record=_record(source_type="dark_web_market"))

    def test_013_malformed_ioc_shape_raises(self):
        bad = _record(ioc={"ip": []})
        with pytest.raises(ThreatIntelligenceError):
            validate_threat_intelligence_record(record=bad)

    def test_014_malformed_attack_shape_raises(self):
        bad = _record(attack={"tactic": []})
        with pytest.raises(ThreatIntelligenceError):
            validate_threat_intelligence_record(record=bad)

    def test_015_ioc_and_attack_values_preserved(self):
        record = _record(
            ioc={"ip": ["10.0.0.1"], "domain": ["evil.test"], "url": [], "file_hash": []},
            attack={"tactic": ["TA0001"], "technique": ["T1190"], "subtechnique": []},
        )
        result = validate_threat_intelligence_record(record=record)
        assert result["ioc"]["ip"] == ["10.0.0.1"]
        assert result["attack"]["technique"] == ["T1190"]

    def test_016_unknown_fields_never_invented_stay_null(self):
        result = validate_threat_intelligence_record(record=_record(actor=None, campaign=None, summary=None))
        assert result["actor"] is None
        assert result["campaign"] is None
        assert result["summary"] is None

    def test_017_evidence_references_preserved(self):
        record = _record(evidence_references=["https://a.test", "https://b.test"])
        result = validate_threat_intelligence_record(record=record)
        assert result["evidence_references"] == ["https://a.test", "https://b.test"]

    def test_018_exact_output_contract_fields(self):
        result = validate_threat_intelligence_record(record=_record())
        assert set(result.keys()) == set(TI_RECORD_REQUIRED_FIELDS)

    def test_019_record_never_mutated(self):
        import copy
        record = _record()
        snapshot = copy.deepcopy(record)
        validate_threat_intelligence_record(record=record)
        assert record == snapshot


# ---------------------------------------------------------------------------
# Corroboration
# ---------------------------------------------------------------------------


class TestCorroboration:
    def test_020_authoritative_source_kev_plus_nvd(self):
        kev = _record(intel_id="TI-A", source_type="cisa_kev", cve=["CVE-2026-1111"], known_exploited=True)
        nvd = _record(intel_id="TI-B", source_type="nvd_cve", cve=["CVE-2026-1111"], known_exploited=True)
        result = compute_corroboration(records=[kev, nvd])
        assert all(r["corroboration_state"] == "authoritative_source" for r in result)
        assert "cisa_kev" in AUTHORITATIVE_SOURCES

    def test_021_single_source_osint_is_single_source_or_unconfirmed(self):
        post = _record(
            intel_id="TI-C", source_type="telegram_public_osint", cve=["CVE-2026-2222"],
            source_reliability="low", information_credibility="low",
        )
        result = compute_corroboration(records=[post])
        assert result[0]["corroboration_state"] == "unconfirmed"

    def test_022_single_source_reasonably_reliable_is_single_source(self):
        post = _record(
            intel_id="TI-D", source_type="public_osint", cve=["CVE-2026-3333"],
            source_reliability="medium", information_credibility="medium",
        )
        result = compute_corroboration(records=[post])
        assert result[0]["corroboration_state"] == "single_source"

    def test_023_multi_source_agreement_without_authoritative_source_is_corroborated(self):
        a = _record(intel_id="TI-E", source_type="public_osint", cve=["CVE-2026-4444"], known_exploited=False)
        b = _record(intel_id="TI-F", source_type="misp", cve=["CVE-2026-4444"], known_exploited=False)
        result = compute_corroboration(records=[a, b])
        assert all(r["corroboration_state"] == "corroborated" for r in result)

    def test_024_conflicting_known_exploited_claims(self):
        a = _record(intel_id="TI-G", source_type="public_osint", cve=["CVE-2026-5555"], known_exploited=True)
        b = _record(intel_id="TI-H", source_type="misp", cve=["CVE-2026-5555"], known_exploited=False)
        result = compute_corroboration(records=[a, b])
        assert all(r["corroboration_state"] == "conflicting" for r in result)

    def test_025_llm_cannot_assign_corroboration_state_directly(self):
        # Even if a caller pre-sets corroboration_state to something
        # else, compute_corroboration always recomputes it from scratch.
        post = _record(intel_id="TI-I", source_type="telegram_public_osint", cve=["CVE-2026-6666"], corroboration_state="authoritative_source")
        result = compute_corroboration(records=[post])
        assert result[0]["corroboration_state"] != "authoritative_source"

    def test_026_grouping_falls_back_to_ioc_when_no_cve(self):
        a = _record(intel_id="TI-J", source_type="public_osint", cve=[], ioc={"ip": ["1.2.3.4"], "domain": [], "url": [], "file_hash": []})
        b = _record(intel_id="TI-K", source_type="misp", cve=[], ioc={"ip": ["1.2.3.4"], "domain": [], "url": [], "file_hash": []})
        result = compute_corroboration(records=[a, b])
        assert all(r["corroboration_state"] == "corroborated" for r in result)

    def test_027_grouping_falls_back_to_intel_id_when_no_cve_or_ioc(self):
        a = _record(intel_id="TI-L", source_type="public_osint", cve=[])
        result = compute_corroboration(records=[a])
        assert result[0]["corroboration_state"] in ("single_source", "unconfirmed")

    def test_028_non_list_records_raises(self):
        with pytest.raises(ThreatIntelligenceError):
            compute_corroboration(records="not-a-list")

    def test_029_malformed_record_in_batch_raises(self):
        with pytest.raises(ThreatIntelligenceError):
            compute_corroboration(records=[{"bad": "shape"}])

    def test_030_records_and_nested_values_never_mutated(self):
        import copy
        records = [_record(intel_id="TI-M", cve=["CVE-2026-7777"])]
        snapshot = copy.deepcopy(records)
        compute_corroboration(records=records)
        assert records == snapshot

    def test_031_deterministic_given_same_input(self):
        records = [
            _record(intel_id="TI-N", source_type="cisa_kev", cve=["CVE-2026-8888"]),
            _record(intel_id="TI-O", source_type="nvd_cve", cve=["CVE-2026-8888"]),
        ]
        first = compute_corroboration(records=records)
        second = compute_corroboration(records=records)
        assert first == second

    def test_032_other_fields_preserved_unchanged(self):
        record = _record(intel_id="TI-P", title="Preserved title")
        result = compute_corroboration(records=[record])
        assert result[0]["title"] == "Preserved title"
