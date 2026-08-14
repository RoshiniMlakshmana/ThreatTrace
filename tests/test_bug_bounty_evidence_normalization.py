"""Focused tests for core.bug_bounty_evidence_normalization -- the pure,
deterministic multi-tool evidence normalizer (Block 15G-CD).

No network, filesystem, environment-variable, subprocess, clock,
randomness, database/Supabase, MCP, or LLM/model access occurs anywhere
in this file. Every input is a plain in-memory mapping.
"""

from __future__ import annotations

import pytest

from core.bug_bounty_evidence_normalization import (
    EVIDENCE_REQUIRED_FIELDS,
    BugBountyEvidenceNormalizationError,
    normalize_bug_bounty_evidence,
)

_SCOPE = "http://localhost:3000"
_OBSERVED_AT = "2026-08-14T12:00:00Z"


def _http_result(**overrides):
    finding = {
        "finding_id": "BB15A-abc123",
        "target": "http://localhost:3000/",
        "affected_path": "/",
        "affected_parameter": None,
        "title": "Missing Content-Security-Policy header",
        "finding_status": "validated",
        "vulnerability_class": "security_header_misconfiguration",
        "owasp_category": "A05:2021 Security Misconfiguration",
        "cwe": "CWE-693",
        "technical_severity": "medium",
        "confidence": "high",
        "evidence": [{
            "method": "GET", "scoped_url": "http://localhost:3000/", "status_code": 200,
            "observation": "Response did not include a Content-Security-Policy header.",
            "evidence_digest": "sha256:" + "a" * 64,
        }],
        "validation": {"method": "deterministic_header_presence_check", "confirmed": True},
    }
    finding.update(overrides)
    return {"assessment_version": "1", "target": "http://localhost:3000/", "testing_profile": "passive", "findings": [finding]}


def _nmap_result(**overrides):
    result = {
        "tool_result_version": "1", "tool_id": "nmap", "request_id": "REQ-1", "target": "localhost",
        "status": "completed",
        "observations": [{"type": "service", "port": 3000, "protocol": "tcp", "state": "open", "service": "http", "product": None, "version": None}],
        "evidence_references": ["nmap_xml_sha256:" + "b" * 64],
        "execution_performed": True,
    }
    result.update(overrides)
    return result


def _nuclei_result(**overrides):
    result = {
        "tool_result_version": "1", "tool_id": "nuclei", "request_id": "REQ-1", "target": "http://localhost:3000/",
        "status": "completed",
        "observations": [{
            "type": "known_pattern_match", "template_id": "exposed-panel", "title": "Exposed Admin Panel",
            "severity": "medium", "target": "http://localhost:3000/admin", "matcher": "status-200",
            "classification": {"cve_id": ["CVE-2021-1234"], "cwe_id": ["CWE-200"]},
        }],
        "evidence_references": ["nuclei_jsonl_sha256:" + "c" * 64],
        "execution_performed": True,
    }
    result.update(overrides)
    return result


def _zap_result(**overrides):
    result = {
        "tool_result_version": "1", "tool_id": "zap", "request_id": "REQ-1", "target": "http://localhost:3000/",
        "status": "completed", "capability": "passive_only",
        "observations": [{
            "tool_id": "zap", "observation_type": "dast_observation", "rule_id": "10038",
            "title": "Content Security Policy (CSP) Header Not Set", "risk": "Medium", "confidence": "High",
            "url": "http://localhost:3000/", "path": "/", "parameter": None, "method": "GET",
            "cwe": "CWE-693", "owasp_category": None, "evidence_reference": "zap_alert_sha256:" + "d" * 64,
            "sanitized_evidence": "", "source_tool_metadata": {"plugin_id": "10038"},
        }],
        "execution_performed": True,
    }
    result.update(overrides)
    return result


def _burp_result(**overrides):
    result = {
        "tool_result_version": "1", "tool_id": "burp_dast", "request_id": "REQ-1", "target": "http://localhost:3000/",
        "adapter_status": "implemented", "runtime_status": "available", "status": "completed", "source": "imported_result",
        "observations": [{
            "tool_id": "burp_dast", "observation_type": "dast_observation", "rule_id": "5243392",
            "title": "Cross-site scripting (reflected)", "risk": "High", "confidence": "Firm",
            "url": "http://localhost:3000/search?q=x", "path": "/search", "parameter": "q", "method": "GET",
            "cwe": "CWE-79", "owasp_category": None, "evidence_reference": "burp_issue_sha256:" + "e" * 64,
            "sanitized_evidence": "reflected", "source_tool_metadata": {"issue_type": "5243392"},
        }],
        "execution_performed": False,
    }
    result.update(overrides)
    return result


def _entry(source_tool, result):
    return {"source_tool": source_tool, "result": result}


# ---------------------------------------------------------------------------
# HTTP assessor normalization
# ---------------------------------------------------------------------------


class TestHttpAssessorNormalization:
    def test_001_finding_normalized(self):
        records = normalize_bug_bounty_evidence(
            source_results=[_entry("http_assessor", _http_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT,
        )
        r = records[0]
        assert r["source_tool"] == "http_assessor"
        assert r["source_observation_id"] == "BB15A-abc123"
        assert r["title"] == "Missing Content-Security-Policy header"
        assert r["vulnerability_class"] == "security_header_misconfiguration"
        assert r["cwe"] == "CWE-693"
        assert r["owasp_category"] == "A05:2021 Security Misconfiguration"
        assert r["technical_severity"] == "medium"
        assert r["confidence"] == "high"
        assert r["host"] == "localhost"
        assert r["scheme"] == "http"
        assert r["path"] == "/"
        assert r["method"] == "GET"
        assert r["validation_state"] == "tool_confirmed"
        assert r["sanitized_evidence"] == "Response did not include a Content-Security-Policy header."
        assert r["source_reference"] == "sha256:" + "a" * 64

    def test_002_unconfirmed_finding_is_unvalidated(self):
        result = _http_result()
        result["findings"][0]["validation"] = {"method": None, "confirmed": False}
        records = normalize_bug_bounty_evidence(source_results=[_entry("http_assessor", result)], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records[0]["validation_state"] == "unvalidated"

    def test_003_multiple_findings_all_normalized(self):
        result = _http_result()
        second = dict(result["findings"][0], finding_id="BB15A-def456", title="Second finding")
        result["findings"].append(second)
        records = normalize_bug_bounty_evidence(source_results=[_entry("http_assessor", result)], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert len(records) == 2

    def test_004_no_cve_field_yields_empty_list(self):
        records = normalize_bug_bounty_evidence(source_results=[_entry("http_assessor", _http_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records[0]["cve"] == []


# ---------------------------------------------------------------------------
# Nmap normalization
# ---------------------------------------------------------------------------


class TestNmapNormalization:
    def test_005_observation_normalized(self):
        records = normalize_bug_bounty_evidence(source_results=[_entry("nmap", _nmap_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        r = records[0]
        assert r["source_tool"] == "nmap"
        assert r["observation_type"] == "service"
        assert r["host"] == "localhost"
        assert r["port"] == 3000
        assert r["service"] == "http"
        assert r["validation_state"] == "tool_asserted"
        assert r["technical_severity"] is None  # nmap has no severity concept -- never invented
        assert r["cve"] == []
        assert "3000" in r["title"]

    def test_006_null_product_version_preserved_as_null(self):
        records = normalize_bug_bounty_evidence(source_results=[_entry("nmap", _nmap_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records[0]["product"] is None
        assert records[0]["version"] is None

    def test_007_product_version_carried_through_when_present(self):
        result = _nmap_result()
        result["observations"][0]["product"] = "Juice Shop"
        result["observations"][0]["version"] = "17.0"
        records = normalize_bug_bounty_evidence(source_results=[_entry("nmap", result)], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records[0]["product"] == "Juice Shop"
        assert records[0]["version"] == "17.0"

    def test_008_empty_observations_yields_no_records(self):
        result = _nmap_result(observations=[])
        records = normalize_bug_bounty_evidence(source_results=[_entry("nmap", result)], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records == []

    def test_009_evidence_source_reference_carried_through(self):
        records = normalize_bug_bounty_evidence(source_results=[_entry("nmap", _nmap_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records[0]["source_reference"] == "nmap_xml_sha256:" + "b" * 64


# ---------------------------------------------------------------------------
# Nuclei normalization
# ---------------------------------------------------------------------------


class TestNucleiNormalization:
    def test_010_observation_normalized(self):
        records = normalize_bug_bounty_evidence(source_results=[_entry("nuclei", _nuclei_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        r = records[0]
        assert r["source_tool"] == "nuclei"
        assert r["source_observation_id"] == "exposed-panel"
        assert r["title"] == "Exposed Admin Panel"
        assert r["technical_severity"] == "medium"
        assert r["cwe"] == "CWE-200"
        assert r["cve"] == ["CVE-2021-1234"]
        assert r["host"] == "localhost"
        assert r["path"] == "/admin"
        assert r["validation_state"] == "tool_asserted"

    def test_011_info_severity_maps_to_none(self):
        result = _nuclei_result()
        result["observations"][0]["severity"] = "info"
        records = normalize_bug_bounty_evidence(source_results=[_entry("nuclei", result)], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records[0]["technical_severity"] is None

    def test_012_missing_classification_yields_null_cwe_and_empty_cve(self):
        result = _nuclei_result()
        result["observations"][0]["classification"] = None
        records = normalize_bug_bounty_evidence(source_results=[_entry("nuclei", result)], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records[0]["cwe"] is None
        assert records[0]["cve"] == []

    def test_013_confidence_always_none_nuclei_has_no_concept(self):
        records = normalize_bug_bounty_evidence(source_results=[_entry("nuclei", _nuclei_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records[0]["confidence"] is None


# ---------------------------------------------------------------------------
# ZAP normalization
# ---------------------------------------------------------------------------


class TestZapNormalization:
    def test_014_observation_normalized(self):
        records = normalize_bug_bounty_evidence(source_results=[_entry("zap", _zap_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        r = records[0]
        assert r["source_tool"] == "zap"
        assert r["source_observation_id"] == "10038"
        assert r["title"] == "Content Security Policy (CSP) Header Not Set"
        assert r["technical_severity"] == "medium"
        assert r["confidence"] == "high"
        assert r["cwe"] == "CWE-693"
        assert r["url"] == "http://localhost:3000/"
        assert r["path"] == "/"
        assert r["method"] == "GET"
        assert r["source_reference"] == "zap_alert_sha256:" + "d" * 64

    def test_015_informational_risk_maps_to_none(self):
        result = _zap_result()
        result["observations"][0]["risk"] = "Informational"
        records = normalize_bug_bounty_evidence(source_results=[_entry("zap", result)], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records[0]["technical_severity"] is None

    def test_016_empty_observations_yields_no_records(self):
        result = _zap_result(observations=[])
        records = normalize_bug_bounty_evidence(source_results=[_entry("zap", result)], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records == []

    def test_017_sanitized_evidence_carried_through(self):
        result = _zap_result()
        result["observations"][0]["sanitized_evidence"] = "some excerpt"
        records = normalize_bug_bounty_evidence(source_results=[_entry("zap", result)], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records[0]["sanitized_evidence"] == "some excerpt"


# ---------------------------------------------------------------------------
# Burp normalization
# ---------------------------------------------------------------------------


class TestBurpNormalization:
    def test_018_observation_normalized(self):
        records = normalize_bug_bounty_evidence(source_results=[_entry("burp_dast", _burp_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        r = records[0]
        assert r["source_tool"] == "burp_dast"
        assert r["source_observation_id"] == "5243392"
        assert r["title"] == "Cross-site scripting (reflected)"
        assert r["technical_severity"] == "high"
        assert r["confidence"] == "medium"  # Burp "Firm" -> medium
        assert r["parameter"] == "q"
        assert r["cwe"] == "CWE-79"

    def test_019_burp_confidence_vocabulary_distinct_from_zap(self):
        # "Firm" only means something under Burp's own confidence
        # vocabulary -- confirms the two tools use separate mapping
        # tables, never a shared one that would misinterpret either.
        result = _burp_result()
        result["observations"][0]["confidence"] = "Certain"
        records = normalize_bug_bounty_evidence(source_results=[_entry("burp_dast", result)], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records[0]["confidence"] == "high"

    def test_020_unavailable_runtime_result_yields_no_records(self):
        result = _burp_result(observations=[], status="not_evaluated", runtime_status="configured_external_runtime_required")
        records = normalize_bug_bounty_evidence(source_results=[_entry("burp_dast", result)], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records == []


# ---------------------------------------------------------------------------
# Cross-cutting: scope_reference / observed_at / determinism / contract
# ---------------------------------------------------------------------------


class TestCrossCutting:
    def test_021_scope_reference_echoed_on_every_record(self):
        records = normalize_bug_bounty_evidence(
            source_results=[_entry("http_assessor", _http_result()), _entry("nmap", _nmap_result())],
            scope_reference=_SCOPE, observed_at=_OBSERVED_AT,
        )
        assert all(r["scope_reference"] == _SCOPE for r in records)

    def test_022_observed_at_applied_to_first_and_last(self):
        records = normalize_bug_bounty_evidence(source_results=[_entry("nmap", _nmap_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records[0]["first_observed"] == _OBSERVED_AT
        assert records[0]["last_observed"] == _OBSERVED_AT

    def test_023_multiple_sources_all_normalized_together(self):
        records = normalize_bug_bounty_evidence(
            source_results=[
                _entry("http_assessor", _http_result()), _entry("nmap", _nmap_result()),
                _entry("nuclei", _nuclei_result()), _entry("zap", _zap_result()), _entry("burp_dast", _burp_result()),
            ],
            scope_reference=_SCOPE, observed_at=_OBSERVED_AT,
        )
        assert len(records) == 5
        assert {r["source_tool"] for r in records} == {"http_assessor", "nmap", "nuclei", "zap", "burp_dast"}

    def test_024_evidence_digest_stable_for_same_input(self):
        first = normalize_bug_bounty_evidence(source_results=[_entry("nmap", _nmap_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        second = normalize_bug_bounty_evidence(source_results=[_entry("nmap", _nmap_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert first[0]["evidence_digest"] == second[0]["evidence_digest"]
        assert first[0]["evidence_id"] == second[0]["evidence_id"]

    def test_024b_distinct_content_never_collides_evidence_id_even_with_same_tool_rule_url_title(self):
        # Real bug discovered during this checkpoint's own live ZAP
        # validation: two alerts sharing tool/rule/url/title but with
        # genuinely different underlying evidence text must never
        # collide on evidence_id (or a correlation-layer consumer
        # indexing by evidence_id would silently lose one of them).
        result = _zap_result()
        result["observations"] = [
            dict(result["observations"][0], sanitized_evidence="Cache-Control: public, max-age=0"),
            dict(result["observations"][0], sanitized_evidence="ETag: W/somethingelse"),
        ]
        records = normalize_bug_bounty_evidence(source_results=[_entry("zap", result)], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert len(records) == 2
        assert records[0]["evidence_id"] != records[1]["evidence_id"]
        assert records[0]["evidence_digest"] != records[1]["evidence_digest"]

    def test_025_evidence_digest_changes_with_content(self):
        first = normalize_bug_bounty_evidence(source_results=[_entry("nmap", _nmap_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        changed = _nmap_result()
        changed["observations"][0]["port"] = 3001
        second = normalize_bug_bounty_evidence(source_results=[_entry("nmap", changed)], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert first[0]["evidence_digest"] != second[0]["evidence_digest"]

    def test_026_evidence_digest_format(self):
        records = normalize_bug_bounty_evidence(source_results=[_entry("nmap", _nmap_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records[0]["evidence_digest"].startswith("sha256:")
        assert len(records[0]["evidence_digest"]) == len("sha256:") + 64

    def test_027_evidence_id_format(self):
        records = normalize_bug_bounty_evidence(source_results=[_entry("nmap", _nmap_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records[0]["evidence_id"].startswith("EV-")
        assert len(records[0]["evidence_id"]) == len("EV-") + 16

    def test_028_exact_field_contract(self):
        records = normalize_bug_bounty_evidence(source_results=[_entry("nmap", _nmap_result())], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert set(records[0].keys()) == set(EVIDENCE_REQUIRED_FIELDS)

    def test_029_execution_performed_always_false(self):
        records = normalize_bug_bounty_evidence(
            source_results=[_entry("http_assessor", _http_result()), _entry("zap", _zap_result())],
            scope_reference=_SCOPE, observed_at=_OBSERVED_AT,
        )
        assert all(r["execution_performed"] is False for r in records)

    def test_030_empty_source_results_yields_empty_list(self):
        records = normalize_bug_bounty_evidence(source_results=[], scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert records == []

    def test_031_source_results_and_nested_values_never_mutated(self):
        import copy
        source = [_entry("nmap", _nmap_result())]
        snapshot = copy.deepcopy(source)
        normalize_bug_bounty_evidence(source_results=source, scope_reference=_SCOPE, observed_at=_OBSERVED_AT)
        assert source == snapshot


# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------


class TestStructuralValidation:
    def test_032_non_list_source_results_raises(self):
        with pytest.raises(BugBountyEvidenceNormalizationError):
            normalize_bug_bounty_evidence(source_results="not-a-list", scope_reference=_SCOPE, observed_at=_OBSERVED_AT)

    def test_033_blank_scope_reference_raises(self):
        with pytest.raises(BugBountyEvidenceNormalizationError):
            normalize_bug_bounty_evidence(source_results=[], scope_reference="   ", observed_at=_OBSERVED_AT)

    def test_034_unrecognized_source_tool_raises(self):
        with pytest.raises(BugBountyEvidenceNormalizationError):
            normalize_bug_bounty_evidence(
                source_results=[{"source_tool": "metasploit", "result": {}}], scope_reference=_SCOPE, observed_at=_OBSERVED_AT,
            )

    def test_035_entry_missing_result_field_raises(self):
        with pytest.raises(BugBountyEvidenceNormalizationError):
            normalize_bug_bounty_evidence(
                source_results=[{"source_tool": "nmap"}], scope_reference=_SCOPE, observed_at=_OBSERVED_AT,
            )

    def test_036_malformed_nmap_result_raises(self):
        with pytest.raises(BugBountyEvidenceNormalizationError):
            normalize_bug_bounty_evidence(
                source_results=[_entry("nmap", {"no_observations_field": True})], scope_reference=_SCOPE, observed_at=_OBSERVED_AT,
            )

    def test_037_malformed_http_assessor_result_raises(self):
        with pytest.raises(BugBountyEvidenceNormalizationError):
            normalize_bug_bounty_evidence(
                source_results=[_entry("http_assessor", {"no_findings_field": True})], scope_reference=_SCOPE, observed_at=_OBSERVED_AT,
            )
