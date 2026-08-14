"""Focused tests for the Threat Intelligence source adapters (Block
15H-I): CISA KEV, NVD, EPSS (real HTTP, mocked in every test here), and
the four honest not_configured boundary adapters (TAXII/MISP/OpenCTI/
Telegram).
"""

from __future__ import annotations

import json

import pytest

from adapters.threat_intel_cisa_kev import (
    MAX_LIMIT as KEV_MAX_LIMIT,
    ThreatIntelCisaKevAdapterError,
    fetch_cisa_kev_records,
)
from adapters.threat_intel_configured_sources import (
    MISP_API_KEY_ENV_VAR,
    OPENCTI_API_KEY_ENV_VAR,
    TAXII_API_KEY_ENV_VAR,
    TELEGRAM_BOT_TOKEN_ENV_VAR,
    ThreatIntelConfiguredSourceError,
    fetch_misp_records,
    fetch_opencti_records,
    fetch_taxii_records,
    fetch_telegram_public_osint_records,
)
from adapters.threat_intel_epss import ThreatIntelEpssAdapterError, fetch_epss_records
from adapters.threat_intel_nvd import ThreatIntelNvdAdapterError, fetch_nvd_records


class _FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def read(self, _n=None):
        return self._body


class _FakeConnection:
    def __init__(self, status, body):
        self._response = _FakeResponse(status, body)

    def request(self, *args, **kwargs):
        pass

    def getresponse(self):
        return self._response

    def close(self):
        pass


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

_KEV_BODY = json.dumps({
    "vulnerabilities": [
        {"cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "Widget",
         "vulnerabilityName": "Acme Widget RCE", "shortDescription": "RCE in Acme Widget", "dateAdded": "2026-08-01"},
        {"cveID": "CVE-2026-0002", "vendorProject": "Acme", "product": "Gadget",
         "vulnerabilityName": "Acme Gadget XSS", "shortDescription": "XSS in Acme Gadget", "dateAdded": "2026-08-05"},
    ],
}).encode("utf-8")


class TestCisaKev:
    def test_001_successful_fetch_normalized(self, monkeypatch):
        monkeypatch.setattr(
            "adapters.threat_intel_cisa_kev.http.client.HTTPSConnection",
            lambda *a, **kw: _FakeConnection(200, _KEV_BODY),
        )
        result = fetch_cisa_kev_records(limit=5)
        assert result["status"] == "completed"
        assert len(result["records"]) == 2
        assert result["records"][0]["cve"] == ["CVE-2026-0002"]  # most-recently-added first
        assert result["records"][0]["known_exploited"] is True
        assert result["records"][0]["source_type"] == "cisa_kev"

    def test_002_limit_truncates(self, monkeypatch):
        monkeypatch.setattr(
            "adapters.threat_intel_cisa_kev.http.client.HTTPSConnection",
            lambda *a, **kw: _FakeConnection(200, _KEV_BODY),
        )
        result = fetch_cisa_kev_records(limit=1)
        assert len(result["records"]) == 1

    def test_003_http_error_reports_unavailable(self, monkeypatch):
        monkeypatch.setattr(
            "adapters.threat_intel_cisa_kev.http.client.HTTPSConnection",
            lambda *a, **kw: _FakeConnection(503, b""),
        )
        result = fetch_cisa_kev_records(limit=5)
        assert result["status"] == "unavailable"
        assert result["records"] == []

    def test_004_connection_failure_reports_unavailable(self, monkeypatch):
        def raise_oserror(*a, **kw):
            raise OSError("connection refused")
        monkeypatch.setattr("adapters.threat_intel_cisa_kev.http.client.HTTPSConnection", raise_oserror)
        result = fetch_cisa_kev_records(limit=5)
        assert result["status"] == "unavailable"

    def test_005_malformed_json_reports_failed(self, monkeypatch):
        monkeypatch.setattr(
            "adapters.threat_intel_cisa_kev.http.client.HTTPSConnection",
            lambda *a, **kw: _FakeConnection(200, b"not json"),
        )
        result = fetch_cisa_kev_records(limit=5)
        assert result["status"] == "failed"

    def test_006_invalid_limit_raises(self):
        with pytest.raises(ThreatIntelCisaKevAdapterError):
            fetch_cisa_kev_records(limit=0)
        with pytest.raises(ThreatIntelCisaKevAdapterError):
            fetch_cisa_kev_records(limit=KEV_MAX_LIMIT + 1)

    def test_007_execution_performed_true_on_attempt(self, monkeypatch):
        monkeypatch.setattr(
            "adapters.threat_intel_cisa_kev.http.client.HTTPSConnection",
            lambda *a, **kw: _FakeConnection(200, _KEV_BODY),
        )
        result = fetch_cisa_kev_records(limit=5)
        assert result["execution_performed"] is True


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

_NVD_BODY = json.dumps({
    "totalResults": 1,
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2026-1234",
            "published": "2026-08-01T00:00:00.000",
            "lastModified": "2026-08-02T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Example CVE description."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
            "weaknesses": [{"description": [{"value": "CWE-79"}]}],
        },
    }],
}).encode("utf-8")


class TestNvd:
    def test_008_successful_fetch_normalized(self, monkeypatch):
        monkeypatch.setattr(
            "adapters.threat_intel_nvd.http.client.HTTPSConnection", lambda *a, **kw: _FakeConnection(200, _NVD_BODY),
        )
        result = fetch_nvd_records(limit=5)
        assert result["status"] == "completed"
        assert result["records"][0]["cve"] == ["CVE-2026-1234"]
        assert result["records"][0]["cwe"] == ["CWE-79"]
        assert result["records"][0]["confidence"] == "high"

    def test_009_keyword_search_passed_through(self, monkeypatch):
        captured = {}

        def fake_connection(*a, **kw):
            return _FakeConnection(200, _NVD_BODY)

        class SpyConnection(_FakeConnection):
            def request(self, method, path, **kwargs):
                captured["path"] = path

        monkeypatch.setattr(
            "adapters.threat_intel_nvd.http.client.HTTPSConnection",
            lambda *a, **kw: SpyConnection(200, _NVD_BODY),
        )
        fetch_nvd_records(limit=5, keyword_search="log4j")
        assert "keywordSearch=log4j" in captured["path"]

    def test_010_invalid_limit_raises(self):
        with pytest.raises(ThreatIntelNvdAdapterError):
            fetch_nvd_records(limit=-1)

    def test_011_blank_keyword_search_raises(self):
        with pytest.raises(ThreatIntelNvdAdapterError):
            fetch_nvd_records(limit=5, keyword_search="  ")

    def test_012_http_error_reports_unavailable(self, monkeypatch):
        monkeypatch.setattr(
            "adapters.threat_intel_nvd.http.client.HTTPSConnection", lambda *a, **kw: _FakeConnection(429, b""),
        )
        result = fetch_nvd_records(limit=5)
        assert result["status"] == "unavailable"

    def test_013_no_confirmed_exploitation_claimed(self, monkeypatch):
        monkeypatch.setattr(
            "adapters.threat_intel_nvd.http.client.HTTPSConnection", lambda *a, **kw: _FakeConnection(200, _NVD_BODY),
        )
        result = fetch_nvd_records(limit=5)
        assert result["records"][0]["known_exploited"] is False


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------

_EPSS_BODY = json.dumps({
    "total": 1, "data": [{"cve": "CVE-2026-5555", "epss": "0.87421", "percentile": "0.99", "date": "2026-08-14"}],
}).encode("utf-8")


class TestEpss:
    def test_014_successful_fetch_normalized(self, monkeypatch):
        monkeypatch.setattr(
            "adapters.threat_intel_epss.http.client.HTTPSConnection", lambda *a, **kw: _FakeConnection(200, _EPSS_BODY),
        )
        result = fetch_epss_records(limit=5)
        assert result["status"] == "completed"
        assert result["records"][0]["epss_score"] == pytest.approx(0.87421)
        assert result["records"][0]["known_exploited"] is False  # EPSS is a probability, never confirmed exploitation

    def test_015_high_score_yields_poc_available_never_exploited(self, monkeypatch):
        monkeypatch.setattr(
            "adapters.threat_intel_epss.http.client.HTTPSConnection", lambda *a, **kw: _FakeConnection(200, _EPSS_BODY),
        )
        result = fetch_epss_records(limit=5)
        assert result["records"][0]["exploitation_status"] == "poc_available"
        assert result["records"][0]["source_type"] == "epss"

    def test_016_cve_ids_filter_requires_nonempty_list(self):
        with pytest.raises(ThreatIntelEpssAdapterError):
            fetch_epss_records(limit=5, cve_ids=[])

    def test_017_invalid_limit_raises(self):
        with pytest.raises(ThreatIntelEpssAdapterError):
            fetch_epss_records(limit=0)

    def test_018_malformed_response_reports_failed(self, monkeypatch):
        monkeypatch.setattr(
            "adapters.threat_intel_epss.http.client.HTTPSConnection", lambda *a, **kw: _FakeConnection(200, b"{}"),
        )
        result = fetch_epss_records(limit=5)
        assert result["status"] == "failed"

    def test_019_epss_never_in_authoritative_sources(self):
        from core.threat_intelligence import AUTHORITATIVE_SOURCES
        assert "epss" not in AUTHORITATIVE_SOURCES


# ---------------------------------------------------------------------------
# Configured-source boundaries (TAXII / MISP / OpenCTI / Telegram)
# ---------------------------------------------------------------------------


class TestConfiguredSourceBoundaries:
    @pytest.mark.parametrize(
        "fetch_fn,env_var",
        [
            (fetch_taxii_records, TAXII_API_KEY_ENV_VAR),
            (fetch_misp_records, MISP_API_KEY_ENV_VAR),
            (fetch_opencti_records, OPENCTI_API_KEY_ENV_VAR),
            (fetch_telegram_public_osint_records, TELEGRAM_BOT_TOKEN_ENV_VAR),
        ],
    )
    def test_020_not_configured_without_env_var(self, monkeypatch, fetch_fn, env_var):
        monkeypatch.delenv(env_var, raising=False)
        result = fetch_fn(limit=5)
        assert result["runtime_status"] == "not_configured"
        assert result["execution_performed"] is False
        assert result["records"] == []

    def test_021_invalid_limit_raises_for_each(self):
        for fetch_fn in (fetch_taxii_records, fetch_misp_records, fetch_opencti_records, fetch_telegram_public_osint_records):
            with pytest.raises(ThreatIntelConfiguredSourceError):
                fetch_fn(limit=0)

    def test_022_telegram_never_fabricates_live_ingestion_even_when_env_var_present(self, monkeypatch):
        monkeypatch.setenv(TELEGRAM_BOT_TOKEN_ENV_VAR, "fake-token")
        result = fetch_telegram_public_osint_records(limit=5)
        assert result["records"] == []
        assert result["execution_performed"] is False

    def test_023_no_network_attempted_for_any_boundary_adapter(self, monkeypatch):
        called = {"count": 0}

        def spy(*a, **kw):
            called["count"] += 1
            raise AssertionError("should never be called")

        monkeypatch.setattr("http.client.HTTPSConnection", spy)
        monkeypatch.setattr("http.client.HTTPConnection", spy)
        for fetch_fn in (fetch_taxii_records, fetch_misp_records, fetch_opencti_records, fetch_telegram_public_osint_records):
            fetch_fn(limit=5)
        assert called["count"] == 0
