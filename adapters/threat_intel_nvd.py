"""Real, bounded NVD (National Vulnerability Database) CVE adapter
(Block 15H-I).

NVD is a public, unauthenticated (at low request volume), defensive
US-government CVE database -- this project's second `AUTHORITATIVE_SOURCES`
member (see `core.threat_intelligence`). This adapter performs one real,
bounded HTTP GET to NVD's own published REST API (`resultsPerPage`
bounds the request server-side, so this adapter never downloads more
than it asked for), and normalizes at most `limit` entries into
`core.threat_intelligence`'s common record contract.

## No authentication, no write access, one GET only

This adapter never sends a credential (an API key would only raise
NVD's own rate limit, never unlock private data -- NVD has no private
tier), never writes anything back to NVD, and performs at most one HTTP
request per call. All I/O is `http.client` only.

`ThreatIntelNvdAdapterError` and `fetch_nvd_records` are this module's
public symbols.
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
from typing import Any
from urllib.parse import urlencode

from core.threat_intelligence import validate_threat_intelligence_record

NVD_HOST = "services.nvd.nist.gov"
NVD_PATH = "/rest/json/cves/2.0"
NVD_CONNECT_TIMEOUT_SECONDS = 15.0
MAX_RESPONSE_BYTES = 4_194_304  # 4 MiB
MAX_LIMIT = 20

STATUS_VALUES = frozenset({"completed", "failed", "unavailable"})

_SEVERITY_TO_CONFIDENCE = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _extract_cvss_severity(cve: dict[str, Any]) -> str | None:
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if isinstance(entries, list) and entries:
            first = entries[0]
            if isinstance(first, dict):
                severity = first.get("baseSeverity") or (first.get("cvssData", {}) or {}).get("baseSeverity")
                if isinstance(severity, str):
                    return severity.upper()
    return None


def _extract_cwe_ids(cve: dict[str, Any]) -> list[str]:
    weaknesses = cve.get("weaknesses")
    if not isinstance(weaknesses, list):
        return []
    cwe_ids: list[str] = []
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        for description in weakness.get("description", []) or []:
            value = description.get("value") if isinstance(description, dict) else None
            if isinstance(value, str) and value.startswith("CWE-") and value not in cwe_ids:
                cwe_ids.append(value)
    return cwe_ids


def _extract_english_description(cve: dict[str, Any]) -> str | None:
    for description in cve.get("descriptions", []) or []:
        if isinstance(description, dict) and description.get("lang") == "en":
            value = description.get("value")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


class ThreatIntelNvdAdapterError(ValueError):
    """Raised only for a structurally invalid `limit`. Never raised for
    a real fetch failure -- that is `status: "failed"`/`"unavailable"`
    in the returned result, not an exception."""


def _normalize_nvd_entry(item: dict[str, Any]) -> dict[str, Any] | None:
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        return None
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not cve_id.strip():
        return None

    severity = _extract_cvss_severity(cve)
    confidence = _SEVERITY_TO_CONFIDENCE.get(severity or "", "medium")
    description = _extract_english_description(cve)

    raw = {
        "intel_version": "1",
        "intel_id": "TI-NVD-" + cve_id.strip(),
        "source_type": "nvd_cve",
        "source_name": "NVD (National Vulnerability Database)",
        "source_reference": f"https://nvd.nist.gov/vuln/detail/{cve_id.strip()}",
        "title": cve_id.strip(),
        "summary": description,
        "published_at": cve.get("published") if isinstance(cve.get("published"), str) else None,
        "modified_at": cve.get("lastModified") if isinstance(cve.get("lastModified"), str) else None,
        "observed_at": None,
        "cve": [cve_id.strip()],
        "cwe": _extract_cwe_ids(cve),
        "owasp": [],
        "affected_products": [],
        "affected_versions": [],
        "ioc": {"ip": [], "domain": [], "url": [], "file_hash": []},
        "actor": None,
        "campaign": None,
        "attack": {"tactic": [], "technique": [], "subtechnique": []},
        "behavioral_indicators": [],
        "exploitation_status": "unknown",
        "known_exploited": False,
        "epss_score": None,
        "confidence": confidence,
        "corroboration_state": "single_source",
        "evidence_references": [f"https://nvd.nist.gov/vuln/detail/{cve_id.strip()}"],
        "source_reliability": "high",
        "information_credibility": "high",
        "limitations": ["NVD does not itself confirm active exploitation -- see CISA KEV for that signal."],
    }
    return validate_threat_intelligence_record(record=raw)


def fetch_nvd_records(*, limit: Any, keyword_search: Any = None) -> dict[str, Any]:
    """Fetch at most `limit` recently-published CVEs from NVD's real,
    public REST API, normalized into `core.threat_intelligence`'s common
    record contract.

    `limit` is required and keyword-only, and must be a positive int not
    exceeding `MAX_LIMIT`. `keyword_search` is optional (default `None`)
    -- when supplied, must be a non-blank string passed to NVD's own
    `keywordSearch` query parameter unchanged (NVD performs the search,
    this adapter never filters client-side).

    Raises `ThreatIntelNvdAdapterError` for a structurally invalid
    `limit`/`keyword_search`.

    Returns a dict with `status` (one of `STATUS_VALUES`), `records`,
    `records_available` (NVD's own reported `totalResults`, `None` if
    the fetch failed), `source_reference`, `error_detail`,
    `execution_performed`.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > MAX_LIMIT:
        raise ThreatIntelNvdAdapterError(f"INVALID_LIMIT: limit must be a positive int not exceeding {MAX_LIMIT}")
    if keyword_search is not None and (not isinstance(keyword_search, str) or not keyword_search.strip()):
        raise ThreatIntelNvdAdapterError("INVALID_KEYWORD_SEARCH: keyword_search must be null or a non-blank string")

    query = {"resultsPerPage": str(limit)}
    if keyword_search:
        query["keywordSearch"] = keyword_search.strip()
    path = f"{NVD_PATH}?{urlencode(query)}"
    source_reference = f"https://{NVD_HOST}{path}"

    connection = None
    try:
        connection = http.client.HTTPSConnection(
            NVD_HOST, 443, timeout=NVD_CONNECT_TIMEOUT_SECONDS, context=ssl.create_default_context(),
        )
        connection.request("GET", path, headers={"User-Agent": "ThreatTrace-TI-Ingestion/1.0"})
        response = connection.getresponse()
        if response.status != 200:
            return {
                "status": "unavailable", "records": [], "records_available": None,
                "source_reference": source_reference, "error_detail": f"NVD returned HTTP {response.status}",
                "execution_performed": True,
            }
        raw_body = response.read(MAX_RESPONSE_BYTES + 1)[:MAX_RESPONSE_BYTES]
    except (OSError, socket.timeout, http.client.HTTPException):
        return {
            "status": "unavailable", "records": [], "records_available": None,
            "source_reference": source_reference, "error_detail": "NVD was unreachable",
            "execution_performed": True,
        }
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

    try:
        payload = json.loads(raw_body.decode("utf-8", errors="replace"))
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise ValueError("missing vulnerabilities list")
        total_results = payload.get("totalResults")
    except (json.JSONDecodeError, ValueError, AttributeError):
        return {
            "status": "failed", "records": [], "records_available": None,
            "source_reference": source_reference, "error_detail": "NVD response could not be parsed",
            "execution_performed": True,
        }

    normalized: list[dict[str, Any]] = []
    for item in vulnerabilities:
        if len(normalized) >= limit:
            break
        record = _normalize_nvd_entry(item) if isinstance(item, dict) else None
        if record is not None:
            normalized.append(record)

    return {
        "status": "completed", "records": normalized,
        "records_available": total_results if isinstance(total_results, int) else len(vulnerabilities),
        "source_reference": source_reference, "error_detail": None, "execution_performed": True,
    }
