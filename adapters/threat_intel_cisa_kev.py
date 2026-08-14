"""Real, bounded CISA Known Exploited Vulnerabilities (KEV) catalog
adapter (Block 15H-I).

CISA KEV is a public, unauthenticated, defensive US-government catalog
of vulnerabilities confirmed to be actively exploited -- one of this
project's two `AUTHORITATIVE_SOURCES` (see `core.threat_intelligence`).
This adapter performs one real, bounded HTTP GET to CISA's own published
JSON feed, and normalizes only the most-recently-added `limit` entries
into `core.threat_intelligence`'s common record contract -- it never
returns the full catalog, and never invents a field the feed does not
supply (CWE/CVSS/EPSS are not part of KEV's own schema, so they are
always left empty/`None` here; `core.threat_intelligence.compute_corroboration`
or a separate EPSS/NVD lookup is how those get attached later).

## No authentication, no write access, one GET only

This adapter never sends a credential, never writes anything back to
CISA, and performs at most one HTTP request per call -- `shutil`/
`subprocess` are never used; all I/O is `http.client` only, mirroring
`adapters.bug_bounty_http`'s own stdlib-only approach.

`ThreatIntelCisaKevAdapterError` and `fetch_cisa_kev_records` are this
module's public symbols.
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
from typing import Any

from core.threat_intelligence import validate_threat_intelligence_record

KEV_HOST = "www.cisa.gov"
KEV_PATH = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CONNECT_TIMEOUT_SECONDS = 15.0
MAX_RESPONSE_BYTES = 8_388_608  # 8 MiB -- bounded, the full catalog is well under this
MAX_LIMIT = 25

STATUS_VALUES = frozenset({"completed", "failed", "unavailable"})


class ThreatIntelCisaKevAdapterError(ValueError):
    """Raised only for a structurally invalid `limit`. Never raised for
    a real fetch failure -- that is `status: "failed"`/`"unavailable"`
    in the returned result, not an exception."""


def _normalize_kev_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    cve_id = entry.get("cveID")
    if not isinstance(cve_id, str) or not cve_id.strip():
        return None
    vendor = entry.get("vendorProject") or ""
    product = entry.get("product") or ""
    affected_products = [p for p in (f"{vendor} {product}".strip(),) if p]

    raw = {
        "intel_version": "1",
        "intel_id": "TI-KEV-" + cve_id.strip(),
        "source_type": "cisa_kev",
        "source_name": "CISA Known Exploited Vulnerabilities Catalog",
        "source_reference": f"https://{KEV_HOST}{KEV_PATH}",
        "title": entry.get("vulnerabilityName") or cve_id,
        "summary": entry.get("shortDescription") if isinstance(entry.get("shortDescription"), str) else None,
        "published_at": None,
        "modified_at": None,
        "observed_at": entry.get("dateAdded") if isinstance(entry.get("dateAdded"), str) else None,
        "cve": [cve_id.strip()],
        "cwe": [],
        "owasp": [],
        "affected_products": affected_products,
        "affected_versions": [],
        "ioc": {"ip": [], "domain": [], "url": [], "file_hash": []},
        "actor": None,
        "campaign": None,
        "attack": {"tactic": [], "technique": [], "subtechnique": []},
        "behavioral_indicators": [],
        "exploitation_status": "exploited_in_wild",
        "known_exploited": True,
        "epss_score": None,
        "confidence": "high",
        "corroboration_state": "single_source",
        "evidence_references": [f"https://{KEV_HOST}{KEV_PATH}#{cve_id.strip()}"],
        "source_reliability": "high",
        "information_credibility": "high",
        "limitations": ["KEV does not itself supply CWE/EPSS -- attach via a separate NVD/EPSS lookup if needed."],
    }
    return validate_threat_intelligence_record(record=raw)


def fetch_cisa_kev_records(*, limit: Any) -> dict[str, Any]:
    """Fetch at most `limit` of the most-recently-added entries from
    CISA's real, public KEV catalog, normalized into
    `core.threat_intelligence`'s common record contract.

    `limit` is required and keyword-only, and must be a positive int not
    exceeding `MAX_LIMIT` -- raises `ThreatIntelCisaKevAdapterError`
    otherwise (a structural input error, not a fetch outcome).

    Returns a dict with `status` (one of `STATUS_VALUES`), `records`
    (a list of normalized records, most-recently-added first, always
    `[]` unless `status == "completed"`), `records_available` (the total
    catalog size actually returned by CISA, before this adapter's own
    `limit` truncation -- `None` if the fetch failed), `source_reference`,
    `error_detail` (a short, safe, fixed description, never a raw
    exception message), `execution_performed` (`True` once a real HTTP
    request was actually sent).
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > MAX_LIMIT:
        raise ThreatIntelCisaKevAdapterError(f"INVALID_LIMIT: limit must be a positive int not exceeding {MAX_LIMIT}")

    source_reference = f"https://{KEV_HOST}{KEV_PATH}"
    connection = None
    try:
        connection = http.client.HTTPSConnection(
            KEV_HOST, 443, timeout=KEV_CONNECT_TIMEOUT_SECONDS, context=ssl.create_default_context(),
        )
        connection.request("GET", KEV_PATH, headers={"User-Agent": "ThreatTrace-TI-Ingestion/1.0"})
        response = connection.getresponse()
        if response.status != 200:
            return {
                "status": "unavailable", "records": [], "records_available": None,
                "source_reference": source_reference, "error_detail": f"CISA KEV returned HTTP {response.status}",
                "execution_performed": True,
            }
        raw_body = response.read(MAX_RESPONSE_BYTES + 1)[:MAX_RESPONSE_BYTES]
    except (OSError, socket.timeout, http.client.HTTPException):
        return {
            "status": "unavailable", "records": [], "records_available": None,
            "source_reference": source_reference, "error_detail": "CISA KEV was unreachable",
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
    except (json.JSONDecodeError, ValueError, AttributeError):
        return {
            "status": "failed", "records": [], "records_available": None,
            "source_reference": source_reference, "error_detail": "CISA KEV response could not be parsed",
            "execution_performed": True,
        }

    ordered = sorted(
        (entry for entry in vulnerabilities if isinstance(entry, dict)),
        key=lambda entry: entry.get("dateAdded") or "", reverse=True,
    )
    normalized: list[dict[str, Any]] = []
    for entry in ordered:
        if len(normalized) >= limit:
            break
        record = _normalize_kev_entry(entry)
        if record is not None:
            normalized.append(record)

    return {
        "status": "completed", "records": normalized, "records_available": len(ordered),
        "source_reference": source_reference, "error_detail": None, "execution_performed": True,
    }
