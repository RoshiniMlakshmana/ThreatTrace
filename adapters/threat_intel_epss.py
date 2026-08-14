"""Real, bounded EPSS (Exploit Prediction Scoring System) adapter
(Block 15H-I).

EPSS (FIRST.org) is a public, unauthenticated defensive feed publishing
a daily-updated probability score (0.0-1.0) that a given CVE will be
exploited in the wild in the next 30 days. This adapter performs one
real, bounded HTTP GET to FIRST's own published REST API, and
normalizes at most `limit` entries into `core.threat_intelligence`'s
common record contract. EPSS is **not** in `AUTHORITATIVE_SOURCES` --
it is a probabilistic model, not a confirmed-exploitation catalog like
CISA KEV, and this adapter never claims otherwise (`known_exploited` is
always `False` here; `exploitation_status` is always `"unknown"` unless
the EPSS score itself is very high, in which case it is still only
`"poc_available"`-equivalent caution, never asserted as confirmed
exploitation).

## No authentication, no write access, one GET only

All I/O is `http.client` only; no credential is ever sent (FIRST's EPSS
API has no authenticated tier).

`ThreatIntelEpssAdapterError` and `fetch_epss_records` are this module's
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

EPSS_HOST = "api.first.org"
EPSS_PATH = "/data/v1/epss"
EPSS_CONNECT_TIMEOUT_SECONDS = 15.0
MAX_RESPONSE_BYTES = 1_048_576  # 1 MiB
MAX_LIMIT = 25

STATUS_VALUES = frozenset({"completed", "failed", "unavailable"})

# A high EPSS score alone is a probability signal, never confirmed
# exploitation -- this threshold only ever affects the caution-flavored
# exploitation_status text, never known_exploited (always False here).
_HIGH_SCORE_THRESHOLD = 0.5


class ThreatIntelEpssAdapterError(ValueError):
    """Raised only for a structurally invalid `limit`/`cve_ids`. Never
    raised for a real fetch failure -- that is `status: "failed"`/
    `"unavailable"` in the returned result, not an exception."""


def _normalize_epss_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    cve_id = entry.get("cve")
    if not isinstance(cve_id, str) or not cve_id.strip():
        return None
    try:
        score = float(entry.get("epss"))
    except (TypeError, ValueError):
        return None
    if not (0.0 <= score <= 1.0):
        return None

    raw = {
        "intel_version": "1",
        "intel_id": "TI-EPSS-" + cve_id.strip(),
        "source_type": "epss",
        "source_name": "FIRST.org EPSS",
        "source_reference": f"https://{EPSS_HOST}{EPSS_PATH}?cve={cve_id.strip()}",
        "title": f"EPSS score for {cve_id.strip()}",
        "summary": None,
        "published_at": None,
        "modified_at": entry.get("date") if isinstance(entry.get("date"), str) else None,
        "observed_at": None,
        "cve": [cve_id.strip()],
        "cwe": [],
        "owasp": [],
        "affected_products": [],
        "affected_versions": [],
        "ioc": {"ip": [], "domain": [], "url": [], "file_hash": []},
        "actor": None,
        "campaign": None,
        "attack": {"tactic": [], "technique": [], "subtechnique": []},
        "behavioral_indicators": [],
        "exploitation_status": "poc_available" if score >= _HIGH_SCORE_THRESHOLD else "unknown",
        "known_exploited": False,
        "epss_score": score,
        "confidence": "medium",
        "corroboration_state": "single_source",
        "evidence_references": [f"https://{EPSS_HOST}{EPSS_PATH}?cve={cve_id.strip()}"],
        "source_reliability": "medium",
        "information_credibility": "medium",
        "limitations": ["EPSS is a probability model, not a confirmed-exploitation source -- never treat as equivalent to CISA KEV."],
    }
    return validate_threat_intelligence_record(record=raw)


def fetch_epss_records(*, limit: Any, cve_ids: Any = None) -> dict[str, Any]:
    """Fetch EPSS scores from FIRST's real, public REST API, normalized
    into `core.threat_intelligence`'s common record contract.

    `limit` is required and keyword-only, and must be a positive int not
    exceeding `MAX_LIMIT`. `cve_ids` is optional (default `None`) -- when
    supplied, must be a non-empty list of non-blank CVE-ID strings (e.g.
    to enrich CVEs already discovered via `adapters.threat_intel_cisa_kev`/
    `adapters.threat_intel_nvd`); when omitted, this adapter requests
    FIRST's own descending-score-ordered default listing.

    Raises `ThreatIntelEpssAdapterError` for a structurally invalid
    `limit`/`cve_ids`.

    Returns a dict with `status` (one of `STATUS_VALUES`), `records`,
    `records_available`, `source_reference`, `error_detail`,
    `execution_performed`.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > MAX_LIMIT:
        raise ThreatIntelEpssAdapterError(f"INVALID_LIMIT: limit must be a positive int not exceeding {MAX_LIMIT}")
    if cve_ids is not None:
        if not isinstance(cve_ids, list) or not cve_ids or not all(isinstance(item, str) and item.strip() for item in cve_ids):
            raise ThreatIntelEpssAdapterError("INVALID_CVE_IDS: cve_ids must be null or a non-empty list of non-blank strings")

    query: dict[str, str] = {}
    if cve_ids:
        query["cve"] = ",".join(item.strip() for item in cve_ids)
    else:
        query["order"] = "!epss"
    query["limit"] = str(limit)
    path = f"{EPSS_PATH}?{urlencode(query)}"
    source_reference = f"https://{EPSS_HOST}{path}"

    connection = None
    try:
        connection = http.client.HTTPSConnection(
            EPSS_HOST, 443, timeout=EPSS_CONNECT_TIMEOUT_SECONDS, context=ssl.create_default_context(),
        )
        connection.request("GET", path, headers={"User-Agent": "ThreatTrace-TI-Ingestion/1.0"})
        response = connection.getresponse()
        if response.status != 200:
            return {
                "status": "unavailable", "records": [], "records_available": None,
                "source_reference": source_reference, "error_detail": f"EPSS returned HTTP {response.status}",
                "execution_performed": True,
            }
        raw_body = response.read(MAX_RESPONSE_BYTES + 1)[:MAX_RESPONSE_BYTES]
    except (OSError, socket.timeout, http.client.HTTPException):
        return {
            "status": "unavailable", "records": [], "records_available": None,
            "source_reference": source_reference, "error_detail": "EPSS was unreachable",
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
        data = payload.get("data")
        if not isinstance(data, list):
            raise ValueError("missing data list")
        total = payload.get("total")
    except (json.JSONDecodeError, ValueError, AttributeError):
        return {
            "status": "failed", "records": [], "records_available": None,
            "source_reference": source_reference, "error_detail": "EPSS response could not be parsed",
            "execution_performed": True,
        }

    normalized: list[dict[str, Any]] = []
    for entry in data:
        if len(normalized) >= limit:
            break
        record = _normalize_epss_entry(entry) if isinstance(entry, dict) else None
        if record is not None:
            normalized.append(record)

    return {
        "status": "completed", "records": normalized,
        "records_available": total if isinstance(total, int) else len(data),
        "source_reference": source_reference, "error_detail": None, "execution_performed": True,
    }
