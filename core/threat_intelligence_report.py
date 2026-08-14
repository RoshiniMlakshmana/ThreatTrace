"""Pure, deterministic Threat Intelligence ingestion report builder
(Block 15H-I).

This module answers exactly one question: *given the results of a batch
of already-attempted TI source fetches and the already-corroborated
records they produced, what does one concise ingestion report look
like?*

## No I/O, no execution, ever

This module performs no network, filesystem, environment-variable,
subprocess, system-clock, or randomness access. It never calls any
`adapters.threat_intel_*` module itself -- every fetch result it
summarizes must already exist. `retrieved_at` is a required,
caller-supplied value (already captured by the caller's own clock),
exactly like every other timestamp-accepting function in this project.

## Duplicates are exact-intel_id repeats only, never cross-source corroboration

`duplicates_removed` counts only records sharing the exact same
`intel_id` appearing more than once in the ingested batch (e.g. an
accidental re-fetch) -- it never treats a CISA KEV record and an NVD
record about the *same* CVE as duplicates of each other; those are
deliberately preserved as separate, corroborating records (see
`core.threat_intelligence.compute_corroboration`).

`ThreatIntelligenceReportError` and `build_threat_intelligence_report`
are this module's public symbols.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

REPORT_VERSION = "1"

_SUCCESSFUL_STATUSES = frozenset({"completed"})
_MAX_LISTED_IDENTIFIERS = 25


class ThreatIntelligenceReportError(ValueError):
    """Raised when a supplied `source_fetch_results`/`corroborated_records`
    input is structurally invalid. Never raised because every source was
    unavailable, or because zero records were ingested -- every one of
    those is a normal, successfully built (mostly-empty) report."""


def _raise(code: str, detail: str) -> None:
    raise ThreatIntelligenceReportError(f"{code}: {detail}")


def _dedupe_by_intel_id(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    duplicate_count = 0
    for record in records:
        intel_id = record.get("intel_id")
        if intel_id in seen:
            duplicate_count += 1
            continue
        seen.add(intel_id)
        deduped.append(record)
    return deduped, duplicate_count


def build_threat_intelligence_report(*, source_fetch_results: Any, corroborated_records: Any, retrieved_at: Any) -> dict[str, Any]:
    """Deterministically build one Threat Intelligence ingestion report.
    Performs no I/O of any kind.

    `source_fetch_results` is required and keyword-only, and must be a
    list of `{"source_name": str, "result": <adapter fetch result>}`
    entries -- each `result` must at least carry `status`, `records`,
    `source_reference`. A `result['status']` of `"completed"` counts as
    successful; anything else (`"failed"`/`"unavailable"`/
    `"not_evaluated"`) counts as unavailable. `corroborated_records`
    must be a list of records shaped like `core.threat_intelligence.
    compute_corroboration`'s own output (re-validated only for the
    minimal fields this function reads). `retrieved_at` may be any
    caller-clock value.

    Returns a dict with `report_version`, `retrieved_at`,
    `sources_queried`, `sources_successful`, `sources_unavailable`,
    `records_ingested` (raw count across all successful fetches, before
    this report's own `intel_id` dedup), `records_normalized` (after
    dedup), `duplicates_removed`, `cve_summary`
    (`{"total_unique_cve", "cve_ids"}`, capped at
    `_MAX_LISTED_IDENTIFIERS`), `kev_summary`
    (`{"known_exploited_count", "cve_ids"}`), `high_priority_summary`
    (records with `corroboration_state == "authoritative_source"` or
    `known_exploited is True`), `corroboration_state_distribution`,
    `limitations`, `source_references`.

    Raises `ThreatIntelligenceReportError` for a structurally invalid
    `source_fetch_results`/`corroborated_records` entry. Never raises
    because every source failed, or because zero records were ingested.
    """
    if not isinstance(source_fetch_results, list):
        _raise("INVALID_SOURCE_FETCH_RESULTS", "source_fetch_results must be a list")

    sources_queried: list[str] = []
    sources_successful: list[str] = []
    sources_unavailable: list[str] = []
    source_references: list[str] = []
    records_ingested = 0

    for entry in source_fetch_results:
        if not isinstance(entry, Mapping) or "source_name" not in entry or "result" not in entry:
            _raise("INVALID_SOURCE_FETCH_RESULTS", "each entry must contain exactly source_name/result")
        source_name = entry["source_name"]
        if not isinstance(source_name, str) or not source_name.strip():
            _raise("INVALID_SOURCE_FETCH_RESULTS", "source_name must be a non-blank string")
        result = entry["result"]
        if not isinstance(result, Mapping):
            _raise("INVALID_SOURCE_FETCH_RESULTS", "result must be a mapping")

        sources_queried.append(source_name)
        status = result.get("status")
        if status in _SUCCESSFUL_STATUSES:
            sources_successful.append(source_name)
            records = result.get("records")
            if isinstance(records, list):
                records_ingested += len(records)
        else:
            sources_unavailable.append(source_name)

        reference = result.get("source_reference")
        if isinstance(reference, str) and reference.strip():
            source_references.append(reference)

    if not isinstance(corroborated_records, list):
        _raise("INVALID_CORROBORATED_RECORDS", "corroborated_records must be a list")
    for record in corroborated_records:
        if not isinstance(record, Mapping) or "intel_id" not in record:
            _raise("INVALID_CORROBORATED_RECORDS", "each record must be a mapping with an intel_id")

    deduped_records, duplicates_removed = _dedupe_by_intel_id(list(corroborated_records))

    cve_ids: list[str] = []
    kev_cve_ids: list[str] = []
    high_priority: list[dict[str, Any]] = []
    corroboration_distribution: dict[str, int] = {}

    for record in deduped_records:
        for cve in record.get("cve") or []:
            if cve not in cve_ids:
                cve_ids.append(cve)
        if record.get("known_exploited") is True:
            for cve in record.get("cve") or []:
                if cve not in kev_cve_ids:
                    kev_cve_ids.append(cve)
        state = record.get("corroboration_state")
        if isinstance(state, str):
            corroboration_distribution[state] = corroboration_distribution.get(state, 0) + 1
        if state == "authoritative_source" or record.get("known_exploited") is True:
            high_priority.append({
                "intel_id": record.get("intel_id"), "title": record.get("title"),
                "cve": record.get("cve"), "corroboration_state": state,
            })

    limitations = [
        "Threat intelligence records are unauthenticated caller-supplied assessments unless from an AUTHORITATIVE_SOURCES member.",
        "duplicates_removed counts only exact intel_id repeats -- cross-source corroboration of the same CVE is preserved, never collapsed.",
    ]
    if sources_unavailable:
        limitations.append(f"{len(sources_unavailable)} source(s) were unavailable or unconfigured this run: {sorted(set(sources_unavailable))}.")

    return {
        "report_version": REPORT_VERSION,
        "retrieved_at": retrieved_at,
        "sources_queried": sources_queried,
        "sources_successful": sources_successful,
        "sources_unavailable": sources_unavailable,
        "records_ingested": records_ingested,
        "records_normalized": len(deduped_records),
        "duplicates_removed": duplicates_removed,
        "cve_summary": {"total_unique_cve": len(cve_ids), "cve_ids": sorted(cve_ids)[:_MAX_LISTED_IDENTIFIERS]},
        "kev_summary": {"known_exploited_count": len(kev_cve_ids), "cve_ids": sorted(kev_cve_ids)[:_MAX_LISTED_IDENTIFIERS]},
        "high_priority_summary": high_priority[:_MAX_LISTED_IDENTIFIERS],
        "corroboration_state_distribution": corroboration_distribution,
        "limitations": limitations,
        "source_references": source_references,
    }
