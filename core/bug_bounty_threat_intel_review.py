"""Pure orchestration for a bounded, per-finding Threat Intelligence
review boundary (Full Security Lifecycle checkpoint).

## Why this module exists

`core.threat_intelligence` operates on batches of already-fetched,
already-normalized TI records shaped exactly like
`TI_RECORD_REQUIRED_FIELDS` -- it has no per-finding "is there relevant
intel for this Bug Bounty finding" contract, and a Bug Bounty canonical
finding does not match its required shape at all. Rather than force a
mismatch or silently skip this stage, this module is the small, honest,
new boundary that connects a real canonical finding to a real,
narrowly-scoped, CVE-exact live TI lookup -- and, for the (expected,
common) case of a finding with no CVE at all, honestly reports
`"no_relevant_intel"` without ever inventing a lookup to perform.

## Dependency direction: no network client imported directly

Exactly like `core.bug_bounty_assessment`'s injected-transport pattern,
this module never imports a network-capable adapter itself. It calls an
injected `nvd_fetch` callable (the real implementation is
`adapters.threat_intel_nvd.fetch_nvd_records`, never imported here)
only when a finding actually carries a CVE -- and even then, the query
is always an *exact* CVE-ID keyword search (NVD's own server-side
search), never a fuzzy/speculative keyword hunt built from unrelated
finding text. This keeps every review decision here fully unit-testable
with a fake `nvd_fetch`, with zero network access, and guarantees a live
query is only ever attempted for a precise, justified reason.

## What this module does NOT do

- It never queries CISA KEV, EPSS, TAXII, MISP, OpenCTI, or any source
  other than NVD, and only for an exact CVE ID a finding itself already
  carries -- never a broader intelligence sweep.
- It never treats "no CVE" as an error -- `"no_relevant_intel"` is a
  normal, honest, successfully-evaluated outcome, not a failure.
- It never treats a real query returning zero matching records as
  anything other than `"no_relevant_intel"` -- a query that ran and
  found nothing is still evaluated, never silently equivalent to a
  query that never ran.
- It never claims "Threat Intelligence completed successfully with
  threat found" -- the stage always completes; the *result* is a
  separate, independently-honest field.

`review_threat_intelligence_for_finding` is this module's only public
function.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

REVIEW_VERSION = "1"

OUTCOMES = frozenset({"reviewed_relevant", "reviewed_no_match", "no_relevant_intel"})

# Only the first CVE on a finding is ever queried -- bounded, never an
# unbounded fan-out of live requests for a finding carrying many CVEs.
_MAX_NVD_QUERY_RESULTS = 5


class ThreatIntelReviewError(ValueError):
    """Raised only for a structurally unusable `canonical_finding`
    argument to this module itself (not a mapping, or missing
    `finding_id`). Never raised because a finding has no CVE, because a
    live NVD query found nothing, or because NVD was unreachable -- all
    three are normal, honestly-reported results."""


class _NvdFetch(Protocol):
    def __call__(self, *, limit: int, keyword_search: str | None = None) -> dict[str, Any]:
        ...


def _validate_finding(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ThreatIntelReviewError("INVALID_FINDING: canonical_finding must be a mapping")
    finding_id = value.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise ThreatIntelReviewError("INVALID_FINDING: canonical_finding['finding_id'] must be a non-blank string")
    return value


def review_threat_intelligence_for_finding(
    *, canonical_finding: Any, nvd_fetch: _NvdFetch,
) -> dict[str, Any]:
    """Deterministically review one canonical Bug Bounty finding for
    relevant threat intelligence. Both parameters are keyword-only and
    required -- `nvd_fetch` has no default so a caller can never
    accidentally trigger a real network request by omission; the real
    implementation (`adapters.threat_intel_nvd.fetch_nvd_records`) must
    be passed explicitly by the orchestrator.

    `canonical_finding` must be a mapping shaped at minimum like
    `core.bug_bounty_final_report`'s own canonical finding contract --
    only `finding_id` and `cve` are ever read.

    Behavior:
    - If `canonical_finding['cve']` is empty/absent (the expected case
      for this project's own config/header/DAST-style Bug Bounty
      findings), no network call is ever made and `outcome` is
      `"no_relevant_intel"`, `real_query_performed` is `False`.
    - Otherwise, the first CVE only is queried via `nvd_fetch(limit=...,
      keyword_search=<that exact CVE id>)` -- a real, bounded, narrowly
      justified live lookup. If NVD returns at least one record whose
      own `cve` field contains that exact CVE id, `outcome` is
      `"reviewed_relevant"` and `references` lists the matching
      records' `source_reference`s. If the query completed but found no
      exact match, or NVD itself reported `status != "completed"`
      (unreachable/failed), `outcome` is `"reviewed_no_match"` --
      distinct from `"no_relevant_intel"` specifically because a real
      query *was* attempted here, unlike the no-CVE case.

    Returns a new dict containing exactly `review_version` (always
    `"1"`), `finding_id`, `queried_cve` (the CVE id queried, or `None`),
    `outcome` (one of `OUTCOMES`), `real_query_performed` (bool),
    `references` (list of source-reference strings, possibly empty),
    `stage_evaluated` (always `True` -- this stage always completes;
    finding no relevant intel is a successful evaluation, never a
    skipped one), `human_review_required` (always `True`),
    `execution_performed` (always `False` -- a real read-only query may
    have occurred, but nothing was remediated, deployed, or acted on).

    Raises `ThreatIntelReviewError` only for a structurally invalid
    `canonical_finding`.
    """
    validated = _validate_finding(canonical_finding)
    cve_list = validated.get("cve")
    finding_id = validated["finding_id"]

    if not isinstance(cve_list, list) or not cve_list:
        return {
            "review_version": REVIEW_VERSION, "finding_id": finding_id, "queried_cve": None,
            "outcome": "no_relevant_intel", "real_query_performed": False, "references": [],
            "stage_evaluated": True, "human_review_required": True, "execution_performed": False,
        }

    queried_cve = str(cve_list[0])
    try:
        fetch_result = nvd_fetch(limit=_MAX_NVD_QUERY_RESULTS, keyword_search=queried_cve)
    except Exception:  # noqa: BLE001 -- an unreachable/failed live source is a normal, honest outcome here
        fetch_result = {"status": "unavailable", "records": []}

    references: list[str] = []
    if fetch_result.get("status") == "completed":
        for record in fetch_result.get("records") or []:
            record_cve = record.get("cve") if isinstance(record, Mapping) else None
            if isinstance(record_cve, list) and queried_cve in record_cve:
                reference = record.get("source_reference")
                if isinstance(reference, str) and reference:
                    references.append(reference)

    outcome = "reviewed_relevant" if references else "reviewed_no_match"
    return {
        "review_version": REVIEW_VERSION, "finding_id": finding_id, "queried_cve": queried_cve,
        "outcome": outcome, "real_query_performed": True, "references": references,
        "stage_evaluated": True, "human_review_required": True, "execution_performed": False,
    }
