"""Pure, deterministic Final Bug Bounty Report builder (Block 15G-CD).

This module answers exactly one question: *given an already-computed
`core.bug_bounty_finding_correlation` result and the full batch of
normalized evidence records it was computed from, what does one
structured, human-readable Final Bug Bounty Report look like?*

## Canonical findings vs. informational observations, kept honestly separate

Every correlation group with `is_informational: True` (see
`core.bug_bounty_finding_correlation`'s own honesty rule -- no
severity/vulnerability_class/cwe/cve on any member) becomes an
`informational_observations` entry, never a `canonical_findings` entry.
This module never promotes a bare Nmap open-port observation into a
"finding" merely to make a report look more substantial.

## Status is always `"requires_human_review"` -- deliberately, in this checkpoint

`STATUS_VALUES` has exactly one member. This module never invents a
`"validated"`/`"confirmed"` status for a canonical finding -- multi-tool
corroboration raises `confidence`, never `status`. A human analyst
decision is always required before any finding produced here is treated
as confirmed. This is a deliberate simplification for this checkpoint,
not an oversight -- see `docs/block15g-cd-multitool-correlation.md`.

## Nothing here is fabricated

`cve`, `mitre_attack_mapping`, and `references` are only ever populated
from data already present on the source evidence records (`cve`) or
left as an empty list/`None` (`mitre_attack_mapping`, `references`) --
this module has no ATT&CK mapping engine and never invents one.
`remediation`/`potential_impact`/`prerequisites`/`exposure` are always
`None` in this checkpoint: `core.bug_bounty_evidence_normalization`'s
own contract does not carry a remediation/impact field from any source
tool, and this module never synthesizes prose to fill the gap -- an
honest `None` beats an invented sentence.

## The executive summary never claims security from silence

Per this checkpoint's own explicit requirement, `executive_summary`
never states or implies "system secure" and never infers absence of
vulnerability from an absence of scanner matches -- it reports counts,
which tools actually ran, and which categories were never tested at
all (`unsupported_test_categories`), always as a structured fact list,
never as a safety claim.

## No I/O, no execution, ever

This module performs no network, filesystem, environment-variable,
subprocess, system-clock, or randomness access -- `assessment_started_at`/
`assessment_completed_at` are required, caller-supplied values (already
captured by the caller's own clock), exactly like every other
timestamp-accepting function in this project.  It imports exactly one
symbol, `core.bug_bounty_finding_correlation.CORRELATION_VERSION`, purely
as a version-compatibility marker check -- it never calls that module's
correlation logic itself, and never imports
`core.bug_bounty_evidence_normalization`.

`BugBountyFinalReportError` and `build_final_bug_bounty_report` are this
module's public symbols (plus `REPORT_VERSION`, `STATUS_VALUES`, and
`UNSUPPORTED_TEST_CATEGORIES`).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from core.bug_bounty_finding_correlation import CORRELATION_VERSION

REPORT_VERSION = "1"

STATUS_VALUES = frozenset({"requires_human_review"})
_VALIDATION_STATE_ORDER = ("unvalidated", "tool_asserted", "tool_confirmed")

# Fixed, honest list of test categories this checkpoint never attempts,
# regardless of what tools were actually executed -- see module docstring.
UNSUPPORTED_TEST_CATEGORIES = (
    "authenticated_testing",
    "controlled_validation",
    "active_exploitation",
    "active_dast_scanning",
    "credential_attacks",
    "denial_of_service",
)

_TOOL_LIST_FIELDS = ("tools_requested", "tools_permitted", "tools_executed", "tools_unavailable")


class BugBountyFinalReportError(ValueError):
    """Raised when a supplied `correlation_result`, `evidence_records`,
    or a required scalar/list parameter is structurally invalid.

    Never raised because there are zero canonical findings, because
    every group is informational, or because `tools_executed` is empty
    -- every one of those is a normal, successfully built report, not an
    error.
    """


def _raise(code: str, detail: str) -> None:
    raise BugBountyFinalReportError(f"{code}: {detail}")


def _require_nonblank_string(value: Any, code: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _raise(code, f"{field_name!r} must be a non-blank string")
    return value.strip()


def _require_string_list(value: Any, code: str, field_name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        _raise(code, f"{field_name!r} must be a list of strings")
    return list(value)


def _canonical_digest_hex(value: Any, length: int | None = None) -> str:
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return digest[:length] if length else digest


def _best_validation_state(records: list[Mapping[str, Any]]) -> str:
    present = [record.get("validation_state") for record in records if record.get("validation_state") in _VALIDATION_STATE_ORDER]
    if not present:
        return "unvalidated"
    return max(present, key=_VALIDATION_STATE_ORDER.index)


def _first_present(records: list[Mapping[str, Any]], field: str) -> Any:
    for record in records:
        value = record.get(field)
        if value:
            return value
    return None


# ---------------------------------------------------------------------------
# Validation of inputs.
# ---------------------------------------------------------------------------


def _validate_correlation_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _raise("INVALID_CORRELATION_RESULT", "correlation_result must be a mapping")
    if value.get("correlation_version") != CORRELATION_VERSION:
        _raise("INVALID_CORRELATION_RESULT", "correlation_result['correlation_version'] is not recognized")
    groups = value.get("groups")
    if not isinstance(groups, list):
        _raise("INVALID_CORRELATION_RESULT", "correlation_result['groups'] must be a list")
    duplicate_evidence_count = value.get("duplicate_evidence_count")
    if isinstance(duplicate_evidence_count, bool) or not isinstance(duplicate_evidence_count, int):
        _raise("INVALID_CORRELATION_RESULT", "correlation_result['duplicate_evidence_count'] must be an int")
    uncertain_correlations = value.get("uncertain_correlations")
    if not isinstance(uncertain_correlations, list):
        _raise("INVALID_CORRELATION_RESULT", "correlation_result['uncertain_correlations'] must be a list")
    total_input_records = value.get("total_input_records")
    if isinstance(total_input_records, bool) or not isinstance(total_input_records, int):
        _raise("INVALID_CORRELATION_RESULT", "correlation_result['total_input_records'] must be an int")
    return {
        "groups": groups,
        "duplicate_evidence_count": duplicate_evidence_count,
        "uncertain_correlations": uncertain_correlations,
        "total_input_records": total_input_records,
    }


def _index_evidence_records(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list):
        _raise("INVALID_EVIDENCE_RECORDS", "evidence_records must be a list")
    indexed: dict[str, dict[str, Any]] = {}
    for record in value:
        if not isinstance(record, Mapping) or "evidence_id" not in record:
            _raise("INVALID_EVIDENCE_RECORDS", "each evidence record must be a mapping with an evidence_id")
        indexed[record["evidence_id"]] = dict(record)
    return indexed


# ---------------------------------------------------------------------------
# Canonical finding / informational observation construction.
# ---------------------------------------------------------------------------


def _build_canonical_finding(group: Mapping[str, Any], members: list[dict[str, Any]], *, scope: str, governor_reference: Any) -> dict[str, Any]:
    validation_state = _best_validation_state(members)
    evidence_sources = [
        {
            "source_tool": record.get("source_tool"),
            "source_observation_id": record.get("source_observation_id"),
            "evidence_id": record.get("evidence_id"),
            "source_reference": record.get("source_reference"),
        }
        for record in members
    ]
    tool_observations = [
        {
            "source_tool": record.get("source_tool"),
            "title": record.get("title"),
            "sanitized_evidence": record.get("sanitized_evidence"),
        }
        for record in members
    ]
    limitations: list[str] = []
    if not group["multi_tool_corroborated"]:
        limitations.append("Single-tool observation -- not independently corroborated by a second tool.")
    if validation_state != "tool_confirmed":
        limitations.append("Not deterministically confirmed by ThreatTrace -- reflects tool-reported evidence only.")

    return {
        "finding_id": "CF-" + _canonical_digest_hex(group["group_id"], 16),
        "title": group.get("representative_title"),
        "vulnerability_class": group.get("vulnerability_class"),
        "cwe": group.get("cwe"),
        "owasp_category": group.get("owasp_category"),
        "cve": list(group.get("cve") or []),
        "host": group.get("host"),
        "port": group.get("port"),
        "url": _first_present(members, "url"),
        "path": group.get("path"),
        "parameter": group.get("parameter"),
        "method": _first_present(members, "method"),
        "technical_severity": group.get("aggregated_technical_severity"),
        "confidence": group.get("aggregated_confidence"),
        "validation_state": validation_state,
        "evidence_sources": evidence_sources,
        "tool_observations": tool_observations,
        "sanitized_proof": _first_present(members, "sanitized_evidence"),
        "potential_impact": None,
        "prerequisites": None,
        "exposure": None,
        "remediation": None,
        "mitre_attack_mapping": None,
        "references": [],
        "tools_used": list(group.get("source_tools") or []),
        "scope": scope,
        "governor_reference": governor_reference,
        "evidence_digests": [record.get("evidence_digest") for record in members],
        "human_validation_required": True,
        "limitations": limitations,
        "status": "requires_human_review",
    }


def _build_informational_observation(group: Mapping[str, Any], members: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "observation_id": "IO-" + _canonical_digest_hex(group["group_id"], 16),
        "title": group.get("representative_title"),
        "observation_type": _first_present(members, "observation_type"),
        "host": group.get("host"),
        "port": group.get("port"),
        "path": group.get("path"),
        "service": _first_present(members, "service"),
        "product": _first_present(members, "product"),
        "version": _first_present(members, "version"),
        "tools_used": list(group.get("source_tools") or []),
        "evidence_digests": [record.get("evidence_digest") for record in members],
    }


# ---------------------------------------------------------------------------
# Executive summary.
# ---------------------------------------------------------------------------


def _build_executive_summary(
    canonical_findings: list[dict[str, Any]], informational_observations: list[dict[str, Any]],
    *, tools_executed: list[str], tools_unavailable: list[str],
) -> dict[str, Any]:
    severity_breakdown = {"low": 0, "medium": 0, "high": 0, "critical": 0, "unknown": 0}
    for finding in canonical_findings:
        severity = finding.get("technical_severity")
        if severity in severity_breakdown:
            severity_breakdown[severity] += 1
        else:
            severity_breakdown["unknown"] += 1

    severity_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0, None: -1}
    strongest = sorted(
        canonical_findings, key=lambda finding: severity_rank.get(finding.get("technical_severity"), -1), reverse=True,
    )[:5]

    return {
        "canonical_finding_count": len(canonical_findings),
        "severity_breakdown": severity_breakdown,
        "strongest_findings": [
            {"finding_id": finding["finding_id"], "title": finding["title"], "technical_severity": finding["technical_severity"]}
            for finding in strongest
        ],
        "informational_observation_count": len(informational_observations),
        "tools_used": sorted(set(tools_executed)),
        "tools_not_available": sorted(set(tools_unavailable)),
        "unsupported_test_categories": list(UNSUPPORTED_TEST_CATEGORIES),
        "human_review_required_count": sum(1 for finding in canonical_findings if finding["human_validation_required"]),
        "summary_text": (
            f"{len(canonical_findings)} canonical finding(s) and {len(informational_observations)} "
            f"informational observation(s) were produced from {sorted(set(tools_executed)) or 'no'} executed "
            "tool(s). Every finding requires human review before being treated as confirmed. "
            "Absence of a scanner match does not establish absence of vulnerability; categories in "
            "unsupported_test_categories were never attempted."
        ),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_final_bug_bounty_report(
    *,
    correlation_result: Any,
    evidence_records: Any,
    target: Any,
    scope: Any,
    testing_profile: Any,
    assessment_started_at: Any,
    assessment_completed_at: Any,
    tools_requested: Any,
    tools_permitted: Any,
    tools_executed: Any,
    tools_unavailable: Any,
    governor_reference: Any = None,
) -> dict[str, Any]:
    """Deterministically build one Final Bug Bounty Report from an
    already-computed `core.bug_bounty_finding_correlation` result and
    the full evidence-record batch it was computed from. Performs no
    I/O of any kind and executes nothing.

    All parameters are required and keyword-only except
    `governor_reference` (default `None`, echoed verbatim -- e.g. a
    Governor decision string/reference the caller already obtained; this
    function never calls the Governor itself). `correlation_result` must
    be shaped like `core.bug_bounty_finding_correlation.
    correlate_bug_bounty_evidence`'s own return value.
    `evidence_records` must be the same list (or a superset) of
    normalized evidence records that correlation was computed from --
    every `member_evidence_ids` entry in every group must resolve to one
    of them, or this function raises `BugBountyFinalReportError`.
    `target`/`scope`/`testing_profile` must each be non-blank strings.
    `assessment_started_at`/`assessment_completed_at` may be any
    caller-clock value (this function never calls a clock itself).
    `tools_requested`/`tools_permitted`/`tools_executed`/
    `tools_unavailable` must each be a list of strings.

    Each correlation group with `is_informational: False` becomes one
    entry in `canonical_findings` (see `_build_canonical_finding`); every
    `is_informational: True` group becomes one entry in
    `informational_observations` instead -- never both.

    Returns a new dict containing exactly `report_id`, `report_version`,
    `target`, `scope`, `testing_profile`, `assessment_started_at`,
    `assessment_completed_at`, `tools_requested`, `tools_permitted`,
    `tools_executed`, `tools_unavailable`, `executive_summary`,
    `canonical_findings`, `informational_observations`,
    `duplicate_evidence_count`, `correlation_summary`,
    `human_review_items`, `limitations`, `unsupported_test_categories`,
    `safety_summary`, `governor_summary`, `evidence_integrity_summary`,
    `execution_performed` (always `False`).

    Raises `BugBountyFinalReportError` for a structurally invalid
    `correlation_result`/`evidence_records`, a blank
    `target`/`scope`/`testing_profile`, a non-string-list tool list, or a
    group referencing an `evidence_id` not present in `evidence_records`.
    Never raises because there are zero canonical findings, zero tools
    executed, or every group is informational -- every one of those is a
    normal, successfully built (possibly mostly-empty) report.
    """
    validated_correlation = _validate_correlation_result(correlation_result)
    records_by_id = _index_evidence_records(evidence_records)

    validated_target = _require_nonblank_string(target, "INVALID_TARGET", "target")
    validated_scope = _require_nonblank_string(scope, "INVALID_SCOPE", "scope")
    validated_testing_profile = _require_nonblank_string(testing_profile, "INVALID_TESTING_PROFILE", "testing_profile")

    tool_lists: dict[str, list[str]] = {}
    for field_name, raw_value in (
        ("tools_requested", tools_requested), ("tools_permitted", tools_permitted),
        ("tools_executed", tools_executed), ("tools_unavailable", tools_unavailable),
    ):
        tool_lists[field_name] = _require_string_list(raw_value, "INVALID_TOOL_LIST", field_name)

    canonical_findings: list[dict[str, Any]] = []
    informational_observations: list[dict[str, Any]] = []
    for group in validated_correlation["groups"]:
        member_ids = group.get("member_evidence_ids") or []
        members: list[dict[str, Any]] = []
        for evidence_id in member_ids:
            if evidence_id not in records_by_id:
                _raise("EVIDENCE_ID_NOT_FOUND", f"group references unknown evidence_id: {evidence_id!r}")
            members.append(records_by_id[evidence_id])

        if group.get("is_informational"):
            informational_observations.append(_build_informational_observation(group, members))
        else:
            canonical_findings.append(
                _build_canonical_finding(group, members, scope=validated_scope, governor_reference=governor_reference),
            )

    executive_summary = _build_executive_summary(
        canonical_findings, informational_observations,
        tools_executed=tool_lists["tools_executed"], tools_unavailable=tool_lists["tools_unavailable"],
    )

    limitations = [
        "Canonical findings are correlated tool evidence, not exploit-confirmed vulnerabilities.",
        "No active exploitation, authenticated testing, or controlled validation was attempted this checkpoint.",
        "ZAP execution (when performed) uses a passive-only capability profile -- active scanning is never enabled.",
        "Burp Suite execution requires an externally-configured runtime this environment may not have.",
    ]

    report_id = "RPT-" + _canonical_digest_hex(
        {"target": validated_target, "started_at": assessment_started_at, "completed_at": assessment_completed_at,
         "finding_ids": sorted(finding["finding_id"] for finding in canonical_findings)},
        16,
    )

    return {
        "report_id": report_id,
        "report_version": REPORT_VERSION,
        "target": validated_target,
        "scope": validated_scope,
        "testing_profile": validated_testing_profile,
        "assessment_started_at": assessment_started_at,
        "assessment_completed_at": assessment_completed_at,
        "tools_requested": tool_lists["tools_requested"],
        "tools_permitted": tool_lists["tools_permitted"],
        "tools_executed": tool_lists["tools_executed"],
        "tools_unavailable": tool_lists["tools_unavailable"],
        "executive_summary": executive_summary,
        "canonical_findings": canonical_findings,
        "informational_observations": informational_observations,
        "duplicate_evidence_count": validated_correlation["duplicate_evidence_count"],
        "correlation_summary": {
            "total_input_records": validated_correlation["total_input_records"],
            "total_groups": len(validated_correlation["groups"]),
            "duplicate_evidence_count": validated_correlation["duplicate_evidence_count"],
            "multi_tool_corroborated_count": sum(
                1 for group in validated_correlation["groups"] if group.get("multi_tool_corroborated")
            ),
            "uncertain_correlation_count": len(validated_correlation["uncertain_correlations"]),
        },
        "human_review_items": (
            [finding["finding_id"] for finding in canonical_findings if finding["human_validation_required"]]
            + [
                f"uncertain_correlation:{item['evidence_id_a']}:{item['evidence_id_b']}"
                for item in validated_correlation["uncertain_correlations"]
            ]
        ),
        "limitations": limitations,
        "unsupported_test_categories": list(UNSUPPORTED_TEST_CATEGORIES),
        "safety_summary": {
            "destructive_testing_implemented": False,
            "active_exploitation_implemented": False,
            "credential_attacks_implemented": False,
            "scan_targets_must_match_analyst_approved_scope": True,
        },
        "governor_summary": governor_reference,
        "evidence_integrity_summary": {
            "evidence_digest_algorithm": "sha256",
            "evidence_record_count": validated_correlation["total_input_records"],
            "note": "Digests are content-correlation identifiers only -- never cryptographic authenticity or non-repudiation proof.",
        },
        "execution_performed": False,
    }
