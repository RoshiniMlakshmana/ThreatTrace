"""Pure, deterministic Bug Bounty finding correlation (Block 15G-CD).

This module answers exactly one question: *given a batch of already-
normalized evidence records (see `core.bug_bounty_evidence_normalization`),
which of them describe the same underlying canonical security issue, and
which are genuinely distinct?*

## Deterministic fingerprinting -- never title strings alone

`_fingerprint` groups evidence using normalized security semantics --
`host`, `port`, a lightly-normalized `path`, `parameter`, and a
`category` derived with priority `cwe` > `vulnerability_class` >
`observation_type` (whichever is present first) -- **never** by comparing
title text. This is why the HTTP assessor's "Missing
Content-Security-Policy header" and ZAP's "Content Security Policy (CSP)
Header Not Set" correctly fall into the same group (both carry
`cwe: "CWE-693"` at the same host/port/path) despite completely
different title strings, while two ZAP alerts sharing the exact same
title (`"Timestamp Disclosure - Unix"`, a real example from this
project's own live validation) at two different paths correctly stay
separate (their fingerprints differ on `path`).

## A shared CVE is an even stronger signal than the fingerprint

Independent of fingerprint matching, any two records whose `cve` lists
overlap are always grouped together -- a shared CVE identifies the same
underlying issue regardless of minor host/path formatting differences a
fingerprint might otherwise treat as distinct.

## LLM semantic assistance is optional, constrained, and never final

`semantic_hints` is an optional, caller-supplied list of already-produced
LLM verdicts (`same_finding`/`different_finding`/`uncertain`, each with a
`rationale` and the two `evidence_id`s it concerns) -- this module never
calls an LLM itself. Every hint is structurally validated before use. A
`same_finding` hint may only ever *add* a merge between two records not
already grouped by the deterministic fingerprint/CVE logic above -- it
can never split an already-deterministically-grouped pair, so an LLM can
supplement what deterministic matching missed but can never undo what
deterministic matching already established. `different_finding` is
recorded as an explicit non-merge decision. `uncertain` is **never**
auto-merged -- it is surfaced in `uncertain_correlations` for human
review instead, exactly as this checkpoint requires.

## Confidence aggregation reflects genuine independent corroboration

A group's `corroboration_count` counts **distinct `source_tool` values**
among its members, never raw record count -- five observations from the
same tool about the same issue are not five independent confirmations.
`multi_tool_corroborated` is `True` only when two or more distinct tools
contributed to a group; only then is `aggregated_confidence` ever raised
above the strongest individual member's own confidence (by exactly one
level, capped at `"high"`) -- this module never claims independent
corroboration when every member came from the same underlying tool.

## Informational vs. canonical, decided honestly

A group is `is_informational: True` only when **every** member has no
`technical_severity`, no `cwe`, and no `cve` (e.g. a bare Nmap open-port
observation, or a ZAP alert whose own risk is "Informational") -- this
module never promotes such a group into a canonical security finding
merely to populate a report; `core.bug_bounty_final_report` is expected
to keep these separate, per this checkpoint's own requirement.
`vulnerability_class` is deliberately excluded from this check: `core.
bug_bounty_evidence_normalization` always populates it for ZAP/Burp DAST
observations (a closed CWE mapping, or an explicit generic placeholder
when no mapping applies), so its presence alone no longer distinguishes
a real finding from a bare observation the way it still does for
`http_assessor`.

## No I/O, no execution, ever

This module performs no network, filesystem, environment-variable,
subprocess, system-clock, or randomness access. `execution_performed` is
always `False`. It imports exactly one symbol,
`core.bug_bounty_evidence_normalization.EVIDENCE_REQUIRED_FIELDS`, since
its own input contract is *by design* that module's exact output shape
(the same kind of deliberate, documented composition as
`core.bug_bounty_planner`'s import of `core.bug_bounty_tool_policy`) --
it never imports or calls that module's actual normalization logic.

`BugBountyFindingCorrelationError` and `correlate_bug_bounty_evidence`
are this module's public symbols (plus `SEMANTIC_VERDICTS` and
`CORRELATION_VERSION`).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from core.bug_bounty_evidence_normalization import EVIDENCE_REQUIRED_FIELDS

CORRELATION_VERSION = "1"

SEMANTIC_VERDICTS = frozenset({"same_finding", "different_finding", "uncertain"})
_SEVERITY_ORDER = ("low", "medium", "high", "critical")
_CONFIDENCE_ORDER = ("low", "medium", "high")

_SEMANTIC_HINT_REQUIRED_FIELDS = ("evidence_id_a", "evidence_id_b", "verdict", "rationale")


class BugBountyFindingCorrelationError(ValueError):
    """Raised when a supplied `evidence_records` entry or `semantic_hints`
    entry is structurally invalid.

    Never raised because two records fail to correlate, because a group
    ends up informational-only, or because a semantic hint's verdict is
    `"uncertain"` -- every one of those is a normal, successfully
    computed result, not an error.
    """


def _raise(code: str, detail: str) -> None:
    raise BugBountyFindingCorrelationError(f"{code}: {detail}")


def _canonical_digest_hex(value: Any, length: int | None = None) -> str:
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return digest[:length] if length else digest


def _validate_evidence_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(EVIDENCE_REQUIRED_FIELDS):
        _raise("INVALID_EVIDENCE_RECORD", "each evidence record must contain exactly the normalized evidence fields")
    evidence_id = value.get("evidence_id")
    if not isinstance(evidence_id, str) or not evidence_id.strip():
        _raise("INVALID_EVIDENCE_RECORD", "evidence_id must be a non-blank string")
    return dict(value)


# ---------------------------------------------------------------------------
# Fingerprinting.
# ---------------------------------------------------------------------------


def _normalize_path(path: Any) -> str | None:
    if not isinstance(path, str) or not path:
        return None
    if path == "/":
        return path
    return path.rstrip("/")


def _category(record: Mapping[str, Any]) -> str | None:
    for field in ("cwe", "vulnerability_class", "observation_type"):
        value = record.get(field)
        if isinstance(value, str) and value.strip():
            return f"{field}:{value.strip()}"
    return None


def _fingerprint(record: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        record.get("host"),
        record.get("port"),
        _normalize_path(record.get("path")),
        record.get("parameter"),
        _category(record),
    )


# ---------------------------------------------------------------------------
# Union-find for deterministic group merging.
# ---------------------------------------------------------------------------


class _UnionFind:
    def __init__(self, items: list[str]) -> None:
        self._parent = {item: item for item in items}

    def find(self, item: str) -> str:
        while self._parent[item] != item:
            self._parent[item] = self._parent[self._parent[item]]
            item = self._parent[item]
        return item

    def union(self, a: str, b: str) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            # Deterministic tie-break: smaller id string becomes the root.
            if root_b < root_a:
                root_a, root_b = root_b, root_a
            self._parent[root_b] = root_a


# ---------------------------------------------------------------------------
# Semantic hint validation.
# ---------------------------------------------------------------------------


def _validate_semantic_hint(value: Any, *, known_evidence_ids: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_SEMANTIC_HINT_REQUIRED_FIELDS):
        _raise("INVALID_SEMANTIC_HINT", "each semantic hint must contain exactly the four required fields")
    evidence_id_a = value.get("evidence_id_a")
    evidence_id_b = value.get("evidence_id_b")
    if not isinstance(evidence_id_a, str) or evidence_id_a not in known_evidence_ids:
        _raise("INVALID_SEMANTIC_HINT", "evidence_id_a must reference a supplied evidence record")
    if not isinstance(evidence_id_b, str) or evidence_id_b not in known_evidence_ids:
        _raise("INVALID_SEMANTIC_HINT", "evidence_id_b must reference a supplied evidence record")
    if evidence_id_a == evidence_id_b:
        _raise("INVALID_SEMANTIC_HINT", "evidence_id_a and evidence_id_b must differ")
    if value.get("verdict") not in SEMANTIC_VERDICTS:
        _raise("INVALID_SEMANTIC_HINT", "verdict must be one of SEMANTIC_VERDICTS")
    rationale = value.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        _raise("INVALID_SEMANTIC_HINT", "rationale must be a non-blank string")
    return {
        "evidence_id_a": evidence_id_a, "evidence_id_b": evidence_id_b,
        "verdict": value["verdict"], "rationale": rationale.strip(),
    }


# ---------------------------------------------------------------------------
# Group construction.
# ---------------------------------------------------------------------------


def _highest(values: list[str | None], order: tuple[str, ...]) -> str | None:
    present = [value for value in values if value in order]
    if not present:
        return None
    return max(present, key=order.index)


def _bump_one_level(value: str | None, order: tuple[str, ...]) -> str | None:
    if value not in order:
        return value
    index = order.index(value)
    return order[min(index + 1, len(order) - 1)]


def _build_group(members_unordered: list[Mapping[str, Any]]) -> dict[str, Any]:
    # Ordered by evidence_digest (always unique per distinct record,
    # unlike evidence_id -- see the internal-indexing note above) for
    # deterministic output regardless of input order.
    members = sorted(members_unordered, key=lambda record: record["evidence_digest"])
    member_ids = [record["evidence_id"] for record in members]
    source_tools = sorted({record["source_tool"] for record in members})
    corroboration_count = len(source_tools)
    multi_tool_corroborated = corroboration_count >= 2

    severities = [record.get("technical_severity") for record in members]
    confidences = [record.get("confidence") for record in members]
    aggregated_severity = _highest(severities, _SEVERITY_ORDER)
    base_confidence = _highest(confidences, _CONFIDENCE_ORDER)
    aggregated_confidence = _bump_one_level(base_confidence, _CONFIDENCE_ORDER) if multi_tool_corroborated else base_confidence

    # `vulnerability_class` is deliberately NOT one of these signals.
    # core.bug_bounty_evidence_normalization always populates it for
    # ZAP/Burp DAST observations now (a closed CWE mapping, or an
    # explicit generic placeholder when no defensible mapping exists) --
    # so its mere presence no longer indicates the source tool asserted
    # anything beyond "this was a DAST-shaped observation." technical
    # _severity/cwe/cve remain the only fields a tool sets specifically
    # because it is reporting a real condition, never as a structural
    # formality -- Nmap's bare port-open observation and ZAP's own
    # informational-risk alerts (e.g. "Modern Web Application") both
    # correctly stay informational under this check.
    is_informational = all(
        not record.get("technical_severity") and not record.get("cwe") and not record.get("cve")
        for record in members
    )

    cve_union: list[str] = []
    for record in members:
        for cve in record.get("cve") or []:
            if cve not in cve_union:
                cve_union.append(cve)

    representative = members[0]
    for record in members:
        if record.get("title"):
            representative = record
            break

    group_id = "CG-" + _canonical_digest_hex([record["evidence_digest"] for record in members], 16)

    return {
        "group_id": group_id,
        "member_evidence_ids": member_ids,
        "source_tools": source_tools,
        "corroboration_count": corroboration_count,
        "multi_tool_corroborated": multi_tool_corroborated,
        "is_informational": is_informational,
        "representative_title": representative.get("title"),
        "host": representative.get("host"),
        "port": representative.get("port"),
        "path": representative.get("path"),
        "parameter": representative.get("parameter"),
        "vulnerability_class": representative.get("vulnerability_class"),
        "cwe": representative.get("cwe"),
        "owasp_category": representative.get("owasp_category"),
        "cve": cve_union,
        "aggregated_technical_severity": aggregated_severity,
        "aggregated_confidence": aggregated_confidence,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def correlate_bug_bounty_evidence(*, evidence_records: Any, semantic_hints: Any = None) -> dict[str, Any]:
    """Deterministically correlate a batch of already-normalized evidence
    records into canonical-candidate groups. Performs no I/O of any
    kind, calls no LLM, and executes nothing -- `execution_performed` is
    always `False`.

    `evidence_records` is required and keyword-only, and must be a list
    of mappings each shaped exactly like `core.
    bug_bounty_evidence_normalization.EVIDENCE_REQUIRED_FIELDS` (this
    module's own input contract is, by design, that module's exact
    output shape). `semantic_hints` is optional (default `None`, treated
    as empty) -- when supplied, each entry must contain exactly
    `evidence_id_a`, `evidence_id_b` (each referencing a supplied
    record's own `evidence_id`), `verdict` (one of `SEMANTIC_VERDICTS`),
    and `rationale` (a non-blank string). This function never calls an
    LLM to produce these -- they must already exist.

    Grouping proceeds in this fixed order: (1) exact duplicates (same
    `evidence_digest`) are collapsed, counted in `duplicate_evidence_count`,
    and only the first occurrence is kept; (2) records sharing a
    deterministic fingerprint (host/port/path/parameter/category -- see
    module docstring, never title text) are grouped; (3) records sharing
    any overlapping CVE are grouped, regardless of fingerprint; (4) a
    `same_finding` semantic hint additionally groups its two referenced
    records, but only if they are not already in the same group -- a
    hint can never split an existing deterministic group.
    `different_finding`/`uncertain` hints never merge anything;
    `uncertain` hints are collected into `uncertain_correlations` for
    human review instead.

    Returns a new dict containing exactly `correlation_version`,
    `groups` (each built by `_build_group` -- see its own fields),
    `duplicate_evidence_count`, `uncertain_correlations`,
    `total_input_records`, `total_groups`, `execution_performed` (always
    `False`).

    Neither `evidence_records` nor `semantic_hints` (nor any nested value
    within either) is ever mutated.

    Raises `BugBountyFindingCorrelationError` for a structurally invalid
    `evidence_records` entry or `semantic_hints` entry (including a hint
    referencing an unknown `evidence_id`). Never raises because two
    records fail to correlate or because every group ends up
    informational -- every one of those is a normal, successfully
    computed result.
    """
    if not isinstance(evidence_records, list):
        _raise("INVALID_EVIDENCE_RECORDS", "evidence_records must be a list")
    validated_records = [_validate_evidence_record(item) for item in evidence_records]
    total_input_records = len(validated_records)

    # Exact-duplicate collapse (by evidence_digest, first occurrence wins).
    deduplicated: list[dict[str, Any]] = []
    seen_digests: set[str] = set()
    duplicate_evidence_count = 0
    for record in validated_records:
        digest = record["evidence_digest"]
        if digest in seen_digests:
            duplicate_evidence_count += 1
            continue
        seen_digests.add(digest)
        deduplicated.append(record)

    # Internal grouping identity is always the record's own position in
    # `deduplicated`, never its evidence_id -- evidence_id is a content-
    # correlation identifier (see core.bug_bounty_evidence_normalization),
    # not a uniqueness guarantee this module is entitled to assume about
    # its input. Two distinct, non-duplicate records could in principle
    # share an evidence_id; indexing internally by position guarantees
    # neither is ever silently dropped, regardless of what any caller
    # (this project's own normalizer, or any other) hands in.
    internal_ids = [str(index) for index in range(len(deduplicated))]
    uf = _UnionFind(internal_ids)

    evidence_id_to_internal_ids: dict[str, list[str]] = {}
    for internal_id, record in zip(internal_ids, deduplicated):
        evidence_id_to_internal_ids.setdefault(record["evidence_id"], []).append(internal_id)

    # Fingerprint grouping.
    fingerprint_buckets: dict[tuple[Any, ...], list[str]] = {}
    for internal_id, record in zip(internal_ids, deduplicated):
        fingerprint_buckets.setdefault(_fingerprint(record), []).append(internal_id)
    for bucket_ids in fingerprint_buckets.values():
        for other_id in bucket_ids[1:]:
            uf.union(bucket_ids[0], other_id)

    # CVE-overlap grouping.
    cve_buckets: dict[str, list[str]] = {}
    for internal_id, record in zip(internal_ids, deduplicated):
        for cve in record.get("cve") or []:
            cve_buckets.setdefault(cve, []).append(internal_id)
    for bucket_ids in cve_buckets.values():
        for other_id in bucket_ids[1:]:
            uf.union(bucket_ids[0], other_id)

    # Semantic hints -- evidence_id_a/evidence_id_b may each resolve to
    # more than one internal record if the input contains a colliding
    # evidence_id; every combination is unioned, since the hint cannot
    # disambiguate which specific record it meant.
    known_evidence_ids = frozenset(evidence_id_to_internal_ids.keys())
    validated_hints = [
        _validate_semantic_hint(item, known_evidence_ids=known_evidence_ids)
        for item in (semantic_hints or [])
    ]
    uncertain_correlations: list[dict[str, Any]] = []
    for hint in validated_hints:
        if hint["verdict"] == "same_finding":
            for internal_a in evidence_id_to_internal_ids[hint["evidence_id_a"]]:
                for internal_b in evidence_id_to_internal_ids[hint["evidence_id_b"]]:
                    if uf.find(internal_a) != uf.find(internal_b):
                        uf.union(internal_a, internal_b)
        elif hint["verdict"] == "uncertain":
            uncertain_correlations.append({
                "evidence_id_a": hint["evidence_id_a"], "evidence_id_b": hint["evidence_id_b"],
                "rationale": hint["rationale"],
            })
        # "different_finding" is an explicit non-merge decision -- no
        # group-structure action needed; it simply never triggers a union.

    # Assemble final groups -- every distinct input record (by position)
    # is guaranteed to appear in exactly one group's member list.
    groups_by_root: dict[str, list[dict[str, Any]]] = {}
    for internal_id, record in zip(internal_ids, deduplicated):
        groups_by_root.setdefault(uf.find(internal_id), []).append(record)

    groups = [_build_group(members) for members in groups_by_root.values()]
    groups.sort(key=lambda group: group["group_id"])

    return {
        "correlation_version": CORRELATION_VERSION,
        "groups": groups,
        "duplicate_evidence_count": duplicate_evidence_count,
        "uncertain_correlations": uncertain_correlations,
        "total_input_records": total_input_records,
        "total_groups": len(groups),
        "execution_performed": False,
    }
