"""Pure, deterministic Bug Bounty benchmark evaluator (Block 15F-A,
checkpoint 2 of 3).

This module answers exactly one question: *given an already-built
ground-truth manifest (see `core.juice_shop_ground_truth`) and an
already-produced list of real Bug Bounty findings, how many of the
manifest's supported cases were correctly detected, incorrectly
detected, or incorrectly missed -- and what do precision, recall, and
F1 look like over that supported set only?*

## Structured matching only -- never semantic, never fuzzy

A finding is matched to a ground-truth case using exactly three
deterministic, explainable rules (see `evaluate_benchmark`'s own
docstring): `vulnerability_class` equality, `affected_path` equality,
and, only when a case supplies one, a literal substring containment
check of `match_hint` against the finding's own `title`/evidence
`observation` text. This module never uses an LLM, an embedding model,
a vector index, or any prose-similarity heuristic of any kind -- every
match is reproducible by hand from the two inputs alone.

## Supported ground truth only -- never invented coverage

This module scores **only** the cases present in
`ground_truth['supported_cases']`. It never reads, and never penalizes
a finding against, `unsupported_categories`/`out_of_scope_categories`
-- those exist in the manifest for honest disclosure only, never as
scored recall denominators.

## A negative case failing is preserved, never silently repaired

When a negative case (`expected_detection: false`) is violated by a
real finding -- e.g. the known `/sitemap.xml` SPA-fallback detector
limitation -- this module reports it plainly as a false positive. It
never adjusts, drops, or reinterprets a supplied ground-truth case to
make a result look better, and it never raises merely because a
violation exists -- a false positive is a normal, informative benchmark
result, not an error condition.

## What this module never claims

A `"pass"`-shaped result here is never described as "ThreatTrace
accuracy," a statistically significant result, or evidence of
production security improvement -- it is a deterministic count over
exactly the supplied `ground_truth`/`findings` pair. `severity_agreement`,
`evidence_completeness`, and `supported_detection_coverage` are each
narrow, explicitly-named measurements, never folded into a single
"accuracy" figure.

## No external capabilities

This module performs no network, filesystem, environment-variable,
subprocess, system-clock, or randomness access; generates no UUID or
timestamp; calls no Supabase/database, MCP, or LLM/model of any kind.
It imports no other `core.*` module -- `ground_truth` and `findings`
are consumed as plain, duck-typed, caller-supplied mappings, validated
only against the minimal fields this module itself reads, following
this project's established convention that each module owns its own
copy of a shape it shares in spirit with another module.

`BenchmarkEvaluationError` and `evaluate_benchmark` are this module's
only public symbols (plus its fixed vocabulary constants).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

BENCHMARK_VERSION = "1"

_EVIDENCE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

_CASE_REQUIRED_FIELDS = (
    "case_id",
    "category",
    "detector_capability",
    "expected_detection",
    "expected_observation",
    "expected_severity",
    "evidence_requirement",
)

_EVIDENCE_REQUIREMENT_FIELDS = frozenset({"affected_path", "match_hint"})

_FINDING_REQUIRED_FIELDS = (
    "finding_id",
    "vulnerability_class",
    "affected_path",
    "title",
    "technical_severity",
    "evidence",
)


class BenchmarkEvaluationError(ValueError):
    """Raised when a supplied `ground_truth`/`findings` input is
    structurally invalid.

    Every message begins with one of a fixed set of stable codes:
    `INVALID_GROUND_TRUTH`, `INVALID_CASE`, `DUPLICATE_CASE_ID`,
    `INVALID_FINDINGS`, `INVALID_FINDING`.

    Never raised because a negative case was violated (a false
    positive), because a positive case has no matching finding (a
    false negative), or because `findings` is empty -- every one of
    those is a normal, successfully computed benchmark result, not an
    error condition.
    """


def _raise(code: str, detail: str) -> None:
    raise BenchmarkEvaluationError(f"{code}: {detail}")


def _in_set(value: Any, allowed: frozenset[str] | None = None) -> bool:
    return isinstance(value, str) and (allowed is None or value in allowed)


# ---------------------------------------------------------------------------
# Minimal, locally-owned structural contracts. Neither
# core.juice_shop_ground_truth nor core.bug_bounty_findings is imported --
# only the fields this module itself reads are validated.
# ---------------------------------------------------------------------------


def _validate_case(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not set(_CASE_REQUIRED_FIELDS).issubset(set(value)):
        _raise("INVALID_CASE", "each supported case must contain at least the required fields")

    case_id = value.get("case_id")
    if not isinstance(case_id, str) or not case_id.strip():
        _raise("INVALID_CASE", "case_id must be a non-blank string")

    detector_capability = value.get("detector_capability")
    if not isinstance(detector_capability, str) or not detector_capability.strip():
        _raise("INVALID_CASE", "detector_capability must be a non-blank string")

    expected_detection = value.get("expected_detection")
    if expected_detection is not True and expected_detection is not False:
        _raise("INVALID_CASE", "expected_detection must be a bool")

    expected_severity = value.get("expected_severity")
    if expected_severity is not None and not isinstance(expected_severity, str):
        _raise("INVALID_CASE", "expected_severity must be null or a string")

    evidence_requirement = value.get("evidence_requirement")
    if not isinstance(evidence_requirement, Mapping) or set(evidence_requirement) != _EVIDENCE_REQUIREMENT_FIELDS:
        _raise("INVALID_CASE", "evidence_requirement must contain exactly affected_path/match_hint")

    affected_path = evidence_requirement.get("affected_path")
    if not isinstance(affected_path, str) or not affected_path.strip():
        _raise("INVALID_CASE", "evidence_requirement.affected_path must be a non-blank string")

    match_hint = evidence_requirement.get("match_hint")
    if match_hint is not None and (not isinstance(match_hint, str) or not match_hint.strip()):
        _raise("INVALID_CASE", "evidence_requirement.match_hint must be null or a non-blank string")

    return {
        "case_id": case_id,
        "detector_capability": detector_capability,
        "expected_detection": expected_detection,
        "expected_severity": expected_severity,
        "affected_path": affected_path,
        "match_hint": match_hint,
    }


def _validate_ground_truth(value: Any) -> tuple[str | None, str | None, list[dict[str, Any]]]:
    if not isinstance(value, Mapping):
        _raise("INVALID_GROUND_TRUTH", "ground_truth must be a mapping")

    target = value.get("target")
    if target is not None and not isinstance(target, str):
        _raise("INVALID_GROUND_TRUTH", "target must be null or a string")

    target_version_or_digest = value.get("target_version_or_digest")
    if target_version_or_digest is not None and not isinstance(target_version_or_digest, str):
        _raise("INVALID_GROUND_TRUTH", "target_version_or_digest must be null or a string")

    raw_cases = value.get("supported_cases")
    if not isinstance(raw_cases, list) or len(raw_cases) == 0:
        _raise("INVALID_GROUND_TRUTH", "ground_truth['supported_cases'] must be a non-empty list")

    validated_cases: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for raw_case in raw_cases:
        case = _validate_case(raw_case)
        if case["case_id"] in seen_ids:
            _raise("DUPLICATE_CASE_ID", f"duplicate case_id: {case['case_id']!r}")
        seen_ids.add(case["case_id"])
        validated_cases.append(case)

    return target, target_version_or_digest, validated_cases


def _validate_finding(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not set(_FINDING_REQUIRED_FIELDS).issubset(set(value)):
        _raise("INVALID_FINDING", "each finding must contain at least the required fields")

    finding_id = value.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip():
        _raise("INVALID_FINDING", "finding_id must be a non-blank string")

    vulnerability_class = value.get("vulnerability_class")
    if not isinstance(vulnerability_class, str) or not vulnerability_class.strip():
        _raise("INVALID_FINDING", "vulnerability_class must be a non-blank string")

    affected_path = value.get("affected_path")
    if not isinstance(affected_path, str) or not affected_path.strip():
        _raise("INVALID_FINDING", "affected_path must be a non-blank string")

    title = value.get("title")
    if not isinstance(title, str) or not title.strip():
        _raise("INVALID_FINDING", "title must be a non-blank string")

    technical_severity = value.get("technical_severity")
    if not isinstance(technical_severity, str) or not technical_severity.strip():
        _raise("INVALID_FINDING", "technical_severity must be a non-blank string")

    evidence = value.get("evidence")
    if not isinstance(evidence, list):
        _raise("INVALID_FINDING", "evidence must be a list")

    observations: list[str] = []
    complete = len(evidence) > 0
    for item in evidence:
        if not isinstance(item, Mapping):
            _raise("INVALID_FINDING", "each evidence item must be a mapping")
        observation = item.get("observation")
        if isinstance(observation, str) and observation.strip():
            observations.append(observation)
        else:
            complete = False
        digest = item.get("evidence_digest")
        if not isinstance(digest, str) or not _EVIDENCE_DIGEST_PATTERN.fullmatch(digest):
            complete = False

    return {
        "finding_id": finding_id,
        "vulnerability_class": vulnerability_class,
        "affected_path": affected_path,
        "title": title,
        "technical_severity": technical_severity,
        "observations": observations,
        "evidence_complete": complete,
    }


def _validate_findings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _raise("INVALID_FINDINGS", "findings must be a list")
    return [_validate_finding(item) for item in value]


# ---------------------------------------------------------------------------
# Deterministic structured matching.
# ---------------------------------------------------------------------------


def _case_matches_finding(case: Mapping[str, Any], finding: Mapping[str, Any]) -> bool:
    if finding["vulnerability_class"] != case["detector_capability"]:
        return False
    if finding["affected_path"] != case["affected_path"]:
        return False
    match_hint = case["match_hint"]
    if match_hint is None:
        return True
    haystacks = [finding["title"], *finding["observations"]]
    return any(match_hint in haystack for haystack in haystacks)


def _find_matching_finding(case: Mapping[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    for finding in findings:
        if _case_matches_finding(case, finding):
            return finding
    return None


def _mean_or_none(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate_benchmark(*, ground_truth: Any, findings: Any) -> dict[str, Any]:
    """Deterministically evaluate an already-produced list of real Bug
    Bounty findings against an already-built ground-truth manifest's
    `supported_cases` only. Performs no I/O of any kind.

    Both parameters are required and keyword-only. `ground_truth` must
    be a mapping containing a non-empty `supported_cases` list, each
    entry shaped at minimum like `core.juice_shop_ground_truth`'s own
    per-case contract (`case_id`, `detector_capability`,
    `expected_detection`, `expected_severity`, `evidence_requirement
    .affected_path`/`.match_hint`) -- this function never imports or
    calls that module. `findings` must be a list (may be empty), each
    entry shaped at minimum like `core.bug_bounty_findings.
    create_bug_bounty_finding`'s own return value (`finding_id`,
    `vulnerability_class`, `affected_path`, `title`, `technical_severity`,
    `evidence`) -- this function never imports or calls that module
    either.

    ## Matching rule (exactly three deterministic checks, in order)

    A finding matches a case iff: (1) `finding['vulnerability_class'] ==
    case['detector_capability']`; (2) `finding['affected_path'] ==
    case['evidence_requirement']['affected_path']`; (3) when the case's
    `match_hint` is not `None`, that exact substring appears in the
    finding's own `title` or in at least one of its evidence items'
    `observation` text. No LLM, embedding, or fuzzy/prose-similarity
    matching is ever used. A case's status is "detected" when **any**
    supplied finding matches it -- duplicate matching findings never
    inflate a case's count beyond one detection.

    ## Outcome per case

    - `expected_detection: true` (a positive case): a match is a true
      positive; no match is a false negative.
    - `expected_detection: false` (a negative case): a match is a false
      positive (the case's own prohibited/absent observation was
      violated); no match is a true negative.

    A finding matching zero supported cases is counted in
    `unmatched_finding_count` and listed (by compact identifiers only --
    `finding_id`/`vulnerability_class`/`affected_path`, never a
    response body) in `unmatched_findings` -- never automatically
    classified as a false positive.

    Returns a new dict containing exactly `benchmark_version` (always
    `"1"`), `target`, `target_version_or_digest` (both echoed from
    `ground_truth` when present, else `None`), `supported_ground_truth_count`,
    `positive_case_count`, `negative_case_count`, `true_positive_count`,
    `false_positive_count`, `false_negative_count`, `true_negative_count`,
    `precision` (`TP/(TP+FP)`, `None` when `TP+FP == 0`), `recall`
    (`TP/(TP+FN)`, `None` when `TP+FN == 0`), `f1` (the harmonic mean of
    `precision`/`recall`, `None` when either is `None` or their sum is
    `0`), `unmatched_finding_count`, `unmatched_findings`, `case_results`
    (one `{case_id, expected_detection, matched, outcome, matched_finding_id}`
    entry per supported case, `outcome` one of `"TP"`/`"FP"`/`"FN"`/`"TN"`),
    `severity_agreement` (`{comparable_count, exact_match_count, rate}`
    -- computed only over true-positive cases, comparing `case
    ['expected_severity']` to its matched finding's `technical_severity`),
    `evidence_completeness` (`{finding_count, complete_count, rate}` --
    a finding is "complete" when its `evidence` is non-empty and every
    item carries a non-blank `observation` and a well-formed
    `evidence_digest`), `supported_detection_coverage`
    (`{detected_positive_cases, positive_supported_cases, rate}`),
    `execution_performed` (always `False`).

    Neither `ground_truth` nor `findings` (nor any nested value within
    either) is ever mutated, and no mutable object from either is
    retained by reference in the result.

    Raises `BenchmarkEvaluationError` for a structurally invalid
    `ground_truth`/`findings`, including a duplicate `case_id`. Never
    raises because a negative case was violated, because a positive
    case has no match, or because `findings` is empty -- every one of
    those is a normal, successfully computed result.
    """
    target, target_version_or_digest, cases = _validate_ground_truth(ground_truth)
    validated_findings = _validate_findings(findings)

    positive_cases = [case for case in cases if case["expected_detection"] is True]
    negative_cases = [case for case in cases if case["expected_detection"] is False]

    true_positive_count = 0
    false_positive_count = 0
    false_negative_count = 0
    true_negative_count = 0
    case_results: list[dict[str, Any]] = []

    severity_comparable = 0
    severity_exact_match = 0

    matched_finding_ids: set[str] = set()

    for case in cases:
        matched_finding = _find_matching_finding(case, validated_findings)
        matched = matched_finding is not None
        if matched:
            matched_finding_ids.add(matched_finding["finding_id"])

        if case["expected_detection"] is True:
            if matched:
                outcome = "TP"
                true_positive_count += 1
                severity_comparable += 1
                if case["expected_severity"] == matched_finding["technical_severity"]:
                    severity_exact_match += 1
            else:
                outcome = "FN"
                false_negative_count += 1
        else:
            if matched:
                outcome = "FP"
                false_positive_count += 1
            else:
                outcome = "TN"
                true_negative_count += 1

        case_results.append({
            "case_id": case["case_id"],
            "expected_detection": case["expected_detection"],
            "matched": matched,
            "outcome": outcome,
            "matched_finding_id": matched_finding["finding_id"] if matched_finding is not None else None,
        })

    unmatched_findings = [
        {
            "finding_id": finding["finding_id"],
            "vulnerability_class": finding["vulnerability_class"],
            "affected_path": finding["affected_path"],
        }
        for finding in validated_findings
        if finding["finding_id"] not in matched_finding_ids
    ]

    precision = _mean_or_none(true_positive_count, true_positive_count + false_positive_count)
    recall = _mean_or_none(true_positive_count, true_positive_count + false_negative_count)
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)

    complete_count = sum(1 for finding in validated_findings if finding["evidence_complete"])
    evidence_completeness = {
        "finding_count": len(validated_findings),
        "complete_count": complete_count,
        "rate": _mean_or_none(complete_count, len(validated_findings)),
    }

    supported_detection_coverage = {
        "detected_positive_cases": true_positive_count,
        "positive_supported_cases": len(positive_cases),
        "rate": _mean_or_none(true_positive_count, len(positive_cases)),
    }

    return {
        "benchmark_version": BENCHMARK_VERSION,
        "target": target,
        "target_version_or_digest": target_version_or_digest,
        "supported_ground_truth_count": len(cases),
        "positive_case_count": len(positive_cases),
        "negative_case_count": len(negative_cases),
        "true_positive_count": true_positive_count,
        "false_positive_count": false_positive_count,
        "false_negative_count": false_negative_count,
        "true_negative_count": true_negative_count,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "unmatched_finding_count": len(unmatched_findings),
        "unmatched_findings": unmatched_findings,
        "case_results": case_results,
        "severity_agreement": {
            "comparable_count": severity_comparable,
            "exact_match_count": severity_exact_match,
            "rate": _mean_or_none(severity_exact_match, severity_comparable),
        },
        "evidence_completeness": evidence_completeness,
        "supported_detection_coverage": supported_detection_coverage,
        "execution_performed": False,
    }
