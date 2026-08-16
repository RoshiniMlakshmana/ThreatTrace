"""Pure, deterministic bridge between one completed Bug Bounty run's real
canonical findings and the existing OWASP Juice Shop benchmark contract
(`core.juice_shop_ground_truth` + `core.benchmark_evaluation`), built for
the live platform's `GET /api/runs/{run_id}/evaluation` endpoint.

## Never invents ground truth for an arbitrary target

`core.juice_shop_ground_truth.build_baseline_ground_truth` describes one
specific, fixed target (the local Juice Shop image at
`DEFAULT_BASELINE_TARGET_ORIGIN`). This module never applies that ground
truth to a run whose target wasn't that origin -- `run_type != "bug_bounty"`
or a non-matching `target_summary` both deterministically produce
`evaluation_state: "not_evaluated"`, never a fabricated or default score.
An incomplete run (no report yet) produces `evaluation_state:
"run_incomplete"` -- also never a score, and never zeros presented as a
measured result.

## Detection accuracy and correlation quality are reported separately

The benchmark result (`true_positive_count`/... /`f1`/
`supported_benchmark_accuracy`) comes from `core.benchmark_evaluation.
evaluate_benchmark` unmodified -- this module never re-derives or
overrides a TP/FP/FN/TN outcome itself. `correlation_quality` is a
distinct, separately-reported section (`canonical_finding_count`,
`multi_tool_corroborated_count`, `duplicate_evidence_count`) and is never
folded into precision/recall/F1 -- a run can score perfectly on the
benchmark while its cross-tool corroboration count is genuinely 0, and
this module reports both facts honestly rather than picking one.

## Structural exclusions are disclosed, never silently dropped

`core.benchmark_evaluation.evaluate_benchmark` requires every finding's
`vulnerability_class`/`affected_path` to be non-blank; a canonical
finding this module cannot express in that shape (any future tool whose
normalization does not yet populate both fields the way
`core.bug_bounty_evidence_normalization` now does for ZAP/Burp) is
excluded from the `evaluate_benchmark` call and listed in
`structurally_excluded_findings` instead of causing the whole evaluation
to fail or being silently dropped.

## `supported_benchmark_accuracy`, never a bare "accuracy"

`(TP+TN)/(TP+TN+FP+FN)` is computed here under the explicit name
`supported_benchmark_accuracy` -- this module never returns a field
named `overall_accuracy` or any other name that could be read as a claim
about ThreatTrace's general detection accuracy.

## No I/O of any kind

This module performs no network, filesystem, environment-variable,
subprocess, clock, randomness, database/Supabase, MCP, or LLM/model
access. `run`/`events` are already-produced, caller-supplied data (the
live backend's own `RunStore`/`EventBus` state) -- no scanner is ever
invoked here, and no new tool execution ever occurs as a side effect of
evaluating a run that already completed.

`BugBountyJuiceShopEvaluationError`, `EVALUATION_STATES`,
`EVALUATION_VERSION`, and
`evaluate_bug_bounty_run_against_juice_shop_benchmark` are this module's
public symbols.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from core.benchmark_evaluation import BENCHMARK_VERSION, evaluate_benchmark
from core.juice_shop_ground_truth import (
    BASELINE_TARGET_VERSION_OR_DIGEST,
    DEFAULT_BASELINE_TARGET_ORIGIN,
    TARGET_LABEL,
    build_baseline_ground_truth,
)

EVALUATION_VERSION = "1"

EVALUATION_STATES = frozenset({"evaluated", "not_evaluated", "run_incomplete"})

_REQUIRED_TOOLS = ("http_assessor", "nmap", "nuclei", "zap")

_FIXED_LIMITATIONS = (
    "This benchmark covers only 9 predefined supported conditions on one fixed Juice Shop image -- it is not a general vulnerability-coverage claim.",
    "Unsupported vulnerability classes (SQL injection, executable XSS, IDOR/access control, SSRF, command injection, authenticated workflow testing) are never scored -- absence of a match there is not a false negative.",
    "Application-logic vulnerabilities requiring authenticated, stateful, or multi-step interaction are outside this benchmark's scope entirely.",
    "Structural/scanner performance on this fixed benchmark is not equivalent to production security accuracy against arbitrary targets.",
    "Results apply to the exact Juice Shop image digest recorded below only -- a different image build is not guaranteed to score the same.",
)


class BugBountyJuiceShopEvaluationError(ValueError):
    """Raised when a supplied `run`/`events` input is structurally
    invalid.

    Never raised because a run's target doesn't match the Juice Shop
    benchmark origin, because a run is incomplete, or because a
    canonical finding cannot be expressed in `evaluate_benchmark`'s
    required shape -- every one of those is a normal, honestly-reported
    outcome (`evaluation_state`/`structurally_excluded_findings`), not
    an error.
    """


def _raise(code: str, detail: str) -> None:
    raise BugBountyJuiceShopEvaluationError(f"{code}: {detail}")


def _is_juice_shop_target(target_summary: Any) -> bool:
    if not isinstance(target_summary, str) or not target_summary.strip():
        return False
    return target_summary.rstrip("/") == DEFAULT_BASELINE_TARGET_ORIGIN.rstrip("/")


def _translate_canonical_finding(cf: Mapping[str, Any]) -> dict[str, Any]:
    evidence = [
        {"observation": obs.get("sanitized_evidence") or obs.get("title"), "evidence_digest": digest}
        for digest, obs in zip(cf.get("evidence_digests") or [], cf.get("tool_observations") or [])
    ]
    return {
        "finding_id": cf.get("finding_id"),
        "vulnerability_class": cf.get("vulnerability_class"),
        "affected_path": cf.get("path"),
        "title": cf.get("title"),
        "technical_severity": cf.get("technical_severity"),
        "evidence": evidence,
    }


def _is_benchmark_structurally_valid(finding: Mapping[str, Any]) -> bool:
    vulnerability_class = finding.get("vulnerability_class")
    affected_path = finding.get("affected_path")
    return (
        isinstance(vulnerability_class, str) and bool(vulnerability_class.strip())
        and isinstance(affected_path, str) and bool(affected_path.strip())
    )


def _extract_tool_statuses(events: list[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    statuses: dict[str, dict[str, Any]] = {}
    for event in events:
        if not isinstance(event, Mapping):
            continue
        event_type = event.get("event_type")
        payload = event.get("sanitized_payload")
        if not isinstance(payload, Mapping):
            continue
        if event_type == "tool_completed":
            if "tool_id" in payload:
                entry = {
                    "status": payload.get("status"),
                    "observation_count": payload.get("observation_count"),
                }
                # Nuclei Reliability Step 1B: carry through any extra
                # per-tool telemetry the orchestrator's own event payload
                # supplied (profile/phases_attempted/phases_completed/
                # duration/partial_results for nuclei) -- never fabricated
                # here, only relayed from what the event already carries.
                for extra_key in ("profile", "phases_attempted", "phases_completed", "duration", "partial_results"):
                    if extra_key in payload:
                        entry[extra_key] = payload[extra_key]
                statuses[payload["tool_id"]] = entry
            elif "findings_count" in payload:
                # http_assessor's own tool_completed payload shape --
                # never carries a "tool_id" key, unlike nmap/nuclei/zap.
                statuses["http_assessor"] = {
                    "status": "completed" if payload.get("assessment_performed") else "not_performed",
                    "observation_count": payload.get("findings_count"),
                }
        elif event_type == "tool_failed":
            tool_id = payload.get("tool_id")
            if isinstance(tool_id, str):
                statuses[tool_id] = {"status": "not_executed", "reason": payload.get("reason"), "observation_count": 0}
    return statuses


def _tool_execution_section(*, report: Mapping[str, Any], events: list[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    requested = set(report.get("tools_requested") or [])
    permitted = set(report.get("tools_permitted") or [])
    executed = set(report.get("tools_executed") or [])
    statuses = _extract_tool_statuses(events)

    canonical_findings = report.get("canonical_findings") or []
    informational_observations = report.get("informational_observations") or []

    section: dict[str, dict[str, Any]] = {}
    for tool_id in _REQUIRED_TOOLS:
        tool_status = statuses.get(tool_id, {})
        canonical_contributed = sum(
            1 for cf in canonical_findings if tool_id in (cf.get("tools_used") or [])
        )
        informational_contributed = sum(
            1 for io in informational_observations if tool_id in (io.get("tools_used") or [])
        )
        entry = {
            "requested": tool_id in requested,
            "permitted": tool_id in permitted,
            "executed": tool_id in executed,
            "status": tool_status.get("status"),
            "observation_count": tool_status.get("observation_count"),
            "canonical_findings_contributed": canonical_contributed,
            "informational_contributed": informational_contributed,
        }
        if tool_id == "nuclei":
            # Nuclei Reliability Step 1B phase telemetry -- present only
            # when the real event payload actually carried it (older
            # runs predating this change simply won't have these keys).
            for extra_key in ("profile", "phases_attempted", "phases_completed", "duration", "partial_results"):
                if extra_key in tool_status:
                    entry[extra_key] = tool_status[extra_key]
        section[tool_id] = entry
    return section


def evaluate_bug_bounty_run_against_juice_shop_benchmark(
    *, run: Any, events: Any,
) -> dict[str, Any]:
    """Deterministically evaluate one already-completed Bug Bounty run's
    real canonical findings against the fixed Juice Shop benchmark.
    Performs no I/O of any kind.

    Both parameters are required and keyword-only. `run` must be a
    mapping shaped at minimum like `backend.run_store.RunStore.get_run`'s
    own return value (`run_id`, `run_type`, `status`, `target_summary`,
    `report`). `events` must be a list of mappings shaped like
    `backend.event_bus.EventBus.get_events`'s own return value -- used
    only to recover each tool's real completion status
    (`completed`/`timeout`/`not_executed`/...), which the report itself
    does not carry per-tool.

    Returns a dict always containing `evaluation_version` and
    `evaluation_state` (one of `EVALUATION_STATES`). When
    `evaluation_state == "not_evaluated"` (not a `bug_bounty` run, or a
    target other than the fixed Juice Shop origin) or `"run_incomplete"`
    (no report yet), only `run_id`/`evaluation_state`/`reason` are
    populated -- every score field is absent, never a fabricated zero.

    When `evaluation_state == "evaluated"`, additionally returns:
    `benchmark_name`, `benchmark_version`, `target_identity`,
    `target_digest`, `supported_positive_count`,
    `supported_negative_count`, `supported_total_count`,
    `true_positive_count`, `false_positive_count`,
    `false_negative_count`, `true_negative_count`, `precision`,
    `recall`, `f1`, `supported_benchmark_accuracy` (`(TP+TN)/(TP+TN+FP+
    FN)`, computed here under this explicit name -- never a bare
    `"accuracy"`/`"overall_accuracy"` field), `case_results` (each entry
    from `core.benchmark_evaluation.evaluate_benchmark`'s own output,
    enriched with `matched_title`/`matched_source_tools` looked up from
    the run's real canonical findings), `unmatched_findings`,
    `structurally_excluded_findings` (canonical findings that could not
    be expressed in `evaluate_benchmark`'s required shape -- never
    silently dropped), `correlation_quality`
    (`canonical_finding_count`/`multi_tool_corroborated_count`/
    `duplicate_evidence_count` -- reported separately from the
    precision/recall/F1 score above, on purpose), `tool_execution` (per-
    tool real status for `http_assessor`/`nmap`/`nuclei`/`zap`),
    `limitations` (a fixed, honest list plus any real per-run additions,
    e.g. a Nuclei timeout), `interpretation` (one safe-framing sentence
    built entirely from the real computed numbers above).

    Raises `BugBountyJuiceShopEvaluationError` only for a structurally
    invalid `run`/`events` input (e.g. `run` is not a mapping). Never
    raises because a run is incomplete, targets something other than
    Juice Shop, or contains a structurally-excludable finding -- every
    one of those is a normal, honestly-reported outcome.
    """
    if not isinstance(run, Mapping):
        _raise("INVALID_RUN", "run must be a mapping")
    if not isinstance(events, list):
        _raise("INVALID_EVENTS", "events must be a list")

    run_id = run.get("run_id")

    if run.get("run_type") != "bug_bounty" or not _is_juice_shop_target(run.get("target_summary")):
        return {
            "evaluation_version": EVALUATION_VERSION,
            "run_id": run_id,
            "evaluation_state": "not_evaluated",
            "reason": (
                "This run is not a Bug Bounty run against the fixed OWASP Juice Shop benchmark origin "
                f"({DEFAULT_BASELINE_TARGET_ORIGIN}) -- no known ground truth applies to it."
            ),
        }

    report = run.get("report")
    if not isinstance(report, Mapping):
        return {
            "evaluation_version": EVALUATION_VERSION,
            "run_id": run_id,
            "evaluation_state": "run_incomplete",
            "reason": "This run has not produced a report yet -- no benchmark evaluation is available.",
        }

    canonical_findings = report.get("canonical_findings") or []
    translated = [_translate_canonical_finding(cf) for cf in canonical_findings]
    valid_findings = [f for f in translated if _is_benchmark_structurally_valid(f)]
    excluded_findings = [
        {"finding_id": f["finding_id"], "title": f["title"], "reason": "missing vulnerability_class or affected_path"}
        for f in translated if not _is_benchmark_structurally_valid(f)
    ]

    ground_truth = build_baseline_ground_truth()
    result = evaluate_benchmark(ground_truth=ground_truth, findings=valid_findings)

    finding_lookup = {cf["finding_id"]: cf for cf in canonical_findings}
    enriched_case_results = []
    for case in result["case_results"]:
        matched_finding = finding_lookup.get(case["matched_finding_id"]) if case["matched_finding_id"] else None
        enriched_case_results.append({
            **case,
            "matched_title": matched_finding.get("title") if matched_finding else None,
            "matched_source_tools": matched_finding.get("tools_used") if matched_finding else None,
        })

    tp, fp, fn, tn = (
        result["true_positive_count"], result["false_positive_count"],
        result["false_negative_count"], result["true_negative_count"],
    )
    denominator = tp + fp + fn + tn
    supported_benchmark_accuracy = (tp + tn) / denominator if denominator else None

    correlation_summary = report.get("correlation_summary") or {}
    correlation_quality = {
        "canonical_finding_count": len(canonical_findings),
        "multi_tool_corroborated_count": correlation_summary.get("multi_tool_corroborated_count"),
        "duplicate_evidence_count": correlation_summary.get("duplicate_evidence_count"),
    }

    tool_execution = _tool_execution_section(report=report, events=events)

    limitations = list(_FIXED_LIMITATIONS)
    if tool_execution.get("nuclei", {}).get("status") == "timeout":
        limitations.append("Nuclei timed out in this run and contributed zero observations -- this did not change any of the 9 supported case outcomes, since none require Nuclei specifically.")
    if excluded_findings:
        limitations.append(
            f"{len(excluded_findings)} canonical finding(s) could not be submitted to the benchmark evaluator "
            "(missing vulnerability_class/affected_path) -- see structurally_excluded_findings; never counted as a false positive or false negative."
        )

    def _pct(value: float | None) -> str:
        return "N/A" if value is None else f"{value * 100:.0f}%"

    interpretation = (
        f"On this fixed, supported OWASP Juice Shop benchmark (image digest {BASELINE_TARGET_VERSION_OR_DIGEST}, "
        f"{result['supported_ground_truth_count']} predefined cases -- {result['positive_case_count']} positive, "
        f"{result['negative_case_count']} negative), this run scored precision={_pct(result['precision'])}, "
        f"recall={_pct(result['recall'])}, f1={_pct(result['f1'])} ({tp} TP, {fp} FP, {fn} FN, {tn} TN). "
        "This measures detection performance on these predefined supported cases for this fixed Juice Shop "
        "image only -- it is not a statement of ThreatTrace's overall accuracy."
    )

    return {
        "evaluation_version": EVALUATION_VERSION,
        "run_id": run_id,
        "evaluation_state": "evaluated",
        "benchmark_name": TARGET_LABEL,
        "benchmark_version": BENCHMARK_VERSION,
        "target_identity": TARGET_LABEL,
        "target_digest": BASELINE_TARGET_VERSION_OR_DIGEST,
        "supported_positive_count": result["positive_case_count"],
        "supported_negative_count": result["negative_case_count"],
        "supported_total_count": result["supported_ground_truth_count"],
        "true_positive_count": tp,
        "false_positive_count": fp,
        "false_negative_count": fn,
        "true_negative_count": tn,
        "precision": result["precision"],
        "recall": result["recall"],
        "f1": result["f1"],
        "supported_benchmark_accuracy": supported_benchmark_accuracy,
        "case_results": enriched_case_results,
        "unmatched_findings": result["unmatched_findings"],
        "structurally_excluded_findings": excluded_findings,
        "correlation_quality": correlation_quality,
        "tool_execution": tool_execution,
        "limitations": limitations,
        "interpretation": interpretation,
    }
