"""Pure, deterministic Research Evaluation Harness (Block 15E,
checkpoint A).

This module answers exactly one question: *given a caller-supplied
batch of already-existing, already-produced ThreatTrace scenario
records (each one a compact summary of a context-prioritization
result, a Security Governor decision, a Validated Security Experience
Memory admission, a security handoff stage history, and a caller-
reported approval/duration outcome), what deterministic, purely
observational research metrics can be computed over that batch?*

## What this module is, and is not

This is a **summarization layer only**. It never runs an experiment,
never produces a scenario record itself, and never calls any other
`core.*` module -- every `scenario_record` is externally/caller-
supplied structured data, exactly like a Block 15C stage result is
caller-supplied data describing work a role already did elsewhere. This
module never re-derives, re-validates against, or cross-checks a
scenario record against `core.context_prioritization`,
`core.security_governor`, `core.security_experience_memory`, or
`core.security_handoff` -- it consumes only the flat, minimal, locally-
owned 17-field scenario contract documented below, exactly like
`core.context_prioritization` never imports `core.bug_bounty_findings`.

The metrics this module computes are **descriptive summaries of the
supplied batch only**. They never prove: causal improvement, statistical
significance, production security improvement, successful remediation,
prevented exploitation, or guaranteed defense. `research_limitations`
states this explicitly, in every result this module can ever produce.

## `validated_defensive_experience` is a workflow judgment, not a
## vulnerability judgment

A scenario's `validated_defensive_experience: true` describes that
scenario's own **defensive workflow outcome** (mirroring Block 15D's
`experience_status: "validated"`/`reusable: true` admission) -- it never
means the scenario's own `technical_severity`/underlying finding was
itself validated, remediated, or confirmed exploitable/unexploitable.
This module never rewrites, recomputes, or infers that judgment; it is
read once, verbatim, from each caller-supplied scenario record.

## MTVD and the stage-count proxy are two different, never-conflated
## measurements

Mean Time to Validated Defense (`mtvd`) uses only a scenario's own
caller-supplied `duration_minutes` -- this module never reads a system
clock, never generates a timestamp, and never substitutes a stage count
for a duration. The separate `stage_count_proxy` metric is explicitly
labeled a **stage-count proxy**, never "time" or "duration," and is
computed independently of `mtvd`.

## Recorded stage/approval/evidence data is never proof of execution,
## authentication, or authenticity

A `handoff_stage_results` entry describes a caller-reported stage
outcome being recorded, never an executed action -- exactly like a
Block 15C stage result. `approval_state` is caller-supplied structured
data, never an authenticated approval. `final_evidence_references`
overlapping a scenario's `source_evidence_digests` establishes
**correlation only**, never authenticity or a cryptographic proof of
origin -- exactly like every content-correlation ID elsewhere in this
project.

## No external capabilities

This module performs no network, filesystem, environment-variable,
subprocess, system-clock, or randomness access; generates no UUID or
timestamp; calls no Supabase/database, MCP, or LLM/model of any kind;
and uses no embedding or vector-database library. It imports no other
`core.*` module -- every closed vocabulary used here (severities,
priority directions, modes, Governor decisions, memory statuses,
handoff stages, approval states) is this module's own private copy,
following this project's established convention that each module owns
its own copy of a shape it shares in spirit with another module.

`ResearchEvaluationError` and `evaluate_research_experiment` are this
module's only public symbols (plus its fixed vocabulary constants).
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

EVALUATION_VERSION = "1"
EXPERIMENT_VERSION = "1"

SEVERITIES = frozenset({"low", "medium", "high", "critical"})
_SEVERITY_BAND: Mapping[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}

PRIORITY_DIRECTIONS = frozenset({"raised", "unchanged", "lowered"})
MODES = frozenset({"enabled", "disabled"})
GOVERNOR_DECISIONS = frozenset({"allow", "warn", "require_review", "block", "freeze"})
_UNSAFE_GOVERNOR_DECISIONS = frozenset({"block", "freeze"})

MEMORY_STATUSES = frozenset({"candidate", "validated", "rejected"})
APPROVAL_STATES = frozenset({"not_required", "pending", "approved", "rejected"})
_HUMAN_REVIEW_APPROVAL_STATES = frozenset({"pending", "approved", "rejected"})

HANDOFF_STAGES = frozenset({
    "threat_intel_review", "threat_hunt", "detection_engineering",
    "red_validation", "purple_remediation",
})

_EXPERIMENT_REQUIRED_FIELDS = ("experiment_version", "experiment_id", "scenario_records")

_SCENARIO_REQUIRED_FIELDS = (
    "scenario_id",
    "technical_severity",
    "operational_priority",
    "priority_direction",
    "context_mode",
    "memory_mode",
    "governor_mode",
    "governor_decision",
    "memory_experience_status",
    "memory_reusable",
    "handoff_stage_results",
    "source_evidence_digests",
    "final_evidence_references",
    "human_review_required",
    "approval_state",
    "validated_defensive_experience",
    "duration_minutes",
)

_HANDOFF_STAGE_RESULT_FIELDS = frozenset({"stage", "outcome"})

RESEARCH_LIMITATIONS = (
    "OBSERVATIONAL_SUMMARY_ONLY",
    "NO_CAUSAL_CLAIM",
    "NO_STATISTICAL_SIGNIFICANCE_TEST",
    "CALLER_SUPPLIED_DURATION",
    "CALLER_SUPPLIED_APPROVAL_STATE",
    "RECORDED_STAGE_NOT_EXECUTION_PROOF",
    "EVIDENCE_REFERENCE_NOT_AUTHENTICITY_PROOF",
)

_ABLATION_DIMENSIONS = (
    ("context_mode", "context_enabled", "context_disabled"),
    ("memory_mode", "memory_enabled", "memory_disabled"),
    ("governor_mode", "governor_enabled", "governor_disabled"),
)


class ResearchEvaluationError(ValueError):
    """Raised when a supplied `experiment` (or a nested `scenario_records`
    entry) is structurally invalid.

    Every message begins with one of a fixed set of stable codes:
    `INVALID_EXPERIMENT`, `INVALID_SCENARIO`, `DUPLICATE_SCENARIO_ID`,
    `INVALID_SEVERITY`, `INVALID_OPERATIONAL_PRIORITY`,
    `PRIORITY_DIRECTION_MISMATCH`, `CONTEXT_BASELINE_VIOLATION`,
    `GOVERNOR_BASELINE_VIOLATION`, `INVALID_MEMORY_STATUS`,
    `INVALID_HANDOFF_STAGE`, `INVALID_EVIDENCE`,
    `INVALID_APPROVAL_STATE`, `INVALID_DURATION`. These are deterministic
    structural/consistency checks only -- never described as
    authentication or verification of the underlying claims.

    Never raised because a computed metric is zero, because a rate is
    `null` for an empty denominator, or because
    `unsafe_reusable_violations` is greater than zero -- every one of
    those is a normal, successfully represented research observation,
    not an error condition.
    """


def _raise(code: str, detail: str) -> None:
    raise ResearchEvaluationError(f"{code}: {detail}")


def _in_vocab(value: Any, vocabulary: frozenset[str]) -> bool:
    return isinstance(value, str) and value in vocabulary


def _require_bool(value: Any, code: str, field_name: str) -> bool:
    if value is not True and value is not False:
        _raise(code, f"{field_name!r} must be a bool")
    return value


def _require_nonblank_string(value: Any, code: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _raise(code, f"{field_name!r} must be a non-blank string")
    return value


def _mean(values: list[float]) -> float | None:
    if not values:
        return None
    return sum(values) / len(values)


# ---------------------------------------------------------------------------
# Scenario validation.
# ---------------------------------------------------------------------------


def _validate_handoff_stage_results(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        _raise("INVALID_HANDOFF_STAGE", "handoff_stage_results must be a list")

    validated: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != _HANDOFF_STAGE_RESULT_FIELDS:
            _raise("INVALID_HANDOFF_STAGE", "each handoff stage result must contain exactly stage/outcome")
        if not _in_vocab(item.get("stage"), HANDOFF_STAGES):
            _raise("INVALID_HANDOFF_STAGE", "stage must be a recognized handoff stage")
        outcome = item.get("outcome")
        if not isinstance(outcome, str) or not outcome.strip():
            _raise("INVALID_HANDOFF_STAGE", "outcome must be a non-blank string")
        validated.append({"stage": item["stage"], "outcome": outcome})
    return validated


def _validate_evidence_list(
    value: Any, *, allow_empty: bool, code: str, field_name: str,
) -> list[str]:
    if not isinstance(value, list):
        _raise(code, f"{field_name!r} must be a list")
    if not allow_empty and len(value) == 0:
        _raise(code, f"{field_name!r} must be a non-empty list")

    validated: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item.strip():
            _raise(code, f"{field_name!r} entries must be non-blank strings")
        if item in seen:
            _raise(code, f"{field_name!r} must not contain duplicates")
        seen.add(item)
        validated.append(item)
    return validated


def _validate_duration_minutes(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _raise("INVALID_DURATION", "duration_minutes must be a number or null")
    if not math.isfinite(value):
        _raise("INVALID_DURATION", "duration_minutes must be finite")
    if value < 0:
        _raise("INVALID_DURATION", "duration_minutes must be >= 0")
    return float(value)


def _validate_scenario(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_SCENARIO_REQUIRED_FIELDS):
        _raise("INVALID_SCENARIO", "scenario record must contain exactly the seventeen required fields")

    scenario_id = _require_nonblank_string(value.get("scenario_id"), "INVALID_SCENARIO", "scenario_id")

    if not _in_vocab(value.get("technical_severity"), SEVERITIES):
        _raise("INVALID_SEVERITY", "technical_severity must be a recognized value")
    technical_severity = value["technical_severity"]

    if not _in_vocab(value.get("operational_priority"), SEVERITIES):
        _raise("INVALID_OPERATIONAL_PRIORITY", "operational_priority must be a recognized value")
    operational_priority = value["operational_priority"]

    if not _in_vocab(value.get("priority_direction"), PRIORITY_DIRECTIONS):
        _raise("INVALID_SCENARIO", "priority_direction must be a recognized value")
    priority_direction = value["priority_direction"]

    priority_delta = _SEVERITY_BAND[operational_priority] - _SEVERITY_BAND[technical_severity]
    if priority_delta > 0:
        expected_direction = "raised"
    elif priority_delta < 0:
        expected_direction = "lowered"
    else:
        expected_direction = "unchanged"
    if priority_direction != expected_direction:
        _raise(
            "PRIORITY_DIRECTION_MISMATCH",
            f"priority_direction {priority_direction!r} does not match computed delta {priority_delta}",
        )

    if not _in_vocab(value.get("context_mode"), MODES):
        _raise("INVALID_SCENARIO", "context_mode must be 'enabled' or 'disabled'")
    context_mode = value["context_mode"]
    if context_mode == "disabled":
        if operational_priority != technical_severity or priority_direction != "unchanged":
            _raise(
                "CONTEXT_BASELINE_VIOLATION",
                "context_mode is disabled but operational_priority/priority_direction reflect a "
                "context-driven change",
            )

    if not _in_vocab(value.get("memory_mode"), MODES):
        _raise("INVALID_SCENARIO", "memory_mode must be 'enabled' or 'disabled'")
    memory_mode = value["memory_mode"]

    if not _in_vocab(value.get("governor_mode"), MODES):
        _raise("INVALID_SCENARIO", "governor_mode must be 'enabled' or 'disabled'")
    governor_mode = value["governor_mode"]

    if not _in_vocab(value.get("governor_decision"), GOVERNOR_DECISIONS):
        _raise("INVALID_SCENARIO", "governor_decision must be a recognized value")
    governor_decision = value["governor_decision"]
    if governor_mode == "disabled" and governor_decision != "allow":
        _raise(
            "GOVERNOR_BASELINE_VIOLATION",
            "governor_mode is disabled but governor_decision is not 'allow'",
        )

    if not _in_vocab(value.get("memory_experience_status"), MEMORY_STATUSES):
        _raise("INVALID_MEMORY_STATUS", "memory_experience_status must be a recognized value")
    memory_experience_status = value["memory_experience_status"]

    memory_reusable = _require_bool(value.get("memory_reusable"), "INVALID_SCENARIO", "memory_reusable")

    handoff_stage_results = _validate_handoff_stage_results(value.get("handoff_stage_results"))

    source_evidence_digests = _validate_evidence_list(
        value.get("source_evidence_digests"), allow_empty=False,
        code="INVALID_EVIDENCE", field_name="source_evidence_digests",
    )
    final_evidence_references = _validate_evidence_list(
        value.get("final_evidence_references"), allow_empty=True,
        code="INVALID_EVIDENCE", field_name="final_evidence_references",
    )

    human_review_required = _require_bool(
        value.get("human_review_required"), "INVALID_SCENARIO", "human_review_required",
    )

    if not _in_vocab(value.get("approval_state"), APPROVAL_STATES):
        _raise("INVALID_APPROVAL_STATE", "approval_state must be a recognized value")
    approval_state = value["approval_state"]

    validated_defensive_experience = _require_bool(
        value.get("validated_defensive_experience"), "INVALID_SCENARIO", "validated_defensive_experience",
    )

    duration_minutes = _validate_duration_minutes(value.get("duration_minutes"))

    return {
        "scenario_id": scenario_id,
        "technical_severity": technical_severity,
        "operational_priority": operational_priority,
        "priority_direction": priority_direction,
        "priority_delta": priority_delta,
        "context_mode": context_mode,
        "memory_mode": memory_mode,
        "governor_mode": governor_mode,
        "governor_decision": governor_decision,
        "memory_experience_status": memory_experience_status,
        "memory_reusable": memory_reusable,
        "handoff_stage_results": handoff_stage_results,
        "source_evidence_digests": source_evidence_digests,
        "final_evidence_references": final_evidence_references,
        "human_review_required": human_review_required,
        "approval_state": approval_state,
        "validated_defensive_experience": validated_defensive_experience,
        "duration_minutes": duration_minutes,
    }


def _validate_experiment(value: Any) -> tuple[str, list[dict[str, Any]]]:
    if not isinstance(value, Mapping) or set(value) != set(_EXPERIMENT_REQUIRED_FIELDS):
        _raise("INVALID_EXPERIMENT", "experiment must contain exactly the three required fields")

    if value.get("experiment_version") != EXPERIMENT_VERSION:
        _raise("INVALID_EXPERIMENT", "experiment_version must be '1'")

    experiment_id = _require_nonblank_string(value.get("experiment_id"), "INVALID_EXPERIMENT", "experiment_id")

    raw_scenarios = value.get("scenario_records")
    if not isinstance(raw_scenarios, list) or len(raw_scenarios) == 0:
        _raise("INVALID_EXPERIMENT", "scenario_records must be a non-empty list")

    seen_ids: set[str] = set()
    validated_scenarios: list[dict[str, Any]] = []
    for raw_scenario in raw_scenarios:
        scenario = _validate_scenario(raw_scenario)
        if scenario["scenario_id"] in seen_ids:
            _raise("DUPLICATE_SCENARIO_ID", f"duplicate scenario_id: {scenario['scenario_id']!r}")
        seen_ids.add(scenario["scenario_id"])
        validated_scenarios.append(scenario)

    return experiment_id, validated_scenarios


# ---------------------------------------------------------------------------
# Metric computation -- each function reads the validated scenario list
# only, never the caller's original objects.
# ---------------------------------------------------------------------------


def _compute_context_metrics(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    scenario_count = len(scenarios)
    raised = sum(1 for s in scenarios if s["priority_direction"] == "raised")
    unchanged = sum(1 for s in scenarios if s["priority_direction"] == "unchanged")
    lowered = sum(1 for s in scenarios if s["priority_direction"] == "lowered")
    critical_operational = sum(1 for s in scenarios if s["operational_priority"] == "critical")
    disagreement = sum(1 for s in scenarios if s["operational_priority"] != s["technical_severity"])
    mean_delta = _mean([float(s["priority_delta"]) for s in scenarios])

    return {
        "scenario_count": scenario_count,
        "raised_count": raised,
        "unchanged_count": unchanged,
        "lowered_count": lowered,
        "critical_operational_priority_count": critical_operational,
        "technical_vs_operational_disagreement_count": disagreement,
        "mean_priority_delta": mean_delta,
    }


def _compute_governor_metrics(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    scenario_count = len(scenarios)
    allow = sum(1 for s in scenarios if s["governor_decision"] == "allow")
    warn = sum(1 for s in scenarios if s["governor_decision"] == "warn")
    require_review = sum(1 for s in scenarios if s["governor_decision"] == "require_review")
    block = sum(1 for s in scenarios if s["governor_decision"] == "block")
    freeze = sum(1 for s in scenarios if s["governor_decision"] == "freeze")
    intervention = require_review + block + freeze

    return {
        "allow_count": allow,
        "warn_count": warn,
        "require_review_count": require_review,
        "block_count": block,
        "freeze_count": freeze,
        "intervention_count": intervention,
        "governor_intervention_rate": intervention / scenario_count,
    }


def _compute_memory_metrics(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    scenario_count = len(scenarios)
    candidate = sum(1 for s in scenarios if s["memory_experience_status"] == "candidate")
    validated = sum(1 for s in scenarios if s["memory_experience_status"] == "validated")
    rejected = sum(1 for s in scenarios if s["memory_experience_status"] == "rejected")
    reusable = sum(1 for s in scenarios if s["memory_reusable"] is True)
    non_reusable = sum(1 for s in scenarios if s["memory_reusable"] is False)

    return {
        "candidate_count": candidate,
        "validated_count": validated,
        "rejected_count": rejected,
        "reusable_count": reusable,
        "non_reusable_count": non_reusable,
        "memory_reuse_rate": reusable / scenario_count,
        "memory_rejection_rate": rejected / scenario_count,
    }


def _compute_governor_memory_protection(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    unsafe = [s for s in scenarios if s["governor_decision"] in _UNSAFE_GOVERNOR_DECISIONS]
    unsafe_count = len(unsafe)
    correctly_non_reusable = sum(1 for s in unsafe if s["memory_reusable"] is False)
    unsafe_reusable_violations = sum(1 for s in unsafe if s["memory_reusable"] is True)
    protection_rate = (correctly_non_reusable / unsafe_count) if unsafe_count > 0 else None

    return {
        "unsafe_governor_records": unsafe_count,
        "correctly_non_reusable": correctly_non_reusable,
        "unsafe_reusable_violations": unsafe_reusable_violations,
        "protection_rate": protection_rate,
    }


def _compute_handoff_metrics(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    scenario_count = len(scenarios)
    total_stage_results = sum(len(s["handoff_stage_results"]) for s in scenarios)

    def _reaches(stage: str) -> int:
        return sum(1 for s in scenarios if any(r["stage"] == stage for r in s["handoff_stage_results"]))

    reaching_human_review = sum(
        1 for s in scenarios if s["approval_state"] in _HUMAN_REVIEW_APPROVAL_STATES
    )

    return {
        "total_stage_results": total_stage_results,
        "mean_stage_results_per_scenario": total_stage_results / scenario_count,
        "scenarios_reaching_detection_engineering": _reaches("detection_engineering"),
        "scenarios_reaching_red_validation": _reaches("red_validation"),
        "scenarios_reaching_purple_remediation": _reaches("purple_remediation"),
        "scenarios_reaching_human_review": reaching_human_review,
    }


def _compute_red_blue_revision(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    revision_cycle_count = 0
    scenarios_with_revision = 0
    red_blocked_count = 0

    for scenario in scenarios:
        results = scenario["handoff_stage_results"]
        scenario_cycles = 0
        for index, result in enumerate(results):
            if result["stage"] == "red_validation" and result["outcome"] == "blocked":
                red_blocked_count += 1
                later_blue = any(
                    later["stage"] == "detection_engineering" for later in results[index + 1:]
                )
                if later_blue:
                    scenario_cycles += 1
        revision_cycle_count += scenario_cycles
        if scenario_cycles > 0:
            scenarios_with_revision += 1

    return {
        "revision_cycle_count": revision_cycle_count,
        "scenarios_with_revision": scenarios_with_revision,
        "red_blocked_count": red_blocked_count,
    }


def _compute_evidence_preservation(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    source_evidence_count = 0
    preserved_evidence_count = 0

    for scenario in scenarios:
        source_set = set(scenario["source_evidence_digests"])
        final_set = set(scenario["final_evidence_references"])
        source_evidence_count += len(source_set)
        preserved_evidence_count += len(source_set & final_set)

    missing_evidence_count = source_evidence_count - preserved_evidence_count
    rate = (preserved_evidence_count / source_evidence_count) if source_evidence_count > 0 else None

    return {
        "source_evidence_count": source_evidence_count,
        "preserved_evidence_count": preserved_evidence_count,
        "missing_evidence_count": missing_evidence_count,
        "evidence_preservation_rate": rate,
    }


def _compute_human_review_metrics(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "human_review_required_count": sum(1 for s in scenarios if s["human_review_required"] is True),
        "not_required_count": sum(1 for s in scenarios if s["approval_state"] == "not_required"),
        "pending_count": sum(1 for s in scenarios if s["approval_state"] == "pending"),
        "approved_count": sum(1 for s in scenarios if s["approval_state"] == "approved"),
        "rejected_count": sum(1 for s in scenarios if s["approval_state"] == "rejected"),
    }


def _compute_validated_defensive_experience(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    scenario_count = len(scenarios)
    count = sum(1 for s in scenarios if s["validated_defensive_experience"] is True)
    return {"count": count, "rate": count / scenario_count}


def _compute_mtvd(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    validated = [s for s in scenarios if s["validated_defensive_experience"] is True]
    with_duration = [s for s in validated if s["duration_minutes"] is not None]
    missing_duration = [s for s in validated if s["duration_minutes"] is None]

    mean_minutes = _mean([s["duration_minutes"] for s in with_duration])

    return {
        "available": len(with_duration) > 0,
        "validated_scenarios_with_duration": len(with_duration),
        "validated_scenarios_missing_duration": len(missing_duration),
        "mean_minutes": mean_minutes,
    }


def _compute_stage_count_proxy(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    validated = [s for s in scenarios if s["validated_defensive_experience"] is True]
    mean_stage_count = _mean([float(len(s["handoff_stage_results"])) for s in validated])

    return {
        "available": len(validated) > 0,
        "validated_scenario_count": len(validated),
        "mean_stage_count_to_validated_experience": mean_stage_count,
    }


def _compute_ablation_group(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    scenario_count = len(scenarios)
    if scenario_count == 0:
        return {
            "scenario_count": 0,
            "validated_defensive_experience_count": 0,
            "validated_defensive_experience_rate": None,
            "mean_stage_count": None,
            "mean_duration_minutes": None,
        }

    validated_count = sum(1 for s in scenarios if s["validated_defensive_experience"] is True)
    mean_stage_count = _mean([float(len(s["handoff_stage_results"])) for s in scenarios])
    durations = [s["duration_minutes"] for s in scenarios if s["duration_minutes"] is not None]
    mean_duration = _mean(durations)

    return {
        "scenario_count": scenario_count,
        "validated_defensive_experience_count": validated_count,
        "validated_defensive_experience_rate": validated_count / scenario_count,
        "mean_stage_count": mean_stage_count,
        "mean_duration_minutes": mean_duration,
    }


def _compute_ablations(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    ablations: dict[str, Any] = {}
    for field_name, enabled_key, disabled_key in _ABLATION_DIMENSIONS:
        enabled_group = [s for s in scenarios if s[field_name] == "enabled"]
        disabled_group = [s for s in scenarios if s[field_name] == "disabled"]
        ablations[enabled_key] = _compute_ablation_group(enabled_group)
        ablations[disabled_key] = _compute_ablation_group(disabled_group)
    return ablations


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate_research_experiment(*, experiment: Any) -> dict[str, Any]:
    """Deterministically compute a fixed set of purely observational
    research metrics over a caller-supplied batch of already-produced
    ThreatTrace scenario records. Performs no I/O of any kind, and
    never calls `core.context_prioritization`, `core.security_governor`,
    `core.security_experience_memory`, or `core.security_handoff` --
    every scenario record is externally/caller-supplied structured
    data, never recomputed or re-verified against those modules.

    `experiment` is required and keyword-only, and must be a mapping
    containing exactly `experiment_version` (must be `"1"`),
    `experiment_id` (a non-blank string), `scenario_records` (a
    non-empty list, each entry shaped like the module docstring's
    17-field scenario contract). Every scenario's `scenario_id` must be
    unique within the batch. `technical_severity`/`operational_priority`
    must each be a recognized severity band, and `priority_direction`
    must exactly match the computed band delta
    (`operational_priority`'s band minus `technical_severity`'s band).
    A `context_mode: "disabled"` scenario must report
    `operational_priority == technical_severity` and
    `priority_direction == "unchanged"` -- a technical-severity-only
    baseline. A `governor_mode: "disabled"` scenario must report
    `governor_decision == "allow"` -- this is never interpreted as
    evidence the Governor evaluated anything; it only means the
    experiment's declared baseline did not use active Governor
    intervention.

    Neither `experiment` nor any nested value within it (including
    `scenario_records`, each scenario's `handoff_stage_results`,
    `source_evidence_digests`, and `final_evidence_references`) is ever
    mutated, and no mutable object from the input is retained by
    reference in the result -- every returned mapping and list is newly
    constructed.

    Returns a new dict containing exactly the fifteen top-level fields
    documented in the module docstring's output contract:
    `evaluation_version` (always `"1"`), `experiment_id`,
    `scenario_count`, `context_prioritization`, `governor`, `memory`,
    `governor_memory_protection`, `handoff`, `red_blue_revision`,
    `evidence_preservation`, `human_review`,
    `validated_defensive_experience`, `mtvd`, `stage_count_proxy`,
    `ablations`, `research_limitations` (always the fixed seven-code
    list in `RESEARCH_LIMITATIONS`'s own order).

    A rate whose denominator is zero (e.g. `governor_memory_protection
    .protection_rate` when no scenario used an unsafe Governor
    decision, or an `ablations` group's rate when that group is empty)
    is always `None` -- never fabricated as `0` or `1.0`. A non-zero
    `governor_memory_protection.unsafe_reusable_violations` is always
    preserved as a normal research observation -- it never causes this
    function to raise, and never causes the rest of the batch to be
    discarded.

    Raises `ResearchEvaluationError` for any structurally invalid
    `experiment` or scenario record. Never raises because a computed
    metric is zero, because a rate is `None`, or because
    `unsafe_reusable_violations` is greater than zero.
    """
    experiment_id, scenarios = _validate_experiment(experiment)
    scenario_count = len(scenarios)

    return {
        "evaluation_version": EVALUATION_VERSION,
        "experiment_id": experiment_id,
        "scenario_count": scenario_count,
        "context_prioritization": _compute_context_metrics(scenarios),
        "governor": _compute_governor_metrics(scenarios),
        "memory": _compute_memory_metrics(scenarios),
        "governor_memory_protection": _compute_governor_memory_protection(scenarios),
        "handoff": _compute_handoff_metrics(scenarios),
        "red_blue_revision": _compute_red_blue_revision(scenarios),
        "evidence_preservation": _compute_evidence_preservation(scenarios),
        "human_review": _compute_human_review_metrics(scenarios),
        "validated_defensive_experience": _compute_validated_defensive_experience(scenarios),
        "mtvd": _compute_mtvd(scenarios),
        "stage_count_proxy": _compute_stage_count_proxy(scenarios),
        "ablations": _compute_ablations(scenarios),
        "research_limitations": list(RESEARCH_LIMITATIONS),
    }
