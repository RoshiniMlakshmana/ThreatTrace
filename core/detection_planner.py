"""Pure, deterministic LLM-generated Detection Plan validator (Block
15H-I).

This module answers exactly one question: *given an LLM-proposed,
already-structured detection plan, is it structurally well-formed,
telemetry-honest, and free of anything this project never allows an LLM
to assert on its own?*

## This module never calls an LLM, and never plans anything itself

`validate_detection_plan` is a pure validator/normalizer only, mirroring
`core.bug_bounty_planner`'s own architecture exactly: the actual
reasoning is `.claude/agents/detection-engineering-planner.md`'s job, a
Claude custom agent this module never invokes and has no dependency on.
This module only checks whether the LLM's own proposal is structurally
well-formed against the real, already-computed `core.detection_trigger`/
`core.detection_telemetry` results it references.

## Telemetry gap means zero rules -- enforced here, not trusted from the LLM

If `plan['telemetry_feasibility']['decision'] == "TELEMETRY_GAP"`, this
function requires `plan['proposed_rules'] == []` and raises
`DetectionPlannerError` otherwise -- an LLM cannot talk its way around
an absent telemetry source by proposing a rule anyway. Every
`required_telemetry` entry on every proposed rule must already be a
member of `telemetry_feasibility['available_sources']` -- a rule
requesting telemetry that was not reported available is rejected as
`UNSUPPORTED_TELEMETRY`, never silently accepted.

## No raw command surface, anywhere in this contract

There is no field anywhere in the plan/rule-draft contract this module
accepts for a shell command, a raw command, a deployment instruction, an
approval state, or a deployment state -- the exact-field-set check on
every level of this contract structurally rejects any of them, exactly
like `core.bug_bounty_tool_policy`'s own tool-request contract excludes
a shell-command field.

## No execution, ever

This module executes nothing. `execution_performed` is always `False`
in every result it can ever produce. It performs no network,
filesystem, environment-variable, subprocess, system-clock, or
randomness access.

`DetectionPlannerError` and `validate_detection_plan` are this module's
public symbols (plus `RULE_FORMATS` and `PLAN_REQUIRED_FIELDS`).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from core.detection_telemetry import TELEMETRY_DECISIONS, TELEMETRY_TYPES
from core.detection_trigger import DetectionTriggerError, validate_detection_trigger

PLAN_VERSION = "1"

RULE_FORMATS = frozenset({"sigma", "splunk_spl", "sentinel_kql", "yara"})

PLAN_REQUIRED_FIELDS = (
    "plan_version", "plan_id", "trigger", "telemetry_feasibility",
    "detection_objective", "proposed_rules", "telemetry_recommendation",
)

_RULE_DRAFT_REQUIRED_FIELDS = (
    "rule_draft_id", "rule_format", "title", "description",
    "generic_rule_content", "context_tuned_rule_content",
    "false_positive_considerations", "required_telemetry",
)

_TELEMETRY_FEASIBILITY_REQUIRED_FIELDS = (
    "telemetry_feasibility_version", "required_sources", "available_sources", "missing_sources",
    "recommended_sources", "telemetry_available", "decision", "siem", "edr", "cloud_provider",
    "environment", "industry", "limitations",
)


class DetectionPlannerError(ValueError):
    """Raised when a supplied `plan` is structurally invalid, including
    a malformed nested `trigger` (wrapping the real
    `core.detection_trigger.DetectionTriggerError`).

    Every message begins with one of a fixed set of stable codes,
    including `INVALID_PLAN`, `INVALID_TELEMETRY_FEASIBILITY`,
    `INVALID_RULE_DRAFT`, `UNSUPPORTED_RULE_FORMAT`,
    `UNSUPPORTED_TELEMETRY`, `TELEMETRY_GAP_MUST_PROPOSE_NO_RULES`,
    `INVALID_TRIGGER`.

    Never raised because `proposed_rules` is empty for a genuine
    `"GENERATE_RULE"`/`"PARTIAL_COVERAGE"` case, or because
    `context_tuned_rule_content` is `null` -- every one of those is a
    normal, successfully validated result.
    """


def _raise(code: str, detail: str) -> None:
    raise DetectionPlannerError(f"{code}: {detail}")


def _require_nonblank_string(value: Any, code: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _raise(code, f"{field_name!r} must be a non-blank string")
    return value.strip()


def _require_optional_nonblank_string(value: Any, code: str, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_nonblank_string(value, code, field_name)


def _require_string_list(value: Any, code: str, field_name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        _raise(code, f"{field_name!r} must be a list of non-blank strings")
    return list(value)


def _validate_telemetry_feasibility(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_TELEMETRY_FEASIBILITY_REQUIRED_FIELDS):
        _raise("INVALID_TELEMETRY_FEASIBILITY", "telemetry_feasibility must contain exactly the required fields")
    if value.get("decision") not in TELEMETRY_DECISIONS:
        _raise("INVALID_TELEMETRY_FEASIBILITY", "telemetry_feasibility['decision'] must be a recognized value")
    available_sources = value.get("available_sources")
    if not isinstance(available_sources, list) or not all(item in TELEMETRY_TYPES for item in available_sources):
        _raise("INVALID_TELEMETRY_FEASIBILITY", "telemetry_feasibility['available_sources'] must be a list of recognized telemetry types")
    return dict(value)


def _validate_rule_draft(value: Any, *, available_sources: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_RULE_DRAFT_REQUIRED_FIELDS):
        _raise("INVALID_RULE_DRAFT", "each proposed rule must contain exactly the required rule-draft fields")

    rule_draft_id = _require_nonblank_string(value.get("rule_draft_id"), "INVALID_RULE_DRAFT", "rule_draft_id")

    if value.get("rule_format") not in RULE_FORMATS:
        _raise("UNSUPPORTED_RULE_FORMAT", f"rule_format must be one of {sorted(RULE_FORMATS)}")
    rule_format = value["rule_format"]

    title = _require_nonblank_string(value.get("title"), "INVALID_RULE_DRAFT", "title")
    description = _require_nonblank_string(value.get("description"), "INVALID_RULE_DRAFT", "description")
    generic_rule_content = _require_nonblank_string(value.get("generic_rule_content"), "INVALID_RULE_DRAFT", "generic_rule_content")
    context_tuned_rule_content = _require_optional_nonblank_string(
        value.get("context_tuned_rule_content"), "INVALID_RULE_DRAFT", "context_tuned_rule_content",
    )
    false_positive_considerations = _require_string_list(
        value.get("false_positive_considerations"), "INVALID_RULE_DRAFT", "false_positive_considerations",
    )

    required_telemetry = value.get("required_telemetry")
    if not isinstance(required_telemetry, list) or not all(isinstance(item, str) for item in required_telemetry):
        _raise("INVALID_RULE_DRAFT", "required_telemetry must be a list of strings")
    for item in required_telemetry:
        if item not in TELEMETRY_TYPES:
            _raise("UNSUPPORTED_TELEMETRY", f"required_telemetry entry {item!r} is not a recognized telemetry type")
        if item not in available_sources:
            _raise("UNSUPPORTED_TELEMETRY", f"required_telemetry entry {item!r} was not reported available")

    return {
        "rule_draft_id": rule_draft_id,
        "rule_format": rule_format,
        "title": title,
        "description": description,
        "generic_rule_content": generic_rule_content,
        "context_tuned_rule_content": context_tuned_rule_content,
        "false_positive_considerations": false_positive_considerations,
        "required_telemetry": list(required_telemetry),
    }


def validate_detection_plan(*, plan: Any) -> dict[str, Any]:
    """Deterministically validate and normalize one LLM-proposed
    detection plan. Performs no I/O of any kind, calls no LLM, and
    executes no tool.

    `plan` is required and keyword-only, and must be a mapping
    containing exactly the seven fields in `PLAN_REQUIRED_FIELDS`.
    `trigger` must be shaped like `core.detection_trigger`'s own trigger
    contract (re-validated via `core.detection_trigger.validate_detection_trigger`
    -- a malformed or unapproved `trigger_type` wraps that module's
    `DetectionTriggerError`, raised here as `DetectionPlannerError` with
    code `INVALID_TRIGGER`). `telemetry_feasibility` must be shaped like
    `core.detection_telemetry`'s own output contract. `detection_objective`
    must be a non-blank string. `proposed_rules` must be a list (each
    entry validated by `_validate_rule_draft`); it must be exactly `[]`
    when `telemetry_feasibility['decision'] == "TELEMETRY_GAP"`, or this
    function raises `DetectionPlannerError` with code
    `TELEMETRY_GAP_MUST_PROPOSE_NO_RULES`. Every rule draft's
    `required_telemetry` entries must already be members of
    `telemetry_feasibility['available_sources']`, or this function
    raises with code `UNSUPPORTED_TELEMETRY`. `telemetry_recommendation`
    must be `None` or a non-blank string.

    Returns a new dict containing exactly `plan_validation_version`,
    `plan_id`, `trigger` (validated), `telemetry_feasibility`
    (validated), `detection_objective`, `proposed_rules` (validated,
    each with exactly the eight `_RULE_DRAFT_REQUIRED_FIELDS`),
    `telemetry_recommendation`, `rule_count`, `human_review_required`
    (always `True`), `execution_performed` (always `False`).

    Neither `plan` nor any nested value within it is ever mutated.

    Raises `DetectionPlannerError` for any structurally invalid `plan`,
    including an unsupported rule format, telemetry that was not
    reported available, a trigger/telemetry-gap mismatch, or a
    malformed nested `trigger`. Never raises because `proposed_rules` is
    empty for a genuine gap/partial case, or because no
    `telemetry_recommendation` was given for a `"GENERATE_RULE"` case.
    """
    if not isinstance(plan, Mapping) or set(plan) != set(PLAN_REQUIRED_FIELDS):
        _raise("INVALID_PLAN", "plan must contain exactly the seven required fields")

    if plan.get("plan_version") != PLAN_VERSION:
        _raise("INVALID_PLAN", "plan_version must be '1'")
    plan_id = _require_nonblank_string(plan.get("plan_id"), "INVALID_PLAN", "plan_id")

    try:
        validated_trigger = validate_detection_trigger(trigger=plan.get("trigger"))
    except DetectionTriggerError as exc:
        _raise("INVALID_TRIGGER", str(exc))

    validated_telemetry = _validate_telemetry_feasibility(plan.get("telemetry_feasibility"))
    available_sources = frozenset(validated_telemetry["available_sources"])

    detection_objective = _require_nonblank_string(plan.get("detection_objective"), "INVALID_PLAN", "detection_objective")

    raw_proposed_rules = plan.get("proposed_rules")
    if not isinstance(raw_proposed_rules, list):
        _raise("INVALID_PLAN", "proposed_rules must be a list")

    if validated_telemetry["decision"] == "TELEMETRY_GAP" and len(raw_proposed_rules) > 0:
        _raise("TELEMETRY_GAP_MUST_PROPOSE_NO_RULES", "proposed_rules must be empty when telemetry_feasibility.decision is TELEMETRY_GAP")

    validated_rules = [_validate_rule_draft(item, available_sources=available_sources) for item in raw_proposed_rules]

    seen_ids: set[str] = set()
    for rule in validated_rules:
        if rule["rule_draft_id"] in seen_ids:
            _raise("INVALID_PLAN", f"duplicate rule_draft_id: {rule['rule_draft_id']!r}")
        seen_ids.add(rule["rule_draft_id"])

    telemetry_recommendation = _require_optional_nonblank_string(
        plan.get("telemetry_recommendation"), "INVALID_PLAN", "telemetry_recommendation",
    )

    return {
        "plan_validation_version": PLAN_VERSION,
        "plan_id": plan_id,
        "trigger": validated_trigger,
        "telemetry_feasibility": validated_telemetry,
        "detection_objective": detection_objective,
        "proposed_rules": validated_rules,
        "telemetry_recommendation": telemetry_recommendation,
        "rule_count": len(validated_rules),
        "human_review_required": True,
        "execution_performed": False,
    }
