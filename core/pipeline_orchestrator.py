"""Pure, deterministic pipeline composition/translation layer (Block
15F-A, checkpoint 3 of 3).

This module answers exactly two questions:

1. *Given an already-existing Block 15C security handoff case and
   explicitly caller-supplied observable control state, what does the
   corresponding Block 15C.5 Security Governor `event` look like?*
   (`build_governor_event`)
2. *Given the real outputs of an already-run Bug Bounty → Context
   Prioritization → Security Handoff → Security Governor → Validated
   Security Experience Memory pipeline, what does the corresponding
   Block 15E Research Evaluation `scenario_record` look like?*
   (`build_research_scenario_record`)

## A thin translator only -- it never reimplements business logic

Both public builders are pure field-mapping functions. Neither this
module, nor any function in it, ever calls `core.agent_gateway`,
`core.agent_identity_policy`, `core.mutation_freeze`,
`core.decision_binding`, `core.security_governor`,
`core.security_handoff`, `core.context_prioritization`,
`core.security_experience_memory`, `core.research_evaluation`, or
`core.bug_bounty_findings` -- it imports no other `core.*` module at
all. Every input (`case`, `finding`, `prioritization`, `governor_result`,
`memory_entry`) is consumed as a plain, duck-typed, caller-supplied
mapping, validated only against the minimal fields this module itself
reads, following this project's established convention that each
module owns its own copy of a shape it shares in spirit with another
module.

## Nothing here invents authenticated identity or infers intent

`actor_role`, `action_class`, `gateway_decision`, `identity_decision`,
`mutation_freeze_active`, `decision_binding_state`, `scope_state`,
`source_truth_state`, `remote_content_state`, `audit_state`,
`prior_policy_denials`, and `execution_requested` are **all** required,
explicitly caller-supplied parameters to `build_governor_event` --
this function never defaults, infers, or silently assumes any of them.
A caller who states `gateway_decision="allow"` is supplying **claimed
observable state only**, exactly like `core.security_governor` itself
documents -- this module never claims that state was authenticated,
and never infers malicious intent, a psychological state, or anything
about the actor beyond the literal, closed-vocabulary value supplied.
Only `current_stage`, `required_role` (derived from `current_stage` via
a fixed, private stage→role mapping), and `approval_state` are read
directly from the supplied `case` -- because those, unlike the rest,
are genuine facts already recorded in that case.

## Remote content and role-generated text remain untrusted data

Free-text fields read from `finding`/`case` (titles, observations,
recommendations) are never parsed, scanned for keywords, or used to
infer `remote_content_state`, `source_truth_state`, or any other
closed-vocabulary field -- every closed-vocabulary field this module
produces comes either from a fixed derivation off already-structured
data (`current_stage`→`required_role`) or from an explicit caller
parameter, never from interpreting prose.

## `validated_defensive_experience` follows the real Memory result only

`build_research_scenario_record`'s `validated_defensive_experience` is
computed as `memory_entry['experience_status'] == "validated" and
memory_entry['reusable'] is True` -- read directly from the real
`core.security_experience_memory.create_security_experience` output
this module is given, never inferred from prose, and never `True`
merely because a source finding's own status happens to be
`"candidate"` or `"validated"`.

## Evidence mapping is correlation only, never authenticity

`source_evidence_digests` is read from the case's own frozen
`finding_reference.evidence_digests`. `final_evidence_references` is
the deduplicated, order-preserving set of `evidence_digest`-type
references actually cited across the case's own `stage_results` --
i.e. which original evidence digests were carried forward into the
handoff's own record. Neither list is ever a claim of cryptographic
authenticity, remote-response integrity, or non-repudiation -- exactly
like every other content-correlation digest in this project.

## No clock access anywhere in this module

`measure_duration_minutes` is pure arithmetic over two caller-supplied
numeric timestamps -- it never calls `time.time()`/`time.monotonic()`
or any other clock source itself. A caller wanting an honest
`duration_minutes` must capture both timestamps with their own
injected clock (mirroring `adapters.bug_bounty_http.
BugBountyHttpTransport`'s own injectable-clock pattern) and pass the
two resulting numbers to this function -- this module never generates,
estimates, or fabricates a duration.

`PipelineOrchestratorError`, `build_governor_event`,
`build_research_scenario_record`, and `measure_duration_minutes` are
this module's only public functions (plus its fixed vocabulary
constants).
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

ORCHESTRATOR_VERSION = "1"

# ---------------------------------------------------------------------------
# Private copies of closed vocabularies shared in spirit with
# core.security_handoff / core.security_governor / core.context_prioritization
# / core.security_experience_memory / core.research_evaluation -- none of
# those modules is ever imported here.
# ---------------------------------------------------------------------------

HANDOFF_STAGES = frozenset({
    "threat_intel_review", "threat_hunt", "detection_engineering",
    "red_validation", "purple_remediation", "human_review",
})

REQUIRED_ROLE_BY_STAGE: Mapping[str, str] = MappingProxyType({
    "threat_intel_review": "threat_intelligence",
    "threat_hunt": "threat_hunting",
    "detection_engineering": "blue_team",
    "red_validation": "red_team",
    "purple_remediation": "purple_ir",
    "human_review": "human_analyst",
})

ROLES = frozenset({
    "bug_bounty", "context_engine", "threat_intelligence", "threat_hunting",
    "blue_team", "red_team", "purple_ir", "human_analyst",
})

ACTION_CLASSES = frozenset({
    "stage_contribution", "approval_decision", "execution_request",
    "source_truth_edit", "audit_action", "content_adoption",
})

GATEWAY_IDENTITY_DECISIONS = frozenset({"allow", "require_approval", "deny"})
APPROVAL_STATES = frozenset({"not_required", "pending", "approved", "rejected"})
DECISION_BINDING_STATES = frozenset({"not_required", "valid", "invalid", "missing"})
SCOPE_STATES = frozenset({"within_scope", "expansion_attempt"})
SOURCE_TRUTH_STATES = frozenset({"unchanged", "modification_attempted"})
REMOTE_CONTENT_STATES = frozenset({"not_present", "untrusted_data_only", "adopted_as_instruction"})
AUDIT_STATES = frozenset({"recorded", "bypass_attempted"})

TECHNICAL_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
PRIORITY_DIRECTIONS = frozenset({"raised", "unchanged", "lowered"})
GOVERNOR_DECISIONS = frozenset({"allow", "warn", "require_review", "block", "freeze"})
MEMORY_STATUSES = frozenset({"candidate", "validated", "rejected"})
MODES = frozenset({"enabled", "disabled"})

_FINDING_REFERENCE_FIELDS = frozenset({
    "finding_id", "technical_severity", "finding_status", "confidence", "evidence_digests",
})


class PipelineOrchestratorError(ValueError):
    """Raised when a supplied input to `build_governor_event`/
    `build_research_scenario_record`/`measure_duration_minutes` is
    structurally invalid.

    Every message begins with one of a fixed set of stable codes,
    including `INVALID_CASE`, `INVALID_ROLE`, `INVALID_ACTION_CLASS`,
    `INVALID_GATEWAY_DECISION`, `INVALID_IDENTITY_DECISION`,
    `INVALID_DECISION_BINDING_STATE`, `INVALID_SCOPE_STATE`,
    `INVALID_SOURCE_TRUTH_STATE`, `INVALID_REMOTE_CONTENT_STATE`,
    `INVALID_AUDIT_STATE`, `INVALID_PRIOR_POLICY_DENIALS`,
    `INVALID_EXECUTION_REQUESTED`, `INVALID_FINDING`,
    `INVALID_PRIORITIZATION`, `INVALID_GOVERNOR_RESULT`,
    `INVALID_MEMORY_ENTRY`, `INVALID_MODE`, `INVALID_SCENARIO_ID`,
    `INVALID_DURATION`, `FINDING_ID_MISMATCH`,
    `TECHNICAL_SEVERITY_MISMATCH`.

    Never raised because a source finding's status is `"candidate"`,
    because a Governor decision is `"block"`/`"freeze"`, or because a
    Memory entry is non-reusable -- every one of those is a normal,
    honestly-mapped input, not an error condition.
    """


def _raise(code: str, detail: str) -> None:
    raise PipelineOrchestratorError(f"{code}: {detail}")


def _in_vocab(value: Any, vocabulary: frozenset[str]) -> bool:
    return isinstance(value, str) and value in vocabulary


def _require_nonblank_string(value: Any, code: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _raise(code, f"{field_name!r} must be a non-blank string")
    return value


def _require_bool(value: Any, code: str, field_name: str) -> bool:
    if value is not True and value is not False:
        _raise(code, f"{field_name!r} must be a bool")
    return value


# ---------------------------------------------------------------------------
# Minimal, locally-owned extraction of the security handoff case fields
# either public builder reads. Never a full structural re-validation of
# the whole case contract -- only the fields genuinely needed here.
# ---------------------------------------------------------------------------


def _extract_case_fields(case: Any) -> dict[str, Any]:
    if not isinstance(case, Mapping):
        _raise("INVALID_CASE", "case must be a mapping")

    if not _in_vocab(case.get("current_stage"), HANDOFF_STAGES):
        _raise("INVALID_CASE", "case['current_stage'] must be a recognized handoff stage")
    current_stage = case["current_stage"]

    if not _in_vocab(case.get("approval_state"), APPROVAL_STATES):
        _raise("INVALID_CASE", "case['approval_state'] must be a recognized approval state")
    approval_state = case["approval_state"]

    if case.get("human_review_required") is not True:
        _raise("INVALID_CASE", "case['human_review_required'] must be true")

    finding_reference = case.get("finding_reference")
    if not isinstance(finding_reference, Mapping) or not _FINDING_REFERENCE_FIELDS.issubset(set(finding_reference)):
        _raise("INVALID_CASE", "case['finding_reference'] is malformed")

    finding_id = finding_reference.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip():
        _raise("INVALID_CASE", "case['finding_reference']['finding_id'] must be a non-blank string")

    if not _in_vocab(finding_reference.get("technical_severity"), TECHNICAL_SEVERITIES):
        _raise("INVALID_CASE", "case['finding_reference']['technical_severity'] must be a recognized value")

    evidence_digests = finding_reference.get("evidence_digests")
    if not isinstance(evidence_digests, list) or len(evidence_digests) == 0:
        _raise("INVALID_CASE", "case['finding_reference']['evidence_digests'] must be a non-empty list")
    for digest in evidence_digests:
        if not isinstance(digest, str) or not digest:
            _raise("INVALID_CASE", "case['finding_reference']['evidence_digests'] entries must be strings")

    raw_stage_results = case.get("stage_results")
    if not isinstance(raw_stage_results, list):
        _raise("INVALID_CASE", "case['stage_results'] must be a list")

    stage_results: list[dict[str, Any]] = []
    for raw_result in raw_stage_results:
        if not isinstance(raw_result, Mapping):
            _raise("INVALID_CASE", "each case stage result must be a mapping")
        stage = raw_result.get("stage")
        outcome = raw_result.get("outcome")
        if not isinstance(stage, str) or not stage.strip():
            _raise("INVALID_CASE", "each case stage result must carry a non-blank 'stage'")
        if not isinstance(outcome, str) or not outcome.strip():
            _raise("INVALID_CASE", "each case stage result must carry a non-blank 'outcome'")
        evidence_references = raw_result.get("evidence_references")
        if not isinstance(evidence_references, list):
            _raise("INVALID_CASE", "each case stage result must carry a list 'evidence_references'")
        stage_results.append({
            "stage": stage,
            "outcome": outcome,
            "evidence_references": list(evidence_references),
        })

    return {
        "current_stage": current_stage,
        "approval_state": approval_state,
        "human_review_required": True,
        "finding_id": finding_id,
        "technical_severity": finding_reference["technical_severity"],
        "evidence_digests": list(evidence_digests),
        "stage_results": stage_results,
    }


# ---------------------------------------------------------------------------
# Public API -- build_governor_event.
# ---------------------------------------------------------------------------


def build_governor_event(
    *,
    case: Any,
    actor_role: Any,
    action_class: Any,
    gateway_decision: Any,
    identity_decision: Any,
    mutation_freeze_active: Any,
    decision_binding_state: Any,
    scope_state: Any,
    source_truth_state: Any,
    remote_content_state: Any,
    audit_state: Any,
    prior_policy_denials: Any,
    execution_requested: Any,
) -> dict[str, Any]:
    """Deterministically translate an already-existing Block 15C
    security handoff case, plus explicit caller-supplied observable
    control state, into one Block 15C.5 Security Governor `event`.
    Performs no I/O of any kind, and never calls
    `core.security_governor` itself -- the returned `event` is meant to
    be passed by the caller to
    `core.security_governor.evaluate_security_governor_event`
    separately.

    `case` is required and keyword-only, and must be a mapping shaped
    at minimum like `core.security_handoff`'s own case contract --
    only `current_stage`, `approval_state`, `human_review_required`,
    and `finding_reference` are read from it. `current_stage` and
    `required_role` (derived from `current_stage` via this module's own
    fixed, private stage→role mapping) and `approval_state` are the
    only three event fields ever read from `case` -- every other field
    is a required, explicitly caller-supplied parameter with no
    default, since none of it is genuinely derivable from `case` alone:
    `actor_role` (one of `ROLES`), `action_class` (one of
    `ACTION_CLASSES`), `gateway_decision`/`identity_decision` (one of
    `GATEWAY_IDENTITY_DECISIONS`), `mutation_freeze_active` (bool),
    `decision_binding_state` (one of `DECISION_BINDING_STATES`),
    `scope_state` (one of `SCOPE_STATES`), `source_truth_state` (one of
    `SOURCE_TRUTH_STATES`), `remote_content_state` (one of
    `REMOTE_CONTENT_STATES`), `audit_state` (one of `AUDIT_STATES`),
    `prior_policy_denials` (non-negative int), `execution_requested`
    (bool).

    Returns a new dict containing exactly the sixteen fields
    `core.security_governor.evaluate_security_governor_event` requires:
    `event_version` (always `"1"`), `actor_role`, `action_class`,
    `current_stage`, `required_role`, `gateway_decision`,
    `identity_decision`, `mutation_freeze_active`, `approval_state`,
    `decision_binding_state`, `scope_state`, `source_truth_state`,
    `remote_content_state`, `audit_state`, `prior_policy_denials`,
    `execution_requested`.

    Neither `case` nor any nested value within it is ever mutated.

    Raises `PipelineOrchestratorError` for any structurally invalid
    `case` or any invalid explicit parameter. Never raises because a
    supplied value describes a policy violation (e.g. `scope_state:
    "expansion_attempt"`) -- evaluating that is
    `core.security_governor`'s own separate concern, never this
    function's.
    """
    case_fields = _extract_case_fields(case)

    if not _in_vocab(actor_role, ROLES):
        _raise("INVALID_ROLE", "actor_role must be a recognized functional role")
    if not _in_vocab(action_class, ACTION_CLASSES):
        _raise("INVALID_ACTION_CLASS", "action_class must be a recognized value")
    if not _in_vocab(gateway_decision, GATEWAY_IDENTITY_DECISIONS):
        _raise("INVALID_GATEWAY_DECISION", "gateway_decision must be a recognized value")
    if not _in_vocab(identity_decision, GATEWAY_IDENTITY_DECISIONS):
        _raise("INVALID_IDENTITY_DECISION", "identity_decision must be a recognized value")

    validated_mutation_freeze_active = _require_bool(
        mutation_freeze_active, "INVALID_CASE", "mutation_freeze_active",
    )

    if not _in_vocab(decision_binding_state, DECISION_BINDING_STATES):
        _raise("INVALID_DECISION_BINDING_STATE", "decision_binding_state must be a recognized value")
    if not _in_vocab(scope_state, SCOPE_STATES):
        _raise("INVALID_SCOPE_STATE", "scope_state must be a recognized value")
    if not _in_vocab(source_truth_state, SOURCE_TRUTH_STATES):
        _raise("INVALID_SOURCE_TRUTH_STATE", "source_truth_state must be a recognized value")
    if not _in_vocab(remote_content_state, REMOTE_CONTENT_STATES):
        _raise("INVALID_REMOTE_CONTENT_STATE", "remote_content_state must be a recognized value")
    if not _in_vocab(audit_state, AUDIT_STATES):
        _raise("INVALID_AUDIT_STATE", "audit_state must be a recognized value")

    if isinstance(prior_policy_denials, bool) or not isinstance(prior_policy_denials, int):
        _raise("INVALID_PRIOR_POLICY_DENIALS", "prior_policy_denials must be an int")
    if prior_policy_denials < 0:
        _raise("INVALID_PRIOR_POLICY_DENIALS", "prior_policy_denials must be a non-negative int")

    validated_execution_requested = _require_bool(execution_requested, "INVALID_EXECUTION_REQUESTED", "execution_requested")

    required_role = REQUIRED_ROLE_BY_STAGE[case_fields["current_stage"]]

    return {
        "event_version": "1",
        "actor_role": actor_role,
        "action_class": action_class,
        "current_stage": case_fields["current_stage"],
        "required_role": required_role,
        "gateway_decision": gateway_decision,
        "identity_decision": identity_decision,
        "mutation_freeze_active": validated_mutation_freeze_active,
        "approval_state": case_fields["approval_state"],
        "decision_binding_state": decision_binding_state,
        "scope_state": scope_state,
        "source_truth_state": source_truth_state,
        "remote_content_state": remote_content_state,
        "audit_state": audit_state,
        "prior_policy_denials": prior_policy_denials,
        "execution_requested": validated_execution_requested,
    }


# ---------------------------------------------------------------------------
# Public API -- build_research_scenario_record.
# ---------------------------------------------------------------------------


def _validate_finding_argument(value: Any, expected_finding_id: str | None) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _raise("INVALID_FINDING", "finding must be a mapping")
    finding_id = value.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip():
        _raise("INVALID_FINDING", "finding['finding_id'] must be a non-blank string")
    if not _in_vocab(value.get("technical_severity"), TECHNICAL_SEVERITIES):
        _raise("INVALID_FINDING", "finding['technical_severity'] must be a recognized value")
    if expected_finding_id is not None and finding_id != expected_finding_id:
        _raise("FINDING_ID_MISMATCH", "finding['finding_id'] does not match case['finding_reference']['finding_id']")
    return {"finding_id": finding_id, "technical_severity": value["technical_severity"]}


def _validate_prioritization_argument(value: Any, expected_finding_id: str | None) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _raise("INVALID_PRIORITIZATION", "prioritization must be a mapping")
    finding_id = value.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip():
        _raise("INVALID_PRIORITIZATION", "prioritization['finding_id'] must be a non-blank string")
    if expected_finding_id is not None and finding_id != expected_finding_id:
        _raise(
            "FINDING_ID_MISMATCH",
            "prioritization['finding_id'] does not match case['finding_reference']['finding_id']",
        )
    if not _in_vocab(value.get("technical_severity"), TECHNICAL_SEVERITIES):
        _raise("INVALID_PRIORITIZATION", "prioritization['technical_severity'] must be a recognized value")
    if not _in_vocab(value.get("operational_priority"), TECHNICAL_SEVERITIES):
        _raise("INVALID_PRIORITIZATION", "prioritization['operational_priority'] must be a recognized value")
    if not _in_vocab(value.get("priority_direction"), PRIORITY_DIRECTIONS):
        _raise("INVALID_PRIORITIZATION", "prioritization['priority_direction'] must be a recognized value")
    return {
        "finding_id": finding_id,
        "technical_severity": value["technical_severity"],
        "operational_priority": value["operational_priority"],
        "priority_direction": value["priority_direction"],
    }


def _validate_governor_result_argument(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _raise("INVALID_GOVERNOR_RESULT", "governor_result must be a mapping")
    if not _in_vocab(value.get("decision"), GOVERNOR_DECISIONS):
        _raise("INVALID_GOVERNOR_RESULT", "governor_result['decision'] must be a recognized value")
    return {"decision": value["decision"]}


def _validate_memory_entry_argument(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _raise("INVALID_MEMORY_ENTRY", "memory_entry must be a mapping")
    if not _in_vocab(value.get("experience_status"), MEMORY_STATUSES):
        _raise("INVALID_MEMORY_ENTRY", "memory_entry['experience_status'] must be a recognized value")
    reusable = value.get("reusable")
    if reusable is not True and reusable is not False:
        _raise("INVALID_MEMORY_ENTRY", "memory_entry['reusable'] must be a bool")
    return {"experience_status": value["experience_status"], "reusable": reusable}


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


def build_research_scenario_record(
    *,
    scenario_id: Any,
    finding: Any,
    prioritization: Any,
    case: Any,
    governor_result: Any,
    memory_entry: Any,
    context_mode: Any,
    memory_mode: Any,
    governor_mode: Any,
    duration_minutes: Any = None,
) -> dict[str, Any]:
    """Deterministically translate the real outputs of an already-run
    Bug Bounty → Context Prioritization → Security Handoff → Security
    Governor → Validated Security Experience Memory pipeline into one
    Block 15E Research Evaluation `scenario_record`. Performs no I/O of
    any kind, and never calls `core.research_evaluation` itself -- the
    returned record is meant to be collected by the caller into an
    `experiment['scenario_records']` list and passed to
    `core.research_evaluation.evaluate_research_experiment` separately.

    All parameters are keyword-only. `scenario_id` must be a non-blank
    string. `finding` must be a mapping shaped at minimum like
    `core.bug_bounty_findings.create_bug_bounty_finding`'s own return
    value (`finding_id`, `technical_severity`). `prioritization` must be
    shaped at minimum like `core.context_prioritization.
    prioritize_finding`'s own return value (`finding_id`,
    `technical_severity`, `operational_priority`, `priority_direction`).
    `case` must be shaped at minimum like `core.security_handoff`'s own
    case contract. `governor_result` must carry a recognized `decision`.
    `memory_entry` must carry a recognized `experience_status` and a
    bool `reusable`. `finding['finding_id']` and
    `prioritization['finding_id']` must each match
    `case['finding_reference']['finding_id']`, or this function raises
    `PipelineOrchestratorError` with `FINDING_ID_MISMATCH`.
    `context_mode`/`memory_mode`/`governor_mode` must each be `"enabled"`
    or `"disabled"`. `duration_minutes` is optional (default `None`) --
    when supplied it must be a finite, non-negative number, never a
    bool; this function never calls a clock itself (see
    `measure_duration_minutes`).

    `technical_severity` is read from `case['finding_reference']`
    (the frozen source of truth) -- not independently recomputed.
    `handoff_stage_results` is `case['stage_results']` mapped down to
    `{stage, outcome}` pairs only. `source_evidence_digests` is
    `case['finding_reference']['evidence_digests']`.
    `final_evidence_references` is the deduplicated, order-preserving
    set of `evidence_digest`-type reference values actually cited
    across `case['stage_results']` -- content correlation only, never a
    claim of authenticity. `validated_defensive_experience` is computed
    as `memory_entry['experience_status'] == "validated" and
    memory_entry['reusable'] is True` -- read from the real Memory
    result only, never inferred from any finding/case free-text field,
    and never dependent on the source finding's own `finding_status`
    (a `"candidate"` source finding can still yield
    `validated_defensive_experience: true`, mirroring
    `core.security_experience_memory`'s own honesty property).

    Returns a new dict containing exactly the seventeen fields
    `core.research_evaluation`'s scenario contract requires:
    `scenario_id`, `technical_severity`, `operational_priority`,
    `priority_direction`, `context_mode`, `memory_mode`,
    `governor_mode`, `governor_decision`, `memory_experience_status`,
    `memory_reusable`, `handoff_stage_results`,
    `source_evidence_digests`, `final_evidence_references`,
    `human_review_required`, `approval_state`,
    `validated_defensive_experience`, `duration_minutes`.

    Neither `finding`, `prioritization`, `case`, `governor_result`, nor
    `memory_entry` (nor any nested value within any of them) is ever
    mutated.

    Raises `PipelineOrchestratorError` for any structurally invalid
    input, including a `finding_id` mismatch across `finding`/
    `prioritization`/`case`. Never raises because
    `governor_result['decision']` is `"block"`/`"freeze"`, or because
    `memory_entry['reusable']` is `False` -- every one of those is a
    normal, honestly-mapped input.
    """
    validated_scenario_id = _require_nonblank_string(scenario_id, "INVALID_SCENARIO_ID", "scenario_id")

    case_fields = _extract_case_fields(case)
    finding_fields = _validate_finding_argument(finding, case_fields["finding_id"])
    prioritization_fields = _validate_prioritization_argument(prioritization, case_fields["finding_id"])
    governor_fields = _validate_governor_result_argument(governor_result)
    memory_fields = _validate_memory_entry_argument(memory_entry)

    if finding_fields["technical_severity"] != case_fields["technical_severity"]:
        _raise(
            "TECHNICAL_SEVERITY_MISMATCH",
            "finding['technical_severity'] does not match case['finding_reference']['technical_severity']",
        )
    if prioritization_fields["technical_severity"] != case_fields["technical_severity"]:
        _raise(
            "TECHNICAL_SEVERITY_MISMATCH",
            "prioritization['technical_severity'] does not match case['finding_reference']['technical_severity']",
        )

    if not _in_vocab(context_mode, MODES):
        _raise("INVALID_MODE", "context_mode must be 'enabled' or 'disabled'")
    if not _in_vocab(memory_mode, MODES):
        _raise("INVALID_MODE", "memory_mode must be 'enabled' or 'disabled'")
    if not _in_vocab(governor_mode, MODES):
        _raise("INVALID_MODE", "governor_mode must be 'enabled' or 'disabled'")

    validated_duration_minutes = _validate_duration_minutes(duration_minutes)

    handoff_stage_results = [
        {"stage": result["stage"], "outcome": result["outcome"]} for result in case_fields["stage_results"]
    ]

    final_evidence_references: list[str] = []
    seen_references: set[str] = set()
    for result in case_fields["stage_results"]:
        for reference in result["evidence_references"]:
            if not isinstance(reference, Mapping):
                continue
            if reference.get("reference_type") != "evidence_digest":
                continue
            reference_value = reference.get("reference")
            if isinstance(reference_value, str) and reference_value not in seen_references:
                seen_references.add(reference_value)
                final_evidence_references.append(reference_value)

    validated_defensive_experience = (
        memory_fields["experience_status"] == "validated" and memory_fields["reusable"] is True
    )

    return {
        "scenario_id": validated_scenario_id,
        "technical_severity": case_fields["technical_severity"],
        "operational_priority": prioritization_fields["operational_priority"],
        "priority_direction": prioritization_fields["priority_direction"],
        "context_mode": context_mode,
        "memory_mode": memory_mode,
        "governor_mode": governor_mode,
        "governor_decision": governor_fields["decision"],
        "memory_experience_status": memory_fields["experience_status"],
        "memory_reusable": memory_fields["reusable"],
        "handoff_stage_results": handoff_stage_results,
        "source_evidence_digests": list(case_fields["evidence_digests"]),
        "final_evidence_references": final_evidence_references,
        "human_review_required": case_fields["human_review_required"],
        "approval_state": case_fields["approval_state"],
        "validated_defensive_experience": validated_defensive_experience,
        "duration_minutes": validated_duration_minutes,
    }


# ---------------------------------------------------------------------------
# Public API -- measure_duration_minutes.
# ---------------------------------------------------------------------------


def measure_duration_minutes(*, start_seconds: Any, end_seconds: Any) -> float:
    """Deterministically compute elapsed minutes between two
    caller-supplied numeric timestamps. Performs no clock access of any
    kind -- `start_seconds`/`end_seconds` must already have been
    captured by the caller's own injected clock (e.g.
    `time.monotonic()`), exactly like
    `adapters.bug_bounty_http.BugBountyHttpTransport`'s own injectable
    `clock` parameter.

    Both parameters are required and keyword-only, and must each be a
    finite number (`int`/`float`, never `bool`). `end_seconds` must be
    greater than or equal to `start_seconds`.

    Returns `(end_seconds - start_seconds) / 60.0` as a float.

    Raises `PipelineOrchestratorError` for a non-numeric/non-finite
    argument, or when `end_seconds < start_seconds`.
    """
    for value, field_name in ((start_seconds, "start_seconds"), (end_seconds, "end_seconds")):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            _raise("INVALID_DURATION", f"{field_name} must be a number")
        if not math.isfinite(value):
            _raise("INVALID_DURATION", f"{field_name} must be finite")

    if end_seconds < start_seconds:
        _raise("INVALID_DURATION", "end_seconds must be >= start_seconds")

    return (end_seconds - start_seconds) / 60.0
