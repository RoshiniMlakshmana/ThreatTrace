"""Pure, deterministic Detection Engineering report builder (Block
15H-I).

This module answers exactly one question: *given the already-built
Detection Triggers, telemetry feasibility results, Detection Rules, and
deduplication results a rule-factory run produced, what does one
concise Detection Engineering report look like?*

## Every rule this report can ever describe is NOT_DEPLOYED

This module never sets, computes, or overrides `deployment_state` --
it only reads it from each supplied rule (which, per `core.detection_rule`,
can only ever be `"NOT_DEPLOYED"` in this checkpoint) and reports the
distribution honestly. If a future checkpoint ever introduces a real
deployment path, this report would then honestly show it -- it is not
hardcoded to claim `"NOT_DEPLOYED"` regardless of the data.

## No I/O, no execution, ever

This module performs no network, filesystem, environment-variable,
subprocess, system-clock, or randomness access, and imports no other
`core.*` module -- every input is consumed as a plain, duck-typed
mapping, validated only against the minimal fields this module reads.

`DetectionEngineeringReportError` and `build_detection_engineering_report`
are this module's public symbols.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

REPORT_VERSION = "1"


class DetectionEngineeringReportError(ValueError):
    """Raised when a supplied input is structurally invalid. Never
    raised because zero rules were generated, because every trigger hit
    a telemetry gap, or because every rule is still `validation_status:
    "draft"` -- every one of those is a normal, successfully built
    (mostly-empty) report."""


def _raise(code: str, detail: str) -> None:
    raise DetectionEngineeringReportError(f"{code}: {detail}")


def _require_list(value: Any, code: str, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        _raise(code, f"{field_name!r} must be a list")
    return value


def build_detection_engineering_report(
    *, triggers: Any, telemetry_feasibility_results: Any, rules: Any, dedup_results: Any, rules_requested: Any,
) -> dict[str, Any]:
    """Deterministically build one Detection Engineering report from an
    already-completed rule-factory run's own results. Performs no I/O of
    any kind.

    `triggers` must be a list of Detection Trigger-shaped mappings.
    `telemetry_feasibility_results` must be a list of `core.
    detection_telemetry.evaluate_telemetry_feasibility`-shaped mappings.
    `rules` must be a list of `core.detection_rule.build_detection_rule`-
    shaped mappings (post-`apply_validation_result`, if applicable).
    `dedup_results` must be a list of `core.detection_rule_deduplication.
    check_rule_duplicate`-shaped mappings. `rules_requested` must be a
    non-negative int (the number of rule drafts an LLM plan proposed,
    before any were rejected -- this function does not re-derive it).

    Returns a dict with `report_version`, `trigger_summary`
    (`{"total", "by_type"}`), `rules_requested`, `rules_generated`
    (`len(rules)`), `rules_rejected` (`rules_requested - rules_generated`,
    floored at 0), `telemetry_gap_count`, `telemetry_gap_trigger_ids`,
    `formats_generated`, `attack_technique_coverage`, `cve_context`,
    `cwe_context`, `owasp_context`, `generic_rule_count`,
    `context_tuned_rule_count`, `deduplication_summary`
    (`{"new_rule", "update_candidate", "existing_rule_match"}` counts),
    `validation_status_distribution`, `human_approval_state_distribution`,
    `deployment_state_distribution`, `limitations`,
    `evidence_references` (union across all rules).

    Raises `DetectionEngineeringReportError` for a structurally invalid
    input list/entry, or a negative `rules_requested`. Never raises
    because no rules were generated or every trigger hit a telemetry gap.
    """
    validated_triggers = _require_list(triggers, "INVALID_TRIGGERS", "triggers")
    validated_telemetry_results = _require_list(telemetry_feasibility_results, "INVALID_TELEMETRY_RESULTS", "telemetry_feasibility_results")
    validated_rules = _require_list(rules, "INVALID_RULES", "rules")
    validated_dedup_results = _require_list(dedup_results, "INVALID_DEDUP_RESULTS", "dedup_results")

    if isinstance(rules_requested, bool) or not isinstance(rules_requested, int) or rules_requested < 0:
        _raise("INVALID_RULES_REQUESTED", "rules_requested must be a non-negative int")

    trigger_by_type: dict[str, int] = {}
    for trigger in validated_triggers:
        if not isinstance(trigger, Mapping) or "trigger_type" not in trigger:
            _raise("INVALID_TRIGGERS", "each trigger must be a mapping with a trigger_type")
        trigger_type = trigger["trigger_type"]
        trigger_by_type[trigger_type] = trigger_by_type.get(trigger_type, 0) + 1

    telemetry_gap_trigger_ids: list[str] = []
    for entry in validated_telemetry_results:
        if not isinstance(entry, Mapping) or "trigger_id" not in entry or "result" not in entry:
            _raise("INVALID_TELEMETRY_RESULTS", "each entry must contain exactly trigger_id/result")
        result = entry["result"]
        if not isinstance(result, Mapping) or "decision" not in result:
            _raise("INVALID_TELEMETRY_RESULTS", "each result must carry a decision")
        if result["decision"] == "TELEMETRY_GAP":
            telemetry_gap_trigger_ids.append(entry["trigger_id"])

    formats_generated: set[str] = set()
    attack_technique_coverage: set[str] = set()
    cve_context: set[str] = set()
    cwe_context: set[str] = set()
    owasp_context: set[str] = set()
    context_tuned_rule_count = 0
    validation_status_distribution: dict[str, int] = {}
    human_approval_state_distribution: dict[str, int] = {}
    deployment_state_distribution: dict[str, int] = {}
    evidence_references: list[str] = []
    limitations: set[str] = set()

    for rule in validated_rules:
        if not isinstance(rule, Mapping):
            _raise("INVALID_RULES", "each rule must be a mapping")
        formats_generated.add(rule.get("rule_format"))
        attack = rule.get("attack") or {}
        for technique in attack.get("technique", []) or []:
            attack_technique_coverage.add(technique)
        for cve in rule.get("cve", []) or []:
            cve_context.add(cve)
        for cwe in rule.get("cwe", []) or []:
            cwe_context.add(cwe)
        for owasp in rule.get("owasp", []) or []:
            owasp_context.add(owasp)
        if rule.get("context_tuned_rule") is not None:
            context_tuned_rule_count += 1
        status = rule.get("validation_status")
        validation_status_distribution[status] = validation_status_distribution.get(status, 0) + 1
        approval = rule.get("human_approval_state")
        human_approval_state_distribution[approval] = human_approval_state_distribution.get(approval, 0) + 1
        deployment = rule.get("deployment_state")
        deployment_state_distribution[deployment] = deployment_state_distribution.get(deployment, 0) + 1
        for reference in rule.get("evidence_references", []) or []:
            if reference not in evidence_references:
                evidence_references.append(reference)
        for limitation in rule.get("known_limitations", []) or []:
            limitations.add(limitation)

    dedup_summary = {"new_rule": 0, "update_candidate": 0, "existing_rule_match": 0}
    for entry in validated_dedup_results:
        if not isinstance(entry, Mapping) or entry.get("status") not in dedup_summary:
            _raise("INVALID_DEDUP_RESULTS", "each dedup result must carry a recognized status")
        dedup_summary[entry["status"]] += 1

    rules_generated = len(validated_rules)
    rules_rejected = max(rules_requested - rules_generated, 0)

    limitations.add("Every rule's status/validation reflects only what was actually performed -- syntax validation is not detection-efficacy validation.")
    if telemetry_gap_trigger_ids:
        limitations.add(f"{len(telemetry_gap_trigger_ids)} trigger(s) had no available telemetry -- no rule was generated for them.")

    return {
        "report_version": REPORT_VERSION,
        "trigger_summary": {"total": len(validated_triggers), "by_type": trigger_by_type},
        "rules_requested": rules_requested,
        "rules_generated": rules_generated,
        "rules_rejected": rules_rejected,
        "telemetry_gap_count": len(telemetry_gap_trigger_ids),
        "telemetry_gap_trigger_ids": telemetry_gap_trigger_ids,
        "formats_generated": sorted(f for f in formats_generated if f),
        "attack_technique_coverage": sorted(attack_technique_coverage),
        "cve_context": sorted(cve_context),
        "cwe_context": sorted(cwe_context),
        "owasp_context": sorted(owasp_context),
        "generic_rule_count": rules_generated,
        "context_tuned_rule_count": context_tuned_rule_count,
        "deduplication_summary": dedup_summary,
        "validation_status_distribution": validation_status_distribution,
        "human_approval_state_distribution": human_approval_state_distribution,
        "deployment_state_distribution": deployment_state_distribution,
        "limitations": sorted(limitations),
        "evidence_references": evidence_references,
    }
