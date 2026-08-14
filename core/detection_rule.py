"""Pure, deterministic Detection Rule contract (Block 15H-I).

This module answers exactly one question: *given one already-validated
LLM rule draft (from `core.detection_planner.validate_detection_plan`'s
own `proposed_rules`) and its source Detection Trigger, what does the
full, structured Detection Rule record look like -- honestly reflecting
that it has been drafted, never deployed, never approved, and never
validated beyond whatever this checkpoint's own bounded structural
checks actually performed?*

## deployment_state can never be anything but NOT_DEPLOYED here

There is no parameter anywhere in `build_detection_rule`'s signature,
and no function anywhere in this module, that can produce a rule with
`deployment_state` other than `"NOT_DEPLOYED"`. This is not merely a
default -- it is structurally the only value this module's code can
ever write to that field. A real deployment (never implemented in this
project) would have to be a separate, later, explicitly-audited action
outside this module entirely.

## validation_status starts, and stays, honest

`build_detection_rule` always sets `validation_status: "draft"` --
never `"syntax_validated"`/`"tested"`/`"validated"` at build time, since
no validation has happened yet. `apply_validation_result` is the only
function that can ever advance `validation_status`, and it only ever
copies forward exactly what `core.detection_rule_validation` itself
reports -- this module never claims `"tested"` from a syntax check alone,
and never claims `"validated"` without a real validation result saying so.

## human_approval_state is caller-reported, never authenticated here

`human_approval_state` always starts `"pending"`. Nothing in this
module verifies who a caller claiming to approve a rule actually is --
exactly like every other approval-state field in this project
(`core.security_handoff.record_security_handoff_approval`, `core.
bug_bounty_tool_policy`'s own `human_approval_state`), a caller-supplied
`"approved"` value is recorded as what the caller reported, never
independently confirmed.

## No I/O, no execution, ever

This module performs no network, filesystem, environment-variable,
subprocess, system-clock, or randomness access, and never imports
`core.detection_rule_validation`/`core.detection_rule_deduplication`
(those consume this module's output, not the reverse).

`DetectionRuleError`, `build_detection_rule`, and `apply_validation_result`
are this module's public symbols (plus `VALIDATION_STATUSES`,
`APPROVAL_STATES`, `DEPLOYMENT_STATES`, and `RULE_REQUIRED_FIELDS`).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

RULE_VERSION = "1"

VALIDATION_STATUSES = frozenset({"draft", "syntax_validated", "tested", "validated", "rejected"})
APPROVAL_STATES = frozenset({"pending", "approved", "rejected"})
DEPLOYMENT_STATES = frozenset({"NOT_DEPLOYED", "DEPLOYED"})
CONFIDENCE_LEVELS = frozenset({"low", "medium", "high"})

_ATTACK_FIELDS = ("tactic", "technique", "subtechnique")

RULE_REQUIRED_FIELDS = (
    "rule_version", "detection_id", "title", "trigger_type", "trigger_id",
    "source_finding_ids", "source_intel_ids", "evidence_references",
    "description", "detection_objective", "cve", "cwe", "owasp", "attack",
    "actor", "campaign", "affected_technology", "required_telemetry", "data_source",
    "rule_format", "generic_rule", "context_tuned_rule",
    "false_positive_considerations", "known_limitations",
    "confidence", "evidence_confidence", "validation_status",
    "human_approval_state", "deployment_state",
)


class DetectionRuleError(ValueError):
    """Raised when a supplied rule draft/trigger/validation-result input
    is structurally invalid.

    Never raised because `context_tuned_rule` is `null`, because
    `validation_status` is `"draft"`, or because `human_approval_state`
    is `"pending"` -- every one of those is the normal, honest starting
    state, not an error.
    """


def _raise(code: str, detail: str) -> None:
    raise DetectionRuleError(f"{code}: {detail}")


def _digest_hex(value: Any, length: int = 16) -> str:
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


def build_detection_rule(
    *, validated_rule_draft: Any, trigger: Any, data_source: Any = None,
) -> dict[str, Any]:
    """Deterministically build one Detection Rule record from an
    already-validated LLM rule draft and its already-validated source
    trigger. Performs no I/O of any kind.

    `validated_rule_draft` must be shaped exactly like one entry of
    `core.detection_planner.validate_detection_plan`'s own
    `proposed_rules` output. `trigger` must be shaped exactly like
    `core.detection_trigger.validate_detection_trigger`'s own output
    (both are consumed as plain, duck-typed mappings -- this module
    imports neither `core.detection_planner` nor `core.detection_trigger`,
    following this project's established convention). `data_source` is
    optional (default `None`, echoed verbatim -- e.g. a SIEM/EDR
    platform name; never independently verified).

    `source_finding_ids`/`source_intel_ids` are populated from
    `trigger['source_ids']` according to `trigger['trigger_type']`
    (`"bug_bounty"` -> `source_finding_ids`; `"threat_intelligence"` ->
    `source_intel_ids`; `"manual"` -> neither). `validation_status` is
    always `"draft"`. `human_approval_state` is always `"pending"`.
    `deployment_state` is always `"NOT_DEPLOYED"` -- see module
    docstring; there is no way to construct any other value here.

    Returns a new dict containing exactly `RULE_REQUIRED_FIELDS`.

    Raises `DetectionRuleError` for a structurally invalid
    `validated_rule_draft`/`trigger`/`data_source`.
    """
    if not isinstance(validated_rule_draft, Mapping):
        _raise("INVALID_RULE_DRAFT", "validated_rule_draft must be a mapping")
    if not isinstance(trigger, Mapping):
        _raise("INVALID_TRIGGER", "trigger must be a mapping")

    trigger_type = trigger.get("trigger_type")
    if trigger_type not in ("bug_bounty", "threat_intelligence", "manual"):
        _raise("INVALID_TRIGGER", "trigger['trigger_type'] must be a recognized value")
    trigger_id = trigger.get("trigger_id")
    if not isinstance(trigger_id, str) or not trigger_id.strip():
        _raise("INVALID_TRIGGER", "trigger['trigger_id'] must be a non-blank string")
    source_ids = trigger.get("source_ids")
    if not isinstance(source_ids, list) or not all(isinstance(item, str) for item in source_ids):
        _raise("INVALID_TRIGGER", "trigger['source_ids'] must be a list of strings")

    rule_format = validated_rule_draft.get("rule_format")
    title = validated_rule_draft.get("title")
    description = validated_rule_draft.get("description")
    generic_rule = validated_rule_draft.get("generic_rule_content")
    if not all(isinstance(value, str) and value.strip() for value in (rule_format, title, description, generic_rule)):
        _raise("INVALID_RULE_DRAFT", "rule_format/title/description/generic_rule_content must each be non-blank strings")

    context_tuned_rule = validated_rule_draft.get("context_tuned_rule_content")
    if context_tuned_rule is not None and (not isinstance(context_tuned_rule, str) or not context_tuned_rule.strip()):
        _raise("INVALID_RULE_DRAFT", "context_tuned_rule_content must be null or a non-blank string")

    false_positive_considerations = validated_rule_draft.get("false_positive_considerations")
    if not isinstance(false_positive_considerations, list) or not all(isinstance(item, str) for item in false_positive_considerations):
        _raise("INVALID_RULE_DRAFT", "false_positive_considerations must be a list of strings")

    required_telemetry = validated_rule_draft.get("required_telemetry")
    if not isinstance(required_telemetry, list) or not all(isinstance(item, str) for item in required_telemetry):
        _raise("INVALID_RULE_DRAFT", "required_telemetry must be a list of strings")

    if data_source is not None and (not isinstance(data_source, str) or not data_source.strip()):
        _raise("INVALID_DATA_SOURCE", "data_source must be null or a non-blank string")

    cve = trigger.get("cve") or []
    cwe = trigger.get("cwe") or []
    owasp = trigger.get("owasp") or []
    attack = trigger.get("attack") or {field: [] for field in _ATTACK_FIELDS}
    affected_technology = trigger.get("affected_technology") or []
    evidence_references = trigger.get("evidence_references") or []
    known_limitations = list(trigger.get("limitations") or [])
    confidence = trigger.get("confidence")
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "low"

    source_finding_ids = source_ids if trigger_type == "bug_bounty" else []
    source_intel_ids = source_ids if trigger_type == "threat_intelligence" else []

    detection_id = "RULE-" + _digest_hex({
        "trigger_id": trigger_id, "rule_format": rule_format, "rule_draft_id": validated_rule_draft.get("rule_draft_id"),
    })

    return {
        "rule_version": RULE_VERSION,
        "detection_id": detection_id,
        "title": title.strip(),
        "trigger_type": trigger_type,
        "trigger_id": trigger_id,
        "source_finding_ids": list(source_finding_ids),
        "source_intel_ids": list(source_intel_ids),
        "evidence_references": list(evidence_references),
        "description": description.strip(),
        "detection_objective": description.strip(),
        "cve": list(cve),
        "cwe": list(cwe),
        "owasp": list(owasp),
        "attack": {field: list(attack.get(field, [])) for field in _ATTACK_FIELDS},
        "actor": None,
        "campaign": None,
        "affected_technology": list(affected_technology),
        "required_telemetry": list(required_telemetry),
        "data_source": data_source.strip() if data_source else None,
        "rule_format": rule_format,
        "generic_rule": generic_rule.strip(),
        "context_tuned_rule": context_tuned_rule.strip() if context_tuned_rule else None,
        "false_positive_considerations": list(false_positive_considerations),
        "known_limitations": known_limitations,
        "confidence": confidence,
        "evidence_confidence": confidence,
        "validation_status": "draft",
        "human_approval_state": "pending",
        "deployment_state": "NOT_DEPLOYED",
    }


def apply_validation_result(*, rule: Any, validation_status: Any, known_limitations_addendum: Any = None) -> dict[str, Any]:
    """Deterministically advance one rule's `validation_status`, given a
    result already produced by `core.detection_rule_validation`.
    Performs no I/O of any kind, and never itself decides what
    validation was performed -- it only records what it is told.

    `rule` must be shaped like `build_detection_rule`'s own output.
    `validation_status` must be one of `VALIDATION_STATUSES`.
    `known_limitations_addendum` is optional (default `None`) -- when
    supplied, must be a non-blank string appended to `known_limitations`.

    Returns a new rule dict with only `validation_status` (and
    optionally `known_limitations`) changed -- `deployment_state` and
    `human_approval_state` are never touched by this function. Neither
    `rule` nor any nested value is ever mutated.

    Raises `DetectionRuleError` for a structurally invalid `rule` or
    `validation_status`.
    """
    if not isinstance(rule, Mapping) or set(rule) != set(RULE_REQUIRED_FIELDS):
        _raise("INVALID_RULE", "rule must contain exactly the required rule fields")
    if validation_status not in VALIDATION_STATUSES:
        _raise("INVALID_VALIDATION_STATUS", "validation_status must be one of VALIDATION_STATUSES")
    if known_limitations_addendum is not None and (
        not isinstance(known_limitations_addendum, str) or not known_limitations_addendum.strip()
    ):
        _raise("INVALID_INPUT", "known_limitations_addendum must be null or a non-blank string")

    updated = dict(rule)
    updated["validation_status"] = validation_status
    if known_limitations_addendum:
        updated["known_limitations"] = list(rule["known_limitations"]) + [known_limitations_addendum.strip()]
    return updated
