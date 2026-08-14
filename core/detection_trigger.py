"""Pure, deterministic Detection Trigger contract (Block 15H-I).

This module answers exactly one question: *given a canonical Bug Bounty
finding, a normalized threat-intelligence record, or an analyst's own
manually-specified inputs, what does the resulting Detection Trigger
look like -- and does it carry enough real evidence to be acted on at
all?*

## A finding or a TI record never automatically produces a rule

Building a trigger is never the same thing as generating a detection
rule -- it is only the first, deterministic step of asking "is there
something here worth evaluating for detectability?" Every trigger this
module produces carries `human_review_required: True` and no
`deployment_state` of any kind; `core.detection_telemetry` (feasibility)
and `core.detection_planner`/`core.detection_rule` (actual rule
construction) are separate, later, equally-gated steps.

## No field is ever invented

`build_bug_bounty_trigger`/`build_threat_intelligence_trigger` only ever
copy or heuristically bucket fields that are *already present* on the
supplied finding/record. `required_telemetry_candidates` is a bounded,
fixed heuristic mapping from `observation_type`/`exploitation_status` to
a short list of telemetry *category names* (see `_TELEMETRY_CANDIDATE_RULES`)
-- it is a candidate list for `core.detection_telemetry` to actually
check against real org-supplied telemetry, never a claim that detection
is possible. No CVE, CWE, OWASP category, or ATT&CK technique is ever
added that was not already present on the source object.

## No I/O, no execution, ever

This module performs no network, filesystem, environment-variable,
subprocess, system-clock, or randomness access. It imports nothing from
`core.bug_bounty_final_report`/`core.threat_intelligence` -- it consumes
each as a plain, duck-typed, caller-supplied mapping, validated only
against the minimal fields it actually reads, following this project's
established convention (compare `core.context_prioritization`'s own
treatment of a Bug Bounty finding).

`DetectionTriggerError`, `build_bug_bounty_trigger`,
`build_threat_intelligence_trigger`, `build_manual_trigger`, and
`validate_detection_trigger` are this module's public symbols (plus
`TRIGGER_TYPES` and `TRIGGER_REQUIRED_FIELDS`).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

TRIGGER_VERSION = "1"
TRIGGER_TYPES = frozenset({"bug_bounty", "threat_intelligence", "manual"})
CONFIDENCE_LEVELS = frozenset({"low", "medium", "high"})

_ATTACK_FIELDS = ("tactic", "technique", "subtechnique")

TRIGGER_REQUIRED_FIELDS = (
    "trigger_version", "trigger_id", "trigger_type", "source_ids", "evidence_references",
    "security_behavior", "vulnerability_context", "cve", "cwe", "owasp", "attack",
    "affected_technology", "required_telemetry_candidates", "confidence", "limitations",
    "human_review_required",
)

# Bounded, fixed heuristic only -- these are *candidates* for
# core.detection_telemetry to check against real telemetry, never a
# claim that a rule is generatable.
_TELEMETRY_CANDIDATE_RULES: Mapping[str, tuple[str, ...]] = {
    "service": ("network_connection",),
    "web_configuration": ("http_proxy", "web_server"),
    "known_pattern_match": ("http_proxy", "web_server", "waf"),
    "dast_observation": ("http_proxy", "web_server", "waf"),
}
_EXPLOITATION_TELEMETRY_RULES: Mapping[str, tuple[str, ...]] = {
    "exploited_in_wild": ("process_creation", "network_connection", "authentication"),
    "weaponized": ("process_creation", "network_connection"),
    "poc_available": ("network_connection",),
    "unknown": (),
}


class DetectionTriggerError(ValueError):
    """Raised when a supplied finding/TI record/manual trigger input is
    structurally invalid.

    Never raised because a trigger's `security_behavior`/
    `vulnerability_context` is thin, because no telemetry candidates
    were derivable, or because `confidence` is `"low"` -- every one of
    those is a normal, successfully built trigger, not an error.
    """


def _raise(code: str, detail: str) -> None:
    raise DetectionTriggerError(f"{code}: {detail}")


def _in_vocab(value: Any, vocabulary: frozenset[str]) -> bool:
    return isinstance(value, str) and value in vocabulary


def _string_list(value: Any, code: str, field_name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        _raise(code, f"{field_name!r} must be a list of non-blank strings")
    return list(value)


def _digest_hex(value: Any, length: int = 16) -> str:
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


def _candidate_telemetry(*sources: tuple[str, ...]) -> list[str]:
    seen: list[str] = []
    for group in sources:
        for item in group:
            if item not in seen:
                seen.append(item)
    return seen


def _build_trigger(
    *, trigger_type: str, source_ids: list[str], evidence_references: list[str],
    security_behavior: str | None, vulnerability_context: str | None,
    cve: list[str], cwe: list[str], owasp: list[str], attack: dict[str, list[str]],
    affected_technology: list[str], required_telemetry_candidates: list[str],
    confidence: str, limitations: list[str],
) -> dict[str, Any]:
    trigger_id = "DT-" + _digest_hex({"trigger_type": trigger_type, "source_ids": sorted(source_ids)})
    return {
        "trigger_version": TRIGGER_VERSION,
        "trigger_id": trigger_id,
        "trigger_type": trigger_type,
        "source_ids": source_ids,
        "evidence_references": evidence_references,
        "security_behavior": security_behavior,
        "vulnerability_context": vulnerability_context,
        "cve": cve,
        "cwe": cwe,
        "owasp": owasp,
        "attack": attack,
        "affected_technology": affected_technology,
        "required_telemetry_candidates": required_telemetry_candidates,
        "confidence": confidence,
        "limitations": limitations,
        "human_review_required": True,
    }


# ---------------------------------------------------------------------------
# Bug Bounty -> trigger
# ---------------------------------------------------------------------------


def build_bug_bounty_trigger(*, canonical_finding: Any) -> dict[str, Any]:
    """Deterministically build one `"bug_bounty"` Detection Trigger from
    an already-existing canonical finding, shaped at minimum like
    `core.bug_bounty_final_report`'s own canonical finding contract.
    Performs no I/O of any kind.

    Only `finding_id`, `title`, `vulnerability_class`, `cwe`,
    `owasp_category`, `cve`, `tools_used`, `confidence`,
    `evidence_digests`, `limitations` are ever read from
    `canonical_finding` -- host/port/path/method/remediation/etc. are
    never inspected. Raises `DetectionTriggerError` for a structurally
    invalid `canonical_finding`.

    Returns a new dict shaped like `TRIGGER_REQUIRED_FIELDS`. `attack`
    is always empty (this project's Bug Bounty findings carry no ATT&CK
    mapping yet -- see `core.security_enrichment` for how one could be
    added, `candidate_pending_review`, before ever appearing here).
    """
    if not isinstance(canonical_finding, Mapping):
        _raise("INVALID_FINDING", "canonical_finding must be a mapping")

    finding_id = canonical_finding.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip():
        _raise("INVALID_FINDING", "canonical_finding['finding_id'] must be a non-blank string")
    title = canonical_finding.get("title")
    if not isinstance(title, str) or not title.strip():
        _raise("INVALID_FINDING", "canonical_finding['title'] must be a non-blank string")

    vulnerability_class = canonical_finding.get("vulnerability_class")
    cwe_value = canonical_finding.get("cwe")
    owasp_value = canonical_finding.get("owasp_category")
    cve = canonical_finding.get("cve")
    if not isinstance(cve, list) or not all(isinstance(item, str) for item in cve):
        _raise("INVALID_FINDING", "canonical_finding['cve'] must be a list of strings")

    tools_used = canonical_finding.get("tools_used")
    if not isinstance(tools_used, list) or not all(isinstance(item, str) for item in tools_used):
        _raise("INVALID_FINDING", "canonical_finding['tools_used'] must be a list of strings")

    confidence = canonical_finding.get("confidence")
    if not _in_vocab(confidence, CONFIDENCE_LEVELS):
        confidence = "low"  # honestly downgrade rather than reject -- an unset/unknown confidence is never inflated

    evidence_digests = canonical_finding.get("evidence_digests")
    if not isinstance(evidence_digests, list) or not all(isinstance(item, str) for item in evidence_digests):
        _raise("INVALID_FINDING", "canonical_finding['evidence_digests'] must be a list of strings")

    limitations = canonical_finding.get("limitations")
    if not isinstance(limitations, list) or not all(isinstance(item, str) for item in limitations):
        _raise("INVALID_FINDING", "canonical_finding['limitations'] must be a list of strings")

    observation_type_hint = "web_configuration" if vulnerability_class else None
    required_telemetry_candidates = _candidate_telemetry(
        _TELEMETRY_CANDIDATE_RULES.get(observation_type_hint or "", ()),
    )

    security_behavior = f"Observed condition: {vulnerability_class}" if vulnerability_class else None

    return _build_trigger(
        trigger_type="bug_bounty",
        source_ids=[finding_id.strip()],
        evidence_references=evidence_digests,
        security_behavior=security_behavior,
        vulnerability_context=title.strip(),
        cve=list(cve),
        cwe=[cwe_value] if isinstance(cwe_value, str) and cwe_value.strip() else [],
        owasp=[owasp_value] if isinstance(owasp_value, str) and owasp_value.strip() else [],
        attack={"tactic": [], "technique": [], "subtechnique": []},
        affected_technology=list(tools_used),
        required_telemetry_candidates=required_telemetry_candidates,
        confidence=confidence,
        limitations=list(limitations) + ["Derived from a Bug Bounty tool observation, not threat intelligence."],
    )


# ---------------------------------------------------------------------------
# Threat Intelligence -> trigger
# ---------------------------------------------------------------------------


def build_threat_intelligence_trigger(*, ti_record: Any) -> dict[str, Any]:
    """Deterministically build one `"threat_intelligence"` Detection
    Trigger from an already-normalized TI record, shaped exactly like
    `core.threat_intelligence.validate_threat_intelligence_record`'s own
    output (re-validated here, never trusted blindly). Performs no I/O
    of any kind, and never calls `core.threat_intelligence` itself.

    Raises `DetectionTriggerError` for a structurally invalid
    `ti_record`.

    Returns a new dict shaped like `TRIGGER_REQUIRED_FIELDS`.
    `security_behavior` is derived only from `ti_record['behavioral_indicators']`
    when present (joined, never invented); prefer this over
    `vulnerability_context`/a bare CVE number for zero-day/emerging
    threats, per this project's own detection-design preference for
    behavioral TTP detection.
    """
    if not isinstance(ti_record, Mapping):
        _raise("INVALID_TI_RECORD", "ti_record must be a mapping")

    intel_id = ti_record.get("intel_id")
    if not isinstance(intel_id, str) or not intel_id.strip():
        _raise("INVALID_TI_RECORD", "ti_record['intel_id'] must be a non-blank string")
    title = ti_record.get("title")
    if not isinstance(title, str) or not title.strip():
        _raise("INVALID_TI_RECORD", "ti_record['title'] must be a non-blank string")

    for field in ("cve", "cwe", "owasp", "affected_products", "evidence_references", "limitations", "behavioral_indicators"):
        value = ti_record.get(field)
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            _raise("INVALID_TI_RECORD", f"ti_record[{field!r}] must be a list of strings")

    attack = ti_record.get("attack")
    if not isinstance(attack, Mapping) or set(attack) != set(_ATTACK_FIELDS):
        _raise("INVALID_TI_RECORD", "ti_record['attack'] must contain exactly tactic/technique/subtechnique")
    for field in _ATTACK_FIELDS:
        if not isinstance(attack[field], list) or not all(isinstance(item, str) for item in attack[field]):
            _raise("INVALID_TI_RECORD", f"ti_record['attack'][{field!r}] must be a list of strings")

    confidence = ti_record.get("confidence")
    if not _in_vocab(confidence, CONFIDENCE_LEVELS):
        _raise("INVALID_TI_RECORD", "ti_record['confidence'] must be a recognized value")

    exploitation_status = ti_record.get("exploitation_status")
    required_telemetry_candidates = _candidate_telemetry(
        _EXPLOITATION_TELEMETRY_RULES.get(exploitation_status if isinstance(exploitation_status, str) else "unknown", ()),
    )

    behavioral_indicators = ti_record["behavioral_indicators"]
    security_behavior = "; ".join(behavioral_indicators) if behavioral_indicators else None

    limitations = list(ti_record["limitations"])
    corroboration_state = ti_record.get("corroboration_state")
    if corroboration_state in ("unconfirmed", "single_source"):
        limitations.append(f"Source corroboration_state is {corroboration_state!r} -- treat as a lead, not confirmed fact.")

    return _build_trigger(
        trigger_type="threat_intelligence",
        source_ids=[intel_id.strip()],
        evidence_references=list(ti_record["evidence_references"]),
        security_behavior=security_behavior,
        vulnerability_context=title.strip(),
        cve=list(ti_record["cve"]),
        cwe=list(ti_record["cwe"]),
        owasp=list(ti_record["owasp"]),
        attack={field: list(attack[field]) for field in _ATTACK_FIELDS},
        affected_technology=list(ti_record["affected_products"]),
        required_telemetry_candidates=required_telemetry_candidates,
        confidence=confidence,
        limitations=limitations,
    )


# ---------------------------------------------------------------------------
# Manual trigger
# ---------------------------------------------------------------------------


def build_manual_trigger(
    *, source_ids: Any, evidence_references: Any, security_behavior: Any, vulnerability_context: Any,
    cve: Any, cwe: Any, owasp: Any, attack: Any, affected_technology: Any,
    required_telemetry_candidates: Any, confidence: Any, limitations: Any,
) -> dict[str, Any]:
    """Deterministically build one `"manual"` Detection Trigger entirely
    from explicit, caller-supplied fields -- no source object is
    inspected or trusted here; every field is exactly what the analyst
    supplied. Performs no I/O of any kind.

    Every parameter is required and keyword-only, validated with the
    same rules `build_threat_intelligence_trigger` applies to its own
    fields. Raises `DetectionTriggerError` for any structurally invalid
    parameter.
    """
    validated_source_ids = _string_list(source_ids, "INVALID_INPUT", "source_ids")
    if not validated_source_ids:
        _raise("INVALID_INPUT", "source_ids must be a non-empty list")
    validated_evidence_references = _string_list(evidence_references, "INVALID_INPUT", "evidence_references")
    validated_cve = _string_list(cve, "INVALID_INPUT", "cve")
    validated_cwe = _string_list(cwe, "INVALID_INPUT", "cwe")
    validated_owasp = _string_list(owasp, "INVALID_INPUT", "owasp")
    validated_affected_technology = _string_list(affected_technology, "INVALID_INPUT", "affected_technology")
    validated_telemetry_candidates = _string_list(required_telemetry_candidates, "INVALID_INPUT", "required_telemetry_candidates")
    validated_limitations = _string_list(limitations, "INVALID_INPUT", "limitations")

    if security_behavior is not None and (not isinstance(security_behavior, str) or not security_behavior.strip()):
        _raise("INVALID_INPUT", "security_behavior must be null or a non-blank string")
    if vulnerability_context is not None and (not isinstance(vulnerability_context, str) or not vulnerability_context.strip()):
        _raise("INVALID_INPUT", "vulnerability_context must be null or a non-blank string")
    if security_behavior is None and vulnerability_context is None:
        _raise("INVALID_INPUT", "at least one of security_behavior/vulnerability_context must be supplied")

    if not isinstance(attack, Mapping) or set(attack) != set(_ATTACK_FIELDS):
        _raise("INVALID_INPUT", "attack must contain exactly tactic/technique/subtechnique")
    validated_attack = {field: _string_list(attack.get(field), "INVALID_INPUT", f"attack.{field}") for field in _ATTACK_FIELDS}

    if not _in_vocab(confidence, CONFIDENCE_LEVELS):
        _raise("INVALID_INPUT", "confidence must be a recognized value")

    return _build_trigger(
        trigger_type="manual",
        source_ids=validated_source_ids,
        evidence_references=validated_evidence_references,
        security_behavior=security_behavior.strip() if security_behavior else None,
        vulnerability_context=vulnerability_context.strip() if vulnerability_context else None,
        cve=validated_cve, cwe=validated_cwe, owasp=validated_owasp,
        attack=validated_attack, affected_technology=validated_affected_technology,
        required_telemetry_candidates=validated_telemetry_candidates,
        confidence=confidence, limitations=validated_limitations,
    )


# ---------------------------------------------------------------------------
# Re-validation of an already-built trigger.
# ---------------------------------------------------------------------------


def validate_detection_trigger(*, trigger: Any) -> dict[str, Any]:
    """Deterministically re-validate an already-built Detection Trigger
    (from any of the three builders above, or reconstructed by a
    caller). Performs no I/O of any kind.

    Raises `DetectionTriggerError` for a structurally invalid `trigger`,
    including an unrecognized `trigger_type` (only `TRIGGER_TYPES` is
    ever accepted -- this is the check `core.detection_planner` relies
    on to reject an unapproved trigger type).

    Returns a new, re-validated dict. Never mutates `trigger`.
    """
    if not isinstance(trigger, Mapping) or set(trigger) != set(TRIGGER_REQUIRED_FIELDS):
        _raise("INVALID_TRIGGER", "trigger must contain exactly the required trigger fields")
    if trigger.get("trigger_version") != TRIGGER_VERSION:
        _raise("INVALID_TRIGGER", "trigger_version must be '1'")
    trigger_id = trigger.get("trigger_id")
    if not isinstance(trigger_id, str) or not trigger_id.startswith("DT-"):
        _raise("INVALID_TRIGGER", "trigger_id must be a non-blank string starting with 'DT-'")
    if not _in_vocab(trigger.get("trigger_type"), TRIGGER_TYPES):
        _raise("INVALID_TRIGGER", "trigger_type must be a recognized value")

    source_ids = _string_list(trigger.get("source_ids"), "INVALID_TRIGGER", "source_ids")
    if not source_ids:
        _raise("INVALID_TRIGGER", "source_ids must be a non-empty list")
    evidence_references = _string_list(trigger.get("evidence_references"), "INVALID_TRIGGER", "evidence_references")

    security_behavior = trigger.get("security_behavior")
    if security_behavior is not None and not isinstance(security_behavior, str):
        _raise("INVALID_TRIGGER", "security_behavior must be null or a string")
    vulnerability_context = trigger.get("vulnerability_context")
    if vulnerability_context is not None and not isinstance(vulnerability_context, str):
        _raise("INVALID_TRIGGER", "vulnerability_context must be null or a string")

    cve = _string_list(trigger.get("cve"), "INVALID_TRIGGER", "cve")
    cwe = _string_list(trigger.get("cwe"), "INVALID_TRIGGER", "cwe")
    owasp = _string_list(trigger.get("owasp"), "INVALID_TRIGGER", "owasp")

    attack = trigger.get("attack")
    if not isinstance(attack, Mapping) or set(attack) != set(_ATTACK_FIELDS):
        _raise("INVALID_TRIGGER", "attack must contain exactly tactic/technique/subtechnique")
    validated_attack = {field: _string_list(attack.get(field), "INVALID_TRIGGER", f"attack.{field}") for field in _ATTACK_FIELDS}

    affected_technology = _string_list(trigger.get("affected_technology"), "INVALID_TRIGGER", "affected_technology")
    required_telemetry_candidates = _string_list(trigger.get("required_telemetry_candidates"), "INVALID_TRIGGER", "required_telemetry_candidates")

    if not _in_vocab(trigger.get("confidence"), CONFIDENCE_LEVELS):
        _raise("INVALID_TRIGGER", "confidence must be a recognized value")
    limitations = _string_list(trigger.get("limitations"), "INVALID_TRIGGER", "limitations")

    if trigger.get("human_review_required") is not True:
        _raise("INVALID_TRIGGER", "human_review_required must be true")

    return {
        "trigger_version": TRIGGER_VERSION,
        "trigger_id": trigger_id,
        "trigger_type": trigger["trigger_type"],
        "source_ids": source_ids,
        "evidence_references": evidence_references,
        "security_behavior": security_behavior,
        "vulnerability_context": vulnerability_context,
        "cve": cve, "cwe": cwe, "owasp": owasp,
        "attack": validated_attack,
        "affected_technology": affected_technology,
        "required_telemetry_candidates": required_telemetry_candidates,
        "confidence": trigger["confidence"],
        "limitations": limitations,
        "human_review_required": True,
    }
