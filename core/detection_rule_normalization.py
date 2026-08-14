"""Pure, deterministic Detection Rule field normalization (Block 15H-I).

This module answers exactly one question: *given one already-built
Detection Rule (`core.detection_rule.build_detection_rule`'s own
output), what does its normalized comparison form look like -- the form
`core.detection_rule_deduplication` actually fingerprints against?*

## Normalization never touches the rule itself

`normalize_detection_rule_fields` returns a **new, separate** dict of
comparison keys -- it never mutates or returns a modified rule. The
rule's own human-readable `title`/`description`/`generic_rule` are never
rewritten; only a derived, lowercase/whitespace-collapsed
`behavior_signature` comparison key is computed from `detection_objective`,
strictly for fingerprinting purposes.

## Meaningful differences are never normalized away

CVE/CWE identifiers are only ever case- and whitespace-normalized, never
merged across genuinely different identifiers. ATT&CK `technique` and
`subtechnique` are normalized (and compared) **separately** -- `T1190`
and `T1190.001` are deliberately different fingerprint members, since a
subtechnique is meaningfully more specific than its parent technique.
`rule_format` is preserved as its own comparison dimension (never
collapsed across formats) -- a Sigma rule and a Splunk SPL rule
addressing the same behavior are legitimately two different artifacts,
not duplicates of each other.

## No I/O, no execution, ever

This module performs no network, filesystem, environment-variable,
subprocess, system-clock, or randomness access, and imports no other
`core.*` module -- it consumes a rule as a plain, duck-typed mapping,
validated only against the minimal fields it actually reads.

`DetectionRuleNormalizationError` and `normalize_detection_rule_fields`
are this module's public symbols.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

_ATTACK_FIELDS = ("technique", "subtechnique")


class DetectionRuleNormalizationError(ValueError):
    """Raised when a supplied `rule` is structurally invalid. Never
    raised because a rule carries no CVE/CWE/ATT&CK mapping -- an empty
    normalized field is a normal result, not an error."""


def _raise(code: str, detail: str) -> None:
    raise DetectionRuleNormalizationError(f"{code}: {detail}")


def _normalized_identifier_set(values: Any, code: str, field_name: str) -> list[str]:
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        _raise(code, f"{field_name!r} must be a list of strings")
    return sorted({item.strip().upper() for item in values if item.strip()})


def _normalized_lowercase_set(values: Any, code: str, field_name: str) -> list[str]:
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        _raise(code, f"{field_name!r} must be a list of strings")
    return sorted({item.strip().lower() for item in values if item.strip()})


def normalize_detection_rule_fields(*, rule: Any) -> dict[str, Any]:
    """Deterministically compute the normalized comparison keys for one
    Detection Rule. Performs no I/O of any kind.

    `rule` is required and keyword-only, and must be a mapping shaped at
    minimum like `core.detection_rule.build_detection_rule`'s own output
    -- only `cve`, `cwe`, `attack`, `required_telemetry`,
    `detection_objective`, `trigger_type`, `rule_format`,
    `affected_technology` are ever read.

    Returns a new dict containing exactly `cve` (uppercase, de-duplicated,
    sorted), `cwe` (same treatment), `attack_technique`/
    `attack_subtechnique` (uppercase, de-duplicated, sorted, kept
    separate from each other), `required_telemetry` (de-duplicated,
    sorted), `behavior_signature` (lowercase, whitespace-collapsed
    `detection_objective`), `trigger_type` (echoed, already a closed
    vocabulary value), `rule_format` (lowercase, stripped),
    `affected_technology` (lowercase, de-duplicated, sorted).

    Raises `DetectionRuleNormalizationError` for a structurally invalid
    `rule`. Never mutates `rule`.
    """
    if not isinstance(rule, Mapping):
        _raise("INVALID_RULE", "rule must be a mapping")

    cve = _normalized_identifier_set(rule.get("cve"), "INVALID_RULE", "cve")
    cwe = _normalized_identifier_set(rule.get("cwe"), "INVALID_RULE", "cwe")

    attack = rule.get("attack")
    if not isinstance(attack, Mapping) or not set(_ATTACK_FIELDS).issubset(set(attack)):
        _raise("INVALID_RULE", "rule['attack'] must contain at least technique/subtechnique")
    attack_technique = _normalized_identifier_set(attack.get("technique"), "INVALID_RULE", "attack.technique")
    attack_subtechnique = _normalized_identifier_set(attack.get("subtechnique"), "INVALID_RULE", "attack.subtechnique")

    required_telemetry = rule.get("required_telemetry")
    if not isinstance(required_telemetry, list) or not all(isinstance(item, str) for item in required_telemetry):
        _raise("INVALID_RULE", "required_telemetry must be a list of strings")
    normalized_telemetry = sorted(set(required_telemetry))

    detection_objective = rule.get("detection_objective")
    if not isinstance(detection_objective, str) or not detection_objective.strip():
        _raise("INVALID_RULE", "detection_objective must be a non-blank string")
    behavior_signature = " ".join(detection_objective.strip().lower().split())

    trigger_type = rule.get("trigger_type")
    if not isinstance(trigger_type, str) or not trigger_type.strip():
        _raise("INVALID_RULE", "trigger_type must be a non-blank string")

    rule_format = rule.get("rule_format")
    if not isinstance(rule_format, str) or not rule_format.strip():
        _raise("INVALID_RULE", "rule_format must be a non-blank string")

    affected_technology = _normalized_lowercase_set(rule.get("affected_technology"), "INVALID_RULE", "affected_technology")

    return {
        "cve": cve,
        "cwe": cwe,
        "attack_technique": attack_technique,
        "attack_subtechnique": attack_subtechnique,
        "required_telemetry": normalized_telemetry,
        "behavior_signature": behavior_signature,
        "trigger_type": trigger_type,
        "rule_format": rule_format.strip().lower(),
        "affected_technology": affected_technology,
    }
