"""Pure, deterministic Detection Rule fingerprinting + deduplication
(Block 15H-I).

This module answers exactly one question: *given one candidate
Detection Rule and a list of already-existing rules, does an equivalent
rule already exist -- and if something related exists but isn't quite
the same, should this be treated as a fresh rule or an update to an
existing one?*

## Two fingerprints, never one collapsed decision

`compute_rule_fingerprints` computes two separate digests over
`core.detection_rule_normalization`'s own normalized comparison fields:

- `identity_fingerprint` -- CVE, CWE, ATT&CK technique/subtechnique,
  `rule_format`, `trigger_type` only. This is "what is this rule
  fundamentally about, in this format."
- `full_fingerprint` -- every normalized field, including
  `required_telemetry`, `behavior_signature`, and `affected_technology`.
  This is "is this *exactly* the same rule."

`check_rule_duplicate` compares a candidate against every existing rule:
a `full_fingerprint` match is `"existing_rule_match"` (a genuine
duplicate -- nothing new here); an `identity_fingerprint`-only match
(same core identity, but telemetry/behavior/tech details differ) is
`"update_candidate"` (the same underlying rule has evolved -- a human
should decide whether to revise the existing rule rather than silently
create a second one); no fingerprint overlap at all is `"new_rule"`.

## Never deduplicated on title alone

Title is never read by this module at all -- neither fingerprint
includes it. Two rules with identical titles but different CVE/CWE/
ATT&CK/telemetry/format are always `"new_rule"` relative to each other;
two rules with wildly different titles but identical normalized fields
are always at least `"update_candidate"`.

## Source/evidence history is preserved, never discarded

This module never merges, drops, or overwrites `source_finding_ids`/
`source_intel_ids`/`evidence_references` on any existing rule -- it only
*reports* a match/candidate relationship; actually merging evidence
history (if a caller chooses to) is a separate, explicit action this
module does not perform.

## No I/O, no execution, ever

This module performs no network, filesystem, environment-variable,
subprocess, system-clock, or randomness access. It imports exactly one
symbol, `core.detection_rule_normalization.normalize_detection_rule_fields`,
since fingerprinting is *by design* built directly on that module's own
normalized output (the same kind of deliberate, documented composition
used throughout this project, e.g. `core.bug_bounty_planner`'s import of
`core.bug_bounty_tool_policy`).

`DetectionRuleDeduplicationError`, `compute_rule_fingerprints`, and
`check_rule_duplicate` are this module's public symbols (plus
`DUPLICATE_STATUSES`).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from core.detection_rule_normalization import DetectionRuleNormalizationError, normalize_detection_rule_fields

DUPLICATE_STATUSES = frozenset({"existing_rule_match", "update_candidate", "new_rule"})

_IDENTITY_FIELDS = ("cve", "cwe", "attack_technique", "attack_subtechnique", "rule_format", "trigger_type")


class DetectionRuleDeduplicationError(ValueError):
    """Raised when a supplied rule/existing-rules-list input is
    structurally invalid (wrapping
    `core.detection_rule_normalization.DetectionRuleNormalizationError`
    for a malformed nested rule).

    Never raised because no existing rule matches (that is the normal
    `"new_rule"` result) or because many existing rules share the same
    identity fingerprint -- every one of those is a normal, successfully
    computed result.
    """


def _raise(code: str, detail: str) -> None:
    raise DetectionRuleDeduplicationError(f"{code}: {detail}")


def _digest_hex(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_rule_fingerprints(*, rule: Any) -> dict[str, str]:
    """Deterministically compute both fingerprints for one Detection
    Rule. Performs no I/O of any kind.

    `rule` must be shaped at minimum like
    `core.detection_rule.build_detection_rule`'s own output (re-used via
    `core.detection_rule_normalization.normalize_detection_rule_fields`,
    never re-implemented here).

    Returns `{"identity_fingerprint": "sha256:...", "full_fingerprint":
    "sha256:..."}`.

    Raises `DetectionRuleDeduplicationError` for a structurally invalid
    `rule` (wrapping the real `DetectionRuleNormalizationError`).
    """
    try:
        normalized = normalize_detection_rule_fields(rule=rule)
    except DetectionRuleNormalizationError as exc:
        _raise("INVALID_RULE", str(exc))

    identity_payload = {field: normalized[field] for field in _IDENTITY_FIELDS}
    return {
        "identity_fingerprint": "sha256:" + _digest_hex(identity_payload),
        "full_fingerprint": "sha256:" + _digest_hex(normalized),
    }


def check_rule_duplicate(*, candidate_rule: Any, existing_rules: Any) -> dict[str, Any]:
    """Deterministically check whether `candidate_rule` duplicates, or
    is an update candidate for, any rule already in `existing_rules`.
    Performs no I/O of any kind, and never modifies any existing rule.

    `candidate_rule` must be shaped like `core.detection_rule.
    build_detection_rule`'s own output. `existing_rules` must be a list
    of rules shaped the same way (each carrying its own `detection_id`
    -- used only to report which existing rule matched, never re-derived).

    Returns a dict with `status` (one of `DUPLICATE_STATUSES`),
    `candidate_fingerprints` (`compute_rule_fingerprints`'s own output
    for `candidate_rule`), `matched_detection_id` (the `detection_id` of
    the matching existing rule, or `None` for `"new_rule"`).

    Raises `DetectionRuleDeduplicationError` for a structurally invalid
    `candidate_rule`/`existing_rules` entry. Never raises because no
    match is found.
    """
    candidate_fingerprints = compute_rule_fingerprints(rule=candidate_rule)

    if not isinstance(existing_rules, list):
        _raise("INVALID_EXISTING_RULES", "existing_rules must be a list")

    identity_match_id: str | None = None
    for existing_rule in existing_rules:
        if not isinstance(existing_rule, Mapping):
            _raise("INVALID_EXISTING_RULES", "each existing rule must be a mapping")
        detection_id = existing_rule.get("detection_id")
        if not isinstance(detection_id, str) or not detection_id.strip():
            _raise("INVALID_EXISTING_RULES", "each existing rule must carry a non-blank detection_id")

        existing_fingerprints = compute_rule_fingerprints(rule=existing_rule)
        if existing_fingerprints["full_fingerprint"] == candidate_fingerprints["full_fingerprint"]:
            return {
                "status": "existing_rule_match",
                "candidate_fingerprints": candidate_fingerprints,
                "matched_detection_id": detection_id,
            }
        if identity_match_id is None and existing_fingerprints["identity_fingerprint"] == candidate_fingerprints["identity_fingerprint"]:
            identity_match_id = detection_id

    if identity_match_id is not None:
        return {
            "status": "update_candidate",
            "candidate_fingerprints": candidate_fingerprints,
            "matched_detection_id": identity_match_id,
        }

    return {
        "status": "new_rule",
        "candidate_fingerprints": candidate_fingerprints,
        "matched_detection_id": None,
    }
