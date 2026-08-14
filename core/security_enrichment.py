"""Pure, deterministic CWE/CVE -> ATT&CK enrichment binding (Block 15H-I).

This module answers exactly one question: *given a CWE or CVE
identifier a finding/TI record/trigger already carries, what ATT&CK
technique (if any) is it reasonable to associate with it -- and how
much should that association be trusted?*

## The LLM never freely invents a mapping

There are exactly three ways an enrichment record can ever carry an
`attack_technique`, and every one of them is explicit in
`mapping_source`:

1. `"source_provided"` -- the caller already supplied the technique
   directly (e.g. a TI record whose own `attack.technique` field already
   named it). Nothing is inferred; this module only echoes it.
2. `"local_dataset"` -- a small, fixed, hardcoded table of well-known,
   general CWE-category-to-ATT&CK-technique associations this project
   ships with (`_LOCAL_CWE_TO_ATTACK`), conceptually informed by MITRE's
   own published CWE/ATT&CK mapping guidance. These are category-level
   associations, never incident-specific claims -- `mapping_confidence`
   is always `"medium"` for this source, never `"high"`.
3. `"llm_proposed"` -- an already-produced LLM suggestion the caller
   passes to `record_llm_proposed_enrichment` explicitly. This module
   never calls an LLM itself; it only validates and labels what it is
   given as `validation_status: "candidate_pending_review"`,
   `mapping_confidence: "low"`, `human_review_required: True` --
   unconditionally, regardless of how confident the LLM's own rationale
   text sounds.

`enrich_identifier` never returns a technique from any source other than
these three, and an identifier with no known mapping in any of them
returns `attack_technique: None`, `validation_status: "unmapped"` --
never a guess.

## No I/O, no execution, ever

This module performs no network, filesystem, environment-variable,
subprocess, system-clock, or randomness access, and imports no other
`core.*` module.

`SecurityEnrichmentError`, `enrich_identifier`, and
`record_llm_proposed_enrichment` are this module's public symbols (plus
`MAPPING_SOURCES`, `MAPPING_CONFIDENCE_LEVELS`, `VALIDATION_STATUSES`,
and `IDENTIFIER_TYPES`).
"""

from __future__ import annotations

import hashlib
import json
from types import MappingProxyType
from typing import Any

ENRICHMENT_VERSION = "1"

IDENTIFIER_TYPES = frozenset({"cwe", "cve"})
MAPPING_SOURCES = frozenset({"source_provided", "local_dataset", "llm_proposed"})
MAPPING_CONFIDENCE_LEVELS = frozenset({"low", "medium", "high"})
VALIDATION_STATUSES = frozenset({"confirmed", "candidate_pending_review", "unmapped"})

# A small, fixed, hardcoded set of well-known, general CWE-category ->
# ATT&CK-technique associations -- conceptually informed by MITRE's own
# published CWE/ATT&CK mapping guidance, never incident-specific, never
# expanded without a future checkpoint's explicit review.
_LOCAL_CWE_TO_ATTACK: dict[str, str] = MappingProxyType({
    "CWE-89": "T1190",   # SQL Injection -> Exploit Public-Facing Application
    "CWE-79": "T1190",   # Cross-Site Scripting -> Exploit Public-Facing Application
    "CWE-78": "T1190",   # OS Command Injection -> Exploit Public-Facing Application
    "CWE-306": "T1190",  # Missing Authentication for Critical Function -> Exploit Public-Facing Application
    "CWE-798": "T1552.001",  # Hardcoded Credentials -> Unsecured Credentials: Credentials In Files
    "CWE-287": "T1078",  # Improper Authentication -> Valid Accounts
    "CWE-284": "T1078",  # Improper Access Control -> Valid Accounts
    "CWE-693": "T1600",  # Protection Mechanism Failure (e.g. missing CSP) -> Weaken Encryption (closest general category; low-confidence)
})


class SecurityEnrichmentError(ValueError):
    """Raised when a supplied identifier/mapping input is structurally
    invalid.

    Never raised because an identifier has no known mapping (that is
    `validation_status: "unmapped"`), or because an LLM-proposed mapping
    seems implausible -- every proposal is accepted as
    `candidate_pending_review`, never rejected on content grounds by
    this module.
    """


def _raise(code: str, detail: str) -> None:
    raise SecurityEnrichmentError(f"{code}: {detail}")


def _require_nonblank_string(value: Any, code: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _raise(code, f"{field_name!r} must be a non-blank string")
    return value.strip()


def _digest_hex(value: Any, length: int = 16) -> str:
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


def _build_record(
    *, identifier_type: str, identifier: str, attack_technique: str | None,
    mapping_source: str | None, mapping_confidence: str | None,
    human_review_required: bool, validation_status: str, rationale: str | None,
) -> dict[str, Any]:
    enrichment_id = "ENR-" + _digest_hex({
        "identifier_type": identifier_type, "identifier": identifier,
        "attack_technique": attack_technique, "mapping_source": mapping_source,
    })
    return {
        "enrichment_version": ENRICHMENT_VERSION,
        "enrichment_id": enrichment_id,
        "identifier_type": identifier_type,
        "identifier": identifier,
        "attack_technique": attack_technique,
        "mapping_source": mapping_source,
        "mapping_confidence": mapping_confidence,
        "human_review_required": human_review_required,
        "validation_status": validation_status,
        "rationale": rationale,
    }


def enrich_identifier(*, identifier_type: Any, identifier: Any, source_provided_technique: Any = None) -> dict[str, Any]:
    """Deterministically bind one CWE/CVE identifier to an ATT&CK
    technique, preferring an already-source-provided technique over this
    module's own small local dataset, and never inventing one when
    neither is available. Performs no I/O of any kind.

    `identifier_type` must be one of `IDENTIFIER_TYPES`. `identifier`
    must be a non-blank string. `source_provided_technique` is optional
    (default `None`) -- when supplied, must be a non-blank string, and
    is always preferred: `mapping_source: "source_provided"`,
    `mapping_confidence: "high"`, `human_review_required: False`,
    `validation_status: "confirmed"` (the caller already asserted it;
    this module only echoes it, never re-derives it).

    When `source_provided_technique` is omitted and `identifier_type ==
    "cwe"` and `identifier` is a key in this module's own fixed
    `_LOCAL_CWE_TO_ATTACK` table: `mapping_source: "local_dataset"`,
    `mapping_confidence: "medium"`, `human_review_required: True`,
    `validation_status: "candidate_pending_review"` (a general category
    association, never a confirmed incident-specific claim).

    Otherwise: `attack_technique: None`, `mapping_source: None`,
    `mapping_confidence: None`, `human_review_required: False` (there is
    nothing here for a human to review), `validation_status: "unmapped"`.

    Raises `SecurityEnrichmentError` for a structurally invalid
    `identifier_type`/`identifier`/`source_provided_technique`. Never
    raises because an identifier has no known mapping.
    """
    if identifier_type not in IDENTIFIER_TYPES:
        _raise("INVALID_IDENTIFIER_TYPE", "identifier_type must be one of IDENTIFIER_TYPES")
    validated_identifier = _require_nonblank_string(identifier, "INVALID_IDENTIFIER", "identifier")

    if source_provided_technique is not None:
        validated_technique = _require_nonblank_string(
            source_provided_technique, "INVALID_TECHNIQUE", "source_provided_technique",
        )
        return _build_record(
            identifier_type=identifier_type, identifier=validated_identifier, attack_technique=validated_technique,
            mapping_source="source_provided", mapping_confidence="high", human_review_required=False,
            validation_status="confirmed", rationale=None,
        )

    if identifier_type == "cwe" and validated_identifier in _LOCAL_CWE_TO_ATTACK:
        technique = _LOCAL_CWE_TO_ATTACK[validated_identifier]
        return _build_record(
            identifier_type=identifier_type, identifier=validated_identifier, attack_technique=technique,
            mapping_source="local_dataset", mapping_confidence="medium", human_review_required=True,
            validation_status="candidate_pending_review",
            rationale="General category association from this project's fixed local dataset -- not incident-specific.",
        )

    return _build_record(
        identifier_type=identifier_type, identifier=validated_identifier, attack_technique=None,
        mapping_source=None, mapping_confidence=None, human_review_required=False,
        validation_status="unmapped", rationale=None,
    )


def record_llm_proposed_enrichment(*, identifier_type: Any, identifier: Any, attack_technique: Any, rationale: Any) -> dict[str, Any]:
    """Deterministically wrap an already-produced LLM-proposed
    CWE/CVE -> ATT&CK mapping as an explicit, low-confidence,
    human-review-required candidate. Performs no I/O of any kind, and
    never calls an LLM itself -- `attack_technique`/`rationale` must
    already exist when this function is called.

    All parameters are required and keyword-only. `identifier_type` must
    be one of `IDENTIFIER_TYPES`. `identifier`/`attack_technique`/
    `rationale` must each be non-blank strings.

    Always returns `mapping_source: "llm_proposed"`, `mapping_confidence:
    "low"`, `human_review_required: True`, `validation_status:
    "candidate_pending_review"` -- unconditionally, regardless of how
    confident `rationale` reads. This module never promotes an
    LLM-proposed mapping to `"confirmed"`; only a separate, explicit
    human review action (outside this module) could ever do that.

    Raises `SecurityEnrichmentError` for any structurally invalid
    parameter.
    """
    if identifier_type not in IDENTIFIER_TYPES:
        _raise("INVALID_IDENTIFIER_TYPE", "identifier_type must be one of IDENTIFIER_TYPES")
    validated_identifier = _require_nonblank_string(identifier, "INVALID_IDENTIFIER", "identifier")
    validated_technique = _require_nonblank_string(attack_technique, "INVALID_TECHNIQUE", "attack_technique")
    validated_rationale = _require_nonblank_string(rationale, "INVALID_RATIONALE", "rationale")

    return _build_record(
        identifier_type=identifier_type, identifier=validated_identifier, attack_technique=validated_technique,
        mapping_source="llm_proposed", mapping_confidence="low", human_review_required=True,
        validation_status="candidate_pending_review", rationale=validated_rationale,
    )
