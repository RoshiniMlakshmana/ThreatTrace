"""Pure, deterministic Validated Security Experience Memory (Block 15D,
checkpoint A).

This module answers exactly one question: *given an already-existing
Block 15C security handoff case, its matching Block 15B prioritization
result, and an already-produced Block 15C.5 Governor result, what
compact, structured "security experience" record can be considered for
future advisory reuse -- and under what conditions is it actually safe
to reuse?*

## Governance gates admission -- this is the whole point of this module

An unsafe or out-of-policy result must never become trusted, reusable
memory. `create_security_experience` never infers admission from free
text, never trusts a caller-asserted status, and never admits an
experience as `"validated"`/`reusable: True` unless the supplied
Governor result's own `decision` is not `"block"`/`"freeze"` *and*
every other structural validation condition documented on
`create_security_experience` is independently satisfied. A Governor
`"block"` or `"freeze"` decision always forces `"rejected"`/
`reusable: False`, unconditionally, regardless of anything else in the
supplied case.

## Source finding truth is never rewritten

`source_finding_status` is read once from the supplied case's own
`finding_reference.finding_status` and never altered. A `"candidate"`
source finding remains `"candidate"` in every experience record derived
from it, even when that experience's own `experience_status` becomes
`"validated"` -- the two are deliberately independent judgments. This
module never calls back into, imports, or rewrites anything belonging
to `core.security_handoff` or `core.context_prioritization`; `case` and
`prioritization` are consumed as plain, duck-typed, caller-supplied
mappings, validated only against the minimal fields this module itself
reads.

## Memory state is pure, caller-owned, and in-memory only

`memory` is always a plain `{"memory_version": "1", "entries": [...]}`
mapping. This module never touches a filesystem, a database, Supabase,
a vector store, or any embedding/LLM service of any kind, and retains
no state between calls -- every public function is a single pure
computation over its own arguments, returning a new object rather than
mutating any input.

## Structured search is not semantic similarity

`search_security_experiences` performs deterministic, exact-match
structured comparison over a fixed set of query fields only. It never
uses embeddings, a vector index, or an LLM, and its
`structured_match_score` is never described as, or intended to
approximate, a probability or a semantic-similarity score. Memory
retrieval is advisory only -- it never deploys, remediates, executes,
approves, or validates a source finding.

`SecurityExperienceMemoryError`, `create_security_experience`,
`add_security_experience`, and `search_security_experiences` are this
module's only public symbols (plus its fixed vocabulary constants).
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

MEMORY_VERSION = "1"
EXPERIENCE_VERSION = "1"
SEARCH_VERSION = "1"

# ---------------------------------------------------------------------------
# Closed vocabularies. Private copies matching the shapes of
# core.security_handoff / core.context_prioritization / core.security_governor
# output values -- none of those modules is ever imported here.
# ---------------------------------------------------------------------------

FINDING_STATUSES = frozenset({"observation", "candidate", "validated"})
TECHNICAL_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
OPERATIONAL_PRIORITIES = frozenset({"low", "medium", "high", "critical"})
STAGES = frozenset({
    "threat_intel_review", "threat_hunt", "detection_engineering",
    "red_validation", "purple_remediation", "human_review",
})
APPROVAL_STATES = frozenset({"not_required", "pending", "approved", "rejected"})
ENVIRONMENTS = frozenset({"production", "staging", "development", "test", "sandbox"})
ASSET_CRITICALITIES = frozenset({"low", "medium", "high", "critical"})
EXPOSURES = frozenset({"internal", "restricted", "partner", "internet_facing"})
THREAT_ACTIVITIES = frozenset({"unknown", "none_observed", "emerging", "active"})

GOVERNOR_DECISIONS = frozenset({"allow", "warn", "require_review", "block", "freeze"})
_GOVERNOR_REJECTING_DECISIONS = frozenset({"block", "freeze"})

EXPERIENCE_STATUSES = frozenset({"candidate", "validated", "rejected"})

_EVIDENCE_REFERENCE_TYPES = frozenset({"finding", "evidence_digest"})

_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_CASE_ID_PATTERN = re.compile(r"^SH-[0-9a-f]{16}$")
_MEMORY_ID_PATTERN = re.compile(r"^SEM-[0-9a-f]{16}$")
_ID_HEX_LENGTH = 16

_ORGANIZATION_CONTEXT_FIELDS = ("environment", "asset_criticality", "exposure", "threat_activity")

_EXPERIENCE_REQUIRED_FIELDS = (
    "experience_version",
    "memory_id",
    "case_id",
    "finding_id",
    "vulnerability_class",
    "technical_severity",
    "source_finding_status",
    "operational_priority",
    "organization_context_summary",
    "stage_pattern",
    "red_validation_summary",
    "approval_state",
    "governor_decision",
    "governor_reason_codes",
    "experience_status",
    "reusable",
    "evidence_references",
    "human_review_required",
    "execution_performed",
)

_MEMORY_REQUIRED_FIELDS = ("memory_version", "entries")

# Query fields search_security_experiences accepts. reusable_only is a
# filter, never a scoring dimension.
_QUERY_SCORING_FIELDS = frozenset({
    "technical_severity", "operational_priority", "environment",
    "asset_criticality", "exposure", "threat_activity", "source_finding_status",
})
_QUERY_FIELDS = _QUERY_SCORING_FIELDS | {"reusable_only"}

_QUERY_FIELD_VOCAB: Mapping[str, frozenset[str]] = {
    "technical_severity": TECHNICAL_SEVERITIES,
    "operational_priority": OPERATIONAL_PRIORITIES,
    "environment": ENVIRONMENTS,
    "asset_criticality": ASSET_CRITICALITIES,
    "exposure": EXPOSURES,
    "threat_activity": THREAT_ACTIVITIES,
    "source_finding_status": FINDING_STATUSES,
}


class SecurityExperienceMemoryError(ValueError):
    """Raised when a supplied `case`, `prioritization`, `governor_result`,
    `memory`, `experience`, or `query` input is structurally invalid, or
    when `case`/`prioritization` disagree on `finding_id`, or when
    `add_security_experience` is given an experience whose `memory_id`
    already exists in `memory`.

    Every message begins with one of a fixed set of stable codes:
    `INVALID_CASE`, `INVALID_PRIORITIZATION`, `INVALID_GOVERNOR_RESULT`,
    `FINDING_ID_MISMATCH`, `INVALID_MEMORY`, `INVALID_EXPERIENCE`,
    `DUPLICATE_EXPERIENCE`, `INVALID_QUERY`.

    Never raised because an experience is admitted as `"candidate"` or
    `"rejected"`, because a source finding is a `"candidate"`, or
    because a Governor decision is `"block"`/`"freeze"` -- every one of
    those is a normal, successfully represented result, never an error
    condition.
    """


def _raise(code: str, detail: str) -> None:
    raise SecurityExperienceMemoryError(f"{code}: {detail}")


def _in_vocab(value: Any, vocabulary: frozenset[str]) -> bool:
    return isinstance(value, str) and value in vocabulary


# ---------------------------------------------------------------------------
# Deterministic canonical-JSON content-correlation digesting -- a private,
# independently owned copy, deliberately never imported from
# core.security_handoff or any other module.
# ---------------------------------------------------------------------------


class _CanonicalizationError(Exception):
    """Internal-only signal that a value could not be canonicalized."""


def _canonicalize(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return value
    if value is None:
        return None
    if isinstance(value, Mapping):
        return {key: _canonicalize(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    raise _CanonicalizationError(f"unsupported value type: {type(value).__name__}")


def _canonical_digest_hex(value: Any, length: int) -> str:
    canonical = _canonicalize(value)
    text = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


def _compute_memory_id(payload: Mapping[str, Any]) -> str:
    return "SEM-" + _canonical_digest_hex(payload, _ID_HEX_LENGTH)


# ---------------------------------------------------------------------------
# Minimal, locally-owned structural contracts for the caller-supplied
# case/prioritization/governor_result inputs. Only the fields this module
# itself reads are validated -- the producing modules are never imported,
# and their own internal ID/consistency recomputation is never redone here.
# ---------------------------------------------------------------------------


def _validate_case_input(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _raise("INVALID_CASE", "case must be a mapping")

    case_id = value.get("case_id")
    if not isinstance(case_id, str) or not _CASE_ID_PATTERN.fullmatch(case_id):
        _raise("INVALID_CASE", "case_id is malformed")

    finding_reference = value.get("finding_reference")
    if not isinstance(finding_reference, Mapping):
        _raise("INVALID_CASE", "finding_reference must be a mapping")

    finding_id = finding_reference.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip():
        _raise("INVALID_CASE", "finding_reference.finding_id must be a non-blank string")

    if not _in_vocab(finding_reference.get("technical_severity"), TECHNICAL_SEVERITIES):
        _raise("INVALID_CASE", "finding_reference.technical_severity must be a recognized value")
    if not _in_vocab(finding_reference.get("finding_status"), FINDING_STATUSES):
        _raise("INVALID_CASE", "finding_reference.finding_status must be a recognized value")

    evidence_digests = finding_reference.get("evidence_digests")
    if not isinstance(evidence_digests, list) or len(evidence_digests) == 0:
        _raise("INVALID_CASE", "finding_reference.evidence_digests must be a non-empty list")
    for digest in evidence_digests:
        if not isinstance(digest, str) or not _DIGEST_PATTERN.fullmatch(digest):
            _raise("INVALID_CASE", "finding_reference.evidence_digests contains a malformed digest")

    if not _in_vocab(value.get("current_stage"), STAGES):
        _raise("INVALID_CASE", "current_stage must be a recognized stage")
    if not _in_vocab(value.get("approval_state"), APPROVAL_STATES):
        _raise("INVALID_CASE", "approval_state must be a recognized value")

    stage_results = value.get("stage_results")
    if not isinstance(stage_results, list):
        _raise("INVALID_CASE", "stage_results must be a list")

    stage_pattern: list[dict[str, str]] = []
    red_validation_summary: dict[str, str] | None = None
    for raw_result in stage_results:
        if not isinstance(raw_result, Mapping):
            _raise("INVALID_CASE", "each stage result must be a mapping")
        stage = raw_result.get("stage")
        role = raw_result.get("role")
        result_type = raw_result.get("result_type")
        outcome = raw_result.get("outcome")
        for field_name, field_value in (
            ("stage", stage), ("role", role), ("result_type", result_type), ("outcome", outcome),
        ):
            if not isinstance(field_value, str) or not field_value.strip():
                _raise("INVALID_CASE", f"stage result {field_name!r} must be a non-blank string")
        entry = {"stage": stage, "role": role, "result_type": result_type, "outcome": outcome}
        stage_pattern.append(entry)
        if stage == "red_validation":
            red_validation_summary = {"result_type": result_type, "outcome": outcome}

    if value.get("human_review_required") is not True:
        _raise("INVALID_CASE", "human_review_required must be true")
    if value.get("execution_performed") is not False:
        _raise("INVALID_CASE", "execution_performed must be false")

    return {
        "case_id": case_id,
        "finding_id": finding_id,
        "technical_severity": finding_reference["technical_severity"],
        "finding_status": finding_reference["finding_status"],
        "evidence_digests": list(evidence_digests),
        "current_stage": value["current_stage"],
        "approval_state": value["approval_state"],
        "stage_pattern": stage_pattern,
        "red_validation_summary": red_validation_summary,
    }


def _validate_prioritization_input(value: Any, *, expected_finding_id: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _raise("INVALID_PRIORITIZATION", "prioritization must be a mapping")

    finding_id = value.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip():
        _raise("INVALID_PRIORITIZATION", "finding_id must be a non-blank string")
    if finding_id != expected_finding_id:
        _raise("FINDING_ID_MISMATCH", "case and prioritization reference different finding_id values")

    if not _in_vocab(value.get("operational_priority"), OPERATIONAL_PRIORITIES):
        _raise("INVALID_PRIORITIZATION", "operational_priority must be a recognized value")

    context = value.get("context")
    if not isinstance(context, Mapping):
        _raise("INVALID_PRIORITIZATION", "context must be a mapping")

    if not _in_vocab(context.get("environment"), ENVIRONMENTS):
        _raise("INVALID_PRIORITIZATION", "context.environment must be a recognized value")
    if not _in_vocab(context.get("asset_criticality"), ASSET_CRITICALITIES):
        _raise("INVALID_PRIORITIZATION", "context.asset_criticality must be a recognized value")
    if not _in_vocab(context.get("exposure"), EXPOSURES):
        _raise("INVALID_PRIORITIZATION", "context.exposure must be a recognized value")
    if not _in_vocab(context.get("threat_activity"), THREAT_ACTIVITIES):
        _raise("INVALID_PRIORITIZATION", "context.threat_activity must be a recognized value")

    return {
        "operational_priority": value["operational_priority"],
        "organization_context_summary": {
            "environment": context["environment"],
            "asset_criticality": context["asset_criticality"],
            "exposure": context["exposure"],
            "threat_activity": context["threat_activity"],
        },
    }


def _validate_governor_result_input(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _raise("INVALID_GOVERNOR_RESULT", "governor_result must be a mapping")

    if not _in_vocab(value.get("decision"), GOVERNOR_DECISIONS):
        _raise("INVALID_GOVERNOR_RESULT", "decision must be a recognized value")

    reason_codes = value.get("reason_codes")
    if not isinstance(reason_codes, list) or not all(isinstance(code, str) for code in reason_codes):
        _raise("INVALID_GOVERNOR_RESULT", "reason_codes must be a list of strings")

    if value.get("observable_only") is not True:
        _raise("INVALID_GOVERNOR_RESULT", "observable_only must be true")
    if value.get("execution_performed") is not False:
        _raise("INVALID_GOVERNOR_RESULT", "execution_performed must be false")

    return {
        "decision": value["decision"],
        "reason_codes": list(reason_codes),
    }


# ---------------------------------------------------------------------------
# Public API -- create_security_experience.
# ---------------------------------------------------------------------------


def create_security_experience(*, case: Any, prioritization: Any, governor_result: Any) -> dict[str, Any]:
    """Deterministically build one candidate/validated/rejected security
    experience record from an already-existing Block 15C security
    handoff case, its matching Block 15B prioritization result, and an
    already-produced Block 15C.5 Governor result. Performs no I/O of
    any kind.

    All three parameters are required and keyword-only. `case` must be
    a mapping shaped at minimum like `core.security_handoff`'s own case
    contract; this function never imports that module and never
    recomputes its content-correlation IDs. `prioritization` must be a
    mapping shaped at minimum like `core.context_prioritization.
    prioritize_finding`'s own return value, and must agree with `case`
    on `finding_id` or this function raises `SecurityExperienceMemoryError`
    with `FINDING_ID_MISMATCH`. `governor_result` must be a mapping
    shaped at minimum like `core.security_governor.
    evaluate_security_governor_event`'s own return value.

    None of the three inputs is ever mutated. `vulnerability_class` is
    always `None` in the returned record: neither the security handoff
    case contract nor the prioritization contract this function reads
    ever carries that field, so it is never guessed or inferred.
    `source_finding_status` is read once from `case['finding_reference']
    ['finding_status']` and never altered by this function.

    `experience_status`/`reusable` are computed as follows, and never
    inferred from any free-text field:

    - `governor_result['decision']` is `"block"` or `"freeze"` -->
      always `experience_status: "rejected"`, `reusable: False`,
      regardless of anything else.
    - Otherwise, when every one of the following holds --
      `case['current_stage'] == "human_review"`,
      `case['approval_state'] == "approved"`,
      at least one stage result is present,
      at least one evidence digest is present -- then
      `experience_status: "validated"`, `reusable: True`. This applies
      identically whether `governor_result['decision']` is `"allow"`,
      `"warn"`, or `"require_review"`; a `"warn"` decision's own reason
      codes are still preserved in the returned record's
      `governor_reason_codes`.
    - Otherwise, `experience_status: "candidate"`, `reusable: False`.

    A `case['finding_reference']['finding_status']` of `"candidate"`
    never by itself prevents `experience_status` from becoming
    `"validated"` -- the two are independent judgments; only the four
    conditions above are ever consulted.

    Returns a new dict containing exactly the nineteen fields documented
    in the module docstring's entry contract: `experience_version`
    (always `"1"`), `memory_id` (a content-correlation id derived from
    every other field below, never authentication), `case_id`,
    `finding_id`, `vulnerability_class` (always `None`),
    `technical_severity`, `source_finding_status`, `operational_priority`,
    `organization_context_summary`, `stage_pattern`, `red_validation_summary`
    (a `{result_type, outcome}` mapping if a `red_validation` stage
    result is present in `case`, else `None`), `approval_state`,
    `governor_decision`, `governor_reason_codes`, `experience_status`,
    `reusable`, `evidence_references` (a compact list of
    `{reference_type, reference}` entries derived from `case`'s own
    `finding_id`/`evidence_digests` -- never full remote response
    content), `human_review_required` (always `True`),
    `execution_performed` (always `False`).

    Raises `SecurityExperienceMemoryError` for any structurally invalid
    `case`/`prioritization`/`governor_result`, or for a finding_id
    mismatch between `case` and `prioritization`. Never raises because
    the computed `experience_status` is `"candidate"`/`"rejected"`, or
    because the source finding is a `"candidate"`/`"observation"` --
    every one of those is a normal, successfully computed result.
    """
    case_fields = _validate_case_input(case)
    prioritization_fields = _validate_prioritization_input(prioritization, expected_finding_id=case_fields["finding_id"])
    governor_fields = _validate_governor_result_input(governor_result)

    meets_validation_conditions = (
        governor_fields["decision"] not in _GOVERNOR_REJECTING_DECISIONS
        and case_fields["current_stage"] == "human_review"
        and case_fields["approval_state"] == "approved"
        and len(case_fields["stage_pattern"]) >= 1
        and len(case_fields["evidence_digests"]) >= 1
    )

    if governor_fields["decision"] in _GOVERNOR_REJECTING_DECISIONS:
        experience_status = "rejected"
        reusable = False
    elif meets_validation_conditions:
        experience_status = "validated"
        reusable = True
    else:
        experience_status = "candidate"
        reusable = False

    evidence_references = [{"reference_type": "finding", "reference": case_fields["finding_id"]}]
    for digest in case_fields["evidence_digests"]:
        evidence_references.append({"reference_type": "evidence_digest", "reference": digest})

    payload = {
        "case_id": case_fields["case_id"],
        "finding_id": case_fields["finding_id"],
        "vulnerability_class": None,
        "technical_severity": case_fields["technical_severity"],
        "source_finding_status": case_fields["finding_status"],
        "operational_priority": prioritization_fields["operational_priority"],
        "organization_context_summary": prioritization_fields["organization_context_summary"],
        "stage_pattern": case_fields["stage_pattern"],
        "red_validation_summary": case_fields["red_validation_summary"],
        "approval_state": case_fields["approval_state"],
        "governor_decision": governor_fields["decision"],
        "governor_reason_codes": governor_fields["reason_codes"],
        "experience_status": experience_status,
        "reusable": reusable,
        "evidence_references": evidence_references,
    }

    memory_id = _compute_memory_id(payload)

    return {
        "experience_version": EXPERIENCE_VERSION,
        "memory_id": memory_id,
        **payload,
        "human_review_required": True,
        "execution_performed": False,
    }


# ---------------------------------------------------------------------------
# Structural re-validation of an already-produced experience record --
# mirrors create_security_experience's own contract and recomputes
# memory_id for integrity, exactly like core.security_handoff recomputes
# stage_result_id on every append.
# ---------------------------------------------------------------------------


def _validate_experience_shape(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_EXPERIENCE_REQUIRED_FIELDS):
        _raise("INVALID_EXPERIENCE", "experience must contain exactly the nineteen required fields")

    if value.get("experience_version") != EXPERIENCE_VERSION:
        _raise("INVALID_EXPERIENCE", "experience_version must be '1'")

    memory_id = value.get("memory_id")
    if not isinstance(memory_id, str) or not _MEMORY_ID_PATTERN.fullmatch(memory_id):
        _raise("INVALID_EXPERIENCE", "memory_id is malformed")

    case_id = value.get("case_id")
    if not isinstance(case_id, str) or not _CASE_ID_PATTERN.fullmatch(case_id):
        _raise("INVALID_EXPERIENCE", "case_id is malformed")

    finding_id = value.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip():
        _raise("INVALID_EXPERIENCE", "finding_id must be a non-blank string")

    vulnerability_class = value.get("vulnerability_class")
    if vulnerability_class is not None and not isinstance(vulnerability_class, str):
        _raise("INVALID_EXPERIENCE", "vulnerability_class must be null or a string")

    if not _in_vocab(value.get("technical_severity"), TECHNICAL_SEVERITIES):
        _raise("INVALID_EXPERIENCE", "technical_severity must be a recognized value")
    if not _in_vocab(value.get("source_finding_status"), FINDING_STATUSES):
        _raise("INVALID_EXPERIENCE", "source_finding_status must be a recognized value")
    if not _in_vocab(value.get("operational_priority"), OPERATIONAL_PRIORITIES):
        _raise("INVALID_EXPERIENCE", "operational_priority must be a recognized value")

    context_summary = value.get("organization_context_summary")
    if not isinstance(context_summary, Mapping) or set(context_summary) != set(_ORGANIZATION_CONTEXT_FIELDS):
        _raise("INVALID_EXPERIENCE", "organization_context_summary is malformed")
    for field in _ORGANIZATION_CONTEXT_FIELDS:
        if not _in_vocab(context_summary.get(field), _QUERY_FIELD_VOCAB[field]):
            _raise("INVALID_EXPERIENCE", f"organization_context_summary[{field!r}] must be a recognized value")

    stage_pattern = value.get("stage_pattern")
    if not isinstance(stage_pattern, list):
        _raise("INVALID_EXPERIENCE", "stage_pattern must be a list")
    for entry in stage_pattern:
        if not isinstance(entry, Mapping) or set(entry) != {"stage", "role", "result_type", "outcome"}:
            _raise("INVALID_EXPERIENCE", "each stage_pattern entry is malformed")

    red_validation_summary = value.get("red_validation_summary")
    if red_validation_summary is not None:
        if not isinstance(red_validation_summary, Mapping) or set(red_validation_summary) != {
            "result_type", "outcome",
        }:
            _raise("INVALID_EXPERIENCE", "red_validation_summary is malformed")

    if not _in_vocab(value.get("approval_state"), APPROVAL_STATES):
        _raise("INVALID_EXPERIENCE", "approval_state must be a recognized value")
    if not _in_vocab(value.get("governor_decision"), GOVERNOR_DECISIONS):
        _raise("INVALID_EXPERIENCE", "governor_decision must be a recognized value")

    governor_reason_codes = value.get("governor_reason_codes")
    if not isinstance(governor_reason_codes, list) or not all(
        isinstance(code, str) for code in governor_reason_codes
    ):
        _raise("INVALID_EXPERIENCE", "governor_reason_codes must be a list of strings")

    if not _in_vocab(value.get("experience_status"), EXPERIENCE_STATUSES):
        _raise("INVALID_EXPERIENCE", "experience_status must be a recognized value")

    reusable = value.get("reusable")
    if reusable not in (True, False):
        _raise("INVALID_EXPERIENCE", "reusable must be a bool")

    if value.get("experience_status") in ("candidate", "rejected") and reusable is not False:
        _raise("INVALID_EXPERIENCE", "reusable must be false unless experience_status is 'validated'")

    evidence_references = value.get("evidence_references")
    if not isinstance(evidence_references, list) or len(evidence_references) == 0:
        _raise("INVALID_EXPERIENCE", "evidence_references must be a non-empty list")
    for reference in evidence_references:
        if not isinstance(reference, Mapping) or set(reference) != {"reference_type", "reference"}:
            _raise("INVALID_EXPERIENCE", "each evidence reference is malformed")
        if not _in_vocab(reference.get("reference_type"), _EVIDENCE_REFERENCE_TYPES):
            _raise("INVALID_EXPERIENCE", "evidence reference reference_type must be recognized")
        if not isinstance(reference.get("reference"), str) or not reference["reference"].strip():
            _raise("INVALID_EXPERIENCE", "evidence reference reference must be a non-blank string")

    if value.get("human_review_required") is not True:
        _raise("INVALID_EXPERIENCE", "human_review_required must be true")
    if value.get("execution_performed") is not False:
        _raise("INVALID_EXPERIENCE", "execution_performed must be false")

    payload = {
        "case_id": case_id,
        "finding_id": finding_id,
        "vulnerability_class": vulnerability_class,
        "technical_severity": value["technical_severity"],
        "source_finding_status": value["source_finding_status"],
        "operational_priority": value["operational_priority"],
        "organization_context_summary": dict(context_summary),
        "stage_pattern": [dict(entry) for entry in stage_pattern],
        "red_validation_summary": dict(red_validation_summary) if red_validation_summary is not None else None,
        "approval_state": value["approval_state"],
        "governor_decision": value["governor_decision"],
        "governor_reason_codes": list(governor_reason_codes),
        "experience_status": value["experience_status"],
        "reusable": reusable,
        "evidence_references": [dict(reference) for reference in evidence_references],
    }

    if memory_id != _compute_memory_id(payload):
        _raise("INVALID_EXPERIENCE", "memory_id does not match its own content")

    return {
        "experience_version": EXPERIENCE_VERSION,
        "memory_id": memory_id,
        **payload,
        "human_review_required": True,
        "execution_performed": False,
    }


def _validate_memory_input(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_MEMORY_REQUIRED_FIELDS):
        _raise("INVALID_MEMORY", "memory must contain exactly memory_version/entries")
    if value.get("memory_version") != MEMORY_VERSION:
        _raise("INVALID_MEMORY", "memory_version must be '1'")

    entries = value.get("entries")
    if not isinstance(entries, list):
        _raise("INVALID_MEMORY", "entries must be a list")

    validated_entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for raw_entry in entries:
        entry = _validate_experience_shape(raw_entry)
        if entry["memory_id"] in seen_ids:
            _raise("INVALID_MEMORY", "duplicate memory_id within memory")
        seen_ids.add(entry["memory_id"])
        validated_entries.append(entry)

    return {"memory_version": MEMORY_VERSION, "entries": validated_entries}


# ---------------------------------------------------------------------------
# Public API -- add_security_experience.
# ---------------------------------------------------------------------------


def add_security_experience(*, memory: Any, experience: Any) -> dict[str, Any]:
    """Deterministically append exactly one already-created security
    experience record to an already-existing memory state, returning a
    new memory object. Performs no I/O of any kind -- there is no
    filesystem, database, or vector-store write anywhere in this
    function.

    Both parameters are required and keyword-only. `memory` must be a
    mapping shaped like this module's own `{"memory_version": "1",
    "entries": [...]}` contract -- it is fully re-validated on every
    call, never trusted blindly. `experience` must be a mapping shaped
    like `create_security_experience`'s own return value; its
    `memory_id` is recomputed from its own content and compared to the
    supplied value, exactly like `core.security_handoff` recomputes
    `stage_result_id` on every append.

    Neither `memory` nor `experience` (nor any nested value within
    either) is ever mutated -- this function returns a new dict whose
    `entries` list is the validated prior entries plus one newly
    appended, freshly-copied experience. Every prior entry is preserved
    exactly as it was.

    Raises `SecurityExperienceMemoryError` for a malformed `memory`, a
    malformed `experience`, or an `experience['memory_id']` that
    already exists in `memory['entries']` (`DUPLICATE_EXPERIENCE`).
    Never raises because the appended experience's `experience_status`
    is `"candidate"`/`"rejected"`, or because `reusable` is `False` --
    every one of those is a normal, successfully appended result.
    """
    validated_memory = _validate_memory_input(memory)
    validated_experience = _validate_experience_shape(experience)

    existing_ids = {entry["memory_id"] for entry in validated_memory["entries"]}
    if validated_experience["memory_id"] in existing_ids:
        _raise("DUPLICATE_EXPERIENCE", "experience['memory_id'] already exists in memory")

    new_entries = [copy.deepcopy(entry) for entry in validated_memory["entries"]]
    new_entries.append(copy.deepcopy(validated_experience))

    return {"memory_version": MEMORY_VERSION, "entries": new_entries}


# ---------------------------------------------------------------------------
# Public API -- search_security_experiences.
# ---------------------------------------------------------------------------


def _validate_query_input(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _raise("INVALID_QUERY", "query must be a mapping")
    if not set(value).issubset(_QUERY_FIELDS):
        _raise("INVALID_QUERY", "query contains an unrecognized field")

    validated: dict[str, Any] = {}
    for field in _QUERY_SCORING_FIELDS:
        if field in value:
            if not _in_vocab(value[field], _QUERY_FIELD_VOCAB[field]):
                _raise("INVALID_QUERY", f"query[{field!r}] must be a recognized value")
            validated[field] = value[field]

    if "reusable_only" in value:
        if value["reusable_only"] not in (True, False):
            _raise("INVALID_QUERY", "query['reusable_only'] must be a bool")
        validated["reusable_only"] = value["reusable_only"]

    return validated


def _entry_value_for_field(entry: Mapping[str, Any], field: str) -> Any:
    if field in ("technical_severity", "operational_priority", "source_finding_status"):
        return entry[field]
    return entry["organization_context_summary"][field]


def search_security_experiences(*, memory: Any, query: Any) -> dict[str, Any]:
    """Deterministically, structurally search an already-existing memory
    state for entries matching a caller-supplied query. Performs no I/O
    of any kind, and never uses embeddings, a vector index, or an
    LLM/model of any kind -- every comparison is an exact match against
    a fixed, closed-vocabulary field.

    Both parameters are required and keyword-only. `memory` must be a
    mapping shaped like this module's own memory contract; it is fully
    re-validated on every call. `query` must be a mapping whose keys
    are a subset of `technical_severity`/`operational_priority`/
    `environment`/`asset_criticality`/`exposure`/`threat_activity`/
    `source_finding_status`/`reusable_only`, each a value from its own
    fixed closed vocabulary (`reusable_only` a bool). An empty `query`
    is valid and applies no filter or scoring criteria.

    When `query['reusable_only']` is `True`, every entry with
    `reusable != True` (including every `"rejected"` and every
    non-reusable `"candidate"` entry) is excluded before scoring --
    memory retrieval never surfaces an unsafe or unvalidated experience
    as if it were reusable.

    For each remaining entry, `structured_match_score` is the count of
    the supplied scoring fields (excluding `reusable_only`) whose value
    exactly equals the entry's corresponding value, divided by the
    number of scoring fields supplied (0.0 when none were supplied).
    This is a deterministic structural overlap count only -- it is
    never described as, and never intended to approximate, a semantic
    similarity score or a probability.

    Returns a new dict containing exactly `search_version` (always
    `"1"`), `query` (the validated query, echoed back), `results` (a
    list of `{memory_id, structured_match_score, matched_components,
    entry}` mappings, sorted by descending `structured_match_score` and
    then ascending `memory_id` for a fully deterministic order),
    `result_count`, `human_review_required` (always `True`),
    `execution_performed` (always `False`). This function never
    deploys, remediates, executes, approves, or validates a source
    finding -- it only returns advisory, already-existing memory
    entries.

    Neither `memory` nor `query` is ever mutated.

    Raises `SecurityExperienceMemoryError` for a malformed `memory` or
    an invalid `query` (an unrecognized field or an out-of-vocabulary
    value). Never raises because zero entries match -- an empty
    `results` list is a normal, successfully computed result.
    """
    validated_memory = _validate_memory_input(memory)
    validated_query = _validate_query_input(query)

    scoring_fields = [field for field in _QUERY_SCORING_FIELDS if field in validated_query]
    # Fixed, stable iteration order for matched_components, independent of
    # frozenset/dict iteration order.
    scoring_fields = [field for field in (
        "technical_severity", "operational_priority", "environment",
        "asset_criticality", "exposure", "threat_activity", "source_finding_status",
    ) if field in scoring_fields]

    entries = validated_memory["entries"]
    if validated_query.get("reusable_only") is True:
        entries = [entry for entry in entries if entry["reusable"] is True]

    results: list[dict[str, Any]] = []
    for entry in entries:
        matched_components = [
            field for field in scoring_fields
            if _entry_value_for_field(entry, field) == validated_query[field]
        ]
        score = len(matched_components) / len(scoring_fields) if scoring_fields else 0.0
        results.append({
            "memory_id": entry["memory_id"],
            "structured_match_score": score,
            "matched_components": matched_components,
            "entry": copy.deepcopy(entry),
        })

    results.sort(key=lambda result: (-result["structured_match_score"], result["memory_id"]))

    return {
        "search_version": SEARCH_VERSION,
        "query": dict(validated_query),
        "results": results,
        "result_count": len(results),
        "human_review_required": True,
        "execution_performed": False,
    }
