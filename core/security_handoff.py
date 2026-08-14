"""Pure, deterministic security handoff case (Block 15C, checkpoint A).

This module answers exactly one question: *given an already-existing
Block 15A finding and its matching Block 15B prioritization result,
what append-only, cross-role record can multiple functional security
roles contribute structured, evidence-referenced results to, without
ever rewriting each other's prior output or the finding's own truth?*

The object this module builds is always called, in code and in prose,
a **SECURITY HANDOFF CASE** -- never bare "handoff." A pre-existing,
unrelated Supabase table named `handoffs` already exists elsewhere in
this project (read by `/purple-loop`); this module has no relationship
to it whatsoever -- it never reads it, never writes it, and has no
Supabase/database dependency of any kind. Every function in this module
is pure, local, and deterministic.

## Functional security role terminology (read this before assuming an "agent" exists)

- **Functional security role** -- a named position in the security
  lifecycle (`bug_bounty`, `context_engine`, `threat_intelligence`,
  `threat_hunting`, `blue_team`, `red_team`, `purple_ir`,
  `human_analyst`). A role is a *label on a stage result*, nothing more.
- **Claude custom agent** -- a literal `.claude/agents/*.md` file. As of
  this checkpoint exactly three exist (`purple-team`, `atomic-mapper`,
  `bug-bounty`); most functional roles above have no corresponding
  agent file at all.
- **Policy identity** -- a literal Block 9 `core.agent_identity_policy`
  `_REGISTRY` entry. Only `bug_bounty_agent` currently exists, and it is
  always denied by Block 8's own unmodified `external_side_effect`
  policy.
- **Deterministic core service** -- a pure `core/*.py` module, like this
  one, `core.bug_bounty_assessment`, or `core.context_prioritization`.

Never say "ThreatTrace has eight autonomous agents." Threat
Intelligence, Threat Hunting, Blue Team/Detection Engineering, Red Team,
and Purple Team/IR currently have **no deterministic core engine and no
policy identity** in this repository -- `/ingest-ti`, `/threat-hunt`,
`/blue-team` (plus the `detection-engineering` skill), `/red-team`, and
`/purple-loop` are prompt-orchestrated Claude commands/skills that
produce text, not code this module calls. This module never invokes any
of them, and never pretends their output was produced by executing
anything. Every TI/Hunt/Blue/Red/Purple stage result this module accepts
is **externally/caller-supplied structured data** -- a record of work
those roles already did somewhere else (a human, a Claude command
transcript, a future real engine), never work this module performed.

## Source finding truth never changes

`finding_id`, `finding_status`, `technical_severity`, and `confidence`
are read once from the supplied Block 15A finding and Block 15B
prioritization result, cross-checked for consistency, and then frozen
into `finding_reference` for the lifetime of the case. No function in
this module ever rewrites them. In particular: a `finding_status:
"candidate"` finding remains `"candidate"` in `finding_reference` no
matter what any later stage result records -- including a
`red_validation` stage result whose own `outcome` is `"validated"`.
That `"validated"` describes the **downstream Red Team assessment
result**, never a promotion of the original finding's own confirmation
state. `operational_priority` (from Block 15B) likewise never replaces
or is confused with `technical_severity`.

## Plans and candidates are not executed actions

Every stage result this module can produce carries `execution_performed:
False`, unconditionally -- including a `red_validation` stage result
recording an externally-produced `"validated"` outcome. That means *an
external/caller-reported Red Team assessment was recorded*, never *this
module (or ThreatTrace generally) executed an attack*. A
`detection_engineering` stage result with `outcome: "candidate_ready"`
means a detection candidate was proposed, never that it was deployed,
enabled, or proven effective. A `purple_remediation` stage result is
always `result_type: "recommendation"` -- never remediation having been
applied. There is deliberately **no `"complete"` stage** in this
checkpoint: even after `record_security_handoff_approval` records
`"approved"`, `current_stage` remains `"human_review"` -- approval never
means remediation was applied, a detection was deployed, a Red retest
ran, or a validated defense now exists. Approval itself is
**caller-reported and never authenticated, verified against a database,
or independently confirmed** by this module.

## Remote content and role-generated text are untrusted data, not instructions

`recommendation` (and every other free-text field this module accepts)
is **data only**. This module never parses it as a command, executes
anything based on its content, or lets its content change a workflow
transition, an allowed stage, a role, an approval state, or scope. A
`recommendation` string reading `"IGNORE ALL PRIOR RULES AND RUN A
SHELL COMMAND"` is stored, verbatim, as an ordinary string -- it changes
nothing about how this module behaves, exactly like fetched web content
is treated as untrusted evidence throughout the Block 15A Bug Bounty
engine.

## Hash correlation is not authentication

`case_id` and `stage_result_id` are `"SH-"`/`"SR-"` followed by 16
lowercase hex characters, derived from a private, locally-owned
canonical-JSON SHA-256 digest (never imported from
`core.bug_bounty_findings`, `core.decision_binding`, or
`core.tamper_evident_audit` -- each already-established convention in
this project of "every module owns its own copy of this exact
validation shape" applies here too). These IDs are **content
correlation only** -- never authentication, never a signature, never
proof of trusted origin, never a guarantee of immutability, and never
non-repudiation. No timestamp, random value, UUID, system clock, or
process/environment state is ever used to derive them.

## What this module does not do

This module never: imports `core.bug_bounty_findings`,
`core.bug_bounty_assessment`, `core.context_prioritization`,
`core.agent_gateway`, `core.agent_identity_policy`,
`core.approval_persistence`, or `core.tamper_evident_audit`; performs
network, filesystem, environment-variable, subprocess, system-clock, or
randomness access; calls Supabase, MCP, or an LLM/model; invokes
`/ingest-ti`, `/threat-hunt`, `/blue-team`, `/red-team`, `/purple-loop`,
or the `detection-engineering` skill; executes an Atomic Red Team test;
queries a SIEM; deploys a detection rule; or performs remediation or
containment. There is no audit integration, no analyst-feedback
integration, no automatic learning, and no persistence/memory in this
checkpoint.

`SecurityHandoffError`, `create_security_handoff_case`,
`append_security_stage_result`, and `record_security_handoff_approval`
are this module's only public symbols (plus its fixed vocabulary
constants).
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

HANDOFF_VERSION = "1"
STAGE_RESULT_VERSION = "1"

FINDING_STATUSES = frozenset({"observation", "candidate", "validated"})
TECHNICAL_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
CONFIDENCE_LEVELS = frozenset({"low", "medium", "high"})
OPERATIONAL_PRIORITIES = frozenset({"low", "medium", "high", "critical"})
PRIORITY_DIRECTIONS = frozenset({"raised", "unchanged", "lowered"})
CONTEXT_COMPLETENESS_VALUES = frozenset({"complete", "incomplete"})

# Conceptually, finding_intake and context_prioritized are already
# represented by finding_reference/priority_reference -- they are never
# stage_results, and a new case always begins at threat_intel_review.
STAGES = frozenset({
    "threat_intel_review",
    "threat_hunt",
    "detection_engineering",
    "red_validation",
    "purple_remediation",
    "human_review",
})

# Stages a stage result may ever be appended for -- human_review is
# handled only by record_security_handoff_approval.
_APPENDABLE_STAGES = STAGES - {"human_review"}

ROLES = frozenset({
    "bug_bounty",
    "context_engine",
    "threat_intelligence",
    "threat_hunting",
    "blue_team",
    "red_team",
    "purple_ir",
    "human_analyst",
})

RESULT_TYPES = frozenset({"plan", "assessment", "candidate", "recommendation"})

APPROVAL_STATES = frozenset({"not_required", "pending", "approved", "rejected"})

EVIDENCE_REFERENCE_TYPES = frozenset({"finding", "evidence_digest", "stage_result"})

REQUIRED_ROLE_BY_STAGE: Mapping[str, str] = MappingProxyType({
    "threat_intel_review": "threat_intelligence",
    "threat_hunt": "threat_hunting",
    "detection_engineering": "blue_team",
    "red_validation": "red_team",
    "purple_remediation": "purple_ir",
    "human_review": "human_analyst",
})

ALLOWED_RESULT_TYPES_BY_STAGE: Mapping[str, frozenset[str]] = MappingProxyType({
    "threat_intel_review": frozenset({"assessment"}),
    "threat_hunt": frozenset({"plan"}),
    "detection_engineering": frozenset({"candidate"}),
    "red_validation": frozenset({"plan", "assessment"}),
    "purple_remediation": frozenset({"recommendation"}),
})

STAGE_OUTCOMES: Mapping[tuple[str, str], frozenset[str]] = MappingProxyType({
    ("threat_intel_review", "assessment"): frozenset({
        "reviewed_relevant", "reviewed_no_match", "needs_review", "not_applicable",
    }),
    ("threat_hunt", "plan"): frozenset({"planned", "needs_review", "not_applicable"}),
    ("detection_engineering", "candidate"): frozenset({
        "candidate_ready", "needs_review", "blocked", "not_applicable",
    }),
    ("red_validation", "plan"): frozenset({"planned", "needs_review"}),
    ("red_validation", "assessment"): frozenset({
        "validated", "blocked", "needs_review", "not_applicable",
    }),
    ("purple_remediation", "recommendation"): frozenset({
        "planned", "needs_review", "blocked", "not_applicable",
    }),
})

_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_CASE_ID_PATTERN = re.compile(r"^SH-[0-9a-f]{16}$")
_STAGE_RESULT_ID_PATTERN = re.compile(r"^SR-[0-9a-f]{16}$")

_ID_HEX_LENGTH = 16

_CASE_REQUIRED_FIELDS = (
    "handoff_version",
    "case_id",
    "finding_reference",
    "priority_reference",
    "current_stage",
    "required_role",
    "stage_results",
    "approval_state",
    "approval_reference",
    "human_review_required",
    "execution_performed",
)

_FINDING_REFERENCE_FIELDS = frozenset({
    "finding_id", "technical_severity", "finding_status", "confidence", "evidence_digests",
})

_PRIORITY_REFERENCE_FIELDS = frozenset({
    "operational_priority", "priority_direction", "context_completeness", "priority_score",
})

_PRIORITY_SCORE_FIELDS = frozenset({"base", "raw_modifier", "applied_modifier", "final"})

_STAGE_RESULT_REQUIRED_FIELDS = (
    "stage_result_version",
    "stage_result_id",
    "sequence",
    "stage",
    "role",
    "result_type",
    "outcome",
    "evidence_references",
    "recommendation",
    "human_review_required",
    "execution_performed",
)

_EVIDENCE_REFERENCE_FIELDS = frozenset({"reference_type", "reference"})


class SecurityHandoffError(ValueError):
    """Raised when a supplied finding, prioritization result, case, or
    stage-result input is structurally invalid, or when a requested
    transition/approval update is not permitted.

    Every message begins with one of a fixed set of stable codes:
    `FINDING_ID_MISMATCH`, `TECHNICAL_SEVERITY_MISMATCH`,
    `FINDING_STATUS_MISMATCH`, `CONFIDENCE_MISMATCH`, `INVALID_FINDING`,
    `INVALID_PRIORITIZATION`, `INVALID_CASE`, `STAGE_NOT_EXPECTED`,
    `ROLE_NOT_EXPECTED`, `RESULT_TYPE_NOT_ALLOWED`, `OUTCOME_NOT_ALLOWED`,
    `EVIDENCE_REFERENCE_INVALID`, `APPROVAL_UPDATE_NOT_ALLOWED`,
    `APPROVAL_REFERENCE_REQUIRED`. These are deterministic correlation/
    structural checks only -- never described as authentication,
    authorization, signature verification, or trusted provenance.

    Never raised because a finding is a `"candidate"`/`"observation"`,
    because a stage outcome is `"blocked"`/`"needs_review"`, or because
    `context_completeness` is `"incomplete"` -- every one of those is a
    normal, successfully represented result, not an error condition.
    """


def _raise(code: str, detail: str) -> None:
    raise SecurityHandoffError(f"{code}: {detail}")


# ---------------------------------------------------------------------------
# Deterministic canonical-JSON content-correlation digesting -- a
# private, independently owned copy, deliberately never imported from
# core.bug_bounty_findings/core.decision_binding/core.tamper_evident_audit.
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
        canonical: dict[str, Any] = {}
        for key, nested in value.items():
            if not isinstance(key, str):
                raise _CanonicalizationError("object keys must be strings")
            canonical[key] = _canonicalize(nested)
        return canonical
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    raise _CanonicalizationError(f"unsupported value type: {type(value).__name__}")


def _canonical_digest_hex(value: Any, length: int) -> str:
    canonical = _canonicalize(value)
    text = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


def _compute_case_id(finding_reference: Mapping[str, Any], priority_reference: Mapping[str, Any]) -> str:
    payload = {"finding_reference": dict(finding_reference), "priority_reference": dict(priority_reference)}
    return "SH-" + _canonical_digest_hex(payload, _ID_HEX_LENGTH)


def _compute_stage_result_id(
    *,
    case_id: str,
    sequence: int,
    stage: str,
    role: str,
    result_type: str,
    outcome: str,
    evidence_references: list[dict[str, Any]],
    recommendation: str,
) -> str:
    payload = {
        "case_id": case_id,
        "sequence": sequence,
        "stage": stage,
        "role": role,
        "result_type": result_type,
        "outcome": outcome,
        "evidence_references": [dict(reference) for reference in evidence_references],
        "recommendation": recommendation,
    }
    return "SR-" + _canonical_digest_hex(payload, _ID_HEX_LENGTH)


# ---------------------------------------------------------------------------
# Narrow, private input validators.
# ---------------------------------------------------------------------------


def _in_vocab(value: Any, vocabulary: frozenset[str]) -> bool:
    return isinstance(value, str) and value in vocabulary


def _validate_finding_input(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _raise("INVALID_FINDING", "finding must be a mapping")
    if value.get("finding_version") != "1":
        _raise("INVALID_FINDING", "finding_version must be '1'")

    finding_id = value.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip():
        _raise("INVALID_FINDING", "finding_id must be a non-blank string")

    if not _in_vocab(value.get("finding_status"), FINDING_STATUSES):
        _raise("INVALID_FINDING", "finding_status must be a recognized value")
    if not _in_vocab(value.get("technical_severity"), TECHNICAL_SEVERITIES):
        _raise("INVALID_FINDING", "technical_severity must be a recognized value")
    if not _in_vocab(value.get("confidence"), CONFIDENCE_LEVELS):
        _raise("INVALID_FINDING", "confidence must be a recognized value")

    evidence = value.get("evidence")
    if not isinstance(evidence, list) or len(evidence) == 0:
        _raise("INVALID_FINDING", "evidence must be a non-empty list")

    digests: list[str] = []
    for item in evidence:
        if not isinstance(item, Mapping):
            _raise("INVALID_FINDING", "each evidence item must be a mapping")
        digest = item.get("evidence_digest")
        if not isinstance(digest, str) or not _DIGEST_PATTERN.fullmatch(digest):
            _raise("INVALID_FINDING", "each evidence item must carry a well-formed evidence_digest")
        digests.append(digest)
    if len(digests) != len(set(digests)):
        _raise("INVALID_FINDING", "evidence digests must not contain duplicates")

    return {
        "finding_id": finding_id,
        "finding_status": value["finding_status"],
        "technical_severity": value["technical_severity"],
        "confidence": value["confidence"],
        "evidence_digests": digests,
    }


def _validate_prioritization_input(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _raise("INVALID_PRIORITIZATION", "prioritization must be a mapping")
    if value.get("prioritization_version") != "1":
        _raise("INVALID_PRIORITIZATION", "prioritization_version must be '1'")

    finding_id = value.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip():
        _raise("INVALID_PRIORITIZATION", "finding_id must be a non-blank string")

    if not _in_vocab(value.get("technical_severity"), TECHNICAL_SEVERITIES):
        _raise("INVALID_PRIORITIZATION", "technical_severity must be a recognized value")
    if not _in_vocab(value.get("finding_status"), FINDING_STATUSES):
        _raise("INVALID_PRIORITIZATION", "finding_status must be a recognized value")
    if not _in_vocab(value.get("confidence"), CONFIDENCE_LEVELS):
        _raise("INVALID_PRIORITIZATION", "confidence must be a recognized value")
    if not _in_vocab(value.get("operational_priority"), OPERATIONAL_PRIORITIES):
        _raise("INVALID_PRIORITIZATION", "operational_priority must be a recognized value")
    if not _in_vocab(value.get("priority_direction"), PRIORITY_DIRECTIONS):
        _raise("INVALID_PRIORITIZATION", "priority_direction must be a recognized value")
    if not _in_vocab(value.get("context_completeness"), CONTEXT_COMPLETENESS_VALUES):
        _raise("INVALID_PRIORITIZATION", "context_completeness must be a recognized value")

    priority_score = _validate_priority_score(value.get("priority_score"))

    return {
        "finding_id": finding_id,
        "technical_severity": value["technical_severity"],
        "finding_status": value["finding_status"],
        "confidence": value["confidence"],
        "operational_priority": value["operational_priority"],
        "priority_direction": value["priority_direction"],
        "context_completeness": value["context_completeness"],
        "priority_score": priority_score,
    }


def _validate_priority_score(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != _PRIORITY_SCORE_FIELDS:
        _raise("INVALID_PRIORITIZATION", "priority_score must contain exactly base/raw_modifier/applied_modifier/final")
    validated: dict[str, int] = {}
    for field in _PRIORITY_SCORE_FIELDS:
        field_value = value[field]
        if isinstance(field_value, bool) or not isinstance(field_value, int):
            _raise("INVALID_PRIORITIZATION", f"priority_score[{field!r}] must be an int")
        validated[field] = field_value
    return validated


def _check_consistency(finding_fields: Mapping[str, Any], prioritization_fields: Mapping[str, Any]) -> None:
    if finding_fields["finding_id"] != prioritization_fields["finding_id"]:
        _raise("FINDING_ID_MISMATCH", "finding and prioritization reference different finding_id values")
    if finding_fields["technical_severity"] != prioritization_fields["technical_severity"]:
        _raise("TECHNICAL_SEVERITY_MISMATCH", "finding and prioritization disagree on technical_severity")
    if finding_fields["finding_status"] != prioritization_fields["finding_status"]:
        _raise("FINDING_STATUS_MISMATCH", "finding and prioritization disagree on finding_status")
    if finding_fields["confidence"] != prioritization_fields["confidence"]:
        _raise("CONFIDENCE_MISMATCH", "finding and prioritization disagree on confidence")


def _validate_evidence_reference_shape(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _EVIDENCE_REFERENCE_FIELDS:
        _raise("EVIDENCE_REFERENCE_INVALID", "evidence reference must contain exactly reference_type/reference")
    if not _in_vocab(value.get("reference_type"), EVIDENCE_REFERENCE_TYPES):
        _raise("EVIDENCE_REFERENCE_INVALID", "reference_type must be a recognized value")
    reference = value.get("reference")
    if not isinstance(reference, str) or not reference.strip():
        _raise("EVIDENCE_REFERENCE_INVALID", "reference must be a non-blank string")
    return {"reference_type": value["reference_type"], "reference": reference}


def _validate_finding_reference(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _FINDING_REFERENCE_FIELDS:
        _raise("INVALID_CASE", "finding_reference is malformed")
    if not isinstance(value.get("finding_id"), str) or not value["finding_id"].strip():
        _raise("INVALID_CASE", "finding_reference.finding_id is malformed")
    if not _in_vocab(value.get("technical_severity"), TECHNICAL_SEVERITIES):
        _raise("INVALID_CASE", "finding_reference.technical_severity is malformed")
    if not _in_vocab(value.get("finding_status"), FINDING_STATUSES):
        _raise("INVALID_CASE", "finding_reference.finding_status is malformed")
    if not _in_vocab(value.get("confidence"), CONFIDENCE_LEVELS):
        _raise("INVALID_CASE", "finding_reference.confidence is malformed")

    digests = value.get("evidence_digests")
    if not isinstance(digests, list) or len(digests) == 0:
        _raise("INVALID_CASE", "finding_reference.evidence_digests is malformed")
    for digest in digests:
        if not isinstance(digest, str) or not _DIGEST_PATTERN.fullmatch(digest):
            _raise("INVALID_CASE", "finding_reference.evidence_digests contains a malformed digest")
    if len(digests) != len(set(digests)):
        _raise("INVALID_CASE", "finding_reference.evidence_digests contains duplicates")

    return {
        "finding_id": value["finding_id"],
        "technical_severity": value["technical_severity"],
        "finding_status": value["finding_status"],
        "confidence": value["confidence"],
        "evidence_digests": list(digests),
    }


def _validate_priority_reference(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _PRIORITY_REFERENCE_FIELDS:
        _raise("INVALID_CASE", "priority_reference is malformed")
    if not _in_vocab(value.get("operational_priority"), OPERATIONAL_PRIORITIES):
        _raise("INVALID_CASE", "priority_reference.operational_priority is malformed")
    if not _in_vocab(value.get("priority_direction"), PRIORITY_DIRECTIONS):
        _raise("INVALID_CASE", "priority_reference.priority_direction is malformed")
    if not _in_vocab(value.get("context_completeness"), CONTEXT_COMPLETENESS_VALUES):
        _raise("INVALID_CASE", "priority_reference.context_completeness is malformed")

    score = value.get("priority_score")
    if not isinstance(score, Mapping) or set(score) != _PRIORITY_SCORE_FIELDS:
        _raise("INVALID_CASE", "priority_reference.priority_score is malformed")
    validated_score: dict[str, int] = {}
    for field in _PRIORITY_SCORE_FIELDS:
        field_value = score[field]
        if isinstance(field_value, bool) or not isinstance(field_value, int):
            _raise("INVALID_CASE", f"priority_reference.priority_score[{field!r}] must be an int")
        validated_score[field] = field_value

    return {
        "operational_priority": value["operational_priority"],
        "priority_direction": value["priority_direction"],
        "context_completeness": value["context_completeness"],
        "priority_score": validated_score,
    }


def _validate_stage_result_shape(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_STAGE_RESULT_REQUIRED_FIELDS):
        _raise("INVALID_CASE", "stage result is malformed")
    if value.get("stage_result_version") != STAGE_RESULT_VERSION:
        _raise("INVALID_CASE", "stage_result_version must be '1'")

    stage_result_id = value.get("stage_result_id")
    if not isinstance(stage_result_id, str) or not _STAGE_RESULT_ID_PATTERN.fullmatch(stage_result_id):
        _raise("INVALID_CASE", "stage_result_id is malformed")

    sequence = value.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        _raise("INVALID_CASE", "sequence must be a positive int")

    if not _in_vocab(value.get("stage"), _APPENDABLE_STAGES):
        _raise("INVALID_CASE", "stage result stage is malformed")
    stage = value["stage"]

    if not _in_vocab(value.get("role"), ROLES):
        _raise("INVALID_CASE", "stage result role is malformed")
    role = value["role"]
    if REQUIRED_ROLE_BY_STAGE[stage] != role:
        _raise("INVALID_CASE", "stage result role does not match its stage")

    if not _in_vocab(value.get("result_type"), RESULT_TYPES):
        _raise("INVALID_CASE", "stage result result_type is malformed")
    result_type = value["result_type"]
    if result_type not in ALLOWED_RESULT_TYPES_BY_STAGE[stage]:
        _raise("INVALID_CASE", "stage result result_type is not allowed for its stage")

    allowed_outcomes = STAGE_OUTCOMES[(stage, result_type)]
    if not isinstance(value.get("outcome"), str) or value["outcome"] not in allowed_outcomes:
        _raise("INVALID_CASE", "stage result outcome is not allowed for its stage/result_type")
    outcome = value["outcome"]

    evidence_references = value.get("evidence_references")
    if not isinstance(evidence_references, list) or len(evidence_references) == 0:
        _raise("INVALID_CASE", "stage result evidence_references must be a non-empty list")
    validated_references = [_validate_evidence_reference_shape(item) for item in evidence_references]

    recommendation = value.get("recommendation")
    if not isinstance(recommendation, str) or not recommendation.strip():
        _raise("INVALID_CASE", "stage result recommendation must be a non-blank string")

    if value.get("human_review_required") is not True:
        _raise("INVALID_CASE", "stage result human_review_required must be true")
    if value.get("execution_performed") is not False:
        _raise("INVALID_CASE", "stage result execution_performed must be false")

    return {
        "stage_result_version": STAGE_RESULT_VERSION,
        "stage_result_id": stage_result_id,
        "sequence": sequence,
        "stage": stage,
        "role": role,
        "result_type": result_type,
        "outcome": outcome,
        "evidence_references": validated_references,
        "recommendation": recommendation,
        "human_review_required": True,
        "execution_performed": False,
    }


def _validate_case(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_CASE_REQUIRED_FIELDS):
        _raise("INVALID_CASE", "case must contain exactly the eleven required fields")

    if value.get("handoff_version") != HANDOFF_VERSION:
        _raise("INVALID_CASE", "handoff_version must be '1'")

    case_id = value.get("case_id")
    if not isinstance(case_id, str) or not _CASE_ID_PATTERN.fullmatch(case_id):
        _raise("INVALID_CASE", "case_id is malformed")

    finding_reference = _validate_finding_reference(value.get("finding_reference"))
    priority_reference = _validate_priority_reference(value.get("priority_reference"))

    if case_id != _compute_case_id(finding_reference, priority_reference):
        _raise("INVALID_CASE", "case_id does not match its own finding_reference/priority_reference content")

    if not _in_vocab(value.get("current_stage"), STAGES):
        _raise("STAGE_NOT_EXPECTED", "current_stage is not a recognized stage")
    current_stage = value["current_stage"]

    if not _in_vocab(value.get("required_role"), ROLES):
        _raise("ROLE_NOT_EXPECTED", "required_role is not a recognized role")
    required_role = value["required_role"]
    if REQUIRED_ROLE_BY_STAGE[current_stage] != required_role:
        _raise("ROLE_NOT_EXPECTED", "required_role does not match current_stage")

    raw_stage_results = value.get("stage_results")
    if not isinstance(raw_stage_results, list):
        _raise("INVALID_CASE", "stage_results must be a list")

    known_digests = set(finding_reference["evidence_digests"])
    finding_id = finding_reference["finding_id"]
    known_ids: set[str] = set()
    validated_results: list[dict[str, Any]] = []

    for index, raw_result in enumerate(raw_stage_results):
        result = _validate_stage_result_shape(raw_result)

        if result["sequence"] != index + 1:
            _raise("INVALID_CASE", "stage_results sequence has a gap or is out of order")
        if result["stage_result_id"] in known_ids:
            _raise("INVALID_CASE", "duplicate stage_result_id")

        expected_id = _compute_stage_result_id(
            case_id=case_id,
            sequence=result["sequence"],
            stage=result["stage"],
            role=result["role"],
            result_type=result["result_type"],
            outcome=result["outcome"],
            evidence_references=result["evidence_references"],
            recommendation=result["recommendation"],
        )
        if result["stage_result_id"] != expected_id:
            _raise("INVALID_CASE", "stage_result_id does not match its own content")

        seen_in_result: set[tuple[str, str]] = set()
        for reference in result["evidence_references"]:
            reference_key = (reference["reference_type"], reference["reference"])
            if reference_key in seen_in_result:
                _raise("EVIDENCE_REFERENCE_INVALID", "duplicate evidence reference within one stage result")
            seen_in_result.add(reference_key)

            if reference["reference_type"] == "finding":
                if reference["reference"] != finding_id:
                    _raise("EVIDENCE_REFERENCE_INVALID", "finding reference does not match case finding_id")
            elif reference["reference_type"] == "evidence_digest":
                if reference["reference"] not in known_digests:
                    _raise("EVIDENCE_REFERENCE_INVALID", "evidence_digest reference is unknown to this case")
            else:
                if reference["reference"] not in known_ids:
                    _raise("EVIDENCE_REFERENCE_INVALID", "stage_result reference must be an earlier stage result")

        known_ids.add(result["stage_result_id"])
        validated_results.append(result)

    if not _in_vocab(value.get("approval_state"), APPROVAL_STATES):
        _raise("INVALID_CASE", "approval_state is not a recognized value")
    approval_state = value["approval_state"]

    approval_reference = value.get("approval_reference")
    if approval_reference is not None and (not isinstance(approval_reference, str) or not approval_reference.strip()):
        _raise("INVALID_CASE", "approval_reference must be null or a non-blank string")

    if approval_state in ("not_required", "pending") and approval_reference is not None:
        _raise("INVALID_CASE", "approval_reference must be null while approval_state is not_required/pending")
    if approval_state in ("approved", "rejected") and approval_reference is None:
        _raise("INVALID_CASE", "approval_reference is required once approval_state is approved/rejected")
    if current_stage != "human_review" and approval_state != "not_required":
        _raise("INVALID_CASE", "approval_state must be not_required before current_stage reaches human_review")
    if current_stage == "human_review" and approval_state == "not_required":
        _raise("INVALID_CASE", "approval_state must not be not_required once current_stage is human_review")

    if value.get("human_review_required") is not True:
        _raise("INVALID_CASE", "human_review_required must be true")
    if value.get("execution_performed") is not False:
        _raise("INVALID_CASE", "execution_performed must be false")

    return {
        "handoff_version": HANDOFF_VERSION,
        "case_id": case_id,
        "finding_reference": finding_reference,
        "priority_reference": priority_reference,
        "current_stage": current_stage,
        "required_role": required_role,
        "stage_results": validated_results,
        "approval_state": approval_state,
        "approval_reference": approval_reference,
        "human_review_required": True,
        "execution_performed": False,
    }


# ---------------------------------------------------------------------------
# Deterministic transition rules -- a fixed, closed graph. Never depends
# on a capability this repository does not actually have.
# ---------------------------------------------------------------------------


def _determine_transition(
    *, current_stage: str, result_type: str, outcome: str, current_approval_state: str,
) -> tuple[str, str, str]:
    if current_stage == "threat_intel_review":
        if outcome == "needs_review":
            return "threat_intel_review", "threat_intelligence", current_approval_state
        return "threat_hunt", "threat_hunting", current_approval_state

    if current_stage == "threat_hunt":
        if outcome == "needs_review":
            return "threat_hunt", "threat_hunting", current_approval_state
        return "detection_engineering", "blue_team", current_approval_state

    if current_stage == "detection_engineering":
        if outcome in ("needs_review", "blocked"):
            return "detection_engineering", "blue_team", current_approval_state
        if outcome == "not_applicable":
            return "purple_remediation", "purple_ir", current_approval_state
        return "red_validation", "red_team", current_approval_state  # candidate_ready

    if current_stage == "red_validation":
        if result_type == "plan":
            return "red_validation", "red_team", current_approval_state
        if outcome == "blocked":
            return "detection_engineering", "blue_team", current_approval_state
        if outcome in ("validated", "not_applicable"):
            return "purple_remediation", "purple_ir", current_approval_state
        return "red_validation", "red_team", current_approval_state  # needs_review

    if current_stage == "purple_remediation":
        if outcome in ("needs_review", "blocked"):
            return "purple_remediation", "purple_ir", current_approval_state
        return "human_review", "human_analyst", "pending"  # planned or not_applicable

    raise AssertionError(f"unreachable current_stage: {current_stage!r}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_security_handoff_case(*, finding: Any, prioritization: Any) -> dict[str, Any]:
    """Deterministically create one new security handoff case from an
    already-existing Block 15A finding and its matching Block 15B
    prioritization result. Performs no I/O of any kind.

    Both parameters are required and keyword-only. `finding` must be a
    mapping shaped at minimum like `core.bug_bounty_findings.
    create_bug_bounty_finding`'s own return value; this function never
    imports that module, and never reads any finding field beyond
    `finding_version`/`finding_id`/`finding_status`/`technical_severity`/
    `confidence`/`evidence` (and, within each evidence item, only
    `evidence_digest`). `prioritization` must be a mapping shaped at
    minimum like `core.context_prioritization.prioritize_finding`'s own
    return value; this function never imports that module, and never
    recomputes any scoring. The two must agree exactly on `finding_id`,
    `technical_severity`, `finding_status`, and `confidence`, or this
    function raises `SecurityHandoffError` with one of
    `FINDING_ID_MISMATCH`/`TECHNICAL_SEVERITY_MISMATCH`/
    `FINDING_STATUS_MISMATCH`/`CONFIDENCE_MISMATCH` -- deterministic
    correlation checks only, never described as authentication.

    Neither `finding` nor `prioritization` is ever mutated.

    Returns a new dict containing exactly the eleven fields documented
    in the module docstring's case contract: `handoff_version` (always
    `"1"`), `case_id` (a content-correlation id, never authentication),
    `finding_reference`, `priority_reference`, `current_stage` (always
    `"threat_intel_review"` for a new case), `required_role` (always
    `"threat_intelligence"`), `stage_results` (always `[]`),
    `approval_state` (always `"not_required"`), `approval_reference`
    (always `None`), `human_review_required` (always `True`),
    `execution_performed` (always `False`).

    Raises `SecurityHandoffError` for any structurally invalid
    `finding`/`prioritization`, or for a finding/prioritization
    substitution mismatch.
    """
    finding_fields = _validate_finding_input(finding)
    prioritization_fields = _validate_prioritization_input(prioritization)
    _check_consistency(finding_fields, prioritization_fields)

    finding_reference = {
        "finding_id": finding_fields["finding_id"],
        "technical_severity": finding_fields["technical_severity"],
        "finding_status": finding_fields["finding_status"],
        "confidence": finding_fields["confidence"],
        "evidence_digests": list(finding_fields["evidence_digests"]),
    }
    priority_reference = {
        "operational_priority": prioritization_fields["operational_priority"],
        "priority_direction": prioritization_fields["priority_direction"],
        "context_completeness": prioritization_fields["context_completeness"],
        "priority_score": dict(prioritization_fields["priority_score"]),
    }

    case_id = _compute_case_id(finding_reference, priority_reference)

    return {
        "handoff_version": HANDOFF_VERSION,
        "case_id": case_id,
        "finding_reference": finding_reference,
        "priority_reference": priority_reference,
        "current_stage": "threat_intel_review",
        "required_role": "threat_intelligence",
        "stage_results": [],
        "approval_state": "not_required",
        "approval_reference": None,
        "human_review_required": True,
        "execution_performed": False,
    }


def append_security_stage_result(
    *,
    case: Any,
    stage: Any,
    role: Any,
    result_type: Any,
    outcome: Any,
    evidence_references: Any,
    recommendation: Any,
) -> dict[str, Any]:
    """Deterministically append exactly one new, externally/caller-
    supplied stage result to an already-existing security handoff case,
    returning a new case object. Performs no I/O of any kind, and never
    invokes any TI/Hunt/Blue/Red/Purple command, skill, or engine --
    every stage result recorded here describes work already done
    elsewhere (by a human, a Claude command, or a future real engine),
    never work this function performed.

    All parameters are required and keyword-only. `case` must be a
    mapping shaped like this module's own case contract -- it is fully
    re-validated on every call (see the module docstring), never
    trusted blindly. `stage` must equal `case["current_stage"]` exactly
    (never `"human_review"` -- that stage is handled only by
    `record_security_handoff_approval`), and `role` must equal the
    fixed required role for that stage (see `REQUIRED_ROLE_BY_STAGE`).
    `result_type` must be one of the values `ALLOWED_RESULT_TYPES_BY_STAGE`
    permits for `stage`, and `outcome` must be one of the values
    `STAGE_OUTCOMES[(stage, result_type)]` permits. `evidence_references`
    must be a non-empty list of `{reference_type, reference}` mappings;
    each `"finding"` reference must equal the case's own `finding_id`,
    each `"evidence_digest"` reference must already appear in
    `finding_reference.evidence_digests`, and each `"stage_result"`
    reference must name an already-appended, strictly earlier stage
    result -- no forward references, no duplicates. `recommendation`
    must be a non-blank string; it is stored as inert data only -- see
    the module docstring's prompt-injection boundary.

    This function never mutates `case` (or any nested value within it)
    -- it deep-copies the validated case, appends exactly one new stage
    result to the copy's `stage_results` list, and updates only
    `current_stage`/`required_role`/`approval_state` as the fixed
    transition rules in the module docstring dictate. Every prior stage
    result is preserved exactly as it was; none is ever edited.

    Returns a new case dict. The newly appended stage result always
    carries `human_review_required: True` and `execution_performed:
    False` -- including a `red_validation` stage result whose `outcome`
    is `"validated"`, which records an externally-produced Red Team
    assessment, never an attack this function executed.

    Raises `SecurityHandoffError` for a malformed `case`, an
    unexpected `stage`/`role`, a disallowed `result_type`/`outcome`, an
    invalid evidence reference, or a malformed `recommendation`. Never
    raises because an outcome is `"blocked"`/`"needs_review"`/
    `"not_applicable"` -- every one of those is a normal, successfully
    appended result.
    """
    validated_case = _validate_case(case)
    current_stage = validated_case["current_stage"]

    if current_stage == "human_review":
        _raise("STAGE_NOT_EXPECTED", "no stage result may be appended once current_stage is human_review")

    if not _in_vocab(stage, _APPENDABLE_STAGES) or stage != current_stage:
        _raise("STAGE_NOT_EXPECTED", "stage must equal the case's current_stage")

    expected_role = REQUIRED_ROLE_BY_STAGE[current_stage]
    if not _in_vocab(role, ROLES) or role != expected_role:
        _raise("ROLE_NOT_EXPECTED", "role does not match the required role for this stage")

    if not _in_vocab(result_type, RESULT_TYPES) or result_type not in ALLOWED_RESULT_TYPES_BY_STAGE[current_stage]:
        _raise("RESULT_TYPE_NOT_ALLOWED", "result_type is not allowed for this stage")

    allowed_outcomes = STAGE_OUTCOMES[(current_stage, result_type)]
    if not isinstance(outcome, str) or outcome not in allowed_outcomes:
        _raise("OUTCOME_NOT_ALLOWED", "outcome is not allowed for this stage/result_type")

    if not isinstance(evidence_references, list) or len(evidence_references) == 0:
        _raise("EVIDENCE_REFERENCE_INVALID", "evidence_references must be a non-empty list")

    finding_id = validated_case["finding_reference"]["finding_id"]
    known_digests = set(validated_case["finding_reference"]["evidence_digests"])
    known_ids = {result["stage_result_id"] for result in validated_case["stage_results"]}

    validated_references: list[dict[str, str]] = []
    seen_references: set[tuple[str, str]] = set()
    for raw_reference in evidence_references:
        reference = _validate_evidence_reference_shape(raw_reference)
        reference_key = (reference["reference_type"], reference["reference"])
        if reference_key in seen_references:
            _raise("EVIDENCE_REFERENCE_INVALID", "duplicate evidence reference")
        seen_references.add(reference_key)

        if reference["reference_type"] == "finding":
            if reference["reference"] != finding_id:
                _raise("EVIDENCE_REFERENCE_INVALID", "finding reference does not match case finding_id")
        elif reference["reference_type"] == "evidence_digest":
            if reference["reference"] not in known_digests:
                _raise("EVIDENCE_REFERENCE_INVALID", "evidence_digest reference is unknown to this case")
        else:
            if reference["reference"] not in known_ids:
                _raise("EVIDENCE_REFERENCE_INVALID", "stage_result reference must be an earlier stage result")

        validated_references.append(reference)

    if not isinstance(recommendation, str) or not recommendation.strip():
        _raise("INVALID_CASE", "recommendation must be a non-blank string")

    sequence = len(validated_case["stage_results"]) + 1
    stage_result_id = _compute_stage_result_id(
        case_id=validated_case["case_id"],
        sequence=sequence,
        stage=current_stage,
        role=role,
        result_type=result_type,
        outcome=outcome,
        evidence_references=validated_references,
        recommendation=recommendation,
    )

    new_result = {
        "stage_result_version": STAGE_RESULT_VERSION,
        "stage_result_id": stage_result_id,
        "sequence": sequence,
        "stage": current_stage,
        "role": role,
        "result_type": result_type,
        "outcome": outcome,
        "evidence_references": validated_references,
        "recommendation": recommendation,
        "human_review_required": True,
        "execution_performed": False,
    }

    next_stage, next_role, next_approval_state = _determine_transition(
        current_stage=current_stage,
        result_type=result_type,
        outcome=outcome,
        current_approval_state=validated_case["approval_state"],
    )

    new_case = copy.deepcopy(validated_case)
    new_case["stage_results"] = new_case["stage_results"] + [new_result]
    new_case["current_stage"] = next_stage
    new_case["required_role"] = next_role
    new_case["approval_state"] = next_approval_state
    return new_case


def record_security_handoff_approval(*, case: Any, approval_state: Any, approval_reference: Any) -> dict[str, Any]:
    """Deterministically record one externally/caller-reported human
    approval decision against a security handoff case that has already
    reached `human_review`, returning a new case object. Performs no
    I/O of any kind -- this function never contacts Supabase, never
    verifies an approval database row, never calls
    `/request-case-update`/`/review-approval`/`/apply-case-update`, and
    never executes any downstream action. The recorded decision is
    exactly what the caller reported; this module never authenticates
    it.

    All parameters are required and keyword-only. `case` must already
    have `current_stage == "human_review"` and `approval_state ==
    "pending"` -- any other case state raises
    `APPROVAL_UPDATE_NOT_ALLOWED`. `approval_state` must be exactly
    `"approved"` or `"rejected"` (never `"pending"`/`"not_required"`,
    and never a second update after the first one -- `approval_state`
    is no longer `"pending"` once set). `approval_reference` must be a
    non-blank string, or this function raises
    `APPROVAL_REFERENCE_REQUIRED`.

    `current_stage` remains exactly `"human_review"` after this call --
    there is no `"complete"` stage in this checkpoint. `"approved"`
    never means a remediation was applied, a detection was deployed, a
    Red retest ran, or a validated defense now exists -- it only means
    the caller reported that decision.

    This function never mutates `case`. Raises `SecurityHandoffError`
    for a case not yet awaiting approval, an unsupported
    `approval_state` value, or a missing/blank `approval_reference`.
    """
    validated_case = _validate_case(case)

    if validated_case["current_stage"] != "human_review":
        _raise("APPROVAL_UPDATE_NOT_ALLOWED", "approval may only be recorded once current_stage is human_review")
    if validated_case["approval_state"] != "pending":
        _raise("APPROVAL_UPDATE_NOT_ALLOWED", "approval_state must be pending before it can be recorded")

    if approval_state not in ("approved", "rejected"):
        _raise("APPROVAL_UPDATE_NOT_ALLOWED", "approval_state must be exactly 'approved' or 'rejected'")

    if not isinstance(approval_reference, str) or not approval_reference.strip():
        _raise("APPROVAL_REFERENCE_REQUIRED", "approval_reference must be a non-blank string")

    new_case = copy.deepcopy(validated_case)
    new_case["approval_state"] = approval_state
    new_case["approval_reference"] = approval_reference
    return new_case
