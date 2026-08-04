"""Pure, deterministic Shadow Execution ("digital twin") simulation for
one approved, risk-aware case-update approval.

This module answers one question only: *if `/apply-case-update` were run
right now against this exact approval and this exact investigation state,
what would change?* It never answers whether the action *should* run --
that remains `core.approval_risk`'s and `core.approval_transition`'s own
concern -- and it never makes the action run.

This module does not:

- query Supabase, read an investigation or approval from a database, or
  perform any I/O of any kind;
- read the system clock, an environment variable, or the filesystem;
- generate a random value of any kind;
- construct SQL, an MCP descriptor, or an RPC parameter set;
- update an investigation, consume an approval, record a review, or
  change an approval's lifecycle status;
- accept a caller-supplied "proposed state" -- the proposed `status`/
  `confidence` are always derived entirely from the trusted approval
  record's own stored `action_payload`, exactly as `/apply-case-update`
  itself already treats that field as the exclusive source of the
  applied change;
- call an AI/LLM model to decide anything. Every warning this module can
  ever emit comes from one small, fixed, closed vocabulary, evaluated by
  plain deterministic comparisons -- never generated, ranked, or worded
  dynamically from arbitrary input, exactly like
  `core.decision_warning_formatter`'s own fixed-explanation convention;
- reimplement risk-aware approval-record validation, the investigation-
  status vocabulary, the confidence vocabulary, action-type validation,
  action-payload validation, or confidence-lowering classification --
  every one of those is reused verbatim from the module that already owns
  it (`core.approval_transition.validate_risk_aware_approval_record` and
  `core.approval_risk.classify_approval_risk`), never duplicated here.

`simulate_case_update` is the module's only public function. Its result
is a strict, self-contained mapping -- never identity fields, raw SQL,
descriptors, RPC parameters, or any other database/transport metadata --
and always carries `mutation_performed: false`, so a caller can never
mistake a shadow-execution report for evidence that execution occurred.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from core.approval_risk import ApprovalRiskError, classify_approval_risk
from core.approval_transition import ApprovalTransitionError, validate_risk_aware_approval_record
from core.decision_context import INVESTIGATION_STATUSES
from core.evidence_normalizer import CONFIDENCE_LEVELS

SIMULATION_VERSION = "1"

_CLOSED_STATUS = "closed"
_SUPPORTED_ACTION_TYPE = "update_investigation_state"

_INVESTIGATION_CONTEXT_FIELDS = ("investigation_id", "status", "confidence")
_INVESTIGATION_CONTEXT_FIELDS_SET = frozenset(_INVESTIGATION_CONTEXT_FIELDS)

# Canonical order for both changed_fields/unchanged_fields and every
# state-comparison this module performs -- status is always compared
# before confidence, regardless of which fields the proposed action
# actually touches.
_COMPARISON_FIELD_ORDER = ("status", "confidence")

# The MVP's entire warning vocabulary, and the one fixed order every
# report's warnings list is evaluated (and therefore ever emitted) in.
# Nothing outside this tuple can ever appear in a warning's "code".
WARNING_CODES = (
    "ALREADY_CONSUMED",
    "NOT_APPROVED",
    "APPROVAL_EXPIRED",
    "STALE_BINDING",
    "CLOSING_INVESTIGATION",
    "REOPENING_INVESTIGATION",
    "CONFIDENCE_LOWERED",
    "COMBINED_FIELD_CHANGE",
    "NO_OP_ACTION",
    "ROLLBACK_UNCERTAIN",
)
_WARNING_CODES_SET = frozenset(WARNING_CODES)

_WARNING_SEVERITY: dict[str, str] = {
    "ALREADY_CONSUMED": "blocking",
    "NOT_APPROVED": "blocking",
    "APPROVAL_EXPIRED": "blocking",
    "STALE_BINDING": "blocking",
    "CLOSING_INVESTIGATION": "caution",
    "REOPENING_INVESTIGATION": "caution",
    "CONFIDENCE_LOWERED": "caution",
    "COMBINED_FIELD_CHANGE": "info",
    "NO_OP_ACTION": "caution",
    "ROLLBACK_UNCERTAIN": "info",
}

_WARNING_BLOCKS_EXECUTION: dict[str, bool] = {
    "ALREADY_CONSUMED": True,
    "NOT_APPROVED": True,
    "APPROVAL_EXPIRED": True,
    "STALE_BINDING": True,
    "CLOSING_INVESTIGATION": False,
    "REOPENING_INVESTIGATION": False,
    "CONFIDENCE_LOWERED": False,
    "COMBINED_FIELD_CHANGE": False,
    "NO_OP_ACTION": False,
    "ROLLBACK_UNCERTAIN": False,
}

_WARNING_MESSAGES: dict[str, str] = {
    "ALREADY_CONSUMED": "This approval has already been consumed and cannot be executed again.",
    "NOT_APPROVED": "This approval has not reached the approved lifecycle status required for execution.",
    "APPROVAL_EXPIRED": "This approval has expired and can no longer be executed.",
    "STALE_BINDING": "This approval's investigation_id does not match the supplied investigation context.",
    "CLOSING_INVESTIGATION": "This action would close the investigation.",
    "REOPENING_INVESTIGATION": "This action would reopen a closed investigation.",
    "CONFIDENCE_LOWERED": "This action would lower the investigation's confidence.",
    "COMBINED_FIELD_CHANGE": "This action proposes both a status change and a confidence change together.",
    "NO_OP_ACTION": "This action proposes no actual change to status or confidence.",
    "ROLLBACK_UNCERTAIN": (
        "Rollback for this action is not guaranteed to succeed and would require a new, "
        "separately approved action."
    ),
}

# The MVP's entire rollback vocabulary. Only the first two are ever
# actually produced by classify() below -- not_reversible and unknown
# are kept in the public vocabulary for a future action type, never
# produced by the one action type this module currently supports.
ROLLBACK_CLASSIFICATIONS = (
    "fully_reversible",
    "conditionally_reversible",
    "not_reversible",
    "unknown",
)

_NO_OP_ROLLBACK = {
    "reversible": "fully_reversible",
    "strategy": "No rollback action is required because this simulation proposes no change to status or confidence.",
    "limitations": "No state change is proposed, so no rollback limitations apply.",
}

_CHANGE_ROLLBACK = {
    "reversible": "conditionally_reversible",
    "strategy": (
        "Rollback would require creating and separately approving a new case-update request "
        "that restores the original status and/or confidence value."
    ),
    "limitations": (
        "The investigation may change again before a rollback request is created; a rollback "
        "itself requires its own new approval; and this simulation does not guarantee that a "
        "future rollback request would be approved, or that a rollback would succeed."
    ),
}

_CANONICAL_TIMESTAMP_PATTERN_HINT = "an aware datetime or an aware ISO-8601 string"


class ShadowExecutionError(ValueError):
    """Raised when a supplied simulation input is structurally invalid or
    describes an unsupported contract.

    This is only raised for malformed input: a malformed or inconsistent
    `approval_record` (delegated entirely to
    `core.approval_transition.validate_risk_aware_approval_record`), a
    malformed `investigation_context` (wrong type, unknown or missing
    field, malformed UUID, unsupported status/confidence value), or a
    malformed `simulated_at` (not an aware datetime/ISO-8601 string).

    It is never raised because a loaded approval happens to be
    ineligible for execution right now (pending, partially_approved,
    rejected, consumed, expired, or bound to a different investigation)
    -- every one of those is a fully valid input that this module
    represents through `eligible_for_execution: false` and one or more
    deterministic warnings, not an exception. This module never exposes
    a database, SQL, MCP, or transport concept in any exception message.
    """


def _validate_uuid_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ShadowExecutionError(f"{field_name} must be a string")
    stripped = value.strip()
    if not stripped:
        raise ShadowExecutionError(f"{field_name} must not be blank")
    try:
        parsed = uuid.UUID(stripped)
    except ValueError as exc:
        raise ShadowExecutionError(f"{field_name} must be a structurally valid UUID") from exc
    return str(parsed)


def _validate_controlled_string(value: Any, field_name: str, vocabulary: frozenset[str]) -> str:
    if not isinstance(value, str):
        raise ShadowExecutionError(f"{field_name} must be a string")
    normalized = value.strip().lower()
    if not normalized:
        raise ShadowExecutionError(f"{field_name} must not be blank")
    if normalized not in vocabulary:
        raise ShadowExecutionError(
            f"{field_name} must be one of {sorted(vocabulary)}, got {normalized!r}"
        )
    return normalized


def _normalize_timestamp(value: Any, field_name: str) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ShadowExecutionError(f"{field_name} must not be blank")
        iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(iso_text)
        except ValueError as exc:
            raise ShadowExecutionError(
                f"{field_name} must be {_CANONICAL_TIMESTAMP_PATTERN_HINT}"
            ) from exc
    else:
        raise ShadowExecutionError(f"{field_name} must be {_CANONICAL_TIMESTAMP_PATTERN_HINT}")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ShadowExecutionError(f"{field_name} must include timezone information")

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_canonical(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _validate_investigation_context(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ShadowExecutionError("investigation_context must be a mapping")

    unknown_fields = set(value) - _INVESTIGATION_CONTEXT_FIELDS_SET
    if unknown_fields:
        raise ShadowExecutionError(
            "unrecognized investigation_context field(s): " + ", ".join(sorted(unknown_fields))
        )

    missing_fields = [field for field in _INVESTIGATION_CONTEXT_FIELDS if field not in value]
    if missing_fields:
        raise ShadowExecutionError(
            "missing required investigation_context field(s): " + ", ".join(missing_fields)
        )

    investigation_id = _validate_uuid_string(value["investigation_id"], "investigation_context.investigation_id")
    status = _validate_controlled_string(value["status"], "investigation_context.status", INVESTIGATION_STATUSES)
    confidence = _validate_controlled_string(
        value["confidence"], "investigation_context.confidence", CONFIDENCE_LEVELS
    )

    return {"investigation_id": investigation_id, "status": status, "confidence": confidence}


def _confidence_is_lowered(current_status: str, current_confidence: str, proposed_confidence: str) -> bool:
    """Determine whether `proposed_confidence` is a lowering relative to
    `current_confidence`, by reusing `core.approval_risk`'s own
    deterministic policy in isolation -- never a second, independently
    maintained confidence-ranking table.

    `classify_approval_risk` is called with a confidence-only
    `action_payload` so that only its confidence-component rule
    (`"medium"` for a lowering, `"low"` otherwise) can ever be reflected
    in the result, regardless of whether the real proposed action also
    changes `status`.
    """
    try:
        component_risk = classify_approval_risk(
            action_type=_SUPPORTED_ACTION_TYPE,
            action_payload={"confidence": proposed_confidence},
            current_status=current_status,
            current_confidence=current_confidence,
        )
    except ApprovalRiskError as exc:
        raise ShadowExecutionError("confidence-lowering classification failed") from exc
    return component_risk == "medium"


def simulate_case_update(
    *,
    approval_record: Mapping[str, Any],
    investigation_context: Mapping[str, Any],
    simulated_at: Any,
) -> dict[str, Any]:
    """Deterministically simulate what `/apply-case-update` would do to
    an investigation, without performing any mutation.

    All three parameters are required and keyword-only, and none has a
    hidden default:

    - `approval_record` must be the trusted, complete eighteen-field
      risk-aware approval record already returned by
      `core.approval_persistence.load_risk_aware_approval_record` (via
      the approval bridge) -- structurally validated here entirely by
      `core.approval_transition.validate_risk_aware_approval_record`,
      never reimplemented. Only `id`, `investigation_id`, `action_type`,
      `action_payload`, `status`, `risk_level`, `required_approvals`,
      `expires_at`, and `consumed_at` are ever read from the validated
      result; every identity field (`requested_by`, `approved_by`,
      `rejected_by`, `consumed_by`, `rejection_reason`) is read only
      during validation and never appears in this function's output.
    - `investigation_context` must contain exactly `investigation_id`,
      `status`, `confidence` -- the same trusted context
      `core.approval_persistence.load_investigation_approval_context`
      already returns. No proposed state, risk, approval status,
      warning, rollback field, SQL, descriptor, or identity is ever
      accepted here; the proposed `status`/`confidence` are derived
      exclusively from the approval record's own `action_payload`.
    - `simulated_at` must be an aware `datetime` or an aware ISO-8601
      string (matching every other pure validator's own timestamp
      contract in this project) -- this function never reads the system
      clock itself, so the caller alone controls what moment is
      simulated.

    Neither `approval_record` nor `investigation_context` (nor any
    nested mapping within either) is ever mutated, and no mutable object
    from either is retained by reference in the result -- every returned
    mapping and list is newly constructed.

    Returns a new dict containing exactly fifteen fields:
    `simulation_version`, `approval_id`, `investigation_id`,
    `action_type`, `risk_level`, `required_approvals`,
    `eligible_for_execution`, `current_state`, `proposed_state`,
    `changed_fields`, `unchanged_fields`, `warnings`, `rollback`,
    `simulated_at`, `mutation_performed`. `mutation_performed` is always
    `False` -- this function never updates an investigation, never
    updates or consumes an approval, never records a review, and never
    performs any database, network, or filesystem operation of any kind.

    Raises `ShadowExecutionError` for any structurally invalid input.
    Never raises because the approval happens to be ineligible for
    execution right now -- that is represented in the returned result
    through `eligible_for_execution` and `warnings` instead.
    """
    try:
        validated_record = validate_risk_aware_approval_record(approval_record)
    except ApprovalTransitionError as exc:
        raise ShadowExecutionError("approval_record failed validation") from exc

    validated_context = _validate_investigation_context(investigation_context)
    canonical_simulated_at = _normalize_timestamp(simulated_at, "simulated_at")

    approval_id = validated_record["id"]
    approval_investigation_id = validated_record["investigation_id"]
    action_type = validated_record["action_type"]
    action_payload = validated_record["action_payload"]
    status = validated_record["status"]
    risk_level = validated_record["risk_level"]
    required_approvals = validated_record["required_approvals"]
    expires_at = validated_record["expires_at"]
    consumed_at = validated_record["consumed_at"]

    current_status = validated_context["status"]
    current_confidence = validated_context["confidence"]

    current_state = {"status": current_status, "confidence": current_confidence}
    proposed_state = {
        "status": action_payload.get("status", current_status),
        "confidence": action_payload.get("confidence", current_confidence),
    }

    changed_fields: list[dict[str, str]] = []
    unchanged_fields: list[str] = []
    for field in _COMPARISON_FIELD_ORDER:
        before = current_state[field]
        after = proposed_state[field]
        if before != after:
            changed_fields.append({"field": field, "before": before, "after": after})
        else:
            unchanged_fields.append(field)

    warnings: list[dict[str, Any]] = []

    def _emit(code: str) -> None:
        warnings.append({
            "code": code,
            "severity": _WARNING_SEVERITY[code],
            "message": _WARNING_MESSAGES[code],
            "blocks_execution": _WARNING_BLOCKS_EXECUTION[code],
        })

    if status == "consumed" or consumed_at is not None:
        _emit("ALREADY_CONSUMED")

    if status != "approved":
        _emit("NOT_APPROVED")

    if expires_at is not None and _parse_canonical(canonical_simulated_at) >= _parse_canonical(expires_at):
        _emit("APPROVAL_EXPIRED")

    if approval_investigation_id != validated_context["investigation_id"]:
        _emit("STALE_BINDING")

    proposed_status = proposed_state["status"]
    if proposed_status == _CLOSED_STATUS and current_status != _CLOSED_STATUS:
        _emit("CLOSING_INVESTIGATION")

    if current_status == _CLOSED_STATUS and proposed_status != _CLOSED_STATUS:
        _emit("REOPENING_INVESTIGATION")

    if "confidence" in action_payload and _confidence_is_lowered(
        current_status, current_confidence, proposed_state["confidence"]
    ):
        _emit("CONFIDENCE_LOWERED")

    if "status" in action_payload and "confidence" in action_payload:
        _emit("COMBINED_FIELD_CHANGE")

    if not changed_fields:
        _emit("NO_OP_ACTION")
        rollback = dict(_NO_OP_ROLLBACK)
    else:
        rollback = dict(_CHANGE_ROLLBACK)

    if rollback["reversible"] in ("conditionally_reversible", "unknown"):
        _emit("ROLLBACK_UNCERTAIN")

    eligible_for_execution = not any(warning["blocks_execution"] for warning in warnings)

    return {
        "simulation_version": SIMULATION_VERSION,
        "approval_id": approval_id,
        "investigation_id": approval_investigation_id,
        "action_type": action_type,
        "risk_level": risk_level,
        "required_approvals": required_approvals,
        "eligible_for_execution": eligible_for_execution,
        "current_state": current_state,
        "proposed_state": proposed_state,
        "changed_fields": changed_fields,
        "unchanged_fields": unchanged_fields,
        "warnings": warnings,
        "rollback": rollback,
        "simulated_at": canonical_simulated_at,
        "mutation_performed": False,
    }
