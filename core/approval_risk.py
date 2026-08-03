"""Pure, deterministic risk classification for a proposed approval action.

This module owns exactly one thing: given an already-validated proposed
action (`action_type`, `action_payload`) and the investigation's current
`status`/`confidence`, deterministically classify how much reviewer
separation the resulting approval should require, before any approval
row is ever created.

This module does not:

- query Supabase, read an investigation from a database, or perform any
  I/O of any kind;
- read the system clock, an environment variable, or the filesystem;
- accept a caller-supplied risk level -- `classify_approval_risk` derives
  the risk level itself, from the action and the investigation's current
  state alone, so a caller can never claim a lower risk level than the
  deterministic policy would assign;
- know anything about approval persistence, reviewer identities, review
  counts already recorded, or the approval lifecycle state machine --
  those all remain the concern of `core.approval_request` (which composes
  with this module) and `core.approval_transition`;
- calculate a hash, verify an identity, or call an AI model.

`RISK_LEVELS` is this module's own closed vocabulary, exactly like
`ACTION_TYPES` (`core.approval_request`), `APPROVAL_STATUSES`
(`core.approval_transition`), `INVESTIGATION_STATUSES`
(`core.decision_context`), and `CONFIDENCE_LEVELS`
(`core.evidence_normalizer`) are each already owned by exactly one
module in this project. `INVESTIGATION_STATUSES` and `CONFIDENCE_LEVELS`
are imported and reused verbatim here, never redefined -- but this module
intentionally does not import `core.approval_request` (which itself
imports this module, to compose risk classification into request
validation), so this module owns its own small, local, deliberately
duplicated `action_type` policy-support set and action-payload shape
check rather than reusing `core.approval_request`'s private helpers.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from core.decision_context import INVESTIGATION_STATUSES
from core.evidence_normalizer import CONFIDENCE_LEVELS

RISK_LEVELS = frozenset({
    "low",
    "medium",
    "high",
    "critical",
})

# Canonical ordering, low to high -- used only to compare two risk levels
# (e.g. picking the higher of a status component and a confidence
# component), never to compare against anything outside this module's own
# vocabulary.
_RISK_ORDER = ("low", "medium", "high", "critical")
_RISK_RANK = {level: index for index, level in enumerate(_RISK_ORDER)}

# Immutable: this mapping is a fixed policy constant, never mutated at
# runtime.
REQUIRED_APPROVALS_BY_RISK = MappingProxyType({
    "low": 1,
    "medium": 1,
    "high": 2,
    "critical": 2,
})

# Canonical confidence ordering, lowest to highest -- reused only to
# determine whether a proposed confidence change is a decrease relative to
# the investigation's current confidence. This ordering is local to this
# module's own risk policy; it is never exported as a replacement for
# `CONFIDENCE_LEVELS` itself.
_CONFIDENCE_ORDER = ("unknown", "low", "medium", "high")
_CONFIDENCE_RANK = {level: index for index, level in enumerate(_CONFIDENCE_ORDER)}

# The only action type this module currently has a deterministic policy
# for. Intentionally a local, independent set -- not imported from
# `core.approval_request.ACTION_TYPES` -- to avoid a circular import
# (`core.approval_request` imports this module). A future action type gets
# its own entry here and its own classification branch, never a caller-
# supplied override.
_SUPPORTED_ACTION_TYPES = frozenset({"update_investigation_state"})

_ALLOWED_ACTION_PAYLOAD_FIELDS = frozenset({"status", "confidence"})

_CLOSED_STATUS = "closed"


class ApprovalRiskError(ValueError):
    """Raised when a proposed risk-classification input is structurally
    invalid, or when an unsupported risk level is passed to
    `required_approvals_for_risk`.

    This is only raised for malformed input: a non-mapping
    `action_payload`, an unsupported `action_type`, an unrecognized
    `action_payload` field, a missing `status`/`confidence` pair, an
    unsupported `status`/`confidence` value (current or proposed), or a
    malformed `risk_level` argument. It is never raised because of what a
    proposed change happens to mean operationally -- this module only
    ever classifies, it never blocks, approves, or rejects anything.
    """


def _validate_action_type(value: Any) -> str:
    if not isinstance(value, str):
        raise ApprovalRiskError("action_type must be a string")
    normalized = value.strip().lower()
    if not normalized:
        raise ApprovalRiskError("action_type must not be blank")
    if normalized not in _SUPPORTED_ACTION_TYPES:
        raise ApprovalRiskError(
            f"action_type must be one of {sorted(_SUPPORTED_ACTION_TYPES)}, got {normalized!r}"
        )
    return normalized


def _validate_controlled_string(value: Any, field_name: str, vocabulary: frozenset[str]) -> str:
    if not isinstance(value, str):
        raise ApprovalRiskError(f"{field_name} must be a string")
    normalized = value.strip().lower()
    if not normalized:
        raise ApprovalRiskError(f"{field_name} must not be blank")
    if normalized not in vocabulary:
        raise ApprovalRiskError(
            f"{field_name} must be one of {sorted(vocabulary)}, got {normalized!r}"
        )
    return normalized


def _validate_action_payload(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ApprovalRiskError("action_payload must be a mapping")

    unknown_fields = set(value) - _ALLOWED_ACTION_PAYLOAD_FIELDS
    if unknown_fields:
        raise ApprovalRiskError(
            "unrecognized action_payload field(s): " + ", ".join(sorted(unknown_fields))
        )

    if not value:
        raise ApprovalRiskError("action_payload must contain at least one of status, confidence")

    result: dict[str, str] = {}

    if "status" in value:
        result["status"] = _validate_controlled_string(value["status"], "action_payload.status", INVESTIGATION_STATUSES)

    if "confidence" in value:
        result["confidence"] = _validate_controlled_string(
            value["confidence"], "action_payload.confidence", CONFIDENCE_LEVELS
        )

    if not result:
        raise ApprovalRiskError("action_payload must contain at least one of status, confidence")

    return result


def _classify_status_component(current_status: str, target_status: str) -> str:
    if target_status == _CLOSED_STATUS:
        return "high"
    if current_status == _CLOSED_STATUS and target_status != _CLOSED_STATUS:
        return "high"
    return "medium"


def _classify_confidence_component(current_confidence: str, target_confidence: str) -> str:
    if _CONFIDENCE_RANK[target_confidence] < _CONFIDENCE_RANK[current_confidence]:
        return "medium"
    return "low"


def required_approvals_for_risk(risk_level: Any) -> int:
    """Return the number of distinct approvals required for `risk_level`.

    `risk_level` must already be one of the four canonical, lowercase
    `RISK_LEVELS` values exactly -- this function performs no trimming or
    case-folding of its own, since it is meant to be fed only the already-
    canonical output of `classify_approval_risk` (or an equally canonical
    stored value), never free-form caller text.

    Raises `ApprovalRiskError` for any value that is not a string, or is a
    string that is not exactly one of `RISK_LEVELS`.
    """
    if not isinstance(risk_level, str) or risk_level not in RISK_LEVELS:
        raise ApprovalRiskError(
            f"risk_level must be one of {sorted(RISK_LEVELS)}, got {risk_level!r}"
        )
    return REQUIRED_APPROVALS_BY_RISK[risk_level]


def classify_approval_risk(
    *,
    action_type: Any,
    action_payload: Any,
    current_status: Any,
    current_confidence: Any,
) -> str:
    """Deterministically classify the risk level of one proposed approval
    action.

    All four parameters are required and keyword-only. `action_type` must
    be the proposed action's own canonical type; only
    `update_investigation_state` has a policy today. `action_payload`
    must be a mapping containing at least one of `status`/`confidence` (no
    other field), exactly like `core.approval_request`'s own action-
    payload contract -- this module never accepts a caller-supplied
    `risk_level` anywhere in this signature, so a caller can never lower
    the classification by claiming one directly. `current_status` and
    `current_confidence` are the investigation's own current values,
    supplied by the caller (this module never reads Supabase itself), and
    must each be a member of `INVESTIGATION_STATUSES` /
    `CONFIDENCE_LEVELS` respectively.

    For `update_investigation_state`:

    - A `confidence`-only change (no `status` in `action_payload`) is
      `"medium"` when it lowers confidence relative to `current_confidence`
      (using the canonical `unknown < low < medium < high` ordering), and
      `"low"` otherwise (raising, preserving, or moving away from
      `unknown`).
    - A `status`-only change to the fixed `"closed"` value is `"high"`
      (closing).
    - A `status`-only change away from a current status of `"closed"` is
      `"high"` (reopening).
    - Any other `status`-only change is `"medium"` (ordinary).
    - When both `status` and `confidence` are present, each component is
      classified independently by the rules above, and the higher of the
      two (by the fixed `low < medium < high < critical` ordering) is
      returned. `"critical"` is never produced by this policy today; it
      remains reserved in `RISK_LEVELS` for a future action type's policy.

    Returns exactly one of `RISK_LEVELS`'s own lowercase string values.

    Raises `ApprovalRiskError` for a non-mapping or malformed
    `action_payload`, an unrecognized `action_payload` field, a missing
    `status`/`confidence` pair, an unsupported `action_type`, or an
    unsupported `current_status`/`current_confidence` value. Never mutates
    `action_payload` or any nested mapping within it, and never retains a
    reference to any caller-supplied mutable object.
    """
    canonical_action_type = _validate_action_type(action_type)
    canonical_payload = _validate_action_payload(action_payload)
    canonical_current_status = _validate_controlled_string(
        current_status, "current_status", INVESTIGATION_STATUSES
    )
    canonical_current_confidence = _validate_controlled_string(
        current_confidence, "current_confidence", CONFIDENCE_LEVELS
    )

    # _validate_action_type already restricted canonical_action_type to
    # _SUPPORTED_ACTION_TYPES -- today that is exactly one value, so no
    # further action_type-specific dispatch is needed yet; a second
    # action type would branch on canonical_action_type here.

    component_risks: list[str] = []

    if "status" in canonical_payload:
        component_risks.append(
            _classify_status_component(canonical_current_status, canonical_payload["status"])
        )

    if "confidence" in canonical_payload:
        component_risks.append(
            _classify_confidence_component(canonical_current_confidence, canonical_payload["confidence"])
        )

    return max(component_risks, key=lambda level: _RISK_RANK[level])
