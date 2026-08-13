"""Pure, deterministic structured analyst feedback collection (Block 13).

This module answers exactly one question: *given a target this project
already produced a decision/outcome for, and an analyst's own
structured response to it, what does that feedback record contain?* It
never re-derives, re-evaluates, or recomputes the target it comments
on -- `target_reference` is a caller-supplied, opaque reference only,
never looked up, never verified against Supabase or any other live
state.

In this MVP, "learning" means exactly:

    producing deterministic structured feedback records that may later
    support human-driven rule tuning, evaluation-case improvement,
    false-positive/false-negative analysis, or future training-dataset
    construction.

It never means, and this module never performs:

- automatic model retraining;
- online learning;
- prompt adaptation;
- automatic policy/rule rewriting;
- automatic evaluation-case updates;
- persistence of any kind -- `feedback_persisted` is always `False`;
- execution of any kind.

This module does not:

- call `core.agent_gateway.evaluate_tool_call`,
  `core.agent_identity_policy.evaluate_agent_tool_call`,
  `core.mutation_freeze.evaluate_mutation_freeze`,
  `core.decision_binding.create_decision_binding`/`verify_decision_binding`,
  or `core.ai_asset_registry.evaluate_ai_security_case` -- it never
  reproduces, re-checks, or recomputes the result it is recording
  feedback about. It imports only three small, already-public, fixed
  vocabularies from `core.decision_analysis` and `core.agent_gateway`
  (plain string tuples/frozensets, never a function) to validate an
  optional `corrected_value` against the domain that already governs
  the referenced target type;
- verify that `target_reference` or any `evidence_reference` entry
  actually exists in Supabase, a file, or any other store -- both are
  claimed, opaque references only, exactly like `agent_id` and
  `approval_reference` are claimed elsewhere in this project;
- authenticate an analyst. No analyst-identity field exists anywhere in
  this MVP's result -- there is no authentication mechanism anywhere in
  this project to honestly back one;
- treat a `"disagree"` record as automatically overriding, correcting,
  or invalidating the system decision it comments on. Recording
  disagreement is not the same as acting on it;
- read the system clock, an environment variable, or the filesystem;
- generate a random value of any kind, including a feedback identifier
  -- there is no persistence layer yet to assign one, so none is
  fabricated here;
- perform any I/O of any kind (no Supabase, no MCP, no SQL, no RPC, no
  subprocess, no network, no tool execution).

`create_analyst_feedback` is this module's only public function. It
never raises an exception for a legitimate analyst disagreement --
`analyst_decision: "disagree"` with a valid `error_category` and
`rationale` is a completely normal, successfully created feedback
record, not an error condition. `AnalystFeedbackError` is raised only
for structurally malformed input.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

from core.agent_gateway import DECISIONS as _SECURITY_POLICY_DECISIONS
from core.decision_analysis import DECISION_STATUSES

FEEDBACK_VERSION = "1"

TARGET_TYPES = frozenset({
    "investigation_decision",
    "security_policy_decision",
    "evaluation_result",
})

ANALYST_DECISIONS = frozenset({"agree", "disagree", "insufficient_evidence"})

ERROR_CATEGORIES = frozenset({
    "false_positive",
    "false_negative",
    "incorrect_severity",
    "incorrect_classification",
    "missing_evidence",
    "policy_mismatch",
    "evaluation_expectation_mismatch",
    "other",
})

# core.ai_asset_registry does not expose a public evaluation-outcome
# constant (its "pass"/"fail"/"not_applicable" vocabulary is used only
# inline in that already-completed module). This mirrors that same
# fixed vocabulary locally rather than modifying merged Blocks 11-12
# just to expose a constant.
_EVALUATION_RESULT_VALUES = frozenset({"pass", "fail", "not_applicable"})

# The domain corrected_value is validated against, keyed by target_type.
# investigation_decision and security_policy_decision reuse the real,
# already-public vocabularies those blocks already own; evaluation_result
# mirrors ai_asset_registry's own fixed, inline vocabulary (see above).
_CORRECTED_VALUE_DOMAINS: dict[str, frozenset[str]] = MappingProxyType({
    "investigation_decision": frozenset(DECISION_STATUSES),
    "security_policy_decision": frozenset(_SECURITY_POLICY_DECISIONS),
    "evaluation_result": _EVALUATION_RESULT_VALUES,
})


class AnalystFeedbackError(ValueError):
    """Raised when a supplied analyst-feedback input is structurally invalid.

    This is only raised for malformed input: an unrecognized
    `target_type`/`analyst_decision`/`error_category`, a blank or
    non-string `target_reference`, a missing `error_category`/
    `rationale` when `analyst_decision` is `"disagree"`, a present
    `error_category` when `analyst_decision` is not `"disagree"`, a
    blank `rationale`, a malformed `evidence_reference` (not `None`,
    not a non-empty list of non-blank strings), a `corrected_value` not
    valid for the selected `target_type`, or a malformed/timezone-naive
    `submitted_at`.

    It is never raised because an analyst disagrees, because evidence
    is judged insufficient, or because a correction is proposed --
    every one of those is a fully valid input this module represents
    through a normal, successfully created feedback record, not an
    exception.
    """


def _validate_target_type(value: Any) -> str:
    if not isinstance(value, str) or value not in TARGET_TYPES:
        raise AnalystFeedbackError("target_type must be one of the recognized target types")
    return value


def _validate_analyst_decision(value: Any) -> str:
    if not isinstance(value, str) or value not in ANALYST_DECISIONS:
        raise AnalystFeedbackError("analyst_decision must be one of the recognized analyst-decision values")
    return value


def _validate_target_reference(value: Any) -> str:
    if not isinstance(value, str):
        raise AnalystFeedbackError("target_reference must be a string")
    if not value.strip():
        raise AnalystFeedbackError("target_reference must not be blank")
    return value


def _validate_error_category_and_rationale(
    analyst_decision: str,
    error_category: Any,
    rationale: Any,
) -> tuple[str | None, str | None]:
    if rationale is not None and not isinstance(rationale, str):
        raise AnalystFeedbackError("rationale must be a string or null")
    if isinstance(rationale, str) and not rationale.strip():
        raise AnalystFeedbackError("rationale must not be blank")

    if analyst_decision == "disagree":
        if not isinstance(error_category, str) or error_category not in ERROR_CATEGORIES:
            raise AnalystFeedbackError(
                "error_category is required and must be a recognized category when analyst_decision is 'disagree'"
            )
        if rationale is None:
            raise AnalystFeedbackError("rationale is required when analyst_decision is 'disagree'")
        return error_category, rationale

    if error_category is not None:
        raise AnalystFeedbackError("error_category must be null when analyst_decision is not 'disagree'")
    return None, rationale


def _validate_evidence_reference(value: Any) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise AnalystFeedbackError("evidence_reference must be a list or null")
    if len(value) == 0:
        raise AnalystFeedbackError("evidence_reference must not be an empty list")
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise AnalystFeedbackError("every evidence_reference item must be a non-blank string")
    return list(value)


def _validate_corrected_value(target_type: str, value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AnalystFeedbackError("corrected_value must be a string or null")
    if value not in _CORRECTED_VALUE_DOMAINS[target_type]:
        raise AnalystFeedbackError("corrected_value is not a recognized value for this target_type")
    return value


def _validate_submitted_at(value: Any) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise AnalystFeedbackError("submitted_at must not be blank")
        iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(iso_text)
        except ValueError as exc:
            raise AnalystFeedbackError("submitted_at must be an aware datetime or an aware ISO-8601 string") from exc
    else:
        raise AnalystFeedbackError("submitted_at must be an aware datetime or an aware ISO-8601 string")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AnalystFeedbackError("submitted_at must include timezone information")

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def create_analyst_feedback(
    *,
    target_type: Any,
    target_reference: Any,
    analyst_decision: Any,
    error_category: Any,
    rationale: Any,
    evidence_reference: Any,
    corrected_value: Any,
    submitted_at: Any,
) -> dict[str, Any]:
    """Deterministically construct one structured analyst-feedback
    record about an already-existing, caller-referenced target, without
    ever recomputing that target's own result.

    All eight parameters are required and keyword-only, and none has a
    hidden default -- callers must explicitly pass `None` for any
    field they are not supplying. `target_type` must be one of
    `"investigation_decision"`, `"security_policy_decision"`,
    `"evaluation_result"`. `target_reference` must be a non-blank
    string; it is a claimed, opaque reference only, never validated
    against Supabase or any other live state, and its meaning depends
    on `target_type` (e.g. an investigation identifier, a description
    of the specific policy evaluation, or of the specific evaluation
    case run). `analyst_decision` must be one of `"agree"`,
    `"disagree"`, `"insufficient_evidence"` -- never the production
    policy vocabulary (`allow`/`require_approval`/`deny`) and never the
    evaluation-lab vocabulary (`pass`/`fail`/`not_applicable`).

    `error_category` and `rationale` are conditionally required
    together: when `analyst_decision` is `"disagree"`, `error_category`
    must be one of the eight recognized categories and `rationale` must
    be a non-blank string; when `analyst_decision` is not `"disagree"`,
    `error_category` must be `None` and `rationale` may be `None` or a
    non-blank string. A blank `rationale` string is never accepted in
    either case. `rationale`'s content is never reinterpreted,
    categorized, or validated beyond being non-blank.

    `evidence_reference` must be `None` or a non-empty list of
    non-blank strings -- each an opaque reference to an already-existing
    evidence item, never a raw evidence blob, a nested object, or an
    arbitrary dictionary, and never verified to exist. The returned
    list, when present, is always newly constructed -- the caller's own
    list is never mutated and never aliased.

    `corrected_value` must be `None` or a plain string drawn from the
    same already-established closed vocabulary that governs the
    selected `target_type` (`core.decision_analysis.DECISION_STATUSES`
    for `investigation_decision`; `allow`/`require_approval`/`deny` for
    `security_policy_decision`; `pass`/`fail`/`not_applicable` for
    `evaluation_result`) -- never an arbitrary free-form value, and
    never a value from a different target type's domain. It may be
    supplied alongside any `analyst_decision` value; this function
    never infers whether a correction is logically necessary and never
    silently derives one on the caller's behalf.

    `submitted_at` must be an aware `datetime` or an aware ISO-8601
    string; this function never reads the system clock itself, so the
    caller alone controls what moment is recorded.

    Returns a new dict containing exactly `feedback_version` (always
    `"1"`), `target_type`, `target_reference`, `analyst_decision`,
    `error_category`, `rationale`, `evidence_reference`,
    `corrected_value`, `submitted_at`, `feedback_persisted` (always
    `False` -- this function persists nothing anywhere), and
    `automatic_learning_performed` (always `False` -- this function
    never retrains, adapts, or rewrites anything).

    Raises `AnalystFeedbackError` for any structurally invalid input.
    Never raises because an analyst disagrees, because evidence is
    judged insufficient, or because a correction is proposed -- every
    one of those is represented in the returned record instead.
    """
    validated_target_type = _validate_target_type(target_type)
    validated_target_reference = _validate_target_reference(target_reference)
    validated_analyst_decision = _validate_analyst_decision(analyst_decision)
    validated_error_category, validated_rationale = _validate_error_category_and_rationale(
        validated_analyst_decision, error_category, rationale,
    )
    validated_evidence_reference = _validate_evidence_reference(evidence_reference)
    validated_corrected_value = _validate_corrected_value(validated_target_type, corrected_value)
    validated_submitted_at = _validate_submitted_at(submitted_at)

    return {
        "feedback_version": FEEDBACK_VERSION,
        "target_type": validated_target_type,
        "target_reference": validated_target_reference,
        "analyst_decision": validated_analyst_decision,
        "error_category": validated_error_category,
        "rationale": validated_rationale,
        "evidence_reference": validated_evidence_reference,
        "corrected_value": validated_corrected_value,
        "submitted_at": validated_submitted_at,
        "feedback_persisted": False,
        "automatic_learning_performed": False,
    }
