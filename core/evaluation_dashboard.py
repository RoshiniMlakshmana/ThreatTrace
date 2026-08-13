"""Pure, deterministic evaluation/audit dashboard summary (Block 14,
module 2 of 2).

This module answers one question only: *given a supplied sequence of
already-created audit records, what deterministic counts and chain-
verification status can be reported about them?* It is a **reporting
API only** -- not a web UI, not live, not real-time, not historical
telemetry, not SOC monitoring, not a SIEM integration. It requires no
charts and queries no external state.

This module never reimplements chain verification -- it always calls
the real, unmodified `core.tamper_evident_audit.verify_audit_chain` and
reports its result honestly, including when the supplied chain is
internally invalid or its trusted anchor does not match. A broken audit
chain is surfaced, never hidden or silently treated as valid.

This module does not:

- accept raw Block 8/9/10/Mutation-Freeze/11-12/13 results directly --
  its only input is already-created audit records (see
  `core.tamper_evident_audit.create_audit_record`). A caller holding an
  unwrapped result must normalize it into an audit record first;
- rerun a security evaluation, reinterpret analyst feedback, change any
  decision, trigger learning, or modify any policy. Every count in this
  module's output is derived only from the `event_summary.outcome`/
  `case_type`/`error_category` values already present in the supplied
  records -- never recomputed;
- read the system clock, an environment variable, or the filesystem;
- generate a random value of any kind;
- perform any I/O of any kind (no Supabase, no MCP, no SQL, no RPC, no
  subprocess, no network, no tool execution);
- persist anything, or claim any record was persisted;
- compute a rate, a percentage, a trend, or a risk score -- only raw
  counts are ever returned, since a percentage's denominator semantics
  would be ambiguous without persisted time-series data this MVP does
  not have;
- fabricate a count for a record it cannot safely read. When an
  individual supplied record is too malformed to safely determine its
  `event_type`/`event_summary`, this module raises
  `EvaluationDashboardError` rather than silently skipping or guessing.

`summarize_audit_dashboard` is this module's only public function.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from core.tamper_evident_audit import AuditRecordError, EVENT_TYPES, verify_audit_chain

DASHBOARD_VERSION = "1"

_EVENT_SUMMARY_ALLOWED_KEYS = frozenset({"outcome", "case_type", "error_category"})

_EVALUATION_OUTCOMES = frozenset({"pass", "fail", "not_applicable"})
_FEEDBACK_OUTCOMES = frozenset({"agree", "disagree", "insufficient_evidence"})
_POLICY_OUTCOMES = frozenset({"allow", "require_approval", "deny"})


class EvaluationDashboardError(ValueError):
    """Raised when a supplied dashboard input is structurally invalid.

    This is only raised for malformed input: a non-list `records`, a
    `records` entry too malformed to safely read its `event_type`/
    `event_summary`, a `security_evaluation_result`/`analyst_feedback`/
    `security_policy_decision` record whose `event_summary.outcome` is
    not a value recognized for that event type, or a malformed
    top-level API input rejected by `core.tamper_evident_audit.
    verify_audit_chain`'s own `AuditRecordError` (translated here
    without exposing internal exception details).

    It is never raised because the supplied audit chain is internally
    invalid, or because its trusted anchor does not match -- both are
    represented honestly in the returned summary's `audit` section
    instead, never hidden and never causing a crash.
    """


def _try_extract_dashboard_fields(record: Any) -> dict[str, Any] | None:
    """Minimally and safely extract `event_type`/`event_summary` from
    one claimed audit record for aggregation purposes only -- never
    raises, and never duplicates `core.tamper_evident_audit`'s own
    full record-structure or digest/chain validation, which remains
    exclusively `verify_audit_chain`'s concern.
    """
    if not isinstance(record, Mapping):
        return None

    event_type = record.get("event_type")
    if not isinstance(event_type, str) or event_type not in EVENT_TYPES:
        return None

    if "event_summary" not in record:
        return None
    event_summary = record["event_summary"]
    if event_summary is not None:
        if not isinstance(event_summary, Mapping):
            return None
        if set(event_summary) - _EVENT_SUMMARY_ALLOWED_KEYS:
            return None
        for key, item in event_summary.items():
            if not isinstance(item, str) or not item.strip():
                return None
        event_summary = dict(event_summary)

    return {"event_type": event_type, "event_summary": event_summary}


def summarize_audit_dashboard(
    *,
    records: Any,
    expected_head_digest: Any = None,
) -> dict[str, Any]:
    """Deterministically summarize a supplied sequence of already-
    created audit records: chain-verification status plus counts by
    event type, security-evaluation outcome, analyst-feedback decision,
    and security-policy decision.

    `records` is required and keyword-only, and must be a list of
    already-created audit records (may be empty). `expected_head_digest`
    is optional and keyword-only, passed through unchanged to
    `core.tamper_evident_audit.verify_audit_chain`.

    Returns a new dict containing exactly `dashboard_version` (always
    `"1"`), `audit` (a summary of the real `verify_audit_chain` result:
    `total_records`, `verification_outcome`, `internal_chain_valid`,
    `trusted_anchor_verified`, `head_digest`, `observed_evidence`),
    `event_type_counts` (all seven recognized event types, always
    present, initialized at `0`), `evaluation_counts`
    (`outcome_counts` for `pass`/`fail`/`not_applicable`, and
    `case_type_counts` for whatever case-type strings were actually
    observed), `feedback_counts` (`decision_counts` for
    `agree`/`disagree`/`insufficient_evidence`, and
    `error_category_counts` for whatever categories were actually
    observed), `policy_counts` (`decision_counts` for
    `allow`/`require_approval`/`deny`), and `execution_performed`
    (always `False`).

    Aggregation proceeds even when the supplied chain is internally
    invalid or its anchor does not match -- the counts reflect only
    what is visibly present in the supplied records, and the `audit`
    section's own fields make the broken/unanchored state explicit
    rather than implying the counts are trusted, verified historical
    truth, or authenticated metrics.

    An event with `event_summary: None` is counted in
    `event_type_counts` only -- no outcome/category counter is
    incremented, and none is ever fabricated. A `security_evaluation_
    result`/`analyst_feedback`/`security_policy_decision` record whose
    `event_summary.outcome` is present but not recognized for that
    event type raises `EvaluationDashboardError`.

    No timestamp, rate, percentage, trend, or risk score is ever
    included. Never mutates the caller-supplied `records` list or any
    record within it.
    """
    if not isinstance(records, list):
        raise EvaluationDashboardError("records must be a list")

    try:
        verification = verify_audit_chain(records=records, expected_head_digest=expected_head_digest)
    except AuditRecordError as exc:
        raise EvaluationDashboardError(str(exc)) from exc

    event_type_counts = {event_type: 0 for event_type in sorted(EVENT_TYPES)}
    evaluation_outcome_counts = {outcome: 0 for outcome in sorted(_EVALUATION_OUTCOMES)}
    case_type_counts: dict[str, int] = {}
    feedback_decision_counts = {outcome: 0 for outcome in sorted(_FEEDBACK_OUTCOMES)}
    error_category_counts: dict[str, int] = {}
    policy_decision_counts = {outcome: 0 for outcome in sorted(_POLICY_OUTCOMES)}

    for record in records:
        fields = _try_extract_dashboard_fields(record)
        if fields is None:
            raise EvaluationDashboardError("a supplied record could not be safely aggregated")

        event_type = fields["event_type"]
        event_type_counts[event_type] += 1

        summary = fields["event_summary"]
        if summary is None:
            continue

        outcome = summary.get("outcome")
        case_type = summary.get("case_type")
        error_category = summary.get("error_category")

        if event_type == "security_evaluation_result":
            if outcome is not None:
                if outcome not in _EVALUATION_OUTCOMES:
                    raise EvaluationDashboardError(
                        "security_evaluation_result event_summary.outcome is not a recognized evaluation outcome"
                    )
                evaluation_outcome_counts[outcome] += 1
            if case_type is not None:
                case_type_counts[case_type] = case_type_counts.get(case_type, 0) + 1

        elif event_type == "analyst_feedback":
            if outcome is not None:
                if outcome not in _FEEDBACK_OUTCOMES:
                    raise EvaluationDashboardError(
                        "analyst_feedback event_summary.outcome is not a recognized analyst-decision value"
                    )
                feedback_decision_counts[outcome] += 1
            if error_category is not None:
                error_category_counts[error_category] = error_category_counts.get(error_category, 0) + 1

        elif event_type == "security_policy_decision":
            if outcome is not None:
                if outcome not in _POLICY_OUTCOMES:
                    raise EvaluationDashboardError(
                        "security_policy_decision event_summary.outcome is not a recognized policy decision"
                    )
                policy_decision_counts[outcome] += 1

        # investigation_decision, approval_decision, shadow_execution_result,
        # and decision_binding_result are counted in event_type_counts only --
        # this MVP dashboard builds no separate outcome breakdown for them,
        # and never rejects their event_summary content merely because it
        # is not aggregated further.

    return {
        "dashboard_version": DASHBOARD_VERSION,
        "audit": {
            "total_records": verification["record_count"],
            "verification_outcome": verification["verification_outcome"],
            "internal_chain_valid": verification["internal_chain_valid"],
            "trusted_anchor_verified": verification["trusted_anchor_verified"],
            "head_digest": verification["head_digest"],
            "observed_evidence": verification["observed_evidence"],
        },
        "event_type_counts": dict(sorted(event_type_counts.items())),
        "evaluation_counts": {
            "outcome_counts": evaluation_outcome_counts,
            "case_type_counts": dict(sorted(case_type_counts.items())),
        },
        "feedback_counts": {
            "decision_counts": feedback_decision_counts,
            "error_category_counts": dict(sorted(error_category_counts.items())),
        },
        "policy_counts": {
            "decision_counts": policy_decision_counts,
        },
        "execution_performed": False,
    }
