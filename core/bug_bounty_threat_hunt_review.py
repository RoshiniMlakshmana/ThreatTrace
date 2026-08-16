"""Pure orchestration for a bounded Threat Hunt feasibility boundary
(Full Security Lifecycle checkpoint).

## No real hunt execution engine exists in this project

This project has no deterministic core module, adapter, or telemetry
query capability that actually searches enterprise logs/EDR/SIEM data
for a hypothesis. Per this checkpoint's own explicit instruction, that
capability is never fabricated here. This module implements only the
smallest honest boundary: given a canonical finding, build a
deterministic hunt hypothesis and a small, closed set of telemetry
types that hypothesis would need, then reuse the exact same real,
already-existing `core.detection_telemetry.evaluate_telemetry_feasibility`
function (never reimplemented) to honestly decide whether that
telemetry is actually available.

## "Hunt evaluated" vs "Hunt executed against telemetry" -- never conflated

A `"hunt_candidate_created"` outcome means a hunt hypothesis was
deterministically scoped and its required telemetry was judged
feasible -- it never means any real log/EDR/SIEM query was performed.
No outcome this module can ever produce claims telemetry was actually
searched; `core.security_handoff.STAGE_OUTCOMES[("threat_hunt",
"plan")]` itself only ever allows `"planned"`/`"needs_review"`/
`"not_applicable"` for exactly this reason -- a hunt is always at most a
*plan* at this stage, never a completed search.

`review_threat_hunt_for_finding` is this module's only public function.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from core.detection_telemetry import evaluate_telemetry_feasibility

REVIEW_VERSION = "1"

OUTCOMES = frozenset({"hunt_candidate_created", "telemetry_gap", "not_applicable"})

# A small, closed, deterministic map from a canonical finding's own
# `vulnerability_class` to the telemetry a hunt hypothesis for that
# class would realistically need -- never invented per-finding, never
# expanded beyond `core.detection_telemetry.TELEMETRY_TYPES`.
_REQUIRED_TELEMETRY_BY_VULNERABILITY_CLASS: Mapping[str, tuple[str, ...]] = {
    "security_header_misconfiguration": ("web_server", "http_proxy"),
    "information_disclosure": ("web_server", "http_proxy"),
    "cors_misconfiguration": ("web_server", "http_proxy"),
    "redirect_observation": ("web_server", "http_proxy"),
    "exposed_metadata": ("web_server", "http_proxy"),
    "http_method_observation": ("web_server", "http_proxy"),
    "input_reflection": ("web_server", "application_log"),
    "dast_observation": ("web_server", "application_log"),
    "nuclei_template_match": ("web_server", "application_log"),
}
_DEFAULT_REQUIRED_TELEMETRY: tuple[str, ...] = ("web_server",)


class ThreatHuntReviewError(ValueError):
    """Raised only for a structurally unusable `canonical_finding`
    argument to this module itself. Never raised because telemetry is
    unavailable -- that is `"telemetry_gap"`, a normal result."""


def _validate_finding(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ThreatHuntReviewError("INVALID_FINDING: canonical_finding must be a mapping")
    finding_id = value.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise ThreatHuntReviewError("INVALID_FINDING: canonical_finding['finding_id'] must be a non-blank string")
    return value


def _build_hunt_hypothesis(finding: Mapping[str, Any]) -> str:
    title = finding.get("title") or finding.get("finding_id")
    return (
        f"If this finding ({title}) reflects genuine attacker activity rather than a scanner "
        "observation, look for repeated/anomalous requests to the affected path in the "
        "available telemetry, distinct from ordinary application traffic."
    )


def review_threat_hunt_for_finding(
    *, canonical_finding: Any, available_telemetry: Any,
) -> dict[str, Any]:
    """Deterministically evaluate hunt feasibility for one canonical Bug
    Bounty finding. Both parameters are keyword-only and required.
    `canonical_finding` must be a mapping shaped at minimum like
    `core.bug_bounty_final_report`'s own canonical finding contract
    (only `finding_id`, `title`, `vulnerability_class` are read).
    `available_telemetry` must be a list of `core.detection_telemetry.
    TELEMETRY_TYPES` values (may be empty) -- the exact same shape and
    meaning `run_detection_workflow` already requires for its own
    `telemetry_context['available_telemetry']`, never a second,
    differently-shaped telemetry contract.

    `required_telemetry` is derived deterministically from the
    finding's own `vulnerability_class` via a small, closed, fixed map
    -- never invented per-finding, never derived from free-text title
    matching.

    Feasibility is decided by calling the real, unmodified
    `core.detection_telemetry.evaluate_telemetry_feasibility` (never
    reimplemented here) with `required_telemetry_candidates=
    required_telemetry, available_telemetry=available_telemetry` --
    `siem`/`edr`/`cloud_provider`/`environment`/`industry` are never
    supplied (this stage only asks "is the raw telemetry type present,"
    never a deployment-specific completeness judgment).

    `outcome` is `"telemetry_gap"` when that function's own `decision`
    is `"TELEMETRY_GAP"` (required telemetry entirely absent);
    `"hunt_candidate_created"` when `decision` is `"GENERATE_RULE"` or
    `"PARTIAL_COVERAGE"` (at least some of the required telemetry
    exists, so a bounded hunt hypothesis could genuinely be scoped).
    `outcome` is never `"not_applicable"` from this function itself --
    that value exists in `OUTCOMES` only because it is one of
    `core.security_handoff`'s own allowed `("threat_hunt", "plan")`
    outcomes; the caller may choose to record it separately for a
    finding this stage was never run against at all.

    Returns a new dict containing exactly `review_version` (always
    `"1"`), `finding_id`, `hunt_hypothesis`, `required_telemetry`
    (tuple), `available_telemetry` (list, echoed unchanged),
    `missing_telemetry` (list, from the underlying feasibility result),
    `outcome` (one of `OUTCOMES`), `stage_evaluated` (always `True`),
    `human_review_required` (always `True`), `execution_performed`
    (always `False` -- no real telemetry query was ever performed,
    only a feasibility judgment over caller-declared availability).

    Raises `ThreatHuntReviewError` only for a structurally invalid
    `canonical_finding`.
    """
    validated = _validate_finding(canonical_finding)
    vulnerability_class = validated.get("vulnerability_class")
    required_telemetry = _REQUIRED_TELEMETRY_BY_VULNERABILITY_CLASS.get(
        vulnerability_class, _DEFAULT_REQUIRED_TELEMETRY,
    )

    feasibility = evaluate_telemetry_feasibility(
        required_telemetry_candidates=list(required_telemetry), available_telemetry=available_telemetry,
    )
    outcome = "telemetry_gap" if feasibility["decision"] == "TELEMETRY_GAP" else "hunt_candidate_created"

    return {
        "review_version": REVIEW_VERSION, "finding_id": validated["finding_id"],
        "hunt_hypothesis": _build_hunt_hypothesis(validated),
        "required_telemetry": required_telemetry, "available_telemetry": list(available_telemetry or []),
        "missing_telemetry": feasibility["missing_sources"], "outcome": outcome,
        "stage_evaluated": True, "human_review_required": True, "execution_performed": False,
    }
