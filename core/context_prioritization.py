"""Pure, deterministic organization-context operational prioritization
(Block 15B, checkpoint A).

This module answers exactly one question: *given an already-existing,
already-true technical finding (from `core.bug_bounty_findings.
create_bug_bounty_finding`, or any object shaped like its result) and a
caller-supplied organization-context object, how urgently should THIS
organization investigate/respond to it?*

## Technical truth is never the same thing as organizational priority

This module never changes, and never even reads for the purpose of
recomputing, any truth-bearing field of the supplied finding --
`finding_status`, `vulnerability_class`, `technical_severity`,
`confidence`, `evidence`, `owasp_category`, `cwe`, `validation`,
`remediation`, `detection_opportunity` all remain exactly what the
finding already says. `prioritize_finding` only ever *echoes*
`finding_id`/`technical_severity`/`finding_status`/`confidence` in its
own result -- it never reproduces, mutates, or returns the finding
object itself. `operational_priority` is a separate, new judgment about
*urgency of attention*, layered on top of an unchanged technical truth.

## Organization context is caller-supplied, unauthenticated, v1 honesty

`context` is caller-supplied technical/organizational configuration
only, exactly like `core.bug_bounty_scope`'s own `allowed_origins`/
`allowed_paths` are caller-supplied technical scope. This module:

- never authenticates who supplied `context`, and never claims to;
- never infers any context value from the finding's own `target`,
  `affected_path`, `title`, `evidence`, or any other field -- context is
  a wholly separate input channel, and this module never reads the
  finding for anything beyond the five truth-bearing/status fields it
  is explicitly allowed to read (see below);
- never fetches, verifies, or refreshes context from anywhere --
  `threat_activity` is not a threat-intelligence lookup, `detection_
  coverage` is not Red-Team-verified, `compensating_controls` are not
  independently validated, and `regulatory_relevance` is never a
  compliance determination;
- treats context as possibly incomplete or stale, and represents that
  honestly through `context_completeness`/`CONTEXT_INCOMPLETE` rather
  than silently treating `"unknown"` as favorable.

## What `operational_priority` is, and is not

`operational_priority` is a **deterministic investigation/response
prioritization recommendation** only. It is never: vulnerability truth,
a replacement for `technical_severity`, a CVSS score, a probability of
compromise, a business-loss prediction, a compliance determination, or
an analyst approval. `human_review_required` is always `True` and
`execution_performed` is always `False` -- this module never closes a
finding, approves remediation, deploys a control, overrides an analyst,
or triggers any Blue/Purple/Red action.

## Candidate findings can still be operationally critical

`finding_status` contributes a bounded, nominal, negative modifier
(`candidate`: -1, `observation`: -2) reflecting that unconfirmed
findings generally deserve somewhat less urgency than a validated one
-- but this module deliberately does **not** impose a hard ceiling
preventing a `candidate` finding from reaching `operational_priority:
"critical"`. Operational priority measures *urgency of investigation*,
not confirmation status: a `candidate` finding on a critical,
internet-facing, actively-threatened production asset can and should
still receive urgent analyst attention, while its `finding_status`
correctly remains `candidate` throughout. Never conflate the two.

## The bounded modifier is a safety property, not a suggestion

All triggered scoring modifiers are summed into `raw_modifier`, then
clamped to `applied_modifier` in `[-1, +2]` before being added to the
`technical_severity`-derived `base` (`low=1` .. `critical=4`) and
re-clamped to `[1, 4]` for `final`. This guarantees, unconditionally:
a `critical`-severity finding can never drop below `high` regardless of
how favorable the supplied context is, and a `low`-severity finding can
never rise above `high` regardless of how unfavorable it is. No single
context field, and no combination of them, can silently erase a serious
technical finding, or manufacture a critical one from a trivial finding.

## Industry is descriptive only, structurally excluded from scoring

`industry` is echoed in the output for traceability and future research
use, but contributes **zero** to every score for every value --
`financial_services` never scores differently from `general` given
otherwise identical context. This is enforced structurally (industry is
never read by any scoring branch), not merely documented, to prevent
industry stereotyping.

## No external capabilities

This module performs no network access, no filesystem access, no
environment-variable reads, no subprocess calls, no system-clock reads,
no randomness, no Supabase/database access, no MCP calls, and no LLM/
model calls of any kind. It never imports `core.bug_bounty_assessment`,
`adapters.bug_bounty_http`, or `core.bug_bounty_findings` -- it consumes
only a locally-owned, minimal structural contract for a finding-shaped
mapping, exactly like `core.mutation_freeze` consumes a duck-typed
Block 9 result without importing `core.agent_identity_policy`.

`prioritize_finding` is this module's only public function.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

PRIORITIZATION_VERSION = "1"

FINDING_STATUSES = frozenset({"observation", "candidate", "validated"})
TECHNICAL_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
CONFIDENCE_LEVELS = frozenset({"low", "medium", "high"})

INDUSTRIES = frozenset({
    "financial_services", "healthcare", "technology", "retail",
    "government", "education", "general", "other",
})
ENVIRONMENTS = frozenset({"production", "staging", "development", "test", "sandbox"})
ASSET_CRITICALITIES = frozenset({"low", "medium", "high", "critical"})
EXPOSURES = frozenset({"internal", "restricted", "partner", "internet_facing"})
DATA_SENSITIVITIES = frozenset({"public", "internal", "confidential", "restricted"})
DETECTION_COVERAGES = frozenset({"none", "partial", "strong", "unknown"})
COMPENSATING_CONTROLS_LEVELS = frozenset({"none", "partial", "strong", "unknown"})
THREAT_ACTIVITIES = frozenset({"unknown", "none_observed", "emerging", "active"})
REGULATORY_RELEVANCES = frozenset({"none", "potential", "direct", "unknown"})

_CONTEXT_REQUIRED_FIELDS = (
    "context_version",
    "industry",
    "environment",
    "asset_criticality",
    "exposure",
    "data_sensitivity",
    "detection_coverage",
    "compensating_controls",
    "threat_activity",
    "regulatory_relevance",
)

# The only fields ever read from the supplied finding. Every other field
# (target, affected_path, title, evidence content, response excerpts,
# reproduction_summary, remediation, detection_opportunity, ...) is
# never inspected -- organizational context is never inferred from any
# of them.
_FINDING_TRUTH_BEARING_PRESENCE_FIELDS = ("vulnerability_class", "evidence", "validation", "owasp_category", "cwe")

_SEVERITY_ORDINAL: Mapping[str, int] = MappingProxyType({
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
})

_ORDINAL_PRIORITY: Mapping[int, str] = MappingProxyType({
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
})

_APPLIED_MODIFIER_MIN = -1
_APPLIED_MODIFIER_MAX = 2
_FINAL_SCORE_MIN = 1
_FINAL_SCORE_MAX = 4

# Fixed, closed, exactly fifteen reason codes -- each corresponds to
# exactly one specific scoring rule, emitted at most once per call,
# always in this fixed order, regardless of which underlying dimension
# triggered it.
_REASON_ORDER = (
    "VALIDATED_FINDING",
    "CANDIDATE_FINDING",
    "OBSERVATION_FINDING",
    "LOW_CONFIDENCE",
    "PRODUCTION_ENVIRONMENT",
    "ISOLATED_ENVIRONMENT",
    "CRITICAL_ASSET",
    "LOW_CRITICALITY_ASSET",
    "INTERNET_EXPOSED",
    "SENSITIVE_DATA",
    "NO_DETECTION_COVERAGE",
    "STRONG_COMPENSATING_CONTROLS",
    "ACTIVE_THREAT_ACTIVITY",
    "DIRECT_REGULATORY_RELEVANCE",
    "CONTEXT_INCOMPLETE",
)

_REASON_MODIFIER: Mapping[str, int] = MappingProxyType({
    "VALIDATED_FINDING": 0,
    "CANDIDATE_FINDING": -1,
    "OBSERVATION_FINDING": -2,
    "LOW_CONFIDENCE": -1,
    "PRODUCTION_ENVIRONMENT": 1,
    "ISOLATED_ENVIRONMENT": -1,
    "CRITICAL_ASSET": 1,
    "LOW_CRITICALITY_ASSET": -1,
    "INTERNET_EXPOSED": 1,
    "SENSITIVE_DATA": 1,
    "NO_DETECTION_COVERAGE": 1,
    "STRONG_COMPENSATING_CONTROLS": -1,
    "ACTIVE_THREAT_ACTIVITY": 1,
    "DIRECT_REGULATORY_RELEVANCE": 1,
    "CONTEXT_INCOMPLETE": 0,
})

_REASON_MESSAGE: Mapping[str, str] = MappingProxyType({
    "VALIDATED_FINDING": "The finding has been deterministically validated within its implemented check.",
    "CANDIDATE_FINDING": "The finding is a candidate; deterministic confirmation is incomplete.",
    "OBSERVATION_FINDING": "The finding is a raw observation, not asserted as a vulnerability.",
    "LOW_CONFIDENCE": "The finding's own confidence is low.",
    "PRODUCTION_ENVIRONMENT": "The caller-supplied environment is production.",
    "ISOLATED_ENVIRONMENT": "The caller-supplied environment is non-production and considered isolated.",
    "CRITICAL_ASSET": "The affected asset is caller-classified as critical.",
    "LOW_CRITICALITY_ASSET": "The affected asset is caller-classified as low criticality.",
    "INTERNET_EXPOSED": "The affected asset is caller-classified as internet-facing.",
    "SENSITIVE_DATA": "The affected asset is caller-classified as handling confidential or restricted data.",
    "NO_DETECTION_COVERAGE": "No known detection coverage is caller-claimed for this class of finding.",
    "STRONG_COMPENSATING_CONTROLS": (
        "Caller-asserted strong compensating controls exist; this module never independently verifies them."
    ),
    "ACTIVE_THREAT_ACTIVITY": "Threat activity relevant to this finding is caller-classified as active.",
    "DIRECT_REGULATORY_RELEVANCE": (
        "This finding is caller-classified as directly regulatory-relevant; this is never a compliance determination."
    ),
    "CONTEXT_INCOMPLETE": "One or more organization-context fields were supplied as 'unknown'.",
})


class ContextPrioritizationError(ValueError):
    """Raised when a supplied `finding` or `context` is structurally
    invalid: `finding` missing a required truth-bearing field or
    carrying an unrecognized `finding_version`/`finding_status`/
    `technical_severity`/`confidence`, or `context` missing/adding a
    field or carrying a value outside its fixed closed vocabulary.

    Never raised because a finding is a `"candidate"` or an
    `"observation"`, because context is incomplete (`"unknown"`
    values), or because the computed `operational_priority` happens to
    equal, exceed, or fall short of `technical_severity` -- every one
    of those is a fully valid, successfully computed result, not an
    error condition.
    """


# ---------------------------------------------------------------------------
# Finding validation -- a minimal, locally-owned structural contract.
# The producing module is deliberately never imported; only a fixed,
# minimal set of finding fields is ever inspected, named below.
# ---------------------------------------------------------------------------


def _validate_finding(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ContextPrioritizationError("finding must be a mapping")

    if value.get("finding_version") != "1":
        raise ContextPrioritizationError("finding['finding_version'] must be '1'")

    finding_id = value.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise ContextPrioritizationError("finding['finding_id'] must be a non-blank string")

    finding_status = value.get("finding_status")
    if finding_status not in FINDING_STATUSES:
        raise ContextPrioritizationError("finding['finding_status'] must be one of the recognized finding statuses")

    technical_severity = value.get("technical_severity")
    if technical_severity not in TECHNICAL_SEVERITIES:
        raise ContextPrioritizationError(
            "finding['technical_severity'] must be one of the recognized technical severities"
        )

    confidence = value.get("confidence")
    if confidence not in CONFIDENCE_LEVELS:
        raise ContextPrioritizationError("finding['confidence'] must be one of the recognized confidence levels")

    for field in _FINDING_TRUTH_BEARING_PRESENCE_FIELDS:
        if field not in value:
            raise ContextPrioritizationError(f"finding is missing required field: {field!r}")

    return {
        "finding_id": finding_id,
        "finding_status": finding_status,
        "technical_severity": technical_severity,
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Context validation.
# ---------------------------------------------------------------------------


def _require_vocabulary_value(mapping: Mapping[str, Any], field_name: str, vocabulary: frozenset[str]) -> str:
    value = mapping.get(field_name)
    if not isinstance(value, str) or value not in vocabulary:
        raise ContextPrioritizationError(f"context[{field_name!r}] must be one of the recognized values")
    return value


def _validate_context(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ContextPrioritizationError("context must be a mapping")

    if set(value) != set(_CONTEXT_REQUIRED_FIELDS):
        raise ContextPrioritizationError("context must contain exactly the ten required fields")

    if value.get("context_version") != "1":
        raise ContextPrioritizationError("context['context_version'] must be '1'")

    return {
        "context_version": "1",
        "industry": _require_vocabulary_value(value, "industry", INDUSTRIES),
        "environment": _require_vocabulary_value(value, "environment", ENVIRONMENTS),
        "asset_criticality": _require_vocabulary_value(value, "asset_criticality", ASSET_CRITICALITIES),
        "exposure": _require_vocabulary_value(value, "exposure", EXPOSURES),
        "data_sensitivity": _require_vocabulary_value(value, "data_sensitivity", DATA_SENSITIVITIES),
        "detection_coverage": _require_vocabulary_value(value, "detection_coverage", DETECTION_COVERAGES),
        "compensating_controls": _require_vocabulary_value(
            value, "compensating_controls", COMPENSATING_CONTROLS_LEVELS
        ),
        "threat_activity": _require_vocabulary_value(value, "threat_activity", THREAT_ACTIVITIES),
        "regulatory_relevance": _require_vocabulary_value(value, "regulatory_relevance", REGULATORY_RELEVANCES),
    }


# ---------------------------------------------------------------------------
# Scoring.
# ---------------------------------------------------------------------------


def _evaluate_reasons(
    *, finding_status: str, confidence: str, context: Mapping[str, str],
) -> tuple[list[dict[str, Any]], int, bool]:
    triggered: set[str] = set()
    incomplete = False

    if finding_status == "validated":
        triggered.add("VALIDATED_FINDING")
    elif finding_status == "candidate":
        triggered.add("CANDIDATE_FINDING")
    else:
        triggered.add("OBSERVATION_FINDING")

    if confidence == "low":
        triggered.add("LOW_CONFIDENCE")

    environment = context["environment"]
    if environment == "production":
        triggered.add("PRODUCTION_ENVIRONMENT")
    elif environment in ("development", "test", "sandbox"):
        triggered.add("ISOLATED_ENVIRONMENT")

    asset_criticality = context["asset_criticality"]
    if asset_criticality == "critical":
        triggered.add("CRITICAL_ASSET")
    elif asset_criticality == "low":
        triggered.add("LOW_CRITICALITY_ASSET")

    if context["exposure"] == "internet_facing":
        triggered.add("INTERNET_EXPOSED")

    if context["data_sensitivity"] in ("confidential", "restricted"):
        triggered.add("SENSITIVE_DATA")

    detection_coverage = context["detection_coverage"]
    if detection_coverage == "none":
        triggered.add("NO_DETECTION_COVERAGE")
    elif detection_coverage == "unknown":
        incomplete = True

    compensating_controls = context["compensating_controls"]
    if compensating_controls == "strong":
        triggered.add("STRONG_COMPENSATING_CONTROLS")
    elif compensating_controls == "unknown":
        incomplete = True

    threat_activity = context["threat_activity"]
    if threat_activity == "active":
        triggered.add("ACTIVE_THREAT_ACTIVITY")
    elif threat_activity == "unknown":
        incomplete = True

    regulatory_relevance = context["regulatory_relevance"]
    if regulatory_relevance == "direct":
        triggered.add("DIRECT_REGULATORY_RELEVANCE")
    elif regulatory_relevance == "unknown":
        incomplete = True

    if incomplete:
        triggered.add("CONTEXT_INCOMPLETE")

    ordered_codes = [code for code in _REASON_ORDER if code in triggered]
    reasons = [
        {"code": code, "modifier": _REASON_MODIFIER[code], "message": _REASON_MESSAGE[code]}
        for code in ordered_codes
    ]
    raw_modifier = sum(_REASON_MODIFIER[code] for code in ordered_codes)

    return reasons, raw_modifier, incomplete


def prioritize_finding(*, finding: Any, context: Any) -> dict[str, Any]:
    """Deterministically compute one operational-priority recommendation
    for an already-existing technical finding, given caller-supplied
    organization context. Performs no I/O of any kind.

    Both parameters are required and keyword-only. `finding` must be a
    mapping shaped at minimum like `core.bug_bounty_findings.
    create_bug_bounty_finding`'s own return value -- `finding_version ==
    "1"`, a non-blank `finding_id`, a recognized `finding_status`/
    `technical_severity`/`confidence`, and the presence (not the
    content) of `vulnerability_class`/`evidence`/`validation`/
    `owasp_category`/`cwe`. This function never recomputes, inspects the
    content of, or returns any of those five truth-bearing fields, and
    never inspects any other finding field (`target`, `affected_path`,
    `title`, `reproduction_summary`, `remediation`,
    `detection_opportunity`, ...) for any purpose -- organizational
    context is never inferred from any of them. `context` must be a
    mapping containing exactly the ten fields documented in the module
    docstring, each a value from its own fixed closed vocabulary --
    values are never trimmed, lowercased, or otherwise normalized before
    comparison.

    Neither `finding` nor `context` (nor any nested value within either)
    is ever mutated, and no mutable object from either is retained by
    reference in the result -- the returned mapping and every nested
    list/mapping within it are newly constructed.

    Returns a new dict containing exactly `prioritization_version`
    (always `"1"`), `finding_id`, `technical_severity`, `finding_status`,
    `confidence` (all four echoed unchanged from `finding`), `context`
    (the validated, newly constructed ten-field context), `priority_score`
    (`base`, `raw_modifier`, `applied_modifier`, `final` -- see module
    docstring for the exact clamp semantics), `operational_priority`
    (`"low"`/`"medium"`/`"high"`/`"critical"`, mapped from `priority_score
    .final`), `priority_direction` (`"raised"`/`"unchanged"`/`"lowered"`,
    comparing `priority_score.final` to `priority_score.base`),
    `priority_reasons` (a deduplicated, fixed-order list of `{code,
    modifier, message}` entries from the fixed fifteen-code vocabulary),
    `context_completeness` (`"complete"`/`"incomplete"`),
    `human_review_required` (always `True`), `execution_performed`
    (always `False`).

    Raises `ContextPrioritizationError` for any structurally invalid
    `finding`/`context`. Never raises because a finding is a candidate
    or an observation, because context is incomplete, or because the
    computed operational priority happens to equal, exceed, or fall
    short of the finding's own technical severity -- every one of those
    is a normal, successfully computed result.
    """
    validated_finding = _validate_finding(finding)
    validated_context = _validate_context(context)

    reasons, raw_modifier, incomplete = _evaluate_reasons(
        finding_status=validated_finding["finding_status"],
        confidence=validated_finding["confidence"],
        context=validated_context,
    )

    base = _SEVERITY_ORDINAL[validated_finding["technical_severity"]]
    applied_modifier = max(_APPLIED_MODIFIER_MIN, min(_APPLIED_MODIFIER_MAX, raw_modifier))
    final = max(_FINAL_SCORE_MIN, min(_FINAL_SCORE_MAX, base + applied_modifier))
    operational_priority = _ORDINAL_PRIORITY[final]

    if final > base:
        priority_direction = "raised"
    elif final < base:
        priority_direction = "lowered"
    else:
        priority_direction = "unchanged"

    return {
        "prioritization_version": PRIORITIZATION_VERSION,
        "finding_id": validated_finding["finding_id"],
        "technical_severity": validated_finding["technical_severity"],
        "finding_status": validated_finding["finding_status"],
        "confidence": validated_finding["confidence"],
        "context": validated_context,
        "priority_score": {
            "base": base,
            "raw_modifier": raw_modifier,
            "applied_modifier": applied_modifier,
            "final": final,
        },
        "operational_priority": operational_priority,
        "priority_direction": priority_direction,
        "priority_reasons": reasons,
        "context_completeness": "incomplete" if incomplete else "complete",
        "human_review_required": True,
        "execution_performed": False,
    }
