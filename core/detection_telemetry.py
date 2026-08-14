"""Pure, deterministic Telemetry Feasibility evaluation (Block 15H-I).

This module answers exactly one question, and it is always the first
question asked before any rule is drafted: *given the telemetry types a
Detection Trigger candidly needs, and what an analyst says is actually
available in their environment, can this condition be meaningfully
detected at all?*

## Absent telemetry is never quietly ignored

If none of a trigger's `required_telemetry_candidates` overlaps with the
caller's own `available_telemetry`, this module returns `decision:
"TELEMETRY_GAP"` -- it never fabricates a "useful" rule against
telemetry that does not exist, and never silently drops the requirement
to make a rule appear generatable. An empty `required_telemetry_candidates`
list (a trigger with no clear telemetry mapping at all -- e.g. a missing
CSP header) is *also* `"TELEMETRY_GAP"`, honestly: there is nothing to
check feasibility against, so there is nothing to generate a meaningful
rule from.

## Organization context is caller-supplied, unauthenticated, never inferred

`available_telemetry`/`siem`/`edr`/`cloud_provider`/`environment`/
`industry` are exactly what the caller says -- this module never
verifies a SIEM/EDR actually exists, never infers `available_telemetry`
from `industry`, and never treats an omitted optional field as
"probably available." Missing optional context is `None`, never guessed.

## No I/O, no execution, ever

This module performs no network, filesystem, environment-variable,
subprocess, system-clock, or randomness access, and imports no other
`core.*` module.

`DetectionTelemetryError` and `evaluate_telemetry_feasibility` are this
module's public symbols (plus `TELEMETRY_TYPES`, `TELEMETRY_AVAILABILITY_VALUES`,
and `TELEMETRY_DECISIONS`).
"""

from __future__ import annotations

from typing import Any

TELEMETRY_VERSION = "1"

TELEMETRY_TYPES = frozenset({
    "process_creation", "network_connection", "dns", "http_proxy", "web_server",
    "authentication", "endpoint", "file", "registry", "cloud_audit", "identity",
    "email", "firewall", "waf", "application_log",
})

TELEMETRY_AVAILABILITY_VALUES = frozenset({"true", "false", "partial"})
TELEMETRY_DECISIONS = frozenset({"GENERATE_RULE", "TELEMETRY_GAP", "PARTIAL_COVERAGE"})

ENVIRONMENTS = frozenset({"production", "staging", "development", "test", "sandbox"})
INDUSTRIES = frozenset({
    "financial_services", "healthcare", "technology", "retail",
    "government", "education", "general", "other",
})


class DetectionTelemetryError(ValueError):
    """Raised when a supplied telemetry-feasibility input is
    structurally invalid.

    Never raised because required telemetry is entirely absent, because
    `available_telemetry` is empty, or because the resulting decision is
    `"TELEMETRY_GAP"` -- every one of those is a normal, successfully
    evaluated result, not an error.
    """


def _raise(code: str, detail: str) -> None:
    raise DetectionTelemetryError(f"{code}: {detail}")


def _in_vocab(value: Any, vocabulary: frozenset[str]) -> bool:
    return isinstance(value, str) and value in vocabulary


def _telemetry_list(value: Any, code: str, field_name: str) -> list[str]:
    if not isinstance(value, list):
        _raise(code, f"{field_name!r} must be a list")
    validated: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not _in_vocab(item, TELEMETRY_TYPES):
            _raise(code, f"{field_name!r} entries must be recognized telemetry types")
        if item in seen:
            _raise(code, f"{field_name!r} must not contain duplicates")
        seen.add(item)
        validated.append(item)
    return validated


def _optional_nonblank_string(value: Any, code: str, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        _raise(code, f"{field_name!r} must be null or a non-blank string")
    return value.strip()


def evaluate_telemetry_feasibility(
    *,
    required_telemetry_candidates: Any,
    available_telemetry: Any,
    siem: Any = None,
    edr: Any = None,
    cloud_provider: Any = None,
    environment: Any = None,
    industry: Any = None,
) -> dict[str, Any]:
    """Deterministically evaluate whether a Detection Trigger's required
    telemetry is actually available. Performs no I/O of any kind.

    `required_telemetry_candidates` and `available_telemetry` are
    required and keyword-only, and must each be a list of distinct
    `TELEMETRY_TYPES` values (each may be empty). `siem`/`edr`/
    `cloud_provider` are optional non-blank strings (default `None`,
    echoed verbatim -- never validated against any external system).
    `environment` is optional, one of `ENVIRONMENTS` when supplied.
    `industry` is optional, one of `INDUSTRIES` when supplied.

    Returns a dict with `telemetry_feasibility_version`,
    `required_sources` (`required_telemetry_candidates`, de-duplicated
    and order-preserved), `available_sources` (`available_telemetry`,
    same treatment), `missing_sources` (`required_sources` entries not
    in `available_sources`), `recommended_sources` (identical to
    `missing_sources` -- these are what would need to be instrumented),
    `telemetry_available` (one of `TELEMETRY_AVAILABILITY_VALUES`:
    `"true"` when `missing_sources` is empty and `required_sources` is
    non-empty; `"false"` when every required source is missing, or
    `required_sources` is empty; `"partial"` otherwise), `decision` (one
    of `TELEMETRY_DECISIONS`, mirroring `telemetry_available` 1:1:
    `"true"`->`"GENERATE_RULE"`, `"false"`->`"TELEMETRY_GAP"`,
    `"partial"`->`"PARTIAL_COVERAGE"`), `siem`, `edr`, `cloud_provider`,
    `environment`, `industry` (all echoed), `limitations`.

    Raises `DetectionTelemetryError` for a structurally invalid
    argument. Never raises because telemetry is entirely absent -- that
    is the normal `"TELEMETRY_GAP"` result.
    """
    required_sources = _telemetry_list(required_telemetry_candidates, "INVALID_INPUT", "required_telemetry_candidates")
    available_sources = _telemetry_list(available_telemetry, "INVALID_INPUT", "available_telemetry")
    validated_siem = _optional_nonblank_string(siem, "INVALID_INPUT", "siem")
    validated_edr = _optional_nonblank_string(edr, "INVALID_INPUT", "edr")
    validated_cloud_provider = _optional_nonblank_string(cloud_provider, "INVALID_INPUT", "cloud_provider")

    if environment is not None and not _in_vocab(environment, ENVIRONMENTS):
        _raise("INVALID_INPUT", "environment must be null or a recognized value")
    if industry is not None and not _in_vocab(industry, INDUSTRIES):
        _raise("INVALID_INPUT", "industry must be null or a recognized value")

    available_set = set(available_sources)
    missing_sources = [source for source in required_sources if source not in available_set]

    limitations: list[str] = []
    if not required_sources:
        telemetry_available = "false"
        limitations.append("No telemetry candidates were identified for this trigger -- there is no basis to evaluate feasibility.")
    elif not missing_sources:
        telemetry_available = "true"
    elif len(missing_sources) == len(required_sources):
        telemetry_available = "false"
    else:
        telemetry_available = "partial"
        limitations.append("Only some required telemetry sources are available -- any generated rule will have reduced coverage.")

    decision = {"true": "GENERATE_RULE", "false": "TELEMETRY_GAP", "partial": "PARTIAL_COVERAGE"}[telemetry_available]

    return {
        "telemetry_feasibility_version": TELEMETRY_VERSION,
        "required_sources": required_sources,
        "available_sources": available_sources,
        "missing_sources": missing_sources,
        "recommended_sources": list(missing_sources),
        "telemetry_available": telemetry_available,
        "decision": decision,
        "siem": validated_siem,
        "edr": validated_edr,
        "cloud_provider": validated_cloud_provider,
        "environment": environment,
        "industry": industry,
        "limitations": limitations,
    }
