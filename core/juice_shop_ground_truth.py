"""Pure, deterministic OWASP Juice Shop ground-truth manifest contract
(Block 15F-A, checkpoint 1 of 3).

This module answers exactly one question: *for a caller-supplied local
OWASP Juice Shop target, what structured, independently-established
ground truth falls within ThreatTrace's already-implemented Bug Bounty
detector capability -- and what does not?*

## Independently established, never re-derived here

Every field in `build_baseline_ground_truth`'s fixed nine-case manifest
was established by **independent, out-of-band inspection** of a real
local Juice Shop container (PowerShell/`curl`-based HTTP checks, never
`core.bug_bounty_assessment`/`adapters.bug_bounty_http`) during Block
15F-A0 -- this module never performs a network request, never re-derives
a case's truth from a live target, and never trusts a caller's claim
about what a target returns without that claim already having been
independently confirmed outside this module.

## Supported ground truth is a capability boundary, not a wish list

A case may only be included in `supported_cases` when the underlying
observation genuinely falls within an already-implemented Bug Bounty
detector (see `core.bug_bounty_assessment`'s fixed check set). Vulnerability
classes this engine does not implement -- SQL injection, executable XSS,
IDOR/access-control testing, SSRF, command injection, authenticated
workflow testing -- are recorded only in `unsupported_categories`, and
destructive/out-of-scope testing classes -- brute force, destructive
methods, denial of service, persistence, shell execution -- only in
`out_of_scope_categories`. Neither list is ever scored as a missed
detection by `core.benchmark_evaluation` -- that module's own recall
computation reads only `supported_cases`.

## Positive and negative cases are both first-class

`expected_detection: true` cases describe an observation the caller's
detector genuinely should produce. `expected_detection: false` cases
describe an observation the detector genuinely should NOT produce --
including a detector-limitation case (`/sitemap.xml` returning the
target's Angular SPA catch-all route, not a genuine sitemap file) that
is deliberately preserved here, unmodified, as a known baseline defect
for a future benchmark comparison -- this module never "fixes" a
detector, and never silently drops a negative case because the
underlying detector currently fails it.

## No network activity, no fabricated identifiers

This module performs **zero network requests, DNS lookups, or socket
activity of any kind**. `target_version_or_digest` is a caller-supplied
string (an image digest or version string already obtained by the
caller, e.g. via `docker image inspect`) -- never independently verified
or looked up here. No case ID, timestamp, or UUID is ever generated;
every `case_id` is a caller/module-supplied literal string.

`JuiceShopGroundTruthError`, `build_juice_shop_ground_truth`, and
`build_baseline_ground_truth` are this module's only public functions
(plus its fixed vocabulary constants).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

GROUND_TRUTH_VERSION = "1"
TARGET_LABEL = "OWASP Juice Shop"

DEFAULT_BASELINE_TARGET_ORIGIN = "http://localhost:3000"

# The exact image digest independently recorded via `docker image
# inspect` during Block 15F-A0 for the running `threattrace-juice-shop`
# container. A fixed, hardcoded literal -- never read from Docker,
# never read from an environment variable.
BASELINE_TARGET_VERSION_OR_DIGEST = (
    "sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e"
)

CASE_CATEGORIES = frozenset({
    "SECURITY_HEADER_PRESENCE",
    "METADATA_PATH",
    "INERT_REFLECTION",
    "CORS_OBSERVATION",
    "ADVERTISED_METHODS",
    "NARROW_TECH_DISCLOSURE",
    "REDIRECT_OBSERVATION",
})

# A private copy of the subset of core.bug_bounty_findings.VULNERABILITY_CLASSES
# that a real assessment can genuinely produce (excluding
# "access_control_indicator", which core.bug_bounty_assessment never
# generates) -- deliberately never imported from core.bug_bounty_findings,
# following this project's convention that each module owns its own copy
# of a shape it shares in spirit with another module.
DETECTOR_CAPABILITIES = frozenset({
    "security_header_misconfiguration",
    "information_disclosure",
    "cors_misconfiguration",
    "exposed_metadata",
    "input_reflection",
    "http_method_observation",
    "redirect_observation",
})

TECHNICAL_SEVERITIES = frozenset({"low", "medium", "high", "critical"})

UNSUPPORTED_CATEGORIES = frozenset({
    "sql_injection",
    "executable_xss",
    "idor_access_control",
    "ssrf",
    "command_injection",
    "authenticated_workflow_testing",
})

OUT_OF_SCOPE_CATEGORIES = frozenset({
    "brute_force",
    "destructive_methods",
    "denial_of_service",
    "persistence",
    "shell_execution",
})

_MANIFEST_REQUIRED_FIELDS = (
    "ground_truth_version",
    "target",
    "target_origin",
    "target_version_or_digest",
    "supported_cases",
    "unsupported_categories",
    "out_of_scope_categories",
)

_SUPPORTED_CASE_REQUIRED_FIELDS = (
    "case_id",
    "category",
    "detector_capability",
    "expected_detection",
    "expected_observation",
    "expected_severity",
    "evidence_requirement",
)

_EVIDENCE_REQUIREMENT_FIELDS = frozenset({"affected_path", "match_hint"})


class JuiceShopGroundTruthError(ValueError):
    """Raised when a supplied ground-truth manifest input is
    structurally invalid.

    Every message begins with one of a fixed set of stable codes:
    `INVALID_TARGET_ORIGIN`, `INVALID_TARGET_VERSION_OR_DIGEST`,
    `INVALID_SUPPORTED_CASES`, `INVALID_CASE`, `DUPLICATE_CASE_ID`,
    `INCONSISTENT_EXPECTED_SEVERITY`, `INVALID_EVIDENCE_REQUIREMENT`,
    `INVALID_UNSUPPORTED_CATEGORIES`, `INVALID_OUT_OF_SCOPE_CATEGORIES`.

    Never raised because a case's `expected_detection` is `false`, or
    because a case describes a known detector limitation (e.g. the
    `/sitemap.xml` SPA-fallback case) -- every one of those is a
    normal, honestly-represented ground-truth entry, not an error
    condition.
    """


def _raise(code: str, detail: str) -> None:
    raise JuiceShopGroundTruthError(f"{code}: {detail}")


def _in_vocab(value: Any, vocabulary: frozenset[str]) -> bool:
    return isinstance(value, str) and value in vocabulary


def _require_nonblank_string(value: Any, code: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _raise(code, f"{field_name!r} must be a non-blank string")
    return value


# ---------------------------------------------------------------------------
# Supported-case validation.
# ---------------------------------------------------------------------------


def _validate_evidence_requirement(value: Any) -> dict[str, str | None]:
    if not isinstance(value, Mapping) or set(value) != _EVIDENCE_REQUIREMENT_FIELDS:
        _raise("INVALID_EVIDENCE_REQUIREMENT", "evidence_requirement must contain exactly affected_path/match_hint")

    affected_path = value.get("affected_path")
    if not isinstance(affected_path, str) or not affected_path.strip():
        _raise("INVALID_EVIDENCE_REQUIREMENT", "evidence_requirement.affected_path must be a non-blank string")
    if not affected_path.startswith("/"):
        _raise("INVALID_EVIDENCE_REQUIREMENT", "evidence_requirement.affected_path must begin with '/'")

    match_hint = value.get("match_hint")
    if match_hint is not None and (not isinstance(match_hint, str) or not match_hint.strip()):
        _raise("INVALID_EVIDENCE_REQUIREMENT", "evidence_requirement.match_hint must be null or a non-blank string")

    return {"affected_path": affected_path, "match_hint": match_hint}


def _validate_supported_case(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_SUPPORTED_CASE_REQUIRED_FIELDS):
        _raise("INVALID_CASE", "each supported case must contain exactly the seven required fields")

    case_id = _require_nonblank_string(value.get("case_id"), "INVALID_CASE", "case_id")

    if not _in_vocab(value.get("category"), CASE_CATEGORIES):
        _raise("INVALID_CASE", "category must be a recognized case category")
    category = value["category"]

    if not _in_vocab(value.get("detector_capability"), DETECTOR_CAPABILITIES):
        _raise("INVALID_CASE", "detector_capability must be a recognized detector capability")
    detector_capability = value["detector_capability"]

    expected_detection = value.get("expected_detection")
    if expected_detection is not True and expected_detection is not False:
        _raise("INVALID_CASE", "expected_detection must be a bool")

    expected_observation = _require_nonblank_string(
        value.get("expected_observation"), "INVALID_CASE", "expected_observation",
    )

    expected_severity = value.get("expected_severity")
    if expected_detection is True:
        if not _in_vocab(expected_severity, TECHNICAL_SEVERITIES):
            _raise(
                "INCONSISTENT_EXPECTED_SEVERITY",
                "expected_severity must be a recognized severity when expected_detection is true",
            )
    else:
        if expected_severity is not None:
            _raise(
                "INCONSISTENT_EXPECTED_SEVERITY",
                "expected_severity must be null when expected_detection is false",
            )

    evidence_requirement = _validate_evidence_requirement(value.get("evidence_requirement"))

    return {
        "case_id": case_id,
        "category": category,
        "detector_capability": detector_capability,
        "expected_detection": expected_detection,
        "expected_observation": expected_observation,
        "expected_severity": expected_severity,
        "evidence_requirement": evidence_requirement,
    }


def _validate_supported_cases(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) == 0:
        _raise("INVALID_SUPPORTED_CASES", "supported_cases must be a non-empty list")

    validated: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for raw_case in value:
        case = _validate_supported_case(raw_case)
        if case["case_id"] in seen_ids:
            _raise("DUPLICATE_CASE_ID", f"duplicate case_id: {case['case_id']!r}")
        seen_ids.add(case["case_id"])
        validated.append(case)
    return validated


def _validate_category_list(value: Any, *, vocabulary: frozenset[str], code: str, field_name: str) -> list[str]:
    if not isinstance(value, list) or len(value) == 0:
        _raise(code, f"{field_name} must be a non-empty list")
    validated: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not _in_vocab(item, vocabulary):
            _raise(code, f"{field_name} entries must be recognized category values")
        if item in seen:
            _raise(code, f"{field_name} must not contain duplicates")
        seen.add(item)
        validated.append(item)
    return validated


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_juice_shop_ground_truth(
    *,
    target_origin: Any,
    target_version_or_digest: Any,
    supported_cases: Any,
    unsupported_categories: Any,
    out_of_scope_categories: Any,
) -> dict[str, Any]:
    """Deterministically construct one OWASP Juice Shop ground-truth
    manifest from caller-supplied, already-independently-established
    structured facts. Performs no network activity of any kind.

    All parameters are required and keyword-only. `target_origin` must
    be a non-blank string. `target_version_or_digest` must be a
    non-blank string (an image digest or version string the caller
    already obtained independently -- never verified or looked up
    here). `supported_cases` must be a non-empty list of mappings, each
    containing exactly `case_id` (non-blank, unique), `category` (one
    of `CASE_CATEGORIES`), `detector_capability` (one of
    `DETECTOR_CAPABILITIES`), `expected_detection` (bool),
    `expected_observation` (non-blank string), `expected_severity`
    (one of `TECHNICAL_SEVERITIES` when `expected_detection` is `true`,
    else `None`), `evidence_requirement` (`{affected_path, match_hint}`,
    `affected_path` a non-blank absolute path, `match_hint` `None` or a
    non-blank string). `unsupported_categories`/`out_of_scope_categories`
    must each be a non-empty list of unique values drawn from
    `UNSUPPORTED_CATEGORIES`/`OUT_OF_SCOPE_CATEGORIES` respectively --
    neither list is ever scored as a missed detection by
    `core.benchmark_evaluation`.

    Returns a new dict containing exactly `ground_truth_version` (always
    `"1"`), `target` (always `"OWASP Juice Shop"`), `target_origin`,
    `target_version_or_digest`, `supported_cases` (validated, newly
    constructed), `unsupported_categories`, `out_of_scope_categories`.

    Raises `JuiceShopGroundTruthError` for any structurally invalid
    input, including a duplicate `case_id` or an `expected_severity`
    inconsistent with its case's own `expected_detection`. Never raises
    because a case's `expected_detection` is `false`.
    """
    validated_target_origin = _require_nonblank_string(target_origin, "INVALID_TARGET_ORIGIN", "target_origin")
    validated_target_version_or_digest = _require_nonblank_string(
        target_version_or_digest, "INVALID_TARGET_VERSION_OR_DIGEST", "target_version_or_digest",
    )
    validated_supported_cases = _validate_supported_cases(supported_cases)
    validated_unsupported_categories = _validate_category_list(
        unsupported_categories, vocabulary=UNSUPPORTED_CATEGORIES,
        code="INVALID_UNSUPPORTED_CATEGORIES", field_name="unsupported_categories",
    )
    validated_out_of_scope_categories = _validate_category_list(
        out_of_scope_categories, vocabulary=OUT_OF_SCOPE_CATEGORIES,
        code="INVALID_OUT_OF_SCOPE_CATEGORIES", field_name="out_of_scope_categories",
    )

    return {
        "ground_truth_version": GROUND_TRUTH_VERSION,
        "target": TARGET_LABEL,
        "target_origin": validated_target_origin,
        "target_version_or_digest": validated_target_version_or_digest,
        "supported_cases": validated_supported_cases,
        "unsupported_categories": validated_unsupported_categories,
        "out_of_scope_categories": validated_out_of_scope_categories,
    }


# ---------------------------------------------------------------------------
# The fixed, real, independently-established Block 15F-A0 baseline.
# ---------------------------------------------------------------------------

_BASELINE_SUPPORTED_CASES: tuple[dict[str, Any], ...] = (
    {
        "case_id": "JS-CSP-MISSING",
        "category": "SECURITY_HEADER_PRESENCE",
        "detector_capability": "security_header_misconfiguration",
        "expected_detection": True,
        "expected_observation": "Content-Security-Policy header is missing from the root response.",
        "expected_severity": "medium",
        "evidence_requirement": {"affected_path": "/", "match_hint": "Content-Security-Policy"},
    },
    {
        "case_id": "JS-ROBOTS-PRESENT",
        "category": "METADATA_PATH",
        "detector_capability": "exposed_metadata",
        "expected_detection": True,
        "expected_observation": "/robots.txt is genuinely present (text/plain, not the SPA fallback).",
        "expected_severity": "low",
        "evidence_requirement": {"affected_path": "/robots.txt", "match_hint": None},
    },
    {
        "case_id": "JS-SECURITY-TXT-PRESENT",
        "category": "METADATA_PATH",
        "detector_capability": "exposed_metadata",
        "expected_detection": True,
        "expected_observation": (
            "/.well-known/security.txt is genuinely present (text/plain, not the SPA fallback)."
        ),
        "expected_severity": "low",
        "evidence_requirement": {"affected_path": "/.well-known/security.txt", "match_hint": None},
    },
    {
        "case_id": "JS-RISKY-METHODS-ADVERTISED",
        "category": "ADVERTISED_METHODS",
        "detector_capability": "http_method_observation",
        "expected_detection": True,
        "expected_observation": (
            "The OPTIONS response advertises PUT/PATCH/DELETE via Access-Control-Allow-Methods."
        ),
        "expected_severity": "low",
        "evidence_requirement": {"affected_path": "/", "match_hint": None},
    },
    {
        "case_id": "JS-CORS-WILDCARD",
        "category": "CORS_OBSERVATION",
        "detector_capability": "cors_misconfiguration",
        "expected_detection": True,
        "expected_observation": "Access-Control-Allow-Origin is wildcarded ('*').",
        "expected_severity": "low",
        "evidence_requirement": {"affected_path": "/", "match_hint": None},
    },
    {
        "case_id": "JS-SITEMAP-SPA-FALLBACK",
        "category": "METADATA_PATH",
        "detector_capability": "exposed_metadata",
        "expected_detection": False,
        "expected_observation": (
            "/sitemap.xml returns the target's Angular SPA catch-all route (text/html), not a genuine "
            "sitemap file -- a metadata-presence finding here is a known detector limitation (status-code-"
            "only check), not a real exposure. Deliberately preserved unfixed for later comparison."
        ),
        "expected_severity": None,
        "evidence_requirement": {"affected_path": "/sitemap.xml", "match_hint": None},
    },
    {
        "case_id": "JS-XCTO-PRESENT",
        "category": "SECURITY_HEADER_PRESENCE",
        "detector_capability": "security_header_misconfiguration",
        "expected_detection": False,
        "expected_observation": (
            "X-Content-Type-Options is genuinely present; no missing-header finding should be produced for it."
        ),
        "expected_severity": None,
        "evidence_requirement": {"affected_path": "/", "match_hint": "X-Content-Type-Options"},
    },
    {
        "case_id": "JS-XFO-PRESENT",
        "category": "SECURITY_HEADER_PRESENCE",
        "detector_capability": "security_header_misconfiguration",
        "expected_detection": False,
        "expected_observation": (
            "X-Frame-Options is genuinely present; no missing-header finding should be produced for it."
        ),
        "expected_severity": None,
        "evidence_requirement": {"affected_path": "/", "match_hint": "X-Frame-Options"},
    },
    {
        "case_id": "JS-NO-REFLECTION",
        "category": "INERT_REFLECTION",
        "detector_capability": "input_reflection",
        "expected_detection": False,
        "expected_observation": (
            "The inert reflection probe marker is not reflected at root; no input_reflection finding "
            "should be produced."
        ),
        "expected_severity": None,
        "evidence_requirement": {"affected_path": "/", "match_hint": None},
    },
)

_BASELINE_UNSUPPORTED_CATEGORIES: tuple[str, ...] = (
    "sql_injection",
    "executable_xss",
    "idor_access_control",
    "ssrf",
    "command_injection",
    "authenticated_workflow_testing",
)

_BASELINE_OUT_OF_SCOPE_CATEGORIES: tuple[str, ...] = (
    "brute_force",
    "destructive_methods",
    "denial_of_service",
    "persistence",
    "shell_execution",
)


def build_baseline_ground_truth(*, target_origin: Any = DEFAULT_BASELINE_TARGET_ORIGIN) -> dict[str, Any]:
    """Deterministically return the fixed, real, independently-established
    Block 15F-A0 ground-truth manifest for the known Juice Shop image
    digest `BASELINE_TARGET_VERSION_OR_DIGEST`. Performs no network
    activity of any kind -- this is a fixed, hardcoded fixture, not a
    live lookup.

    `target_origin` is optional and keyword-only, defaulting to
    `DEFAULT_BASELINE_TARGET_ORIGIN` (`"http://localhost:3000"`) --
    the same target used for the real independent baseline observation.

    Returns the same nine-case manifest shape
    `build_juice_shop_ground_truth` returns: five positive cases
    (`JS-CSP-MISSING`, `JS-ROBOTS-PRESENT`, `JS-SECURITY-TXT-PRESENT`,
    `JS-RISKY-METHODS-ADVERTISED`, `JS-CORS-WILDCARD`) and four negative
    cases (`JS-SITEMAP-SPA-FALLBACK`, `JS-XCTO-PRESENT`, `JS-XFO-PRESENT`,
    `JS-NO-REFLECTION`), plus the fixed unsupported/out-of-scope
    category lists. The `JS-SITEMAP-SPA-FALLBACK` case is preserved
    exactly as independently observed -- this function never adjusts it
    to make a downstream benchmark result look better.

    Raises `JuiceShopGroundTruthError` only for a structurally invalid
    `target_origin`; the fixed case data always passes validation by
    construction.
    """
    return build_juice_shop_ground_truth(
        target_origin=target_origin,
        target_version_or_digest=BASELINE_TARGET_VERSION_OR_DIGEST,
        supported_cases=[dict(case) for case in _BASELINE_SUPPORTED_CASES],
        unsupported_categories=list(_BASELINE_UNSUPPORTED_CATEGORIES),
        out_of_scope_categories=list(_BASELINE_OUT_OF_SCOPE_CATEGORIES),
    )
