"""Pure, deterministic Bug Bounty evidence and finding contracts (Block
15A, checkpoint A).

This module answers exactly two questions:

1. *Given one bounded, caller-supplied observation of an HTTP
   request/response (already made, already scoped, by a separate,
   future, non-pure execution adapter this module never calls), what
   does a redacted, deterministic evidence record about it look like?*
   (`create_bug_bounty_evidence`)
2. *Given one or more such evidence records and an analyst/adapter's own
   assessment of them, what does a structured, approval-ready
   vulnerability finding look like?* (`create_bug_bounty_finding`)

## Remote web content is untrusted evidence, never instructions

Everything a target web application returns -- response bodies,
headers, error messages, redirect targets -- is **untrusted evidence
data only**. Nothing in this module (or in any caller of this module)
may treat text observed from a remote target as an instruction to
follow. `response_excerpt`, `observation`, `title`,
`reproduction_summary`, and every other free-text field this module
accepts are stored and reported as data; this module never interprets,
executes, or acts on their content beyond the structural validation
described below.

## Scanner/tool output is never automatically a confirmed vulnerability

A raw signal from a scanner, a header check, or any other detection
mechanism is, at most, an `"observation"` or `"candidate"` finding --
never automatically `"validated"`. `"validated"` may only be claimed
when a supported, deterministic confirmation step genuinely ran and
passed (see `create_bug_bounty_finding`); for vulnerability classes this
version cannot deterministically confirm, `"validated"` is refused
outright, never silently downgraded or worked around.

## Evidence digest is local content correlation only

`evidence_digest` is `"sha256:" + SHA256(canonical JSON of the other
evidence fields)`, exactly like the same pattern already established in
`core.decision_binding` and `core.tamper_evident_audit` -- a private,
independently owned copy of that algorithm, per this project's
established convention that each module owns its own copy of this exact
validation shape rather than sharing one. It is a **local
content-correlation digest only**. It never authenticates the remote
target, never proves the observed response is authentic or unaltered in
transit, never provides a signature, never provides non-repudiation,
and never provides immutability -- nothing here is persisted anywhere.

## A finding is not an approval, and no downstream action occurred

`create_bug_bounty_finding` never means an analyst reviewed or approved
anything -- `human_approval_required` is always `True`, and this module
never creates an approval record, never calls
`core.approval_request`/`core.approval_persistence`, and never routes
anything to a Blue Team or Purple Team workflow. `remediation` and
`detection_opportunity`, when present, are plain-text suggestions only
-- never a patch, a diff, a deployed code change, or a compiled/created
SIEM, EDR, or WAF detection rule. `execution_performed` is always
`False`: this module never deploys a remediation, never creates or
applies a production detection rule, and never mutates production state
as a response to a finding. A real HTTP assessment request having
occurred is represented honestly through `assessment_performed`/
`network_requests_performed` instead -- see `create_bug_bounty_finding`'s
own docstring for the precise distinction from `execution_performed`.

## No network activity

Like `core.bug_bounty_scope`, this module performs **zero network
requests, DNS lookups, or socket activity of any kind**. It only
normalizes, redacts, and validates data the caller already collected
elsewhere.

`create_bug_bounty_evidence` and `create_bug_bounty_finding` are this
module's only public functions.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

EVIDENCE_VERSION = "1"
FINDING_VERSION = "1"

FINDING_STATUSES = frozenset({"observation", "candidate", "validated"})

VULNERABILITY_CLASSES = frozenset({
    "security_header_misconfiguration",
    "information_disclosure",
    "cors_misconfiguration",
    "exposed_metadata",
    "input_reflection",
    "access_control_indicator",
    "http_method_observation",
    "redirect_observation",
})

# Only these classes can ever be automatically finding_status == "validated"
# in v1 -- their condition can be directly and deterministically
# established from bounded HTTP evidence alone (e.g. a header's literal
# presence/absence/value). The remaining classes require a stronger
# validation mechanism this version does not implement, and are refused
# outright rather than silently downgraded.
_AUTO_VALIDATABLE_CLASSES = frozenset({
    "security_header_misconfiguration",
    "information_disclosure",
    "cors_misconfiguration",
    "exposed_metadata",
})

TECHNICAL_SEVERITIES = frozenset({"low", "medium", "high", "critical"})

CONFIDENCE_LEVELS = frozenset({"low", "medium", "high"})

# Deterministic, fixed lookup only -- populated exclusively where the
# vulnerability class has a defensible fixed classification. Never
# guessed, never LLM-derived, never present for a class whose evidence
# cannot honestly support a specific CWE/OWASP category.
_OWASP_CWE_MAPPING: Mapping[str, tuple[str, str]] = MappingProxyType({
    "security_header_misconfiguration": ("A05:2021 Security Misconfiguration", "CWE-693"),
    "information_disclosure": ("A05:2021 Security Misconfiguration", "CWE-200"),
    "cors_misconfiguration": ("A05:2021 Security Misconfiguration", "CWE-942"),
    "exposed_metadata": ("A05:2021 Security Misconfiguration", "CWE-200"),
})

_HTTP_METHODS = frozenset({
    "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE",
})

# A fixed, explicit allowlist -- never a denylist. Any header name not
# listed here is simply omitted from selected_headers, never retained
# "just in case." Credential/session-shaped headers (authorization,
# cookie, set-cookie, api keys, ...) are deliberately absent.
_SAFE_HEADER_ALLOWLIST = frozenset({
    "content-type",
    "content-length",
    "server",
    "x-powered-by",
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-credentials",
    "location",
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
})

_MAX_RESPONSE_EXCERPT_LENGTH = 500

_EVIDENCE_REQUIRED_FIELDS = (
    "evidence_version",
    "tool",
    "method",
    "scoped_url",
    "status_code",
    "selected_headers",
    "response_excerpt",
    "observation",
    "evidence_digest",
)

_EVIDENCE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class BugBountyFindingError(ValueError):
    """Raised when a supplied evidence- or finding-construction input is
    structurally invalid, including an unsupported
    `finding_status: "validated"` request for a vulnerability class this
    version cannot deterministically confirm.

    It is never raised because a finding is merely a `"candidate"`
    rather than `"validated"`, or because `technical_severity`/
    `confidence` is low -- every one of those is a fully valid,
    successfully constructed result, not an error condition.
    """


# ---------------------------------------------------------------------------
# Deterministic canonical-JSON evidence digesting -- a private,
# independently owned copy of the same algorithm core.decision_binding
# and core.tamper_evident_audit each already use, deliberately not
# imported from either (their helpers are private, and every module in
# this project owns its own copy of this exact validation shape rather
# than sharing one).
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


def _canonical_json_digest(value: Any) -> str:
    canonical = _canonicalize(value)
    text = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Narrow, private input validators.
# ---------------------------------------------------------------------------


def _validate_nonblank_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BugBountyFindingError(f"{field_name} must be a non-blank string")
    return value


def _validate_optional_nonblank_string(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise BugBountyFindingError(f"{field_name} must be null or a non-blank string")
    return value


def _validate_enum(value: Any, vocabulary: frozenset[str], field_name: str) -> str:
    if not isinstance(value, str) or value not in vocabulary:
        raise BugBountyFindingError(f"{field_name} must be one of the recognized values")
    return value


def _validate_strict_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise BugBountyFindingError(f"{field_name} must be a boolean")
    return value


def _validate_nonnegative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BugBountyFindingError(f"{field_name} must be a non-negative int")
    if value < 0:
        raise BugBountyFindingError(f"{field_name} must be a non-negative int")
    return value


def _validate_http_method(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BugBountyFindingError("method must be a non-blank string")
    canonical = value.strip().upper()
    if canonical not in _HTTP_METHODS:
        raise BugBountyFindingError("method must be a recognized HTTP method")
    return canonical


def _validate_status_code(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise BugBountyFindingError("status_code must be an int or null")
    if value < 100 or value > 599:
        raise BugBountyFindingError("status_code must be a valid HTTP status code (100-599)")
    return value


def _validate_and_redact_headers(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise BugBountyFindingError("headers must be a mapping")
    selected: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise BugBountyFindingError("header names must be strings")
        lowered = key.strip().lower()
        if lowered not in _SAFE_HEADER_ALLOWLIST:
            continue
        if not isinstance(item, str):
            continue
        selected[lowered] = item
    return dict(sorted(selected.items()))


def _validate_response_excerpt(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise BugBountyFindingError("response_excerpt must be a string or null")
    return value[:_MAX_RESPONSE_EXCERPT_LENGTH]


def _validate_affected_path(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BugBountyFindingError("affected_path must be a non-blank string")
    if value != value.strip():
        raise BugBountyFindingError("affected_path must not have surrounding whitespace")
    if not value.startswith("/"):
        raise BugBountyFindingError("affected_path must begin with '/'")
    if "\\" in value:
        raise BugBountyFindingError("affected_path must not contain backslashes")
    if any(segment in (".", "..") for segment in value.split("/")):
        raise BugBountyFindingError("affected_path must not contain dot-segments")
    lowered = value.lower()
    if "%2f" in lowered or "%5c" in lowered:
        raise BugBountyFindingError(
            "affected_path must not contain ambiguous percent-encoded slash/backslash sequences"
        )
    return value


def _validate_evidence_item(item: Any) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        raise BugBountyFindingError("each evidence item must be a mapping")
    if set(item) != set(_EVIDENCE_REQUIRED_FIELDS):
        raise BugBountyFindingError(
            "each evidence item must contain exactly the fields create_bug_bounty_evidence returns"
        )
    if item["evidence_version"] != EVIDENCE_VERSION:
        raise BugBountyFindingError("evidence item evidence_version must be '1'")
    if not isinstance(item["tool"], str) or not item["tool"].strip():
        raise BugBountyFindingError("evidence item tool must be a non-blank string")
    if not isinstance(item["method"], str) or item["method"] not in _HTTP_METHODS:
        raise BugBountyFindingError("evidence item method must be a recognized HTTP method")
    if not isinstance(item["scoped_url"], str) or not item["scoped_url"].strip():
        raise BugBountyFindingError("evidence item scoped_url must be a non-blank string")

    status_code = item["status_code"]
    if status_code is not None and (isinstance(status_code, bool) or not isinstance(status_code, int)):
        raise BugBountyFindingError("evidence item status_code must be an int or null")

    if not isinstance(item["selected_headers"], Mapping):
        raise BugBountyFindingError("evidence item selected_headers must be a mapping")

    excerpt = item["response_excerpt"]
    if excerpt is not None and not isinstance(excerpt, str):
        raise BugBountyFindingError("evidence item response_excerpt must be a string or null")

    if not isinstance(item["observation"], str) or not item["observation"].strip():
        raise BugBountyFindingError("evidence item observation must be a non-blank string")

    digest = item["evidence_digest"]
    if not isinstance(digest, str) or not _EVIDENCE_DIGEST_PATTERN.fullmatch(digest):
        raise BugBountyFindingError(
            "evidence item evidence_digest must match 'sha256:' followed by 64 lowercase hex characters"
        )

    return dict(item)


def _validate_evidence_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) == 0:
        raise BugBountyFindingError("evidence must be a non-empty list")
    return [_validate_evidence_item(item) for item in value]


# ---------------------------------------------------------------------------
# Evidence construction
# ---------------------------------------------------------------------------


def create_bug_bounty_evidence(
    *,
    tool: Any,
    method: Any,
    scoped_url: Any,
    status_code: Any,
    headers: Any,
    response_excerpt: Any,
    observation: Any,
) -> dict[str, Any]:
    """Deterministically construct one bounded, redacted evidence record
    from a caller-supplied observation of an HTTP request/response that
    already happened elsewhere. Performs no network request itself.

    All seven parameters are required and keyword-only. `tool` and
    `observation` must be non-blank strings. `method` must be a
    non-blank string naming a recognized HTTP method, canonicalized to
    uppercase. `scoped_url` must be a non-blank string (this function
    never re-validates it against a scope -- that is
    `core.bug_bounty_scope`'s own separate concern). `status_code` must
    be `None` or an int between 100 and 599. `headers` must be a
    mapping; only header names on this module's fixed
    `_SAFE_HEADER_ALLOWLIST` are ever retained (case-insensitively,
    normalized to lowercase), and only when their value is itself a
    string -- every other header, including any credential/session-
    shaped header (`authorization`, `cookie`, `set-cookie`, API-key
    headers, and so on), is silently omitted, never retained redacted-
    by-name. `response_excerpt` must be `None` or a string,
    deterministically truncated to its first 500 characters -- the full
    response body is never stored.

    Returns a new dict containing exactly `evidence_version` (always
    `"1"`), `tool`, `method`, `scoped_url`, `status_code`,
    `selected_headers`, `response_excerpt`, `observation`, and
    `evidence_digest`. `evidence_digest` is `"sha256:" + SHA256(canonical
    JSON)` over the other eight fields -- never a digest of itself, and
    never a claim of remote-response authenticity, origin verification,
    signature, or immutability; see the module docstring.

    Raises `BugBountyFindingError` for any structurally invalid input.
    """
    validated_tool = _validate_nonblank_string(tool, "tool")
    validated_method = _validate_http_method(method)
    validated_scoped_url = _validate_nonblank_string(scoped_url, "scoped_url")
    validated_status_code = _validate_status_code(status_code)
    validated_headers = _validate_and_redact_headers(headers)
    validated_response_excerpt = _validate_response_excerpt(response_excerpt)
    validated_observation = _validate_nonblank_string(observation, "observation")

    payload = {
        "evidence_version": EVIDENCE_VERSION,
        "tool": validated_tool,
        "method": validated_method,
        "scoped_url": validated_scoped_url,
        "status_code": validated_status_code,
        "selected_headers": validated_headers,
        "response_excerpt": validated_response_excerpt,
        "observation": validated_observation,
    }

    result = dict(payload)
    result["evidence_digest"] = _canonical_json_digest(payload)
    return result


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------


def create_bug_bounty_finding(
    *,
    finding_id: Any,
    target: Any,
    affected_path: Any,
    affected_parameter: Any,
    title: Any,
    finding_status: Any,
    vulnerability_class: Any,
    evidence: Any,
    validation_method: Any,
    validation_confirmed: Any,
    reproduction_summary: Any,
    technical_severity: Any,
    confidence: Any,
    remediation: Any,
    detection_opportunity: Any,
    assessment_performed: Any,
    network_requests_performed: Any,
) -> dict[str, Any]:
    """Deterministically construct one structured, approval-ready Bug
    Bounty finding from already-collected evidence. Performs no network
    request itself, and never re-derives or re-validates the evidence it
    is given -- only its structural shape.

    All parameters are keyword-only. `finding_id` must be a non-blank,
    caller/deterministically-supplied string -- this function never
    generates a random identifier. `target`, `title`, and
    `reproduction_summary` must be non-blank strings. `affected_path`
    must be a non-blank absolute path beginning with `/`, free of
    backslashes, dot-segments, and ambiguous percent-encoded slash/
    backslash sequences. `affected_parameter` must be `None` or a
    non-blank string. `finding_status` must be one of `"observation"`,
    `"candidate"`, `"validated"`. `vulnerability_class` must be one of
    this module's fixed eight-value vocabulary -- deliberately excluding
    stronger claims like SQL injection, XSS, SSRF, RCE, or IDOR, which
    this version's evidence model cannot honestly support.

    `evidence` must be a non-empty list of mappings, each shaped exactly
    like `create_bug_bounty_evidence`'s own return value (exact key set,
    a recognized `method`, and an `evidence_digest` matching the
    `sha256:<64 lowercase hex>` format) -- every finding, regardless of
    `finding_status`, requires at least one evidence record. This
    function validates evidence *shape*, not by recomputing each
    item's digest.

    `finding_status: "validated"` requires all three: `validation_confirmed
    is True`, a non-null `validation_method`, and `vulnerability_class`
    in this module's fixed auto-validatable subset
    (`security_header_misconfiguration`, `information_disclosure`,
    `cors_misconfiguration`, `exposed_metadata`) -- any other
    `vulnerability_class` raises `BugBountyFindingError` rather than
    silently downgrading the finding. `"candidate"` and `"observation"`
    both require `validation_confirmed is False`.

    `technical_severity` must be one of `"low"`/`"medium"`/`"high"`/
    `"critical"` -- never described as CVSS, a business-risk score, an
    organizational priority, or an AI-generated risk score (see module
    docstring; organization/environment relevance is a separate, later
    concern). `confidence` must be one of `"low"`/`"medium"`/`"high"`.
    `owasp_category`/`cwe` are never caller-supplied -- they are derived
    from `vulnerability_class` through this module's own fixed,
    deterministic mapping, and are `None`/`None` for any class without a
    defensible fixed classification.

    `remediation` and `detection_opportunity` must each be `None` or a
    non-blank plain-text string -- never a patch, a diff, or a claim that
    a SIEM/EDR/WAF rule was created.

    `assessment_performed` must be a strict bool and
    `network_requests_performed` a non-negative int; they must agree
    (`network_requests_performed == 0` requires `assessment_performed is
    False`; `network_requests_performed > 0` requires `assessment_performed
    is True`), or this function raises. `assessment_performed`/
    `network_requests_performed` mean only that a real assessment HTTP
    request occurred -- never that a vulnerability was exploited or that
    a production action executed; `execution_performed` is always
    `False` for exactly that reason, and `human_approval_required` is
    always `True` -- this function never claims an analyst approved
    anything, and never routes anything to a Blue Team or Purple Team
    workflow.

    Returns a new dict containing exactly `finding_version` (always
    `"1"`), `finding_id`, `target`, `affected_path`,
    `affected_parameter`, `title`, `finding_status`,
    `vulnerability_class`, `owasp_category`, `cwe`, `technical_severity`,
    `confidence`, `evidence`, `validation` (`method`, `confirmed`),
    `reproduction_summary`, `remediation`, `detection_opportunity`,
    `human_approval_required` (always `True`), `assessment_performed`,
    `network_requests_performed`, `execution_performed` (always
    `False`).

    Raises `BugBountyFindingError` for any structurally invalid input,
    including an unsupported `"validated"` request for a
    non-auto-validatable `vulnerability_class`.
    """
    validated_finding_id = _validate_nonblank_string(finding_id, "finding_id")
    validated_target = _validate_nonblank_string(target, "target")
    validated_affected_path = _validate_affected_path(affected_path)
    validated_affected_parameter = _validate_optional_nonblank_string(affected_parameter, "affected_parameter")
    validated_title = _validate_nonblank_string(title, "title")
    validated_finding_status = _validate_enum(finding_status, FINDING_STATUSES, "finding_status")
    validated_vulnerability_class = _validate_enum(vulnerability_class, VULNERABILITY_CLASSES, "vulnerability_class")
    validated_evidence = _validate_evidence_list(evidence)
    validated_reproduction_summary = _validate_nonblank_string(reproduction_summary, "reproduction_summary")
    validated_validation_method = _validate_optional_nonblank_string(validation_method, "validation_method")
    validated_validation_confirmed = _validate_strict_bool(validation_confirmed, "validation_confirmed")
    validated_technical_severity = _validate_enum(technical_severity, TECHNICAL_SEVERITIES, "technical_severity")
    validated_confidence = _validate_enum(confidence, CONFIDENCE_LEVELS, "confidence")
    validated_remediation = _validate_optional_nonblank_string(remediation, "remediation")
    validated_detection_opportunity = _validate_optional_nonblank_string(detection_opportunity, "detection_opportunity")
    validated_assessment_performed = _validate_strict_bool(assessment_performed, "assessment_performed")
    validated_network_requests_performed = _validate_nonnegative_int(
        network_requests_performed, "network_requests_performed"
    )

    if validated_network_requests_performed == 0 and validated_assessment_performed is not False:
        raise BugBountyFindingError("assessment_performed must be false when network_requests_performed is 0")
    if validated_network_requests_performed > 0 and validated_assessment_performed is not True:
        raise BugBountyFindingError(
            "assessment_performed must be true when network_requests_performed is greater than 0"
        )

    if validated_finding_status == "validated":
        if validated_validation_confirmed is not True:
            raise BugBountyFindingError("finding_status 'validated' requires validation_confirmed to be true")
        if validated_validation_method is None:
            raise BugBountyFindingError("finding_status 'validated' requires a non-null validation_method")
        if validated_vulnerability_class not in _AUTO_VALIDATABLE_CLASSES:
            raise BugBountyFindingError(
                f"vulnerability_class {validated_vulnerability_class!r} does not support "
                "finding_status 'validated' in this version"
            )
    else:
        if validated_validation_confirmed is not False:
            raise BugBountyFindingError(
                f"finding_status {validated_finding_status!r} requires validation_confirmed to be false"
            )

    owasp_category, cwe = _OWASP_CWE_MAPPING.get(validated_vulnerability_class, (None, None))

    return {
        "finding_version": FINDING_VERSION,
        "finding_id": validated_finding_id,
        "target": validated_target,
        "affected_path": validated_affected_path,
        "affected_parameter": validated_affected_parameter,
        "title": validated_title,
        "finding_status": validated_finding_status,
        "vulnerability_class": validated_vulnerability_class,
        "owasp_category": owasp_category,
        "cwe": cwe,
        "technical_severity": validated_technical_severity,
        "confidence": validated_confidence,
        "evidence": validated_evidence,
        "validation": {
            "method": validated_validation_method,
            "confirmed": validated_validation_confirmed,
        },
        "reproduction_summary": validated_reproduction_summary,
        "remediation": validated_remediation,
        "detection_opportunity": validated_detection_opportunity,
        "human_approval_required": True,
        "assessment_performed": validated_assessment_performed,
        "network_requests_performed": validated_network_requests_performed,
        "execution_performed": False,
    }
