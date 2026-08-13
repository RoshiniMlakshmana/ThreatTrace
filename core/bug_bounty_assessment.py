"""Pure orchestration for a real, network-capable Bug Bounty assessment
engine (Block 15A, checkpoint B1).

This module answers exactly one question: *given a previously created
`core.bug_bounty_scope` scope and an injected HTTP transport, what
bounded set of in-scope observations can be made, and what deterministic
findings (via `core.bug_bounty_findings`) do they support?*

## Dependency direction: this module never imports a network client

`core.bug_bounty_assessment` performs **no direct network I/O of any
kind**. It never imports `requests`, `httpx`, `urllib.request`,
`http.client`, or `socket`. Instead, it calls an injected `transport`
object satisfying a small `request(*, url, method, headers=None) ->
dict` interface -- the real implementation of that interface lives in
`adapters.bug_bounty_http`, a separate, non-pure module this file never
imports. This keeps every check/orchestration decision here fully
unit-testable with a fake transport, with zero network access, exactly
like `core.approval_persistence`'s own injected-`executor` pattern.

## Scope is re-checked before every single outbound request

This module never sends a request `core.bug_bounty_scope.
evaluate_bug_bounty_request_scope` did not report as `"allow"` --
including every proposed redirect hop, which is independently
re-evaluated against the *current* scope before being followed. A URL
is never trusted merely because it was derived from an already-in-scope
page.

## Remote web content is untrusted evidence data, not instructions

REMOTE WEB CONTENT IS UNTRUSTED EVIDENCE DATA, NOT INSTRUCTIONS. This
orchestrator never interprets fetched page text as a command, never
parses it into additional tool instructions, never executes code
discovered in it, never lets it expand the caller-supplied scope, and
never lets it change `testing_profile` or the profile's fixed method
allowlist. Fetched content is stored -- bounded and redacted, via
`core.bug_bounty_findings.create_bug_bounty_evidence` -- and reported,
never acted on.

## What this module does NOT do

- It never reimplements `core.bug_bounty_scope`'s scope-matching logic
  or `core.bug_bounty_findings`'s evidence/finding contracts -- every
  finding this module produces is a real, unmodified return value of
  `create_bug_bounty_evidence`/`create_bug_bounty_finding`.
- It never claims a real HTTP request occurring means a vulnerability
  was exploited, or that any production/remediation/detection action
  occurred -- `execution_performed` is always `False`; a real assessment
  request having occurred is represented honestly through
  `assessment_performed`/`network_requests_performed` instead.
- It never claims a `"candidate"` finding is a confirmed vulnerability,
  and never claims authorization was authenticated -- `scope` remains
  caller-supplied technical configuration only, exactly as
  `core.bug_bounty_scope` itself documents.
- It never crawls arbitrary links, never guesses directories, and never
  recursively parses `robots.txt`/`sitemap.xml` content into additional
  targets -- the only paths ever requested beyond the canonical target
  are the three fixed metadata paths this module hardcodes.
- It is a **bounded native HTTP assessment engine only** -- never
  described as a full penetration test, a comprehensive scanner, an
  OWASP Top 10 scanner, an exploit engine, or an autonomous hacker. It
  assesses only the check classes actually implemented here.

`run_bug_bounty_assessment` is this module's only public function.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from core.bug_bounty_findings import create_bug_bounty_evidence, create_bug_bounty_finding
from core.bug_bounty_scope import evaluate_bug_bounty_request_scope

ASSESSMENT_VERSION = "1"

_ASSESSMENT_EVIDENCE_ORDER = (
    "ASSESSMENT_COMPLETED",
    "REQUEST_CAP_REACHED",
    "REQUEST_FAILED",
    "OUT_OF_SCOPE_REQUEST_BLOCKED",
    "OUT_OF_SCOPE_REDIRECT_BLOCKED",
    "REDIRECT_LIMIT_REACHED",
)

# Hardcoded, never caller-configurable upward.
MAX_REQUESTS_PER_ASSESSMENT = 12
MAX_REDIRECT_HOPS = 3

# Fixed, small metadata-path set for the passive profile. Never derived
# from crawling, never expanded from page content.
_METADATA_PATHS = ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")

_REFLECTION_PARAM = "tt_probe"
_REFLECTION_MARKER = "THREATTRACE_REFLECTION_PROBE_15A"

_ASSESSMENT_TOOL_NAME = "threattrace_bug_bounty_assessment"

# (header name, title fragment, severity, https_only)
_SECURITY_HEADER_CHECKS = (
    ("strict-transport-security", "Strict-Transport-Security", "medium", True),
    ("content-security-policy", "Content-Security-Policy", "medium", False),
    ("x-content-type-options", "X-Content-Type-Options", "low", False),
    ("x-frame-options", "X-Frame-Options", "low", False),
)

_ADVERTISED_RISKY_METHODS = frozenset({"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"})


class BugBountyAssessmentError(ValueError):
    """Raised when a supplied `scope` or `transport` is structurally
    unusable by this orchestrator: `scope` not a mapping (or missing
    the minimal `target`/`testing_profile` keys this module reads
    directly), or `transport` missing a callable `request` attribute.

    A `scope` that is a mapping but fails `core.bug_bounty_scope`'s own
    deeper structural validation is never re-wrapped here -- the real
    `BugBountyScopeError` it raises on the first scope evaluation
    propagates unchanged, since this module never reimplements or
    hides that validation.

    Never raised because a proposed request was denied by scope,
    because a transport request failed, or because no findings were
    produced -- every one of those is represented in the returned
    result instead, never as an exception.
    """


class _Transport(Protocol):
    """The minimal interface `run_bug_bounty_assessment` expects from
    an injected transport. This module never imports a concrete
    implementation of it -- see `adapters.bug_bounty_http` for the real
    network-capable one.
    """

    def request(
        self,
        *,
        url: str,
        method: str,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        ...


# ---------------------------------------------------------------------------
# Narrow, private input validators.
# ---------------------------------------------------------------------------


def _validate_scope_argument(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BugBountyAssessmentError("scope must be a mapping")
    if "target" not in value or "testing_profile" not in value:
        raise BugBountyAssessmentError("scope must contain 'target' and 'testing_profile'")
    if not isinstance(value["target"], str) or not value["target"].strip():
        raise BugBountyAssessmentError("scope['target'] must be a non-blank string")
    return value


def _validate_transport_argument(value: Any) -> None:
    if not hasattr(value, "request") or not callable(value.request):
        raise BugBountyAssessmentError("transport must expose a callable request(...) method")


# ---------------------------------------------------------------------------
# Deterministic finding-id generation -- never random, never a reuse of
# an evidence_digest.
# ---------------------------------------------------------------------------


def _finding_id(*, target: str, affected_path: str, vulnerability_class: str, check_id: str) -> str:
    payload = "|".join((target, affected_path, vulnerability_class, check_id))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"BB15A-{digest}"


def _register_finding(
    bucket: list[dict[str, Any]],
    finding_keys_seen: set[tuple[str, str, str, str]],
    key: tuple[str, str, str, str],
    finding: dict[str, Any],
) -> None:
    if key in finding_keys_seen:
        return
    finding_keys_seen.add(key)
    bucket.append(finding)


def _lower_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, Mapping):
        return {}
    return {str(key).lower(): value for key, value in headers.items() if isinstance(value, str)}


def _affected_path_of(url: str) -> str:
    return urlsplit(url).path or "/"


def _looks_like_version_disclosure(value: str) -> bool:
    return any(character.isdigit() for character in value)


# ---------------------------------------------------------------------------
# Request execution -- every call passes through scope evaluation first;
# the transport is only ever invoked for a request scope reported
# "allow", and only while the fixed per-assessment request cap has not
# yet been reached.
# ---------------------------------------------------------------------------


def _perform_request(
    *,
    scope: Mapping[str, Any],
    transport: Any,
    url: str,
    method: str,
    request_state: dict[str, Any],
    blocked_code: str,
) -> dict[str, Any] | None:
    if request_state["count"] >= MAX_REQUESTS_PER_ASSESSMENT:
        request_state["evidence"].add("REQUEST_CAP_REACHED")
        return None

    scope_result = evaluate_bug_bounty_request_scope(scope=scope, url=url, method=method)
    if scope_result["decision"] != "allow":
        request_state["evidence"].add(blocked_code)
        return None

    try:
        response = transport.request(
            url=scope_result["normalized_url"],
            method=scope_result["method"],
            headers=None,
        )
    except Exception:
        request_state["count"] += 1
        request_state["evidence"].add("REQUEST_FAILED")
        return None

    request_state["count"] += 1
    return response


def _is_redirect(response: Mapping[str, Any]) -> bool:
    status_code = response.get("status_code")
    return (
        isinstance(status_code, int)
        and 300 <= status_code < 400
        and bool(response.get("redirect_location"))
    )


def _perform_request_with_redirects(
    *,
    scope: Mapping[str, Any],
    transport: Any,
    target: str,
    url: str,
    method: str,
    request_state: dict[str, Any],
    redirect_bucket: list[dict[str, Any]],
    finding_keys_seen: set[tuple[str, str, str, str]],
) -> dict[str, Any] | None:
    current_url = url
    response = _perform_request(
        scope=scope, transport=transport, url=current_url, method=method,
        request_state=request_state, blocked_code="OUT_OF_SCOPE_REQUEST_BLOCKED",
    )

    hop_count = 0
    while response is not None and _is_redirect(response):
        _record_redirect_observation(
            target=target, source_url=current_url, method=method, response=response,
            bucket=redirect_bucket, finding_keys_seen=finding_keys_seen,
        )

        if hop_count >= MAX_REDIRECT_HOPS:
            request_state["evidence"].add("REDIRECT_LIMIT_REACHED")
            return None

        location = response.get("redirect_location")
        if not location:
            return None

        next_url = urljoin(current_url, location)
        next_response = _perform_request(
            scope=scope, transport=transport, url=next_url, method=method,
            request_state=request_state, blocked_code="OUT_OF_SCOPE_REDIRECT_BLOCKED",
        )
        hop_count += 1
        current_url = next_url
        response = next_response

    return response


def _join_target_path(target: str, path: str) -> str:
    parsed = urlsplit(target)
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _build_reflection_url(target: str) -> str | None:
    parsed = urlsplit(target)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if any(key == _REFLECTION_PARAM for key, _value in query_pairs):
        return None
    query_pairs.append((_REFLECTION_PARAM, _REFLECTION_MARKER))
    new_query = urlencode(query_pairs)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, ""))


# ---------------------------------------------------------------------------
# Deterministic check evaluators -- each builds real evidence via
# core.bug_bounty_findings.create_bug_bounty_evidence and a real finding
# via core.bug_bounty_findings.create_bug_bounty_finding; neither
# contract is ever reimplemented here.
# ---------------------------------------------------------------------------


def _evaluate_security_headers(
    *, target: str, method: str, response: Mapping[str, Any],
    bucket: list[dict[str, Any]], finding_keys_seen: set[tuple[str, str, str, str]],
) -> None:
    headers_lower = _lower_headers(response.get("headers"))
    scheme = urlsplit(response["url"]).scheme
    affected_path = _affected_path_of(response["url"])

    for header_name, display_name, severity, https_only in _SECURITY_HEADER_CHECKS:
        if https_only and scheme != "https":
            continue
        if header_name in headers_lower:
            continue

        check_id = f"missing_header:{header_name}"
        key = (target, affected_path, "security_header_misconfiguration", check_id)
        if key in finding_keys_seen:
            continue

        evidence = create_bug_bounty_evidence(
            tool=_ASSESSMENT_TOOL_NAME, method=method, scoped_url=response["url"],
            status_code=response.get("status_code"), headers=response.get("headers") or {},
            response_excerpt=response.get("body_excerpt"),
            observation=f"Response did not include a {display_name} header.",
        )
        finding = create_bug_bounty_finding(
            finding_id=_finding_id(
                target=target, affected_path=affected_path,
                vulnerability_class="security_header_misconfiguration", check_id=check_id,
            ),
            target=target, affected_path=affected_path, affected_parameter=None,
            title=f"Missing {display_name} header",
            finding_status="validated",
            vulnerability_class="security_header_misconfiguration",
            evidence=[evidence],
            validation_method="deterministic_header_presence_check",
            validation_confirmed=True,
            reproduction_summary=f"Requested {affected_path} and observed no {display_name} response header.",
            technical_severity=severity,
            confidence="high",
            remediation=f"Add a {display_name} response header with an appropriate policy value.",
            detection_opportunity=f"Alert on responses from this target missing {display_name}.",
            assessment_performed=True,
            network_requests_performed=1,
        )
        _register_finding(bucket, finding_keys_seen, key, finding)


def _evaluate_information_disclosure(
    *, target: str, method: str, response: Mapping[str, Any],
    bucket: list[dict[str, Any]], finding_keys_seen: set[tuple[str, str, str, str]],
) -> None:
    headers_lower = _lower_headers(response.get("headers"))
    affected_path = _affected_path_of(response["url"])

    for header_name in ("server", "x-powered-by"):
        value = headers_lower.get(header_name)
        if not value or not _looks_like_version_disclosure(value):
            continue

        check_id = f"info_disclosure:{header_name}"
        key = (target, affected_path, "information_disclosure", check_id)
        if key in finding_keys_seen:
            continue

        evidence = create_bug_bounty_evidence(
            tool=_ASSESSMENT_TOOL_NAME, method=method, scoped_url=response["url"],
            status_code=response.get("status_code"), headers=response.get("headers") or {},
            response_excerpt=response.get("body_excerpt"),
            observation=f"{header_name} header disclosed: {value}",
        )
        finding = create_bug_bounty_finding(
            finding_id=_finding_id(
                target=target, affected_path=affected_path,
                vulnerability_class="information_disclosure", check_id=check_id,
            ),
            target=target, affected_path=affected_path, affected_parameter=None,
            title=f"{header_name} header discloses product/version information",
            finding_status="candidate",
            vulnerability_class="information_disclosure",
            evidence=[evidence],
            validation_method=None, validation_confirmed=False,
            reproduction_summary=f"Requested {affected_path} and observed {header_name}: {value}.",
            technical_severity="low", confidence="medium",
            remediation=f"Suppress or generalize the {header_name} header to avoid version disclosure.",
            detection_opportunity=None,
            assessment_performed=True, network_requests_performed=1,
        )
        _register_finding(bucket, finding_keys_seen, key, finding)


def _record_redirect_observation(
    *, target: str, source_url: str, method: str, response: Mapping[str, Any],
    bucket: list[dict[str, Any]], finding_keys_seen: set[tuple[str, str, str, str]],
) -> None:
    affected_path = _affected_path_of(source_url)
    location = response.get("redirect_location") or ""
    check_id = f"redirect:{affected_path}"
    key = (target, affected_path, "redirect_observation", check_id)
    if key in finding_keys_seen:
        return

    evidence = create_bug_bounty_evidence(
        tool=_ASSESSMENT_TOOL_NAME, method=method, scoped_url=response["url"],
        status_code=response.get("status_code"), headers=response.get("headers") or {},
        response_excerpt=response.get("body_excerpt"),
        observation=f"Response redirected (HTTP {response.get('status_code')}) to: {location}",
    )
    finding = create_bug_bounty_finding(
        finding_id=_finding_id(
            target=target, affected_path=affected_path,
            vulnerability_class="redirect_observation", check_id=check_id,
        ),
        target=target, affected_path=affected_path, affected_parameter=None,
        title="Redirect observed",
        finding_status="observation",
        vulnerability_class="redirect_observation",
        evidence=[evidence],
        validation_method=None, validation_confirmed=False,
        reproduction_summary=(
            f"Requested {affected_path} and received an HTTP {response.get('status_code')} "
            f"redirect to {location}."
        ),
        technical_severity="low", confidence="high",
        remediation=None, detection_opportunity=None,
        assessment_performed=True, network_requests_performed=1,
    )
    _register_finding(bucket, finding_keys_seen, key, finding)


def _evaluate_metadata_observation(
    *, target: str, path: str, method: str, response: Mapping[str, Any],
    bucket: list[dict[str, Any]], finding_keys_seen: set[tuple[str, str, str, str]],
) -> None:
    if response.get("status_code") != 200:
        return

    check_id = f"metadata_present:{path}"
    key = (target, path, "exposed_metadata", check_id)
    if key in finding_keys_seen:
        return

    evidence = create_bug_bounty_evidence(
        tool=_ASSESSMENT_TOOL_NAME, method=method, scoped_url=response["url"],
        status_code=response.get("status_code"), headers=response.get("headers") or {},
        response_excerpt=response.get("body_excerpt"),
        observation=f"{path} returned HTTP 200.",
    )
    finding = create_bug_bounty_finding(
        finding_id=_finding_id(
            target=target, affected_path=path, vulnerability_class="exposed_metadata", check_id=check_id,
        ),
        target=target, affected_path=path, affected_parameter=None,
        title=f"{path} is present and publicly accessible",
        finding_status="observation",
        vulnerability_class="exposed_metadata",
        evidence=[evidence],
        validation_method=None, validation_confirmed=False,
        reproduction_summary=f"Requested {path} and received HTTP 200.",
        technical_severity="low", confidence="high",
        remediation=None, detection_opportunity=None,
        assessment_performed=True, network_requests_performed=1,
    )
    _register_finding(bucket, finding_keys_seen, key, finding)


def _evaluate_http_methods(
    *, target: str, method: str, response: Mapping[str, Any],
    bucket: list[dict[str, Any]], finding_keys_seen: set[tuple[str, str, str, str]],
) -> None:
    headers_lower = _lower_headers(response.get("headers"))
    affected_path = _affected_path_of(response["url"])

    advertised: set[str] = set()
    for header_name in ("allow", "access-control-allow-methods"):
        value = headers_lower.get(header_name)
        if not value:
            continue
        for token in value.split(","):
            advertised.add(token.strip().upper())

    risky = sorted(advertised & _ADVERTISED_RISKY_METHODS)
    if not risky:
        return

    check_id = "advertised_methods:" + ",".join(risky)
    key = (target, affected_path, "http_method_observation", check_id)
    if key in finding_keys_seen:
        return

    evidence = create_bug_bounty_evidence(
        tool=_ASSESSMENT_TOOL_NAME, method=method, scoped_url=response["url"],
        status_code=response.get("status_code"), headers=response.get("headers") or {},
        response_excerpt=response.get("body_excerpt"),
        observation=f"Advertised HTTP methods included: {', '.join(risky)}.",
    )
    finding = create_bug_bounty_finding(
        finding_id=_finding_id(
            target=target, affected_path=affected_path,
            vulnerability_class="http_method_observation", check_id=check_id,
        ),
        target=target, affected_path=affected_path, affected_parameter=None,
        title="Potentially state-changing HTTP methods advertised",
        finding_status="candidate",
        vulnerability_class="http_method_observation",
        evidence=[evidence],
        validation_method=None, validation_confirmed=False,
        reproduction_summary=f"Requested OPTIONS {affected_path} and observed advertised methods {', '.join(risky)}.",
        technical_severity="low", confidence="medium",
        remediation="Confirm these methods are intentionally enabled and properly access-controlled.",
        detection_opportunity="Alert on requests using these methods against this path.",
        assessment_performed=True, network_requests_performed=1,
    )
    _register_finding(bucket, finding_keys_seen, key, finding)


def _evaluate_cors(
    *, target: str, method: str, response: Mapping[str, Any],
    bucket: list[dict[str, Any]], finding_keys_seen: set[tuple[str, str, str, str]],
) -> None:
    headers_lower = _lower_headers(response.get("headers"))
    affected_path = _affected_path_of(response["url"])

    acao = headers_lower.get("access-control-allow-origin")
    acac = headers_lower.get("access-control-allow-credentials")
    if not acao:
        return

    notable = acao.strip() == "*" or (acac is not None and acac.strip().lower() == "true")
    if not notable:
        return

    check_id = "cors_observation"
    key = (target, affected_path, "cors_misconfiguration", check_id)
    if key in finding_keys_seen:
        return

    observation = f"Access-Control-Allow-Origin: {acao}"
    if acac:
        observation += f", Access-Control-Allow-Credentials: {acac}"

    evidence = create_bug_bounty_evidence(
        tool=_ASSESSMENT_TOOL_NAME, method=method, scoped_url=response["url"],
        status_code=response.get("status_code"), headers=response.get("headers") or {},
        response_excerpt=response.get("body_excerpt"),
        observation=observation,
    )
    finding = create_bug_bounty_finding(
        finding_id=_finding_id(
            target=target, affected_path=affected_path,
            vulnerability_class="cors_misconfiguration", check_id=check_id,
        ),
        target=target, affected_path=affected_path, affected_parameter=None,
        title="Notable CORS response headers observed",
        finding_status="candidate",
        vulnerability_class="cors_misconfiguration",
        evidence=[evidence],
        validation_method=None, validation_confirmed=False,
        reproduction_summary=f"Requested OPTIONS {affected_path} and observed the CORS headers above.",
        technical_severity="low", confidence="medium",
        remediation="Review whether this CORS configuration is intentional and appropriately scoped.",
        detection_opportunity=None,
        assessment_performed=True, network_requests_performed=1,
    )
    _register_finding(bucket, finding_keys_seen, key, finding)


def _evaluate_reflection(
    *, target: str, method: str, response: Mapping[str, Any],
    bucket: list[dict[str, Any]], finding_keys_seen: set[tuple[str, str, str, str]],
) -> None:
    body = response.get("body_excerpt")
    affected_path = _affected_path_of(response["url"])
    if not body or _REFLECTION_MARKER not in body:
        return

    check_id = "reflection_probe"
    key = (target, affected_path, "input_reflection", check_id)
    if key in finding_keys_seen:
        return

    evidence = create_bug_bounty_evidence(
        tool=_ASSESSMENT_TOOL_NAME, method=method, scoped_url=response["url"],
        status_code=response.get("status_code"), headers=response.get("headers") or {},
        response_excerpt=body,
        observation=f"Inert reflection marker {_REFLECTION_MARKER!r} observed in the response body.",
    )
    finding = create_bug_bounty_finding(
        finding_id=_finding_id(
            target=target, affected_path=affected_path, vulnerability_class="input_reflection", check_id=check_id,
        ),
        target=target, affected_path=affected_path, affected_parameter=_REFLECTION_PARAM,
        title="Inert query parameter value reflected in response",
        finding_status="candidate",
        vulnerability_class="input_reflection",
        evidence=[evidence],
        validation_method=None, validation_confirmed=False,
        reproduction_summary=(
            f"Requested {affected_path}?{_REFLECTION_PARAM}={_REFLECTION_MARKER} and observed the "
            "marker reflected in the response body."
        ),
        technical_severity="low", confidence="medium",
        remediation="Confirm output encoding/escaping is applied wherever this parameter is reflected.",
        detection_opportunity=None,
        assessment_performed=True, network_requests_performed=1,
    )
    _register_finding(bucket, finding_keys_seen, key, finding)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_bug_bounty_assessment(*, scope: Any, transport: Any) -> dict[str, Any]:
    """Deterministically run one bounded, real, network-capable Bug
    Bounty assessment against `scope["target"]`, using only the checks
    permitted by `scope["testing_profile"]`, via the injected
    `transport`.

    Both parameters are keyword-only. `scope` must be a mapping shaped
    like `core.bug_bounty_scope.create_bug_bounty_scope`'s own return
    value -- this function never re-derives a target or profile from
    anywhere else. `transport` must expose a callable `request(*, url,
    method, headers=None)` method; the real implementation lives in
    `adapters.bug_bounty_http`, never imported here.

    Every proposed request -- the canonical target baseline, each fixed
    metadata path, every `safe_active` addition, and every redirect hop
    -- is independently re-evaluated through
    `core.bug_bounty_scope.evaluate_bug_bounty_request_scope` immediately
    before being sent; a request that scope reports as anything other
    than `"allow"` is never sent. At most `MAX_REQUESTS_PER_ASSESSMENT`
    (12) outbound transport calls are ever made in one assessment, and
    at most `MAX_REDIRECT_HOPS` (3) redirect hops are ever followed for
    one originating request.

    Returns a new dict containing exactly `assessment_version` (always
    `"1"`), `target`, `testing_profile`, `findings` (a list of real,
    unmodified `core.bug_bounty_findings.create_bug_bounty_finding`
    results, in a fixed category order: security-header findings,
    information-disclosure findings, redirect observations, metadata
    observations, `safe_active` method/CORS observations, then the
    reflection observation), `observed_evidence` (a deduplicated,
    fixed-order list of assessment-level codes -- a security finding's
    own evidence belongs inside that finding, never duplicated here),
    `assessment_performed` (`True` iff at least one transport request
    was actually attempted), `network_requests_performed` (the exact
    count of transport invocations actually made), `human_approval_required`
    (always `True`), `execution_performed` (always `False` -- real HTTP
    assessment requests may have occurred, but no remediation was
    applied, no production configuration was changed, no detection rule
    was created or applied, and no downstream Blue/Purple action
    occurred).

    Raises `BugBountyAssessmentError` only for a structurally unusable
    `scope`/`transport` argument to this function itself. A deeper
    structural problem within `scope` surfaces as the real
    `BugBountyScopeError` `core.bug_bounty_scope` raises, propagated
    unchanged. A denied request, a failed transport call, or an
    assessment that produces zero findings are all normal, successful
    results -- never exceptions.
    """
    validated_scope = _validate_scope_argument(scope)
    _validate_transport_argument(transport)

    target = validated_scope["target"]
    profile = validated_scope["testing_profile"]

    request_state: dict[str, Any] = {"count": 0, "evidence": set()}
    finding_keys_seen: set[tuple[str, str, str, str]] = set()

    header_findings: list[dict[str, Any]] = []
    information_disclosure_findings: list[dict[str, Any]] = []
    redirect_findings: list[dict[str, Any]] = []
    metadata_findings: list[dict[str, Any]] = []
    options_findings: list[dict[str, Any]] = []
    reflection_findings: list[dict[str, Any]] = []

    baseline_response = _perform_request_with_redirects(
        scope=validated_scope, transport=transport, target=target, url=target, method="GET",
        request_state=request_state, redirect_bucket=redirect_findings, finding_keys_seen=finding_keys_seen,
    )
    if baseline_response is not None:
        _evaluate_security_headers(
            target=target, method="GET", response=baseline_response,
            bucket=header_findings, finding_keys_seen=finding_keys_seen,
        )
        _evaluate_information_disclosure(
            target=target, method="GET", response=baseline_response,
            bucket=information_disclosure_findings, finding_keys_seen=finding_keys_seen,
        )

    for path in _METADATA_PATHS:
        metadata_url = _join_target_path(target, path)
        metadata_response = _perform_request_with_redirects(
            scope=validated_scope, transport=transport, target=target, url=metadata_url, method="GET",
            request_state=request_state, redirect_bucket=redirect_findings, finding_keys_seen=finding_keys_seen,
        )
        if metadata_response is not None:
            _evaluate_metadata_observation(
                target=target, path=path, method="GET", response=metadata_response,
                bucket=metadata_findings, finding_keys_seen=finding_keys_seen,
            )

    if profile == "safe_active":
        options_response = _perform_request(
            scope=validated_scope, transport=transport, url=target, method="OPTIONS",
            request_state=request_state, blocked_code="OUT_OF_SCOPE_REQUEST_BLOCKED",
        )
        if options_response is not None:
            _evaluate_http_methods(
                target=target, method="OPTIONS", response=options_response,
                bucket=options_findings, finding_keys_seen=finding_keys_seen,
            )
            _evaluate_cors(
                target=target, method="OPTIONS", response=options_response,
                bucket=options_findings, finding_keys_seen=finding_keys_seen,
            )

        reflection_url = _build_reflection_url(target)
        if reflection_url is not None:
            reflection_response = _perform_request(
                scope=validated_scope, transport=transport, url=reflection_url, method="GET",
                request_state=request_state, blocked_code="OUT_OF_SCOPE_REQUEST_BLOCKED",
            )
            if reflection_response is not None:
                _evaluate_reflection(
                    target=target, method="GET", response=reflection_response,
                    bucket=reflection_findings, finding_keys_seen=finding_keys_seen,
                )

    findings = (
        header_findings
        + information_disclosure_findings
        + redirect_findings
        + metadata_findings
        + options_findings
        + reflection_findings
    )

    network_requests_performed = request_state["count"]
    assessment_performed = network_requests_performed > 0

    triggered_evidence: set[str] = set(request_state["evidence"])
    triggered_evidence.add("ASSESSMENT_COMPLETED")
    observed_evidence = [code for code in _ASSESSMENT_EVIDENCE_ORDER if code in triggered_evidence]

    return {
        "assessment_version": ASSESSMENT_VERSION,
        "target": target,
        "testing_profile": profile,
        "findings": findings,
        "observed_evidence": observed_evidence,
        "assessment_performed": assessment_performed,
        "network_requests_performed": network_requests_performed,
        "human_approval_required": True,
        "execution_performed": False,
    }
