"""Pure, deterministic Bug Bounty target/scope contract (Block 15A,
checkpoint A).

This module answers exactly two questions:

1. *Given a deployer-supplied target URL and a deployer-supplied set of
   allowed origins/paths/testing profile, what is the normalized,
   internally consistent scope configuration?* (`create_bug_bounty_scope`)
2. *Given that scope configuration and one proposed assessment request
   (a URL and an HTTP method), is that specific request within scope?*
   (`evaluate_bug_bounty_request_scope`)

## Caller-supplied configuration, not authorization proof

`allowed_origins`, `allowed_paths`, `excluded_paths`, and
`testing_profile` are **caller-supplied technical policy only**. This
module enforces the supplied technical scope deterministically; it never
verifies, and never claims to verify, that the caller was actually
authorized (by a bug-bounty program, a client engagement, or any other
real-world agreement) to test the supplied target. Authorization is
always the deployer's own responsibility, stated honestly as
configuration this module was told, never as configuration this module
independently confirmed.

## No network activity

This module performs **zero network requests, DNS lookups, or socket
activity of any kind**. It only parses and compares URL strings the
caller already supplied. The real HTTP execution adapter (a later,
separate, non-pure component) is expected to call
`evaluate_bug_bounty_request_scope` before every single outbound
request it proposes to make -- including, critically, every proposed
redirect hop -- and must never send a request this function reports as
`"deny"`. This module has no way to enforce that by itself; it can only
answer the scope question honestly when asked.

## Origin matching

An origin entry is exactly `"<scheme>://<host>[:<port>]"`. Only `http`
and `https` are recognized. A default port (`80` for `http`, `443` for
`https`) is always normalized away, both for the target and for every
`allowed_origins` entry -- `https://example.test:443` and
`https://example.test` are the same origin; an explicit non-default port
is significant and must match exactly.

Exactly one wildcard form is recognized: a complete left-most hostname
label, e.g. `https://*.example.test`. This matches exactly one
additional label prepended to `example.test` (e.g. `app.example.test`,
`api.example.test`) -- it never matches multiple additional labels
(`a.b.example.test` is not matched) and it never matches the bare domain
itself (`example.test` is not matched by `https://*.example.test` --
the bare origin must be listed separately if it should also be in
scope). No other wildcard syntax is recognized. Scope is never silently
expanded beyond what the caller explicitly listed.

## Path matching

Path matching is segment-aware: an allowed/excluded entry of `/api`
matches `/api` and `/api/users`, but never `/api2`. The entry `/` matches
every path. `excluded_paths` always overrides `allowed_paths` for any
path that matches both.

## Raw IP targets are rejected in v1

A target or request URL whose host is a raw IP address (IPv4 or IPv6) is
rejected. Only name-based scoping is supported in this version --
IP-based scoping raises DNS-rebinding-class ambiguity this module does
not attempt to resolve.

`create_bug_bounty_scope` and `evaluate_bug_bounty_request_scope` are
this module's only public functions.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

SCOPE_VERSION = "1"
SCOPE_EVALUATION_VERSION = "1"

TARGET_TYPES = frozenset({"web_application", "api"})

TESTING_PROFILES = frozenset({"passive", "safe_active"})

_ALLOWED_SCHEMES = frozenset({"http", "https"})

_DEFAULT_PORTS = MappingProxyType({"http": 80, "https": 443})

_PROFILE_ALLOWED_METHODS = MappingProxyType({
    "passive": frozenset({"GET", "HEAD"}),
    "safe_active": frozenset({"GET", "HEAD", "OPTIONS"}),
})

_EVIDENCE_CODE_ORDER = (
    "TARGET_ORIGIN_NOT_ALLOWED",
    "REQUEST_ORIGIN_NOT_ALLOWED",
    "REQUEST_PATH_NOT_ALLOWED",
    "REQUEST_PATH_EXCLUDED",
    "METHOD_NOT_ALLOWED",
    "INVALID_REQUEST_URL",
)

_SCOPE_REQUIRED_FIELDS = (
    "scope_version",
    "target",
    "target_type",
    "allowed_origins",
    "allowed_paths",
    "excluded_paths",
    "testing_profile",
)


class BugBountyScopeError(ValueError):
    """Raised when a supplied scope-construction input, or a
    structurally malformed `scope`/`allowed_origins` entry supplied to
    `evaluate_bug_bounty_request_scope`, is invalid.

    It is never raised because a well-formed proposed request happens to
    fall outside the supplied scope -- that is always represented
    through a normal `decision: "deny"` result and `observed_evidence`,
    not an exception.
    """


# ---------------------------------------------------------------------------
# URL / origin / path parsing -- pure string parsing only, no network
# activity of any kind.
# ---------------------------------------------------------------------------


def _is_safe_path_string(path: str) -> bool:
    if "\\" in path:
        return False
    lowered = path.lower()
    if "%2f" in lowered or "%5c" in lowered:
        return False
    for segment in path.split("/"):
        if segment in (".", ".."):
            return False
    return True


def _normalize_url(value: Any) -> dict[str, Any] | None:
    """Parse and normalize an absolute http/https URL. Returns `None`
    for any structurally invalid, unsupported, or disallowed shape
    (non-string, blank, unsupported scheme, missing hostname, userinfo,
    fragment, raw IP host, unsafe path) rather than raising -- callers
    decide whether that `None` should become an exception or a `"deny"`
    evidence code.
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None
    try:
        parsed = urlsplit(stripped)
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        return None
    if "@" in parsed.netloc:
        return None

    try:
        hostname = parsed.hostname
    except ValueError:
        return None
    if not hostname:
        return None
    hostname = hostname.lower()

    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass

    try:
        port = parsed.port
    except ValueError:
        return None

    if parsed.fragment:
        return None

    raw_path = parsed.path
    if not _is_safe_path_string(raw_path):
        return None
    normalized_path = raw_path if raw_path else "/"
    if not normalized_path.startswith("/"):
        return None

    default_port = _DEFAULT_PORTS[scheme]
    explicit_port = None if port is None or port == default_port else port

    origin = f"{scheme}://{hostname}" + (f":{explicit_port}" if explicit_port is not None else "")
    url = origin + normalized_path
    if parsed.query:
        url += f"?{parsed.query}"

    return {
        "scheme": scheme,
        "hostname": hostname,
        "port": explicit_port,
        "origin": origin,
        "path": normalized_path,
        "url": url,
    }


def _origin_entry_from_normalized(normalized: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "scheme": normalized["scheme"],
        "hostname": normalized["hostname"],
        "port": normalized["port"],
        "is_wildcard": False,
        "canonical": normalized["origin"],
    }


def _parse_origin_entry(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None
    try:
        parsed = urlsplit(stripped)
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        return None
    if parsed.path or parsed.query or parsed.fragment:
        return None
    if "@" in parsed.netloc:
        return None

    try:
        hostname = parsed.hostname
    except ValueError:
        return None
    if not hostname:
        return None
    hostname = hostname.lower()

    is_wildcard = hostname.startswith("*.")
    if is_wildcard:
        domain_part = hostname[2:]
        if not domain_part or "*" in domain_part:
            return None
    elif "*" in hostname:
        return None

    try:
        port = parsed.port
    except ValueError:
        return None

    default_port = _DEFAULT_PORTS[scheme]
    explicit_port = None if port is None or port == default_port else port
    canonical = f"{scheme}://{hostname}" + (f":{explicit_port}" if explicit_port is not None else "")

    return {
        "scheme": scheme,
        "hostname": hostname,
        "port": explicit_port,
        "is_wildcard": is_wildcard,
        "canonical": canonical,
    }


def _origin_allowed(candidate: Mapping[str, Any], allowed_entries: list[dict[str, Any]]) -> bool:
    for entry in allowed_entries:
        if entry["scheme"] != candidate["scheme"]:
            continue
        if entry["port"] != candidate["port"]:
            continue
        if entry["is_wildcard"]:
            domain = entry["hostname"][2:]
            candidate_host = candidate["hostname"]
            if candidate_host == domain:
                continue
            suffix = "." + domain
            if candidate_host.endswith(suffix):
                prefix = candidate_host[: -len(suffix)]
                if prefix and "." not in prefix:
                    return True
            continue
        if entry["hostname"] == candidate["hostname"]:
            return True
    return False


def _path_matches(path: str, entry: str) -> bool:
    if entry == "/":
        return True
    if path == entry:
        return True
    return path.startswith(entry + "/")


# ---------------------------------------------------------------------------
# Narrow, private input validators for create_bug_bounty_scope.
# ---------------------------------------------------------------------------


def _validate_target_type(value: Any) -> str:
    if not isinstance(value, str) or value not in TARGET_TYPES:
        raise BugBountyScopeError("target_type must be one of the recognized target types")
    return value


def _validate_testing_profile(value: Any) -> str:
    if not isinstance(value, str) or value not in TESTING_PROFILES:
        raise BugBountyScopeError("testing_profile must be one of the recognized testing profiles")
    return value


def _validate_allowed_origins(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) == 0:
        raise BugBountyScopeError("allowed_origins must be a non-empty list")
    parsed_entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        entry = _parse_origin_entry(item)
        if entry is None:
            raise BugBountyScopeError(
                "allowed_origins entries must be well-formed http/https origins, optionally with a "
                "single leading wildcard label ('*.<domain>')"
            )
        if entry["canonical"] in seen:
            raise BugBountyScopeError("allowed_origins must not contain duplicate normalized origins")
        seen.add(entry["canonical"])
        parsed_entries.append(entry)
    return parsed_entries


def _validate_path_entry(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BugBountyScopeError(f"{field_name} entries must be non-blank strings")
    if value != value.strip():
        raise BugBountyScopeError(f"{field_name} entries must not have surrounding whitespace")
    if not value.startswith("/"):
        raise BugBountyScopeError(f"{field_name} entries must begin with '/'")
    if "?" in value or "#" in value:
        raise BugBountyScopeError(f"{field_name} entries must not contain a query or fragment")
    if value != "/" and value.endswith("/"):
        raise BugBountyScopeError(f"{field_name} entries must not end with '/' except the root path")
    if not _is_safe_path_string(value):
        raise BugBountyScopeError(
            f"{field_name} entries must not contain backslashes, dot-segments, or ambiguous "
            "percent-encoded slash/backslash sequences"
        )
    return value


def _validate_allowed_paths(value: Any) -> tuple[str, ...]:
    if value is None:
        return ("/",)
    if not isinstance(value, list) or len(value) == 0:
        raise BugBountyScopeError("allowed_paths must be a non-empty list when supplied")
    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        path = _validate_path_entry(item, "allowed_paths")
        if path in seen:
            raise BugBountyScopeError("allowed_paths must not contain duplicate normalized paths")
        seen.add(path)
        normalized.append(path)
    return tuple(normalized)


def _validate_excluded_paths(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise BugBountyScopeError("excluded_paths must be a list when supplied")
    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        path = _validate_path_entry(item, "excluded_paths")
        if path in seen:
            raise BugBountyScopeError("excluded_paths must not contain duplicate normalized paths")
        seen.add(path)
        normalized.append(path)
    return tuple(normalized)


# ---------------------------------------------------------------------------
# Scope construction
# ---------------------------------------------------------------------------


def create_bug_bounty_scope(
    *,
    target: Any,
    target_type: Any,
    allowed_origins: Any,
    allowed_paths: Any = None,
    excluded_paths: Any = None,
    testing_profile: Any,
) -> dict[str, Any]:
    """Deterministically normalize and validate one deployer-supplied
    Bug Bounty target/scope configuration. Performs no network activity.

    All parameters are keyword-only. `target` must be a non-blank
    absolute `http`/`https` URL string with a hostname; userinfo,
    fragment, and raw-IP hosts are rejected. `target_type` must be
    `"web_application"` or `"api"`. `allowed_origins` must be a
    non-empty list of well-formed origin strings (see module docstring
    for wildcard semantics); duplicates after normalization are
    rejected, never silently deduplicated. `allowed_paths` defaults to
    `["/"]` when `None`, otherwise must be a non-empty list of absolute
    path strings; `excluded_paths` defaults to `[]` when `None` or when
    an empty list is supplied. `testing_profile` must be `"passive"` or
    `"safe_active"`.

    The normalized `target`'s origin **must** already be present in
    `allowed_origins` (exactly, or via one matching wildcard entry) --
    this function never infers or adds it implicitly. A caller who
    wants the target itself in scope must list its origin explicitly.

    Returns a new dict containing exactly `scope_version` (always
    `"1"`), `target` (normalized), `target_type`, `allowed_origins`
    (normalized, order preserved), `allowed_paths` (normalized, order
    preserved), `excluded_paths` (normalized, order preserved),
    `testing_profile`.

    Raises `BugBountyScopeError` for any structurally invalid input,
    including a well-formed target whose origin is not included in
    `allowed_origins`. This module never fabricates proof that the
    caller was authorized to test the supplied target -- `allowed_origins`
    /`allowed_paths`/`excluded_paths`/`testing_profile` are caller-supplied
    technical configuration only.
    """
    validated_target_type = _validate_target_type(target_type)
    validated_testing_profile = _validate_testing_profile(testing_profile)
    validated_allowed_origins = _validate_allowed_origins(allowed_origins)
    validated_allowed_paths = _validate_allowed_paths(allowed_paths)
    validated_excluded_paths = _validate_excluded_paths(excluded_paths)

    normalized_target = _normalize_url(target)
    if normalized_target is None:
        raise BugBountyScopeError(
            "target must be a non-blank absolute http/https URL with a hostname, and must not "
            "contain userinfo, a fragment, or a raw IP host"
        )

    target_origin_entry = _origin_entry_from_normalized(normalized_target)
    if not _origin_allowed(target_origin_entry, validated_allowed_origins):
        raise BugBountyScopeError("target origin must be explicitly included in allowed_origins")

    return {
        "scope_version": SCOPE_VERSION,
        "target": normalized_target["url"],
        "target_type": validated_target_type,
        "allowed_origins": [entry["canonical"] for entry in validated_allowed_origins],
        "allowed_paths": list(validated_allowed_paths),
        "excluded_paths": list(validated_excluded_paths),
        "testing_profile": validated_testing_profile,
    }


# ---------------------------------------------------------------------------
# Request-scope evaluation
# ---------------------------------------------------------------------------


def _validate_scope_structure(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BugBountyScopeError("scope must be a mapping")
    if set(value) != set(_SCOPE_REQUIRED_FIELDS):
        raise BugBountyScopeError("scope must contain exactly the fields produced by create_bug_bounty_scope")
    if value["scope_version"] != SCOPE_VERSION:
        raise BugBountyScopeError("scope['scope_version'] must be '1'")
    if not isinstance(value["target"], str) or not value["target"].strip():
        raise BugBountyScopeError("scope['target'] must be a non-blank string")
    if value["target_type"] not in TARGET_TYPES:
        raise BugBountyScopeError("scope['target_type'] must be a recognized target type")
    if not isinstance(value["allowed_origins"], list) or not value["allowed_origins"]:
        raise BugBountyScopeError("scope['allowed_origins'] must be a non-empty list")
    if not all(isinstance(item, str) for item in value["allowed_origins"]):
        raise BugBountyScopeError("scope['allowed_origins'] entries must be strings")
    if not isinstance(value["allowed_paths"], list) or not value["allowed_paths"]:
        raise BugBountyScopeError("scope['allowed_paths'] must be a non-empty list")
    if not all(isinstance(item, str) for item in value["allowed_paths"]):
        raise BugBountyScopeError("scope['allowed_paths'] entries must be strings")
    if not isinstance(value["excluded_paths"], list):
        raise BugBountyScopeError("scope['excluded_paths'] must be a list")
    if not all(isinstance(item, str) for item in value["excluded_paths"]):
        raise BugBountyScopeError("scope['excluded_paths'] entries must be strings")
    if value["testing_profile"] not in TESTING_PROFILES:
        raise BugBountyScopeError("scope['testing_profile'] must be a recognized testing profile")
    return dict(value)


def evaluate_bug_bounty_request_scope(
    *,
    scope: Any,
    url: Any,
    method: Any,
) -> dict[str, Any]:
    """Deterministically evaluate whether one proposed assessment
    request (a URL and an HTTP method) is within a previously created
    Bug Bounty scope. Performs no network activity -- this function only
    compares strings.

    `scope` must be a mapping shaped like `create_bug_bounty_scope`'s
    own return value; this function never trusts that it actually came
    from that function -- it independently re-validates the shape and,
    as defense in depth, re-confirms that `scope['target']`'s own origin
    is genuinely present in `scope['allowed_origins']`
    (`TARGET_ORIGIN_NOT_ALLOWED` evidence if not). A structurally
    malformed `scope` raises `BugBountyScopeError`.

    `url` and `method` are the caller's proposed request. Neither being
    malformed raises -- a malformed `url` is reported as
    `INVALID_REQUEST_URL` evidence, and a malformed/unsupported `method`
    is reported as `METHOD_NOT_ALLOWED` evidence, each resulting in a
    normal `decision: "deny"` result.

    The intended calling convention: the future real assessment adapter
    calls this function before every single outbound HTTP request it
    proposes to make, including every proposed redirect hop, and never
    sends a request this function reports as `"deny"`. This module
    cannot enforce that by itself -- it only answers the scope question.

    Returns a new dict containing exactly `scope_evaluation_version`
    (always `"1"`), `normalized_url` (the normalized request URL, or
    `None` when `url` could not be normalized), `method` (the canonical
    uppercase HTTP method, or `None` when `method` was malformed),
    `decision` (`"allow"` or `"deny"`), `observed_evidence` (a
    deterministic, deduplicated, fixed-order list of evidence-code
    strings).
    """
    validated_scope = _validate_scope_structure(scope)

    normalized_scope_target = _normalize_url(validated_scope["target"])
    if normalized_scope_target is None:
        raise BugBountyScopeError("scope['target'] is not a well-formed http/https URL")

    scope_allowed_origin_entries: list[dict[str, Any]] = []
    for item in validated_scope["allowed_origins"]:
        entry = _parse_origin_entry(item)
        if entry is None:
            raise BugBountyScopeError("scope['allowed_origins'] contains a malformed origin entry")
        scope_allowed_origin_entries.append(entry)

    triggered: set[str] = set()

    scope_target_origin_entry = _origin_entry_from_normalized(normalized_scope_target)
    if not _origin_allowed(scope_target_origin_entry, scope_allowed_origin_entries):
        triggered.add("TARGET_ORIGIN_NOT_ALLOWED")

    normalized_request = _normalize_url(url)
    if normalized_request is None:
        triggered.add("INVALID_REQUEST_URL")
    else:
        request_origin_entry = _origin_entry_from_normalized(normalized_request)
        if not _origin_allowed(request_origin_entry, scope_allowed_origin_entries):
            triggered.add("REQUEST_ORIGIN_NOT_ALLOWED")
        else:
            request_path = normalized_request["path"]
            if any(_path_matches(request_path, entry) for entry in validated_scope["excluded_paths"]):
                triggered.add("REQUEST_PATH_EXCLUDED")
            elif not any(_path_matches(request_path, entry) for entry in validated_scope["allowed_paths"]):
                triggered.add("REQUEST_PATH_NOT_ALLOWED")

    canonical_method: str | None = None
    if isinstance(method, str) and method.strip():
        canonical_method = method.strip().upper()

    allowed_methods = _PROFILE_ALLOWED_METHODS[validated_scope["testing_profile"]]
    if canonical_method is None or canonical_method not in allowed_methods:
        triggered.add("METHOD_NOT_ALLOWED")

    observed_evidence = [code for code in _EVIDENCE_CODE_ORDER if code in triggered]
    decision = "deny" if observed_evidence else "allow"

    return {
        "scope_evaluation_version": SCOPE_EVALUATION_VERSION,
        "normalized_url": normalized_request["url"] if normalized_request is not None else None,
        "method": canonical_method,
        "decision": decision,
        "observed_evidence": observed_evidence,
    }
