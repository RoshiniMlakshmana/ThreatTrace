"""Pure, deterministic Bug Bounty tool-permission policy (Block 15G-A,
checkpoint 1 of 2).

This module answers exactly one question: *given an analyst-supplied
permission contract and one structured tool-request proposal (from a
human, or from the deterministic-plan-validation layer sitting in
front of the LLM planner), is that specific tool action permitted --
and, separately, can it even run yet?*

## Two independent questions, never conflated

"Is this analyst-permitted?" and "Is this adapter implemented yet?" are
deliberately kept as two separate fields (`analyst_permitted`/
`profile_permitted` vs. `adapter_available`) in every result this
module returns. An analyst granting `nmap` in `allowed_tools` never
means Nmap actually runs -- `adapter_available` is `False` for every
tool this checkpoint has not implemented (see `TOOL_CATALOG`), and this
module never silently executes, simulates, or fabricates a result for
an unimplemented adapter. `ADAPTER_UNAVAILABLE` is reported honestly
instead.

## The testing profile is a ceiling, never a grant

`testing_profile` bounds the *maximum* tool set a permission contract
could ever allow (see `PROFILE_TOOL_CEILING`) -- it never, by itself,
grants a tool. A tool is only `analyst_permitted` when it is *also*
explicitly present in the analyst's own `allowed_tools` list. A
`safe_dast` profile with `allowed_tools: ["http_assessor"]` never
permits Nmap/Nuclei/ZAP/Burp merely because the profile's ceiling could
support them.

## Authenticated testing and controlled validation always require an
## explicit, separate grant

`authenticated_testing_allowed` and `controlled_validation_allowed` are
independent boolean gates on the permission contract. Either capability
being requested -- via the matching `tool_id`, or via
`tool_request.authentication_requested`/`controlled_validation_requested`
on any tool -- is denied unless its own explicit gate is `True`. This
module never infers authorization from a target's own content, from a
tool's category, or from any planner-supplied rationale text -- only
the analyst's own structured permission fields ever grant anything.

## No execution, ever

This module executes nothing. `execution_performed` is always `False`
in every result it can ever produce, including a fully permitted one.
It performs no network, filesystem, environment-variable, subprocess,
system-clock, or randomness access, and imports no other `core.*`
module.

`BugBountyToolPolicyError` and `evaluate_tool_permission` are this
module's two primary public symbols (plus its fixed vocabulary
constants and the read-only `TOOL_CATALOG`).
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

POLICY_VERSION = "1"
PERMISSION_VERSION = "1"
REQUEST_VERSION = "1"

TOOL_IDS = frozenset({
    "http_assessor",
    "crawler",
    "nmap",
    "nuclei",
    "zap",
    "burp_dast",
    "authenticated_testing",
    "controlled_validation",
})

TOOL_CATEGORIES = frozenset({
    "passive_web",
    "network_recon",
    "web_dast",
    "authenticated_testing",
    "controlled_validation",
})

RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})

TESTING_PROFILES = frozenset({"passive", "recon", "safe_dast", "authenticated", "controlled_validation"})

APPROVAL_STATES = frozenset({"not_required", "pending", "approved", "rejected"})

# Fixed, closed, nine-code reason vocabulary, evaluated and emitted in
# this exact order.
REASON_CODES = (
    "TOOL_NOT_ALLOWED",
    "PROFILE_DISALLOWS_TOOL",
    "TARGET_OUT_OF_SCOPE",
    "PORT_OUT_OF_SCOPE",
    "PATH_OUT_OF_SCOPE",
    "AUTHENTICATED_TESTING_NOT_ALLOWED",
    "CONTROLLED_VALIDATION_NOT_ALLOWED",
    "HUMAN_APPROVAL_REQUIRED",
    "ADAPTER_UNAVAILABLE",
)

# ---------------------------------------------------------------------------
# Fixed, hardcoded tool catalog. `implemented` is the single honest
# source of truth for "can this actually run today" -- it is never
# inferred from `risk_level`/`category`, and never overridden by a
# caller. `http_assessor`, `nmap`, and `nuclei` became `True` in Block
# 15G-B; `zap` and `burp_dast` became `True` in Block 15G-CD (see
# `adapters.bug_bounty_zap`/`adapters.bug_bounty_burp` -- for `burp_dast`,
# `implemented: True` reflects that a real, deterministic adapter
# boundary exists, independent of whether a compatible Burp runtime is
# actually configured in any given environment; see that module's own
# `runtime_status`/`adapter_status` distinction). `authenticated_testing`
# and `controlled_validation` remain declared, not-yet-built capabilities.
# ---------------------------------------------------------------------------

_TOOL_CATALOG_ENTRIES: tuple[dict[str, Any], ...] = (
    {
        "tool_id": "http_assessor", "category": "passive_web", "risk_level": "low",
        "implemented": True, "requires_human_approval": False,
        "supports_authentication": False, "state_changing_capability": False,
    },
    {
        # Step 2 (Attack-Surface Discovery): bounded same-origin
        # crawler/endpoint/parameter discovery -- see
        # core.bug_bounty_crawler. Same risk category as http_assessor
        # (bounded GET-only discovery requests, never a form submission,
        # never a state-changing request) -- never authenticated, never
        # a controlled-validation capability.
        "tool_id": "crawler", "category": "passive_web", "risk_level": "low",
        "implemented": True, "requires_human_approval": False,
        "supports_authentication": False, "state_changing_capability": False,
    },
    {
        "tool_id": "nmap", "category": "network_recon", "risk_level": "low",
        "implemented": True, "requires_human_approval": False,
        "supports_authentication": False, "state_changing_capability": False,
    },
    {
        "tool_id": "nuclei", "category": "web_dast", "risk_level": "medium",
        "implemented": True, "requires_human_approval": False,
        "supports_authentication": False, "state_changing_capability": False,
    },
    {
        "tool_id": "zap", "category": "web_dast", "risk_level": "medium",
        "implemented": True, "requires_human_approval": False,
        "supports_authentication": True, "state_changing_capability": False,
    },
    {
        "tool_id": "burp_dast", "category": "web_dast", "risk_level": "medium",
        "implemented": True, "requires_human_approval": False,
        "supports_authentication": True, "state_changing_capability": False,
    },
    {
        "tool_id": "authenticated_testing", "category": "authenticated_testing", "risk_level": "high",
        "implemented": False, "requires_human_approval": True,
        "supports_authentication": True, "state_changing_capability": True,
    },
    {
        "tool_id": "controlled_validation", "category": "controlled_validation", "risk_level": "high",
        "implemented": False, "requires_human_approval": True,
        "supports_authentication": True, "state_changing_capability": True,
    },
)

TOOL_CATALOG: Mapping[str, Mapping[str, Any]] = MappingProxyType({
    entry["tool_id"]: MappingProxyType(dict(entry)) for entry in _TOOL_CATALOG_ENTRIES
})

# Fixed profile ceilings -- the maximum tool set a permission contract
# under that profile could ever permit. Never a grant by itself.
PROFILE_TOOL_CEILING: Mapping[str, frozenset[str]] = MappingProxyType({
    "passive": frozenset({"http_assessor", "crawler"}),
    "recon": frozenset({"http_assessor", "crawler", "nmap"}),
    "safe_dast": frozenset({"http_assessor", "crawler", "nmap", "nuclei", "zap", "burp_dast"}),
    "authenticated": frozenset({
        "http_assessor", "crawler", "nmap", "nuclei", "zap", "burp_dast", "authenticated_testing",
    }),
    "controlled_validation": frozenset({
        "http_assessor", "crawler", "nmap", "nuclei", "zap", "burp_dast",
        "authenticated_testing", "controlled_validation",
    }),
})

_PERMISSION_REQUIRED_FIELDS = (
    "permission_version",
    "target_origin",
    "allowed_hosts",
    "allowed_ports",
    "allowed_paths",
    "excluded_paths",
    "testing_profile",
    "allowed_tools",
    "authenticated_testing_allowed",
    "controlled_validation_allowed",
    "max_requests",
    "human_approval_state",
)

_TOOL_REQUEST_REQUIRED_FIELDS = (
    "request_version",
    "request_id",
    "tool_id",
    "purpose",
    "target",
    "ports",
    "paths",
    "testing_mode",
    "authentication_requested",
    "controlled_validation_requested",
)


class BugBountyToolPolicyError(ValueError):
    """Raised when a supplied `permissions` or `tool_request` input is
    structurally invalid.

    Every message begins with one of a fixed set of stable codes:
    `INVALID_PERMISSIONS`, `DUPLICATE_ALLOWED_TOOL`, `INVALID_TOOL_REQUEST`.
    These are deterministic structural checks only -- a malformed input
    is rejected before any permission question is even asked.

    Never raised because a tool is denied, because an adapter is
    unavailable, or because human approval is missing -- every one of
    those is a normal, successfully evaluated result, represented
    through the returned `reason_codes`, not an exception.
    """


def _raise(code: str, detail: str) -> None:
    raise BugBountyToolPolicyError(f"{code}: {detail}")


def _in_vocab(value: Any, vocabulary: frozenset[str]) -> bool:
    return isinstance(value, str) and value in vocabulary


def _require_bool(value: Any, field_name: str) -> bool:
    if value is not True and value is not False:
        _raise("INVALID_PERMISSIONS", f"{field_name!r} must be a bool")
    return value


def _require_nonblank_string(value: Any, code: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _raise(code, f"{field_name!r} must be a non-blank string")
    return value


def _require_path_string(value: Any, code: str, field_name: str) -> str:
    path = _require_nonblank_string(value, code, field_name)
    if not path.startswith("/"):
        _raise(code, f"{field_name!r} entries must begin with '/'")
    return path


def _require_port(value: Any, code: str, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _raise(code, f"{field_name!r} entries must be ints")
    if value < 1 or value > 65535:
        _raise(code, f"{field_name!r} entries must be between 1 and 65535")
    return value


# ---------------------------------------------------------------------------
# Permission-contract validation.
# ---------------------------------------------------------------------------


def _validate_permissions(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_PERMISSION_REQUIRED_FIELDS):
        _raise("INVALID_PERMISSIONS", "permissions must contain exactly the twelve required fields")

    if value.get("permission_version") != PERMISSION_VERSION:
        _raise("INVALID_PERMISSIONS", "permission_version must be '1'")

    target_origin = _require_nonblank_string(value.get("target_origin"), "INVALID_PERMISSIONS", "target_origin")

    raw_hosts = value.get("allowed_hosts")
    if not isinstance(raw_hosts, list) or len(raw_hosts) == 0:
        _raise("INVALID_PERMISSIONS", "allowed_hosts must be a non-empty list")
    allowed_hosts: list[str] = []
    seen_hosts: set[str] = set()
    for item in raw_hosts:
        host = _require_nonblank_string(item, "INVALID_PERMISSIONS", "allowed_hosts").lower()
        if host in seen_hosts:
            _raise("INVALID_PERMISSIONS", "allowed_hosts must not contain duplicates")
        seen_hosts.add(host)
        allowed_hosts.append(host)

    raw_ports = value.get("allowed_ports")
    if not isinstance(raw_ports, list) or len(raw_ports) == 0:
        _raise("INVALID_PERMISSIONS", "allowed_ports must be a non-empty list")
    allowed_ports: list[int] = []
    seen_ports: set[int] = set()
    for item in raw_ports:
        port = _require_port(item, "INVALID_PERMISSIONS", "allowed_ports")
        if port in seen_ports:
            _raise("INVALID_PERMISSIONS", "allowed_ports must not contain duplicates")
        seen_ports.add(port)
        allowed_ports.append(port)

    raw_allowed_paths = value.get("allowed_paths")
    if not isinstance(raw_allowed_paths, list) or len(raw_allowed_paths) == 0:
        _raise("INVALID_PERMISSIONS", "allowed_paths must be a non-empty list")
    allowed_paths = [_require_path_string(item, "INVALID_PERMISSIONS", "allowed_paths") for item in raw_allowed_paths]

    raw_excluded_paths = value.get("excluded_paths")
    if not isinstance(raw_excluded_paths, list):
        _raise("INVALID_PERMISSIONS", "excluded_paths must be a list")
    excluded_paths = [_require_path_string(item, "INVALID_PERMISSIONS", "excluded_paths") for item in raw_excluded_paths]

    if not _in_vocab(value.get("testing_profile"), TESTING_PROFILES):
        _raise("INVALID_PERMISSIONS", "testing_profile must be a recognized value")
    testing_profile = value["testing_profile"]

    raw_allowed_tools = value.get("allowed_tools")
    if not isinstance(raw_allowed_tools, list) or len(raw_allowed_tools) == 0:
        _raise("INVALID_PERMISSIONS", "allowed_tools must be a non-empty list")
    allowed_tools: list[str] = []
    seen_tools: set[str] = set()
    for item in raw_allowed_tools:
        if not _in_vocab(item, TOOL_IDS):
            _raise("INVALID_PERMISSIONS", "allowed_tools entries must be recognized tool ids")
        if item in seen_tools:
            _raise("DUPLICATE_ALLOWED_TOOL", f"duplicate entry in allowed_tools: {item!r}")
        seen_tools.add(item)
        allowed_tools.append(item)

    authenticated_testing_allowed = _require_bool(
        value.get("authenticated_testing_allowed"), "authenticated_testing_allowed",
    )
    controlled_validation_allowed = _require_bool(
        value.get("controlled_validation_allowed"), "controlled_validation_allowed",
    )

    max_requests = value.get("max_requests")
    if isinstance(max_requests, bool) or not isinstance(max_requests, int) or max_requests < 1:
        _raise("INVALID_PERMISSIONS", "max_requests must be a positive int")

    if not _in_vocab(value.get("human_approval_state"), APPROVAL_STATES):
        _raise("INVALID_PERMISSIONS", "human_approval_state must be a recognized value")
    human_approval_state = value["human_approval_state"]

    return {
        "permission_version": PERMISSION_VERSION,
        "target_origin": target_origin,
        "allowed_hosts": allowed_hosts,
        "allowed_ports": allowed_ports,
        "allowed_paths": allowed_paths,
        "excluded_paths": excluded_paths,
        "testing_profile": testing_profile,
        "allowed_tools": allowed_tools,
        "authenticated_testing_allowed": authenticated_testing_allowed,
        "controlled_validation_allowed": controlled_validation_allowed,
        "max_requests": max_requests,
        "human_approval_state": human_approval_state,
    }


# ---------------------------------------------------------------------------
# Tool-request validation. The exact fixed field set below is the only
# thing this module (or any caller) can ever populate -- there is
# structurally no field for a shell/raw/terminal command or arbitrary
# arguments, so no such value can ever reach this module undetected.
# ---------------------------------------------------------------------------


def _validate_tool_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_TOOL_REQUEST_REQUIRED_FIELDS):
        _raise("INVALID_TOOL_REQUEST", "tool_request must contain exactly the ten required fields")

    if value.get("request_version") != REQUEST_VERSION:
        _raise("INVALID_TOOL_REQUEST", "request_version must be '1'")

    request_id = _require_nonblank_string(value.get("request_id"), "INVALID_TOOL_REQUEST", "request_id")

    if not _in_vocab(value.get("tool_id"), TOOL_IDS):
        _raise("INVALID_TOOL_REQUEST", "tool_id must be a recognized tool id")
    tool_id = value["tool_id"]

    purpose = _require_nonblank_string(value.get("purpose"), "INVALID_TOOL_REQUEST", "purpose")
    target = _require_nonblank_string(value.get("target"), "INVALID_TOOL_REQUEST", "target")

    raw_ports = value.get("ports")
    if not isinstance(raw_ports, list):
        _raise("INVALID_TOOL_REQUEST", "ports must be a list")
    ports = [_require_port(item, "INVALID_TOOL_REQUEST", "ports") for item in raw_ports]

    raw_paths = value.get("paths")
    if not isinstance(raw_paths, list):
        _raise("INVALID_TOOL_REQUEST", "paths must be a list")
    paths = [_require_path_string(item, "INVALID_TOOL_REQUEST", "paths") for item in raw_paths]

    if not _in_vocab(value.get("testing_mode"), TESTING_PROFILES):
        _raise("INVALID_TOOL_REQUEST", "testing_mode must be a recognized testing profile value")
    testing_mode = value["testing_mode"]

    authentication_requested = _require_bool(value.get("authentication_requested"), "authentication_requested")
    controlled_validation_requested = _require_bool(
        value.get("controlled_validation_requested"), "controlled_validation_requested",
    )

    return {
        "request_version": REQUEST_VERSION,
        "request_id": request_id,
        "tool_id": tool_id,
        "purpose": purpose,
        "target": target,
        "ports": ports,
        "paths": paths,
        "testing_mode": testing_mode,
        "authentication_requested": authentication_requested,
        "controlled_validation_requested": controlled_validation_requested,
    }


# ---------------------------------------------------------------------------
# Scope helpers -- private, minimal, local copies. Never imported from
# core.bug_bounty_scope, following this project's established convention.
# ---------------------------------------------------------------------------


def _extract_host(target: str) -> str:
    if "://" in target:
        return (urlsplit(target).hostname or "").lower()
    return target.split("/", 1)[0].split(":", 1)[0].lower()


def _path_matches(path: str, entry: str) -> bool:
    if entry == "/":
        return True
    if path == entry:
        return True
    return path.startswith(entry + "/")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate_tool_permission(*, permissions: Any, tool_request: Any) -> dict[str, Any]:
    """Deterministically evaluate one structured tool-request proposal
    against an analyst-supplied permission contract. Performs no I/O of
    any kind, and never executes the requested tool.

    Both parameters are required and keyword-only. `permissions` must be
    a mapping containing exactly the twelve fields documented in the
    module docstring's permission contract. `tool_request` must be a
    mapping containing exactly the ten fields documented in the module
    docstring's tool-request contract -- there is no field for a shell/
    raw/terminal command or arbitrary arguments in this contract, so
    none can ever be smuggled through it.

    Returns a new dict containing exactly `policy_version` (always
    `"1"`), `request_id`, `tool_id`, `analyst_permitted` (`tool_id` is
    explicitly present in `permissions['allowed_tools']`),
    `profile_permitted` (`tool_id` is within `PROFILE_TOOL_CEILING`
    for `permissions['testing_profile']`), `adapter_available`
    (`TOOL_CATALOG[tool_id]['implemented']`), `human_approval_required`,
    `approval_satisfied` (`permissions['human_approval_state'] ==
    "approved"`), `execution_permitted` (`True` only when every check
    passes -- equivalently, `reason_codes` is empty), `reason_codes` (a
    fixed-order, deduplicated list drawn from `REASON_CODES`),
    `execution_performed` (always `False`).

    `TOOL_NOT_ALLOWED` triggers when `tool_id` is not in
    `permissions['allowed_tools']`. `PROFILE_DISALLOWS_TOOL` triggers
    when `tool_id` is outside `permissions['testing_profile']`'s own
    ceiling -- the profile is a ceiling only; both this and
    `TOOL_NOT_ALLOWED` are evaluated independently, and either or both
    may appear together. `TARGET_OUT_OF_SCOPE`/`PORT_OUT_OF_SCOPE`/
    `PATH_OUT_OF_SCOPE` trigger when `tool_request['target']`'s own
    host, or any of its `ports`/`paths`, fall outside
    `permissions['allowed_hosts']`/`allowed_ports`/`allowed_paths`
    (respecting `excluded_paths`). `AUTHENTICATED_TESTING_NOT_ALLOWED`
    triggers when `tool_id == "authenticated_testing"` or
    `tool_request['authentication_requested']` is `True`, while
    `permissions['authenticated_testing_allowed']` is `False` --
    authorization is never inferred from anything else.
    `CONTROLLED_VALIDATION_NOT_ALLOWED` mirrors this for
    `controlled_validation`/`controlled_validation_requested`/
    `controlled_validation_allowed`. `HUMAN_APPROVAL_REQUIRED` triggers
    when `TOOL_CATALOG[tool_id]['requires_human_approval']`, or either
    of the two authentication/controlled-validation flags above, is
    `True`, while `permissions['human_approval_state'] != "approved"`.
    `ADAPTER_UNAVAILABLE` triggers when
    `TOOL_CATALOG[tool_id]['implemented']` is `False` -- an analyst
    permitting a tool never makes an unimplemented adapter run, and
    this function never simulates or fabricates a result for one.

    Neither `permissions` nor `tool_request` is ever mutated.

    Raises `BugBountyToolPolicyError` for any structurally invalid
    `permissions`/`tool_request`, including a duplicate entry in
    `allowed_tools`. Never raises because a tool is denied, an adapter
    is unavailable, or approval is missing -- every one of those is a
    normal, successfully evaluated result.
    """
    validated_permissions = _validate_permissions(permissions)
    validated_request = _validate_tool_request(tool_request)

    tool_id = validated_request["tool_id"]
    testing_profile = validated_permissions["testing_profile"]

    triggered: list[str] = []

    def _trigger(code: str) -> None:
        if code not in triggered:
            triggered.append(code)

    analyst_permitted = tool_id in validated_permissions["allowed_tools"]
    if not analyst_permitted:
        _trigger("TOOL_NOT_ALLOWED")

    profile_permitted = tool_id in PROFILE_TOOL_CEILING[testing_profile]
    if not profile_permitted:
        _trigger("PROFILE_DISALLOWS_TOOL")

    target_host = _extract_host(validated_request["target"])
    if target_host not in validated_permissions["allowed_hosts"]:
        _trigger("TARGET_OUT_OF_SCOPE")

    for port in validated_request["ports"]:
        if port not in validated_permissions["allowed_ports"]:
            _trigger("PORT_OUT_OF_SCOPE")
            break

    for path in validated_request["paths"]:
        excluded = any(_path_matches(path, entry) for entry in validated_permissions["excluded_paths"])
        allowed = any(_path_matches(path, entry) for entry in validated_permissions["allowed_paths"])
        if excluded or not allowed:
            _trigger("PATH_OUT_OF_SCOPE")
            break

    wants_authenticated = tool_id == "authenticated_testing" or validated_request["authentication_requested"]
    if wants_authenticated and not validated_permissions["authenticated_testing_allowed"]:
        _trigger("AUTHENTICATED_TESTING_NOT_ALLOWED")

    wants_controlled_validation = (
        tool_id == "controlled_validation" or validated_request["controlled_validation_requested"]
    )
    if wants_controlled_validation and not validated_permissions["controlled_validation_allowed"]:
        _trigger("CONTROLLED_VALIDATION_NOT_ALLOWED")

    catalog_entry = TOOL_CATALOG[tool_id]
    human_approval_required = (
        catalog_entry["requires_human_approval"] or wants_authenticated or wants_controlled_validation
    )
    approval_satisfied = validated_permissions["human_approval_state"] == "approved"
    if human_approval_required and not approval_satisfied:
        _trigger("HUMAN_APPROVAL_REQUIRED")

    adapter_available = catalog_entry["implemented"]
    if not adapter_available:
        _trigger("ADAPTER_UNAVAILABLE")

    reason_codes = [code for code in REASON_CODES if code in triggered]
    execution_permitted = len(reason_codes) == 0

    return {
        "policy_version": POLICY_VERSION,
        "request_id": validated_request["request_id"],
        "tool_id": tool_id,
        "analyst_permitted": analyst_permitted,
        "profile_permitted": profile_permitted,
        "adapter_available": adapter_available,
        "human_approval_required": human_approval_required,
        "approval_satisfied": approval_satisfied,
        "execution_permitted": execution_permitted,
        "reason_codes": reason_codes,
        "execution_performed": False,
    }
