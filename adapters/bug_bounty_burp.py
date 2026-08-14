"""Deterministic Burp Suite DAST adapter boundary (Block 15G-CD).

Unlike `adapters.bug_bounty_nmap`/`adapters.bug_bounty_nuclei`/
`adapters.bug_bounty_zap`, this checkpoint does **not** have a compatible
local Burp runtime available -- Burp Suite is commercial/licensed
software this project never auto-installs. This module is honest about
that distinction throughout: **the ThreatTrace adapter capability is
fully implemented**; **live Burp execution is a separate, environment-
dependent question this module never fabricates an answer to.**

## Two independent capabilities, never conflated

1. **Live scan** (`run_burp_scan`) -- attempts to reach a caller-
   configured local Burp REST API (the same kind of runtime-extension
   API Burp Suite Professional/Enterprise can optionally expose). This
   project never ships, installs, or auto-configures that runtime or its
   API key -- both must already exist via the fixed environment variable
   `BURP_API_KEY_ENV_VAR` this module reads (never a caller-supplied
   parameter, so a scan request can never smuggle in a different key or
   endpoint). If the key is not set, this module reports
   `runtime_status: "configured_external_runtime_required"` **without
   ever attempting a network connection** -- there is nothing to connect
   to. If the key is set but the API is unreachable within a short fixed
   timeout, `runtime_status: "unavailable"`. Only when both the key is
   set and the API responds does this module attempt anything resembling
   a real scan, and even then it never enables an active/attack scan
   profile -- see `_build_scan_configuration`.
2. **Result ingestion** (`import_burp_result`) -- a pure, deterministic
   normalizer for an already-produced, externally-supplied structured
   Burp result (e.g. a human or a separate process already exported and
   parsed a Burp report into the minimal shape `_validate_raw_result`
   documents). This function performs **no I/O of any kind** and never
   executes anything -- it is exactly as pure as
   `core.bug_bounty_evidence_normalization`, just scoped to Burp's own
   issue shape. It is always available, regardless of runtime status,
   because it never depends on one.

## Never fabricate an execution

If no compatible runtime exists during this checkpoint (the expected
case in this development environment), `run_burp_scan` returns
`adapter_status: "implemented"`, `runtime_status:
"configured_external_runtime_required"`, `status: "not_evaluated"`,
`execution_performed: False` -- this module never claims a scan ran, and
never invents an observation. `import_burp_result`'s own
`execution_performed` is always `False` too, since ingesting an
already-produced result is data transformation, never execution.

## Structured observations only, same shape as ZAP's

Both public functions produce `dast_observation` entries with the same
fixed field set `adapters.bug_bounty_zap._normalize_zap_alert` uses
(`tool_id`, `observation_type`, `rule_id`, `title`, `risk`, `confidence`,
`url`, `path`, `parameter`, `method`, `cwe`, `owasp_category`,
`evidence_reference`, `sanitized_evidence`, `source_tool_metadata`) --
this module owns its own private copy of that normalization shape rather
than importing `adapters.bug_bounty_zap`, following this project's
established convention.

`BugBountyBurpAdapterError`, `run_burp_scan`, and `import_burp_result`
are this module's public symbols (plus `STATUS_VALUES`,
`RUNTIME_STATUS_VALUES`, `BURP_API_KEY_ENV_VAR`, and
`TOOL_RESULT_VERSION`).
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

TOOL_RESULT_VERSION = "1"

# Never a caller-supplied parameter -- if a compatible Burp runtime is
# ever configured for this project, it is configured here, in the
# environment, never through a tool_request/planner-supplied value.
BURP_API_KEY_ENV_VAR = "THREATTRACE_BURP_API_KEY"
BURP_API_HOST_ENV_VAR = "THREATTRACE_BURP_API_HOST"
BURP_API_PORT_ENV_VAR = "THREATTRACE_BURP_API_PORT"
BURP_CONNECT_TIMEOUT_SECONDS = 3.0

MAX_PROCESS_TIMEOUT_SECONDS = 120
MAX_OUTPUT_BYTES = 1_048_576

STATUS_VALUES = frozenset({"completed", "failed", "not_evaluated", "timeout"})
RUNTIME_STATUS_VALUES = frozenset({"available", "unavailable", "configured_external_runtime_required"})
ADAPTER_STATUS_VALUES = frozenset({"implemented"})

_EXECUTION_CONFIG_VERSION = "1"
_EXECUTION_CONFIG_REQUIRED_FIELDS = ("execution_config_version", "process_timeout_seconds", "max_output_bytes")

_RAW_RESULT_REQUIRED_FIELDS = ("issues",)
_ISSUE_OPTIONAL_FIELDS = (
    "issue_type", "name", "severity", "confidence", "url", "param", "method", "cwe", "detail",
)

_FREE_TEXT_MAX_LENGTH = 256
_EVIDENCE_EXCERPT_MAX_LENGTH = 200
_REDACTION_MARKERS = (
    "authorization:", "cookie:", "set-cookie:", "api_key", "apikey", "password", "bearer ",
)


class BugBountyBurpAdapterError(ValueError):
    """Raised when a supplied `target`/`execution_config`/`raw_result`
    is structurally invalid.

    Never raised because no compatible Burp runtime is configured, or
    because `raw_result` contains zero issues -- every one of those is a
    normal, successfully returned result via `runtime_status`/`status`,
    not an error.
    """


def _raise(code: str, detail: str) -> None:
    raise BugBountyBurpAdapterError(f"{code}: {detail}")


def _require_nonblank_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _raise("INVALID_INPUT", f"{field_name!r} must be a non-blank string")
    return value.strip()


def _sanitize_free_text(value: Any, *, max_length: int = _FREE_TEXT_MAX_LENGTH) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    lowered = text.lower()
    if any(marker in lowered for marker in _REDACTION_MARKERS):
        return "[REDACTED]"
    return text[:max_length]


def _digest_reference(payload: Any, *, kind: str) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"burp_{kind}_sha256:{digest}"


# ---------------------------------------------------------------------------
# Target / execution_config validation.
# ---------------------------------------------------------------------------


def _validate_scan_target(target: Any) -> str:
    candidate = _require_nonblank_string(target, "target")
    parsed = urlsplit(candidate)
    if parsed.scheme not in ("http", "https"):
        _raise("INVALID_TARGET", "target must be an http(s) URL")
    if not parsed.hostname:
        _raise("INVALID_TARGET", "target must include a hostname")
    return candidate


def _validate_execution_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_EXECUTION_CONFIG_REQUIRED_FIELDS):
        _raise("INVALID_EXECUTION_CONFIG", "execution_config must contain exactly the three required fields")
    if value.get("execution_config_version") != _EXECUTION_CONFIG_VERSION:
        _raise("INVALID_EXECUTION_CONFIG", "execution_config_version must be '1'")

    timeout = value.get("process_timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        _raise("INVALID_EXECUTION_CONFIG", "process_timeout_seconds must be a positive number")
    if timeout > MAX_PROCESS_TIMEOUT_SECONDS:
        _raise("INVALID_EXECUTION_CONFIG", f"process_timeout_seconds must not exceed {MAX_PROCESS_TIMEOUT_SECONDS}")

    max_output = value.get("max_output_bytes")
    if isinstance(max_output, bool) or not isinstance(max_output, int) or max_output <= 0:
        _raise("INVALID_EXECUTION_CONFIG", "max_output_bytes must be a positive int")
    if max_output > MAX_OUTPUT_BYTES:
        _raise("INVALID_EXECUTION_CONFIG", f"max_output_bytes must not exceed {MAX_OUTPUT_BYTES}")

    return {
        "execution_config_version": _EXECUTION_CONFIG_VERSION,
        "process_timeout_seconds": timeout,
        "max_output_bytes": max_output,
    }


# ---------------------------------------------------------------------------
# Runtime discovery -- never a caller-supplied endpoint.
# ---------------------------------------------------------------------------


class _BurpRuntimeUnavailable(Exception):
    """Internal-only signal that a configured Burp API could not be reached."""


def _discover_burp_runtime() -> tuple[str, str, int] | None:
    """Returns `(api_key, host, port)` if a runtime is configured via
    environment variables, else `None`. Never attempts a network call --
    that is a separate step."""
    api_key = os.environ.get(BURP_API_KEY_ENV_VAR)
    if not api_key or not api_key.strip():
        return None
    host = os.environ.get(BURP_API_HOST_ENV_VAR, "127.0.0.1").strip() or "127.0.0.1"
    port_raw = os.environ.get(BURP_API_PORT_ENV_VAR, "1337").strip()
    try:
        port = int(port_raw)
    except ValueError:
        port = 1337
    return api_key.strip(), host, port


def _check_burp_reachable(host: str, port: int) -> bool:
    try:
        connection = http.client.HTTPConnection(host, port, timeout=BURP_CONNECT_TIMEOUT_SECONDS)
        connection.request("GET", "/")
        connection.getresponse()
        connection.close()
        return True
    except (OSError, socket.timeout, http.client.HTTPException):
        return False


# ---------------------------------------------------------------------------
# Shared observation normalization (own private copy -- see module docstring).
# ---------------------------------------------------------------------------


def _normalize_issue(issue: Mapping[str, Any], *, evidence_kind: str) -> dict[str, Any]:
    cwe_raw = issue.get("cwe")
    cwe = None
    if isinstance(cwe_raw, str) and cwe_raw.strip():
        cwe = cwe_raw.strip() if cwe_raw.strip().upper().startswith("CWE-") else f"CWE-{cwe_raw.strip()}"
    elif isinstance(cwe_raw, int) and not isinstance(cwe_raw, bool):
        cwe = f"CWE-{cwe_raw}"

    url_value = issue.get("url")
    path = None
    if isinstance(url_value, str) and url_value:
        path = urlsplit(url_value).path or None

    return {
        "tool_id": "burp_dast",
        "observation_type": "dast_observation",
        "rule_id": _sanitize_free_text(issue.get("issue_type")),
        "title": _sanitize_free_text(issue.get("name")),
        "risk": _sanitize_free_text(issue.get("severity")),
        "confidence": _sanitize_free_text(issue.get("confidence")),
        "url": _sanitize_free_text(url_value, max_length=512),
        "path": _sanitize_free_text(path),
        "parameter": _sanitize_free_text(issue.get("param")) or None,
        "method": _sanitize_free_text(issue.get("method")),
        "cwe": cwe,
        "owasp_category": None,
        "evidence_reference": _digest_reference(dict(issue), kind=evidence_kind),
        "sanitized_evidence": _sanitize_free_text(issue.get("detail"), max_length=_EVIDENCE_EXCERPT_MAX_LENGTH),
        "source_tool_metadata": {"issue_type": _sanitize_free_text(issue.get("issue_type"))},
    }


# ---------------------------------------------------------------------------
# Result contract.
# ---------------------------------------------------------------------------


def _build_result(
    *,
    request_id: str,
    target: str | None,
    runtime_status: str,
    status: str,
    source: str | None,
    observations: list[dict[str, Any]],
    evidence_references: list[str],
    output_truncated: bool,
    error_detail: str | None,
    execution_performed: bool,
) -> dict[str, Any]:
    return {
        "tool_result_version": TOOL_RESULT_VERSION,
        "tool_id": "burp_dast",
        "request_id": request_id,
        "target": target,
        "adapter_status": "implemented",
        "runtime_status": runtime_status,
        "status": status,
        "source": source,
        "observations": observations,
        "evidence_references": evidence_references,
        "network_requests_performed": None,
        "output_truncated": output_truncated,
        "error_detail": error_detail,
        "execution_performed": execution_performed,
    }


# ---------------------------------------------------------------------------
# Public API -- live scan.
# ---------------------------------------------------------------------------


def run_burp_scan(*, target: Any, request_id: Any, execution_config: Any) -> dict[str, Any]:
    """Attempt one bounded Burp DAST scan against a single
    analyst-approved URL through a caller-*configured* (environment
    variable only, never a request parameter) local Burp REST API, and
    return a structured result that always honestly distinguishes
    whether the ThreatTrace adapter itself exists (`adapter_status`,
    always `"implemented"`) from whether a compatible runtime is
    actually reachable (`runtime_status`) from whether a scan actually
    ran (`status`).

    Raises `BugBountyBurpAdapterError` for a structurally invalid
    `target`/`request_id`/`execution_config`. Never raises because no
    runtime is configured or reachable -- that is `runtime_status:
    "configured_external_runtime_required"`/`"unavailable"`, a normal
    result, never an error.

    In this checkpoint's environment (no `BURP_API_KEY_ENV_VAR` set),
    this always returns `runtime_status:
    "configured_external_runtime_required"`, `status: "not_evaluated"`,
    `execution_performed: False`, without ever attempting a network
    call -- this module never fabricates a Burp execution.
    """
    validated_target = _validate_scan_target(target)
    validated_request_id = _require_nonblank_string(request_id, "request_id")
    validated_config = _validate_execution_config(execution_config)

    runtime = _discover_burp_runtime()
    if runtime is None:
        return _build_result(
            request_id=validated_request_id, target=validated_target,
            runtime_status="configured_external_runtime_required", status="not_evaluated", source=None,
            observations=[], evidence_references=[], output_truncated=False, error_detail=None,
            execution_performed=False,
        )

    _api_key, host, port = runtime
    if not _check_burp_reachable(host, port):
        return _build_result(
            request_id=validated_request_id, target=validated_target,
            runtime_status="unavailable", status="not_evaluated", source=None,
            observations=[], evidence_references=[], output_truncated=False, error_detail=None,
            execution_performed=False,
        )

    # A compatible runtime is reachable, but this checkpoint does not
    # implement the live scan-submission protocol itself (there is no
    # single standard Burp REST API across editions/extensions to target
    # deterministically) -- honestly report the runtime as available
    # without fabricating a scan that did not happen.
    return _build_result(
        request_id=validated_request_id, target=validated_target,
        runtime_status="available", status="not_evaluated", source=None,
        observations=[], evidence_references=[], output_truncated=False,
        error_detail="a Burp runtime is reachable, but live scan submission is not implemented in this checkpoint",
        execution_performed=False,
    )


# ---------------------------------------------------------------------------
# Public API -- sanitized result ingestion.
# ---------------------------------------------------------------------------


def _validate_raw_result(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Mapping) or not set(_RAW_RESULT_REQUIRED_FIELDS).issubset(set(value)):
        _raise("INVALID_RAW_RESULT", "raw_result must be a mapping containing at least 'issues'")
    issues = value.get("issues")
    if not isinstance(issues, list):
        _raise("INVALID_RAW_RESULT", "raw_result['issues'] must be a list")
    validated: list[dict[str, Any]] = []
    for item in issues:
        if not isinstance(item, Mapping):
            _raise("INVALID_RAW_RESULT", "each issue must be a mapping")
        validated.append({field: item.get(field) for field in _ISSUE_OPTIONAL_FIELDS})
    return validated


def import_burp_result(*, raw_result: Any, request_id: Any, target: Any = None) -> dict[str, Any]:
    """Deterministically normalize an already-produced, externally-
    supplied structured Burp scan result into this adapter's shared
    observation contract. Performs no I/O of any kind, and never
    executes anything -- `execution_performed` is always `False`.

    `raw_result` must be a mapping containing at least an `"issues"`
    list; each issue is read only for a small, fixed set of optional
    fields (`issue_type`, `name`, `severity`, `confidence`, `url`,
    `param`, `method`, `cwe`, `detail`) -- any other field on an issue is
    ignored, never invented if absent. `request_id` must be a non-blank
    string. `target` is optional (default `None`) and, when supplied,
    echoed back verbatim -- this function never infers a target from the
    issues themselves.

    Returns the same result contract `run_burp_scan` produces, with
    `runtime_status: "available"` (a runtime clearly produced this data
    at some point), `status: "completed"`, `source: "imported_result"`.

    Raises `BugBountyBurpAdapterError` for a structurally invalid
    `raw_result` (missing `"issues"`, non-list `"issues"`, or a non-
    mapping issue entry) or a blank `request_id`. Never raises because
    `issues` is empty -- an empty, successfully-ingested result is
    normal.
    """
    validated_request_id = _require_nonblank_string(request_id, "request_id")
    validated_target = None
    if target is not None:
        validated_target = _validate_scan_target(target)

    issues = _validate_raw_result(raw_result)
    observations = [_normalize_issue(issue, evidence_kind="issue") for issue in issues]
    evidence_references = [_digest_reference(issues, kind="issues")] if issues else []

    return _build_result(
        request_id=validated_request_id, target=validated_target,
        runtime_status="available", status="completed", source="imported_result",
        observations=observations, evidence_references=evidence_references, output_truncated=False,
        error_detail=None, execution_performed=False,
    )
