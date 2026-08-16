"""Real, bounded OWASP ZAP passive-DAST adapter (Block 15G-CD).

This is the third real external-tool adapter in the Bug Bounty stack,
alongside `adapters.bug_bounty_nmap`/`adapters.bug_bounty_nuclei`. Like
those two, this is a boundary module -- it performs real local network
I/O (to a ZAP daemon's REST API, never to the scan target directly) so
`core.bug_bounty_tool_execution` and every other `core.*` module never
have to.

## Passive-first, and honestly passive-only in this checkpoint

ZAP supports active scanning (sending real attack payloads), but this
checkpoint's own safety requirement is explicit: active scanning is only
ever enabled if the repository architecture can *deterministically prove*
no destructive/high-risk rule category is included. Curating and proving
such a rule allowlist is real, separate engineering this checkpoint does
not attempt -- so this adapter **never enables ZAP's active scanner**,
full stop. `capability` in every result this adapter returns is always
`"passive_only"`. This is a documented, honest limitation, not a claim
that active scanning was attempted and found unsafe.

This adapter also proactively calls ZAP's own `setMode` API to force
`"safe"` mode (ZAP's own built-in engine-level guarantee that
state-changing/potentially-dangerous operations are refused) before
doing anything else, and verifies the mode actually took effect before
proceeding -- defense in depth on top of never requesting an active scan
in the first place.

## What this adapter does

1. Discover a local ZAP daemon via its REST API (`http://127.0.0.1:8080`
   by default -- see `ZAP_API_HOST`/`ZAP_API_PORT`). No API key is
   required against a daemon this project's own local container starts
   with `-config api.disablekey=true`, since the daemon is bound to
   `127.0.0.1` only and never exposed. If unreachable within a short,
   fixed connect timeout, this adapter returns `status: "unavailable"`
   immediately -- it never waits indefinitely, never starts a container
   itself, and never falls back to any other tool.
2. Force `"safe"` mode.
3. Visit **exactly one** analyst-approved target URL
   (`/JSON/core/action/accessUrl/`), which alone is enough to trigger
   ZAP's passive-scan engine on that one response.
4. Wait (bounded by `execution_config['process_timeout_seconds']`) for
   ZAP's passive-scan queue to drain, then reads back structured alerts
   for the visited origin only.

No spider/crawl step is performed in this checkpoint: a real local ZAP
daemon's own `"safe"` mode refuses spider operations against a URL with
no established Context/scope (`mode_violation: "Operation not allowed
for current mode"`), discovered during this checkpoint's own live
validation. Rather than build Context/scope management to work around
that, this adapter honors it -- single-URL, passive-only is both simpler
and strictly safer, and matches what ZAP's own safe-mode engine
independently enforces anyway. `MAX_SPIDER_URLS`/`MAX_SPIDER_DEPTH`
remain declared as reserved bounds for a future checkpoint that adds
real Context-scoped bounded crawling; they are unused by this one.

Never submits a form, never logs in/out, never uploads a file, never
enables OAST/interactsh-equivalent callback checks, never runs a custom
script, and never scans an out-of-origin host -- there is no parameter
anywhere in `run_zap_scan`'s signature through which a caller could ask
for any of those.

## The ZAP daemon runs in its own container -- a routing detail, never a
## scope change

The ZAP daemon this adapter talks to runs in its own Docker container,
with its own network namespace. When the analyst-approved target's host
is `localhost`/`127.0.0.1` (this project's own Juice Shop container,
published on the *host's* loopback), that hostname means something
different from inside the ZAP container -- it would resolve to the ZAP
container itself, not the target. `_daemon_reachable_url` rewrites only
the URL string actually sent to the ZAP daemon's own API, substituting
Docker's `host.docker.internal` gateway name for `localhost`/`127.0.0.1`
so the daemon can reach the same, already-approved local target.
`_original_form_url` reverses that substitution on every URL ZAP reports
back (spider results, alert `url` fields) before this adapter includes
it anywhere in its result. Every field this adapter ever returns --
`target`, `urls_visited`, each observation's `url` -- always reflects the
original analyst-approved host, never the internal Docker routing name.
This is a pure routing detail local to how one already-approved local
daemon reaches one already-approved local target; it never widens scope,
never changes what `core.bug_bounty_tool_policy` already authorized, and
is a no-op for any target whose host is not one of the loopback aliases.

## Structured observations only, never a raw response body

Each ZAP alert is normalized into a small, fixed-field `dast_observation`
(see `_normalize_zap_alert`) -- `sanitized_evidence` is a short, bounded,
redacted excerpt (never a full request/response body), and no cookie,
`Authorization` header, or other credential-shaped value is ever
preserved in it.

## Tool result is not a finding

Exactly like the Nmap/Nuclei adapters, a result this module returns is a
raw tool observation, never a canonical ThreatTrace finding --
`core.bug_bounty_evidence_normalization`/`core.bug_bounty_finding_correlation`
are the modules responsible for turning it into one.

`BugBountyZapAdapterError` and `run_zap_scan` are this module's public
symbols (plus `ZAP_API_HOST`, `ZAP_API_PORT`, `ZAP_API_URL_ENV_VAR`,
`MAX_SPIDER_URLS`, `MAX_SPIDER_DEPTH`, `MAX_PROCESS_TIMEOUT_SECONDS`,
`MAX_OUTPUT_BYTES`, and `TOOL_RESULT_VERSION`).
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import time
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

TOOL_RESULT_VERSION = "1"

# The ZAP daemon this project starts is bound to 127.0.0.1 only, with its
# API key disabled (-config api.disablekey=true) -- never exposed, never
# reachable from anywhere but this host. This is the correct, unchanged
# default for host-native deployment (the backend runs on the host;
# ZAP's own container publishes its API to the host's loopback).
#
# `ZAP_API_URL_ENV_VAR` exists for exactly one other, also-legitimate
# topology: the self-hosted Docker deployment, where the backend itself
# also runs in a container on the same Compose network as ZAP -- there,
# the backend's own `127.0.0.1` is itself, not the ZAP container, so it
# must reach ZAP by Docker DNS service name instead (`http://zap:8080`,
# set as this exact env var in `docker-compose.yml`'s `threattrace`
# service only). This is a fixed, deployment-time-configured location for
# the daemon's own API -- never a caller-supplied value, never read per
# request, and never used to widen what `core.bug_bounty_tool_policy`
# already authorized for the *scan target* (a completely separate
# concern from where the ZAP daemon's control API happens to live).
ZAP_API_URL_ENV_VAR = "ZAP_API_URL"
ZAP_API_HOST = "127.0.0.1"
ZAP_API_PORT = 8080
ZAP_CONNECT_TIMEOUT_SECONDS = 3.0


def _resolve_zap_api_target() -> tuple[str, int]:
    """Resolve the ZAP daemon's own API host/port. Reads
    `ZAP_API_URL_ENV_VAR` fresh on every call (never cached at import
    time) so tests can set/unset it deterministically; falls back to the
    fixed `ZAP_API_HOST`/`ZAP_API_PORT` defaults for any unset, blank, or
    malformed value -- this function never raises."""
    configured = os.environ.get(ZAP_API_URL_ENV_VAR, "").strip()
    if not configured:
        return ZAP_API_HOST, ZAP_API_PORT
    parsed = urlsplit(configured)
    if parsed.scheme != "http" or not parsed.hostname:
        return ZAP_API_HOST, ZAP_API_PORT
    return parsed.hostname, parsed.port or ZAP_API_PORT

# Bounded, fixed adapter constants -- never supplied by the planner/LLM.
MAX_SPIDER_URLS = 5
MAX_SPIDER_DEPTH = 1
MAX_PROCESS_TIMEOUT_SECONDS = 120
MAX_OUTPUT_BYTES = 1_048_576  # 1 MiB, applied to the serialized alert payload

STATUS_VALUES = frozenset({"completed", "failed", "unavailable", "timeout"})
CAPABILITY_VALUES = frozenset({"passive_only"})

_EXECUTION_CONFIG_VERSION = "1"
_EXECUTION_CONFIG_REQUIRED_FIELDS = ("execution_config_version", "process_timeout_seconds", "max_output_bytes")

_FREE_TEXT_MAX_LENGTH = 256
_EVIDENCE_EXCERPT_MAX_LENGTH = 200
_REDACTION_MARKERS = (
    "authorization:", "cookie:", "set-cookie:", "api_key", "apikey", "password", "bearer ",
)


class BugBountyZapAdapterError(ValueError):
    """Raised when a supplied `target`/`execution_config` is structurally
    invalid.

    Never raised for a real scan outcome (unreachable daemon, timeout,
    unexpected ZAP API response, mode that could not be forced to
    `"safe"`) -- every one of those is a normal, successfully returned
    result with a `status` field, not an error.
    """


def _raise(code: str, detail: str) -> None:
    raise BugBountyZapAdapterError(f"{code}: {detail}")


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


# ---------------------------------------------------------------------------
# Target / execution_config validation -- private, local, additive on top
# of whatever core.bug_bounty_tool_policy already approved.
# ---------------------------------------------------------------------------


# Loopback aliases the ZAP daemon's own container cannot resolve to the
# host the same way this project's other (non-containerized) adapters
# can -- see the module docstring's "routing detail" section. Fixed,
# never caller-configurable.
_DAEMON_HOST_ALIASES: Mapping[str, str] = MappingProxyType({
    "localhost": "host.docker.internal",
    "127.0.0.1": "host.docker.internal",
})


def _rewrite_host(url: str, *, from_host: str, to_host: str) -> str:
    parsed = urlsplit(url)
    if parsed.hostname != from_host:
        return url
    netloc = to_host + (f":{parsed.port}" if parsed.port else "")
    if parsed.username or parsed.password:
        return url  # never rewrite a URL carrying credentials
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def _daemon_reachable_url(url: str) -> str:
    parsed = urlsplit(url)
    alias = _DAEMON_HOST_ALIASES.get(parsed.hostname or "")
    if alias is None:
        return url
    return _rewrite_host(url, from_host=parsed.hostname, to_host=alias)


def _original_form_url(url: str, *, original_hostname: str) -> str:
    parsed = urlsplit(url)
    if parsed.hostname != "host.docker.internal":
        return url
    return _rewrite_host(url, from_host="host.docker.internal", to_host=original_hostname)


def _validate_scan_target(target: Any) -> tuple[str, str]:
    candidate = _require_nonblank_string(target, "target")
    parsed = urlsplit(candidate)
    if parsed.scheme not in ("http", "https"):
        _raise("INVALID_TARGET", "target must be an http(s) URL")
    if not parsed.hostname:
        _raise("INVALID_TARGET", "target must include a hostname")
    origin = f"{parsed.scheme}://{parsed.hostname}" + (f":{parsed.port}" if parsed.port else "")
    return candidate, origin


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
# Minimal ZAP REST API client -- stdlib http.client only, no new
# dependency, mirroring adapters.bug_bounty_http's own approach. Every
# call targets ZAP_API_HOST:ZAP_API_PORT only -- never the scan target
# directly.
# ---------------------------------------------------------------------------


class _ZapUnavailable(Exception):
    """Internal-only signal that the ZAP daemon could not be reached."""


def _zap_api_call(path: str, params: Mapping[str, str], *, timeout: float) -> Any:
    query = "&".join(f"{key}={quote(str(value), safe='')}" for key, value in params.items())
    full_path = f"{path}?{query}" if query else path
    api_host, api_port = _resolve_zap_api_target()
    connection = http.client.HTTPConnection(api_host, api_port, timeout=timeout)
    try:
        connection.request("GET", full_path)
        response = connection.getresponse()
        raw_body = response.read()
        if response.status != 200:
            raise _ZapUnavailable(f"ZAP API returned status {response.status}")
    except _ZapUnavailable:
        raise
    except (OSError, socket.timeout, http.client.HTTPException) as exc:
        raise _ZapUnavailable(str(exc)) from None
    finally:
        try:
            connection.close()
        except Exception:
            pass

    try:
        return json.loads(raw_body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        raise _ZapUnavailable("ZAP API returned a non-JSON response") from None


# ---------------------------------------------------------------------------
# Alert normalization.
# ---------------------------------------------------------------------------


def _digest_reference(payload: Any, *, kind: str) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"zap_{kind}_sha256:{digest}"


def _normalize_zap_alert(alert: Mapping[str, Any]) -> dict[str, Any]:
    cwe_raw = alert.get("cweid")
    cwe = None
    if isinstance(cwe_raw, str) and cwe_raw.strip() and cwe_raw.strip() != "-1":
        cwe = f"CWE-{cwe_raw.strip()}"

    evidence_excerpt = _sanitize_free_text(alert.get("evidence"), max_length=_EVIDENCE_EXCERPT_MAX_LENGTH)

    return {
        "tool_id": "zap",
        "observation_type": "dast_observation",
        "rule_id": _sanitize_free_text(alert.get("pluginId")),
        "title": _sanitize_free_text(alert.get("alert") or alert.get("name")),
        "risk": _sanitize_free_text(alert.get("risk")),
        "confidence": _sanitize_free_text(alert.get("confidence")),
        "url": _sanitize_free_text(alert.get("url"), max_length=512),
        "path": _sanitize_free_text(urlsplit(alert.get("url", "")).path or None),
        "parameter": _sanitize_free_text(alert.get("param")) or None,
        "method": _sanitize_free_text(alert.get("method")),
        "cwe": cwe,
        "owasp_category": None,  # ZAP's core alert API does not reliably supply this
        "evidence_reference": _digest_reference(alert, kind="alert"),
        "sanitized_evidence": evidence_excerpt,
        "source_tool_metadata": {"plugin_id": _sanitize_free_text(alert.get("pluginId"))},
    }


# ---------------------------------------------------------------------------
# Result contract.
# ---------------------------------------------------------------------------


def _build_result(
    *,
    request_id: str,
    target: str,
    status: str,
    runtime_version: str | None,
    urls_visited: list[str],
    requests_performed: int | None,
    runtime_duration_seconds: float | None,
    observations: list[dict[str, Any]],
    evidence_references: list[str],
    output_truncated: bool,
    error_detail: str | None,
    execution_performed: bool,
) -> dict[str, Any]:
    return {
        "tool_result_version": TOOL_RESULT_VERSION,
        "tool_id": "zap",
        "request_id": request_id,
        "target": target,
        "status": status,
        "capability": "passive_only",
        "runtime_version": runtime_version,
        "mode": "safe" if status == "completed" else None,
        "urls_visited": urls_visited,
        "requests_performed": requests_performed,
        "runtime_duration_seconds": runtime_duration_seconds,
        "observations": observations,
        "evidence_references": evidence_references,
        "output_truncated": output_truncated,
        "error_detail": error_detail,
        "execution_performed": execution_performed,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_zap_scan(*, target: Any, request_id: Any, execution_config: Any) -> dict[str, Any]:
    """Run one bounded, passive-only ZAP scan against a single
    analyst-approved URL, and return a structured, sanitized tool
    result. Never invoked directly by the LLM planner -- only
    `core.bug_bounty_tool_execution` calls this, and only after it has
    re-evaluated the real tool permission policy and confirmed a
    Security Governor `allow` decision.

    Raises `BugBountyZapAdapterError` for a structurally invalid
    `target` (not a bare `http(s)` URL), `request_id` (not a non-blank
    string), or `execution_config` (wrong shape, or a value exceeding a
    hardcoded safety ceiling). Never raises because the ZAP daemon is
    unreachable, times out, or returns an unexpected response -- every
    one of those is a normal, successfully returned result via `status`.

    Returns a dict with `tool_result_version`, `tool_id` (always
    `"zap"`), `request_id`, `target`, `status` (one of `STATUS_VALUES`),
    `capability` (always `"passive_only"` in this checkpoint --
    see module docstring), `runtime_version`, `mode`, `urls_visited`,
    `requests_performed`, `runtime_duration_seconds`, `observations`
    (each a `dast_observation`, see `_normalize_zap_alert`),
    `evidence_references`, `output_truncated`, `error_detail`,
    `execution_performed`.
    """
    validated_target, origin = _validate_scan_target(target)
    validated_request_id = _require_nonblank_string(request_id, "request_id")
    validated_config = _validate_execution_config(execution_config)

    original_hostname = urlsplit(validated_target).hostname
    daemon_target = _daemon_reachable_url(validated_target)
    daemon_origin = _daemon_reachable_url(origin)

    started_at = time.monotonic()
    deadline = started_at + validated_config["process_timeout_seconds"]

    def _empty_result(status: str, *, error_detail: str | None, execution_performed: bool) -> dict[str, Any]:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status=status,
            runtime_version=None, urls_visited=[], requests_performed=None,
            runtime_duration_seconds=None, observations=[], evidence_references=[],
            output_truncated=False, error_detail=error_detail, execution_performed=execution_performed,
        )

    try:
        version_response = _zap_api_call(
            "/JSON/core/view/version/", {}, timeout=ZAP_CONNECT_TIMEOUT_SECONDS,
        )
    except _ZapUnavailable:
        return _empty_result("unavailable", error_detail=None, execution_performed=False)

    runtime_version = _sanitize_free_text(version_response.get("version")) if isinstance(version_response, dict) else None

    try:
        # Force safe mode -- defense in depth on top of never requesting
        # an active scan. Refuse to proceed if it does not take effect.
        _zap_api_call("/JSON/core/action/setMode/", {"mode": "safe"}, timeout=ZAP_CONNECT_TIMEOUT_SECONDS)
        mode_response = _zap_api_call("/JSON/core/view/mode/", {}, timeout=ZAP_CONNECT_TIMEOUT_SECONDS)
        current_mode = mode_response.get("mode") if isinstance(mode_response, dict) else None
        if current_mode != "safe":
            return _build_result(
                request_id=validated_request_id, target=validated_target, status="failed",
                runtime_version=runtime_version, urls_visited=[], requests_performed=None,
                runtime_duration_seconds=time.monotonic() - started_at, observations=[], evidence_references=[],
                output_truncated=False, error_detail="ZAP could not be confirmed in safe mode",
                execution_performed=True,
            )

        # Visit the one approved target -- this alone seeds the passive
        # scanner on that response. daemon_target is a routing detail
        # only (see module docstring) -- urls_visited always records the
        # original, analyst-approved form.
        #
        # No spider/crawl step: ZAP's own "safe" mode refuses spider
        # operations against a URL with no established Context/scope
        # ("mode_violation: Operation not allowed for current mode"),
        # confirmed against a real local ZAP daemon. Rather than build
        # Context/scope management to work around that, this checkpoint
        # honors it -- single-URL, passive-only is both simpler and
        # strictly safer, and ZAP's own safe-mode engine independently
        # agrees. MAX_SPIDER_URLS/MAX_SPIDER_DEPTH remain declared as
        # reserved bounds for a future checkpoint that adds real
        # Context-scoped bounded crawling.
        _zap_api_call("/JSON/core/action/accessUrl/", {"url": daemon_target}, timeout=ZAP_CONNECT_TIMEOUT_SECONDS)
        urls_visited = [validated_target]

        # Wait for the passive-scan queue to drain, bounded by the
        # remaining time budget.
        while time.monotonic() < deadline:
            pscan_response = _zap_api_call(
                "/JSON/pscan/view/recordsToScan/", {}, timeout=ZAP_CONNECT_TIMEOUT_SECONDS,
            )
            remaining = pscan_response.get("recordsToScan") if isinstance(pscan_response, dict) else "0"
            if str(remaining) == "0":
                break
            time.sleep(0.5)
        else:
            return _build_result(
                request_id=validated_request_id, target=validated_target, status="timeout",
                runtime_version=runtime_version, urls_visited=urls_visited, requests_performed=None,
                runtime_duration_seconds=time.monotonic() - started_at, observations=[], evidence_references=[],
                output_truncated=False, error_detail="passive scan did not complete within the configured timeout",
                execution_performed=True,
            )

        alerts_response = _zap_api_call(
            "/JSON/core/view/alerts/", {"baseurl": daemon_origin}, timeout=ZAP_CONNECT_TIMEOUT_SECONDS,
        )
        raw_alerts = alerts_response.get("alerts", []) if isinstance(alerts_response, dict) else []

        num_messages_response = _zap_api_call(
            "/JSON/core/view/numberOfMessages/", {"baseurl": daemon_origin}, timeout=ZAP_CONNECT_TIMEOUT_SECONDS,
        )
        requests_performed = None
        if isinstance(num_messages_response, dict):
            try:
                requests_performed = int(num_messages_response.get("numberOfMessages"))
            except (TypeError, ValueError):
                requests_performed = None

    except _ZapUnavailable as exc:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status="failed",
            runtime_version=runtime_version, urls_visited=[], requests_performed=None,
            runtime_duration_seconds=time.monotonic() - started_at, observations=[], evidence_references=[],
            output_truncated=False, error_detail="ZAP API call failed after the daemon was initially reachable",
            execution_performed=True,
        )

    serialized_alerts = json.dumps(raw_alerts, sort_keys=True, ensure_ascii=False)
    output_truncated = len(serialized_alerts.encode("utf-8")) > validated_config["max_output_bytes"]
    bounded_alerts = raw_alerts if not output_truncated else raw_alerts[: max(1, len(raw_alerts) // 2)]

    rewritten_alerts = []
    for alert in bounded_alerts:
        if not isinstance(alert, Mapping):
            continue
        alert_copy = dict(alert)
        if isinstance(alert_copy.get("url"), str):
            alert_copy["url"] = _original_form_url(alert_copy["url"], original_hostname=original_hostname)
        rewritten_alerts.append(alert_copy)

    observations = [_normalize_zap_alert(alert) for alert in rewritten_alerts]
    evidence_references = [_digest_reference(bounded_alerts, kind="alerts")]

    return _build_result(
        request_id=validated_request_id, target=validated_target, status="completed",
        runtime_version=runtime_version, urls_visited=urls_visited, requests_performed=requests_performed,
        runtime_duration_seconds=time.monotonic() - started_at, observations=observations,
        evidence_references=evidence_references, output_truncated=output_truncated, error_detail=None,
        execution_performed=True,
    )
