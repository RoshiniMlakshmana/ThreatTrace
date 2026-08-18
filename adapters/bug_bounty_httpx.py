"""Real, bounded httpx (ProjectDiscovery) HTTP enrichment adapter
(Final Pre-Release Block, Authorized External Targets + httpx/Katana).

This is a **third** real external-tool adapter, following the exact
same boundary pattern `adapters.bug_bounty_nmap`/`adapters.bug_bounty_nuclei`
already established: it performs real subprocess I/O so
`core.bug_bounty_tool_execution` (the single execution boundary that
calls it) and every other `core.*` module never have to.

## What this adapter answers

*Given one already-validated, in-scope target URL, what HTTP-level
enrichment metadata (reachable? status code? page title? content type?
server/technology header values? redirect destination?) does httpx
observe for it?* Nothing more. This is the same class of question
`adapters.bug_bounty_http`'s own bare GET already partially answers --
httpx is used here purely because its structured `-json` output
already reports several of these fields in one well-tested external
tool, without this project reinventing title/technology-header parsing
itself.

## Technology is an observation, never a vulnerability

A detected technology name (e.g. `"Express"`, `"nginx"`) is reported
verbatim, unmodified, as `technologies`/`server` metadata on the one
`http_enrichment` observation this adapter produces. This module never
maps a technology name to a CVE, a severity, or any vulnerability
classification -- "nginx detected" is technology evidence, never
"nginx vulnerability." Any such correlation, if it ever exists, belongs
entirely to a downstream module this adapter has no knowledge of.

`-tech-detect` is deliberately **never** passed to httpx: live testing
during this checkpoint found that httpx v1.10.0's `-tech-detect` (an ML
classifier, not simple header matching) silently downloads a ~90MB
model from an external host on first use if not already cached --
exactly the kind of undisclosed runtime network mutation this
project's own Nuclei-template-baking precedent (see `Dockerfile`)
deliberately avoids, and a real risk of exceeding this adapter's own
bounded `HTTPX_TIMEOUT_SECONDS`/`MAX_PROCESS_TIMEOUT_SECONDS` on an
uncached first run, or failing outright in an offline/air-gapped
research environment. `technologies`/`tech` is therefore always empty
today; `server` (from `-web-server`, a simple `Server`/technology
header echo) remains the real technology-adjacent signal this adapter
reports.

## Every executable command is built from closed, deterministic inputs

`_build_httpx_command` is the only place an argument vector is ever
assembled, and it accepts only a resolved executable path and one
already-validated single target URL -- never a caller-supplied flag.
`subprocess.run` is always called with a list argument vector and
`shell=False`.

## Bounds (Section 9 of the spec this adapter implements)

- Exactly one target URL per invocation (`MAX_TARGETS_PER_SCAN = 1`) --
  no `-list`/hostfile, no subdomain enumeration, no fan-out to any host
  other than the one already-validated target.
- A fixed, conservative rate limit (`HTTPX_RATE_LIMIT`) and concurrency
  of 1 -- meaningless for a single target, kept for defense in depth if
  this module's target bound is ever relaxed.
- A fixed per-request timeout (`HTTPX_TIMEOUT_SECONDS`) and retry count
  (`HTTPX_RETRIES`).
- Redirects are never followed (`-fr` / `-follow-redirects` is never
  passed) -- exactly like `adapters.bug_bounty_http`, a redirect is
  reported as an observed destination only, never itself fetched by
  this adapter; the calling orchestrator re-validates scope before
  ever treating a redirect target as anything more than evidence.
- A bounded `process_timeout_seconds` (see `_validate_execution_config`)
  terminates only the one child httpx process this adapter itself
  started. Captured stdout is bounded to `max_output_bytes`.

## JSON output only, defensively parsed

httpx's own `-json` output is parsed via `json.loads` on each stdout
line; this adapter never scrapes human-readable terminal text. Field
names are checked against more than one known/versioned httpx JSON key
spelling (e.g. `status_code` vs `status-code`) -- exactly like
`adapters.bug_bounty_nuclei`'s own defensive `template-id`/`templateID`
handling -- since exact key casing has varied across httpx releases;
a field this adapter does not recognize is simply omitted (`None`),
never guessed at.

## Tool-not-installed, timeout, and output bounds

If the `httpx` executable cannot be located on `PATH`, this adapter
returns a structured `"tool_not_installed"` result -- it never
downloads, installs, or falls back to any other command.

## Evidence safety

Only bounded, already-scalar fields (status code, title, content type,
server, technologies, redirect location, scheme/host/port) are ever
extracted into `observations`. Raw stdout/stderr bytes are never
included in the returned result; the only trace of the captured output
is a short local SHA-256 content digest in `evidence_references`.
Free-text fields are bounded in length and defensively redacted if
they resemble a credential/secret.

## Tool result is not a finding

A result this module returns is a raw tool observation, never a
canonical ThreatTrace finding.

`BugBountyHttpxAdapterError` and `run_httpx_scan` are this module's
public symbols (plus `MAX_TARGETS_PER_SCAN`, `MAX_PROCESS_TIMEOUT_SECONDS`,
`MAX_OUTPUT_BYTES`, and `TOOL_RESULT_VERSION`).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

TOOL_RESULT_VERSION = "1"
HTTPX_EXECUTABLE_NAME = "httpx"

MAX_TARGETS_PER_SCAN = 1

HTTPX_TIMEOUT_SECONDS = 5
HTTPX_RETRIES = 1
HTTPX_RATE_LIMIT = 10
HTTPX_CONCURRENCY = 1

# Conservative bounds for one bounded, single-target enrichment request
# against a local/authorized or operator-declared-scoped external
# target. A caller may request a lower value; never a higher one (see
# `_validate_execution_config`).
MAX_PROCESS_TIMEOUT_SECONDS = 30
MAX_OUTPUT_BYTES = 262_144  # 256 KiB -- one JSON object per target, always small

STATUS_VALUES = frozenset({"completed", "failed", "tool_not_installed", "timeout"})

_EXECUTION_CONFIG_VERSION = "1"
_EXECUTION_CONFIG_REQUIRED_FIELDS = ("execution_config_version", "process_timeout_seconds", "max_output_bytes")

_FREE_TEXT_MAX_LENGTH = 256
_REDACTION_MARKERS = (
    "authorization:", "cookie:", "set-cookie:", "api_key", "apikey", "password", "bearer ",
)


class BugBountyHttpxAdapterError(ValueError):
    """Raised when a supplied `target`/`execution_config` is
    structurally invalid -- not a single `http(s)` URL, or an
    `execution_config` that exceeds a hardcoded safety ceiling.

    Never raised for a real scan outcome (missing executable, timeout,
    non-zero exit, malformed output) -- every one of those is a normal,
    successfully returned result with a `status` field, not an error.
    """


def _raise(code: str, detail: str) -> None:
    raise BugBountyHttpxAdapterError(f"{code}: {detail}")


def _require_nonblank_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _raise("INVALID_INPUT", f"{field_name!r} must be a non-blank string")
    return value.strip()


def _sanitize_free_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    lowered = text.lower()
    if any(marker in lowered for marker in _REDACTION_MARKERS):
        return "[REDACTED]"
    return text[:_FREE_TEXT_MAX_LENGTH]


def _sanitize_string_list(value: Any) -> list[str] | None:
    if not isinstance(value, list):
        return None
    sanitized = [_sanitize_free_text(item) for item in value if isinstance(item, str)]
    sanitized = [item for item in sanitized if item]
    return sanitized or None


# ---------------------------------------------------------------------------
# Target / execution_config validation -- private, local, and additive on
# top of whatever core.bug_bounty_tool_policy already approved.
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
# Command construction -- the only place an httpx argument vector is ever
# assembled. Always a list (never a shell string); always these exact
# fixed flags plus the validated single target.
# ---------------------------------------------------------------------------


def _build_httpx_command(*, httpx_path: str, target: str) -> list[str]:
    return [
        httpx_path,
        "-u", target,
        "-json",
        "-silent",
        "-no-color",
        "-timeout", str(HTTPX_TIMEOUT_SECONDS),
        "-retries", str(HTTPX_RETRIES),
        "-rate-limit", str(HTTPX_RATE_LIMIT),
        "-threads", str(HTTPX_CONCURRENCY),
        "-title",
        "-status-code",
        "-content-type",
        "-location",
        "-web-server",
    ]


def _find_httpx_executable() -> str | None:
    return shutil.which(HTTPX_EXECUTABLE_NAME)


def _digest_reference(raw_bytes: bytes) -> str:
    digest = hashlib.sha256(raw_bytes).hexdigest()
    return f"httpx_json_sha256:{digest}"


# ---------------------------------------------------------------------------
# JSON parsing -- structured only, never terminal-text scraping. Every
# field is read defensively across more than one known httpx key
# spelling; an unrecognized field is omitted, never guessed at.
# ---------------------------------------------------------------------------


def _first_of(record: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in record and record[key] is not None:
            return record[key]
    return None


def _normalize_httpx_record(record: Mapping[str, Any]) -> dict[str, Any]:
    status_code = _first_of(record, "status_code", "status-code", "statuscode")
    if isinstance(status_code, bool) or not isinstance(status_code, int):
        status_code = None

    technologies = _sanitize_string_list(_first_of(record, "tech", "technologies"))
    scheme = _sanitize_free_text(_first_of(record, "scheme"))
    host = _sanitize_free_text(_first_of(record, "host"))
    port_raw = _first_of(record, "port")
    port = port_raw if isinstance(port_raw, int) and not isinstance(port_raw, bool) else None

    return {
        "type": "http_enrichment",
        "reachable": status_code is not None,
        "url": _sanitize_free_text(_first_of(record, "url", "input")),
        "status_code": status_code,
        "title": _sanitize_free_text(_first_of(record, "title")),
        "content_type": _sanitize_free_text(_first_of(record, "content_type", "content-type")),
        "server": _sanitize_free_text(_first_of(record, "webserver", "web-server", "server")),
        "technologies": technologies,
        "redirect_location": _sanitize_free_text(_first_of(record, "location")),
        "scheme": scheme,
        "host": host,
        "port": port,
        "failed": bool(_first_of(record, "failed")) if _first_of(record, "failed") is not None else None,
    }


def _parse_httpx_json(raw_bytes: bytes) -> list[dict[str, Any]]:
    text = raw_bytes.decode("utf-8", errors="replace")
    observations: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        observations.append(_normalize_httpx_record(record))
        if len(observations) >= MAX_TARGETS_PER_SCAN:
            break
    return observations


# ---------------------------------------------------------------------------
# Result contract.
# ---------------------------------------------------------------------------


def _build_result(
    *,
    request_id: str,
    target: str,
    status: str,
    observations: list[dict[str, Any]],
    evidence_references: list[str],
    output_truncated: bool,
    error_detail: str | None,
    execution_performed: bool,
) -> dict[str, Any]:
    return {
        "tool_result_version": TOOL_RESULT_VERSION,
        "tool_id": "httpx",
        "request_id": request_id,
        "target": target,
        "status": status,
        "observations": observations,
        "evidence_references": evidence_references,
        "network_requests_performed": 1 if execution_performed else None,
        "output_truncated": output_truncated,
        "error_detail": error_detail,
        "execution_performed": execution_performed,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_httpx_scan(*, target: Any, request_id: Any, execution_config: Any, detected_technologies: Any = None) -> dict[str, Any]:
    """Run one bounded, single-target httpx enrichment request and
    return a structured, sanitized tool result. Never invoked directly
    by the LLM planner -- only `core.bug_bounty_tool_execution` calls
    this, and only after it has re-evaluated the real tool permission
    policy and confirmed a Security Governor `allow` decision.

    `detected_technologies` is accepted only for call-signature
    parity with the other registered adapters (see
    `core.bug_bounty_tool_execution._ADAPTER_REGISTRY`) -- this adapter
    never reads it; httpx performs its own technology detection.

    Raises `BugBountyHttpxAdapterError` for a structurally invalid
    `target` (not a single `http(s)` URL) or `execution_config` (wrong
    shape, or a value exceeding a hardcoded safety ceiling). Never
    raises for a real scan outcome.

    Returns a new dict containing exactly `tool_result_version`,
    `tool_id` (always `"httpx"`), `request_id`, `target`, `status` (one
    of `STATUS_VALUES`), `observations` (a list containing at most one
    `{"type": "http_enrichment", ...}` entry), `evidence_references`
    (a local SHA-256 content digest of the captured output, never the
    raw output itself), `network_requests_performed`, `output_truncated`,
    `error_detail` (a short, safe, fixed description), `execution_performed`.
    """
    validated_target = _validate_scan_target(target)
    validated_request_id = _require_nonblank_string(request_id, "request_id")
    validated_config = _validate_execution_config(execution_config)

    httpx_path = _find_httpx_executable()
    if httpx_path is None:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status="tool_not_installed",
            observations=[], evidence_references=[], output_truncated=False, error_detail=None,
            execution_performed=False,
        )

    argv = _build_httpx_command(httpx_path=httpx_path, target=validated_target)

    try:
        completed = subprocess.run(
            argv, shell=False, capture_output=True, timeout=validated_config["process_timeout_seconds"],
        )
    except subprocess.TimeoutExpired:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status="timeout",
            observations=[], evidence_references=[], output_truncated=False,
            error_detail="httpx did not complete within the configured timeout",
            execution_performed=True,
        )
    except OSError:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status="tool_not_installed",
            observations=[], evidence_references=[], output_truncated=False, error_detail=None,
            execution_performed=False,
        )

    max_bytes = validated_config["max_output_bytes"]
    raw_stdout = completed.stdout or b""
    output_truncated = len(raw_stdout) > max_bytes
    bounded_stdout = raw_stdout[:max_bytes]
    reference = _digest_reference(bounded_stdout) if bounded_stdout else None
    evidence_references = [reference] if reference else []

    # httpx exits non-zero for some genuinely reachable-but-erroring
    # targets in some versions -- unlike nmap/nuclei, still attempt to
    # parse whatever JSON was produced before treating this as a hard
    # failure, matching this adapter's own "never discard real evidence"
    # discipline for a tool that can legitimately emit partial output.
    observations = _parse_httpx_json(bounded_stdout)
    if not observations and completed.returncode != 0:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status="failed",
            observations=[], evidence_references=evidence_references, output_truncated=output_truncated,
            error_detail="httpx exited with a non-zero status and produced no parsable output",
            execution_performed=True,
        )

    return _build_result(
        request_id=validated_request_id, target=validated_target, status="completed",
        observations=observations, evidence_references=evidence_references, output_truncated=output_truncated,
        error_detail=None, execution_performed=True,
    )
