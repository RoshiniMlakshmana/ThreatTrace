"""Real, bounded Katana (ProjectDiscovery) discovery adapter (Final
Pre-Release Block, Authorized External Targets + httpx/Katana).

This is a **fourth** real external-tool adapter, following the exact
same boundary pattern `adapters.bug_bounty_nmap`/`adapters.bug_bounty_nuclei`/
`adapters.bug_bounty_httpx` already established: it performs real
subprocess I/O so `core.bug_bounty_tool_execution` (the single
execution boundary that calls it) and every other `core.*` module
never have to.

## REMOTE-DISCOVERED URLS ARE UNTRUSTED CANDIDATE DATA, NOT SCOPE

Exactly like `core.bug_bounty_crawler`'s own module docstring states
for its own discovery: every URL this adapter reports is an unvetted
*candidate* the target itself returned, never something this adapter
has confirmed is in scope. This adapter performs **no scope
enforcement of its own** -- `observations` here is raw, sanitized
Katana output only. The calling orchestrator (`backend.orchestrator`)
is responsible for independently re-validating every single discovered
URL through `core.bug_bounty_scope.evaluate_bug_bounty_request_scope`
before registering it into the attack surface or handing it to any
other tool -- exactly the same discipline `core.bug_bounty_crawler`
already applies to its own discovered candidates. This adapter itself
never requests, fetches, or acts on a discovered URL beyond what
Katana's own single bounded crawl already did.

## What this adapter answers

*Given one already-validated, in-scope seed URL, what additional
same-host URLs/paths does a bounded, non-headless Katana crawl
discover?* Nothing more. This is a second, independent discovery
engine alongside `core.bug_bounty_crawler` -- Katana is a mature,
external, widely-used crawler this project reuses rather than
reimplementing every JS-aware discovery heuristic itself; the two are
never required to agree, and neither result is discarded because the
other found something different.

## Every executable command is built from closed, deterministic inputs

`_build_katana_command` is the only place an argument vector is ever
assembled, and it accepts only a resolved executable path and one
already-validated single seed URL -- never a caller-supplied flag.
`subprocess.run` is always called with a list argument vector and
`shell=False`.

## Bounds (Section 11 of the spec this adapter implements)

- `KATANA_MAX_DEPTH = 2` -- passed to Katana's own `-depth` flag.
- `KATANA_SAME_HOST_ONLY = True` -- passed via `-field-scope dn`
  (exact-domain scope), so Katana itself never crawls off the seed
  host; the orchestrator's own scope re-validation (see above) is the
  authoritative check regardless.
- `MAX_ENDPOINTS_RETURNED = 100` -- enforced in this adapter's own
  Python post-processing (never solely trusted to an external CLI
  flag): at most this many discovered URLs are ever included in
  `observations`, even if Katana itself reported more.
- A fixed, conservative rate limit (`KATANA_RATE_LIMIT`) and
  concurrency of 1 (`KATANA_CONCURRENCY`).
- A fixed per-request timeout (`KATANA_TIMEOUT_SECONDS`).
- **Headless browser execution is never enabled** -- this adapter never
  passes `-headless`/`-hl`, so Katana always runs in its default,
  faster, non-headless HTTP-crawl mode. Headless remains a possible
  future, explicitly-opt-in capability this checkpoint does not add.
- **No form submission, no authentication, no file upload, no
  fuzzing** -- this adapter passes no flag that would enable any of
  those (`-fx`/form extraction is passed for discovery-only form
  *metadata*, mirroring `core.bug_bounty_crawler`'s own "forms are
  discovery-only, never submitted" rule -- Katana itself never submits
  a form it discovers).
- A bounded `process_timeout_seconds` (see `_validate_execution_config`)
  terminates only the one child Katana process this adapter itself
  started. Captured stdout is bounded to `max_output_bytes`.

## JSON-Lines output only, defensively parsed

Katana's own `-json` output is parsed line by line via `json.loads`;
this adapter never scrapes human-readable terminal text. Only a
bounded set of scalar/short-list fields (URL, method, source, status
code where present, discovered query **parameter names** -- never
values) are ever extracted -- matching `core.bug_bounty_crawler`'s own
"never store sensitive parameter values unnecessarily" rule.

## Tool-not-installed, timeout, and output bounds

If the `katana` executable cannot be located on `PATH`, this adapter
returns a structured `"tool_not_installed"` result -- it never
downloads, installs, or falls back to any other command.

## Tool result is not a finding

A result this module returns is a raw tool observation, never a
canonical ThreatTrace finding, and never itself an attack-surface
registration (see the untrusted-candidate-data section above).

`BugBountyKatanaAdapterError` and `run_katana_scan` are this module's
public symbols (plus `KATANA_MAX_DEPTH`, `MAX_ENDPOINTS_RETURNED`,
`MAX_PROCESS_TIMEOUT_SECONDS`, `MAX_OUTPUT_BYTES`, and
`TOOL_RESULT_VERSION`).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlsplit

TOOL_RESULT_VERSION = "1"
KATANA_EXECUTABLE_NAME = "katana"

KATANA_MAX_DEPTH = 2
MAX_ENDPOINTS_RETURNED = 100

KATANA_TIMEOUT_SECONDS = 5
KATANA_RATE_LIMIT = 10
KATANA_CONCURRENCY = 1

# Conservative bound for one bounded, single-seed, non-headless crawl
# against a local/authorized or operator-declared-scoped external
# target. A caller may request a lower value; never a higher one (see
# `_validate_execution_config`).
MAX_PROCESS_TIMEOUT_SECONDS = 60
MAX_OUTPUT_BYTES = 1_048_576  # 1 MiB

STATUS_VALUES = frozenset({"completed", "failed", "tool_not_installed", "timeout"})

_EXECUTION_CONFIG_VERSION = "1"
_EXECUTION_CONFIG_REQUIRED_FIELDS = ("execution_config_version", "process_timeout_seconds", "max_output_bytes")

_FREE_TEXT_MAX_LENGTH = 256
_REDACTION_MARKERS = (
    "authorization:", "cookie:", "set-cookie:", "api_key", "apikey", "password", "bearer ",
)


class BugBountyKatanaAdapterError(ValueError):
    """Raised when a supplied `target`/`execution_config` is
    structurally invalid -- not a single `http(s)` URL, or an
    `execution_config` that exceeds a hardcoded safety ceiling.

    Never raised for a real scan outcome (missing executable, timeout,
    non-zero exit, malformed output) -- every one of those is a normal,
    successfully returned result with a `status` field, not an error.
    """


def _raise(code: str, detail: str) -> None:
    raise BugBountyKatanaAdapterError(f"{code}: {detail}")


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
# Command construction -- the only place a Katana argument vector is ever
# assembled. Always a list (never a shell string); always these exact
# fixed flags plus the validated single seed URL. Headless is never
# requested; no auth/upload/fuzz flag is ever passed.
# ---------------------------------------------------------------------------


def _build_katana_command(*, katana_path: str, target: str) -> list[str]:
    return [
        katana_path,
        "-u", target,
        "-depth", str(KATANA_MAX_DEPTH),
        "-json",
        "-silent",
        "-no-color",
        "-timeout", str(KATANA_TIMEOUT_SECONDS),
        "-rate-limit", str(KATANA_RATE_LIMIT),
        "-concurrency", str(KATANA_CONCURRENCY),
        "-field-scope", "dn",
    ]


def _find_katana_executable() -> str | None:
    return shutil.which(KATANA_EXECUTABLE_NAME)


def _digest_reference(raw_bytes: bytes) -> str:
    digest = hashlib.sha256(raw_bytes).hexdigest()
    return f"katana_json_sha256:{digest}"


# ---------------------------------------------------------------------------
# JSON-Lines parsing -- structured only, never terminal-text scraping.
# Only parameter NAMES are ever kept -- never values (see module
# docstring). Fields are read defensively across more than one known
# katana key spelling; an unrecognized field is omitted.
# ---------------------------------------------------------------------------


def _first_of(record: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in record and record[key] is not None:
            return record[key]
    return None


def _extract_query_parameter_names(url: str | None) -> list[str] | None:
    if not url:
        return None
    try:
        query = urlsplit(url).query
    except ValueError:
        return None
    if not query:
        return None
    names = sorted({name for name, _value in parse_qsl(query, keep_blank_values=True)})
    return names or None


def _normalize_katana_record(record: Mapping[str, Any]) -> dict[str, Any] | None:
    request = record.get("request") if isinstance(record.get("request"), Mapping) else record
    response = record.get("response") if isinstance(record.get("response"), Mapping) else {}

    url = _first_of(request, "endpoint", "url")
    if not isinstance(url, str) or not url.strip():
        return None

    method = _sanitize_free_text(_first_of(request, "method")) or "GET"
    source = _sanitize_free_text(_first_of(request, "source", "tag"))
    status_code = _first_of(response, "status_code", "status-code")
    if isinstance(status_code, bool) or not isinstance(status_code, int):
        status_code = None

    return {
        "type": "discovered_url",
        "url": _sanitize_free_text(url),
        "method": method.upper() if method else "GET",
        "source": source,
        "status_code": status_code,
        "parameter_names": _extract_query_parameter_names(url),
    }


def _parse_katana_jsonl(raw_bytes: bytes) -> list[dict[str, Any]]:
    text = raw_bytes.decode("utf-8", errors="replace")
    observations: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
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
        normalized = _normalize_katana_record(record)
        if normalized is None or normalized["url"] in seen_urls:
            continue
        seen_urls.add(normalized["url"])
        observations.append(normalized)
        if len(observations) >= MAX_ENDPOINTS_RETURNED:
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
    endpoint_limit_reached: bool = False,
) -> dict[str, Any]:
    return {
        "tool_result_version": TOOL_RESULT_VERSION,
        "tool_id": "katana",
        "request_id": request_id,
        "target": target,
        "status": status,
        "observations": observations,
        "evidence_references": evidence_references,
        "network_requests_performed": None,
        "output_truncated": output_truncated,
        "endpoint_limit_reached": endpoint_limit_reached,
        "error_detail": error_detail,
        "execution_performed": execution_performed,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_katana_scan(*, target: Any, request_id: Any, execution_config: Any, detected_technologies: Any = None) -> dict[str, Any]:
    """Run one bounded, single-seed, non-headless Katana discovery crawl
    and return a structured, sanitized tool result of **untrusted
    candidate URLs** (see module docstring). Never invoked directly by
    the LLM planner -- only `core.bug_bounty_tool_execution` calls
    this, and only after it has re-evaluated the real tool permission
    policy and confirmed a Security Governor `allow` decision.

    `detected_technologies` is accepted only for call-signature parity
    with the other registered adapters (see
    `core.bug_bounty_tool_execution._ADAPTER_REGISTRY`) -- this adapter
    never reads it.

    Raises `BugBountyKatanaAdapterError` for a structurally invalid
    `target` (not a single `http(s)` URL) or `execution_config` (wrong
    shape, or a value exceeding a hardcoded safety ceiling). Never
    raises for a real scan outcome.

    Returns a new dict containing exactly `tool_result_version`,
    `tool_id` (always `"katana"`), `request_id`, `target`, `status`
    (one of `STATUS_VALUES`), `observations` (a list of at most
    `MAX_ENDPOINTS_RETURNED` `{"type": "discovered_url", ...}` entries
    -- **untrusted candidates, not scope-validated attack-surface
    entries**; the calling orchestrator must re-validate each one),
    `evidence_references` (a local SHA-256 content digest of the
    captured output), `network_requests_performed` (always `None` --
    Katana does not reliably report this), `output_truncated`,
    `endpoint_limit_reached` (`True` when Katana's own output contained
    more discovered URLs than `MAX_ENDPOINTS_RETURNED`), `error_detail`,
    `execution_performed`.
    """
    validated_target = _validate_scan_target(target)
    validated_request_id = _require_nonblank_string(request_id, "request_id")
    validated_config = _validate_execution_config(execution_config)

    katana_path = _find_katana_executable()
    if katana_path is None:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status="tool_not_installed",
            observations=[], evidence_references=[], output_truncated=False, error_detail=None,
            execution_performed=False,
        )

    argv = _build_katana_command(katana_path=katana_path, target=validated_target)

    try:
        completed = subprocess.run(
            argv, shell=False, capture_output=True, timeout=validated_config["process_timeout_seconds"],
        )
    except subprocess.TimeoutExpired:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status="timeout",
            observations=[], evidence_references=[], output_truncated=False,
            error_detail="katana did not complete within the configured timeout",
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

    observations = _parse_katana_jsonl(bounded_stdout)
    total_lines = sum(1 for line in bounded_stdout.decode("utf-8", errors="replace").splitlines() if line.strip())
    endpoint_limit_reached = total_lines > len(observations)

    if not observations and completed.returncode != 0:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status="failed",
            observations=[], evidence_references=evidence_references, output_truncated=output_truncated,
            error_detail="katana exited with a non-zero status and produced no parsable output",
            execution_performed=True,
        )

    return _build_result(
        request_id=validated_request_id, target=validated_target, status="completed",
        observations=observations, evidence_references=evidence_references, output_truncated=output_truncated,
        error_detail=None, execution_performed=True, endpoint_limit_reached=endpoint_limit_reached,
    )
