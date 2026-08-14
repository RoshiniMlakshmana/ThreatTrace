"""Real, bounded Nuclei safe-profile scanning adapter (Block 15G-B).

This is the **second** of two real external-tool adapters this block
adds. Like `adapters.bug_bounty_nmap`, this is a boundary module -- it
performs real subprocess I/O so `core.bug_bounty_tool_execution` (the
single execution boundary that calls it) and every other `core.*` module
never have to.

## Every executable command is built from closed, deterministic inputs

`_build_nuclei_command` is the only place an argument vector is ever
assembled, and it accepts only a resolved executable path and one
already-validated target URL -- never a caller-supplied flag, template
path, template ID, or raw string. `subprocess.run` is always called with
a list argument vector and `shell=False`.

## One fixed safe profile only -- no planner-selected templates

Block 15G-B's own spec is explicit: if template IDs cannot be safely
allowlisted yet, use one fixed safe profile instead of accepting any
caller-selected template surface. This adapter does exactly that --
there is no parameter anywhere in `run_nuclei_scan`'s signature for a
template path, template ID, or tag. The fixed profile:

- Template directories: `http/` and `ssl/` only (via `-t http/ -t ssl/`)
  -- never `code/`, `javascript/`, `file/`, `headless/`, or any
  workflow-based aggressive chain.
- `-etags fuzz` -- explicitly excludes fuzzing templates.
- `-ni` (`-no-interactsh`) -- explicitly disables OAST/interactsh
  polling.
- Headless, code-protocol, JS-protocol, cloud-upload, uncover/internet-
  database-discovery, and authenticated-scan flags are never passed --
  every one of those capabilities is opt-in in Nuclei itself, so simply
  never including the flag that would enable it keeps this adapter's
  invocation safe by omission, not by attempting to enumerate every
  possible dangerous flag.
- `-rl <NUCLEI_RATE_LIMIT>` / `-c <NUCLEI_CONCURRENCY>` -- fixed,
  conservative, non-caller-configurable rate and concurrency limits (see
  the module constants below), well under Nuclei's own higher defaults.
- `-jsonl -silent` -- structured JSON-Lines output only; this adapter
  never scrapes Nuclei's human-readable terminal output.

## Tool-not-installed, timeout, and output bounds

Mirrors `adapters.bug_bounty_nmap`: a missing `nuclei` executable is
reported as a structured `"tool_not_installed"` result; a bounded
`process_timeout_seconds` terminates only the one child Nuclei process
this adapter started; captured stdout is bounded to `max_output_bytes`
with `output_truncated` reported honestly.

## Evidence safety

Only a small, fixed set of scalar fields is ever extracted from each
JSON-Lines match record into `observations`; a full raw response body,
if Nuclei's own output happens to include one for a matched template, is
never copied into the result. Free-text fields are bounded in length and
defensively redacted if they resemble a credential/secret. No CVE/CWE
identifier is ever invented -- `classification` only ever echoes what
Nuclei's own template metadata reported, or is `None`.

## Tool result is not a finding

Exactly like `adapters.bug_bounty_nmap`, a result this module returns is
a raw tool observation, never a canonical ThreatTrace finding.

`BugBountyNucleiAdapterError` and `run_nuclei_scan` are this module's
public symbols (plus `NUCLEI_RATE_LIMIT`, `NUCLEI_CONCURRENCY`,
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
from urllib.parse import urlsplit

TOOL_RESULT_VERSION = "1"
NUCLEI_EXECUTABLE_NAME = "nuclei"

# Fixed safe profile -- see module docstring. Never caller-configurable.
NUCLEI_TEMPLATE_DIRECTORIES = ("http/", "ssl/")
NUCLEI_EXCLUDED_TAGS = ("fuzz",)
NUCLEI_RATE_LIMIT = 10
NUCLEI_CONCURRENCY = 5

# Conservative bounds for one bounded scan, against a local/authorized
# target, restricted to the http/ssl template directories only. A caller
# may request a lower value; never a higher one.
MAX_PROCESS_TIMEOUT_SECONDS = 90
MAX_OUTPUT_BYTES = 1_048_576  # 1 MiB

STATUS_VALUES = frozenset({"completed", "failed", "tool_not_installed", "timeout"})

_EXECUTION_CONFIG_VERSION = "1"
_EXECUTION_CONFIG_REQUIRED_FIELDS = ("execution_config_version", "process_timeout_seconds", "max_output_bytes")

_FREE_TEXT_MAX_LENGTH = 256
_REDACTION_MARKERS = (
    "authorization:", "cookie:", "set-cookie:", "api_key", "apikey", "password", "bearer ",
)


class BugBountyNucleiAdapterError(ValueError):
    """Raised when a supplied `target`/`execution_config` is structurally
    invalid -- not a bare `http(s)` URL, or an `execution_config` that
    exceeds a hardcoded safety ceiling.

    Never raised for a real scan outcome (missing executable, timeout,
    non-zero exit, malformed output) -- every one of those is a normal,
    successfully returned result with a `status` field, not an error.
    """


def _raise(code: str, detail: str) -> None:
    raise BugBountyNucleiAdapterError(f"{code}: {detail}")


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
# Target / execution_config validation -- private, local, additive on top
# of whatever core.bug_bounty_tool_policy already approved.
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
# Command construction -- the only place a Nuclei argument vector is ever
# assembled. Always a list (never a shell string); always this exact
# fixed safe profile plus the one validated target URL.
# ---------------------------------------------------------------------------


def _build_nuclei_command(*, nuclei_path: str, target: str) -> list[str]:
    argv = [nuclei_path, "-u", target]
    for directory in NUCLEI_TEMPLATE_DIRECTORIES:
        argv += ["-t", directory]
    argv += [
        "-etags", ",".join(NUCLEI_EXCLUDED_TAGS),
        "-ni",
        "-rl", str(NUCLEI_RATE_LIMIT),
        "-c", str(NUCLEI_CONCURRENCY),
        "-jsonl",
        "-silent",
    ]
    return argv


def _find_nuclei_executable() -> str | None:
    return shutil.which(NUCLEI_EXECUTABLE_NAME)


def _digest_reference(raw_bytes: bytes) -> str:
    digest = hashlib.sha256(raw_bytes).hexdigest()
    return f"nuclei_jsonl_sha256:{digest}"


# ---------------------------------------------------------------------------
# JSON-Lines parsing -- structured only, never terminal-text scraping.
# Malformed individual lines are skipped, never treated as a fatal error
# for the whole scan.
# ---------------------------------------------------------------------------


def _normalize_classification(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    cve_id = _sanitize_string_list(value.get("cve-id"))
    cwe_id = _sanitize_string_list(value.get("cwe-id"))
    if cve_id is None and cwe_id is None:
        return None
    return {"cve_id": cve_id, "cwe_id": cwe_id}


def _normalize_nuclei_record(record: Mapping[str, Any]) -> dict[str, Any]:
    template_id = record.get("template-id") or record.get("templateID")
    info = record.get("info") if isinstance(record.get("info"), Mapping) else {}
    matched_at = record.get("matched-at") or record.get("matched_at") or record.get("host")

    return {
        "type": "known_pattern_match",
        "template_id": _sanitize_free_text(template_id),
        "title": _sanitize_free_text(info.get("name")),
        "severity": _sanitize_free_text(info.get("severity")),
        "target": _sanitize_free_text(matched_at),
        "matcher": _sanitize_free_text(record.get("matcher-name")),
        "classification": _normalize_classification(info.get("classification")),
    }


def _parse_nuclei_jsonl(raw_bytes: bytes) -> list[dict[str, Any]]:
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
        observations.append(_normalize_nuclei_record(record))
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
        "tool_id": "nuclei",
        "request_id": request_id,
        "target": target,
        "status": status,
        "observations": observations,
        "evidence_references": evidence_references,
        "network_requests_performed": None,
        "output_truncated": output_truncated,
        "error_detail": error_detail,
        "execution_performed": execution_performed,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_nuclei_scan(*, target: Any, request_id: Any, execution_config: Any) -> dict[str, Any]:
    """Run one bounded Nuclei scan, restricted to the fixed safe
    `http/`+`ssl/` template profile (see module docstring), and return a
    structured, sanitized tool result. Never invoked directly by the LLM
    planner -- only `core.bug_bounty_tool_execution` calls this, and only
    after it has re-evaluated the real tool permission policy and
    confirmed a Security Governor `allow` decision.

    Raises `BugBountyNucleiAdapterError` for a structurally invalid
    `target` (not a bare `http(s)` URL), `request_id` (not a non-blank
    string), or `execution_config` (wrong shape, or a value exceeding a
    hardcoded safety ceiling). Never raises for a real scan outcome -- a
    missing `nuclei` executable, a process timeout, a non-zero exit, or
    malformed JSON-Lines output are all represented through the returned
    `status` field (individual malformed lines are silently skipped
    rather than failing the whole scan).

    Returns a new dict containing exactly `tool_result_version`,
    `tool_id` (always `"nuclei"`), `request_id`, `target`, `status` (one
    of `STATUS_VALUES`), `observations` (a list of
    `{"type": "known_pattern_match", ...}` entries), `evidence_references`
    (a local SHA-256 content digest of the captured output, never the raw
    output itself), `network_requests_performed` (always `None`),
    `output_truncated`, `error_detail` (a short, safe, fixed description,
    never raw stderr or an exception message), `execution_performed`
    (`True` once a real Nuclei process was actually started, including a
    timed-out one; `False` only when the executable could not be found
    and no process was ever started).
    """
    validated_target = _validate_scan_target(target)
    validated_request_id = _require_nonblank_string(request_id, "request_id")
    validated_config = _validate_execution_config(execution_config)

    nuclei_path = _find_nuclei_executable()
    if nuclei_path is None:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status="tool_not_installed",
            observations=[], evidence_references=[], output_truncated=False, error_detail=None,
            execution_performed=False,
        )

    argv = _build_nuclei_command(nuclei_path=nuclei_path, target=validated_target)

    try:
        completed = subprocess.run(
            argv, shell=False, capture_output=True, timeout=validated_config["process_timeout_seconds"],
        )
    except subprocess.TimeoutExpired:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status="timeout",
            observations=[], evidence_references=[], output_truncated=False,
            error_detail="nuclei did not complete within the configured timeout",
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
    reference = _digest_reference(bounded_stdout)

    if completed.returncode != 0:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status="failed",
            observations=[], evidence_references=[reference], output_truncated=output_truncated,
            error_detail="nuclei exited with a non-zero status", execution_performed=True,
        )

    observations = _parse_nuclei_jsonl(bounded_stdout)

    return _build_result(
        request_id=validated_request_id, target=validated_target, status="completed",
        observations=observations, evidence_references=[reference], output_truncated=output_truncated,
        error_detail=None, execution_performed=True,
    )
