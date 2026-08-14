"""Real, bounded Nmap TCP reconnaissance adapter (Block 15G-B).

This is the **first** of two real external-tool adapters this block adds.
Like `adapters.bug_bounty_http`, this is a boundary module -- it performs
real subprocess/filesystem-adjacent I/O so `core.bug_bounty_tool_execution`
(the single execution boundary that calls it) and every other `core.*`
module never have to.

## What this adapter answers

Exactly the bounded question Block 15G-B scopes it to: *is one
analyst-approved host reachable through a requested, scoped TCP port
check, and what service/version information (if any) does Nmap report
for each open port?* It never performs host discovery across a range,
OS fingerprinting, NSE scripting, or UDP scanning.

## Every executable command is built from closed, deterministic inputs

`_build_nmap_command` is the only place an argument vector is ever
assembled, and it accepts only a resolved executable path, one already
-validated single host string, and an already-validated list of ports --
never a caller-supplied flag, script name, or raw string. The fixed flags
(`-Pn -sT -T3 -p <ports> -oX -`) are hardcoded and never vary: no `-sC`,
no `--script`, no `-O` (OS detection), no `-sU` (UDP), no timing/evasion
flags beyond the fixed `-T3`. `subprocess.run` is always called with a
list argument vector and `shell=False` -- this module never builds a
shell string, never calls `os.system`, and never interpolates caller data
into a string that reaches a shell.

## Target and port boundaries (Section 9/10 of the Block 15G-B spec)

Exactly one bare host per invocation -- no CIDR notation, no wildcard, no
comma/whitespace-separated multiple hosts, no hostfile. At most
`MAX_PORTS_PER_SCAN` (20) explicit ports per invocation -- never `-p-`,
never all 65535 ports. These are enforced here independently of, and in
addition to, whatever `core.bug_bounty_tool_policy` has already approved
-- the policy layer bounds analyst/profile/scope permission; this layer
additionally bounds what a single Nmap invocation is structurally allowed
to request, regardless of how permissive the policy layer's own ports
list is.

## XML output only, never scraped terminal text

Nmap's own documentation recommends its XML output (`-oX`) for
programmatic consumption; this adapter requests it on stdout (`-oX -`)
and parses it with the standard library's `xml.etree.ElementTree`. It
never parses Nmap's human-readable terminal output.

## Tool-not-installed, timeout, and output bounds

If the `nmap` executable cannot be located on `PATH`, this adapter
returns a structured `"tool_not_installed"` result -- it never downloads,
installs, or falls back to any other command. A bounded
`process_timeout_seconds` (see `_validate_execution_config`) terminates
only the one child Nmap process this adapter itself started, never an
unrelated process. Captured stdout is bounded to `max_output_bytes`;
anything beyond that is dropped and `output_truncated` is reported
`True` -- this adapter never buffers unbounded subprocess output.

## Evidence safety

Only a small set of scalar fields (port/protocol/state/service/product/
version) are ever extracted from Nmap's XML into `observations`. Raw
stdout/stderr bytes are never included in the returned result; the only
trace of the captured output is a short local SHA-256 content digest in
`evidence_references`, exactly mirroring the local-content-correlation-
digest pattern used elsewhere in this project (see
`adapters.bug_bounty_http`'s docstring). Free-text fields are bounded in
length and defensively redacted if they resemble a credential/secret.

## Tool result is not a finding

A result this module returns is a raw tool observation, never a
canonical ThreatTrace finding -- correlation into findings is explicitly
out of scope for this block (see `docs/block15g-nmap-nuclei-adapters.md`).

`BugBountyNmapAdapterError` and `run_nmap_scan` are this module's public
symbols (plus `MAX_PORTS_PER_SCAN`, `MAX_PROCESS_TIMEOUT_SECONDS`,
`MAX_OUTPUT_BYTES`, and `TOOL_RESULT_VERSION`).
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from typing import Any

TOOL_RESULT_VERSION = "1"
NMAP_EXECUTABLE_NAME = "nmap"

# A single-host, single-invocation bounded TCP recon adapter -- 20 ports
# is a generous ceiling for one deliberate, analyst-approved check while
# staying far away from anything resembling a broad port sweep.
MAX_PORTS_PER_SCAN = 20

# Conservative bounds for one bounded, single-host, <=20-port TCP connect
# scan against a local/authorized target. A caller may request a lower
# value; never a higher one (see `_validate_execution_config`).
MAX_PROCESS_TIMEOUT_SECONDS = 60
MAX_OUTPUT_BYTES = 1_048_576  # 1 MiB

STATUS_VALUES = frozenset({"completed", "failed", "tool_not_installed", "timeout"})

_EXECUTION_CONFIG_VERSION = "1"
_EXECUTION_CONFIG_REQUIRED_FIELDS = ("execution_config_version", "process_timeout_seconds", "max_output_bytes")

_FREE_TEXT_MAX_LENGTH = 256
_REDACTION_MARKERS = (
    "authorization:", "cookie:", "set-cookie:", "api_key", "apikey", "password", "bearer ",
)


class BugBountyNmapAdapterError(ValueError):
    """Raised when a supplied `target`/`ports`/`execution_config` is
    structurally invalid -- not a single bare host, a CIDR/wildcard
    target, more than `MAX_PORTS_PER_SCAN` ports, or an `execution_config`
    that exceeds a hardcoded safety ceiling.

    Never raised for a real scan outcome (missing executable, timeout,
    non-zero exit, malformed XML) -- every one of those is a normal,
    successfully returned result with a `status` field, not an error.
    """


def _raise(code: str, detail: str) -> None:
    raise BugBountyNmapAdapterError(f"{code}: {detail}")


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
# Target / port / execution_config validation -- private, local, and
# additive on top of whatever core.bug_bounty_tool_policy already
# approved. Never imported from that module, following this project's
# established convention of each module owning its own validation logic.
# ---------------------------------------------------------------------------


def _validate_scan_target(target: Any) -> str:
    candidate = _require_nonblank_string(target, "target")
    if "://" in candidate:
        _raise("INVALID_TARGET", "target must be a bare host, not a URL")
    if "/" in candidate:
        _raise("INVALID_TARGET", "CIDR ranges are not permitted")
    if "," in candidate or " " in candidate or "\t" in candidate:
        _raise("INVALID_TARGET", "only a single host is permitted per invocation")
    if "*" in candidate:
        _raise("INVALID_TARGET", "wildcard targets are not permitted")
    return candidate


def _validate_ports(ports: Any) -> list[int]:
    if not isinstance(ports, list) or len(ports) == 0:
        _raise("INVALID_PORTS", "ports must be a non-empty list")
    if len(ports) > MAX_PORTS_PER_SCAN:
        _raise("INVALID_PORTS", f"at most {MAX_PORTS_PER_SCAN} ports are permitted per invocation")
    validated: list[int] = []
    seen: set[int] = set()
    for item in ports:
        if isinstance(item, bool) or not isinstance(item, int) or item < 1 or item > 65535:
            _raise("INVALID_PORTS", "each port must be an int between 1 and 65535")
        if item in seen:
            _raise("INVALID_PORTS", "duplicate port entries are not permitted")
        seen.add(item)
        validated.append(item)
    return validated


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
# Command construction -- the only place an Nmap argument vector is ever
# assembled. Always a list (never a shell string); always these exact
# fixed flags plus the validated host/ports.
# ---------------------------------------------------------------------------


def _build_nmap_command(*, nmap_path: str, target: str, ports: list[int]) -> list[str]:
    port_list = ",".join(str(port) for port in ports)
    return [nmap_path, "-Pn", "-sT", "-T3", "-p", port_list, "-oX", "-", target]


def _find_nmap_executable() -> str | None:
    return shutil.which(NMAP_EXECUTABLE_NAME)


def _digest_reference(raw_bytes: bytes) -> str:
    digest = hashlib.sha256(raw_bytes).hexdigest()
    return f"nmap_xml_sha256:{digest}"


# ---------------------------------------------------------------------------
# XML parsing -- structured only, never terminal-text scraping.
# ---------------------------------------------------------------------------


def _parse_nmap_xml(xml_bytes: bytes) -> list[dict[str, Any]]:
    root = ET.fromstring(xml_bytes)  # may raise ET.ParseError -- caller handles it
    observations: list[dict[str, Any]] = []
    for host_el in root.findall("host"):
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            portid = port_el.get("portid")
            try:
                port_number = int(portid) if portid is not None else None
            except ValueError:
                port_number = None
            if port_number is None:
                continue

            protocol = port_el.get("protocol")
            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else None
            service_el = port_el.find("service")
            service_name = service_el.get("name") if service_el is not None else None
            product = service_el.get("product") if service_el is not None else None
            version = service_el.get("version") if service_el is not None else None

            observations.append({
                "type": "service",
                "port": port_number,
                "protocol": protocol if protocol == "udp" else "tcp",
                "state": _sanitize_free_text(state),
                "service": _sanitize_free_text(service_name),
                "product": _sanitize_free_text(product),
                "version": _sanitize_free_text(version),
            })
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
        "tool_id": "nmap",
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


def run_nmap_scan(*, target: Any, ports: Any, request_id: Any, execution_config: Any) -> dict[str, Any]:
    """Run one bounded, single-host, TCP-only Nmap scan and return a
    structured, sanitized tool result. Never invoked directly by the LLM
    planner -- only `core.bug_bounty_tool_execution` calls this, and only
    after it has re-evaluated the real tool permission policy and
    confirmed a Security Governor `allow` decision.

    Raises `BugBountyNmapAdapterError` for a structurally invalid
    `target` (not a bare single host; CIDR/wildcard/multiple hosts),
    `ports` (empty, more than `MAX_PORTS_PER_SCAN`, out of range, or
    duplicated), `request_id` (not a non-blank string), or
    `execution_config` (wrong shape, or a value exceeding a hardcoded
    safety ceiling). Never raises for a real scan outcome -- a missing
    `nmap` executable, a process timeout, a non-zero exit, or malformed
    XML output are all represented through the returned `status` field.

    Returns a new dict containing exactly `tool_result_version`,
    `tool_id` (always `"nmap"`), `request_id`, `target`, `status` (one of
    `STATUS_VALUES`), `observations` (a list of `{"type": "service", ...}`
    entries), `evidence_references` (a local SHA-256 content digest of
    the captured output, never the raw output itself),
    `network_requests_performed` (always `None` -- Nmap does not reliably
    report this), `output_truncated`, `error_detail` (a short, safe,
    fixed description, never raw stderr or an exception message),
    `execution_performed` (`True` once a real Nmap process was actually
    started, including a timed-out one; `False` only when the executable
    could not be found and no process was ever started).
    """
    validated_target = _validate_scan_target(target)
    validated_ports = _validate_ports(ports)
    validated_request_id = _require_nonblank_string(request_id, "request_id")
    validated_config = _validate_execution_config(execution_config)

    nmap_path = _find_nmap_executable()
    if nmap_path is None:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status="tool_not_installed",
            observations=[], evidence_references=[], output_truncated=False, error_detail=None,
            execution_performed=False,
        )

    argv = _build_nmap_command(nmap_path=nmap_path, target=validated_target, ports=validated_ports)

    try:
        completed = subprocess.run(
            argv, shell=False, capture_output=True, timeout=validated_config["process_timeout_seconds"],
        )
    except subprocess.TimeoutExpired:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status="timeout",
            observations=[], evidence_references=[], output_truncated=False,
            error_detail="nmap did not complete within the configured timeout",
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
            error_detail="nmap exited with a non-zero status", execution_performed=True,
        )

    try:
        observations = _parse_nmap_xml(bounded_stdout)
    except ET.ParseError:
        return _build_result(
            request_id=validated_request_id, target=validated_target, status="failed",
            observations=[], evidence_references=[reference], output_truncated=output_truncated,
            error_detail="nmap output could not be parsed as XML", execution_performed=True,
        )

    return _build_result(
        request_id=validated_request_id, target=validated_target, status="completed",
        observations=observations, evidence_references=[reference], output_truncated=output_truncated,
        error_detail=None, execution_performed=True,
    )
