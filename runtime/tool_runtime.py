"""Deterministic tool/runtime readiness detection (Block 15L-16).

This module answers exactly one question per tool: *is it usable right
now, and if not, precisely why not?* It never executes an offensive
scan, never installs software, never elevates privileges, and never
bypasses analyst/admin approval.

## Injectable I/O boundary, mirroring this project's adapter convention

Every real subprocess call, `PATH` lookup, and HTTP probe is reached
through an injectable parameter with a real default (`which_func`,
`runner`, `http_get`, `env`) -- exactly like `adapters.bug_bounty_http.
BugBountyHttpTransport`'s injectable `clock`/`sleep`. This is what makes
every check in this module deterministically testable with a fake
runner, never a real `nmap`/`docker`/`nuclei` process, per this
checkpoint's own explicit requirement that tests mock environment
discovery.

## Closed argv, `shell=False`, always

`real_run` never accepts a shell string -- every subprocess invocation
in this module builds a fixed, closed `argv` list (a discovered
executable path plus a small number of hardcoded, non-caller-supplied
flags like `-V`/`-version`) and calls `subprocess.run(argv, shell=False,
...)`. No LLM-generated command, and no caller-supplied string, is ever
concatenated into a shell command anywhere in this module.

## Never a silent installer, never a privilege escalation

This module only *detects*. It never runs `pip install`, `docker pull`,
`nuclei -update-templates`, an Npcap installer, or any other
install/update command on its own. Where an install step is genuinely
needed (Nmap/Npcap on Windows, missing Nuclei templates), the readiness
state names the requirement (`requires_admin_install`) and the detail
text points to `docs/demo-runbook.md` for manual, analyst-performed
instructions -- it is never performed here.

## Two questions kept separate: capability declared vs. adapter implemented

`authenticated_testing`/`controlled_validation` are always
`"not_implemented"` here, mirroring `core.bug_bounty_tool_policy.
TOOL_CATALOG`'s own `implemented: False` for the same two tool ids --
this module never claims a capability is ready merely because it is a
recognized `TOOL_IDS` entry.

`ToolRuntimeError`, `evaluate_tool_readiness`, and the individual
`check_*` functions are this module's public API (plus its fixed
vocabulary constants).
"""

from __future__ import annotations

import http.client
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from adapters.bug_bounty_burp import BURP_API_HOST_ENV_VAR, BURP_API_KEY_ENV_VAR, BURP_API_PORT_ENV_VAR

RUNTIME_REPORT_VERSION = "1"

READINESS_STATES = frozenset({
    "ready",
    "missing",
    "not_configured",
    "requires_admin_install",
    "container_available",
    "runtime_unavailable",
    "version_incompatible",
    "unsupported",
    "not_implemented",
})

TOOL_IDS = frozenset({
    "http_assessor", "nmap", "nuclei", "nuclei_templates", "docker", "zap", "burp_dast",
    "authenticated_testing", "controlled_validation",
})

DEFAULT_COMMAND_TIMEOUT_SECONDS = 8.0
DEFAULT_HTTP_TIMEOUT_SECONDS = 5.0

ZAP_CONTAINER_NAME = "threattrace-zap"
ZAP_API_HOST = "127.0.0.1"
ZAP_API_PORT = 8080  # matches adapters.bug_bounty_zap.ZAP_API_PORT

JUICE_SHOP_CONTAINER_NAME = "threattrace-juice-shop"
JUICE_SHOP_HOST = "127.0.0.1"
JUICE_SHOP_PORT = 3000

NUCLEI_TEMPLATES_DIR_ENV_VAR = "THREATTRACE_NUCLEI_TEMPLATES_DIR"
_DEFAULT_NUCLEI_TEMPLATES_DIRNAME = "nuclei-templates"

WhichFunc = Callable[[str], "str | None"]
CommandRunner = Callable[..., dict]
HttpGetFunc = Callable[..., str]


class ToolRuntimeError(ValueError):
    """Raised only for a structurally invalid argument to a function in
    this module. Never raised because a tool is missing, unconfigured,
    version-incompatible, or a subprocess/HTTP probe failed -- every one
    of those is represented as a normal, honestly-reported readiness
    state, never an exception.
    """


def _raise(code: str, detail: str) -> None:
    raise ToolRuntimeError(f"{code}: {detail}")


# ---------------------------------------------------------------------------
# Real I/O defaults -- every one of these is overridable by tests.
# ---------------------------------------------------------------------------


def real_which(name: str) -> str | None:
    return shutil.which(name)


def real_run(argv: list[str], *, timeout: float) -> dict[str, Any]:
    """Real, closed-argv, `shell=False` subprocess runner. `argv` must
    already be a fixed, pre-built list -- this function never builds a
    shell string and never accepts one."""
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=False)
        return {
            "returncode": completed.returncode, "stdout": completed.stdout,
            "stderr": completed.stderr, "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        return {"returncode": None, "stdout": "", "stderr": "", "timed_out": True}
    except OSError as exc:
        return {"returncode": None, "stdout": "", "stderr": str(exc), "timed_out": False}


def real_http_get(url: str, *, timeout: float) -> str:
    parsed = urlsplit(url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    try:
        connection.request("GET", parsed.path or "/")
        response = connection.getresponse()
        return response.read().decode("utf-8", errors="replace")
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Always-ready / always-declared checks
# ---------------------------------------------------------------------------


def check_http_assessor() -> dict[str, Any]:
    """`adapters.bug_bounty_http` is pure Python standard library --
    always ready, no external binary or runtime dependency."""
    return {
        "tool_id": "http_assessor", "state": "ready", "version": None,
        "detail": "Pure Python HTTP client (adapters.bug_bounty_http) -- no external dependency.",
    }


def check_authenticated_testing() -> dict[str, Any]:
    return {
        "tool_id": "authenticated_testing", "state": "not_implemented", "version": None,
        "detail": "Declared capability in core.bug_bounty_tool_policy.TOOL_CATALOG; no adapter is implemented.",
    }


def check_controlled_validation() -> dict[str, Any]:
    return {
        "tool_id": "controlled_validation", "state": "not_implemented", "version": None,
        "detail": "Declared capability in core.bug_bounty_tool_policy.TOOL_CATALOG; no adapter is implemented.",
    }


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------

_NMAP_VERSION_PATTERN = re.compile(r"Nmap version (\S+)")


def check_nmap(
    *, which_func: WhichFunc = real_which, runner: CommandRunner = real_run, platform_name: str | None = None,
) -> dict[str, Any]:
    """Detect an Nmap installation on `PATH` and its reported version.
    Never installs Nmap or Npcap, and never attempts to elevate
    privileges -- on Windows, a missing Nmap is reported as
    `requires_admin_install` (Nmap + Npcap both require an
    administrator-performed host install on Windows), never silently
    worked around."""
    active_platform = platform_name if platform_name is not None else platform.system()
    path = which_func("nmap")
    if path is None:
        if active_platform == "Windows":
            return {
                "tool_id": "nmap", "state": "requires_admin_install", "version": None,
                "detail": (
                    "Nmap not found on PATH. On Windows, Nmap requires a host installation plus Npcap "
                    "(both need administrator privileges) -- ThreatTrace never installs either "
                    "automatically. See docs/demo-runbook.md for manual installation guidance."
                ),
            }
        return {
            "tool_id": "nmap", "state": "missing", "version": None,
            "detail": "Nmap not found on PATH. Install it via your OS package manager, then re-run the readiness check.",
        }

    result = runner([path, "-V"], timeout=DEFAULT_COMMAND_TIMEOUT_SECONDS)
    if result.get("timed_out"):
        return {"tool_id": "nmap", "state": "runtime_unavailable", "version": None, "detail": "Nmap found but 'nmap -V' timed out."}
    if result.get("returncode") != 0:
        return {"tool_id": "nmap", "state": "runtime_unavailable", "version": None, "detail": "Nmap found but 'nmap -V' failed to run."}

    match = _NMAP_VERSION_PATTERN.search(result.get("stdout") or "")
    return {"tool_id": "nmap", "state": "ready", "version": match.group(1) if match else None, "detail": path}


# ---------------------------------------------------------------------------
# Nuclei + templates
# ---------------------------------------------------------------------------

_NUCLEI_VERSION_PATTERN = re.compile(r"[Vv]ersion:\s*v?(\S+)")


def check_nuclei(*, which_func: WhichFunc = real_which, runner: CommandRunner = real_run) -> dict[str, Any]:
    """Detect a Nuclei binary on `PATH` and its reported engine
    version. Never runs `-update-templates` or any other mutating
    command -- see `check_nuclei_templates` for the separate,
    read-only template-state check, and `runtime.bootstrap` for the
    explicit, analyst-invoked template update action."""
    path = which_func("nuclei")
    if path is None:
        return {
            "tool_id": "nuclei", "state": "missing", "version": None,
            "detail": "Nuclei not found on PATH. See docs/demo-runbook.md for a user-local install path (no admin required).",
        }

    result = runner([path, "-version"], timeout=DEFAULT_COMMAND_TIMEOUT_SECONDS)
    if result.get("timed_out"):
        return {"tool_id": "nuclei", "state": "runtime_unavailable", "version": None, "detail": "Nuclei found but 'nuclei -version' timed out."}

    combined_output = (result.get("stdout") or "") + (result.get("stderr") or "")
    match = _NUCLEI_VERSION_PATTERN.search(combined_output)
    version = match.group(1) if match else None
    if version is None:
        return {"tool_id": "nuclei", "state": "runtime_unavailable", "version": None, "detail": "Nuclei found but its version could not be determined."}
    return {"tool_id": "nuclei", "state": "ready", "version": version, "detail": path}


def _resolve_nuclei_templates_dir(*, templates_dir: str | None, env: Any) -> Path:
    if templates_dir is not None:
        return Path(templates_dir)
    active_env = env if env is not None else os.environ
    configured = active_env.get(NUCLEI_TEMPLATES_DIR_ENV_VAR)
    if configured:
        return Path(configured)
    return Path.home() / _DEFAULT_NUCLEI_TEMPLATES_DIRNAME


def check_nuclei_templates(*, templates_dir: str | None = None, env: Any = None) -> dict[str, Any]:
    """Detect whether a Nuclei templates directory exists and is
    non-empty. Read-only -- never downloads or updates templates
    itself. The directory is resolved from `templates_dir` if given,
    else `THREATTRACE_NUCLEI_TEMPLATES_DIR`, else `~/nuclei-templates`
    (Nuclei's own default)."""
    resolved = _resolve_nuclei_templates_dir(templates_dir=templates_dir, env=env)
    if not resolved.is_dir():
        return {
            "tool_id": "nuclei_templates", "state": "missing", "version": None,
            "detail": f"No templates directory found at {resolved}. Run 'nuclei -update-templates' manually, or see docs/demo-runbook.md.",
        }
    has_entries = any(resolved.iterdir())
    if not has_entries:
        return {
            "tool_id": "nuclei_templates", "state": "missing", "version": None,
            "detail": f"{resolved} exists but is empty. Run 'nuclei -update-templates' manually.",
        }
    return {"tool_id": "nuclei_templates", "state": "ready", "version": None, "detail": str(resolved)}


# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

_DOCKER_VERSION_PATTERN = re.compile(r"(\d+\.\d+\.\d+)")


def check_docker(*, which_func: WhichFunc = real_which, runner: CommandRunner = real_run) -> dict[str, Any]:
    """Detect the Docker CLI on `PATH` and confirm the daemon is
    actually reachable (not merely that the CLI binary exists)."""
    path = which_func("docker")
    if path is None:
        return {"tool_id": "docker", "state": "missing", "version": None, "detail": "Docker not found on PATH."}

    result = runner([path, "version", "--format", "{{.Server.Version}}"], timeout=DEFAULT_COMMAND_TIMEOUT_SECONDS)
    if result.get("timed_out"):
        return {"tool_id": "docker", "state": "runtime_unavailable", "version": None, "detail": "Docker CLI found but the command timed out (daemon may be starting)."}

    stdout = (result.get("stdout") or "").strip()
    if result.get("returncode") != 0 or not stdout:
        return {
            "tool_id": "docker", "state": "runtime_unavailable", "version": None,
            "detail": "Docker CLI found but the daemon is not reachable. Is Docker Desktop running?",
        }

    match = _DOCKER_VERSION_PATTERN.search(stdout)
    return {"tool_id": "docker", "state": "ready", "version": match.group(1) if match else stdout, "detail": path}


# ---------------------------------------------------------------------------
# ZAP
# ---------------------------------------------------------------------------


def check_zap(
    *,
    docker_state: dict[str, Any] | None = None,
    which_func: WhichFunc = real_which,
    runner: CommandRunner = real_run,
    http_get: HttpGetFunc | None = None,
    container_name: str = ZAP_CONTAINER_NAME,
    api_host: str = ZAP_API_HOST,
    api_port: int = ZAP_API_PORT,
) -> dict[str, Any]:
    """Detect whether an approved local ZAP container is running and
    its REST API is answering. Never starts, stops, or modifies a
    container itself -- see `runtime.bootstrap.start_demo` for the
    explicit, analyst-invoked start action. `docker_state` may be
    supplied to avoid re-running the Docker check when the caller
    already has one (see `evaluate_tool_readiness`)."""
    active_docker_state = docker_state if docker_state is not None else check_docker(which_func=which_func, runner=runner)
    if active_docker_state["state"] != "ready":
        return {
            "tool_id": "zap", "state": "runtime_unavailable", "version": None,
            "detail": "Docker is required to run the ZAP container and is not ready.",
        }

    docker_path = which_func("docker")
    inspect_result = runner(
        [docker_path, "ps", "--filter", f"name=^{container_name}$", "--filter", "status=running", "--format", "{{.Names}}"],
        timeout=DEFAULT_COMMAND_TIMEOUT_SECONDS,
    )
    running = bool((inspect_result.get("stdout") or "").strip())
    if not running:
        return {
            "tool_id": "zap", "state": "container_available", "version": None,
            "detail": f"Docker is ready; the '{container_name}' container is not currently running. "
                      f"Start it via 'python -m runtime.bootstrap start-demo'.",
        }

    active_http_get = http_get if http_get is not None else real_http_get
    try:
        body = active_http_get(f"http://{api_host}:{api_port}/JSON/core/view/version/", timeout=DEFAULT_HTTP_TIMEOUT_SECONDS)
        version = json.loads(body).get("version")
    except Exception:  # noqa: BLE001 -- any probe failure is honestly reported, never raised
        return {
            "tool_id": "zap", "state": "runtime_unavailable", "version": None,
            "detail": f"'{container_name}' is running but its API did not respond on {api_host}:{api_port}.",
        }

    return {
        "tool_id": "zap", "state": "ready", "version": version,
        "detail": f"'{container_name}' running; API verified at {api_host}:{api_port}.",
    }


# ---------------------------------------------------------------------------
# Burp
# ---------------------------------------------------------------------------


def _discover_burp_config(*, env: Any = None) -> tuple[str, int] | None:
    active_env = env if env is not None else os.environ
    api_key = active_env.get(BURP_API_KEY_ENV_VAR)
    if not api_key or not api_key.strip():
        return None
    host = (active_env.get(BURP_API_HOST_ENV_VAR) or "127.0.0.1").strip() or "127.0.0.1"
    port_raw = (active_env.get(BURP_API_PORT_ENV_VAR) or "1337").strip()
    try:
        port = int(port_raw)
    except ValueError:
        port = 1337
    return host, port


def check_burp_dast(*, env: Any = None, http_get: HttpGetFunc | None = None) -> dict[str, Any]:
    """Burp remains a `configured_external_runtime_required` capability
    -- reported as `not_configured` unless the same
    `THREATTRACE_BURP_API_*` environment variables
    `adapters.bug_bounty_burp` itself reads are actually set (see
    `.env.example`). Never auto-installs Burp, never bundles a
    proprietary binary, and never implies scanning occurred merely
    because the adapter code exists."""
    config = _discover_burp_config(env=env)
    if config is None:
        return {
            "tool_id": "burp_dast", "state": "not_configured", "version": None,
            "detail": (
                "No THREATTRACE_BURP_API_KEY configured. Burp requires an analyst-configured external "
                "runtime -- see .env.example. ThreatTrace never bundles or auto-installs Burp."
            ),
        }
    host, port = config
    active_http_get = http_get if http_get is not None else real_http_get
    try:
        active_http_get(f"http://{host}:{port}/", timeout=DEFAULT_HTTP_TIMEOUT_SECONDS)
    except Exception:  # noqa: BLE001 -- any probe failure is honestly reported, never raised
        return {
            "tool_id": "burp_dast", "state": "runtime_unavailable", "version": None,
            "detail": f"Burp API configured for {host}:{port} but not reachable.",
        }
    return {
        "tool_id": "burp_dast", "state": "ready", "version": None,
        "detail": f"Configured external Burp runtime reachable at {host}:{port}. Version is not exposed by this adapter boundary.",
    }


# ---------------------------------------------------------------------------
# Aggregate report
# ---------------------------------------------------------------------------


def evaluate_tool_readiness(
    *,
    which_func: WhichFunc = real_which,
    runner: CommandRunner = real_run,
    http_get: HttpGetFunc | None = None,
    env: Any = None,
    platform_name: str | None = None,
    templates_dir: str | None = None,
) -> dict[str, Any]:
    """Run every individual `check_*` function and assemble one
    readiness report. Performs real detection I/O by default (all
    overridable); never installs, never elevates, never executes an
    offensive scan.

    Returns a new dict containing `runtime_report_version`, `platform`,
    and `tools` -- a mapping of `TOOL_IDS` (plus `"docker"`) to each
    check's own result dict (`tool_id`/`state`/`version`/`detail`).
    """
    docker_result = check_docker(which_func=which_func, runner=runner)
    tools = {
        "http_assessor": check_http_assessor(),
        "nmap": check_nmap(which_func=which_func, runner=runner, platform_name=platform_name),
        "nuclei": check_nuclei(which_func=which_func, runner=runner),
        "nuclei_templates": check_nuclei_templates(templates_dir=templates_dir, env=env),
        "docker": docker_result,
        "zap": check_zap(docker_state=docker_result, which_func=which_func, runner=runner, http_get=http_get),
        "burp_dast": check_burp_dast(env=env, http_get=http_get),
        "authenticated_testing": check_authenticated_testing(),
        "controlled_validation": check_controlled_validation(),
    }
    return {
        "runtime_report_version": RUNTIME_REPORT_VERSION,
        "platform": platform_name if platform_name is not None else platform.system(),
        "tools": tools,
    }
