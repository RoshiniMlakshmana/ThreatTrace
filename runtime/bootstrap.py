"""Deterministic local demo bootstrap CLI (Block 15L-16).

Three subcommands:

    python -m runtime.bootstrap check
    python -m runtime.bootstrap start-demo [--dry-run] [--with-zap]
    python -m runtime.bootstrap stop-demo [--dry-run]

## Never a universal installer

`start-demo` only ever does two things, both via a fixed, closed Docker
`argv` (never a shell string): start the `threattrace-juice-shop`
container (the local, authorized demo target) if it is not already
running, and — only when `--with-zap` is passed — start the
`threattrace-zap` container if Docker reports it as `container_available`
(present-but-not-running is never assumed; `runtime.tool_runtime.
check_zap` is the single source of truth for that state). It never
installs Nmap, Npcap, Nuclei, or Docker itself, never touches an
unrelated container, and never elevates privileges. `stop-demo`
similarly only ever stops those exact two fixed container names.

## Planning and execution are kept separate, like every Governor/policy
## boundary elsewhere in this project

`build_start_demo_plan`/`build_stop_demo_plan` are pure decision
functions over an already-computed status snapshot — no I/O, fully
unit-testable. `execute_start_demo`/`execute_stop_demo` are the only
functions that actually run a Docker command, and only when
`dry_run=False`; a `dry_run=True` plan reports exactly what *would* run
without ever invoking `runner`.

## Local-only binds, always

Every container this module can ever start publishes its port bound to
`127.0.0.1` only (`-p 127.0.0.1:<port>:<container_port>`, never a bare
`-p <port>:<container_port>`, which Docker would bind to all host
interfaces). ZAP's own in-container `-host 0.0.0.0` flag is standard and
required for Docker's internal bridge networking to reach it at all —
it is the outer `-p 127.0.0.1:...` host-side bind that actually
determines whether the port is reachable from outside the machine, and
this module never omits it.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Callable

from runtime.tool_runtime import (
    JUICE_SHOP_CONTAINER_NAME,
    JUICE_SHOP_HOST,
    JUICE_SHOP_PORT,
    ZAP_API_HOST,
    ZAP_API_PORT,
    ZAP_CONTAINER_NAME,
    CommandRunner,
    DEFAULT_COMMAND_TIMEOUT_SECONDS,
    WhichFunc,
    real_run,
    real_which,
    evaluate_tool_readiness,
)

BOOTSTRAP_VERSION = "1"

JUICE_SHOP_IMAGE = "bkimminich/juice-shop"
ZAP_IMAGE = "zaproxy/zap-stable"

_CONTAINER_START_TIMEOUT_SECONDS = 60.0

_DISPLAY_ORDER = (
    "http_assessor", "nmap", "nuclei", "nuclei_templates", "docker", "zap",
    "burp_dast", "authenticated_testing", "controlled_validation",
)

_DISPLAY_NAMES = {
    "http_assessor": "HTTP Assessor",
    "nmap": "Nmap",
    "nuclei": "Nuclei",
    "nuclei_templates": "Nuclei Templates",
    "docker": "Docker",
    "zap": "ZAP",
    "burp_dast": "Burp DAST",
    "authenticated_testing": "Authenticated Testing",
    "controlled_validation": "Controlled Validation",
}


# ---------------------------------------------------------------------------
# Readiness table formatting
# ---------------------------------------------------------------------------


def format_readiness_table(report: dict[str, Any]) -> str:
    """Render `runtime.tool_runtime.evaluate_tool_readiness`'s own
    return value as a fixed-width, human-readable table. Never
    fabricates a version -- a tool with `version: None` shows its state
    alone."""
    label_width = max(len(name) for name in _DISPLAY_NAMES.values()) + 2
    lines = [f"ThreatTrace Runtime Readiness (platform: {report['platform']})", ""]
    for tool_id in _DISPLAY_ORDER:
        result = report["tools"][tool_id]
        label = _DISPLAY_NAMES[tool_id].ljust(label_width)
        state_text = result["state"].upper()
        if result.get("version"):
            state_text += f" {result['version']}"
        lines.append(f"{label}{state_text}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Juice Shop status (the demo target -- not a scanning tool, so it lives
# here rather than in runtime.tool_runtime).
# ---------------------------------------------------------------------------


def check_juice_shop_status(*, which_func: WhichFunc = real_which, runner: CommandRunner = real_run) -> dict[str, Any]:
    docker_path = which_func("docker")
    if docker_path is None:
        return {"status": "docker_unavailable", "detail": "Docker not found on PATH."}

    running = runner(
        [docker_path, "ps", "--filter", f"name=^{JUICE_SHOP_CONTAINER_NAME}$", "--filter", "status=running", "--format", "{{.Names}}"],
        timeout=DEFAULT_COMMAND_TIMEOUT_SECONDS,
    )
    if (running.get("stdout") or "").strip():
        return {"status": "running", "detail": f"'{JUICE_SHOP_CONTAINER_NAME}' is running."}

    existing = runner(
        [docker_path, "ps", "-a", "--filter", f"name=^{JUICE_SHOP_CONTAINER_NAME}$", "--format", "{{.Names}}"],
        timeout=DEFAULT_COMMAND_TIMEOUT_SECONDS,
    )
    if (existing.get("stdout") or "").strip():
        return {"status": "exists_stopped", "detail": f"'{JUICE_SHOP_CONTAINER_NAME}' exists but is not running."}

    return {"status": "not_present", "detail": f"'{JUICE_SHOP_CONTAINER_NAME}' does not exist yet."}


# ---------------------------------------------------------------------------
# start-demo: plan, then execute
# ---------------------------------------------------------------------------


def build_start_demo_plan(
    *, juice_shop_status: dict[str, Any], zap_readiness: dict[str, Any], docker_readiness: dict[str, Any], with_zap: bool,
) -> dict[str, Any]:
    """Pure decision function -- no I/O. Given already-computed status
    snapshots, decide what `execute_start_demo` should do. Never
    proposes touching any container other than the two fixed demo
    names, and never proposes anything at all if Docker itself is not
    `"ready"`."""
    if docker_readiness["state"] != "ready":
        return {
            "plan_version": BOOTSTRAP_VERSION, "docker_ready": False, "steps": [],
            "blocked_reason": "Docker is not ready; cannot start any demo container.",
        }

    steps: list[dict[str, Any]] = []

    if juice_shop_status["status"] == "running":
        steps.append({"target": "juice_shop", "action": "already_running", "command": None})
    elif juice_shop_status["status"] == "exists_stopped":
        steps.append({"target": "juice_shop", "action": "start_existing_container", "command": ["docker", "start", JUICE_SHOP_CONTAINER_NAME]})
    elif juice_shop_status["status"] == "not_present":
        steps.append({
            "target": "juice_shop", "action": "run_new_container",
            "command": [
                "docker", "run", "-d", "--name", JUICE_SHOP_CONTAINER_NAME,
                "-p", f"{JUICE_SHOP_HOST}:{JUICE_SHOP_PORT}:3000", JUICE_SHOP_IMAGE,
            ],
        })
    else:
        steps.append({"target": "juice_shop", "action": "skip_unavailable", "command": None})

    if with_zap:
        if zap_readiness["state"] == "ready":
            steps.append({"target": "zap", "action": "already_running", "command": None})
        elif zap_readiness["state"] == "container_available":
            steps.append({
                "target": "zap", "action": "run_new_container",
                "command": [
                    "docker", "run", "-d", "--name", ZAP_CONTAINER_NAME,
                    "-p", f"{ZAP_API_HOST}:{ZAP_API_PORT}:8080", ZAP_IMAGE,
                    "zap.sh", "-daemon", "-host", "0.0.0.0", "-port", "8080",
                    "-config", "api.disablekey=true",
                ],
            })
        else:
            steps.append({"target": "zap", "action": "skip_unavailable", "command": None})

    return {"plan_version": BOOTSTRAP_VERSION, "docker_ready": True, "steps": steps, "blocked_reason": None}


def execute_start_demo(*, plan: dict[str, Any], runner: CommandRunner = real_run, dry_run: bool = False) -> dict[str, Any]:
    """Execute (or, if `dry_run=True`, only describe) the steps in
    `plan`. Every real command runs through `runner` as a fixed, closed
    argv -- never a shell string."""
    if not plan["docker_ready"]:
        return {"executed": False, "dry_run": dry_run, "results": [], "blocked_reason": plan["blocked_reason"]}

    results: list[dict[str, Any]] = []
    for step in plan["steps"]:
        if step["command"] is None:
            results.append({"target": step["target"], "action": step["action"], "executed": False, "success": True, "detail": "No action needed."})
            continue
        if dry_run:
            results.append({
                "target": step["target"], "action": step["action"], "executed": False, "success": True,
                "detail": "DRY RUN: " + " ".join(step["command"]),
            })
            continue

        outcome = runner(step["command"], timeout=_CONTAINER_START_TIMEOUT_SECONDS)
        success = outcome.get("returncode") == 0
        detail = (outcome.get("stdout") or "").strip() or (outcome.get("stderr") or "").strip() or "(no output)"
        results.append({"target": step["target"], "action": step["action"], "executed": True, "success": success, "detail": detail})

    return {"executed": True, "dry_run": dry_run, "results": results, "blocked_reason": None}


# ---------------------------------------------------------------------------
# stop-demo: plan, then execute
# ---------------------------------------------------------------------------


def build_stop_demo_plan(*, juice_shop_status: dict[str, Any], zap_running: bool) -> dict[str, Any]:
    """Pure decision function -- no I/O. Only ever proposes `docker
    stop` for the two fixed demo container names, and only when each is
    actually reported running."""
    steps: list[dict[str, Any]] = []
    if juice_shop_status["status"] == "running":
        steps.append({"target": "juice_shop", "action": "stop_container", "command": ["docker", "stop", JUICE_SHOP_CONTAINER_NAME]})
    else:
        steps.append({"target": "juice_shop", "action": "not_running", "command": None})

    if zap_running:
        steps.append({"target": "zap", "action": "stop_container", "command": ["docker", "stop", ZAP_CONTAINER_NAME]})
    else:
        steps.append({"target": "zap", "action": "not_running", "command": None})

    return {"plan_version": BOOTSTRAP_VERSION, "steps": steps}


def execute_stop_demo(*, plan: dict[str, Any], runner: CommandRunner = real_run, dry_run: bool = False) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for step in plan["steps"]:
        if step["command"] is None:
            results.append({"target": step["target"], "action": step["action"], "executed": False, "success": True, "detail": "Not running."})
            continue
        if dry_run:
            results.append({
                "target": step["target"], "action": step["action"], "executed": False, "success": True,
                "detail": "DRY RUN: " + " ".join(step["command"]),
            })
            continue
        outcome = runner(step["command"], timeout=_CONTAINER_START_TIMEOUT_SECONDS)
        success = outcome.get("returncode") == 0
        detail = (outcome.get("stdout") or "").strip() or (outcome.get("stderr") or "").strip() or "(no output)"
        results.append({"target": step["target"], "action": step["action"], "executed": True, "success": success, "detail": detail})
    return {"executed": True, "dry_run": dry_run, "results": results}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_BACKEND_STARTUP_MESSAGE = (
    "\nNext steps:\n"
    "  1. Start the backend:  python -m backend.app   (binds 127.0.0.1:8420)\n"
    "  2. Open the live dashboard:  http://127.0.0.1:8420/\n"
)


def _run_check(*, print_func: Callable[[str], None] = print) -> int:
    report = evaluate_tool_readiness()
    print_func(format_readiness_table(report))
    return 0


def _run_start_demo(*, with_zap: bool, dry_run: bool, print_func: Callable[[str], None] = print) -> int:
    report = evaluate_tool_readiness()
    juice_shop_status = check_juice_shop_status()
    plan = build_start_demo_plan(
        juice_shop_status=juice_shop_status, zap_readiness=report["tools"]["zap"],
        docker_readiness=report["tools"]["docker"], with_zap=with_zap,
    )
    outcome = execute_start_demo(plan=plan, dry_run=dry_run)

    if not outcome["executed"]:
        print_func(f"BLOCKED: {outcome['blocked_reason']}")
        return 1

    for result in outcome["results"]:
        print_func(f"[{result['target']}] {result['action']}: {result['detail']}")

    if not dry_run:
        print_func(_BACKEND_STARTUP_MESSAGE)

    return 0 if all(result.get("success", True) for result in outcome["results"]) else 1


def _run_stop_demo(*, dry_run: bool, print_func: Callable[[str], None] = print) -> int:
    juice_shop_status = check_juice_shop_status()
    report = evaluate_tool_readiness()
    zap_running = report["tools"]["zap"]["state"] == "ready"
    plan = build_stop_demo_plan(juice_shop_status=juice_shop_status, zap_running=zap_running)
    outcome = execute_stop_demo(plan=plan, dry_run=dry_run)
    for result in outcome["results"]:
        print_func(f"[{result['target']}] {result['action']}: {result['detail']}")
    return 0 if all(result.get("success", True) for result in outcome["results"]) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m runtime.bootstrap", description="ThreatTrace local demo readiness/bootstrap.")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    subparsers.add_parser("check", help="Print tool/runtime readiness.")

    start_parser = subparsers.add_parser("start-demo", help="Start local demo dependencies (Juice Shop, optionally ZAP).")
    start_parser.add_argument("--dry-run", action="store_true", help="Describe actions without executing them.")
    start_parser.add_argument("--with-zap", action="store_true", help="Also start the approved local ZAP container if available.")

    stop_parser = subparsers.add_parser("stop-demo", help="Stop ThreatTrace-managed demo containers.")
    stop_parser.add_argument("--dry-run", action="store_true", help="Describe actions without executing them.")

    args = parser.parse_args(argv)

    if args.subcommand == "check":
        return _run_check()
    if args.subcommand == "start-demo":
        return _run_start_demo(with_zap=args.with_zap, dry_run=args.dry_run)
    if args.subcommand == "stop-demo":
        return _run_stop_demo(dry_run=args.dry_run)
    return 2


if __name__ == "__main__":
    sys.exit(main())
