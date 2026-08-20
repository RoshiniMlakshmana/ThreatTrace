"""ThreatTrace Live Platform backend HTTP/SSE interface (Block 15J-K).

## Local-only, by construction

`main()` binds uvicorn to `127.0.0.1` by default -- never `0.0.0.0`,
never a LAN-reachable interface -- unless the deployment operator
explicitly overrides it via `THREATTRACE_BIND_HOST` (never inferred
from a request; this is a fixed, deployment-time setting, exactly like
`THREATTRACE_DEMO_TARGET`/`ZAP_API_URL`). The self-hosted Docker
runtime is the one deployment that legitimately needs this: uvicorn
must bind the *container's* `0.0.0.0` for Docker's own port-publish
mechanism to forward traffic to it at all (a process bound to a
container's own `127.0.0.1` is unreachable from outside that
container's network namespace, including from the host). External
reachability is still governed entirely by `docker-compose.yml`'s host
port publish spec, which stays `127.0.0.1:8420:8420` -- loopback-only
on the host, regardless of what the container binds internally. There
is no cloud tunnel, no reverse proxy configuration, and no
authentication of any kind anywhere in this module. This is a **local
development/research interface**, never a production-authenticated
control plane -- every response this module returns is honest about
that (see `GET /api/health`).

## Route handlers are thin -- all logic lives in the modules they call

Every handler below does at most: read/validate a request, call exactly
one of `backend.run_store`/`backend.event_bus`/`backend.orchestrator`,
and translate the result to an HTTP/SSE response. No scope/policy/
Governor/telemetry/rule logic is ever implemented inline here -- see
`backend.orchestrator` for where the actual `core.*` calls happen.

## Errors are always sanitized before leaving this process

`_api_error_boundary` is the single place an exception becomes an HTTP
response. A recognized, already-safe-message error (`_ApiError`,
`backend.run_store.RunStoreError`, `backend.models.RunModelError`,
`backend.event_bus.EventBusError`) is mapped to a clean `4xx` JSON body
using that error's own already-sanitized message (these modules never
put a raw secret or stack trace into a message string -- see each
module's own docstring). Any other exception is logged in full to
stderr (`traceback.print_exc()`) but the HTTP response is always the
fixed, generic `{"error_code": "INTERNAL_ERROR", ...}` body -- a stack
trace is never sent to a client.

## Only one active offensive-assessment run at a time

`POST /api/runs/bug-bounty` checks `backend.run_store.RunStore.
active_bug_bounty_run_id()` before creating anything; a second
concurrent request while one is active receives a clean `409` and no
new run is ever created for it. `POST /api/runs/detection` has no such
restriction -- a Detection Engineering run never executes an offensive
tool.

## Background execution, off the asyncio event loop

Each accepted run is executed by `backend.orchestrator` on a dedicated
background `threading.Thread` (daemon, so it never blocks process
shutdown) -- the orchestrator functions perform real blocking I/O (a
live HTTP request to the local Juice Shop container) and must never run
directly on the asyncio event loop this module serves requests from.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.routing import Route

from backend.event_bus import EventBus, EventBusError
from backend.models import TERMINAL_STATUSES, RunModelError, validate_authorized_external_target_scope, validate_local_only_target
from backend.orchestrator import (
    TRIGGER_SOURCES,
    record_lifecycle_human_review,
    run_authorized_external_target_workflow,
    run_bug_bounty_workflow,
    run_detection_workflow,
    run_security_lifecycle_workflow,
)
from backend.run_store import RunStore, RunStoreError, is_valid_run_id
from core.bug_bounty_juice_shop_evaluation import evaluate_bug_bounty_run_against_juice_shop_benchmark
from runtime.tool_runtime import evaluate_tool_readiness

BACKEND_VERSION = "1"

# Deployment-time only -- never derived from a request. Defaults preserve
# the loopback-only safety property; the self-hosted Docker runtime is the
# only place these are overridden (see module docstring).
BIND_HOST = os.environ.get("THREATTRACE_BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("THREATTRACE_BIND_PORT", "8420"))

MAX_REQUEST_BODY_BYTES = 65536

_TERMINAL_EVENT_TYPES = frozenset({"run_completed", "run_blocked", "run_failed", "run_cancelled"})

_DASHBOARD_PATH = Path(__file__).resolve().parent.parent / "dashboard" / "live" / "index.html"

_run_store = RunStore()
_event_bus = EventBus()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class _ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def _error_code_from_message(message: str) -> str:
    return message.split(":", 1)[0].strip() if ":" in message else "ERROR"


def _concurrent_run_active_error() -> "_ApiError":
    """Builds the real `409 CONCURRENT_RUN_ACTIVE` error, naming the
    actual run id currently holding the execution slot (never a
    historical/awaiting-review run -- see
    `backend.run_store.RunStore.active_bug_bounty_run_id`) so a caller
    -- including the dashboard's own error banner -- can tell the
    operator exactly which run to wait on, instead of a generic message."""
    active_id = _run_store.active_bug_bounty_run_id()
    detail = f" ({active_id})" if active_id else ""
    return _ApiError(409, "CONCURRENT_RUN_ACTIVE", f"Another security assessment is currently executing{detail}.")


async def _read_json_body(request: Request) -> dict[str, Any]:
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_REQUEST_BODY_BYTES:
            raise _ApiError(413, "PAYLOAD_TOO_LARGE", "Request body exceeds the maximum allowed size.")
    if not body:
        return {}
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        raise _ApiError(400, "INVALID_JSON", "Request body must be valid JSON.")
    if not isinstance(parsed, dict):
        raise _ApiError(400, "INVALID_JSON", "Request body must be a JSON object.")
    return parsed


def _api_route(handler: Any) -> Any:
    async def wrapped(request: Request) -> Response:
        try:
            return await handler(request)
        except _ApiError as exc:
            return JSONResponse({"error_code": exc.code, "message": exc.message}, status_code=exc.status_code)
        except RunStoreError as exc:
            code = _error_code_from_message(str(exc))
            status = 404 if code == "RUN_NOT_FOUND" else 400
            return JSONResponse({"error_code": code, "message": str(exc)}, status_code=status)
        except RunModelError as exc:
            return JSONResponse({"error_code": _error_code_from_message(str(exc)), "message": str(exc)}, status_code=400)
        except EventBusError as exc:
            return JSONResponse({"error_code": _error_code_from_message(str(exc)), "message": str(exc)}, status_code=400)
        except Exception:  # noqa: BLE001 -- last-resort sanitized boundary; full detail logged, never returned
            traceback.print_exc()
            return JSONResponse({"error_code": "INTERNAL_ERROR", "message": "An internal error occurred."}, status_code=500)

    return wrapped


def _require_valid_run_id(run_id: Any) -> str:
    if not is_valid_run_id(run_id):
        raise _ApiError(400, "INVALID_RUN_ID", "run_id is not a recognized identifier shape.")
    return run_id


def _get_run_or_404(run_id: str) -> dict[str, Any]:
    try:
        return _run_store.get_run(run_id=run_id)
    except RunStoreError:
        raise _ApiError(404, "RUN_NOT_FOUND", "No run exists with that id.")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@_api_route
async def health(request: Request) -> Response:
    return JSONResponse({
        "status": "ok",
        "backend_version": BACKEND_VERSION,
        "bind": f"{BIND_HOST}:{BIND_PORT}",
        "interface_class": "local_development_research_interface",
    })


def _always_ready(*, tool_id: str, label: str, detail: str) -> dict[str, Any]:
    return {"id": tool_id, "label": label, "state": "ready", "version": None, "required": True, "detail": detail}


@_api_route
async def system_info(request: Request) -> Response:
    readiness = evaluate_tool_readiness()
    tools = readiness["tools"]

    def _scanner_item(tool_id: str, label: str, *, required: bool) -> dict[str, Any]:
        result = tools[tool_id]
        return {
            "id": tool_id, "label": label, "state": result["state"], "version": result.get("version"),
            "required": required, "detail": result["detail"],
        }

    categories = [
        {
            "category": "core_services", "label": "Core Services",
            "items": [
                _always_ready(tool_id="backend", label="ThreatTrace Backend", detail="Process running."),
                _always_ready(tool_id="governor", label="Security Governor", detail="core.security_governor -- deterministic, no external dependency."),
            ],
        },
        {
            "category": "discovery", "label": "Discovery",
            "items": [
                _scanner_item("http_assessor", "HTTP Assessor", required=True),
                _scanner_item("httpx", "httpx", required=True),
                _scanner_item("katana", "Katana", required=True),
            ],
        },
        {
            "category": "scanners", "label": "Scanners",
            "items": [
                _scanner_item("nmap", "Nmap", required=True),
                _scanner_item("nuclei", "Nuclei", required=True),
                _scanner_item("zap", "ZAP", required=True),
            ],
        },
        {
            "category": "intelligence", "label": "Intelligence",
            "items": [
                _always_ready(tool_id="threat_intel", label="Threat Intelligence", detail="CISA KEV / NVD / EPSS ingestion -- queried live per use, no persistent dependency."),
            ],
        },
        {
            "category": "detection", "label": "Detection",
            "items": [
                _always_ready(tool_id="detection_engineering", label="Detection Engineering", detail="Deterministic core -- no external dependency."),
            ],
        },
        {
            "category": "optional_integrations", "label": "Optional Integrations",
            "items": [
                _scanner_item("burp_dast", "Burp DAST", required=False),
                {
                    "id": "authenticated_testing", "label": "Authenticated Testing", "required": False,
                    "state": tools["authenticated_testing"]["state"], "version": None,
                    "detail": tools["authenticated_testing"]["detail"],
                },
                {
                    "id": "controlled_validation", "label": "Controlled Validation", "required": False,
                    "state": tools["controlled_validation"]["state"], "version": None,
                    "detail": tools["controlled_validation"]["detail"],
                },
            ],
        },
    ]

    return JSONResponse({
        "system_version": "1",
        "bind": f"{BIND_HOST}:{BIND_PORT}",
        "categories": categories,
        # Flat map retained for simple consumers -- the exact same states
        # `runtime.tool_runtime.evaluate_tool_readiness` computed above,
        # never a separate/weaker check.
        "tools": {tool_id: result["state"] for tool_id, result in tools.items()},
        # Execution-active only -- a run sitting at "awaiting_human_review"
        # never holds this (see backend.run_store.RunStore.transition /
        # backend.models.EXECUTION_ACTIVE_STATUSES). Never conflate this
        # with "any historical run remains unreviewed" -- that is exactly
        # what pending_human_review_count reports instead.
        "active_bug_bounty_run_id": _run_store.active_bug_bounty_run_id(),
        "pending_human_review_count": sum(
            1 for run in _run_store.list_runs() if run["status"] == "awaiting_human_review"
        ),
        "limitations": [
            "local development/research interface -- not a production-authenticated control plane",
            "run history is in-memory only and is lost on backend restart",
            "authenticated_testing/controlled_validation are declared, not implemented -- shown under Optional Integrations, never as a failed core service",
        ],
    })


@_api_route
async def list_runs(request: Request) -> Response:
    return JSONResponse({"runs": _run_store.list_runs()})


@_api_route
async def create_bug_bounty_run(request: Request) -> Response:
    body = await _read_json_body(request)
    try:
        target = validate_local_only_target(body.get("target"))
    except RunModelError as exc:
        raise _ApiError(400, _error_code_from_message(str(exc)), str(exc))

    if _run_store.active_bug_bounty_run_id() is not None:
        raise _concurrent_run_active_error()

    run = _run_store.create_run(run_type="bug_bounty", created_at=_now())
    if not _run_store.try_acquire_bug_bounty_slot(run_id=run["run_id"]):
        _run_store.transition(
            run_id=run["run_id"], new_status="blocked", completed_at=_now(),
            limitations=["CONCURRENT_RUN_ACTIVE: another Bug Bounty run claimed the slot first."],
        )
        raise _concurrent_run_active_error()

    _event_bus.publish(
        run_id=run["run_id"], event_type="run_created", timestamp=_now(), stage="intake",
        source_component="orchestrator", summary=f"Run created (bug_bounty) for target {target}",
        sanitized_payload={"target": target},
    )

    thread = threading.Thread(
        target=run_bug_bounty_workflow,
        kwargs={"run_id": run["run_id"], "target": target, "run_store": _run_store, "event_bus": _event_bus},
        daemon=True,
    )
    thread.start()

    return JSONResponse({"run_id": run["run_id"], "status": run["status"]}, status_code=202)


@_api_route
async def create_security_lifecycle_run(request: Request) -> Response:
    """Starts one real Full Security Lifecycle run: the exact same Bug
    Bounty phase `POST /api/runs/bug-bounty` runs, continued into real
    Context Prioritization, Security Handoff, Threat Intel/Hunt review,
    Detection Engineering review, a Red Validation fact-check, and a
    Purple remediation recommendation for the highest-priority findings.
    Demo Mode (no `scope` field in the request body) remains
    localhost/demo-target only -- `validate_local_only_target` is the
    same authoritative check `create_bug_bounty_run` uses, never
    weakened or bypassed here. When the caller supplies a `scope` field
    (and `operator_scope_acknowledged`), this instead runs as an
    Authorized External Target Full Security Lifecycle run -- see
    `create_authorized_target_run`'s own docstring for that contract;
    the same `validate_authorized_external_target_scope` gate applies,
    never a weaker one. Shares the same single-active-offensive-
    assessment concurrency slot as a plain Bug Bounty run either way
    (this run still executes the exact same real nmap/nuclei/zap/httpx/
    katana tools)."""
    body = await _read_json_body(request)
    external_scope_bundle: dict[str, Any] | None = None
    if body.get("scope") is not None:
        try:
            external_scope_bundle = validate_authorized_external_target_scope(
                target=body.get("target"), scope=body.get("scope"),
                operator_scope_acknowledged=body.get("operator_scope_acknowledged"),
            )
        except RunModelError as exc:
            raise _ApiError(400, _error_code_from_message(str(exc)), str(exc))
        target = external_scope_bundle["bug_bounty_scope"]["target"]
    else:
        try:
            target = validate_local_only_target(body.get("target"))
        except RunModelError as exc:
            raise _ApiError(400, _error_code_from_message(str(exc)), str(exc))

    available_telemetry = body.get("available_telemetry")
    if available_telemetry is None:
        available_telemetry = []
    if not isinstance(available_telemetry, list) or not all(isinstance(item, str) for item in available_telemetry):
        raise _ApiError(400, "INVALID_AVAILABLE_TELEMETRY", "available_telemetry must be a list of strings.")

    detection_llm_proposals = body.get("detection_llm_proposals")
    if detection_llm_proposals is not None and not isinstance(detection_llm_proposals, dict):
        raise _ApiError(400, "INVALID_DETECTION_LLM_PROPOSALS", "detection_llm_proposals must be a JSON object.")

    if _run_store.active_bug_bounty_run_id() is not None:
        raise _concurrent_run_active_error()

    run = _run_store.create_run(run_type="bug_bounty", created_at=_now())
    if not _run_store.try_acquire_bug_bounty_slot(run_id=run["run_id"]):
        _run_store.transition(
            run_id=run["run_id"], new_status="blocked", completed_at=_now(),
            limitations=["CONCURRENT_RUN_ACTIVE: another Bug Bounty run claimed the slot first."],
        )
        raise _concurrent_run_active_error()

    lifecycle_mode = "full_security_lifecycle_external_target" if external_scope_bundle is not None else "full_security_lifecycle"
    _event_bus.publish(
        run_id=run["run_id"], event_type="run_created", timestamp=_now(), stage="intake",
        source_component="orchestrator", summary=f"Run created ({lifecycle_mode}) for target {target}",
        sanitized_payload={"target": target, "mode": lifecycle_mode},
    )

    thread = threading.Thread(
        target=run_security_lifecycle_workflow,
        kwargs={
            "run_id": run["run_id"], "target": target, "run_store": _run_store, "event_bus": _event_bus,
            "available_telemetry": available_telemetry, "detection_llm_proposals": detection_llm_proposals,
            "external_scope_bundle": external_scope_bundle,
        },
        daemon=True,
    )
    thread.start()

    return JSONResponse({"run_id": run["run_id"], "status": run["status"]}, status_code=202)


@_api_route
async def create_authorized_target_run(request: Request) -> Response:
    """Starts one real, bounded Bug Bounty assessment against an
    operator-declared Authorized External Target (Final Pre-Release
    Block) -- never the fixed Demo Mode alias, and never a target this
    module infers or expands on its own.

    Request body: `{"target": "<http(s) URL>", "scope": {"hosts": [...],
    "ports": [...], "path_prefixes": [...], "allowed_tools": [...]},
    "operator_scope_acknowledged": true}` -- see
    `backend.models.validate_authorized_external_target_scope` for the
    exact contract. `operator_scope_acknowledged` must be the literal
    `true`; this only permits ThreatTrace to accept the caller-declared
    scope -- it is never used, and never presented, as proof that the
    operator actually holds legal authorization to test `target`.

    Shares the same single-active-offensive-assessment concurrency slot
    as a plain Bug Bounty / Full Security Lifecycle run."""
    body = await _read_json_body(request)
    try:
        scope_bundle = validate_authorized_external_target_scope(
            target=body.get("target"), scope=body.get("scope"),
            operator_scope_acknowledged=body.get("operator_scope_acknowledged"),
        )
    except RunModelError as exc:
        raise _ApiError(400, _error_code_from_message(str(exc)), str(exc))

    target = scope_bundle["bug_bounty_scope"]["target"]

    if _run_store.active_bug_bounty_run_id() is not None:
        raise _concurrent_run_active_error()

    run = _run_store.create_run(run_type="bug_bounty", created_at=_now())
    if not _run_store.try_acquire_bug_bounty_slot(run_id=run["run_id"]):
        _run_store.transition(
            run_id=run["run_id"], new_status="blocked", completed_at=_now(),
            limitations=["CONCURRENT_RUN_ACTIVE: another Bug Bounty run claimed the slot first."],
        )
        raise _concurrent_run_active_error()

    _event_bus.publish(
        run_id=run["run_id"], event_type="run_created", timestamp=_now(), stage="intake",
        source_component="orchestrator", summary=f"Run created (authorized_external_target) for target {target}",
        sanitized_payload={
            "target": target, "mode": "authorized_external_target",
            "allowed_tools": scope_bundle["allowed_tools"],
        },
    )

    thread = threading.Thread(
        target=run_authorized_external_target_workflow,
        kwargs={
            "run_id": run["run_id"], "target": target, "scope_bundle": scope_bundle,
            "run_store": _run_store, "event_bus": _event_bus,
        },
        daemon=True,
    )
    thread.start()

    return JSONResponse({"run_id": run["run_id"], "status": run["status"]}, status_code=202)


@_api_route
async def record_lifecycle_review(request: Request) -> Response:
    """Records one local development/research review decision
    (`"approved"`/`"rejected"`) against one Security Handoff case within
    an `"awaiting_human_review"` Full Security Lifecycle run. No
    authentication exists in this backend -- `approval_reference` is
    always a caller-supplied string, never verified against any real
    identity."""
    run_id = _require_valid_run_id(request.path_params["run_id"])
    _get_run_or_404(run_id)
    body = await _read_json_body(request)

    case_id = body.get("case_id")
    if not isinstance(case_id, str) or not case_id.strip():
        raise _ApiError(400, "INVALID_CASE_ID", "case_id must be a non-blank string.")
    approval_state = body.get("approval_state")
    if approval_state not in ("approved", "rejected"):
        raise _ApiError(400, "INVALID_APPROVAL_STATE", "approval_state must be 'approved' or 'rejected'.")
    approval_reference = body.get("approval_reference")
    if not isinstance(approval_reference, str) or not approval_reference.strip():
        raise _ApiError(400, "INVALID_APPROVAL_REFERENCE", "approval_reference must be a non-blank string.")

    try:
        updated_run = record_lifecycle_human_review(
            run_id=run_id, case_id=case_id, approval_state=approval_state, approval_reference=approval_reference,
            run_store=_run_store, event_bus=_event_bus,
        )
    except ValueError as exc:
        raise _ApiError(400, _error_code_from_message(str(exc)), str(exc))

    return JSONResponse({"run_id": run_id, "status": updated_run["status"], "lifecycle": updated_run["lifecycle"]})


@_api_route
async def create_detection_run(request: Request) -> Response:
    body = await _read_json_body(request)

    trigger_source = body.get("trigger_source")
    if trigger_source not in TRIGGER_SOURCES:
        raise _ApiError(400, "INVALID_TRIGGER_SOURCE", f"trigger_source must be one of {sorted(TRIGGER_SOURCES)}.")

    trigger_input = body.get("trigger_input")
    if not isinstance(trigger_input, dict):
        raise _ApiError(400, "INVALID_TRIGGER_INPUT", "trigger_input must be a JSON object.")

    telemetry_context = body.get("telemetry_context")
    if telemetry_context is None:
        telemetry_context = {}
    if not isinstance(telemetry_context, dict):
        raise _ApiError(400, "INVALID_TELEMETRY_CONTEXT", "telemetry_context must be a JSON object.")

    llm_proposal = body.get("llm_proposal")
    if llm_proposal is None:
        llm_proposal = {}
    if not isinstance(llm_proposal, dict):
        raise _ApiError(400, "INVALID_LLM_PROPOSAL", "llm_proposal must be a JSON object.")

    run = _run_store.create_run(run_type="detection", created_at=_now())
    _event_bus.publish(
        run_id=run["run_id"], event_type="run_created", timestamp=_now(), stage="intake",
        source_component="orchestrator", summary=f"Run created (detection, trigger_source={trigger_source})",
    )

    thread = threading.Thread(
        target=run_detection_workflow,
        kwargs={
            "run_id": run["run_id"], "trigger_source": trigger_source, "trigger_input": trigger_input,
            "telemetry_context": telemetry_context, "llm_proposal": llm_proposal,
            "run_store": _run_store, "event_bus": _event_bus,
        },
        daemon=True,
    )
    thread.start()

    return JSONResponse({"run_id": run["run_id"], "status": run["status"]}, status_code=202)


@_api_route
async def get_run(request: Request) -> Response:
    run_id = _require_valid_run_id(request.path_params["run_id"])
    return JSONResponse(_get_run_or_404(run_id))


@_api_route
async def get_events(request: Request) -> Response:
    run_id = _require_valid_run_id(request.path_params["run_id"])
    _get_run_or_404(run_id)

    raw_since = request.query_params.get("since_sequence", "0")
    try:
        since_sequence = int(raw_since)
    except ValueError:
        raise _ApiError(400, "INVALID_SEQUENCE", "since_sequence must be an integer.")

    events = _event_bus.get_events(run_id=run_id, since_sequence=since_sequence)
    return JSONResponse({"events": events})


@_api_route
async def get_report(request: Request) -> Response:
    run_id = _require_valid_run_id(request.path_params["run_id"])
    run = _get_run_or_404(run_id)
    if run["report"] is None:
        raise _ApiError(409, "REPORT_NOT_AVAILABLE", "This run has not produced a report yet.")
    return JSONResponse({"run_id": run_id, "report": run["report"]})


@_api_route
async def get_evaluation(request: Request) -> Response:
    run_id = _require_valid_run_id(request.path_params["run_id"])
    run = _get_run_or_404(run_id)
    events = _event_bus.get_events(run_id=run_id, since_sequence=0)
    evaluation = evaluate_bug_bounty_run_against_juice_shop_benchmark(run=run, events=events)
    return JSONResponse(evaluation)


@_api_route
async def cancel_run(request: Request) -> Response:
    run_id = _require_valid_run_id(request.path_params["run_id"])
    run = _get_run_or_404(run_id)
    if run["status"] in TERMINAL_STATUSES:
        raise _ApiError(409, "RUN_ALREADY_TERMINAL", "This run has already finished and cannot be cancelled.")
    _run_store.update_fields(run_id=run_id, cancellation_requested=True)
    return JSONResponse({"run_id": run_id, "cancellation_requested": True})


async def stream_events(request: Request) -> Response:
    try:
        run_id = _require_valid_run_id(request.path_params["run_id"])
        _get_run_or_404(run_id)
    except _ApiError as exc:
        return JSONResponse({"error_code": exc.code, "message": exc.message}, status_code=exc.status_code)

    last_event_id = request.headers.get("last-event-id")
    since_param = request.query_params.get("since_sequence")
    since_sequence = 0
    for candidate in (last_event_id, since_param):
        if candidate is not None:
            try:
                since_sequence = max(since_sequence, int(candidate))
            except ValueError:
                pass

    subscription = _event_bus.subscribe(run_id=run_id, since_sequence=since_sequence)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await run_in_threadpool(subscription.queue.get, True, 1.0)
                except queue.Empty:
                    yield ": keep-alive\n\n"
                    continue
                payload = json.dumps(event)
                yield f"id: {event['sequence']}\nevent: {event['event_type']}\ndata: {payload}\n\n"
                if event["event_type"] in _TERMINAL_EVENT_TYPES:
                    break
        finally:
            _event_bus.unsubscribe(subscription)

    return StreamingResponse(
        event_generator(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


async def serve_dashboard(request: Request) -> Response:
    if not _DASHBOARD_PATH.is_file():
        return PlainTextResponse(
            "Live dashboard not found. Expected dashboard/live/index.html.", status_code=404,
        )
    return FileResponse(_DASHBOARD_PATH, media_type="text/html")


routes = [
    Route("/", serve_dashboard, methods=["GET"]),
    Route("/live", serve_dashboard, methods=["GET"]),
    Route("/api/health", health, methods=["GET"]),
    Route("/api/system", system_info, methods=["GET"]),
    Route("/api/runs", list_runs, methods=["GET"]),
    Route("/api/runs/bug-bounty", create_bug_bounty_run, methods=["POST"]),
    Route("/api/runs/security-lifecycle", create_security_lifecycle_run, methods=["POST"]),
    Route("/api/runs/authorized-target", create_authorized_target_run, methods=["POST"]),
    Route("/api/runs/detection", create_detection_run, methods=["POST"]),
    Route("/api/runs/{run_id}", get_run, methods=["GET"]),
    Route("/api/runs/{run_id}/events", get_events, methods=["GET"]),
    Route("/api/runs/{run_id}/stream", stream_events, methods=["GET"]),
    Route("/api/runs/{run_id}/report", get_report, methods=["GET"]),
    Route("/api/runs/{run_id}/evaluation", get_evaluation, methods=["GET"]),
    Route("/api/runs/{run_id}/cancel", cancel_run, methods=["POST"]),
    Route("/api/runs/{run_id}/lifecycle/review", record_lifecycle_review, methods=["POST"]),
]

app = Starlette(routes=routes)


def main() -> None:
    """Start the ThreatTrace Live Platform backend, bound to
    `127.0.0.1` only. Run via `python -m backend.app`."""
    uvicorn.run(app, host=BIND_HOST, port=BIND_PORT, log_level="info")


if __name__ == "__main__":
    main()
