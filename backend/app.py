"""ThreatTrace Live Platform backend HTTP/SSE interface (Block 15J-K).

## Local-only, by construction

`main()` binds uvicorn to `127.0.0.1` only -- never `0.0.0.0`, never a
LAN-reachable interface. There is no cloud tunnel, no reverse proxy
configuration, and no authentication of any kind anywhere in this
module. This is a **local development/research interface**, never a
production-authenticated control plane -- every response this module
returns is honest about that (see `GET /api/health`).

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
import queue
import shutil
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
from backend.models import TERMINAL_STATUSES, RunModelError, validate_local_only_target
from backend.orchestrator import TRIGGER_SOURCES, run_bug_bounty_workflow, run_detection_workflow
from backend.run_store import RunStore, RunStoreError, is_valid_run_id

BACKEND_VERSION = "1"
BIND_HOST = "127.0.0.1"
BIND_PORT = 8420

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


@_api_route
async def system_info(request: Request) -> Response:
    return JSONResponse({
        "system_version": "1",
        "bind": f"{BIND_HOST}:{BIND_PORT}",
        "tools": {
            "http_assessor": "available",
            "nmap": "available" if shutil.which("nmap") else "not_installed",
            "nuclei": "available" if shutil.which("nuclei") else "not_installed",
            "zap": "not_configured",
            "burp_dast": "not_configured",
        },
        "active_bug_bounty_run_id": _run_store.active_bug_bounty_run_id(),
        "limitations": [
            "local development/research interface -- not a production-authenticated control plane",
            "run history is in-memory only and is lost on backend restart",
            "zap/burp_dast readiness is never probed automatically -- reported not_configured until a run exercises them",
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
        raise _ApiError(409, "CONCURRENT_RUN_ACTIVE", "Another Bug Bounty run is already active.")

    run = _run_store.create_run(run_type="bug_bounty", created_at=_now())
    if not _run_store.try_acquire_bug_bounty_slot(run_id=run["run_id"]):
        _run_store.transition(
            run_id=run["run_id"], new_status="blocked", completed_at=_now(),
            limitations=["CONCURRENT_RUN_ACTIVE: another Bug Bounty run claimed the slot first."],
        )
        raise _ApiError(409, "CONCURRENT_RUN_ACTIVE", "Another Bug Bounty run is already active.")

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
    Route("/api/runs/detection", create_detection_run, methods=["POST"]),
    Route("/api/runs/{run_id}", get_run, methods=["GET"]),
    Route("/api/runs/{run_id}/events", get_events, methods=["GET"]),
    Route("/api/runs/{run_id}/stream", stream_events, methods=["GET"]),
    Route("/api/runs/{run_id}/report", get_report, methods=["GET"]),
    Route("/api/runs/{run_id}/cancel", cancel_run, methods=["POST"]),
]

app = Starlette(routes=routes)


def main() -> None:
    """Start the ThreatTrace Live Platform backend, bound to
    `127.0.0.1` only. Run via `python -m backend.app`."""
    uvicorn.run(app, host=BIND_HOST, port=BIND_PORT, log_level="info")


if __name__ == "__main__":
    main()
