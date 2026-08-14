---
description: Start the local-only ThreatTrace Live Platform backend and open the real-time operational dashboard (Block 15J-K)
argument-hint: "(no arguments -- optionally \"stop\" to shut down a backend this command started)"
---

# ThreatTrace Live Platform

`/threattrace-live` starts the Block 15J-K local backend (`backend.app`, bound to
`127.0.0.1:8420` only) and opens the real-time operational dashboard it serves at
`http://127.0.0.1:8420/`. This is purely a **startup convenience command** -- it
performs no security logic itself, computes no finding, evaluates no policy, and
never touches Supabase/MCP. Every actual decision (scope, tool policy, Governor,
telemetry feasibility, rule validation) happens inside `backend.orchestrator`
calling the project's existing, unmodified `core.*` modules, exactly as documented
in `docs/block15jk-live-platform-dashboard.md`.

## What This Command Does

1. Confirms a Python launcher is available (`py`, else `python3`, else a `python`
   confirmed to resolve to 3.10+), following this project's standard launcher
   selection convention.
2. Confirms `backend.app` is importable with that launcher. If not, stop and report
   `THREATTRACE_LIVE_UNAVAILABLE` -- never attempt to install a package.
3. Starts `python -m backend.app` as a background process (the caller may also run
   this directly in their own terminal instead of asking Claude to start it).
4. Once `GET http://127.0.0.1:8420/api/health` responds `200`, report the backend
   is ready and state the dashboard URL: `http://127.0.0.1:8420/` (the backend
   itself serves the dashboard -- there is no separate static file server).
5. Tell the caller to open that URL in their own browser -- this command never
   claims to have visually inspected the rendered page itself unless the caller
   separately reports having done so.

## What This Command Never Does

- Never binds the backend to anything other than `127.0.0.1` -- no `0.0.0.0`, no
  LAN interface, no cloud tunnel, no reverse proxy.
- Never starts a Bug Bounty or Detection run itself -- that only happens when the
  caller explicitly uses the dashboard's own controls, or calls
  `POST /api/runs/bug-bounty` / `POST /api/runs/detection` directly.
- Never claims authentication exists. The backend implements none; every response
  it returns says so explicitly (`GET /api/health` / `GET /api/system`).
- Never touches Supabase, MCP, or any external network endpoint.
- Never modifies `backend/`, `dashboard/live/`, or any `core.*`/`adapters.*` module
  -- this is a startup command only, never a code-generation or editing command.

## Stopping the Backend

If the caller passes `stop` as an argument and Claude itself started the backend
process in this session, stop that process. If the backend was started outside
this session (the caller ran `python -m backend.app` themselves), tell the caller
to stop it themselves (e.g. `Ctrl+C` in their own terminal) -- this command never
attempts to locate or kill a process it did not itself start.

## Required Failure Categories

### THREATTRACE_LIVE_UNAVAILABLE

No Python launcher could be selected, or `backend.app` failed to import (e.g. a
missing `starlette`/`uvicorn` dependency -- see `requirements.txt`). Report the
exact import error text; never guess a fix or silently install a package.

### THREATTRACE_LIVE_START_FAILED

The backend process was started but `GET /api/health` never returned `200` within
a reasonable bounded wait (a few seconds). Report this plainly; never claim the
backend is ready when it is not.

## Safety Rules

- Bind is always `127.0.0.1` -- never accept an argument that would change this.
- Never claim a Bug Bounty/Detection run happened unless the caller actually
  triggered one and this command (or the caller) observed a real API response.
- Never claim visual dashboard verification without the caller reporting it.
- Never expose a raw stack trace -- report the sanitized failure category only.
- This is a **local development/research interface** -- state that plainly
  whenever reporting the backend as ready, mirroring `GET /api/health`'s own
  `interface_class` field.
