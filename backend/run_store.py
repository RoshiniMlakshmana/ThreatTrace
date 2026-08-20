"""Thread-safe, bounded, in-memory Run store for the ThreatTrace Live
Platform backend (Block 15J-K).

## In-memory runtime history, not persistent/audit storage

Exactly like `backend.event_bus`, every run record lives in process
memory only -- no filesystem, database, or Supabase write anywhere in
this module. Restarting the backend loses every run. This is never
described as an audit trail (`core.tamper_evident_audit` is a separate,
unrelated, unmodified module).

## Run IDs are opaque and never used as a filesystem path

`generate_run_id` produces `f"RUN-{16 random hex bytes}"` via
`secrets.token_hex` -- unguessable, and structurally incapable of
containing a path-traversal sequence, a shell metacharacter, or a slash.
`is_valid_run_id` additionally lets `backend.app` reject any
caller-supplied run-id-shaped path segment that does not match this
exact fixed pattern *before* ever calling `get_run` -- since this
module builds no filesystem path from a run id at all (no persistence
exists in this checkpoint), a malformed id can only ever produce an
honest "not found," never any traversal risk; `is_valid_run_id` exists
purely so the API layer can return a clean `400` instead of a `404` for
an obviously malformed id, and so a dedicated regression test can
assert the rejection directly.

## One active offensive-assessment *execution* at a time

`try_acquire_bug_bounty_slot`/`release_bug_bounty_slot` implement
Section 27's concurrency bound: at most one `run_type == "bug_bounty"`
run (the only run type that actually executes a real network-capable
tool against the local Juice Shop container) may be *executing* at
once. This is an execution guard, not a run-history guard -- it answers
"is a tool/workflow actually running right now," never "does some
historical run remain unreviewed." `transition` automatically releases
the slot the instant a bug-bounty run's status leaves
`backend.models.EXECUTION_ACTIVE_STATUSES`: either because it reached a
terminal status (see `backend.models.TERMINAL_STATUSES`), or because it
reached `"awaiting_human_review"` -- execution has genuinely finished at
that point; the run is only waiting on a human decision, so it must not
continue to block a new assessment from starting. The orchestrator never
has to remember to release it itself, so a crashed/failed run -- or one
sitting unreviewed indefinitely -- can never permanently wedge the slot.
`run_type == "detection"` runs never touch this slot at all; they never
execute an offensive tool.

`RunStoreError`, `RunStore`, `generate_run_id`, `is_valid_run_id` are
this module's public symbols (plus its fixed retention constant).
"""

from __future__ import annotations

import re
import secrets
import threading
from collections import OrderedDict
from typing import Any

from backend.models import EXECUTION_ACTIVE_STATUSES, RUN_TYPES, RunModelError, apply_run_transition, build_run

MAX_RUNS_RETAINED = 100

RUN_ID_PATTERN = re.compile(r"^RUN-[0-9a-f]{32}$")

__all__ = ["RunStoreError", "RunStore", "generate_run_id", "is_valid_run_id", "MAX_RUNS_RETAINED"]


class RunStoreError(ValueError):
    """Raised for an unknown `run_id`, a structurally invalid `run_id`,
    an invalid `run_type`, or (via the re-raised `RunModelError`) an
    invalid status transition/field update.

    Every message begins with one of a fixed set of stable codes:
    `RUN_NOT_FOUND`, `INVALID_RUN_ID`, `INVALID_RUN_TYPE`,
    `SLOT_UNAVAILABLE`.

    Never raised because a run ends up blocked/failed/cancelled --
    every one of those is a normal, honestly-recorded outcome.
    """


def generate_run_id() -> str:
    """Generate one new opaque, unguessable, filesystem-path-safe run
    id: `"RUN-"` followed by 32 lowercase hex characters
    (`secrets.token_hex(16)`). Never derived from caller input, a
    counter, or a timestamp.
    """
    return f"RUN-{secrets.token_hex(16)}"


def is_valid_run_id(value: Any) -> bool:
    """Return whether `value` matches the exact fixed run-id shape this
    store ever generates. Used by `backend.app` to reject a malformed
    (e.g. path-traversal-shaped) run id in a URL path segment with a
    clean `400` before any lookup is attempted."""
    return isinstance(value, str) and bool(RUN_ID_PATTERN.match(value))


class RunStore:
    """A bounded, thread-safe, in-memory store of `backend.models` run
    records. One instance is meant to be shared by the whole backend
    process (constructed once in `backend.app`)."""

    def __init__(self, *, max_runs_retained: int = MAX_RUNS_RETAINED) -> None:
        self._max_runs_retained = max_runs_retained
        self._lock = threading.Lock()
        self._runs: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._active_bug_bounty_run_id: str | None = None

    def create_run(self, *, run_type: Any, created_at: Any) -> dict[str, Any]:
        """Generate a new opaque run id, build a `"created"`-status run
        record for it, store it, and return a copy. Raises
        `RunStoreError` (`INVALID_RUN_TYPE`) for an invalid `run_type`,
        propagating `backend.models.RunModelError` otherwise unchanged.
        """
        if not isinstance(run_type, str) or run_type not in RUN_TYPES:
            raise RunStoreError("INVALID_RUN_TYPE: run_type must be one of RUN_TYPES")

        run_id = generate_run_id()
        try:
            run = build_run(run_id=run_id, run_type=run_type, created_at=created_at)
        except RunModelError:
            raise

        with self._lock:
            self._runs[run_id] = run
            self._evict_if_needed()
        return dict(run)

    def _evict_if_needed(self) -> None:
        while len(self._runs) > self._max_runs_retained:
            oldest_run_id, _ = self._runs.popitem(last=False)
            if self._active_bug_bounty_run_id == oldest_run_id:
                self._active_bug_bounty_run_id = None

    def get_run(self, *, run_id: Any) -> dict[str, Any]:
        """Return a copy of the run record for `run_id`. Raises
        `RunStoreError` (`RUN_NOT_FOUND`) for an unknown or malformed
        `run_id`."""
        if not isinstance(run_id, str):
            raise RunStoreError("RUN_NOT_FOUND: unknown run_id")
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise RunStoreError("RUN_NOT_FOUND: unknown run_id")
            return dict(run)

    def list_runs(self) -> list[dict[str, Any]]:
        """Return a copy of every currently-retained run record, most
        recently created first."""
        with self._lock:
            return [dict(run) for run in reversed(self._runs.values())]

    def transition(self, *, run_id: Any, new_status: Any, timestamp: Any = None, **field_updates: Any) -> dict[str, Any]:
        """Apply `backend.models.apply_run_transition` to the stored
        run for `run_id`, store the result, and return a copy. If
        `new_status` leaves `backend.models.EXECUTION_ACTIVE_STATUSES`
        (a terminal status, or `"awaiting_human_review"`) and the run is
        a `"bug_bounty"` run currently holding the concurrency slot, the
        slot is released automatically as part of the same locked
        operation -- a run awaiting human review no longer occupies the
        execution slot, even though it remains fully in run history.

        Raises `RunStoreError` (`RUN_NOT_FOUND`) for an unknown
        `run_id`, or propagates `backend.models.RunModelError` unchanged
        for an invalid transition (e.g. re-entering `"created"`, or
        transitioning an already-terminal run).
        """
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise RunStoreError("RUN_NOT_FOUND: unknown run_id")

            updated = apply_run_transition(run=run, new_status=new_status, timestamp=timestamp, **field_updates)
            self._runs[run_id] = updated

            if updated["run_type"] == "bug_bounty" and updated["status"] not in EXECUTION_ACTIVE_STATUSES:
                if self._active_bug_bounty_run_id == run_id:
                    self._active_bug_bounty_run_id = None

            return dict(updated)

    def update_fields(self, *, run_id: Any, **field_updates: Any) -> dict[str, Any]:
        """Update mutable fields on the stored run for `run_id` without
        changing its `status` (e.g. incrementing `finding_count` mid-run).
        Raises `RunStoreError` (`RUN_NOT_FOUND`) for an unknown
        `run_id`, or propagates `backend.models.RunModelError` unchanged
        for an invalid field name/value."""
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise RunStoreError("RUN_NOT_FOUND: unknown run_id")
            updated = apply_run_transition(run=run, new_status=run["status"], **field_updates)
            self._runs[run_id] = updated
            return dict(updated)

    def try_acquire_bug_bounty_slot(self, *, run_id: Any) -> bool:
        """Attempt to claim the single-active-offensive-assessment slot
        for `run_id`. Returns `True` if claimed (or already held by
        this exact `run_id`), `False` if another bug-bounty run
        currently holds it. Never raises for a busy slot -- the caller
        (`backend.app`) is expected to translate `False` into a clean
        `409 Conflict` response."""
        with self._lock:
            if self._active_bug_bounty_run_id in (None, run_id):
                self._active_bug_bounty_run_id = run_id
                return True
            return False

    def release_bug_bounty_slot(self, *, run_id: Any) -> None:
        """Release the concurrency slot if currently held by `run_id`.
        Safe to call even if not held -- never raises."""
        with self._lock:
            if self._active_bug_bounty_run_id == run_id:
                self._active_bug_bounty_run_id = None

    def active_bug_bounty_run_id(self) -> str | None:
        """Return the run id currently holding the execution concurrency
        slot, or `None` if free. Reflects whether a tool/workflow is
        actually executing right now -- a run sitting at
        `"awaiting_human_review"` never holds this, regardless of how
        long it has been waiting for a decision."""
        with self._lock:
            return self._active_bug_bounty_run_id
