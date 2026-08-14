"""Bounded, thread-safe, in-memory event pub/sub for the ThreatTrace
Live Platform backend (Block 15J-K).

## In-memory only -- restarting the backend loses all history

`EventBus` keeps every event in process memory only. There is no
filesystem, database, or Supabase write anywhere in this module. This
is deliberate operational event delivery for the current backend
process's lifetime -- never a tamper-evident audit store (compare
`core.tamper_evident_audit`, never imported here) and never an
authenticated message bus. A restarted backend starts with zero runs
and zero events.

## Bounded retention, deterministic eviction

At most `MAX_EVENTS_PER_RUN` events are retained per run (oldest
evicted first, FIFO, once exceeded) and at most `MAX_RUNS_RETAINED`
runs' event histories are retained at all (oldest-created run's entire
history evicted first, once exceeded) -- eviction is always
deterministic, never random, and never silently swaps to unbounded
growth under load.

## Sequencing is assigned here, not by the caller

`publish` is the *only* place a `sequence` number is ever assigned --
it reads the run's current highest sequence under a lock, increments,
and calls `backend.models.build_event` with that exact number, so two
concurrent publishers for the same run can never race into a duplicate
or out-of-order sequence. `backend.models.build_event` itself never
assigns a sequence; it only validates one it is given.

## Subscriptions are a best-effort live tail, never the source of truth

`subscribe`/`unsubscribe` hand out a small, independently bounded
`queue.Queue` per subscriber (`MAX_SUBSCRIBER_QUEUE_SIZE`) that
receives every event published *after* subscription (plus, if
`since_sequence` is supplied, a replay of already-retained history
newer than that sequence, seeded into the queue before any live event).
If a subscriber's queue fills up (a slow consumer), the oldest queued
item is dropped to make room for the newest -- this never blocks the
publishing thread. A subscriber that falls behind can always recover
missed events via `get_events`/`since_sequence`, bounded by
`MAX_EVENTS_PER_RUN` retention -- exactly the same bounded in-memory
history the queue itself was seeded from, so no permanent guarantee is
made beyond that same bound.

`EventBusError`, `EventBus` are this module's public symbols (plus its
fixed retention constants).
"""

from __future__ import annotations

import queue
import threading
from collections import OrderedDict, deque
from typing import Any

from backend.models import EVENT_TYPES, STAGES, SOURCE_COMPONENTS, EventModelError, build_event

MAX_EVENTS_PER_RUN = 500
MAX_RUNS_RETAINED = 50
MAX_SUBSCRIBER_QUEUE_SIZE = 100

__all__ = [
    "EventBusError", "EventBus", "MAX_EVENTS_PER_RUN", "MAX_RUNS_RETAINED", "MAX_SUBSCRIBER_QUEUE_SIZE",
    "EVENT_TYPES", "STAGES", "SOURCE_COMPONENTS",
]


class EventBusError(ValueError):
    """Raised when a supplied argument to `EventBus.publish`/`subscribe`/
    `unsubscribe`/`get_events` is structurally invalid, or (via the
    re-raised `EventModelError`) when the assembled event itself is
    invalid (an unrecognized `event_type`/`stage`/`source_component`, an
    oversized/forbidden-key `sanitized_payload`).

    Never raised because a run has zero events, because a subscriber
    queue overflowed and dropped an item, or because `since_sequence`
    is newer than any retained event (that simply yields an empty
    replay) -- every one of those is a normal, honestly-reported
    outcome.
    """


class _Subscription:
    __slots__ = ("run_id", "subscription_id", "queue")

    def __init__(self, *, run_id: str, subscription_id: int, maxsize: int) -> None:
        self.run_id = run_id
        self.subscription_id = subscription_id
        self.queue: queue.Queue = queue.Queue(maxsize=maxsize)


def _require_nonblank_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EventBusError(f"INVALID_RUN_ID: {field_name!r} must be a non-blank string")
    return value


class EventBus:
    """A bounded, thread-safe, in-memory event bus. One instance is
    meant to be shared by the whole backend process (constructed once
    in `backend.app`) and used both by orchestrator threads (via
    `publish`) and by SSE request handlers (via `subscribe`/
    `get_events`).
    """

    def __init__(self, *, max_events_per_run: int = MAX_EVENTS_PER_RUN, max_runs_retained: int = MAX_RUNS_RETAINED) -> None:
        self._max_events_per_run = max_events_per_run
        self._max_runs_retained = max_runs_retained
        self._lock = threading.Lock()
        self._events: OrderedDict[str, deque] = OrderedDict()
        self._next_sequence: dict[str, int] = {}
        self._subscribers: dict[str, list[_Subscription]] = {}
        self._next_subscription_id = 1

    def _ensure_run_bucket(self, run_id: str) -> None:
        if run_id in self._events:
            self._events.move_to_end(run_id)
            return
        self._events[run_id] = deque(maxlen=self._max_events_per_run)
        self._next_sequence[run_id] = 1
        self._subscribers.setdefault(run_id, [])
        while len(self._events) > self._max_runs_retained:
            oldest_run_id, _ = self._events.popitem(last=False)
            self._next_sequence.pop(oldest_run_id, None)
            self._subscribers.pop(oldest_run_id, None)

    def publish(
        self,
        *,
        run_id: Any,
        event_type: Any,
        timestamp: Any,
        stage: Any,
        source_component: Any,
        summary: Any,
        sanitized_payload: Any = None,
    ) -> dict[str, Any]:
        """Assign the next monotonic sequence number for `run_id`,
        build a validated event via `backend.models.build_event`,
        store it (bounded, FIFO-evicted), fan it out to every current
        subscriber for `run_id` (best-effort, drop-oldest on a full
        queue), and return the stored event.

        Raises `EventBusError` for an invalid `run_id`, or propagates
        `backend.models.EventModelError` unchanged for any other
        invalid field -- no event is ever stored or fanned out for a
        call that failed validation.
        """
        validated_run_id = _require_nonblank_string(run_id, "run_id")

        with self._lock:
            self._ensure_run_bucket(validated_run_id)
            sequence = self._next_sequence[validated_run_id]

            try:
                event = build_event(
                    run_id=validated_run_id, event_type=event_type, sequence=sequence, timestamp=timestamp,
                    stage=stage, source_component=source_component, summary=summary,
                    sanitized_payload=sanitized_payload,
                )
            except EventModelError:
                raise

            self._next_sequence[validated_run_id] = sequence + 1
            self._events[validated_run_id].append(event)
            subscribers = list(self._subscribers.get(validated_run_id, ()))

        for subscription in subscribers:
            self._deliver(subscription, event)
        return event

    def _deliver(self, subscription: _Subscription, event: dict[str, Any]) -> None:
        try:
            subscription.queue.put_nowait(event)
        except queue.Full:
            try:
                subscription.queue.get_nowait()
            except queue.Empty:
                pass
            try:
                subscription.queue.put_nowait(event)
            except queue.Full:
                pass

    def get_events(self, *, run_id: Any, since_sequence: int = 0) -> list[dict[str, Any]]:
        """Return every currently-retained event for `run_id` with
        `sequence > since_sequence`, in publication order. Returns an
        empty list for an unknown `run_id`, or when nothing newer than
        `since_sequence` is retained -- never raises for either case.
        """
        validated_run_id = _require_nonblank_string(run_id, "run_id")
        if isinstance(since_sequence, bool) or not isinstance(since_sequence, int) or since_sequence < 0:
            raise EventBusError("INVALID_SEQUENCE: since_sequence must be a non-negative int")

        with self._lock:
            bucket = self._events.get(validated_run_id)
            if bucket is None:
                return []
            return [event for event in bucket if event["sequence"] > since_sequence]

    def subscribe(self, *, run_id: Any, since_sequence: int = 0) -> _Subscription:
        """Register a new live subscriber for `run_id`, seed its queue
        with any already-retained history newer than `since_sequence`,
        and return the subscription handle. The caller must eventually
        call `unsubscribe` with the same handle (typically in a
        `finally` block) -- an un-unsubscribed handle is never
        automatically garbage-collected out of this bus's internal
        state.
        """
        validated_run_id = _require_nonblank_string(run_id, "run_id")
        if isinstance(since_sequence, bool) or not isinstance(since_sequence, int) or since_sequence < 0:
            raise EventBusError("INVALID_SEQUENCE: since_sequence must be a non-negative int")

        with self._lock:
            self._ensure_run_bucket(validated_run_id)
            subscription_id = self._next_subscription_id
            self._next_subscription_id += 1
            subscription = _Subscription(
                run_id=validated_run_id, subscription_id=subscription_id, maxsize=MAX_SUBSCRIBER_QUEUE_SIZE,
            )
            replay = [event for event in self._events[validated_run_id] if event["sequence"] > since_sequence]
            self._subscribers.setdefault(validated_run_id, []).append(subscription)

        for event in replay:
            self._deliver(subscription, event)
        return subscription

    def unsubscribe(self, subscription: Any) -> None:
        """Remove a subscription previously returned by `subscribe`.
        Safe to call more than once, or with a subscription whose run
        has since been evicted -- never raises either way.
        """
        if not isinstance(subscription, _Subscription):
            raise EventBusError("INVALID_SUBSCRIPTION: subscription must be a handle returned by subscribe()")
        with self._lock:
            subscribers = self._subscribers.get(subscription.run_id)
            if subscribers is None:
                return
            self._subscribers[subscription.run_id] = [
                entry for entry in subscribers if entry.subscription_id != subscription.subscription_id
            ]

    def subscriber_count(self, *, run_id: Any) -> int:
        """Return the number of currently-registered live subscribers
        for `run_id` (0 for an unknown run) -- used by tests to confirm
        `unsubscribe` cleanup actually happened.
        """
        validated_run_id = _require_nonblank_string(run_id, "run_id")
        with self._lock:
            return len(self._subscribers.get(validated_run_id, ()))
