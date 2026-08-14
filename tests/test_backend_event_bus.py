"""Focused tests for backend.event_bus -- bounded, thread-safe, in-memory
pub/sub (Block 15J-K).
"""

from __future__ import annotations

import pytest

from backend.event_bus import EventBus, EventBusError


def _publish(bus, run_id="RUN-abc", **overrides):
    payload = {
        "run_id": run_id, "event_type": "run_started", "timestamp": "t0",
        "stage": "intake", "source_component": "orchestrator", "summary": "x",
    }
    payload.update(overrides)
    return bus.publish(**payload)


class TestSequencing:
    def test_001_sequence_starts_at_one_and_is_monotonic(self):
        bus = EventBus()
        e1 = _publish(bus)
        e2 = _publish(bus)
        assert e1["sequence"] == 1
        assert e2["sequence"] == 2

    def test_002_sequence_is_per_run(self):
        bus = EventBus()
        a1 = _publish(bus, run_id="RUN-a")
        b1 = _publish(bus, run_id="RUN-b")
        a2 = _publish(bus, run_id="RUN-a")
        assert a1["sequence"] == 1
        assert b1["sequence"] == 1
        assert a2["sequence"] == 2


class TestRetention:
    def test_003_bounds_events_per_run(self):
        bus = EventBus(max_events_per_run=3)
        for _ in range(10):
            _publish(bus)
        events = bus.get_events(run_id="RUN-abc")
        assert len(events) == 3
        assert [e["sequence"] for e in events] == [8, 9, 10]

    def test_004_bounds_runs_retained_fifo(self):
        bus = EventBus(max_runs_retained=2)
        _publish(bus, run_id="RUN-1")
        _publish(bus, run_id="RUN-2")
        _publish(bus, run_id="RUN-3")
        assert bus.get_events(run_id="RUN-1") == []
        assert len(bus.get_events(run_id="RUN-2")) == 1
        assert len(bus.get_events(run_id="RUN-3")) == 1


class TestRunSeparation:
    def test_005_events_do_not_cross_runs(self):
        bus = EventBus()
        _publish(bus, run_id="RUN-a", summary="a-event")
        _publish(bus, run_id="RUN-b", summary="b-event")
        a_events = bus.get_events(run_id="RUN-a")
        assert len(a_events) == 1
        assert a_events[0]["summary"] == "a-event"


class TestPayloadSize:
    def test_006_oversized_payload_propagates_event_model_error(self):
        from backend.models import EventModelError
        bus = EventBus()
        with pytest.raises(EventModelError, match="PAYLOAD_TOO_LARGE"):
            _publish(bus, sanitized_payload={"blob": "x" * 20000})

    def test_007_invalid_publish_never_stores_event(self):
        from backend.models import EventModelError
        bus = EventBus()
        with pytest.raises(EventModelError):
            _publish(bus, sanitized_payload={"blob": "x" * 20000})
        assert bus.get_events(run_id="RUN-abc") == []


class TestSanitization:
    def test_008_forbidden_key_propagates(self):
        from backend.models import EventModelError
        bus = EventBus()
        with pytest.raises(EventModelError, match="PAYLOAD_FORBIDDEN_KEY"):
            _publish(bus, sanitized_payload={"cookie": "x"})


class TestReplay:
    def test_009_since_sequence_filters_history(self):
        bus = EventBus()
        for i in range(5):
            _publish(bus, summary=f"e{i}")
        events = bus.get_events(run_id="RUN-abc", since_sequence=3)
        assert [e["sequence"] for e in events] == [4, 5]

    def test_010_subscribe_seeds_replay_from_since_sequence(self):
        bus = EventBus()
        for i in range(3):
            _publish(bus, summary=f"e{i}")
        subscription = bus.subscribe(run_id="RUN-abc", since_sequence=1)
        seeded = [subscription.queue.get_nowait() for _ in range(subscription.queue.qsize())]
        assert [e["sequence"] for e in seeded] == [2, 3]
        bus.unsubscribe(subscription)

    def test_011_subscribe_receives_live_events_after_subscription(self):
        bus = EventBus()
        subscription = bus.subscribe(run_id="RUN-abc")
        _publish(bus, summary="live")
        event = subscription.queue.get_nowait()
        assert event["summary"] == "live"
        bus.unsubscribe(subscription)


class TestUnknownRun:
    def test_012_get_events_unknown_run_returns_empty(self):
        bus = EventBus()
        assert bus.get_events(run_id="RUN-nonexistent") == []

    def test_013_subscriber_count_unknown_run_is_zero(self):
        bus = EventBus()
        assert bus.subscriber_count(run_id="RUN-nonexistent") == 0


class TestSubscriberCleanup:
    def test_014_unsubscribe_removes_subscriber(self):
        bus = EventBus()
        subscription = bus.subscribe(run_id="RUN-abc")
        assert bus.subscriber_count(run_id="RUN-abc") == 1
        bus.unsubscribe(subscription)
        assert bus.subscriber_count(run_id="RUN-abc") == 0

    def test_015_unsubscribed_subscriber_receives_no_further_events(self):
        bus = EventBus()
        subscription = bus.subscribe(run_id="RUN-abc")
        bus.unsubscribe(subscription)
        _publish(bus, summary="after-unsub")
        assert subscription.queue.empty()

    def test_016_unsubscribe_is_idempotent(self):
        bus = EventBus()
        subscription = bus.subscribe(run_id="RUN-abc")
        bus.unsubscribe(subscription)
        bus.unsubscribe(subscription)  # must not raise

    def test_017_slow_subscriber_drops_oldest_never_blocks_publisher(self):
        bus = EventBus()
        subscription = bus.subscribe(run_id="RUN-abc")
        for i in range(200):
            _publish(bus, summary=f"e{i}")  # must never raise/block despite a full queue
        assert subscription.queue.qsize() <= 100


class TestInvalidArguments:
    def test_018_publish_rejects_blank_run_id(self):
        bus = EventBus()
        with pytest.raises(EventBusError, match="INVALID_RUN_ID"):
            _publish(bus, run_id="")

    def test_019_get_events_rejects_negative_since_sequence(self):
        bus = EventBus()
        with pytest.raises(EventBusError, match="INVALID_SEQUENCE"):
            bus.get_events(run_id="RUN-abc", since_sequence=-1)

    def test_020_unsubscribe_rejects_non_subscription(self):
        bus = EventBus()
        with pytest.raises(EventBusError, match="INVALID_SUBSCRIPTION"):
            bus.unsubscribe("not-a-subscription")
