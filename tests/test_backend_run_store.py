"""Focused tests for backend.run_store -- bounded, thread-safe, in-memory
Run storage (Block 15J-K).
"""

from __future__ import annotations

import pytest

from backend.models import RunModelError
from backend.run_store import RunStore, RunStoreError, generate_run_id, is_valid_run_id


class TestRunIds:
    def test_001_generated_id_matches_expected_shape(self):
        run_id = generate_run_id()
        assert is_valid_run_id(run_id)
        assert run_id.startswith("RUN-")
        assert len(run_id) == len("RUN-") + 32

    def test_002_generated_ids_are_unique(self):
        ids = {generate_run_id() for _ in range(50)}
        assert len(ids) == 50

    @pytest.mark.parametrize("candidate", [
        "../../etc/passwd", "RUN-short", "RUN-" + "z" * 32, "RUN-" + "0" * 31,
        "not-a-run-id", "", None, 123, "RUN-" + "0" * 32 + "/../evil",
    ])
    def test_003_rejects_malformed_ids(self, candidate):
        assert is_valid_run_id(candidate) is False


class TestCreate:
    def test_004_create_run_returns_created_status(self):
        store = RunStore()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        assert run["status"] == "created"
        assert is_valid_run_id(run["run_id"])

    def test_005_create_run_rejects_invalid_type(self):
        store = RunStore()
        with pytest.raises(RunStoreError, match="INVALID_RUN_TYPE"):
            store.create_run(run_type="nope", created_at="t0")


class TestTransitions:
    def test_006_transition_updates_status_and_fields(self):
        store = RunStore()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        updated = store.transition(run_id=run["run_id"], new_status="planning", current_stage="planning")
        assert updated["status"] == "planning"
        assert updated["current_stage"] == "planning"

    def test_007_invalid_transition_raises(self):
        store = RunStore()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        store.transition(run_id=run["run_id"], new_status="completed", completed_at="t1")
        with pytest.raises(RunModelError, match="TERMINAL_RUN"):
            store.transition(run_id=run["run_id"], new_status="running")

    def test_008_complete_run(self):
        store = RunStore()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        updated = store.transition(run_id=run["run_id"], new_status="completed", completed_at="t1")
        assert updated["status"] == "completed"

    def test_009_block_run(self):
        store = RunStore()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        updated = store.transition(run_id=run["run_id"], new_status="blocked", completed_at="t1")
        assert updated["status"] == "blocked"

    def test_010_fail_run(self):
        store = RunStore()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        updated = store.transition(run_id=run["run_id"], new_status="failed", error_summary="boom")
        assert updated["status"] == "failed"
        assert updated["error_summary"] == "boom"

    def test_011_transition_unknown_run_raises(self):
        store = RunStore()
        with pytest.raises(RunStoreError, match="RUN_NOT_FOUND"):
            store.transition(run_id="RUN-" + "0" * 32, new_status="planning")


class TestGetAndList:
    def test_012_get_run_unknown_raises(self):
        store = RunStore()
        with pytest.raises(RunStoreError, match="RUN_NOT_FOUND"):
            store.get_run(run_id="RUN-" + "0" * 32)

    def test_013_get_run_returns_independent_copy(self):
        store = RunStore()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        copy = store.get_run(run_id=run["run_id"])
        copy["status"] = "mutated"
        assert store.get_run(run_id=run["run_id"])["status"] == "created"

    def test_014_list_runs_most_recent_first(self):
        store = RunStore()
        first = store.create_run(run_type="bug_bounty", created_at="t0")
        second = store.create_run(run_type="detection", created_at="t1")
        runs = store.list_runs()
        assert runs[0]["run_id"] == second["run_id"]
        assert runs[1]["run_id"] == first["run_id"]


class TestRetention:
    def test_015_bounds_total_runs_retained(self):
        store = RunStore(max_runs_retained=3)
        ids = [store.create_run(run_type="bug_bounty", created_at="t0")["run_id"] for _ in range(10)]
        assert len(store.list_runs()) == 3
        with pytest.raises(RunStoreError, match="RUN_NOT_FOUND"):
            store.get_run(run_id=ids[0])


class TestConcurrencySlot:
    def test_016_first_acquire_succeeds(self):
        store = RunStore()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        assert store.try_acquire_bug_bounty_slot(run_id=run["run_id"]) is True

    def test_017_second_concurrent_acquire_fails(self):
        store = RunStore()
        run1 = store.create_run(run_type="bug_bounty", created_at="t0")
        run2 = store.create_run(run_type="bug_bounty", created_at="t1")
        assert store.try_acquire_bug_bounty_slot(run_id=run1["run_id"]) is True
        assert store.try_acquire_bug_bounty_slot(run_id=run2["run_id"]) is False

    def test_018_slot_releases_automatically_on_terminal_transition(self):
        store = RunStore()
        run1 = store.create_run(run_type="bug_bounty", created_at="t0")
        run2 = store.create_run(run_type="bug_bounty", created_at="t1")
        store.try_acquire_bug_bounty_slot(run_id=run1["run_id"])
        store.transition(run_id=run1["run_id"], new_status="completed", completed_at="t2")
        assert store.try_acquire_bug_bounty_slot(run_id=run2["run_id"]) is True

    def test_019_explicit_release(self):
        store = RunStore()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        store.try_acquire_bug_bounty_slot(run_id=run["run_id"])
        store.release_bug_bounty_slot(run_id=run["run_id"])
        assert store.active_bug_bounty_run_id() is None

    def test_020_detection_runs_never_touch_slot(self):
        store = RunStore()
        bb_run = store.create_run(run_type="bug_bounty", created_at="t0")
        store.try_acquire_bug_bounty_slot(run_id=bb_run["run_id"])
        detection_run = store.create_run(run_type="detection", created_at="t1")
        store.transition(run_id=detection_run["run_id"], new_status="completed", completed_at="t2")
        assert store.active_bug_bounty_run_id() == bb_run["run_id"]

    def test_024_slot_releases_on_awaiting_human_review(self):
        store = RunStore()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        store.try_acquire_bug_bounty_slot(run_id=run["run_id"])
        store.transition(run_id=run["run_id"], new_status="awaiting_human_review", current_stage="human_review")
        assert store.active_bug_bounty_run_id() is None

    def test_025_new_run_can_acquire_slot_while_old_run_awaits_review(self):
        store = RunStore()
        run_a = store.create_run(run_type="bug_bounty", created_at="t0")
        store.try_acquire_bug_bounty_slot(run_id=run_a["run_id"])
        store.transition(run_id=run_a["run_id"], new_status="awaiting_human_review", current_stage="human_review")

        run_b = store.create_run(run_type="bug_bounty", created_at="t1")
        assert store.try_acquire_bug_bounty_slot(run_id=run_b["run_id"]) is True
        assert store.active_bug_bounty_run_id() == run_b["run_id"]

    def test_026_awaiting_review_run_stays_in_history_and_gettable(self):
        store = RunStore()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        store.try_acquire_bug_bounty_slot(run_id=run["run_id"])
        store.transition(run_id=run["run_id"], new_status="awaiting_human_review", current_stage="human_review")

        assert store.get_run(run_id=run["run_id"])["status"] == "awaiting_human_review"
        assert any(r["run_id"] == run["run_id"] for r in store.list_runs())

    def test_027_reviewing_old_run_after_new_run_starts_does_not_disturb_new_runs_slot(self):
        store = RunStore()
        run_a = store.create_run(run_type="bug_bounty", created_at="t0")
        store.try_acquire_bug_bounty_slot(run_id=run_a["run_id"])
        store.transition(run_id=run_a["run_id"], new_status="awaiting_human_review", current_stage="human_review")

        run_b = store.create_run(run_type="bug_bounty", created_at="t1")
        store.try_acquire_bug_bounty_slot(run_id=run_b["run_id"])

        # Reviewing/completing run A (the old, already-slot-released run)
        # later must never touch run B's slot ownership.
        updated_a = store.transition(run_id=run_a["run_id"], new_status="completed", completed_at="t2")
        assert updated_a["status"] == "completed"
        assert store.active_bug_bounty_run_id() == run_b["run_id"]

    def test_028_multiple_runs_can_independently_await_review(self):
        store = RunStore()
        run_a = store.create_run(run_type="bug_bounty", created_at="t0")
        store.try_acquire_bug_bounty_slot(run_id=run_a["run_id"])
        store.transition(run_id=run_a["run_id"], new_status="awaiting_human_review", current_stage="human_review")

        run_b = store.create_run(run_type="bug_bounty", created_at="t1")
        store.try_acquire_bug_bounty_slot(run_id=run_b["run_id"])
        store.transition(run_id=run_b["run_id"], new_status="awaiting_human_review", current_stage="human_review")

        assert store.get_run(run_id=run_a["run_id"])["status"] == "awaiting_human_review"
        assert store.get_run(run_id=run_b["run_id"])["status"] == "awaiting_human_review"
        assert store.active_bug_bounty_run_id() is None

    def test_029_no_two_executions_run_concurrently_even_across_review_transitions(self):
        store = RunStore()
        run_a = store.create_run(run_type="bug_bounty", created_at="t0")
        assert store.try_acquire_bug_bounty_slot(run_id=run_a["run_id"]) is True

        run_b = store.create_run(run_type="bug_bounty", created_at="t1")
        # Run A is still executing (never reached awaiting_human_review or
        # terminal) -- run B must be rejected.
        assert store.try_acquire_bug_bounty_slot(run_id=run_b["run_id"]) is False

        store.transition(run_id=run_a["run_id"], new_status="awaiting_human_review", current_stage="human_review")
        # Now run B can acquire it, and a third run C must be rejected
        # while B genuinely executes.
        assert store.try_acquire_bug_bounty_slot(run_id=run_b["run_id"]) is True
        run_c = store.create_run(run_type="bug_bounty", created_at="t2")
        assert store.try_acquire_bug_bounty_slot(run_id=run_c["run_id"]) is False

    def test_030_completed_blocked_failed_cancelled_do_not_block_new_run(self):
        for terminal_status in ("completed", "blocked", "failed", "cancelled"):
            store = RunStore()
            run = store.create_run(run_type="bug_bounty", created_at="t0")
            store.try_acquire_bug_bounty_slot(run_id=run["run_id"])
            store.transition(run_id=run["run_id"], new_status=terminal_status, completed_at="t1")
            assert store.active_bug_bounty_run_id() is None, terminal_status

            run2 = store.create_run(run_type="bug_bounty", created_at="t2")
            assert store.try_acquire_bug_bounty_slot(run_id=run2["run_id"]) is True, terminal_status


class TestUpdateFields:
    def test_021_update_fields_leaves_status_unchanged(self):
        store = RunStore()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        updated = store.update_fields(run_id=run["run_id"], finding_count=5)
        assert updated["status"] == "created"
        assert updated["finding_count"] == 5

    def test_022_update_fields_on_terminal_run_raises(self):
        store = RunStore()
        run = store.create_run(run_type="bug_bounty", created_at="t0")
        store.transition(run_id=run["run_id"], new_status="completed", completed_at="t1")
        with pytest.raises(RunModelError, match="TERMINAL_RUN"):
            store.update_fields(run_id=run["run_id"], finding_count=5)

    def test_023_update_fields_unknown_run_raises(self):
        store = RunStore()
        with pytest.raises(RunStoreError, match="RUN_NOT_FOUND"):
            store.update_fields(run_id="RUN-" + "0" * 32, finding_count=1)
