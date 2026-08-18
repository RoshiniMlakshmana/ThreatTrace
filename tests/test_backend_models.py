"""Focused tests for backend.models -- the pure, deterministic Run +
Event contract layer (Block 15J-K).
"""

from __future__ import annotations

import pytest

from backend.models import (
    DEFAULT_EXTERNAL_TARGET_ALLOWED_TOOLS,
    DEMO_TARGET_DISPLAY_ALIAS,
    DEMO_TARGET_ENV_VAR,
    EXTERNAL_TARGET_ELIGIBLE_TOOL_IDS,
    RUN_STATUSES,
    TERMINAL_STATUSES,
    EventModelError,
    RunModelError,
    apply_run_transition,
    build_event,
    build_run,
    resolve_execution_target,
    validate_authorized_external_target_scope,
    validate_local_only_target,
)


def _external_scope(**overrides):
    scope = {
        "hosts": ["security-test.example.com"],
        "ports": [443],
        "path_prefixes": ["/"],
        "allowed_tools": ["http_assessor", "httpx", "katana"],
    }
    scope.update(overrides)
    return scope


class TestBuildRun:
    def test_001_creates_run_with_defaults(self):
        run = build_run(run_id="RUN-abc", run_type="bug_bounty", created_at="t0")
        assert run["status"] == "created"
        assert run["current_stage"] == "created"
        assert run["started_at"] is None
        assert run["completed_at"] is None
        assert run["finding_count"] == 0
        assert run["governor_decisions"] == []
        assert run["human_review_required"] is False
        assert run["cancellation_requested"] is False
        assert run["report"] is None

    def test_002_rejects_invalid_run_type(self):
        with pytest.raises(RunModelError, match="INVALID_RUN_TYPE"):
            build_run(run_id="RUN-abc", run_type="not_a_type", created_at="t0")

    def test_003_rejects_blank_run_id(self):
        with pytest.raises(RunModelError, match="INVALID_RUN_ID"):
            build_run(run_id="", run_type="bug_bounty", created_at="t0")

    def test_004_rejects_blank_created_at(self):
        with pytest.raises(RunModelError, match="INVALID_TIMESTAMP"):
            build_run(run_id="RUN-abc", run_type="bug_bounty", created_at="")


class TestApplyRunTransition:
    def test_005_transitions_and_does_not_mutate_original(self):
        run = build_run(run_id="RUN-abc", run_type="bug_bounty", created_at="t0")
        updated = apply_run_transition(run=run, new_status="planning", current_stage="planning")
        assert updated["status"] == "planning"
        assert run["status"] == "created"

    def test_006_rejects_reentering_created_from_a_different_status(self):
        run = build_run(run_id="RUN-abc", run_type="bug_bounty", created_at="t0")
        planning = apply_run_transition(run=run, new_status="planning")
        with pytest.raises(RunModelError, match="REENTER_CREATED"):
            apply_run_transition(run=planning, new_status="created")

    def test_006b_allows_field_update_noop_while_still_created(self):
        run = build_run(run_id="RUN-abc", run_type="bug_bounty", created_at="t0")
        updated = apply_run_transition(run=run, new_status="created", cancellation_requested=True)
        assert updated["status"] == "created"
        assert updated["cancellation_requested"] is True

    def test_007_rejects_transition_from_terminal(self):
        run = build_run(run_id="RUN-abc", run_type="bug_bounty", created_at="t0")
        terminal = apply_run_transition(run=run, new_status="completed", completed_at="t1")
        with pytest.raises(RunModelError, match="TERMINAL_RUN"):
            apply_run_transition(run=terminal, new_status="running")

    def test_008_rejects_unrecognized_status(self):
        run = build_run(run_id="RUN-abc", run_type="bug_bounty", created_at="t0")
        with pytest.raises(RunModelError, match="INVALID_STATUS"):
            apply_run_transition(run=run, new_status="not_a_status")

    def test_009_rejects_immutable_field_update(self):
        run = build_run(run_id="RUN-abc", run_type="bug_bounty", created_at="t0")
        with pytest.raises(RunModelError, match="INVALID_FIELD"):
            apply_run_transition(run=run, new_status="planning", run_id="RUN-hacked")

    def test_010_every_status_is_reachable_target(self):
        run = build_run(run_id="RUN-abc", run_type="detection", created_at="t0")
        for status in RUN_STATUSES - {"created"}:
            apply_run_transition(run=run, new_status=status)

    def test_011_terminal_statuses_subset_of_run_statuses(self):
        assert TERMINAL_STATUSES.issubset(RUN_STATUSES)


class TestBuildEvent:
    def test_012_builds_valid_event(self):
        event = build_event(
            run_id="RUN-abc", event_type="run_started", sequence=1, timestamp="t0",
            stage="intake", source_component="orchestrator", summary="started",
        )
        assert event["event_id"] == "EVT-RUN-abc-1"
        assert event["sanitized_payload"] == {}

    def test_013_rejects_unrecognized_event_type(self):
        with pytest.raises(EventModelError, match="INVALID_EVENT_TYPE"):
            build_event(
                run_id="RUN-abc", event_type="not_a_type", sequence=1, timestamp="t0",
                stage="intake", source_component="orchestrator", summary="x",
            )

    def test_014_rejects_non_positive_sequence(self):
        with pytest.raises(EventModelError, match="INVALID_SEQUENCE"):
            build_event(
                run_id="RUN-abc", event_type="run_started", sequence=0, timestamp="t0",
                stage="intake", source_component="orchestrator", summary="x",
            )

    def test_015_truncates_oversized_summary(self):
        event = build_event(
            run_id="RUN-abc", event_type="run_started", sequence=1, timestamp="t0",
            stage="intake", source_component="orchestrator", summary="x" * 500,
        )
        assert len(event["summary"]) <= 300
        assert event["summary"].endswith("...")

    def test_016_rejects_oversized_payload(self):
        with pytest.raises(EventModelError, match="PAYLOAD_TOO_LARGE"):
            build_event(
                run_id="RUN-abc", event_type="run_started", sequence=1, timestamp="t0",
                stage="intake", source_component="orchestrator", summary="x",
                sanitized_payload={"blob": "x" * 20000},
            )

    @pytest.mark.parametrize("key", ["cookie", "auth_token", "Authorization", "api_key", "password", "SECRET"])
    def test_017_rejects_forbidden_payload_keys(self, key):
        with pytest.raises(EventModelError, match="PAYLOAD_FORBIDDEN_KEY"):
            build_event(
                run_id="RUN-abc", event_type="run_started", sequence=1, timestamp="t0",
                stage="intake", source_component="orchestrator", summary="x",
                sanitized_payload={key: "x"},
            )

    def test_018_rejects_forbidden_key_nested(self):
        with pytest.raises(EventModelError, match="PAYLOAD_FORBIDDEN_KEY"):
            build_event(
                run_id="RUN-abc", event_type="run_started", sequence=1, timestamp="t0",
                stage="intake", source_component="orchestrator", summary="x",
                sanitized_payload={"details": {"nested": {"cookie": "x"}}},
            )

    def test_019_rejects_non_serializable_payload(self):
        with pytest.raises(EventModelError, match="INVALID_PAYLOAD"):
            build_event(
                run_id="RUN-abc", event_type="run_started", sequence=1, timestamp="t0",
                stage="intake", source_component="orchestrator", summary="x",
                sanitized_payload={"obj": object()},
            )

    def test_020_rejects_unrecognized_stage(self):
        with pytest.raises(EventModelError, match="INVALID_STAGE"):
            build_event(
                run_id="RUN-abc", event_type="run_started", sequence=1, timestamp="t0",
                stage="not_a_stage", source_component="orchestrator", summary="x",
            )

    def test_021_rejects_unrecognized_source_component(self):
        with pytest.raises(EventModelError, match="INVALID_SOURCE_COMPONENT"):
            build_event(
                run_id="RUN-abc", event_type="run_started", sequence=1, timestamp="t0",
                stage="intake", source_component="not_a_component", summary="x",
            )


class TestValidateLocalOnlyTarget:
    def test_022_accepts_localhost(self):
        assert validate_local_only_target("http://localhost:3000/") == "http://localhost:3000/"

    @pytest.mark.parametrize("target", [
        "http://127.0.0.1:3000/",
        "https://localhost:3000/",
        "http://example.com/",
        "http://192.168.1.5/",
        "http://10.0.0.5/",
        "file:///etc/passwd",
        "ftp://localhost/",
        "javascript:alert(1)",
        "http://user:pass@localhost:3000/",
        "http://localhost:3000/#frag",
        "",
        None,
        123,
    ])
    def test_023_rejects_everything_else(self, target):
        with pytest.raises(RunModelError, match="INVALID_TARGET"):
            validate_local_only_target(target)


class TestResolveExecutionTarget:
    """Docker self-hosted deployment: the demo-target alias mechanism.

    resolve_execution_target is strictly additive and only ever runs
    after validate_local_only_target has already accepted the caller's
    display target -- it never widens what a caller may submit, it only
    optionally redirects one exact, pre-approved alias to a
    Docker-internal execution target.
    """

    def test_024_no_op_when_env_unset(self):
        result = resolve_execution_target(display_target="http://localhost:3000/", env={})
        assert result == "http://localhost:3000/"

    def test_025_maps_exact_alias_when_configured(self):
        env = {DEMO_TARGET_ENV_VAR: "http://juice-shop:3000"}
        result = resolve_execution_target(display_target=DEMO_TARGET_DISPLAY_ALIAS, env=env)
        assert result == "http://juice-shop:3000"

    def test_026_tolerates_trailing_slash_mismatch(self):
        env = {DEMO_TARGET_ENV_VAR: "http://juice-shop:3000"}
        result = resolve_execution_target(display_target="http://localhost:3000", env=env)
        assert result == "http://juice-shop:3000"

    @pytest.mark.parametrize("display_target", [
        "http://localhost:3001/",
        "http://localhost:3000/admin",
        "https://localhost:3000/",
        "http://127.0.0.1:3000/",
        "http://juice-shop:3000/",
        "http://evil.example.com/",
    ])
    def test_027_never_maps_any_other_hostname_or_variant(self, display_target):
        env = {DEMO_TARGET_ENV_VAR: "http://juice-shop:3000"}
        result = resolve_execution_target(display_target=display_target, env=env)
        assert result == display_target

    def test_028_blank_env_value_is_no_op(self):
        env = {DEMO_TARGET_ENV_VAR: "   "}
        result = resolve_execution_target(display_target=DEMO_TARGET_DISPLAY_ALIAS, env=env)
        assert result == DEMO_TARGET_DISPLAY_ALIAS

    def test_029_does_not_weaken_validate_local_only_target(self):
        # Even with the demo alias configured, the execution target
        # itself (a Docker-network hostname) must still be rejected as
        # a *display* target -- only the orchestrator's internal
        # resolve_execution_target call is permitted to see it.
        with pytest.raises(RunModelError, match="INVALID_TARGET"):
            validate_local_only_target("http://juice-shop:3000")


class TestValidateAuthorizedExternalTargetScope:
    def test_030_valid_scope_accepted(self):
        result = validate_authorized_external_target_scope(
            target="https://security-test.example.com/", scope=_external_scope(), operator_scope_acknowledged=True,
        )
        assert result["bug_bounty_scope"]["target"] == "https://security-test.example.com/"
        assert result["allowed_tools"] == ["http_assessor", "httpx", "katana"]
        assert result["operator_scope_acknowledged"] is True

    def test_031_acknowledgment_required(self):
        with pytest.raises(RunModelError, match="EXTERNAL_SCOPE_NOT_ACKNOWLEDGED"):
            validate_authorized_external_target_scope(
                target="https://security-test.example.com/", scope=_external_scope(), operator_scope_acknowledged=False,
            )

    def test_032_acknowledgment_string_true_rejected(self):
        # Only the literal boolean True satisfies this -- never a
        # truthy string, which could arrive from a sloppy client.
        with pytest.raises(RunModelError, match="EXTERNAL_SCOPE_NOT_ACKNOWLEDGED"):
            validate_authorized_external_target_scope(
                target="https://security-test.example.com/", scope=_external_scope(), operator_scope_acknowledged="true",
            )

    def test_033_missing_scope_field_rejected(self):
        scope = _external_scope()
        del scope["ports"]
        with pytest.raises(RunModelError, match="INVALID_EXTERNAL_SCOPE"):
            validate_authorized_external_target_scope(
                target="https://security-test.example.com/", scope=scope, operator_scope_acknowledged=True,
            )

    def test_034_extra_scope_field_rejected(self):
        scope = _external_scope()
        scope["cidr_ranges"] = ["10.0.0.0/8"]
        with pytest.raises(RunModelError, match="INVALID_EXTERNAL_SCOPE"):
            validate_authorized_external_target_scope(
                target="https://security-test.example.com/", scope=scope, operator_scope_acknowledged=True,
            )

    def test_035_wildcard_host_rejected(self):
        with pytest.raises(RunModelError, match="EXTERNAL_SCOPE_WILDCARD_NOT_ALLOWED"):
            validate_authorized_external_target_scope(
                target="https://security-test.example.com/",
                scope=_external_scope(hosts=["*.example.com"]),
                operator_scope_acknowledged=True,
            )

    def test_036_empty_hosts_rejected(self):
        with pytest.raises(RunModelError, match="INVALID_EXTERNAL_SCOPE"):
            validate_authorized_external_target_scope(
                target="https://security-test.example.com/", scope=_external_scope(hosts=[]), operator_scope_acknowledged=True,
            )

    def test_037_port_out_of_range_rejected(self):
        with pytest.raises(RunModelError, match="INVALID_EXTERNAL_SCOPE"):
            validate_authorized_external_target_scope(
                target="https://security-test.example.com/", scope=_external_scope(ports=[70000]), operator_scope_acknowledged=True,
            )

    def test_038_bool_port_rejected(self):
        with pytest.raises(RunModelError, match="INVALID_EXTERNAL_SCOPE"):
            validate_authorized_external_target_scope(
                target="https://security-test.example.com/", scope=_external_scope(ports=[True]), operator_scope_acknowledged=True,
            )

    def test_039_relative_path_prefix_rejected(self):
        with pytest.raises(RunModelError, match="INVALID_EXTERNAL_SCOPE"):
            validate_authorized_external_target_scope(
                target="https://security-test.example.com/",
                scope=_external_scope(path_prefixes=["relative"]),
                operator_scope_acknowledged=True,
            )

    def test_040_unrecognized_tool_id_rejected(self):
        with pytest.raises(RunModelError, match="EXTERNAL_SCOPE_TOOL_NOT_PERMITTED"):
            validate_authorized_external_target_scope(
                target="https://security-test.example.com/",
                scope=_external_scope(allowed_tools=["nikto"]),
                operator_scope_acknowledged=True,
            )

    def test_041_authenticated_testing_not_permitted_via_this_endpoint(self):
        with pytest.raises(RunModelError, match="EXTERNAL_SCOPE_TOOL_NOT_PERMITTED"):
            validate_authorized_external_target_scope(
                target="https://security-test.example.com/",
                scope=_external_scope(allowed_tools=["authenticated_testing"]),
                operator_scope_acknowledged=True,
            )

    def test_042_target_host_not_in_scope_hosts_rejected(self):
        with pytest.raises(RunModelError, match="INVALID_EXTERNAL_TARGET"):
            validate_authorized_external_target_scope(
                target="https://other-host.example.com/", scope=_external_scope(), operator_scope_acknowledged=True,
            )

    def test_043_target_port_not_in_scope_ports_rejected(self):
        with pytest.raises(RunModelError, match="INVALID_EXTERNAL_TARGET"):
            validate_authorized_external_target_scope(
                target="https://security-test.example.com:8443/",
                scope=_external_scope(),
                operator_scope_acknowledged=True,
            )

    def test_044_raw_ip_target_rejected(self):
        with pytest.raises(RunModelError):
            validate_authorized_external_target_scope(
                target="https://93.184.216.34/", scope=_external_scope(hosts=["93.184.216.34"]), operator_scope_acknowledged=True,
            )

    def test_045_non_http_scheme_rejected(self):
        with pytest.raises(RunModelError, match="INVALID_TARGET"):
            validate_authorized_external_target_scope(
                target="ftp://security-test.example.com/", scope=_external_scope(), operator_scope_acknowledged=True,
            )

    def test_046_javascript_scheme_rejected(self):
        with pytest.raises(RunModelError, match="INVALID_TARGET"):
            validate_authorized_external_target_scope(
                target="javascript:alert(1)", scope=_external_scope(), operator_scope_acknowledged=True,
            )

    def test_047_non_default_port_reflected_in_allowed_origins(self):
        result = validate_authorized_external_target_scope(
            target="https://security-test.example.com:8443/",
            scope=_external_scope(ports=[8443], path_prefixes=["/app"]),
            operator_scope_acknowledged=True,
        )
        assert "https://security-test.example.com:8443" in result["bug_bounty_scope"]["allowed_origins"]

    def test_048_multiple_hosts_and_ports_produce_cartesian_origins(self):
        result = validate_authorized_external_target_scope(
            target="https://a.example.com/",
            scope=_external_scope(hosts=["a.example.com", "b.example.com"], ports=[443, 8443]),
            operator_scope_acknowledged=True,
        )
        origins = set(result["bug_bounty_scope"]["allowed_origins"])
        assert origins == {
            "https://a.example.com", "https://a.example.com:8443",
            "https://b.example.com", "https://b.example.com:8443",
        }

    def test_049_path_prefixes_become_allowed_paths(self):
        result = validate_authorized_external_target_scope(
            target="https://security-test.example.com/",
            scope=_external_scope(path_prefixes=["/app", "/api"]),
            operator_scope_acknowledged=True,
        )
        assert result["bug_bounty_scope"]["allowed_paths"] == ["/app", "/api"]

    def test_050_default_external_target_allowed_tools_is_conservative(self):
        assert DEFAULT_EXTERNAL_TARGET_ALLOWED_TOOLS == ("http_assessor", "httpx", "katana")
        for tool_id in DEFAULT_EXTERNAL_TARGET_ALLOWED_TOOLS:
            assert tool_id in EXTERNAL_TARGET_ELIGIBLE_TOOL_IDS

    def test_051_nmap_nuclei_zap_are_eligible_but_not_default(self):
        for tool_id in ("nmap", "nuclei", "zap", "burp_dast"):
            assert tool_id in EXTERNAL_TARGET_ELIGIBLE_TOOL_IDS
            assert tool_id not in DEFAULT_EXTERNAL_TARGET_ALLOWED_TOOLS

    def test_052_scope_never_mutated(self):
        scope = _external_scope()
        original = dict(scope)
        validate_authorized_external_target_scope(
            target="https://security-test.example.com/", scope=scope, operator_scope_acknowledged=True,
        )
        assert scope == original

    def test_053_returns_new_dict_not_reusing_scope_object(self):
        scope = _external_scope()
        result = validate_authorized_external_target_scope(
            target="https://security-test.example.com/", scope=scope, operator_scope_acknowledged=True,
        )
        assert result["allowed_tools"] is not scope["allowed_tools"]
