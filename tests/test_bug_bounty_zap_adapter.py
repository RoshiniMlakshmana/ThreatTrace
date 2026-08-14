"""Focused tests for adapters.bug_bounty_zap -- the real, bounded,
passive-only OWASP ZAP adapter (Block 15G-CD).

`_zap_api_call` (the module's own private ZAP REST API client) is
monkeypatched in every test -- this file never talks to a real ZAP
daemon, and never performs a real scan.
"""

from __future__ import annotations

import pytest

from adapters.bug_bounty_zap import (
    MAX_PROCESS_TIMEOUT_SECONDS,
    MAX_SPIDER_URLS,
    STATUS_VALUES,
    BugBountyZapAdapterError,
    _daemon_reachable_url,
    _original_form_url,
    _ZapUnavailable,
    run_zap_scan,
)


def _execution_config(**overrides):
    config = {"execution_config_version": "1", "process_timeout_seconds": 30, "max_output_bytes": 65536}
    config.update(overrides)
    return config


_SAMPLE_ALERT = {
    "pluginId": "10038",
    "alert": "Content Security Policy (CSP) Header Not Set",
    "risk": "Medium",
    "confidence": "High",
    "url": "http://localhost:3000/",
    "param": "",
    "method": "GET",
    "cweid": "693",
    "evidence": "",
}


def _make_zap_api(*, version="2.15.0", mode="safe", spider_scan_id="1", spider_progress="100",
                   spider_results=None, pscan_remaining="0", alerts=None, num_messages=3,
                   fail_on=None, unreachable=False):
    spider_results = spider_results if spider_results is not None else []
    alerts = alerts if alerts is not None else [_SAMPLE_ALERT]
    calls = []

    def fake(path, params, *, timeout):
        calls.append((path, dict(params)))
        if unreachable:
            raise _ZapUnavailable("connection refused")
        if fail_on and path == fail_on:
            raise _ZapUnavailable("simulated failure")

        if path == "/JSON/core/view/version/":
            return {"version": version}
        if path == "/JSON/core/action/setMode/":
            return {"Result": "OK"}
        if path == "/JSON/core/view/mode/":
            return {"mode": mode}
        if path == "/JSON/core/action/accessUrl/":
            return {"Result": "OK"}
        if path == "/JSON/spider/action/scan/":
            return {"scan": spider_scan_id}
        if path == "/JSON/spider/view/status/":
            return {"status": spider_progress}
        if path == "/JSON/spider/view/results/":
            return {"results": spider_results}
        if path == "/JSON/pscan/view/recordsToScan/":
            return {"recordsToScan": pscan_remaining}
        if path == "/JSON/core/view/alerts/":
            return {"alerts": alerts}
        if path == "/JSON/core/view/numberOfMessages/":
            return {"numberOfMessages": num_messages}
        raise AssertionError(f"unexpected ZAP API call: {path}")

    return fake, calls


# ---------------------------------------------------------------------------
# Runtime discovery / unavailability
# ---------------------------------------------------------------------------


class TestRuntimeDiscovery:
    def test_001_unreachable_daemon_reports_unavailable(self, monkeypatch):
        fake, _ = _make_zap_api(unreachable=True)
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "unavailable"
        assert result["execution_performed"] is False

    def test_002_reachable_daemon_proceeds(self, monkeypatch):
        fake, _ = _make_zap_api()
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "completed"
        assert result["runtime_version"] == "2.15.0"

    def test_003_mode_not_confirmed_safe_reports_failed(self, monkeypatch):
        fake, _ = _make_zap_api(mode="protect")
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "failed"
        assert "safe mode" in result["error_detail"]
        assert result["execution_performed"] is True

    def test_004_failure_mid_scan_reports_failed(self, monkeypatch):
        fake, _ = _make_zap_api(fail_on="/JSON/core/action/accessUrl/")
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] == "failed"
        assert result["execution_performed"] is True


# ---------------------------------------------------------------------------
# Safe-mode enforcement
# ---------------------------------------------------------------------------


class TestSafeModeEnforcement:
    def test_005_set_mode_called_before_anything_else(self, monkeypatch):
        fake, calls = _make_zap_api()
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        paths = [call[0] for call in calls]
        assert "/JSON/core/action/setMode/" in paths
        assert paths.index("/JSON/core/action/setMode/") < paths.index("/JSON/core/action/accessUrl/")

    def test_006_set_mode_argument_is_always_safe(self, monkeypatch):
        fake, calls = _make_zap_api()
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        set_mode_calls = [call for call in calls if call[0] == "/JSON/core/action/setMode/"]
        assert set_mode_calls[0][1]["mode"] == "safe"

    def test_007_no_active_scan_endpoint_ever_called(self, monkeypatch):
        fake, calls = _make_zap_api()
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        paths = [call[0] for call in calls]
        assert not any("ascan" in path.lower() for path in paths)

    def test_008_no_form_submission_params_ever_sent(self, monkeypatch):
        fake, calls = _make_zap_api()
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        for _, params in calls:
            assert "postForm" not in params
            assert "processForm" not in params

    def test_009_capability_always_passive_only(self, monkeypatch):
        fake, _ = _make_zap_api()
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["capability"] == "passive_only"


# ---------------------------------------------------------------------------
# Scope / same-origin enforcement
# ---------------------------------------------------------------------------


class TestScopeBoundary:
    def test_010_no_spider_step_urls_visited_is_target_only(self, monkeypatch):
        # ZAP's own safe mode refuses spider operations without an
        # established Context/scope (see module docstring) -- this
        # checkpoint never attempts one, so exactly the one approved
        # target is ever visited, never anything discovered by crawling.
        fake, calls = _make_zap_api()
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["urls_visited"] == ["http://localhost:3000/"]
        assert not any("spider" in call[0] for call in calls)

    def test_011_bounded_url_count_trivially_satisfied(self, monkeypatch):
        fake, _ = _make_zap_api()
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert len(result["urls_visited"]) <= MAX_SPIDER_URLS

    def test_012_non_http_target_rejected(self):
        with pytest.raises(BugBountyZapAdapterError):
            run_zap_scan(target="ftp://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())

    def test_013_blank_target_rejected(self):
        with pytest.raises(BugBountyZapAdapterError):
            run_zap_scan(target="   ", request_id="REQ-1", execution_config=_execution_config())

    def test_014_no_hostname_rejected(self):
        with pytest.raises(BugBountyZapAdapterError):
            run_zap_scan(target="http:///path", request_id="REQ-1", execution_config=_execution_config())


# ---------------------------------------------------------------------------
# Alert normalization / sanitized output
# ---------------------------------------------------------------------------


class TestAlertNormalization:
    def test_015_alert_fields_normalized(self, monkeypatch):
        fake, _ = _make_zap_api()
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        obs = result["observations"][0]
        assert obs["tool_id"] == "zap"
        assert obs["observation_type"] == "dast_observation"
        assert obs["rule_id"] == "10038"
        assert obs["title"] == "Content Security Policy (CSP) Header Not Set"
        assert obs["risk"] == "Medium"
        assert obs["confidence"] == "High"
        assert obs["url"] == "http://localhost:3000/"
        assert obs["method"] == "GET"
        assert obs["cwe"] == "CWE-693"
        assert obs["owasp_category"] is None
        assert obs["evidence_reference"].startswith("zap_alert_sha256:")  # per-alert digest, distinct from batch
        assert obs["source_tool_metadata"] == {"plugin_id": "10038"}

    def test_016_cweid_negative_one_maps_to_null(self, monkeypatch):
        alert = dict(_SAMPLE_ALERT, cweid="-1")
        fake, _ = _make_zap_api(alerts=[alert])
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["observations"][0]["cwe"] is None

    def test_017_sensitive_evidence_redacted(self, monkeypatch):
        alert = dict(_SAMPLE_ALERT, evidence="Authorization: Bearer secret-token-123")
        fake, _ = _make_zap_api(alerts=[alert])
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["observations"][0]["sanitized_evidence"] == "[REDACTED]"

    def test_018_no_raw_response_body_stored(self, monkeypatch):
        alert = dict(_SAMPLE_ALERT, evidence="x" * 5000)
        fake, _ = _make_zap_api(alerts=[alert])
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert len(result["observations"][0]["sanitized_evidence"]) < 5000

    def test_019_multiple_alerts_all_normalized(self, monkeypatch):
        alerts = [_SAMPLE_ALERT, dict(_SAMPLE_ALERT, pluginId="10063", alert="Missing X-Content-Type-Options")]
        fake, _ = _make_zap_api(alerts=alerts)
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert len(result["observations"]) == 2

    def test_020_no_credential_like_top_level_fields(self, monkeypatch):
        fake, _ = _make_zap_api()
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        forbidden = {"password", "authorization", "cookie", "api_key", "token", "secret"}
        assert forbidden.isdisjoint(set(result.keys()))


# ---------------------------------------------------------------------------
# Timeout / output bounds
# ---------------------------------------------------------------------------


class TestTimeoutAndOutputBounds:
    def test_021_pscan_never_drains_reports_timeout(self, monkeypatch):
        fake, _ = _make_zap_api(pscan_remaining="5")
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(
            target="http://localhost:3000/", request_id="REQ-1",
            execution_config=_execution_config(process_timeout_seconds=1),
        )
        assert result["status"] == "timeout"
        assert result["execution_performed"] is True

    def test_022_output_size_limit_truncates(self, monkeypatch):
        many_alerts = [dict(_SAMPLE_ALERT, pluginId=str(i)) for i in range(500)]
        fake, _ = _make_zap_api(alerts=many_alerts)
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(
            target="http://localhost:3000/", request_id="REQ-1",
            execution_config=_execution_config(max_output_bytes=200),
        )
        assert result["output_truncated"] is True

    def test_023_execution_config_timeout_ceiling_enforced(self):
        with pytest.raises(BugBountyZapAdapterError):
            run_zap_scan(
                target="http://localhost:3000/", request_id="REQ-1",
                execution_config=_execution_config(process_timeout_seconds=MAX_PROCESS_TIMEOUT_SECONDS + 1),
            )

    def test_024_execution_config_wrong_shape_rejected(self):
        with pytest.raises(BugBountyZapAdapterError):
            run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config={"bad": "shape"})

    def test_025_execution_config_extra_field_rejected(self):
        bad = _execution_config()
        bad["raw_command"] = "rm -rf /"
        with pytest.raises(BugBountyZapAdapterError):
            run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=bad)


# ---------------------------------------------------------------------------
# Output contract / determinism
# ---------------------------------------------------------------------------


class TestOutputContract:
    def test_026_tool_id_always_zap(self, monkeypatch):
        fake, _ = _make_zap_api(unreachable=True)
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["tool_id"] == "zap"

    def test_027_status_always_in_fixed_vocabulary(self, monkeypatch):
        fake, _ = _make_zap_api(unreachable=True)
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] in STATUS_VALUES

    def test_028_request_id_echoed(self, monkeypatch):
        fake, _ = _make_zap_api(unreachable=True)
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-XYZ", execution_config=_execution_config())
        assert result["request_id"] == "REQ-XYZ"

    def test_029_requests_performed_parsed_as_int(self, monkeypatch):
        fake, _ = _make_zap_api(num_messages=7)
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["requests_performed"] == 7

    def test_030_evidence_references_present_for_completed_scan(self, monkeypatch):
        fake, _ = _make_zap_api()
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert len(result["evidence_references"]) == 1
        assert result["evidence_references"][0].startswith("zap_alerts_sha256:")

    def test_030b_batch_and_per_alert_digest_prefixes_are_distinct(self, monkeypatch):
        fake, _ = _make_zap_api()
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["evidence_references"][0].startswith("zap_alerts_sha256:")
        assert result["observations"][0]["evidence_reference"].startswith("zap_alert_sha256:")

    def test_031_exact_result_contract_fields(self, monkeypatch):
        fake, _ = _make_zap_api()
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert set(result.keys()) == {
            "tool_result_version", "tool_id", "request_id", "target", "status", "capability",
            "runtime_version", "mode", "urls_visited", "requests_performed", "runtime_duration_seconds",
            "observations", "evidence_references", "output_truncated", "error_detail", "execution_performed",
        }

    def test_032_execution_performed_false_when_unavailable(self, monkeypatch):
        fake, _ = _make_zap_api(unreachable=True)
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["execution_performed"] is False


# ---------------------------------------------------------------------------
# Docker host-alias routing (localhost -> host.docker.internal), the real
# integration issue discovered validating this adapter against a real
# local ZAP daemon container.
# ---------------------------------------------------------------------------


class TestDaemonHostAliasRouting:
    def test_033_localhost_rewritten_to_host_docker_internal(self):
        assert _daemon_reachable_url("http://localhost:3000/") == "http://host.docker.internal:3000/"

    def test_034_127_0_0_1_rewritten_to_host_docker_internal(self):
        assert _daemon_reachable_url("http://127.0.0.1:3000/") == "http://host.docker.internal:3000/"

    def test_035_non_loopback_host_untouched(self):
        assert _daemon_reachable_url("http://example.internal:3000/") == "http://example.internal:3000/"

    def test_036_original_form_reverses_the_alias(self):
        assert _original_form_url(
            "http://host.docker.internal:3000/admin", original_hostname="localhost",
        ) == "http://localhost:3000/admin"

    def test_037_original_form_is_a_noop_for_non_alias_host(self):
        assert _original_form_url(
            "http://example.internal:3000/", original_hostname="localhost",
        ) == "http://example.internal:3000/"

    def test_038_reported_target_never_shows_internal_routing_name(self, monkeypatch):
        fake, _ = _make_zap_api()
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        result = run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert "host.docker.internal" not in result["target"]
        assert all("host.docker.internal" not in url for url in result["urls_visited"])

    def test_039_daemon_receives_the_alias_form_not_localhost(self, monkeypatch):
        fake, calls = _make_zap_api()
        monkeypatch.setattr("adapters.bug_bounty_zap._zap_api_call", fake)
        run_zap_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        access_url_calls = [call for call in calls if call[0] == "/JSON/core/action/accessUrl/"]
        assert access_url_calls[0][1]["url"] == "http://host.docker.internal:3000/"
