"""Focused tests for adapters.bug_bounty_burp -- the deterministic Burp
Suite DAST adapter boundary (Block 15G-CD).

No compatible Burp runtime exists in this development environment, so
`run_burp_scan`'s "reachable" path is exercised with `_check_burp_reachable`
monkeypatched; `import_burp_result` never performs I/O and is tested
directly against real (in-memory) structured input.
"""

from __future__ import annotations

import pytest

from adapters.bug_bounty_burp import (
    BURP_API_KEY_ENV_VAR,
    RUNTIME_STATUS_VALUES,
    STATUS_VALUES,
    BugBountyBurpAdapterError,
    import_burp_result,
    run_burp_scan,
)


def _execution_config(**overrides):
    config = {"execution_config_version": "1", "process_timeout_seconds": 30, "max_output_bytes": 65536}
    config.update(overrides)
    return config


_SAMPLE_ISSUE = {
    "issue_type": "5243392",
    "name": "Cross-site scripting (reflected)",
    "severity": "High",
    "confidence": "Firm",
    "url": "http://localhost:3000/search?q=x",
    "param": "q",
    "method": "GET",
    "cwe": "79",
    "detail": "The value of the q parameter is reflected in the response.",
}


@pytest.fixture(autouse=True)
def _no_burp_env(monkeypatch):
    monkeypatch.delenv(BURP_API_KEY_ENV_VAR, raising=False)


# ---------------------------------------------------------------------------
# run_burp_scan -- runtime discovery, never fabricated
# ---------------------------------------------------------------------------


class TestRuntimeDiscovery:
    def test_001_no_env_var_reports_configured_external_runtime_required(self):
        result = run_burp_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["runtime_status"] == "configured_external_runtime_required"
        assert result["status"] == "not_evaluated"
        assert result["execution_performed"] is False

    def test_002_no_env_var_never_attempts_network_call(self, monkeypatch):
        called = {"count": 0}

        def spy(host, port):
            called["count"] += 1
            return True

        monkeypatch.setattr("adapters.bug_bounty_burp._check_burp_reachable", spy)
        run_burp_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert called["count"] == 0

    def test_003_env_var_set_but_unreachable_reports_unavailable(self, monkeypatch):
        monkeypatch.setenv(BURP_API_KEY_ENV_VAR, "fake-key")
        monkeypatch.setattr("adapters.bug_bounty_burp._check_burp_reachable", lambda host, port: False)
        result = run_burp_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["runtime_status"] == "unavailable"
        assert result["status"] == "not_evaluated"
        assert result["execution_performed"] is False

    def test_004_env_var_set_and_reachable_reports_available_but_no_fabricated_scan(self, monkeypatch):
        monkeypatch.setenv(BURP_API_KEY_ENV_VAR, "fake-key")
        monkeypatch.setattr("adapters.bug_bounty_burp._check_burp_reachable", lambda host, port: True)
        result = run_burp_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["runtime_status"] == "available"
        assert result["status"] == "not_evaluated"
        assert result["execution_performed"] is False
        assert result["observations"] == []
        assert result["error_detail"] is not None

    def test_005_blank_env_var_treated_as_not_configured(self, monkeypatch):
        monkeypatch.setenv(BURP_API_KEY_ENV_VAR, "   ")
        result = run_burp_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["runtime_status"] == "configured_external_runtime_required"

    def test_006_adapter_status_always_implemented(self):
        result = run_burp_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["adapter_status"] == "implemented"

    def test_007_no_request_parameter_can_override_runtime_endpoint(self):
        import inspect
        signature = inspect.signature(run_burp_scan)
        assert set(signature.parameters) == {"target", "request_id", "execution_config"}


# ---------------------------------------------------------------------------
# run_burp_scan -- structural validation
# ---------------------------------------------------------------------------


class TestScanValidation:
    def test_008_non_http_target_rejected(self):
        with pytest.raises(BugBountyBurpAdapterError):
            run_burp_scan(target="ftp://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())

    def test_009_blank_request_id_rejected(self):
        with pytest.raises(BugBountyBurpAdapterError):
            run_burp_scan(target="http://localhost:3000/", request_id="  ", execution_config=_execution_config())

    def test_010_execution_config_wrong_shape_rejected(self):
        with pytest.raises(BugBountyBurpAdapterError):
            run_burp_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config={"bad": "shape"})

    def test_011_execution_config_extra_field_rejected(self):
        bad = _execution_config()
        bad["raw_command"] = "rm -rf /"
        with pytest.raises(BugBountyBurpAdapterError):
            run_burp_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=bad)

    def test_012_request_id_echoed(self):
        result = run_burp_scan(target="http://localhost:3000/", request_id="REQ-XYZ", execution_config=_execution_config())
        assert result["request_id"] == "REQ-XYZ"

    def test_013_tool_id_always_burp_dast(self):
        result = run_burp_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["tool_id"] == "burp_dast"

    def test_014_status_always_in_fixed_vocabulary(self):
        result = run_burp_scan(target="http://localhost:3000/", request_id="REQ-1", execution_config=_execution_config())
        assert result["status"] in STATUS_VALUES
        assert result["runtime_status"] in RUNTIME_STATUS_VALUES


# ---------------------------------------------------------------------------
# import_burp_result -- pure normalization, no I/O, no execution
# ---------------------------------------------------------------------------


class TestImportBurpResult:
    def test_015_valid_issue_normalized(self):
        result = import_burp_result(raw_result={"issues": [_SAMPLE_ISSUE]}, request_id="REQ-1")
        obs = result["observations"][0]
        assert obs["tool_id"] == "burp_dast"
        assert obs["observation_type"] == "dast_observation"
        assert obs["rule_id"] == "5243392"
        assert obs["title"] == "Cross-site scripting (reflected)"
        assert obs["risk"] == "High"
        assert obs["confidence"] == "Firm"
        assert obs["url"] == "http://localhost:3000/search?q=x"
        assert obs["path"] == "/search"
        assert obs["parameter"] == "q"
        assert obs["method"] == "GET"
        assert obs["cwe"] == "CWE-79"
        assert obs["owasp_category"] is None
        assert obs["evidence_reference"].startswith("burp_issue_sha256:")
        assert "reflected" in obs["sanitized_evidence"]

    def test_016_cwe_int_normalized(self):
        issue = dict(_SAMPLE_ISSUE, cwe=79)
        result = import_burp_result(raw_result={"issues": [issue]}, request_id="REQ-1")
        assert result["observations"][0]["cwe"] == "CWE-79"

    def test_017_empty_issues_yields_completed_with_no_observations(self):
        result = import_burp_result(raw_result={"issues": []}, request_id="REQ-1")
        assert result["status"] == "completed"
        assert result["observations"] == []
        assert result["evidence_references"] == []

    def test_018_missing_issues_field_rejected(self):
        with pytest.raises(BugBountyBurpAdapterError):
            import_burp_result(raw_result={}, request_id="REQ-1")

    def test_019_non_list_issues_rejected(self):
        with pytest.raises(BugBountyBurpAdapterError):
            import_burp_result(raw_result={"issues": "not-a-list"}, request_id="REQ-1")

    def test_020_non_mapping_issue_entry_rejected(self):
        with pytest.raises(BugBountyBurpAdapterError):
            import_burp_result(raw_result={"issues": ["not-a-mapping"]}, request_id="REQ-1")

    def test_021_sensitive_detail_redacted(self):
        issue = dict(_SAMPLE_ISSUE, detail="Authorization: Bearer secret-abc123")
        result = import_burp_result(raw_result={"issues": [issue]}, request_id="REQ-1")
        assert result["observations"][0]["sanitized_evidence"] == "[REDACTED]"

    def test_022_execution_performed_always_false(self):
        result = import_burp_result(raw_result={"issues": [_SAMPLE_ISSUE]}, request_id="REQ-1")
        assert result["execution_performed"] is False

    def test_023_runtime_status_available_source_imported(self):
        result = import_burp_result(raw_result={"issues": [_SAMPLE_ISSUE]}, request_id="REQ-1")
        assert result["runtime_status"] == "available"
        assert result["source"] == "imported_result"

    def test_024_target_optional_defaults_to_none(self):
        result = import_burp_result(raw_result={"issues": []}, request_id="REQ-1")
        assert result["target"] is None

    def test_025_target_echoed_when_supplied(self):
        result = import_burp_result(raw_result={"issues": []}, request_id="REQ-1", target="http://localhost:3000/")
        assert result["target"] == "http://localhost:3000/"

    def test_026_invalid_target_rejected(self):
        with pytest.raises(BugBountyBurpAdapterError):
            import_burp_result(raw_result={"issues": []}, request_id="REQ-1", target="not-a-url")

    def test_027_blank_request_id_rejected(self):
        with pytest.raises(BugBountyBurpAdapterError):
            import_burp_result(raw_result={"issues": []}, request_id="   ")

    def test_028_multiple_issues_all_normalized(self):
        issues = [_SAMPLE_ISSUE, dict(_SAMPLE_ISSUE, issue_type="1049088", name="SQL injection")]
        result = import_burp_result(raw_result={"issues": issues}, request_id="REQ-1")
        assert len(result["observations"]) == 2

    def test_029_unknown_extra_issue_fields_ignored_not_invented(self):
        issue = dict(_SAMPLE_ISSUE, some_random_field="should be ignored")
        result = import_burp_result(raw_result={"issues": [issue]}, request_id="REQ-1")
        obs = result["observations"][0]
        assert "some_random_field" not in obs
        assert "some_random_field" not in obs["source_tool_metadata"]

    def test_030_no_credential_like_top_level_fields(self):
        result = import_burp_result(raw_result={"issues": [_SAMPLE_ISSUE]}, request_id="REQ-1")
        forbidden = {"password", "authorization", "cookie", "api_key", "token", "secret"}
        assert forbidden.isdisjoint(set(result.keys()))

    def test_031_deterministic_given_same_input(self):
        first = import_burp_result(raw_result={"issues": [_SAMPLE_ISSUE]}, request_id="REQ-1")
        second = import_burp_result(raw_result={"issues": [_SAMPLE_ISSUE]}, request_id="REQ-1")
        assert first == second

    def test_032_exact_result_contract_fields(self):
        result = import_burp_result(raw_result={"issues": [_SAMPLE_ISSUE]}, request_id="REQ-1")
        assert set(result.keys()) == {
            "tool_result_version", "tool_id", "request_id", "target", "adapter_status", "runtime_status",
            "status", "source", "observations", "evidence_references", "network_requests_performed",
            "output_truncated", "error_detail", "execution_performed",
        }
