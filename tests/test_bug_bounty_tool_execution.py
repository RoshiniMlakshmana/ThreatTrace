"""Tests for core.bug_bounty_tool_execution -- the single execution
boundary for the Bug Bounty Nmap/Nuclei adapters (Block 15G-B).

`run_nmap_scan`/`run_nuclei_scan` are monkeypatched at their
`core.bug_bounty_tool_execution` import site in every test -- this file
never performs a real external scan, and asserts that no subprocess is
launched whenever execution should be blocked.
"""

from __future__ import annotations

import pytest

from core.bug_bounty_tool_execution import (
    TOOL_EXECUTION_VERSION,
    BugBountyToolExecutionError,
    execute_bug_bounty_tool,
)
from core.security_governor import evaluate_security_governor_event


def _permissions(**overrides):
    permissions = {
        "permission_version": "1",
        "target_origin": "http://localhost:3000",
        "allowed_hosts": ["localhost"],
        "allowed_ports": [3000],
        "allowed_paths": ["/"],
        "excluded_paths": [],
        "testing_profile": "recon",
        "allowed_tools": ["http_assessor", "nmap", "nuclei"],
        "authenticated_testing_allowed": False,
        "controlled_validation_allowed": False,
        "max_requests": 12,
        "human_approval_state": "not_required",
    }
    permissions.update(overrides)
    return permissions


def _tool_request(**overrides):
    request = {
        "request_version": "1",
        "request_id": "REQ-1",
        "tool_id": "nmap",
        "purpose": "Confirm the local Juice Shop service exposure.",
        "target": "localhost",
        "ports": [3000],
        "paths": [],
        "testing_mode": "recon",
        "authentication_requested": False,
        "controlled_validation_requested": False,
    }
    request.update(overrides)
    return request


def _governor_result(**overrides):
    result = {
        "governor_version": "1",
        "decision": "allow",
        "reason_codes": [],
        "actor_role": "bug_bounty",
        "action_class": "execution_request",
        "human_review_required": False,
        "mutation_freeze_recommended": False,
        "execution_allowed": True,
        "observable_only": True,
        "execution_performed": False,
    }
    result.update(overrides)
    return result


def _execution_config(**overrides):
    config = {"execution_config_version": "1", "process_timeout_seconds": 30, "max_output_bytes": 65536}
    config.update(overrides)
    return config


def _fake_nmap_result(**overrides):
    result = {
        "tool_result_version": "1", "tool_id": "nmap", "request_id": "REQ-1", "target": "localhost",
        "status": "completed", "observations": [], "evidence_references": [], "network_requests_performed": None,
        "output_truncated": False, "error_detail": None, "execution_performed": True,
    }
    result.update(overrides)
    return result


# ---------------------------------------------------------------------------
# Governor result / execution_config structural validation
# ---------------------------------------------------------------------------


class TestStructuralValidation:
    def test_001_missing_governor_field_raises(self):
        bad = _governor_result()
        del bad["decision"]
        with pytest.raises(BugBountyToolExecutionError):
            execute_bug_bounty_tool(
                permissions=_permissions(), tool_request=_tool_request(), governor_result=bad,
                execution_config=_execution_config(),
            )

    def test_002_extra_governor_field_raises(self):
        bad = _governor_result(unexpected="x")
        with pytest.raises(BugBountyToolExecutionError):
            execute_bug_bounty_tool(
                permissions=_permissions(), tool_request=_tool_request(), governor_result=bad,
                execution_config=_execution_config(),
            )

    def test_003_invalid_governor_decision_raises(self):
        bad = _governor_result(decision="maybe")
        with pytest.raises(BugBountyToolExecutionError):
            execute_bug_bounty_tool(
                permissions=_permissions(), tool_request=_tool_request(), governor_result=bad,
                execution_config=_execution_config(),
            )

    def test_004_non_bool_execution_allowed_raises(self):
        bad = _governor_result(execution_allowed="yes")
        with pytest.raises(BugBountyToolExecutionError):
            execute_bug_bounty_tool(
                permissions=_permissions(), tool_request=_tool_request(), governor_result=bad,
                execution_config=_execution_config(),
            )

    def test_005_execution_config_wrong_shape_raises(self):
        with pytest.raises(BugBountyToolExecutionError):
            execute_bug_bounty_tool(
                permissions=_permissions(), tool_request=_tool_request(), governor_result=_governor_result(),
                execution_config={"bad": "shape"},
            )

    def test_006_execution_config_raw_command_field_raises(self):
        bad = _execution_config()
        bad["raw_command"] = "rm -rf /"
        with pytest.raises(BugBountyToolExecutionError):
            execute_bug_bounty_tool(
                permissions=_permissions(), tool_request=_tool_request(), governor_result=_governor_result(),
                execution_config=bad,
            )

    def test_007_invalid_permissions_wraps_policy_error(self):
        bad_permissions = _permissions()
        del bad_permissions["max_requests"]
        with pytest.raises(BugBountyToolExecutionError):
            execute_bug_bounty_tool(
                permissions=bad_permissions, tool_request=_tool_request(), governor_result=_governor_result(),
                execution_config=_execution_config(),
            )

    def test_008_invalid_tool_request_wraps_policy_error(self):
        bad_request = _tool_request()
        bad_request["shell_command"] = "rm -rf /"
        with pytest.raises(BugBountyToolExecutionError):
            execute_bug_bounty_tool(
                permissions=_permissions(), tool_request=bad_request, governor_result=_governor_result(),
                execution_config=_execution_config(),
            )


# ---------------------------------------------------------------------------
# Policy re-evaluation -- never trusts a caller-supplied boolean
# ---------------------------------------------------------------------------


class TestPolicyReEvaluation:
    def test_009_tool_permission_is_actually_reevaluated(self, monkeypatch):
        called = {"count": 0}
        import core.bug_bounty_tool_execution as execution_module
        real_evaluate = execution_module.evaluate_tool_permission

        def spy(**kwargs):
            called["count"] += 1
            return real_evaluate(**kwargs)

        monkeypatch.setattr(execution_module, "evaluate_tool_permission", spy)
        monkeypatch.setattr(execution_module, "run_nmap_scan", lambda **kw: _fake_nmap_result())
        execute_bug_bounty_tool(
            permissions=_permissions(), tool_request=_tool_request(), governor_result=_governor_result(),
            execution_config=_execution_config(),
        )
        assert called["count"] == 1

    def test_010_analyst_denied_blocks_and_no_subprocess(self, monkeypatch):
        import core.bug_bounty_tool_execution as execution_module
        spy = {"called": False}
        monkeypatch.setattr(execution_module, "run_nmap_scan", lambda **kw: spy.update(called=True))

        permissions = _permissions(allowed_tools=["http_assessor"])
        result = execute_bug_bounty_tool(
            permissions=permissions, tool_request=_tool_request(), governor_result=_governor_result(),
            execution_config=_execution_config(),
        )
        assert result["execution_permitted"] is False
        assert result["execution_blocked_reason"] == "POLICY_DENIED"
        assert spy["called"] is False
        assert result["execution_performed"] is False

    def test_011_profile_denied_blocks_and_no_subprocess(self, monkeypatch):
        import core.bug_bounty_tool_execution as execution_module
        spy = {"called": False}
        monkeypatch.setattr(execution_module, "run_nmap_scan", lambda **kw: spy.update(called=True))

        permissions = _permissions(testing_profile="passive", allowed_tools=["http_assessor", "nmap"])
        result = execute_bug_bounty_tool(
            permissions=permissions, tool_request=_tool_request(), governor_result=_governor_result(),
            execution_config=_execution_config(),
        )
        assert result["execution_permitted"] is False
        assert result["execution_blocked_reason"] == "POLICY_DENIED"
        assert spy["called"] is False

    def test_012_adapter_unavailable_tool_blocks_and_no_subprocess(self, monkeypatch):
        # authenticated_testing has no adapter yet (Block 15G-CD
        # implemented nmap/nuclei/zap/burp_dast only).
        import core.bug_bounty_tool_execution as execution_module
        spy = {"called": False}
        monkeypatch.setattr(execution_module, "run_nmap_scan", lambda **kw: spy.update(called=True))
        monkeypatch.setattr(execution_module, "run_nuclei_scan", lambda **kw: spy.update(called=True))

        permissions = _permissions(
            testing_profile="authenticated", allowed_tools=["http_assessor", "authenticated_testing"],
            authenticated_testing_allowed=True,
        )
        request = _tool_request(tool_id="authenticated_testing", testing_mode="authenticated", ports=[])
        result = execute_bug_bounty_tool(
            permissions=permissions, tool_request=request, governor_result=_governor_result(),
            execution_config=_execution_config(),
        )
        assert result["execution_permitted"] is False
        assert result["execution_blocked_reason"] == "POLICY_DENIED"
        assert spy["called"] is False


# ---------------------------------------------------------------------------
# Governor gate
# ---------------------------------------------------------------------------


class TestGovernorGate:
    @pytest.mark.parametrize("decision", ["block", "freeze", "require_review"])
    def test_013_governor_blocking_decisions_prevent_execution(self, monkeypatch, decision):
        import core.bug_bounty_tool_execution as execution_module
        spy = {"called": False}
        monkeypatch.setattr(execution_module, "run_nmap_scan", lambda **kw: spy.update(called=True))

        governor_result = _governor_result(decision=decision, execution_allowed=False)
        result = execute_bug_bounty_tool(
            permissions=_permissions(), tool_request=_tool_request(), governor_result=governor_result,
            execution_config=_execution_config(),
        )
        assert result["execution_permitted"] is False
        assert result["execution_blocked_reason"] == "GOVERNOR_DENIED"
        assert spy["called"] is False
        assert result["governor_decision"] == decision

    def test_014_governor_warn_without_execution_allowed_prevents_execution(self, monkeypatch):
        import core.bug_bounty_tool_execution as execution_module
        spy = {"called": False}
        monkeypatch.setattr(execution_module, "run_nmap_scan", lambda **kw: spy.update(called=True))

        governor_result = _governor_result(decision="warn", execution_allowed=False)
        result = execute_bug_bounty_tool(
            permissions=_permissions(), tool_request=_tool_request(), governor_result=governor_result,
            execution_config=_execution_config(),
        )
        assert result["execution_permitted"] is False
        assert result["execution_blocked_reason"] == "GOVERNOR_DENIED"
        assert spy["called"] is False

    def test_015_governor_allow_plus_policy_allow_permits_execution(self, monkeypatch):
        import core.bug_bounty_tool_execution as execution_module
        monkeypatch.setattr(execution_module, "run_nmap_scan", lambda **kw: _fake_nmap_result())

        result = execute_bug_bounty_tool(
            permissions=_permissions(), tool_request=_tool_request(), governor_result=_governor_result(),
            execution_config=_execution_config(),
        )
        assert result["execution_permitted"] is True
        assert result["execution_blocked_reason"] is None
        assert result["tool_result"] is not None

    def test_016_governor_decision_never_synthesized_missing_field_rejected(self):
        # There is no default/fallback governor_result -- omitting it
        # entirely is a TypeError (keyword-only, required parameter).
        with pytest.raises(TypeError):
            execute_bug_bounty_tool(
                permissions=_permissions(), tool_request=_tool_request(), execution_config=_execution_config(),
            )


# ---------------------------------------------------------------------------
# Closed adapter registry / unknown tool
# ---------------------------------------------------------------------------


class TestClosedAdapterRegistry:
    def test_017_registry_contains_only_nmap_nuclei_zap_burp_dast(self):
        import core.bug_bounty_tool_execution as execution_module
        assert set(execution_module._ADAPTER_REGISTRY.keys()) == {"nmap", "nuclei", "zap", "burp_dast"}

    def test_018_http_assessor_not_registered_reports_no_adapter_registered(self, monkeypatch):
        import core.bug_bounty_tool_execution as execution_module
        spy = {"called": False}
        monkeypatch.setattr(execution_module, "run_nmap_scan", lambda **kw: spy.update(called=True))
        monkeypatch.setattr(execution_module, "run_nuclei_scan", lambda **kw: spy.update(called=True))

        permissions = _permissions(testing_profile="passive", allowed_tools=["http_assessor"])
        request = _tool_request(tool_id="http_assessor", testing_mode="passive", target="http://localhost:3000/", ports=[], paths=["/"])
        result = execute_bug_bounty_tool(
            permissions=permissions, tool_request=request, governor_result=_governor_result(),
            execution_config=_execution_config(),
        )
        # http_assessor is fully policy-permitted (its own adapter exists
        # elsewhere) but this execution boundary deliberately does not
        # carry a registry entry for it.
        assert result["execution_permitted"] is False
        assert result["execution_blocked_reason"] == "NO_ADAPTER_REGISTERED"
        assert spy["called"] is False

    def test_019_registry_is_not_built_from_caller_input(self):
        import core.bug_bounty_tool_execution as execution_module
        # The registry is a MappingProxyType literal -- attempting to
        # add an entry must fail, proving it cannot be mutated at runtime
        # by any caller-controlled code path.
        with pytest.raises(TypeError):
            execution_module._ADAPTER_REGISTRY["metasploit"] = lambda **kw: None


# ---------------------------------------------------------------------------
# Adapter-level rejection (structural request violates an adapter's own
# additional scope rules, e.g. too many ports)
# ---------------------------------------------------------------------------


class TestAdapterRejection:
    def test_020_adapter_structural_rejection_reports_bounded_failure(self, monkeypatch):
        import core.bug_bounty_tool_execution as execution_module
        from adapters.bug_bounty_nmap import BugBountyNmapAdapterError

        def raising_adapter(**kwargs):
            raise BugBountyNmapAdapterError("INVALID_PORTS: too many")

        monkeypatch.setattr(execution_module, "run_nmap_scan", raising_adapter)
        result = execute_bug_bounty_tool(
            permissions=_permissions(), tool_request=_tool_request(), governor_result=_governor_result(),
            execution_config=_execution_config(),
        )
        assert result["execution_permitted"] is False
        assert result["execution_blocked_reason"] == "ADAPTER_REJECTED_REQUEST"
        assert result["tool_result"] is None


# ---------------------------------------------------------------------------
# execution_performed honesty
# ---------------------------------------------------------------------------


class TestExecutionPerformedHonesty:
    def test_021_execution_performed_true_when_adapter_ran(self, monkeypatch):
        import core.bug_bounty_tool_execution as execution_module
        monkeypatch.setattr(execution_module, "run_nmap_scan", lambda **kw: _fake_nmap_result(execution_performed=True))
        result = execute_bug_bounty_tool(
            permissions=_permissions(), tool_request=_tool_request(), governor_result=_governor_result(),
            execution_config=_execution_config(),
        )
        assert result["execution_performed"] is True

    def test_022_execution_performed_false_when_adapter_reports_tool_not_installed(self, monkeypatch):
        import core.bug_bounty_tool_execution as execution_module
        monkeypatch.setattr(
            execution_module, "run_nmap_scan",
            lambda **kw: _fake_nmap_result(status="tool_not_installed", execution_performed=False),
        )
        result = execute_bug_bounty_tool(
            permissions=_permissions(), tool_request=_tool_request(), governor_result=_governor_result(),
            execution_config=_execution_config(),
        )
        assert result["execution_performed"] is False

    def test_023_execution_performed_false_for_every_blocked_path(self, monkeypatch):
        import core.bug_bounty_tool_execution as execution_module
        monkeypatch.setattr(execution_module, "run_nmap_scan", lambda **kw: _fake_nmap_result())

        permissions = _permissions(allowed_tools=["http_assessor"])
        result = execute_bug_bounty_tool(
            permissions=permissions, tool_request=_tool_request(), governor_result=_governor_result(),
            execution_config=_execution_config(),
        )
        assert result["execution_performed"] is False


# ---------------------------------------------------------------------------
# Output contract / no raw command surface
# ---------------------------------------------------------------------------


class TestOutputContract:
    def test_024_exact_result_contract_fields(self, monkeypatch):
        import core.bug_bounty_tool_execution as execution_module
        monkeypatch.setattr(execution_module, "run_nmap_scan", lambda **kw: _fake_nmap_result())
        result = execute_bug_bounty_tool(
            permissions=_permissions(), tool_request=_tool_request(), governor_result=_governor_result(),
            execution_config=_execution_config(),
        )
        assert set(result.keys()) == {
            "tool_execution_version", "request_id", "tool_id", "execution_permitted",
            "execution_blocked_reason", "permission_result", "governor_decision", "tool_result",
            "execution_performed",
        }

    def test_025_tool_execution_version_is_one(self, monkeypatch):
        import core.bug_bounty_tool_execution as execution_module
        monkeypatch.setattr(execution_module, "run_nmap_scan", lambda **kw: _fake_nmap_result())
        result = execute_bug_bounty_tool(
            permissions=_permissions(), tool_request=_tool_request(), governor_result=_governor_result(),
            execution_config=_execution_config(),
        )
        assert result["tool_execution_version"] == TOOL_EXECUTION_VERSION == "1"

    def test_026_execution_config_has_no_raw_command_field_possible(self):
        # Structurally, the only three fields ever accepted are these --
        # asserted directly against the required-field tuple to guard
        # against any future accidental addition of a raw-command-like
        # field.
        import core.bug_bounty_tool_execution as execution_module
        assert set(execution_module._EXECUTION_CONFIG_REQUIRED_FIELDS) == {
            "execution_config_version", "process_timeout_seconds", "max_output_bytes",
        }

    def test_027_permissions_and_tool_request_never_mutated(self, monkeypatch):
        import core.bug_bounty_tool_execution as execution_module
        monkeypatch.setattr(execution_module, "run_nmap_scan", lambda **kw: _fake_nmap_result())
        import copy
        permissions = _permissions()
        request = _tool_request()
        permissions_snapshot = copy.deepcopy(permissions)
        request_snapshot = copy.deepcopy(request)
        execute_bug_bounty_tool(
            permissions=permissions, tool_request=request, governor_result=_governor_result(),
            execution_config=_execution_config(),
        )
        assert permissions == permissions_snapshot
        assert request == request_snapshot


# ---------------------------------------------------------------------------
# Block 15G-B.2: real end-to-end integration with the new
# "bug_bounty_assessment" Governor operational stage -- these two tests
# call the real evaluate_security_governor_event (not a hand-built dict)
# to prove the actual cross-module wiring works, not just the shape
# contract the tests above already cover.
# ---------------------------------------------------------------------------


def _real_bug_bounty_governor_event(**overrides):
    event = {
        "event_version": "1", "actor_role": "bug_bounty", "action_class": "execution_request",
        "current_stage": "bug_bounty_assessment", "required_role": "bug_bounty",
        "gateway_decision": "allow", "identity_decision": "allow", "mutation_freeze_active": False,
        "approval_state": "approved", "decision_binding_state": "valid", "scope_state": "within_scope",
        "source_truth_state": "unchanged", "remote_content_state": "not_present", "audit_state": "recorded",
        "prior_policy_denials": 0, "execution_requested": True,
    }
    event.update(overrides)
    return event


class TestRealGovernorIntegration:
    def test_028_real_bug_bounty_assessment_allow_plus_real_policy_allow_permits_adapter(self, monkeypatch):
        import core.bug_bounty_tool_execution as execution_module
        monkeypatch.setattr(execution_module, "run_nmap_scan", lambda **kw: _fake_nmap_result())

        real_governor_result = evaluate_security_governor_event(event=_real_bug_bounty_governor_event())
        assert real_governor_result["execution_allowed"] is True  # sanity on the Governor call itself

        result = execute_bug_bounty_tool(
            permissions=_permissions(), tool_request=_tool_request(), governor_result=real_governor_result,
            execution_config=_execution_config(),
        )
        assert result["execution_permitted"] is True
        assert result["execution_blocked_reason"] is None
        assert result["tool_result"] is not None

    def test_029_real_governor_block_still_prevents_adapter_invocation(self, monkeypatch):
        # Wrong role for this stage -- a real, honestly-evaluated block,
        # not a hand-built one. No source-of-truth shortcut was taken.
        import core.bug_bounty_tool_execution as execution_module
        spy = {"called": False}
        monkeypatch.setattr(execution_module, "run_nmap_scan", lambda **kw: spy.update(called=True))

        real_governor_result = evaluate_security_governor_event(
            event=_real_bug_bounty_governor_event(actor_role="red_team", required_role="red_team"),
        )
        assert real_governor_result["decision"] == "block"

        result = execute_bug_bounty_tool(
            permissions=_permissions(), tool_request=_tool_request(), governor_result=real_governor_result,
            execution_config=_execution_config(),
        )
        assert result["execution_permitted"] is False
        assert result["execution_blocked_reason"] == "GOVERNOR_DENIED"
        assert spy["called"] is False


# ---------------------------------------------------------------------------
# Block 15G-CD: zap/burp_dast registry entries.
# ---------------------------------------------------------------------------


def _fake_zap_result(**overrides):
    result = {
        "tool_result_version": "1", "tool_id": "zap", "request_id": "REQ-1", "target": "http://localhost:3000/",
        "status": "completed", "capability": "passive_only", "runtime_version": "2.17.0", "mode": "safe",
        "urls_visited": ["http://localhost:3000/"], "requests_performed": 1, "runtime_duration_seconds": 0.5,
        "observations": [], "evidence_references": [], "output_truncated": False, "error_detail": None,
        "execution_performed": True,
    }
    result.update(overrides)
    return result


def _fake_burp_result(**overrides):
    result = {
        "tool_result_version": "1", "tool_id": "burp_dast", "request_id": "REQ-1", "target": "http://localhost:3000/",
        "adapter_status": "implemented", "runtime_status": "configured_external_runtime_required",
        "status": "not_evaluated", "source": None, "observations": [], "evidence_references": [],
        "network_requests_performed": None, "output_truncated": False, "error_detail": None,
        "execution_performed": False,
    }
    result.update(overrides)
    return result


class TestZapAndBurpRegistryEntries:
    def test_030_zap_permitted_execution_calls_zap_adapter(self, monkeypatch):
        import core.bug_bounty_tool_execution as execution_module
        monkeypatch.setattr(execution_module, "run_zap_scan", lambda **kw: _fake_zap_result())

        permissions = _permissions(testing_profile="safe_dast", allowed_tools=["http_assessor", "zap"])
        request = _tool_request(tool_id="zap", testing_mode="safe_dast", target="http://localhost:3000/", ports=[3000])
        result = execute_bug_bounty_tool(
            permissions=permissions, tool_request=request, governor_result=_governor_result(),
            execution_config=_execution_config(),
        )
        assert result["execution_permitted"] is True
        assert result["tool_result"]["tool_id"] == "zap"

    def test_031_burp_permitted_execution_calls_burp_adapter_honestly(self, monkeypatch):
        # burp_dast is policy-permitted (adapter implemented), but the
        # adapter itself honestly reports no runtime configured -- the
        # execution boundary must not paper over that.
        import core.bug_bounty_tool_execution as execution_module
        monkeypatch.setattr(execution_module, "run_burp_scan", lambda **kw: _fake_burp_result())

        permissions = _permissions(testing_profile="safe_dast", allowed_tools=["http_assessor", "burp_dast"])
        request = _tool_request(
            tool_id="burp_dast", testing_mode="safe_dast", target="http://localhost:3000/", ports=[3000],
        )
        result = execute_bug_bounty_tool(
            permissions=permissions, tool_request=request, governor_result=_governor_result(),
            execution_config=_execution_config(),
        )
        assert result["execution_permitted"] is True
        assert result["tool_result"]["runtime_status"] == "configured_external_runtime_required"
        assert result["tool_result"]["execution_performed"] is False
        assert result["execution_performed"] is False  # honestly propagated, never overridden to True

    def test_032_zap_governor_denied_never_calls_adapter(self, monkeypatch):
        import core.bug_bounty_tool_execution as execution_module
        spy = {"called": False}
        monkeypatch.setattr(execution_module, "run_zap_scan", lambda **kw: spy.update(called=True))

        permissions = _permissions(testing_profile="safe_dast", allowed_tools=["http_assessor", "zap"])
        request = _tool_request(tool_id="zap", testing_mode="safe_dast", target="http://localhost:3000/", ports=[3000])
        governor_result = _governor_result(decision="block", execution_allowed=False)
        result = execute_bug_bounty_tool(
            permissions=permissions, tool_request=request, governor_result=governor_result,
            execution_config=_execution_config(),
        )
        assert result["execution_permitted"] is False
        assert result["execution_blocked_reason"] == "GOVERNOR_DENIED"
        assert spy["called"] is False
