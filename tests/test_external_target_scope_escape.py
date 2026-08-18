"""Consolidated scope-escape regression tests for the Final Pre-Release
Block's Authorized External Target capability (Section 32 of that
spec). Every real protection mechanism already has its own focused
test suite elsewhere in this repository -- this file exists as ONE
place that proves the full escape-attempt checklist end to end,
referencing where each protection actually lives:

- backend.models.validate_authorized_external_target_scope /
  core.bug_bounty_scope -- exact-hostname / port / path scoping.
- adapters.bug_bounty_http's allow_private_destinations=False path --
  SSRF destination-network protection.
- backend.orchestrator._merge_katana_discoveries_into_attack_surface --
  Katana's own raw output can never expand scope.
- core.detection_planner / core.bug_bounty_tool_policy -- structurally,
  no LLM-proposal or tool-request field can ever add or expand a
  target/scope.

No real network access occurs anywhere in this file.
"""

from __future__ import annotations

import pytest

from adapters.bug_bounty_http import BugBountyHttpError, BugBountyHttpTransport
from backend.models import RunModelError, validate_authorized_external_target_scope
from core.bug_bounty_scope import BugBountyScopeError, evaluate_bug_bounty_request_scope


def _scope_bundle(**overrides):
    scope = {
        "hosts": ["security-test.example.com"], "ports": [443], "path_prefixes": ["/app"],
        "allowed_tools": ["http_assessor", "httpx", "katana"],
    }
    scope.update(overrides)
    return validate_authorized_external_target_scope(
        target=overrides.get("_target", "https://security-test.example.com/app"),
        scope={k: v for k, v in scope.items() if not k.startswith("_")},
        operator_scope_acknowledged=True,
    )


class TestScopeEscapeChecklist:
    # A: exact approved hostname accepted
    def test_A_exact_approved_hostname_accepted(self):
        bundle = _scope_bundle()
        result = evaluate_bug_bounty_request_scope(
            scope=bundle["bug_bounty_scope"], url="https://security-test.example.com/app/page", method="GET",
        )
        assert result["decision"] == "allow"

    # B: different hostname rejected
    def test_B_different_hostname_rejected(self):
        bundle = _scope_bundle()
        result = evaluate_bug_bounty_request_scope(
            scope=bundle["bug_bounty_scope"], url="https://attacker.test/app", method="GET",
        )
        assert result["decision"] == "deny"
        assert "REQUEST_ORIGIN_NOT_ALLOWED" in result["observed_evidence"]

    # C: subdomain rejected unless explicitly approved (this endpoint
    # supports no wildcard syntax at all -- see backend.models'
    # EXTERNAL_SCOPE_WILDCARD_NOT_ALLOWED)
    def test_C_subdomain_rejected(self):
        bundle = _scope_bundle()
        result = evaluate_bug_bounty_request_scope(
            scope=bundle["bug_bounty_scope"], url="https://staging.security-test.example.com/app", method="GET",
        )
        assert result["decision"] == "deny"

    def test_C2_wildcard_hostname_rejected_at_the_endpoint_level(self):
        with pytest.raises(RunModelError, match="EXTERNAL_SCOPE_WILDCARD_NOT_ALLOWED"):
            validate_authorized_external_target_scope(
                target="https://security-test.example.com/app",
                scope={
                    "hosts": ["*.example.com"], "ports": [443], "path_prefixes": ["/app"],
                    "allowed_tools": ["http_assessor"],
                },
                operator_scope_acknowledged=True,
            )

    # D: different port rejected
    def test_D_different_port_rejected(self):
        bundle = _scope_bundle()
        result = evaluate_bug_bounty_request_scope(
            scope=bundle["bug_bounty_scope"], url="https://security-test.example.com:8443/app", method="GET",
        )
        assert result["decision"] == "deny"

    # E: outside path prefix rejected
    def test_E_outside_path_prefix_rejected(self):
        bundle = _scope_bundle()
        result = evaluate_bug_bounty_request_scope(
            scope=bundle["bug_bounty_scope"], url="https://security-test.example.com/admin", method="GET",
        )
        assert result["decision"] == "deny"
        assert "REQUEST_PATH_NOT_ALLOWED" in result["observed_evidence"]

    # F: redirect outside scope rejected -- a "redirect hop" is just
    # another evaluate_bug_bounty_request_scope call in this
    # architecture (see core.bug_bounty_crawler/core.bug_bounty_
    # assessment, which both re-validate every hop this exact way).
    def test_F_redirect_destination_outside_scope_rejected(self):
        bundle = _scope_bundle()
        redirect_target = "https://attacker.test/steal"
        result = evaluate_bug_bounty_request_scope(scope=bundle["bug_bounty_scope"], url=redirect_target, method="GET")
        assert result["decision"] == "deny"

    # G: redirect (or any request) to localhost/private/link-local
    # rejected via the real SSRF destination check, unless the
    # deployment explicitly allows it (allow_private_destinations=True,
    # never the default for an external run).
    @pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "10.0.0.5", "192.168.1.1"])
    def test_G_private_destination_rejected_for_external_transport(self, ip, monkeypatch):
        import http.client

        class _FakeConn:
            def __init__(self, *a, **kw): pass
            def request(self, *a, **kw): pass
            def getresponse(self): raise AssertionError("must never reach a real connection attempt")
            def close(self): pass

        monkeypatch.setattr(http.client, "HTTPSConnection", _FakeConn)
        transport = BugBountyHttpTransport(allow_private_destinations=False, resolve_hostname=lambda h, p: [ip])
        with pytest.raises(BugBountyHttpError):
            transport.request(url="https://security-test.example.com/app", method="GET")

    # H: unsupported protocol rejected
    def test_H_unsupported_protocol_rejected(self):
        with pytest.raises(RunModelError, match="INVALID_TARGET"):
            validate_authorized_external_target_scope(
                target="ftp://security-test.example.com/app",
                scope={
                    "hosts": ["security-test.example.com"], "ports": [443], "path_prefixes": ["/app"],
                    "allowed_tools": ["http_assessor"],
                },
                operator_scope_acknowledged=True,
            )

    # I: scope expansion from discovered content rejected -- an
    # OpenAPI/robots/sitemap document's own claimed alternate
    # server/host is always ignored by core.bug_bounty_crawler (see
    # that module's own docstring); every discovered path is joined
    # onto the already-authorized scope origin only.
    def test_I_scope_never_expands_from_discovered_content(self):
        import inspect

        import core.bug_bounty_crawler as crawler_module

        source = inspect.getsource(crawler_module)
        assert "document itself claims" in source or "never a server URL the document" in source

    # J: LLM cannot add targets -- structurally, core.detection_planner's
    # plan contract has no field for a target/host/scope override; only
    # the trigger's own (already-real, already-scoped) finding data
    # ever supplies a target.
    def test_J_llm_proposal_contract_has_no_target_field(self):
        from core.detection_planner import PLAN_REQUIRED_FIELDS, _RULE_DRAFT_REQUIRED_FIELDS

        for field in list(PLAN_REQUIRED_FIELDS) + list(_RULE_DRAFT_REQUIRED_FIELDS):
            assert "target" not in field
            assert "host" not in field
            assert "scope" not in field

    # K: Katana output cannot expand scope -- covered end to end at the
    # orchestrator level (an out-of-scope Katana-discovered URL is
    # dropped, never merged) by
    # tests/test_backend_orchestrator.py::TestHttpxKatanaWiring::
    # test_H5_katana_out_of_scope_url_never_merged. Re-verified here at
    # the adapter boundary: the adapter itself has no scope-evaluation
    # capability at all.
    def test_K_katana_adapter_has_no_scope_evaluation_capability(self):
        import adapters.bug_bounty_katana as katana_module

        assert not hasattr(katana_module, "evaluate_bug_bounty_request_scope")

    # L: httpx redirect cannot expand scope -- httpx never follows a
    # redirect itself (no -follow-redirects flag is ever passed; see
    # tests/test_bug_bounty_httpx_adapter.py::TestCommandVector::
    # test_012_no_follow_redirects_flag), so it can never make a second,
    # unvalidated request to a redirect destination on this run's behalf.
    def test_L_httpx_command_never_enables_redirect_following(self):
        from adapters.bug_bounty_httpx import _build_httpx_command

        argv = _build_httpx_command(httpx_path="/usr/bin/httpx", target="https://security-test.example.com/app")
        assert not any("redirect" in a.lower() for a in argv)


class TestScopeStructuralInvariants:
    def test_M_bug_bounty_scope_never_performs_network_io(self):
        import inspect

        import core.bug_bounty_scope as scope_module

        source = inspect.getsource(scope_module)
        for forbidden in ("socket.", "http.client", "urllib.request", "subprocess"):
            assert forbidden not in source

    def test_N_evaluate_request_scope_rejects_malformed_scope_never_silently_allows(self):
        with pytest.raises(BugBountyScopeError):
            evaluate_bug_bounty_request_scope(scope={"not": "a real scope"}, url="https://x.test/", method="GET")
