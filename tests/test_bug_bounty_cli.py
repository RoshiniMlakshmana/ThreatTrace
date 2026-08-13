"""Tests for core.bug_bounty_cli -- the human-invoked stdin/stdout JSON
adapter around the real Block 15A Bug Bounty assessment engine
(checkpoint B2).

NO real network access occurs anywhere in this file. Every test
monkeypatches `core.bug_bounty_cli._build_transport` with a fake,
in-memory transport factory -- the smallest possible seam -- so the real
`adapters.bug_bounty_http.BugBountyHttpTransport` is never constructed
during tests. Production security logic in `core.bug_bounty_scope`,
`core.bug_bounty_findings`, and `core.bug_bounty_assessment` is never
altered or bypassed for testability.
"""

from __future__ import annotations

import inspect
import json
from io import StringIO

import pytest

import core.bug_bounty_cli as bug_bounty_cli
from core.bug_bounty_assessment import run_bug_bounty_assessment
from core.bug_bounty_scope import create_bug_bounty_scope

_RESULT_FIELDS = {
    "assessment_version", "target", "testing_profile", "findings", "observed_evidence",
    "assessment_performed", "network_requests_performed", "human_approval_required", "execution_performed",
}


def _envelope(**overrides):
    envelope = {
        "operation": "assess",
        "target": "https://app.example.test/",
        "target_type": "web_application",
        "allowed_origins": ["https://app.example.test"],
        "allowed_paths": None,
        "excluded_paths": None,
        "testing_profile": "passive",
    }
    envelope.update(overrides)
    return envelope


def _response(*, status_code=200, headers=None, body_excerpt=None, redirect_location=None, url="https://app.example.test/"):
    return {
        "url": url,
        "status_code": status_code,
        "headers": headers or {},
        "body_excerpt": body_excerpt,
        "redirect_location": redirect_location,
        "request_performed": True,
    }


class FakeTransport:
    def __init__(self, handler=None, *, default=None, fail_always=False):
        self.calls = []
        self._handler = handler
        self._default = default or _response()
        self._fail_always = fail_always

    def request(self, *, url, method, headers=None):
        self.calls.append((url, method))
        if self._fail_always:
            raise RuntimeError("simulated transport failure")
        if self._handler is not None:
            result = self._handler(url=url, method=method)
            if result is not None:
                return result
        return dict(self._default, url=url)


def _clean_transport():
    def handler(*, url, method):
        if url == "https://app.example.test/" and method == "GET":
            return _response(status_code=200, headers={"Content-Type": "text/html"}, url=url)
        return _response(status_code=404, url=url)

    return FakeTransport(handler=handler)


def _install_transport(monkeypatch, transport):
    monkeypatch.setattr(bug_bounty_cli, "_build_transport", lambda: transport)


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = bug_bounty_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _assert_no_forbidden_content(rendered):
    forbidden = (
        "Traceback", "BugBountyScopeError", "BugBountyAssessmentError", "BugBountyHttpError",
        "ValueError", "RuntimeError", "KeyError", "AttributeError", "TypeError",
    )
    for text in forbidden:
        assert text not in rendered


# ---------------------------------------------------------------------------
# A/B/C. Valid assessments
# ---------------------------------------------------------------------------


class TestValidAssessments:
    def test_001_valid_passive_assessment_exits_zero(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, stderr = _run(json.dumps(_envelope(testing_profile="passive")))
        assert exit_code == 0
        assert stderr == ""
        assert json.loads(stdout)["testing_profile"] == "passive"

    def test_002_valid_safe_active_assessment_exits_zero(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, stderr = _run(json.dumps(_envelope(testing_profile="safe_active")))
        assert exit_code == 0
        assert stderr == ""
        assert json.loads(stdout)["testing_profile"] == "safe_active"

    def test_003_stdout_exactly_equals_direct_api_call(self, monkeypatch):
        transport_for_cli = _clean_transport()
        _install_transport(monkeypatch, transport_for_cli)
        envelope = _envelope()
        _, stdout, _ = _run(json.dumps(envelope))
        cli_result = json.loads(stdout)

        direct_scope = create_bug_bounty_scope(
            target=envelope["target"], target_type=envelope["target_type"],
            allowed_origins=envelope["allowed_origins"], allowed_paths=envelope["allowed_paths"],
            excluded_paths=envelope["excluded_paths"], testing_profile=envelope["testing_profile"],
        )
        direct_result = run_bug_bounty_assessment(scope=direct_scope, transport=_clean_transport())
        assert cli_result == direct_result

    def test_004_exact_eight_field_result(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        _, stdout, _ = _run(json.dumps(_envelope()))
        assert set(json.loads(stdout).keys()) == _RESULT_FIELDS

    def test_005_human_approval_required_always_true(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        _, stdout, _ = _run(json.dumps(_envelope()))
        assert json.loads(stdout)["human_approval_required"] is True

    def test_006_execution_performed_always_false(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        _, stdout, _ = _run(json.dumps(_envelope()))
        assert json.loads(stdout)["execution_performed"] is False

    def test_007_stdout_ends_with_single_newline(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        _, stdout, _ = _run(json.dumps(_envelope()))
        assert stdout.endswith("\n")
        assert stdout.count("\n") == 1

    def test_008_key_order_in_envelope_does_not_matter(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        envelope = _envelope()
        reordered_text = json.dumps(dict(reversed(list(envelope.items()))))
        exit_code, stdout, _ = _run(reordered_text)
        assert exit_code == 0
        assert json.loads(stdout)["target"] == envelope["target"]

    def test_009_findings_are_real_finding_shaped_records(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        _, stdout, _ = _run(json.dumps(_envelope()))
        result = json.loads(stdout)
        for finding in result["findings"]:
            assert "finding_version" in finding
            assert "evidence" in finding


# ---------------------------------------------------------------------------
# D/E/F/G/H. Envelope validation
# ---------------------------------------------------------------------------


class TestEnvelopeValidation:
    def test_010_malformed_json_exits_two(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, stderr = _run("{not valid json")
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("BUG_BOUNTY_VALIDATION_FAILED")

    def test_011_top_level_array_exits_two(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps(["assess"]))
        assert exit_code == 2
        assert stdout == ""

    def test_012_top_level_string_exits_two(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps("assess"))
        assert exit_code == 2
        assert stdout == ""

    def test_013_top_level_null_exits_two(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps(None))
        assert exit_code == 2
        assert stdout == ""

    def test_014_top_level_number_exits_two(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps(42))
        assert exit_code == 2
        assert stdout == ""

    def test_015_empty_stdin_exits_two(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run("")
        assert exit_code == 2
        assert stdout == ""

    @pytest.mark.parametrize("missing_key", [
        "operation", "target", "target_type", "allowed_origins", "allowed_paths", "excluded_paths", "testing_profile",
    ])
    def test_016_missing_each_required_key_exits_two(self, monkeypatch, missing_key):
        _install_transport(monkeypatch, _clean_transport())
        envelope = _envelope()
        del envelope[missing_key]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("BUG_BOUNTY_VALIDATION_FAILED")

    def test_017_extra_key_exits_two(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps(_envelope(extra_field="not allowed")))
        assert exit_code == 2
        assert stdout == ""

    def test_018_operation_not_assess_exits_two(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps(_envelope(operation="run")))
        assert exit_code == 2
        assert stdout == ""

    def test_019_blank_operation_exits_two(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps(_envelope(operation="")))
        assert exit_code == 2
        assert stdout == ""

    def test_020_null_operation_exits_two(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps(_envelope(operation=None)))
        assert exit_code == 2
        assert stdout == ""

    def test_021_empty_object_exits_two(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps({}))
        assert exit_code == 2
        assert stdout == ""

    def test_022_allowed_paths_key_required_even_though_value_may_be_null(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        envelope = _envelope()
        del envelope["allowed_paths"]
        exit_code, _, stderr = _run(json.dumps(envelope))
        assert exit_code == 2
        assert "allowed_paths" in stderr

    def test_023_excluded_paths_key_required_even_though_value_may_be_null(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        envelope = _envelope()
        del envelope["excluded_paths"]
        exit_code, _, stderr = _run(json.dumps(envelope))
        assert exit_code == 2
        assert "excluded_paths" in stderr

    def test_024_null_allowed_paths_value_is_accepted(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps(_envelope(allowed_paths=None)))
        assert exit_code == 0

    def test_025_explicit_empty_excluded_paths_accepted(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps(_envelope(excluded_paths=[])))
        assert exit_code == 0


# ---------------------------------------------------------------------------
# I/J/K/L/M/N. Scope-contract inheritance (never reimplemented in the CLI)
# ---------------------------------------------------------------------------


class TestScopeContractInheritance:
    def test_026_target_scope_error_exits_two(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, stderr = _run(json.dumps(_envelope(
            target="https://app.example.test/",
            allowed_origins=["https://other.example.test"],
        )))
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("BUG_BOUNTY_VALIDATION_FAILED")

    def test_027_unsupported_testing_profile_exits_two(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps(_envelope(testing_profile="standard_web")))
        assert exit_code == 2
        assert stdout == ""

    def test_028_raw_ip_target_rejected_by_core_scope(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps(_envelope(
            target="https://192.168.1.1/",
            allowed_origins=["https://192.168.1.1"],
        )))
        assert exit_code == 2
        assert stdout == ""

    def test_029_http_and_https_origin_distinction_inherited(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps(_envelope(
            target="http://app.example.test/",
            allowed_origins=["https://app.example.test"],
        )))
        assert exit_code == 2
        assert stdout == ""

    def test_030_excluded_paths_passed_through_exactly(self, monkeypatch):
        transport = _clean_transport()
        _install_transport(monkeypatch, transport)
        _run(json.dumps(_envelope(excluded_paths=["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"])))
        assert "https://app.example.test/robots.txt" not in [url for url, _ in transport.calls]

    def test_031_cli_does_not_trim_target_whitespace(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps(_envelope(target=" https://app.example.test/ ")))
        # Passed through unchanged to the deterministic core, which itself
        # trims/normalizes -- the CLI performs no preprocessing of its own.
        assert exit_code == 0

    def test_032_cli_does_not_lowercase_or_lift_scope_values(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps(_envelope(testing_profile="PASSIVE")))
        assert exit_code == 2  # core rejects the un-lowercased value; CLI never normalizes it first
        assert stdout == ""


# ---------------------------------------------------------------------------
# O/P. Network failure honesty
# ---------------------------------------------------------------------------


class TestNetworkFailureHonesty:
    def test_033_transport_failure_returns_valid_assessment_exit_zero(self, monkeypatch):
        _install_transport(monkeypatch, FakeTransport(fail_always=True))
        exit_code, stdout, stderr = _run(json.dumps(_envelope()))
        assert exit_code == 0
        assert stderr == ""
        result = json.loads(stdout)
        assert "REQUEST_FAILED" in result["observed_evidence"]

    def test_034_exit_zero_even_with_request_failed_evidence(self, monkeypatch):
        _install_transport(monkeypatch, FakeTransport(fail_always=True))
        exit_code, stdout, _ = _run(json.dumps(_envelope()))
        assert exit_code == 0
        result = json.loads(stdout)
        assert result["findings"] == []

    def test_035_out_of_scope_blocked_request_is_a_normal_result(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        exit_code, stdout, _ = _run(json.dumps(_envelope(allowed_paths=["/only-here"])))
        assert exit_code == 0
        result = json.loads(stdout)
        assert "OUT_OF_SCOPE_REQUEST_BLOCKED" in result["observed_evidence"]


# ---------------------------------------------------------------------------
# Q/R/S. Internal failure behavior
# ---------------------------------------------------------------------------


class TestInternalFailureBehavior:
    def test_036_unexpected_internal_exception_maps_to_exit_one(self, monkeypatch):
        def _broken():
            raise RuntimeError("simulated internal failure")

        monkeypatch.setattr(bug_bounty_cli, "_build_transport", _broken)
        exit_code, stdout, stderr = _run(json.dumps(_envelope()))
        assert exit_code == 1
        assert stdout == ""
        assert stderr.startswith("BUG_BOUNTY_INTERNAL_FAILURE")

    def test_037_internal_failure_has_no_traceback(self, monkeypatch):
        def _broken():
            raise RuntimeError("simulated internal failure")

        monkeypatch.setattr(bug_bounty_cli, "_build_transport", _broken)
        _, _, stderr = _run(json.dumps(_envelope()))
        _assert_no_forbidden_content(stderr)

    def test_038_internal_failure_does_not_leak_exception_message(self, monkeypatch):
        def _broken():
            raise RuntimeError("sensitive internal detail")

        monkeypatch.setattr(bug_bounty_cli, "_build_transport", _broken)
        _, _, stderr = _run(json.dumps(_envelope()))
        assert "sensitive internal detail" not in stderr

    def test_039_validation_failure_token_is_stable_across_causes(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        _, _, stderr_missing = _run(json.dumps({"operation": "assess"}))
        _, _, stderr_scope = _run(json.dumps(_envelope(testing_profile="bogus")))
        assert stderr_missing.startswith("BUG_BOUNTY_VALIDATION_FAILED")
        assert stderr_scope.startswith("BUG_BOUNTY_VALIDATION_FAILED")

    def test_040_no_exception_class_name_leaked_on_validation_failure(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        _, _, stderr = _run(json.dumps(_envelope(testing_profile="bogus")))
        _assert_no_forbidden_content(stderr)


# ---------------------------------------------------------------------------
# T. Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_041_same_input_yields_identical_stdout(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        envelope_text = json.dumps(_envelope())
        _, stdout_1, _ = _run(envelope_text)
        _install_transport(monkeypatch, _clean_transport())
        _, stdout_2, _ = _run(envelope_text)
        assert stdout_1 == stdout_2

    def test_042_same_input_yields_identical_parsed_json(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        envelope_text = json.dumps(_envelope())
        _, stdout_1, _ = _run(envelope_text)
        _install_transport(monkeypatch, _clean_transport())
        _, stdout_2, _ = _run(envelope_text)
        assert json.loads(stdout_1) == json.loads(stdout_2)


# ---------------------------------------------------------------------------
# U/V. No exception-class leakage / no real network
# ---------------------------------------------------------------------------


class TestNoRealNetworkAndNoLeakage:
    def test_043_no_real_transport_constructed_during_tests(self, monkeypatch):
        constructed = {"real": False}

        class _Sentinel:
            def __init__(self):
                constructed["real"] = True

            def request(self, **kwargs):
                raise AssertionError("real transport must never be used in tests")

        from adapters.bug_bounty_http import BugBountyHttpTransport
        monkeypatch.setattr(bug_bounty_cli, "BugBountyHttpTransport", _Sentinel)
        _install_transport(monkeypatch, _clean_transport())
        _run(json.dumps(_envelope()))
        assert constructed["real"] is False

    def test_044_disallowed_method_error_never_leaked_verbatim(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        _, stdout, stderr = _run(json.dumps(_envelope()))
        _assert_no_forbidden_content(stdout)
        _assert_no_forbidden_content(stderr)


# ---------------------------------------------------------------------------
# W. Thin-wrapper / structural checks
# ---------------------------------------------------------------------------


class TestThinWrapperStructural:
    def _code_body(self):
        return inspect.getsource(bug_bounty_cli).split("from __future__ import annotations", 1)[1]

    def test_045_cli_delegates_to_real_core_function(self, monkeypatch):
        calls = []
        real = run_bug_bounty_assessment

        def _spy(**kwargs):
            calls.append(kwargs)
            return real(**kwargs)

        monkeypatch.setattr(bug_bounty_cli, "run_bug_bounty_assessment", _spy)
        _install_transport(monkeypatch, _clean_transport())
        _run(json.dumps(_envelope()))
        assert len(calls) == 1

    def test_046_module_never_implements_raw_socket_or_http_client_logic(self):
        code_body = self._code_body()
        for token in ("socket.socket", "http.client", "urllib.request", "HTTPConnection", "HTTPSConnection"):
            assert token not in code_body

    def test_047_module_never_uses_requests_or_httpx_directly(self):
        code_body = self._code_body()
        assert "import requests" not in code_body
        assert "import httpx" not in code_body

    def test_048_module_never_invokes_external_scanner(self):
        code_body = self._code_body()
        for token in ("curl", "wget", "nuclei", "zap", "ffuf", "burp", "sqlmap"):
            assert token.lower() not in code_body.lower()

    def test_049_module_never_uses_subprocess(self):
        code_body = self._code_body()
        assert "subprocess" not in code_body

    def test_050_module_never_reimplements_scope_or_finding_logic(self):
        code_body = self._code_body()
        for token in ("_origin_allowed", "_path_matches", "_canonicalize", "evidence_digest ="):
            assert token not in code_body

    def test_051_module_never_uses_database_supabase_or_mcp(self):
        code_body = self._code_body()
        for token in ("supabase", "mcp__", "execute_sql"):
            assert token not in code_body

    def test_052_module_imports_only_the_permitted_symbols(self):
        code_body = self._code_body()
        import_block = code_body.split("_VALIDATION_ERROR_PREFIX", 1)[0]
        allowed_modules = ("adapters.bug_bounty_http", "core.bug_bounty_assessment", "core.bug_bounty_scope", "typing", "json", "sys")
        for line in import_block.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("from ") or stripped.startswith("import "):
                assert any(module in stripped for module in allowed_modules), stripped

    def test_053_no_argparse_used(self):
        code_body = self._code_body()
        assert "argparse" not in code_body

    def test_054_stdout_never_wraps_result_in_extra_envelope(self, monkeypatch):
        _install_transport(monkeypatch, _clean_transport())
        _, stdout, _ = _run(json.dumps(_envelope()))
        result = json.loads(stdout)
        assert "success" not in result
        assert "status" not in result
        assert "result" not in result

    def test_055_build_transport_is_the_only_seam_used_for_construction(self, monkeypatch):
        calls = {"n": 0}
        real_build = bug_bounty_cli._build_transport

        def _spy():
            calls["n"] += 1
            return _clean_transport()

        monkeypatch.setattr(bug_bounty_cli, "_build_transport", _spy)
        _run(json.dumps(_envelope()))
        assert calls["n"] == 1
