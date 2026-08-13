"""Tests for adapters.bug_bounty_http -- the real, bounded HTTP
transport for the Bug Bounty assessment engine (Block 15A, checkpoint
B1).

NO real network access occurs anywhere in this file. Every test
monkeypatches `http.client.HTTPConnection`/`HTTPSConnection` with an
in-memory fake connection, and every rate-limit test injects a fake
`sleep`/`clock` so no test actually waits on a real clock.
"""

from __future__ import annotations

import http.client
import inspect

import pytest

import adapters.bug_bounty_http as bug_bounty_http
from adapters.bug_bounty_http import BugBountyHttpError, BugBountyHttpTransport


class _FakeResponse:
    def __init__(self, *, status=200, headers=None, body=b""):
        self.status = status
        self._headers = dict(headers or {})
        self._body = body
        self.read_calls: list[int] = []

    def read(self, n):
        self.read_calls.append(n)
        chunk = self._body[:n]
        self._body = self._body[n:]
        return chunk

    def getheaders(self):
        return list(self._headers.items())


class _FakeConnection:
    """Records construction/request arguments; `configure` sets the
    class-level behavior the next constructed instance will exhibit.
    """

    instances: list["_FakeConnection"] = []
    _response_factory = None
    _request_exception = None
    _getresponse_exception = None

    def __init__(self, host, port, timeout=None, context=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.requested = None
        self.closed = False
        type(self).instances.append(self)

    def request(self, method, target, headers=None):
        if type(self)._request_exception is not None:
            raise type(self)._request_exception
        self.requested = (method, target, headers)

    def getresponse(self):
        if type(self)._getresponse_exception is not None:
            raise type(self)._getresponse_exception
        return type(self)._response_factory()

    def close(self):
        self.closed = True


def _install_fake_connection(monkeypatch, *, status=200, headers=None, body=b"", request_exception=None, getresponse_exception=None):
    _FakeConnection.instances = []
    _FakeConnection._response_factory = lambda: _FakeResponse(status=status, headers=headers, body=body)
    _FakeConnection._request_exception = request_exception
    _FakeConnection._getresponse_exception = getresponse_exception
    monkeypatch.setattr(http.client, "HTTPSConnection", _FakeConnection)
    monkeypatch.setattr(http.client, "HTTPConnection", _FakeConnection)
    return _FakeConnection


def _transport(**kwargs):
    kwargs.setdefault("sleep", lambda seconds: None)
    return BugBountyHttpTransport(**kwargs)


# ---------------------------------------------------------------------------
# Method restrictions
# ---------------------------------------------------------------------------


class TestMethodRestrictions:
    def test_001_get_allowed(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={"Content-Type": "text/plain"}, body=b"ok")
        result = _transport().request(url="https://app.example.test/", method="GET")
        assert result["status_code"] == 200

    def test_002_head_allowed(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        result = _transport().request(url="https://app.example.test/", method="HEAD")
        assert result["status_code"] == 200

    def test_003_options_allowed(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=204, headers={"Allow": "GET, HEAD"}, body=b"")
        result = _transport().request(url="https://app.example.test/", method="OPTIONS")
        assert result["status_code"] == 204

    @pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"])
    def test_004_disallowed_methods_rejected(self, monkeypatch, method):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        with pytest.raises(BugBountyHttpError):
            _transport().request(url="https://app.example.test/", method=method)

    def test_005_disallowed_method_never_reaches_connection(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        with pytest.raises(BugBountyHttpError):
            _transport().request(url="https://app.example.test/", method="DELETE")
        assert _FakeConnection.instances == []

    def test_006_lowercase_method_accepted_and_canonicalized(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        _transport().request(url="https://app.example.test/", method="get")
        assert _FakeConnection.instances[0].requested[0] == "GET"

    def test_007_unrecognized_method_string_rejected(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        with pytest.raises(BugBountyHttpError):
            _transport().request(url="https://app.example.test/", method="FETCH")


# ---------------------------------------------------------------------------
# Fixed User-Agent / timeout / headers
# ---------------------------------------------------------------------------


class TestFixedRequestShape:
    def test_008_fixed_user_agent_sent(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        _transport().request(url="https://app.example.test/", method="GET")
        headers_sent = _FakeConnection.instances[0].requested[2]
        assert headers_sent["User-Agent"] == "ThreatTrace-SafeAssessment/1.0"

    def test_009_fixed_timeout_passed_to_connection(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        _transport().request(url="https://app.example.test/", method="GET")
        assert _FakeConnection.instances[0].timeout == bug_bounty_http.DEFAULT_TIMEOUT_SECONDS

    def test_010_connection_close_header_sent(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        _transport().request(url="https://app.example.test/", method="GET")
        assert _FakeConnection.instances[0].requested[2]["Connection"] == "close"

    def test_011_no_authorization_header_sent_even_if_supplied(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        _transport().request(url="https://app.example.test/", method="GET", headers={"Authorization": "Bearer x"})
        headers_sent = _FakeConnection.instances[0].requested[2]
        assert "Authorization" not in headers_sent

    def test_012_no_cookie_header_sent_even_if_supplied(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        _transport().request(url="https://app.example.test/", method="GET", headers={"Cookie": "session=abc"})
        headers_sent = _FakeConnection.instances[0].requested[2]
        assert "Cookie" not in headers_sent

    def test_013_no_proxy_authorization_header_sent(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        _transport().request(url="https://app.example.test/", method="GET", headers={"Proxy-Authorization": "x"})
        headers_sent = _FakeConnection.instances[0].requested[2]
        assert "Proxy-Authorization" not in headers_sent

    def test_014_safe_header_passthrough_preserved(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        _transport().request(url="https://app.example.test/", method="GET", headers={"Accept": "text/html"})
        headers_sent = _FakeConnection.instances[0].requested[2]
        assert headers_sent["Accept"] == "text/html"

    def test_015_none_headers_accepted(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        result = _transport().request(url="https://app.example.test/", method="GET", headers=None)
        assert result["status_code"] == 200

    def test_016_no_browser_state_or_session_object_referenced(self):
        source = inspect.getsource(bug_bounty_http)
        for token in ("cookiejar", "CookieJar", "session", "Session"):
            assert token not in source


# ---------------------------------------------------------------------------
# Redirects
# ---------------------------------------------------------------------------


class TestRedirectHandling:
    def test_017_redirect_not_automatically_followed(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=302, headers={"Location": "/next"}, body=b"")
        _transport().request(url="https://app.example.test/", method="GET")
        assert len(_FakeConnection.instances) == 1

    def test_018_3xx_returned_normally_not_as_error(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=301, headers={"Location": "/moved"}, body=b"")
        result = _transport().request(url="https://app.example.test/", method="GET")
        assert result["status_code"] == 301

    def test_019_relative_location_preserved_unresolved(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=302, headers={"Location": "/relative/path"}, body=b"")
        result = _transport().request(url="https://app.example.test/", method="GET")
        assert result["redirect_location"] == "/relative/path"

    def test_020_absolute_location_preserved_unresolved(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=302, headers={"Location": "https://other.test/x"}, body=b"")
        result = _transport().request(url="https://app.example.test/", method="GET")
        assert result["redirect_location"] == "https://other.test/x"

    def test_021_non_redirect_status_has_null_redirect_location(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={"Location": "/ignored"}, body=b"")
        result = _transport().request(url="https://app.example.test/", method="GET")
        assert result["redirect_location"] is None

    def test_022_redirect_without_location_header_has_null_redirect_location(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=302, headers={}, body=b"")
        result = _transport().request(url="https://app.example.test/", method="GET")
        assert result["redirect_location"] is None


# ---------------------------------------------------------------------------
# Body bound / decoding
# ---------------------------------------------------------------------------


class TestBodyBound:
    def test_023_body_read_capped_at_64kib(self, monkeypatch):
        huge_body = b"x" * (200 * 1024)
        _install_fake_connection(monkeypatch, status=200, headers={"Content-Type": "text/plain"}, body=huge_body)
        result = _transport().request(url="https://app.example.test/", method="GET")
        assert len(result["body_excerpt"]) == bug_bounty_http.MAX_BODY_BYTES

    def test_024_read_call_uses_a_fixed_bound_not_unbounded(self, monkeypatch):
        captured_responses: list[_FakeResponse] = []

        def _factory():
            response = _FakeResponse(status=200, headers={}, body=b"short")
            captured_responses.append(response)
            return response

        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"short")
        _FakeConnection._response_factory = _factory
        _transport().request(url="https://app.example.test/", method="GET")
        assert captured_responses[0].read_calls == [bug_bounty_http.MAX_BODY_BYTES + 1]

    def test_025_declared_charset_used_for_decoding(self, monkeypatch):
        body = "café".encode("latin-1")
        _install_fake_connection(
            monkeypatch, status=200, headers={"Content-Type": "text/plain; charset=latin-1"}, body=body,
        )
        result = _transport().request(url="https://app.example.test/", method="GET")
        assert result["body_excerpt"] == "café"

    def test_026_utf8_fallback_when_no_charset_declared(self, monkeypatch):
        body = "café".encode("utf-8")
        _install_fake_connection(monkeypatch, status=200, headers={}, body=body)
        result = _transport().request(url="https://app.example.test/", method="GET")
        assert result["body_excerpt"] == "café"

    def test_027_empty_body_yields_none_excerpt(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        result = _transport().request(url="https://app.example.test/", method="GET")
        assert result["body_excerpt"] is None

    def test_028_undecodable_bytes_use_replacement_not_crash(self, monkeypatch):
        body = b"\xff\xfe\x00broken"
        _install_fake_connection(
            monkeypatch, status=200, headers={"Content-Type": "text/plain; charset=ascii"}, body=body,
        )
        result = _transport().request(url="https://app.example.test/", method="GET")
        assert isinstance(result["body_excerpt"], str)

    def test_029_unknown_charset_falls_back_to_utf8(self, monkeypatch):
        body = "plain".encode("utf-8")
        _install_fake_connection(
            monkeypatch, status=200, headers={"Content-Type": "text/plain; charset=not-a-real-charset"}, body=body,
        )
        result = _transport().request(url="https://app.example.test/", method="GET")
        assert result["body_excerpt"] == "plain"


# ---------------------------------------------------------------------------
# Network failure handling
# ---------------------------------------------------------------------------


class TestNetworkFailure:
    def test_030_connection_request_failure_becomes_adapter_error(self, monkeypatch):
        _install_fake_connection(monkeypatch, request_exception=OSError("connection refused"))
        with pytest.raises(BugBountyHttpError):
            _transport().request(url="https://app.example.test/", method="GET")

    def test_031_getresponse_failure_becomes_adapter_error(self, monkeypatch):
        _install_fake_connection(monkeypatch, getresponse_exception=TimeoutError("timed out"))
        with pytest.raises(BugBountyHttpError):
            _transport().request(url="https://app.example.test/", method="GET")

    def test_032_no_raw_exception_message_leaked(self, monkeypatch):
        _install_fake_connection(monkeypatch, request_exception=OSError("super secret internal detail"))
        try:
            _transport().request(url="https://app.example.test/", method="GET")
            assert False, "expected BugBountyHttpError"
        except BugBountyHttpError as exc:
            assert "super secret internal detail" not in str(exc)

    def test_033_no_exception_class_name_leaked(self, monkeypatch):
        _install_fake_connection(monkeypatch, request_exception=ConnectionRefusedError("x"))
        try:
            _transport().request(url="https://app.example.test/", method="GET")
            assert False, "expected BugBountyHttpError"
        except BugBountyHttpError as exc:
            assert "ConnectionRefusedError" not in str(exc)

    def test_034_connection_closed_after_failure(self, monkeypatch):
        _install_fake_connection(monkeypatch, getresponse_exception=OSError("boom"))
        with pytest.raises(BugBountyHttpError):
            _transport().request(url="https://app.example.test/", method="GET")
        assert _FakeConnection.instances[0].closed is True

    def test_035_connection_closed_after_success(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"ok")
        _transport().request(url="https://app.example.test/", method="GET")
        assert _FakeConnection.instances[0].closed is True

    def test_036_malformed_url_rejected(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        with pytest.raises(BugBountyHttpError):
            _transport().request(url="not-a-url", method="GET")

    def test_037_unsupported_scheme_rejected(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        with pytest.raises(BugBountyHttpError):
            _transport().request(url="ftp://app.example.test/", method="GET")

    def test_038_missing_hostname_rejected(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        with pytest.raises(BugBountyHttpError):
            _transport().request(url="https:///path", method="GET")


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimit:
    def test_039_no_sleep_on_first_request(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        sleep_calls = []
        transport = BugBountyHttpTransport(sleep=lambda s: sleep_calls.append(s), clock=lambda: 100.0)
        transport.request(url="https://app.example.test/", method="GET")
        assert sleep_calls == []

    def test_040_sleep_invoked_when_requests_too_close(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        sleep_calls = []
        times = iter([100.0, 100.02, 100.02])
        transport = BugBountyHttpTransport(sleep=lambda s: sleep_calls.append(s), clock=lambda: next(times))
        transport.request(url="https://app.example.test/", method="GET")
        transport.request(url="https://app.example.test/", method="GET")
        assert len(sleep_calls) == 1
        assert sleep_calls[0] == pytest.approx(0.08, abs=0.001)

    def test_041_no_sleep_when_interval_already_elapsed(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        sleep_calls = []
        times = iter([100.0, 100.5, 100.5])
        transport = BugBountyHttpTransport(sleep=lambda s: sleep_calls.append(s), clock=lambda: next(times))
        transport.request(url="https://app.example.test/", method="GET")
        transport.request(url="https://app.example.test/", method="GET")
        assert sleep_calls == []

    def test_042_min_interval_is_100_milliseconds(self):
        assert bug_bounty_http.MIN_REQUEST_INTERVAL_SECONDS == 0.1

    def test_043_min_interval_not_overridable_via_request_call(self):
        signature = inspect.signature(BugBountyHttpTransport.request)
        assert "min_interval" not in signature.parameters
        assert "timeout" not in signature.parameters


# ---------------------------------------------------------------------------
# Contract shape / determinism
# ---------------------------------------------------------------------------


class TestContractShape:
    def test_044_exact_result_key_set(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        result = _transport().request(url="https://app.example.test/", method="GET")
        assert set(result.keys()) == {
            "url", "status_code", "headers", "body_excerpt", "redirect_location", "request_performed",
        }

    def test_045_request_performed_always_true_on_success(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        result = _transport().request(url="https://app.example.test/", method="GET")
        assert result["request_performed"] is True

    def test_046_deterministic_repeated_output(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={"Content-Type": "text/plain"}, body=b"hi")
        first = _transport().request(url="https://app.example.test/", method="GET")
        _install_fake_connection(monkeypatch, status=200, headers={"Content-Type": "text/plain"}, body=b"hi")
        second = _transport().request(url="https://app.example.test/", method="GET")
        assert first == second

    def test_047_url_field_echoes_input_url(self, monkeypatch):
        _install_fake_connection(monkeypatch, status=200, headers={}, body=b"")
        result = _transport().request(url="https://app.example.test/path?x=1", method="GET")
        assert result["url"] == "https://app.example.test/path?x=1"


# ---------------------------------------------------------------------------
# Structural / purity
# ---------------------------------------------------------------------------


class TestStructuralPurity:
    def test_048_module_never_uses_subprocess(self):
        code_body = inspect.getsource(bug_bounty_http).split("from __future__ import annotations", 1)[1]
        assert "subprocess" not in code_body

    def test_049_module_never_invokes_external_scanner(self):
        code_body = inspect.getsource(bug_bounty_http).split("from __future__ import annotations", 1)[1]
        for token in ("nuclei", "zap", "ffuf", "katana", "curl "):
            assert token.lower() not in code_body.lower()

    def test_050_module_never_reads_environment_variables(self):
        code_body = inspect.getsource(bug_bounty_http).split("from __future__ import annotations", 1)[1]
        assert "os.environ" not in code_body
        assert "import os" not in code_body

    def test_051_module_never_uses_database_supabase_or_mcp(self):
        code_body = inspect.getsource(bug_bounty_http).split("from __future__ import annotations", 1)[1]
        for token in ("supabase", "mcp__", "execute_sql"):
            assert token not in code_body

    def test_052_module_only_uses_stdlib_http_client(self):
        code_body = inspect.getsource(bug_bounty_http).split("from __future__ import annotations", 1)[1]
        for token in ("import requests", "import httpx", "import socket"):
            assert token not in code_body
        assert "import http.client" in code_body

    def test_053_public_symbols_are_exactly_expected(self):
        public_names = sorted(
            name for name in vars(bug_bounty_http)
            if not name.startswith("_") and not inspect.ismodule(getattr(bug_bounty_http, name))
        )
        assert "BugBountyHttpTransport" in public_names
        assert "BugBountyHttpError" in public_names

    def test_054_error_is_an_exception(self):
        assert issubclass(BugBountyHttpError, Exception)

    def test_055_module_documents_untrusted_remote_content(self):
        assert "UNTRUSTED EVIDENCE" in bug_bounty_http.__doc__

    def test_056_module_documents_dns_rebinding_limitation(self):
        assert "DNS-rebinding" in bug_bounty_http.__doc__ or "DNS rebinding" in bug_bounty_http.__doc__.replace("-", " ")
