"""Tests for core.bug_bounty_assessment -- the pure orchestration layer
for the Bug Bounty assessment engine (Block 15A, checkpoint B1).

NO real network access occurs anywhere in this file. Every test uses a
fake, in-memory injected transport; `core.bug_bounty_assessment` itself
never imports a network client, so there is nothing to mock at the
network layer -- only the injected transport needs to be faked.
"""

from __future__ import annotations

import inspect

import pytest

import core.bug_bounty_assessment as bug_bounty_assessment
from core.bug_bounty_assessment import (
    BugBountyAssessmentError,
    MAX_REDIRECT_HOPS,
    MAX_REQUESTS_PER_ASSESSMENT,
    run_bug_bounty_assessment,
)
from core.bug_bounty_scope import create_bug_bounty_scope

_RESULT_FIELDS = {
    "assessment_version", "target", "testing_profile", "findings", "observed_evidence",
    "assessment_performed", "network_requests_performed", "human_approval_required", "execution_performed",
}


def _scope(**overrides):
    kwargs = {
        "target": "https://app.example.test/",
        "target_type": "web_application",
        "allowed_origins": ["https://app.example.test"],
        "allowed_paths": None,
        "excluded_paths": None,
        "testing_profile": "passive",
    }
    kwargs.update(overrides)
    return create_bug_bounty_scope(**kwargs)


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
    """Deterministic, in-memory fake transport. `handler` maps
    (method, path-or-full-url) lookups to canned responses via a
    caller-supplied function, or a fixed default response.
    """

    def __init__(self, handler=None, *, default=None, fail_on=None):
        self.calls: list[tuple[str, str]] = []
        self._handler = handler
        self._default = default or _response()
        self._fail_on = fail_on or set()

    def request(self, *, url, method, headers=None):
        self.calls.append((url, method))
        if (url, method) in self._fail_on or url in self._fail_on:
            raise RuntimeError("simulated transport failure")
        if self._handler is not None:
            result = self._handler(url=url, method=method)
            if result is not None:
                return result
        return dict(self._default, url=url)


def _baseline_ok_transport(**extra_headers):
    headers = {"Content-Type": "text/html"}
    headers.update(extra_headers)

    def handler(*, url, method):
        if url == "https://app.example.test/" and method == "GET":
            return _response(status_code=200, headers=headers, body_excerpt="<html></html>", url=url)
        return _response(status_code=404, headers={}, url=url)

    return FakeTransport(handler=handler)


# ---------------------------------------------------------------------------
# A. Contract
# ---------------------------------------------------------------------------


class TestContract:
    def test_001_exact_eight_field_result(self):
        scope = _scope()
        result = run_bug_bounty_assessment(scope=scope, transport=_baseline_ok_transport())
        assert set(result.keys()) == _RESULT_FIELDS

    def test_002_assessment_version_is_one(self):
        scope = _scope()
        result = run_bug_bounty_assessment(scope=scope, transport=_baseline_ok_transport())
        assert result["assessment_version"] == "1"

    def test_003_human_approval_required_always_true(self):
        scope = _scope()
        result = run_bug_bounty_assessment(scope=scope, transport=_baseline_ok_transport())
        assert result["human_approval_required"] is True

    def test_004_execution_performed_always_false(self):
        scope = _scope()
        result = run_bug_bounty_assessment(scope=scope, transport=_baseline_ok_transport())
        assert result["execution_performed"] is False

    def test_005_deterministic_repeated_results(self):
        scope = _scope()
        first = run_bug_bounty_assessment(scope=scope, transport=_baseline_ok_transport())
        second = run_bug_bounty_assessment(scope=scope, transport=_baseline_ok_transport())
        assert first == second

    def test_006_target_reflects_scope_target(self):
        scope = _scope()
        result = run_bug_bounty_assessment(scope=scope, transport=_baseline_ok_transport())
        assert result["target"] == scope["target"]

    def test_007_testing_profile_reflects_scope_profile(self):
        scope = _scope(testing_profile="safe_active")
        result = run_bug_bounty_assessment(scope=scope, transport=_baseline_ok_transport())
        assert result["testing_profile"] == "safe_active"

    def test_008_malformed_scope_raises(self):
        with pytest.raises(BugBountyAssessmentError):
            run_bug_bounty_assessment(scope="not a scope", transport=_baseline_ok_transport())

    def test_009_transport_without_request_method_raises(self):
        with pytest.raises(BugBountyAssessmentError):
            run_bug_bounty_assessment(scope=_scope(), transport=object())

    def test_010_deeply_malformed_scope_propagates_real_scope_error(self):
        from core.bug_bounty_scope import BugBountyScopeError
        broken = dict(_scope())
        broken["allowed_origins"] = ["not-a-url"]
        with pytest.raises(BugBountyScopeError):
            run_bug_bounty_assessment(scope=broken, transport=_baseline_ok_transport())


# ---------------------------------------------------------------------------
# B. Scope enforcement
# ---------------------------------------------------------------------------


class TestScopeEnforcement:
    def test_011_every_request_is_prechecked(self):
        scope = _scope(excluded_paths=["/robots.txt"])
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=scope, transport=transport)
        assert "https://app.example.test/robots.txt" not in [url for url, _ in transport.calls]

    def test_012_excluded_paths_never_sent(self):
        scope = _scope(excluded_paths=["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"])
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=scope, transport=transport)
        assert transport.calls == [("https://app.example.test/", "GET")]

    def test_013_out_of_origin_redirect_target_never_sent(self):
        def handler(*, url, method):
            if url == "https://app.example.test/":
                return _response(status_code=302, redirect_location="https://evil.test/", url=url)
            return None

        transport = FakeTransport(handler=handler)
        scope = _scope()
        run_bug_bounty_assessment(scope=scope, transport=transport)
        assert all("evil.test" not in url for url, _ in transport.calls)

    def test_014_in_scope_relative_redirect_followed(self):
        def handler(*, url, method):
            if url == "https://app.example.test/":
                return _response(status_code=302, redirect_location="/landed", url=url)
            if url == "https://app.example.test/landed":
                return _response(status_code=200, headers={"Content-Type": "text/html"}, url=url)
            return _response(status_code=404, url=url)

        transport = FakeTransport(handler=handler)
        scope = _scope()
        run_bug_bounty_assessment(scope=scope, transport=transport)
        assert ("https://app.example.test/landed", "GET") in transport.calls

    def test_015_redirect_hop_limit_is_three(self):
        assert MAX_REDIRECT_HOPS == 3

    def test_016_no_fourth_redirect_request_after_limit(self):
        call_count = {"n": 0}

        def handler(*, url, method):
            call_count["n"] += 1
            return _response(status_code=302, redirect_location=f"/hop{call_count['n']}", url=url)

        transport = FakeTransport(handler=handler)
        scope = _scope(allowed_paths=["/"])
        result = run_bug_bounty_assessment(scope=scope, transport=transport)
        baseline_chain_calls = [c for c in transport.calls if "hop" in c[0] or c[0] == "https://app.example.test/"]
        # Exactly 4 requests for the baseline chain: original + 3 hops, never a 4th hop.
        first_chain = baseline_chain_calls[:4]
        assert len(first_chain) == 4
        assert "REDIRECT_LIMIT_REACHED" in result["observed_evidence"]

    def test_017_request_cap_is_twelve(self):
        assert MAX_REQUESTS_PER_ASSESSMENT == 12

    def test_018_request_cap_enforced(self):
        call_count = {"n": 0}

        def handler(*, url, method):
            call_count["n"] += 1
            return _response(status_code=302, redirect_location=f"/loop{call_count['n']}", url=url)

        transport = FakeTransport(handler=handler)
        scope = _scope()
        result = run_bug_bounty_assessment(scope=scope, transport=transport)
        assert len(transport.calls) == MAX_REQUESTS_PER_ASSESSMENT
        assert "REQUEST_CAP_REACHED" in result["observed_evidence"]

    def test_019_out_of_scope_request_blocked_evidence(self):
        scope = _scope(allowed_paths=["/only-this"])
        transport = _baseline_ok_transport()
        result = run_bug_bounty_assessment(scope=scope, transport=transport)
        assert "OUT_OF_SCOPE_REQUEST_BLOCKED" in result["observed_evidence"]
        assert transport.calls == []


# ---------------------------------------------------------------------------
# C. Passive profile
# ---------------------------------------------------------------------------


class TestPassiveProfile:
    def test_020_canonical_get_sent(self):
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=_scope(), transport=transport)
        assert ("https://app.example.test/", "GET") in transport.calls

    def test_021_scoped_robots_requested(self):
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=_scope(), transport=transport)
        assert ("https://app.example.test/robots.txt", "GET") in transport.calls

    def test_022_scoped_sitemap_requested(self):
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=_scope(), transport=transport)
        assert ("https://app.example.test/sitemap.xml", "GET") in transport.calls

    def test_023_scoped_security_txt_requested(self):
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=_scope(), transport=transport)
        assert ("https://app.example.test/.well-known/security.txt", "GET") in transport.calls

    def test_024_excluded_metadata_path_skipped(self):
        scope = _scope(excluded_paths=["/sitemap.xml"])
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=scope, transport=transport)
        assert "https://app.example.test/sitemap.xml" not in [url for url, _ in transport.calls]

    def test_025_no_crawling_from_returned_content(self):
        def handler(*, url, method):
            if url == "https://app.example.test/":
                return _response(
                    status_code=200, headers={"Content-Type": "text/html"},
                    body_excerpt='<a href="/secret-page">link</a>', url=url,
                )
            return _response(status_code=404, url=url)

        transport = FakeTransport(handler=handler)
        run_bug_bounty_assessment(scope=_scope(), transport=transport)
        assert "https://app.example.test/secret-page" not in [url for url, _ in transport.calls]

    def test_026_no_options_in_passive_profile(self):
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=_scope(testing_profile="passive"), transport=transport)
        assert all(method != "OPTIONS" for _, method in transport.calls)

    def test_027_no_reflection_request_in_passive_profile(self):
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=_scope(testing_profile="passive"), transport=transport)
        assert all("tt_probe" not in url for url, _ in transport.calls)

    def test_028_passive_profile_exactly_four_requests_on_clean_target(self):
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=_scope(), transport=transport)
        assert len(transport.calls) == 4


# ---------------------------------------------------------------------------
# D. Safe-active profile
# ---------------------------------------------------------------------------


class TestSafeActiveProfile:
    def test_029_passive_behavior_retained(self):
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=_scope(testing_profile="safe_active"), transport=transport)
        assert ("https://app.example.test/robots.txt", "GET") in transport.calls

    def test_030_options_sent_on_canonical_target(self):
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=_scope(testing_profile="safe_active"), transport=transport)
        assert ("https://app.example.test/", "OPTIONS") in transport.calls

    def test_031_inert_reflection_request_sent_exactly_once(self):
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=_scope(testing_profile="safe_active"), transport=transport)
        reflection_calls = [c for c in transport.calls if "tt_probe" in c[0]]
        assert len(reflection_calls) == 1

    def test_032_reflection_marker_preserved_in_url(self):
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=_scope(testing_profile="safe_active"), transport=transport)
        reflection_calls = [url for url, _ in transport.calls if "tt_probe" in url]
        assert "THREATTRACE_REFLECTION_PROBE_15A" in reflection_calls[0]

    def test_033_existing_tt_probe_param_causes_skip(self):
        scope = _scope(
            target="https://app.example.test/?tt_probe=caller_value",
            allowed_origins=["https://app.example.test"],
            testing_profile="safe_active",
        )
        transport = FakeTransport(default=_response(status_code=200, headers={"Content-Type": "text/html"}))
        run_bug_bounty_assessment(scope=scope, transport=transport)
        reflection_calls = [url for url, _ in transport.calls if "THREATTRACE_REFLECTION_PROBE_15A" in url]
        assert reflection_calls == []

    def test_034_no_non_idempotent_methods_ever_sent(self):
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=_scope(testing_profile="safe_active"), transport=transport)
        used_methods = {method for _, method in transport.calls}
        assert used_methods <= {"GET", "HEAD", "OPTIONS"}


# ---------------------------------------------------------------------------
# E. Security header findings
# ---------------------------------------------------------------------------


class TestSecurityHeaderFindings:
    def _findings_of(self, result, vulnerability_class):
        return [f for f in result["findings"] if f["vulnerability_class"] == vulnerability_class]

    def test_035_https_missing_hsts_validated(self):
        transport = _baseline_ok_transport()
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        hsts = [f for f in self._findings_of(result, "security_header_misconfiguration") if "Strict-Transport-Security" in f["title"]]
        assert hsts and hsts[0]["finding_status"] == "validated"

    def test_036_http_missing_hsts_not_generated(self):
        scope = create_bug_bounty_scope(
            target="http://app.example.test/", target_type="web_application",
            allowed_origins=["http://app.example.test"], testing_profile="passive",
        )

        def handler(*, url, method):
            if url == "http://app.example.test/" and method == "GET":
                return _response(status_code=200, headers={"Content-Type": "text/html"}, url=url)
            return _response(status_code=404, url=url)

        transport = FakeTransport(handler=handler)
        result = run_bug_bounty_assessment(scope=scope, transport=transport)
        hsts = [f for f in result["findings"] if "Strict-Transport-Security" in f["title"]]
        assert hsts == []

    def test_037_missing_csp_validated(self):
        transport = _baseline_ok_transport()
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        csp = [f for f in self._findings_of(result, "security_header_misconfiguration") if "Content-Security-Policy" in f["title"]]
        assert csp and csp[0]["finding_status"] == "validated"

    def test_038_missing_xcto_validated(self):
        transport = _baseline_ok_transport()
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        xcto = [f for f in self._findings_of(result, "security_header_misconfiguration") if "X-Content-Type-Options" in f["title"]]
        assert xcto and xcto[0]["finding_status"] == "validated"

    def test_039_missing_xfo_validated(self):
        transport = _baseline_ok_transport()
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        xfo = [f for f in self._findings_of(result, "security_header_misconfiguration") if "X-Frame-Options" in f["title"]]
        assert xfo and xfo[0]["finding_status"] == "validated"

    def test_040_present_headers_not_falsely_flagged(self):
        def handler(*, url, method):
            if url == "https://app.example.test/" and method == "GET":
                return _response(status_code=200, headers={
                    "Content-Type": "text/html",
                    "Strict-Transport-Security": "max-age=31536000",
                    "Content-Security-Policy": "default-src 'self'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                }, url=url)
            return _response(status_code=404, url=url)

        transport = FakeTransport(handler=handler)
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        header_findings = self._findings_of(result, "security_header_misconfiguration")
        assert header_findings == []

    def test_041_conservative_severity_assigned(self):
        transport = _baseline_ok_transport()
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        header_findings = self._findings_of(result, "security_header_misconfiguration")
        severities = {f["title"]: f["technical_severity"] for f in header_findings}
        assert severities["Missing Strict-Transport-Security header"] == "medium"
        assert severities["Missing Content-Security-Policy header"] == "medium"
        assert severities["Missing X-Content-Type-Options header"] == "low"
        assert severities["Missing X-Frame-Options header"] == "low"
        assert "critical" not in severities.values()
        assert "high" not in severities.values()

    def test_042_high_confidence_for_directly_observed_absence(self):
        transport = _baseline_ok_transport()
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        header_findings = self._findings_of(result, "security_header_misconfiguration")
        assert all(f["confidence"] == "high" for f in header_findings)

    def test_043_header_findings_use_real_evidence_contract(self):
        transport = _baseline_ok_transport()
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        header_findings = self._findings_of(result, "security_header_misconfiguration")
        for finding in header_findings:
            assert finding["evidence"][0]["evidence_digest"].startswith("sha256:")


# ---------------------------------------------------------------------------
# F. Information disclosure
# ---------------------------------------------------------------------------


class TestInformationDisclosure:
    def test_044_product_version_disclosure_is_candidate(self):
        transport = _baseline_ok_transport(Server="nginx/1.18.0")
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        disclosures = [f for f in result["findings"] if f["vulnerability_class"] == "information_disclosure"]
        assert disclosures and disclosures[0]["finding_status"] == "candidate"

    def test_045_generic_server_header_not_overclaimed(self):
        transport = _baseline_ok_transport(Server="nginx")
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        disclosures = [f for f in result["findings"] if f["vulnerability_class"] == "information_disclosure"]
        assert disclosures == []

    def test_046_no_high_or_critical_severity_from_banner_alone(self):
        transport = _baseline_ok_transport(Server="Apache/2.4.41 (Ubuntu)")
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        disclosures = [f for f in result["findings"] if f["vulnerability_class"] == "information_disclosure"]
        assert disclosures
        assert disclosures[0]["technical_severity"] == "low"

    def test_047_x_powered_by_disclosure_detected(self):
        transport = _baseline_ok_transport(**{"X-Powered-By": "PHP/8.1.2"})
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        disclosures = [f for f in result["findings"] if f["vulnerability_class"] == "information_disclosure"]
        assert any("x-powered-by" in f["title"] for f in disclosures)

    def test_048_no_information_disclosure_finding_when_headers_absent(self):
        transport = _baseline_ok_transport()
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        disclosures = [f for f in result["findings"] if f["vulnerability_class"] == "information_disclosure"]
        assert disclosures == []


# ---------------------------------------------------------------------------
# G. CORS
# ---------------------------------------------------------------------------


class TestCorsObservation:
    def test_049_wildcard_acao_is_candidate_not_validated(self):
        def handler(*, url, method):
            if method == "OPTIONS":
                return _response(status_code=204, headers={"Access-Control-Allow-Origin": "*"}, url=url)
            return _response(status_code=200, headers={"Content-Type": "text/html"}, url=url)

        transport = FakeTransport(handler=handler)
        result = run_bug_bounty_assessment(scope=_scope(testing_profile="safe_active"), transport=transport)
        cors = [f for f in result["findings"] if f["vulnerability_class"] == "cors_misconfiguration"]
        assert cors and cors[0]["finding_status"] == "candidate"

    def test_050_no_fabricated_exploitability_claim(self):
        def handler(*, url, method):
            if method == "OPTIONS":
                return _response(status_code=204, headers={"Access-Control-Allow-Origin": "*"}, url=url)
            return _response(status_code=200, headers={"Content-Type": "text/html"}, url=url)

        transport = FakeTransport(handler=handler)
        result = run_bug_bounty_assessment(scope=_scope(testing_profile="safe_active"), transport=transport)
        cors = [f for f in result["findings"] if f["vulnerability_class"] == "cors_misconfiguration"]
        assert cors[0]["finding_status"] != "validated"
        assert "exploit" not in cors[0]["title"].lower()

    def test_051_no_cors_finding_without_acao_header(self):
        def handler(*, url, method):
            if method == "OPTIONS":
                return _response(status_code=204, headers={"Allow": "GET, HEAD, OPTIONS"}, url=url)
            return _response(status_code=200, headers={"Content-Type": "text/html"}, url=url)

        transport = FakeTransport(handler=handler)
        result = run_bug_bounty_assessment(scope=_scope(testing_profile="safe_active"), transport=transport)
        cors = [f for f in result["findings"] if f["vulnerability_class"] == "cors_misconfiguration"]
        assert cors == []


# ---------------------------------------------------------------------------
# H. HTTP method observation
# ---------------------------------------------------------------------------


class TestHttpMethodObservation:
    def test_052_advertised_put_delete_creates_candidate(self):
        def handler(*, url, method):
            if method == "OPTIONS":
                return _response(status_code=204, headers={"Allow": "GET, HEAD, OPTIONS, PUT, DELETE"}, url=url)
            return _response(status_code=200, headers={"Content-Type": "text/html"}, url=url)

        transport = FakeTransport(handler=handler)
        result = run_bug_bounty_assessment(scope=_scope(testing_profile="safe_active"), transport=transport)
        method_findings = [f for f in result["findings"] if f["vulnerability_class"] == "http_method_observation"]
        assert method_findings and method_findings[0]["finding_status"] == "candidate"

    def test_053_actual_put_delete_never_sent(self):
        def handler(*, url, method):
            if method == "OPTIONS":
                return _response(status_code=204, headers={"Allow": "GET, HEAD, OPTIONS, PUT, DELETE"}, url=url)
            return _response(status_code=200, headers={"Content-Type": "text/html"}, url=url)

        transport = FakeTransport(handler=handler)
        run_bug_bounty_assessment(scope=_scope(testing_profile="safe_active"), transport=transport)
        used_methods = {method for _, method in transport.calls}
        assert "PUT" not in used_methods
        assert "DELETE" not in used_methods

    def test_054_no_method_finding_when_only_safe_methods_advertised(self):
        def handler(*, url, method):
            if method == "OPTIONS":
                return _response(status_code=204, headers={"Allow": "GET, HEAD, OPTIONS"}, url=url)
            return _response(status_code=200, headers={"Content-Type": "text/html"}, url=url)

        transport = FakeTransport(handler=handler)
        result = run_bug_bounty_assessment(scope=_scope(testing_profile="safe_active"), transport=transport)
        method_findings = [f for f in result["findings"] if f["vulnerability_class"] == "http_method_observation"]
        assert method_findings == []


# ---------------------------------------------------------------------------
# I. Reflection
# ---------------------------------------------------------------------------


class TestReflection:
    def test_055_exact_marker_reflected_creates_candidate(self):
        def handler(*, url, method):
            if "tt_probe" in url:
                return _response(status_code=200, headers={}, body_excerpt="echo: THREATTRACE_REFLECTION_PROBE_15A", url=url)
            return _response(status_code=200, headers={"Content-Type": "text/html"}, url=url)

        transport = FakeTransport(handler=handler)
        result = run_bug_bounty_assessment(scope=_scope(testing_profile="safe_active"), transport=transport)
        reflection = [f for f in result["findings"] if f["vulnerability_class"] == "input_reflection"]
        assert reflection and reflection[0]["finding_status"] == "candidate"

    def test_056_reflection_never_validated(self):
        def handler(*, url, method):
            if "tt_probe" in url:
                return _response(status_code=200, headers={}, body_excerpt="echo: THREATTRACE_REFLECTION_PROBE_15A", url=url)
            return _response(status_code=200, headers={"Content-Type": "text/html"}, url=url)

        transport = FakeTransport(handler=handler)
        result = run_bug_bounty_assessment(scope=_scope(testing_profile="safe_active"), transport=transport)
        reflection = [f for f in result["findings"] if f["vulnerability_class"] == "input_reflection"]
        assert reflection[0]["finding_status"] != "validated"

    def test_057_reflection_never_labeled_xss(self):
        def handler(*, url, method):
            if "tt_probe" in url:
                return _response(status_code=200, headers={}, body_excerpt="echo: THREATTRACE_REFLECTION_PROBE_15A", url=url)
            return _response(status_code=200, headers={"Content-Type": "text/html"}, url=url)

        transport = FakeTransport(handler=handler)
        result = run_bug_bounty_assessment(scope=_scope(testing_profile="safe_active"), transport=transport)
        reflection = [f for f in result["findings"] if f["vulnerability_class"] == "input_reflection"]
        assert "xss" not in reflection[0]["title"].lower()
        assert "xss" not in reflection[0]["reproduction_summary"].lower()

    def test_058_no_reflection_finding_when_marker_absent(self):
        transport = _baseline_ok_transport()
        result = run_bug_bounty_assessment(scope=_scope(testing_profile="safe_active"), transport=transport)
        reflection = [f for f in result["findings"] if f["vulnerability_class"] == "input_reflection"]
        assert reflection == []


# ---------------------------------------------------------------------------
# J. Redirect observation
# ---------------------------------------------------------------------------


class TestRedirectObservation:
    def test_059_redirect_observation_is_not_open_redirect_finding(self):
        def handler(*, url, method):
            if url == "https://app.example.test/":
                return _response(status_code=302, redirect_location="/landed", url=url)
            return _response(status_code=200, headers={"Content-Type": "text/html"}, url=url)

        transport = FakeTransport(handler=handler)
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        redirect_findings = [f for f in result["findings"] if f["vulnerability_class"] == "redirect_observation"]
        assert redirect_findings
        assert redirect_findings[0]["finding_status"] == "observation"
        assert "open redirect" not in redirect_findings[0]["title"].lower()

    def test_060_out_of_scope_redirect_blocked_and_recorded(self):
        def handler(*, url, method):
            if url == "https://app.example.test/":
                return _response(status_code=302, redirect_location="https://evil.test/", url=url)
            return _response(status_code=404, url=url)

        transport = FakeTransport(handler=handler)
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        assert "OUT_OF_SCOPE_REDIRECT_BLOCKED" in result["observed_evidence"]
        assert all("evil.test" not in url for url, _ in transport.calls)


# ---------------------------------------------------------------------------
# K. Evidence
# ---------------------------------------------------------------------------


class TestEvidenceHandling:
    def test_061_all_findings_have_real_evidence_shape(self):
        transport = _baseline_ok_transport(Server="nginx/1.18.0")
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        for finding in result["findings"]:
            for evidence_item in finding["evidence"]:
                assert set(evidence_item.keys()) == {
                    "evidence_version", "tool", "method", "scoped_url", "status_code",
                    "selected_headers", "response_excerpt", "observation", "evidence_digest",
                }

    def test_062_cookies_not_preserved_in_evidence(self):
        transport = _baseline_ok_transport(**{"Set-Cookie": "session=secret123"})
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        for finding in result["findings"]:
            for evidence_item in finding["evidence"]:
                assert "set-cookie" not in evidence_item["selected_headers"]

    def test_063_response_excerpt_bounded(self):
        def handler(*, url, method):
            if url == "https://app.example.test/":
                return _response(status_code=200, headers={"Content-Type": "text/html"}, body_excerpt="x" * 10000, url=url)
            return _response(status_code=404, url=url)

        transport = FakeTransport(handler=handler)
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        header_findings = [f for f in result["findings"] if f["vulnerability_class"] == "security_header_misconfiguration"]
        for finding in header_findings:
            assert len(finding["evidence"][0]["response_excerpt"]) <= 500

    def test_064_network_requests_performed_matches_transport_calls(self):
        transport = _baseline_ok_transport()
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        assert result["network_requests_performed"] == len(transport.calls)


# ---------------------------------------------------------------------------
# L. Failures
# ---------------------------------------------------------------------------


class TestFailures:
    def test_065_baseline_request_failure_yields_valid_result(self):
        transport = FakeTransport(fail_on={"https://app.example.test/"})
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        assert result["assessment_performed"] is True
        assert result["network_requests_performed"] >= 1

    def test_066_no_fake_findings_from_total_failure(self):
        def always_fail(*, url, method):
            raise RuntimeError("simulated total outage")

        class AlwaysFailingTransport:
            def request(self, *, url, method, headers=None):
                raise RuntimeError("simulated total outage")

        result = run_bug_bounty_assessment(scope=_scope(), transport=AlwaysFailingTransport())
        assert result["findings"] == []

    def test_067_request_failed_evidence_present(self):
        class AlwaysFailingTransport:
            def request(self, *, url, method, headers=None):
                raise RuntimeError("simulated total outage")

        result = run_bug_bounty_assessment(scope=_scope(), transport=AlwaysFailingTransport())
        assert "REQUEST_FAILED" in result["observed_evidence"]

    def test_068_total_failure_never_claims_target_secure(self):
        class AlwaysFailingTransport:
            def request(self, *, url, method, headers=None):
                raise RuntimeError("simulated total outage")

        result = run_bug_bounty_assessment(scope=_scope(), transport=AlwaysFailingTransport())
        assert result["findings"] == []
        assert "secure" not in str(result).lower()

    def test_069_baseline_complete_failure_exact_semantics(self):
        class AlwaysFailingTransport:
            def request(self, *, url, method, headers=None):
                raise RuntimeError("boom")

        result = run_bug_bounty_assessment(scope=_scope(), transport=AlwaysFailingTransport())
        assert result["assessment_performed"] is True
        assert result["network_requests_performed"] >= 1
        assert result["findings"] == []
        assert "REQUEST_FAILED" in result["observed_evidence"]

    def test_070_metadata_request_failure_does_not_stop_assessment(self):
        def handler(*, url, method):
            if "robots.txt" in url:
                raise RuntimeError("robots.txt fetch failed")
            if url == "https://app.example.test/":
                return _response(status_code=200, headers={"Content-Type": "text/html"}, url=url)
            return _response(status_code=404, url=url)

        transport = FakeTransport(handler=handler)
        result = run_bug_bounty_assessment(scope=_scope(), transport=transport)
        assert ("https://app.example.test/sitemap.xml", "GET") in transport.calls
        assert "REQUEST_FAILED" in result["observed_evidence"]

    def test_071_assessment_performed_false_when_zero_requests(self):
        scope = _scope(allowed_paths=["/impossible-to-reach"])
        transport = _baseline_ok_transport()
        result = run_bug_bounty_assessment(scope=scope, transport=transport)
        assert result["network_requests_performed"] == 0
        assert result["assessment_performed"] is False


# ---------------------------------------------------------------------------
# M. Structural honesty
# ---------------------------------------------------------------------------


class TestStructuralHonesty:
    def _code_body(self):
        return inspect.getsource(bug_bounty_assessment).split("from __future__ import annotations", 1)[1]

    def test_072_module_never_imports_network_clients(self):
        code_body = self._code_body()
        for token in ("import requests", "import httpx", "import http.client", "import socket", "urllib.request"):
            assert token not in code_body

    def test_073_module_never_performs_direct_network_io(self):
        code_body = self._code_body()
        for token in (".connect(", "socket.socket", "HTTPConnection", "HTTPSConnection"):
            assert token not in code_body

    def test_074_module_never_uses_subprocess(self):
        code_body = self._code_body()
        assert "subprocess" not in code_body

    def test_075_module_never_uses_database_supabase_or_mcp(self):
        code_body = self._code_body()
        for token in ("supabase", "mcp__", "execute_sql"):
            assert token not in code_body

    def test_076_module_never_invokes_external_scanner(self):
        code_body = self._code_body()
        for token in ("nuclei", "zap", "ffuf", "katana"):
            assert token.lower() not in code_body.lower()

    def test_077_module_never_uses_randomness_or_system_clock(self):
        code_body = self._code_body()
        for token in ("import random", "import time", "datetime.now", "utcnow", "import uuid"):
            assert token not in code_body

    def test_078_module_never_imports_adapters_package(self):
        code_body = self._code_body()
        assert "import adapters" not in code_body
        assert "from adapters" not in code_body

    def test_079_module_never_imports_block_8_or_9_registries(self):
        code_body = self._code_body()
        for token in ("agent_gateway", "agent_identity_policy"):
            assert token not in code_body

    def test_080_module_never_reimplements_evidence_or_finding_contract(self):
        code_body = self._code_body()
        for token in ("evidence_digest =", "hashlib.sha256(json"):
            assert token not in code_body

    def test_081_public_functions_and_classes_are_exactly_expected(self):
        public_callables = sorted(
            name for name in vars(bug_bounty_assessment)
            if not name.startswith("_")
            and (inspect.isfunction(getattr(bug_bounty_assessment, name)) or inspect.isclass(getattr(bug_bounty_assessment, name)))
            and getattr(getattr(bug_bounty_assessment, name), "__module__", None) == bug_bounty_assessment.__name__
        )
        assert public_callables == sorted({"BugBountyAssessmentError", "run_bug_bounty_assessment"})

    def test_082_error_is_a_value_error(self):
        assert issubclass(BugBountyAssessmentError, ValueError)

    def test_083_calls_real_create_bug_bounty_evidence_and_finding(self, monkeypatch):
        from core import bug_bounty_findings

        evidence_calls = []
        real_evidence = bug_bounty_findings.create_bug_bounty_evidence

        def _spy_evidence(**kwargs):
            evidence_calls.append(kwargs)
            return real_evidence(**kwargs)

        finding_calls = []
        real_finding = bug_bounty_findings.create_bug_bounty_finding

        def _spy_finding(**kwargs):
            finding_calls.append(kwargs)
            return real_finding(**kwargs)

        monkeypatch.setattr(bug_bounty_assessment, "create_bug_bounty_evidence", _spy_evidence)
        monkeypatch.setattr(bug_bounty_assessment, "create_bug_bounty_finding", _spy_finding)

        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=_scope(), transport=transport)
        assert len(evidence_calls) >= 1
        assert len(finding_calls) >= 1

    def test_084_calls_real_evaluate_bug_bounty_request_scope(self, monkeypatch):
        from core import bug_bounty_scope as scope_module

        calls = []
        real_evaluate = scope_module.evaluate_bug_bounty_request_scope

        def _spy(**kwargs):
            calls.append(kwargs)
            return real_evaluate(**kwargs)

        monkeypatch.setattr(bug_bounty_assessment, "evaluate_bug_bounty_request_scope", _spy)
        transport = _baseline_ok_transport()
        run_bug_bounty_assessment(scope=_scope(), transport=transport)
        assert len(calls) >= 1
