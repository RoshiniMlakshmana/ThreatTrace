"""Tests for core.bug_bounty_scope -- the pure, deterministic Bug Bounty
target/scope contract (Block 15A, checkpoint A).

No network, filesystem, clock, randomness, subprocess, or database
access occurs anywhere in this file. Every scope decision is computed
from plain in-memory strings.
"""

from __future__ import annotations

import inspect

import pytest

import core.bug_bounty_scope as bug_bounty_scope
from core.bug_bounty_scope import (
    BugBountyScopeError,
    create_bug_bounty_scope,
    evaluate_bug_bounty_request_scope,
)


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


# ---------------------------------------------------------------------------
# Origin allow/deny
# ---------------------------------------------------------------------------


class TestOriginMatching:
    def test_001_exact_https_origin_allowed(self):
        scope = _scope()
        assert scope["allowed_origins"] == ["https://app.example.test"]

    def test_002_http_and_https_are_separate_origins(self):
        with pytest.raises(BugBountyScopeError):
            create_bug_bounty_scope(
                target="http://app.example.test/",
                target_type="web_application",
                allowed_origins=["https://app.example.test"],
                testing_profile="passive",
            )

    def test_003_http_target_allowed_when_http_origin_listed(self):
        scope = create_bug_bounty_scope(
            target="http://app.example.test/",
            target_type="web_application",
            allowed_origins=["http://app.example.test"],
            testing_profile="passive",
        )
        assert scope["target"] == "http://app.example.test/"

    def test_004_default_https_port_normalizes_away(self):
        scope = create_bug_bounty_scope(
            target="https://app.example.test:443/",
            target_type="web_application",
            allowed_origins=["https://app.example.test:443"],
            testing_profile="passive",
        )
        assert scope["target"] == "https://app.example.test/"
        assert scope["allowed_origins"] == ["https://app.example.test"]

    def test_005_default_http_port_normalizes_away(self):
        scope = create_bug_bounty_scope(
            target="http://app.example.test:80/",
            target_type="web_application",
            allowed_origins=["http://app.example.test:80"],
            testing_profile="passive",
        )
        assert scope["target"] == "http://app.example.test/"
        assert scope["allowed_origins"] == ["http://app.example.test"]

    def test_006_non_default_port_is_significant(self):
        scope = create_bug_bounty_scope(
            target="https://app.example.test:8443/",
            target_type="web_application",
            allowed_origins=["https://app.example.test:8443"],
            testing_profile="passive",
        )
        assert scope["target"] == "https://app.example.test:8443/"

    def test_007_non_default_port_mismatch_rejected(self):
        with pytest.raises(BugBountyScopeError):
            create_bug_bounty_scope(
                target="https://app.example.test:8443/",
                target_type="web_application",
                allowed_origins=["https://app.example.test"],
                testing_profile="passive",
            )

    def test_008_wildcard_subdomain_origin_accepted_in_scope(self):
        scope = _scope(
            target="https://app.example.test/",
            allowed_origins=["https://*.example.test"],
        )
        assert scope["allowed_origins"] == ["https://*.example.test"]

    def test_009_wildcard_matches_single_label_subdomain_request(self):
        scope = _scope(allowed_origins=["https://app.example.test", "https://*.example.test"])
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://api.example.test/x", method="GET")
        assert result["decision"] == "allow"

    def test_010_wildcard_does_not_match_bare_domain(self):
        scope = _scope(allowed_origins=["https://app.example.test", "https://*.example.test"])
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://example.test/x", method="GET")
        assert result["decision"] == "deny"
        assert "REQUEST_ORIGIN_NOT_ALLOWED" in result["observed_evidence"]

    def test_011_wildcard_does_not_match_multi_label_subdomain(self):
        scope = _scope(allowed_origins=["https://app.example.test", "https://*.example.test"])
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://a.b.example.test/x", method="GET")
        assert result["decision"] == "deny"

    def test_012_unrelated_subdomain_denied(self):
        scope = _scope()
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://other.example.test/x", method="GET")
        assert result["decision"] == "deny"
        assert result["observed_evidence"] == ["REQUEST_ORIGIN_NOT_ALLOWED"]

    def test_013_unrelated_host_denied(self):
        scope = _scope()
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://evil.test/x", method="GET")
        assert result["decision"] == "deny"
        assert "REQUEST_ORIGIN_NOT_ALLOWED" in result["observed_evidence"]

    def test_014_raw_ipv4_target_rejected(self):
        with pytest.raises(BugBountyScopeError):
            create_bug_bounty_scope(
                target="https://192.168.1.1/",
                target_type="web_application",
                allowed_origins=["https://192.168.1.1"],
                testing_profile="passive",
            )

    def test_015_raw_ipv6_target_rejected(self):
        with pytest.raises(BugBountyScopeError):
            create_bug_bounty_scope(
                target="https://[::1]/",
                target_type="web_application",
                allowed_origins=["https://[::1]"],
                testing_profile="passive",
            )

    def test_016_userinfo_in_target_rejected(self):
        with pytest.raises(BugBountyScopeError):
            create_bug_bounty_scope(
                target="https://user:pass@app.example.test/",
                target_type="web_application",
                allowed_origins=["https://app.example.test"],
                testing_profile="passive",
            )

    def test_017_fragment_in_target_rejected(self):
        with pytest.raises(BugBountyScopeError):
            create_bug_bounty_scope(
                target="https://app.example.test/#frag",
                target_type="web_application",
                allowed_origins=["https://app.example.test"],
                testing_profile="passive",
            )

    def test_018_target_outside_allowed_origins_rejected(self):
        with pytest.raises(BugBountyScopeError):
            create_bug_bounty_scope(
                target="https://app.example.test/",
                target_type="web_application",
                allowed_origins=["https://other.example.test"],
                testing_profile="passive",
            )

    def test_019_no_implicit_origin_expansion(self):
        with pytest.raises(BugBountyScopeError):
            create_bug_bounty_scope(
                target="https://app.example.test/",
                target_type="web_application",
                allowed_origins=[],
                testing_profile="passive",
            )

    def test_020_duplicate_normalized_origins_rejected(self):
        with pytest.raises(BugBountyScopeError):
            create_bug_bounty_scope(
                target="https://app.example.test/",
                target_type="web_application",
                allowed_origins=["https://app.example.test", "https://app.example.test:443"],
                testing_profile="passive",
            )

    def test_021_scheme_case_normalized(self):
        scope = create_bug_bounty_scope(
            target="HTTPS://APP.example.test/",
            target_type="web_application",
            allowed_origins=["https://app.example.test"],
            testing_profile="passive",
        )
        assert scope["target"].startswith("https://app.example.test")

    def test_022_malformed_origin_entry_rejected(self):
        with pytest.raises(BugBountyScopeError):
            create_bug_bounty_scope(
                target="https://app.example.test/",
                target_type="web_application",
                allowed_origins=["not-a-url"],
                testing_profile="passive",
            )

    def test_023_ftp_scheme_origin_rejected(self):
        with pytest.raises(BugBountyScopeError):
            create_bug_bounty_scope(
                target="https://app.example.test/",
                target_type="web_application",
                allowed_origins=["ftp://app.example.test"],
                testing_profile="passive",
            )

    def test_024_origin_entry_with_path_rejected(self):
        with pytest.raises(BugBountyScopeError):
            create_bug_bounty_scope(
                target="https://app.example.test/",
                target_type="web_application",
                allowed_origins=["https://app.example.test/path"],
                testing_profile="passive",
            )

    def test_025_wildcard_only_star_rejected(self):
        with pytest.raises(BugBountyScopeError):
            create_bug_bounty_scope(
                target="https://app.example.test/",
                target_type="web_application",
                allowed_origins=["https://*"],
                testing_profile="passive",
            )

    def test_026_target_origin_allow_via_matching_wildcard(self):
        scope = create_bug_bounty_scope(
            target="https://app.example.test/",
            target_type="web_application",
            allowed_origins=["https://*.example.test"],
            testing_profile="passive",
        )
        assert scope["target"] == "https://app.example.test/"


# ---------------------------------------------------------------------------
# Path normalization / matching
# ---------------------------------------------------------------------------


class TestPathMatching:
    def test_027_allowed_paths_default_to_root(self):
        scope = _scope()
        assert scope["allowed_paths"] == ["/"]

    def test_028_root_allowed_path_matches_everything(self):
        scope = _scope()
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/anything/deep", method="GET")
        assert result["decision"] == "allow"

    def test_029_segment_aware_prefix_match(self):
        scope = _scope(allowed_paths=["/api"])
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/api/users", method="GET")
        assert result["decision"] == "allow"

    def test_030_exact_path_match(self):
        scope = _scope(allowed_paths=["/api"])
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/api", method="GET")
        assert result["decision"] == "allow"

    def test_031_api_does_not_match_api2(self):
        scope = _scope(allowed_paths=["/api"])
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/api2", method="GET")
        assert result["decision"] == "deny"
        assert result["observed_evidence"] == ["REQUEST_PATH_NOT_ALLOWED"]

    def test_032_path_outside_allowed_paths_denied(self):
        scope = _scope(allowed_paths=["/api"])
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/other", method="GET")
        assert result["decision"] == "deny"
        assert result["observed_evidence"] == ["REQUEST_PATH_NOT_ALLOWED"]

    def test_033_excluded_path_overrides_allowed(self):
        scope = _scope(allowed_paths=["/"], excluded_paths=["/admin"])
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/admin", method="GET")
        assert result["decision"] == "deny"
        assert result["observed_evidence"] == ["REQUEST_PATH_EXCLUDED"]

    def test_034_nested_excluded_path_matched(self):
        scope = _scope(allowed_paths=["/"], excluded_paths=["/admin"])
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/admin/danger", method="GET")
        assert result["decision"] == "deny"
        assert result["observed_evidence"] == ["REQUEST_PATH_EXCLUDED"]

    def test_035_sibling_of_excluded_path_not_excluded(self):
        scope = _scope(allowed_paths=["/"], excluded_paths=["/admin"])
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/administrator", method="GET")
        assert result["decision"] == "allow"

    def test_036_allowed_paths_must_begin_with_slash(self):
        with pytest.raises(BugBountyScopeError):
            _scope(allowed_paths=["api"])

    def test_037_allowed_paths_reject_blank(self):
        with pytest.raises(BugBountyScopeError):
            _scope(allowed_paths=["   "])

    def test_038_allowed_paths_reject_empty_list(self):
        with pytest.raises(BugBountyScopeError):
            _scope(allowed_paths=[])

    def test_039_excluded_paths_accept_explicit_empty_list(self):
        scope = _scope(excluded_paths=[])
        assert scope["excluded_paths"] == []

    def test_040_allowed_paths_reject_query(self):
        with pytest.raises(BugBountyScopeError):
            _scope(allowed_paths=["/api?x=1"])

    def test_041_allowed_paths_reject_fragment(self):
        with pytest.raises(BugBountyScopeError):
            _scope(allowed_paths=["/api#frag"])

    def test_042_allowed_paths_reject_backslash(self):
        with pytest.raises(BugBountyScopeError):
            _scope(allowed_paths=["/api\\admin"])

    def test_043_allowed_paths_reject_dot_segment(self):
        with pytest.raises(BugBountyScopeError):
            _scope(allowed_paths=["/api/../admin"])

    def test_044_allowed_paths_reject_single_dot_segment(self):
        with pytest.raises(BugBountyScopeError):
            _scope(allowed_paths=["/api/./admin"])

    def test_045_allowed_paths_reject_trailing_dot_dot(self):
        with pytest.raises(BugBountyScopeError):
            _scope(allowed_paths=["/api/.."])

    def test_046_allowed_paths_reject_encoded_slash(self):
        with pytest.raises(BugBountyScopeError):
            _scope(allowed_paths=["/api%2fadmin"])

    def test_047_allowed_paths_reject_encoded_backslash(self):
        with pytest.raises(BugBountyScopeError):
            _scope(allowed_paths=["/api%5cadmin"])

    def test_048_allowed_paths_reject_trailing_slash_except_root(self):
        with pytest.raises(BugBountyScopeError):
            _scope(allowed_paths=["/api/"])

    def test_049_duplicate_allowed_paths_rejected(self):
        with pytest.raises(BugBountyScopeError):
            _scope(allowed_paths=["/api", "/api"])

    def test_050_duplicate_excluded_paths_rejected(self):
        with pytest.raises(BugBountyScopeError):
            _scope(excluded_paths=["/admin", "/admin"])

    def test_051_excluded_paths_reject_dot_segment(self):
        with pytest.raises(BugBountyScopeError):
            _scope(excluded_paths=["/admin/../x"])

    def test_052_request_path_with_dot_segment_treated_as_invalid_url(self):
        scope = _scope()
        result = evaluate_bug_bounty_request_scope(
            scope=scope, url="https://app.example.test/../etc/passwd", method="GET"
        )
        assert result["decision"] == "deny"
        assert result["observed_evidence"] == ["INVALID_REQUEST_URL"]

    def test_053_request_path_preserves_query(self):
        scope = _scope()
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/search?q=1", method="GET")
        assert result["normalized_url"] == "https://app.example.test/search?q=1"


# ---------------------------------------------------------------------------
# Testing profiles / methods
# ---------------------------------------------------------------------------


class TestProfilesAndMethods:
    def test_054_passive_allows_get(self):
        scope = _scope(testing_profile="passive")
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/", method="GET")
        assert result["decision"] == "allow"

    def test_055_passive_allows_head(self):
        scope = _scope(testing_profile="passive")
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/", method="HEAD")
        assert result["decision"] == "allow"

    def test_056_passive_denies_options(self):
        scope = _scope(testing_profile="passive")
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/", method="OPTIONS")
        assert result["decision"] == "deny"
        assert result["observed_evidence"] == ["METHOD_NOT_ALLOWED"]

    def test_057_safe_active_allows_options(self):
        scope = _scope(testing_profile="safe_active")
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/", method="OPTIONS")
        assert result["decision"] == "allow"

    def test_058_safe_active_denies_post(self):
        scope = _scope(testing_profile="safe_active")
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/", method="POST")
        assert result["decision"] == "deny"
        assert result["observed_evidence"] == ["METHOD_NOT_ALLOWED"]

    def test_059_safe_active_denies_delete(self):
        scope = _scope(testing_profile="safe_active")
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/", method="DELETE")
        assert result["decision"] == "deny"

    def test_060_lowercase_method_canonicalized(self):
        scope = _scope(testing_profile="passive")
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/", method="get")
        assert result["method"] == "GET"
        assert result["decision"] == "allow"

    def test_061_unsupported_profile_rejected(self):
        with pytest.raises(BugBountyScopeError):
            _scope(testing_profile="standard_web")

    def test_062_blank_method_denied(self):
        scope = _scope()
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/", method="")
        assert result["decision"] == "deny"
        assert result["method"] is None

    def test_063_non_string_method_denied(self):
        scope = _scope()
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/", method=123)
        assert result["decision"] == "deny"
        assert result["method"] is None


# ---------------------------------------------------------------------------
# Out-of-scope requests deny rather than raise; errors vs. denials
# ---------------------------------------------------------------------------


class TestDenyVersusRaise:
    def test_064_out_of_scope_request_returns_deny_not_exception(self):
        scope = _scope()
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://evil.test/", method="GET")
        assert result["decision"] == "deny"

    def test_065_malformed_scope_raises(self):
        with pytest.raises(BugBountyScopeError):
            evaluate_bug_bounty_request_scope(scope={"not": "a scope"}, url="https://app.example.test/", method="GET")

    def test_066_scope_not_a_mapping_raises(self):
        with pytest.raises(BugBountyScopeError):
            evaluate_bug_bounty_request_scope(scope="not a scope", url="https://app.example.test/", method="GET")

    def test_067_tampered_scope_target_origin_mismatch_is_deny_not_raise(self):
        scope = _scope()
        tampered = dict(scope)
        tampered["allowed_origins"] = ["https://other.example.test"]
        result = evaluate_bug_bounty_request_scope(scope=tampered, url="https://app.example.test/", method="GET")
        assert result["decision"] == "deny"
        assert "TARGET_ORIGIN_NOT_ALLOWED" in result["observed_evidence"]

    def test_068_scope_missing_field_raises(self):
        scope = _scope()
        broken = dict(scope)
        del broken["testing_profile"]
        with pytest.raises(BugBountyScopeError):
            evaluate_bug_bounty_request_scope(scope=broken, url="https://app.example.test/", method="GET")

    def test_069_scope_extra_field_raises(self):
        scope = _scope()
        broken = dict(scope)
        broken["extra"] = "unexpected"
        with pytest.raises(BugBountyScopeError):
            evaluate_bug_bounty_request_scope(scope=broken, url="https://app.example.test/", method="GET")

    def test_070_target_type_must_be_recognized(self):
        with pytest.raises(BugBountyScopeError):
            _scope(target_type="mobile_app")

    def test_071_target_must_be_string(self):
        with pytest.raises(BugBountyScopeError):
            create_bug_bounty_scope(
                target=None, target_type="web_application",
                allowed_origins=["https://app.example.test"], testing_profile="passive",
            )

    def test_072_target_must_be_absolute_url(self):
        with pytest.raises(BugBountyScopeError):
            create_bug_bounty_scope(
                target="app.example.test", target_type="web_application",
                allowed_origins=["https://app.example.test"], testing_profile="passive",
            )


# ---------------------------------------------------------------------------
# Contract shape / determinism
# ---------------------------------------------------------------------------


class TestContractShape:
    def test_073_scope_exact_key_set(self):
        scope = _scope()
        assert set(scope.keys()) == {
            "scope_version", "target", "target_type", "allowed_origins",
            "allowed_paths", "excluded_paths", "testing_profile",
        }

    def test_074_scope_version_is_one(self):
        scope = _scope()
        assert scope["scope_version"] == "1"

    def test_075_evaluation_result_exact_key_set(self):
        scope = _scope()
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/", method="GET")
        assert set(result.keys()) == {
            "scope_evaluation_version", "normalized_url", "method", "decision", "observed_evidence",
        }

    def test_076_evaluation_version_is_one(self):
        scope = _scope()
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/", method="GET")
        assert result["scope_evaluation_version"] == "1"

    def test_077_deterministic_repeated_scope_creation(self):
        first = _scope()
        second = _scope()
        assert first == second

    def test_078_deterministic_repeated_evaluation(self):
        scope = _scope()
        first = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/x", method="GET")
        second = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/x", method="GET")
        assert first == second

    def test_079_allowed_origins_order_preserved(self):
        scope = _scope(allowed_origins=["https://b.example.test", "https://app.example.test"])
        assert scope["allowed_origins"] == ["https://b.example.test", "https://app.example.test"]

    def test_080_observed_evidence_is_deduplicated_and_fixed_order(self):
        scope = _scope(allowed_paths=["/api"])
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://evil.test/other", method="POST")
        assert result["observed_evidence"] == ["REQUEST_ORIGIN_NOT_ALLOWED", "METHOD_NOT_ALLOWED"]
        assert len(result["observed_evidence"]) == len(set(result["observed_evidence"]))

    def test_081_allow_has_empty_evidence(self):
        scope = _scope()
        result = evaluate_bug_bounty_request_scope(scope=scope, url="https://app.example.test/", method="GET")
        assert result["decision"] == "allow"
        assert result["observed_evidence"] == []


# ---------------------------------------------------------------------------
# Structural / purity
# ---------------------------------------------------------------------------


class TestStructuralPurity:
    def test_082_module_never_imports_network_clients(self):
        source = inspect.getsource(bug_bounty_scope)
        for token in ("import requests", "import httpx", "import socket", "urllib.request", "http.client"):
            assert token not in source

    def test_083_module_never_uses_subprocess(self):
        source = inspect.getsource(bug_bounty_scope)
        assert "subprocess" not in source

    def test_084_module_never_uses_filesystem(self):
        source = inspect.getsource(bug_bounty_scope)
        for token in ("open(", "pathlib", "Path(", "os.environ"):
            assert token not in source

    def test_085_module_never_uses_clock_or_randomness(self):
        source = inspect.getsource(bug_bounty_scope)
        for token in ("datetime.now", "utcnow", "import random", "import time", "import uuid"):
            assert token not in source

    def test_086_module_never_uses_database_supabase_or_mcp(self):
        source = inspect.getsource(bug_bounty_scope)
        for token in ("supabase", "mcp__", "execute_sql"):
            assert token not in source

    def test_087_module_never_imports_block_8_or_9_registries(self):
        source = inspect.getsource(bug_bounty_scope)
        for token in ("agent_gateway", "agent_identity_policy"):
            assert token not in source

    def test_088_public_symbols_are_exactly_expected(self):
        public_names = sorted(
            name for name in vars(bug_bounty_scope)
            if not name.startswith("_") and not inspect.ismodule(getattr(bug_bounty_scope, name))
        )
        assert "BugBountyScopeError" in public_names
        assert "create_bug_bounty_scope" in public_names
        assert "evaluate_bug_bounty_request_scope" in public_names

    def test_089_error_is_a_value_error(self):
        assert issubclass(BugBountyScopeError, ValueError)
