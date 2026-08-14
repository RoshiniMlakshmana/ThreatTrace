"""Tests for core.juice_shop_ground_truth -- the pure, deterministic
OWASP Juice Shop ground-truth manifest contract (Block 15F-A).

No network, filesystem, environment-variable, subprocess, clock,
randomness, database/Supabase, MCP, or LLM/model access occurs anywhere
in this file. Every input is a plain in-memory mapping.
"""

from __future__ import annotations

import copy

import pytest

from core.juice_shop_ground_truth import (
    BASELINE_TARGET_VERSION_OR_DIGEST,
    CASE_CATEGORIES,
    DETECTOR_CAPABILITIES,
    OUT_OF_SCOPE_CATEGORIES,
    UNSUPPORTED_CATEGORIES,
    JuiceShopGroundTruthError,
    build_baseline_ground_truth,
    build_juice_shop_ground_truth,
)

_MANIFEST_FIELDS = {
    "ground_truth_version", "target", "target_origin", "target_version_or_digest",
    "supported_cases", "unsupported_categories", "out_of_scope_categories",
}

_CASE_FIELDS = {
    "case_id", "category", "detector_capability", "expected_detection",
    "expected_observation", "expected_severity", "evidence_requirement",
}


def _case(**overrides):
    case = {
        "case_id": "TEST-CASE-1",
        "category": "SECURITY_HEADER_PRESENCE",
        "detector_capability": "security_header_misconfiguration",
        "expected_detection": True,
        "expected_observation": "A header is missing.",
        "expected_severity": "medium",
        "evidence_requirement": {"affected_path": "/", "match_hint": "X-Test-Header"},
    }
    case.update(overrides)
    return case


def _negative_case(**overrides):
    case = _case(
        case_id="TEST-CASE-NEG",
        expected_detection=False,
        expected_observation="A header is present; no finding expected.",
        expected_severity=None,
    )
    case.update(overrides)
    return case


def _unsupported():
    return ["sql_injection", "executable_xss"]


def _out_of_scope():
    return ["brute_force", "destructive_methods"]


def _manifest_kwargs(**overrides):
    kwargs = {
        "target_origin": "http://localhost:3000",
        "target_version_or_digest": "sha256:" + "a" * 64,
        "supported_cases": [_case(), _negative_case()],
        "unsupported_categories": _unsupported(),
        "out_of_scope_categories": _out_of_scope(),
    }
    kwargs.update(overrides)
    return kwargs


# ---------------------------------------------------------------------------
# build_juice_shop_ground_truth -- success contract
# ---------------------------------------------------------------------------


class TestBuildSuccess:
    def test_001_exact_manifest_field_contract(self):
        manifest = build_juice_shop_ground_truth(**_manifest_kwargs())
        assert set(manifest.keys()) == _MANIFEST_FIELDS

    def test_002_ground_truth_version_is_one(self):
        manifest = build_juice_shop_ground_truth(**_manifest_kwargs())
        assert manifest["ground_truth_version"] == "1"

    def test_003_target_is_fixed_label(self):
        manifest = build_juice_shop_ground_truth(**_manifest_kwargs())
        assert manifest["target"] == "OWASP Juice Shop"

    def test_004_target_origin_echoed(self):
        manifest = build_juice_shop_ground_truth(**_manifest_kwargs(target_origin="http://localhost:3000"))
        assert manifest["target_origin"] == "http://localhost:3000"

    def test_005_target_version_or_digest_echoed(self):
        digest = "sha256:" + "b" * 64
        manifest = build_juice_shop_ground_truth(**_manifest_kwargs(target_version_or_digest=digest))
        assert manifest["target_version_or_digest"] == digest

    def test_006_exact_case_field_contract(self):
        manifest = build_juice_shop_ground_truth(**_manifest_kwargs())
        for case in manifest["supported_cases"]:
            assert set(case.keys()) == _CASE_FIELDS

    def test_007_case_count_preserved(self):
        manifest = build_juice_shop_ground_truth(**_manifest_kwargs())
        assert len(manifest["supported_cases"]) == 2

    def test_008_deterministic_output(self):
        kwargs = _manifest_kwargs()
        first = build_juice_shop_ground_truth(**kwargs)
        second = build_juice_shop_ground_truth(**kwargs)
        assert first == second

    def test_009_evidence_requirement_null_match_hint_preserved(self):
        manifest = build_juice_shop_ground_truth(
            **_manifest_kwargs(supported_cases=[
                _case(evidence_requirement={"affected_path": "/robots.txt", "match_hint": None}),
            ]),
        )
        assert manifest["supported_cases"][0]["evidence_requirement"]["match_hint"] is None

    def test_010_unsupported_categories_echoed(self):
        manifest = build_juice_shop_ground_truth(**_manifest_kwargs())
        assert manifest["unsupported_categories"] == _unsupported()

    def test_011_out_of_scope_categories_echoed(self):
        manifest = build_juice_shop_ground_truth(**_manifest_kwargs())
        assert manifest["out_of_scope_categories"] == _out_of_scope()


# ---------------------------------------------------------------------------
# Manifest-level validation
# ---------------------------------------------------------------------------


class TestManifestValidation:
    def test_012_blank_target_origin_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(**_manifest_kwargs(target_origin="   "))

    def test_013_non_string_target_origin_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(**_manifest_kwargs(target_origin=123))

    def test_014_blank_target_version_or_digest_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(**_manifest_kwargs(target_version_or_digest=""))

    def test_015_supported_cases_not_a_list_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(**_manifest_kwargs(supported_cases={"not": "a list"}))

    def test_016_empty_supported_cases_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(**_manifest_kwargs(supported_cases=[]))

    def test_017_empty_unsupported_categories_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(**_manifest_kwargs(unsupported_categories=[]))

    def test_018_unknown_unsupported_category_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(**_manifest_kwargs(unsupported_categories=["not_a_category"]))

    def test_019_duplicate_unsupported_category_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(
                **_manifest_kwargs(unsupported_categories=["sql_injection", "sql_injection"]),
            )

    def test_020_empty_out_of_scope_categories_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(**_manifest_kwargs(out_of_scope_categories=[]))

    def test_021_unknown_out_of_scope_category_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(**_manifest_kwargs(out_of_scope_categories=["not_a_category"]))

    def test_022_duplicate_out_of_scope_category_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(
                **_manifest_kwargs(out_of_scope_categories=["brute_force", "brute_force"]),
            )


# ---------------------------------------------------------------------------
# Supported-case validation
# ---------------------------------------------------------------------------


class TestCaseValidation:
    def test_023_missing_case_field_raises(self):
        bad_case = _case()
        del bad_case["expected_observation"]
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(**_manifest_kwargs(supported_cases=[bad_case]))

    def test_024_extra_case_field_raises(self):
        bad_case = _case(unexpected="x")
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(**_manifest_kwargs(supported_cases=[bad_case]))

    def test_025_blank_case_id_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(**_manifest_kwargs(supported_cases=[_case(case_id="")]))

    def test_026_unknown_category_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(**_manifest_kwargs(supported_cases=[_case(category="NOT_A_CATEGORY")]))

    def test_027_unknown_detector_capability_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(
                **_manifest_kwargs(supported_cases=[_case(detector_capability="sql_injection")]),
            )

    def test_028_non_bool_expected_detection_raises(self):
        for bad_value in (1, 0, "true", None):
            with pytest.raises(JuiceShopGroundTruthError):
                build_juice_shop_ground_truth(
                    **_manifest_kwargs(supported_cases=[_case(expected_detection=bad_value)]),
                )

    def test_029_blank_expected_observation_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(**_manifest_kwargs(supported_cases=[_case(expected_observation="  ")]))

    def test_030_positive_case_missing_severity_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(
                **_manifest_kwargs(supported_cases=[_case(expected_detection=True, expected_severity=None)]),
            )

    def test_031_negative_case_with_severity_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(
                **_manifest_kwargs(supported_cases=[
                    _case(expected_detection=False, expected_severity="low"),
                ]),
            )

    def test_032_unknown_severity_value_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(
                **_manifest_kwargs(supported_cases=[_case(expected_severity="extreme")]),
            )

    def test_033_duplicate_case_id_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(
                **_manifest_kwargs(supported_cases=[_case(case_id="DUP"), _case(case_id="DUP")]),
            )

    def test_034_malformed_evidence_requirement_missing_field_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(
                **_manifest_kwargs(supported_cases=[_case(evidence_requirement={"affected_path": "/"})]),
            )

    def test_035_malformed_evidence_requirement_extra_field_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(
                **_manifest_kwargs(supported_cases=[
                    _case(evidence_requirement={"affected_path": "/", "match_hint": None, "extra": "x"}),
                ]),
            )

    def test_036_evidence_requirement_path_not_absolute_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(
                **_manifest_kwargs(supported_cases=[
                    _case(evidence_requirement={"affected_path": "robots.txt", "match_hint": None}),
                ]),
            )

    def test_037_evidence_requirement_blank_match_hint_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(
                **_manifest_kwargs(supported_cases=[
                    _case(evidence_requirement={"affected_path": "/", "match_hint": "   "}),
                ]),
            )

    def test_038_evidence_requirement_not_a_mapping_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_juice_shop_ground_truth(**_manifest_kwargs(supported_cases=[_case(evidence_requirement="nope")]))


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_039_input_supported_cases_never_mutated(self):
        cases = [_case(), _negative_case()]
        snapshot = copy.deepcopy(cases)
        build_juice_shop_ground_truth(**_manifest_kwargs(supported_cases=cases))
        assert cases == snapshot

    def test_040_input_category_lists_never_mutated(self):
        unsupported = _unsupported()
        out_of_scope = _out_of_scope()
        build_juice_shop_ground_truth(**_manifest_kwargs(
            unsupported_categories=unsupported, out_of_scope_categories=out_of_scope,
        ))
        assert unsupported == _unsupported()
        assert out_of_scope == _out_of_scope()

    def test_041_mutating_returned_manifest_does_not_affect_next_call(self):
        kwargs = _manifest_kwargs()
        first = build_juice_shop_ground_truth(**kwargs)
        first["supported_cases"].append({"tampered": True})
        second = build_juice_shop_ground_truth(**kwargs)
        assert len(second["supported_cases"]) == 2


# ---------------------------------------------------------------------------
# build_baseline_ground_truth -- the real Block 15F-A0 baseline
# ---------------------------------------------------------------------------


class TestBaselineGroundTruth:
    def test_042_baseline_uses_fixed_digest(self):
        manifest = build_baseline_ground_truth()
        assert manifest["target_version_or_digest"] == BASELINE_TARGET_VERSION_OR_DIGEST
        assert manifest["target_version_or_digest"] == (
            "sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e"
        )

    def test_043_baseline_default_target_origin(self):
        manifest = build_baseline_ground_truth()
        assert manifest["target_origin"] == "http://localhost:3000"

    def test_044_baseline_target_origin_overridable(self):
        manifest = build_baseline_ground_truth(target_origin="http://localhost:3000/")
        assert manifest["target_origin"] == "http://localhost:3000/"

    def test_045_baseline_has_nine_cases(self):
        manifest = build_baseline_ground_truth()
        assert len(manifest["supported_cases"]) == 9

    def test_046_baseline_has_five_positive_cases(self):
        manifest = build_baseline_ground_truth()
        positive = [c for c in manifest["supported_cases"] if c["expected_detection"] is True]
        assert len(positive) == 5

    def test_047_baseline_has_four_negative_cases(self):
        manifest = build_baseline_ground_truth()
        negative = [c for c in manifest["supported_cases"] if c["expected_detection"] is False]
        assert len(negative) == 4

    def test_048_baseline_case_ids_are_exactly_expected(self):
        manifest = build_baseline_ground_truth()
        ids = {c["case_id"] for c in manifest["supported_cases"]}
        assert ids == {
            "JS-CSP-MISSING", "JS-ROBOTS-PRESENT", "JS-SECURITY-TXT-PRESENT",
            "JS-RISKY-METHODS-ADVERTISED", "JS-CORS-WILDCARD", "JS-SITEMAP-SPA-FALLBACK",
            "JS-XCTO-PRESENT", "JS-XFO-PRESENT", "JS-NO-REFLECTION",
        }

    def test_049_sitemap_case_preserved_as_negative_unfixed(self):
        manifest = build_baseline_ground_truth()
        sitemap_case = next(c for c in manifest["supported_cases"] if c["case_id"] == "JS-SITEMAP-SPA-FALLBACK")
        assert sitemap_case["expected_detection"] is False
        assert sitemap_case["evidence_requirement"]["affected_path"] == "/sitemap.xml"
        assert sitemap_case["detector_capability"] == "exposed_metadata"

    def test_050_baseline_never_includes_hsts_case(self):
        # The target is HTTP-only; ThreatTrace correctly skips the
        # HTTPS-only HSTS check, so no HSTS case may appear as a "missed"
        # ground-truth case.
        manifest = build_baseline_ground_truth()
        observations = " ".join(c["expected_observation"] for c in manifest["supported_cases"])
        assert "Strict-Transport-Security" not in observations
        assert "HSTS" not in observations

    def test_051_baseline_deterministic_across_calls(self):
        first = build_baseline_ground_truth()
        second = build_baseline_ground_truth()
        assert first == second

    def test_052_baseline_unsupported_categories_exact(self):
        manifest = build_baseline_ground_truth()
        assert set(manifest["unsupported_categories"]) == UNSUPPORTED_CATEGORIES

    def test_053_baseline_out_of_scope_categories_exact(self):
        manifest = build_baseline_ground_truth()
        assert set(manifest["out_of_scope_categories"]) == OUT_OF_SCOPE_CATEGORIES

    def test_054_baseline_passes_general_validation_shape(self):
        manifest = build_baseline_ground_truth()
        assert set(manifest.keys()) == _MANIFEST_FIELDS
        for case in manifest["supported_cases"]:
            assert set(case.keys()) == _CASE_FIELDS

    def test_055_mutating_baseline_result_does_not_affect_next_call(self):
        first = build_baseline_ground_truth()
        first["supported_cases"][0]["case_id"] = "TAMPERED"
        second = build_baseline_ground_truth()
        assert second["supported_cases"][0]["case_id"] != "TAMPERED"

    def test_056_baseline_detector_capabilities_are_all_recognized(self):
        manifest = build_baseline_ground_truth()
        for case in manifest["supported_cases"]:
            assert case["detector_capability"] in DETECTOR_CAPABILITIES

    def test_057_baseline_invalid_target_origin_raises(self):
        with pytest.raises(JuiceShopGroundTruthError):
            build_baseline_ground_truth(target_origin="")
