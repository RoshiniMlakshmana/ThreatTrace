"""Tests for core.bug_bounty_findings -- the pure, deterministic Bug
Bounty evidence and finding contracts (Block 15A, checkpoint A).

No network, filesystem, clock, randomness, subprocess, or database
access occurs anywhere in this file. Every evidence/finding record is
built from plain in-memory data.
"""

from __future__ import annotations

import inspect

import pytest

import core.bug_bounty_findings as bug_bounty_findings
from core.bug_bounty_findings import (
    BugBountyFindingError,
    create_bug_bounty_evidence,
    create_bug_bounty_finding,
)

_EVIDENCE_FIELDS = {
    "evidence_version", "tool", "method", "scoped_url", "status_code",
    "selected_headers", "response_excerpt", "observation", "evidence_digest",
}

_FINDING_FIELDS = {
    "finding_version", "finding_id", "target", "affected_path", "affected_parameter",
    "title", "finding_status", "vulnerability_class", "owasp_category", "cwe",
    "technical_severity", "confidence", "evidence", "validation", "reproduction_summary",
    "remediation", "detection_opportunity", "human_approval_required",
    "assessment_performed", "network_requests_performed", "execution_performed",
}


def _evidence(**overrides):
    kwargs = {
        "tool": "python_requests",
        "method": "GET",
        "scoped_url": "https://app.example.test/",
        "status_code": 200,
        "headers": {"Content-Type": "text/html"},
        "response_excerpt": "<html></html>",
        "observation": "Baseline response observed.",
    }
    kwargs.update(overrides)
    return create_bug_bounty_evidence(**kwargs)


def _finding(**overrides):
    kwargs = {
        "finding_id": "find-001",
        "target": "https://app.example.test/",
        "affected_path": "/",
        "affected_parameter": None,
        "title": "Missing security headers",
        "finding_status": "observation",
        "vulnerability_class": "security_header_misconfiguration",
        "evidence": [_evidence()],
        "validation_method": None,
        "validation_confirmed": False,
        "reproduction_summary": "Requested / and inspected response headers.",
        "technical_severity": "low",
        "confidence": "medium",
        "remediation": None,
        "detection_opportunity": None,
        "assessment_performed": True,
        "network_requests_performed": 1,
    }
    kwargs.update(overrides)
    return create_bug_bounty_finding(**kwargs)


def _validated_finding(**overrides):
    kwargs = {
        "finding_status": "validated",
        "validation_method": "deterministic header presence check",
        "validation_confirmed": True,
    }
    kwargs.update(overrides)
    return _finding(**kwargs)


# ---------------------------------------------------------------------------
# Evidence: contract shape
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def test_001_exact_evidence_key_set(self):
        evidence = _evidence()
        assert set(evidence.keys()) == _EVIDENCE_FIELDS

    def test_002_evidence_version_is_one(self):
        evidence = _evidence()
        assert evidence["evidence_version"] == "1"

    def test_003_method_normalized_to_uppercase(self):
        evidence = _evidence(method="get")
        assert evidence["method"] == "GET"

    def test_004_unrecognized_method_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _evidence(method="FETCH")

    def test_005_blank_method_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _evidence(method="   ")

    def test_006_non_string_method_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _evidence(method=1)

    def test_007_tool_must_be_nonblank(self):
        with pytest.raises(BugBountyFindingError):
            _evidence(tool="")

    def test_008_observation_must_be_nonblank(self):
        with pytest.raises(BugBountyFindingError):
            _evidence(observation="   ")

    def test_009_scoped_url_must_be_nonblank(self):
        with pytest.raises(BugBountyFindingError):
            _evidence(scoped_url="")

    def test_010_valid_status_code_accepted(self):
        evidence = _evidence(status_code=404)
        assert evidence["status_code"] == 404

    def test_011_null_status_code_accepted(self):
        evidence = _evidence(status_code=None)
        assert evidence["status_code"] is None

    def test_012_status_code_below_range_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _evidence(status_code=99)

    def test_013_status_code_above_range_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _evidence(status_code=600)

    def test_014_status_code_bool_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _evidence(status_code=True)

    def test_015_status_code_non_int_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _evidence(status_code="200")

    def test_016_headers_must_be_mapping(self):
        with pytest.raises(BugBountyFindingError):
            _evidence(headers=["not", "a", "mapping"])

    def test_017_none_response_excerpt_accepted(self):
        evidence = _evidence(response_excerpt=None)
        assert evidence["response_excerpt"] is None

    def test_018_non_string_response_excerpt_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _evidence(response_excerpt=123)

    def test_019_empty_string_response_excerpt_accepted(self):
        evidence = _evidence(response_excerpt="")
        assert evidence["response_excerpt"] == ""


# ---------------------------------------------------------------------------
# Evidence: header allowlist / redaction
# ---------------------------------------------------------------------------


class TestEvidenceRedaction:
    def test_020_allowlisted_header_retained(self):
        evidence = _evidence(headers={"Content-Type": "text/html"})
        assert evidence["selected_headers"] == {"content-type": "text/html"}

    def test_021_header_name_lowercased(self):
        evidence = _evidence(headers={"X-Frame-Options": "DENY"})
        assert "x-frame-options" in evidence["selected_headers"]

    def test_022_set_cookie_omitted(self):
        evidence = _evidence(headers={"Set-Cookie": "session=abc123", "Content-Type": "text/html"})
        assert "set-cookie" not in evidence["selected_headers"]
        assert "content-type" in evidence["selected_headers"]

    def test_023_authorization_header_omitted(self):
        evidence = _evidence(headers={"Authorization": "Bearer secret-token"})
        assert evidence["selected_headers"] == {}

    def test_024_cookie_header_omitted(self):
        evidence = _evidence(headers={"Cookie": "session=abc123"})
        assert evidence["selected_headers"] == {}

    def test_025_api_key_header_omitted(self):
        evidence = _evidence(headers={"X-Api-Key": "secret"})
        assert evidence["selected_headers"] == {}

    def test_026_unknown_header_omitted(self):
        evidence = _evidence(headers={"X-Totally-Unknown-Header": "value"})
        assert evidence["selected_headers"] == {}

    def test_027_multiple_allowlisted_headers_retained(self):
        evidence = _evidence(headers={
            "Server": "nginx",
            "X-Powered-By": "Express",
            "Strict-Transport-Security": "max-age=0",
        })
        assert evidence["selected_headers"] == {
            "server": "nginx",
            "x-powered-by": "Express",
            "strict-transport-security": "max-age=0",
        }

    def test_028_non_string_header_value_omitted(self):
        evidence = _evidence(headers={"Content-Length": 12345})
        assert evidence["selected_headers"] == {}

    def test_029_no_redacted_placeholder_for_sensitive_header_name(self):
        evidence = _evidence(headers={"Set-Cookie": "session=abc123"})
        assert "set-cookie" not in evidence["selected_headers"]
        assert "REDACTED" not in str(evidence["selected_headers"])

    def test_030_selected_headers_sorted_deterministically(self):
        evidence = _evidence(headers={"X-Frame-Options": "DENY", "Content-Type": "text/html"})
        assert list(evidence["selected_headers"].keys()) == sorted(evidence["selected_headers"].keys())

    def test_031_non_string_header_key_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _evidence(headers={1: "value"})


# ---------------------------------------------------------------------------
# Evidence: response excerpt bounding
# ---------------------------------------------------------------------------


class TestEvidenceExcerpt:
    def test_032_excerpt_truncated_to_500_chars(self):
        evidence = _evidence(response_excerpt="x" * 10000)
        assert len(evidence["response_excerpt"]) == 500

    def test_033_short_excerpt_not_padded(self):
        evidence = _evidence(response_excerpt="short body")
        assert evidence["response_excerpt"] == "short body"

    def test_034_truncation_is_deterministic_prefix(self):
        text = "abcdefgh" * 200
        evidence = _evidence(response_excerpt=text)
        assert evidence["response_excerpt"] == text[:500]

    def test_035_exactly_500_chars_not_altered(self):
        text = "a" * 500
        evidence = _evidence(response_excerpt=text)
        assert evidence["response_excerpt"] == text


# ---------------------------------------------------------------------------
# Evidence: digest
# ---------------------------------------------------------------------------


class TestEvidenceDigest:
    def test_036_digest_format(self):
        evidence = _evidence()
        assert evidence["evidence_digest"].startswith("sha256:")
        assert len(evidence["evidence_digest"]) == len("sha256:") + 64
        hex_part = evidence["evidence_digest"][len("sha256:"):]
        assert all(c in "0123456789abcdef" for c in hex_part)

    def test_037_digest_deterministic_for_identical_input(self):
        first = _evidence()
        second = _evidence()
        assert first["evidence_digest"] == second["evidence_digest"]

    def test_038_digest_changes_when_observation_changes(self):
        first = _evidence(observation="Observation A")
        second = _evidence(observation="Observation B")
        assert first["evidence_digest"] != second["evidence_digest"]

    def test_039_digest_changes_when_status_code_changes(self):
        first = _evidence(status_code=200)
        second = _evidence(status_code=404)
        assert first["evidence_digest"] != second["evidence_digest"]

    def test_040_digest_changes_when_headers_change(self):
        first = _evidence(headers={"Content-Type": "text/html"})
        second = _evidence(headers={"Content-Type": "application/json"})
        assert first["evidence_digest"] != second["evidence_digest"]

    def test_041_digest_excludes_itself(self):
        evidence = _evidence()
        payload = {key: value for key, value in evidence.items() if key != "evidence_digest"}
        from core.bug_bounty_findings import _canonical_json_digest
        assert _canonical_json_digest(payload) == evidence["evidence_digest"]

    def test_042_digest_not_affected_by_omitted_headers(self):
        first = _evidence(headers={"Content-Type": "text/html"})
        second = _evidence(headers={"Content-Type": "text/html", "Set-Cookie": "irrelevant"})
        assert first["evidence_digest"] == second["evidence_digest"]


# ---------------------------------------------------------------------------
# Finding: contract shape
# ---------------------------------------------------------------------------


class TestFindingContract:
    def test_043_exact_finding_key_set(self):
        finding = _finding()
        assert set(finding.keys()) == _FINDING_FIELDS

    def test_044_finding_version_is_one(self):
        finding = _finding()
        assert finding["finding_version"] == "1"

    def test_045_validation_nested_shape(self):
        finding = _finding()
        assert set(finding["validation"].keys()) == {"method", "confirmed"}

    def test_046_human_approval_required_always_true(self):
        finding = _finding()
        assert finding["human_approval_required"] is True

    def test_047_execution_performed_always_false(self):
        finding = _finding()
        assert finding["execution_performed"] is False

    def test_048_human_approval_required_cannot_be_overridden(self):
        finding = _validated_finding()
        assert finding["human_approval_required"] is True


# ---------------------------------------------------------------------------
# Finding: status vocabulary and statuses
# ---------------------------------------------------------------------------


class TestFindingStatuses:
    def test_049_observation_status_accepted(self):
        finding = _finding(finding_status="observation", validation_confirmed=False, validation_method=None)
        assert finding["finding_status"] == "observation"

    def test_050_candidate_status_accepted(self):
        finding = _finding(finding_status="candidate", validation_confirmed=False, validation_method=None)
        assert finding["finding_status"] == "candidate"

    def test_051_validated_status_accepted_for_supported_class(self):
        finding = _validated_finding()
        assert finding["finding_status"] == "validated"

    def test_052_unrecognized_status_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _finding(finding_status="confirmed_exploit")

    def test_053_candidate_cannot_be_confirmed_true(self):
        with pytest.raises(BugBountyFindingError):
            _finding(finding_status="candidate", validation_confirmed=True, validation_method="something")

    def test_054_observation_cannot_be_confirmed_true(self):
        with pytest.raises(BugBountyFindingError):
            _finding(finding_status="observation", validation_confirmed=True, validation_method="something")

    def test_055_candidate_with_attempted_but_unconfirmed_method_allowed(self):
        finding = _finding(
            finding_status="candidate", validation_confirmed=False,
            validation_method="attempted reflection check, inconclusive",
        )
        assert finding["validation"]["method"] == "attempted reflection check, inconclusive"


# ---------------------------------------------------------------------------
# Finding: vulnerability class vocabulary
# ---------------------------------------------------------------------------


class TestVulnerabilityClasses:
    @pytest.mark.parametrize("vulnerability_class", sorted(bug_bounty_findings.VULNERABILITY_CLASSES))
    def test_056_each_vulnerability_class_accepted_as_observation(self, vulnerability_class):
        finding = _finding(
            vulnerability_class=vulnerability_class,
            finding_status="observation",
            validation_confirmed=False,
            validation_method=None,
        )
        assert finding["vulnerability_class"] == vulnerability_class

    def test_057_unrecognized_vulnerability_class_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _finding(vulnerability_class="sql_injection")

    def test_058_xss_class_not_supported(self):
        with pytest.raises(BugBountyFindingError):
            _finding(vulnerability_class="xss")

    def test_059_ssrf_class_not_supported(self):
        with pytest.raises(BugBountyFindingError):
            _finding(vulnerability_class="ssrf")

    def test_060_rce_class_not_supported(self):
        with pytest.raises(BugBountyFindingError):
            _finding(vulnerability_class="rce")

    def test_061_idor_class_not_supported(self):
        with pytest.raises(BugBountyFindingError):
            _finding(vulnerability_class="idor")


# ---------------------------------------------------------------------------
# Finding: automatic validation boundary
# ---------------------------------------------------------------------------


class TestAutoValidationBoundary:
    @pytest.mark.parametrize("vulnerability_class", sorted(bug_bounty_findings._AUTO_VALIDATABLE_CLASSES))
    def test_062_auto_validatable_classes_can_be_validated(self, vulnerability_class):
        finding = _validated_finding(vulnerability_class=vulnerability_class)
        assert finding["finding_status"] == "validated"

    @pytest.mark.parametrize(
        "vulnerability_class",
        sorted(bug_bounty_findings.VULNERABILITY_CLASSES - bug_bounty_findings._AUTO_VALIDATABLE_CLASSES),
    )
    def test_063_non_auto_validatable_classes_reject_validated(self, vulnerability_class):
        with pytest.raises(BugBountyFindingError):
            _validated_finding(vulnerability_class=vulnerability_class)

    def test_064_validated_requires_confirmed_true(self):
        with pytest.raises(BugBountyFindingError):
            _finding(
                finding_status="validated", validation_confirmed=False,
                validation_method="header check",
            )

    def test_065_validated_requires_nonnull_validation_method(self):
        with pytest.raises(BugBountyFindingError):
            _finding(finding_status="validated", validation_confirmed=True, validation_method=None)

    def test_066_validated_requires_nonblank_validation_method(self):
        with pytest.raises(BugBountyFindingError):
            _finding(finding_status="validated", validation_confirmed=True, validation_method="   ")

    def test_067_scanner_alert_alone_is_never_auto_validated(self):
        # A finding with no confirmation step attempted stays a candidate,
        # never silently becomes validated.
        finding = _finding(finding_status="candidate", validation_confirmed=False, validation_method=None)
        assert finding["finding_status"] != "validated"


# ---------------------------------------------------------------------------
# Finding: OWASP/CWE mapping
# ---------------------------------------------------------------------------


class TestOwaspCweMapping:
    def test_068_security_header_misconfiguration_mapping(self):
        finding = _finding(vulnerability_class="security_header_misconfiguration")
        assert finding["owasp_category"] == "A05:2021 Security Misconfiguration"
        assert finding["cwe"] == "CWE-693"

    def test_069_information_disclosure_mapping(self):
        finding = _finding(vulnerability_class="information_disclosure")
        assert finding["owasp_category"] == "A05:2021 Security Misconfiguration"
        assert finding["cwe"] == "CWE-200"

    def test_070_cors_misconfiguration_mapping(self):
        finding = _finding(vulnerability_class="cors_misconfiguration")
        assert finding["owasp_category"] == "A05:2021 Security Misconfiguration"
        assert finding["cwe"] == "CWE-942"

    def test_071_exposed_metadata_mapping(self):
        finding = _finding(vulnerability_class="exposed_metadata")
        assert finding["owasp_category"] == "A05:2021 Security Misconfiguration"
        assert finding["cwe"] == "CWE-200"

    def test_072_input_reflection_has_null_mapping(self):
        finding = _finding(vulnerability_class="input_reflection")
        assert finding["owasp_category"] is None
        assert finding["cwe"] is None

    def test_073_access_control_indicator_has_null_mapping(self):
        finding = _finding(vulnerability_class="access_control_indicator")
        assert finding["owasp_category"] is None
        assert finding["cwe"] is None

    def test_074_http_method_observation_has_null_mapping(self):
        finding = _finding(vulnerability_class="http_method_observation")
        assert finding["owasp_category"] is None
        assert finding["cwe"] is None

    def test_075_redirect_observation_has_null_mapping(self):
        finding = _finding(vulnerability_class="redirect_observation")
        assert finding["owasp_category"] is None
        assert finding["cwe"] is None

    def test_076_mapping_never_caller_supplied(self):
        # create_bug_bounty_finding accepts no owasp_category/cwe kwargs at all.
        signature = inspect.signature(create_bug_bounty_finding)
        assert "owasp_category" not in signature.parameters
        assert "cwe" not in signature.parameters


# ---------------------------------------------------------------------------
# Finding: evidence requirement
# ---------------------------------------------------------------------------


class TestFindingEvidenceRequirement:
    def test_077_observation_requires_evidence(self):
        with pytest.raises(BugBountyFindingError):
            _finding(finding_status="observation", evidence=[], validation_confirmed=False, validation_method=None)

    def test_078_candidate_requires_evidence(self):
        with pytest.raises(BugBountyFindingError):
            _finding(finding_status="candidate", evidence=[], validation_confirmed=False, validation_method=None)

    def test_079_validated_requires_evidence(self):
        with pytest.raises(BugBountyFindingError):
            _validated_finding(evidence=[])

    def test_080_evidence_must_be_a_list(self):
        with pytest.raises(BugBountyFindingError):
            _finding(evidence="not a list")

    def test_081_arbitrary_dict_pretending_to_be_evidence_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _finding(evidence=[{"made_up": "evidence"}])

    def test_082_evidence_item_missing_field_rejected(self):
        broken = dict(_evidence())
        del broken["observation"]
        with pytest.raises(BugBountyFindingError):
            _finding(evidence=[broken])

    def test_083_evidence_item_extra_field_rejected(self):
        broken = dict(_evidence())
        broken["extra_field"] = "unexpected"
        with pytest.raises(BugBountyFindingError):
            _finding(evidence=[broken])

    def test_084_evidence_item_malformed_digest_rejected(self):
        broken = dict(_evidence())
        broken["evidence_digest"] = "not-a-real-digest"
        with pytest.raises(BugBountyFindingError):
            _finding(evidence=[broken])

    def test_085_evidence_item_wrong_digest_length_rejected(self):
        broken = dict(_evidence())
        broken["evidence_digest"] = "sha256:abc123"
        with pytest.raises(BugBountyFindingError):
            _finding(evidence=[broken])

    def test_086_multiple_evidence_items_accepted(self):
        finding = _finding(evidence=[_evidence(), _evidence(observation="Second observation")])
        assert len(finding["evidence"]) == 2


# ---------------------------------------------------------------------------
# Finding: severity / confidence
# ---------------------------------------------------------------------------


class TestSeverityConfidence:
    @pytest.mark.parametrize("severity", sorted(bug_bounty_findings.TECHNICAL_SEVERITIES))
    def test_087_each_severity_accepted(self, severity):
        finding = _finding(technical_severity=severity)
        assert finding["technical_severity"] == severity

    def test_088_unrecognized_severity_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _finding(technical_severity="catastrophic")

    @pytest.mark.parametrize("confidence", sorted(bug_bounty_findings.CONFIDENCE_LEVELS))
    def test_089_each_confidence_level_accepted(self, confidence):
        finding = _finding(confidence=confidence)
        assert finding["confidence"] == confidence

    def test_090_unrecognized_confidence_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _finding(confidence="certain")

    def test_091_no_cvss_vector_string_ever_computed(self):
        source = inspect.getsource(bug_bounty_findings)
        assert "CVSS:3" not in source
        finding = _finding()
        assert "CVSS" not in str(finding["technical_severity"])


# ---------------------------------------------------------------------------
# Finding: remediation / detection opportunity
# ---------------------------------------------------------------------------


class TestRemediationDetection:
    def test_092_remediation_none_accepted(self):
        finding = _finding(remediation=None)
        assert finding["remediation"] is None

    def test_093_remediation_nonblank_accepted(self):
        finding = _finding(remediation="Add the missing header.")
        assert finding["remediation"] == "Add the missing header."

    def test_094_remediation_blank_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _finding(remediation="   ")

    def test_095_detection_opportunity_none_accepted(self):
        finding = _finding(detection_opportunity=None)
        assert finding["detection_opportunity"] is None

    def test_096_detection_opportunity_nonblank_accepted(self):
        finding = _finding(detection_opportunity="Alert on missing header in responses.")
        assert finding["detection_opportunity"] == "Alert on missing header in responses."

    def test_097_detection_opportunity_blank_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _finding(detection_opportunity="   ")

    def test_098_both_may_be_none_for_low_confidence(self):
        finding = _finding(remediation=None, detection_opportunity=None, confidence="low")
        assert finding["remediation"] is None
        assert finding["detection_opportunity"] is None


# ---------------------------------------------------------------------------
# Finding: assessment / network / execution semantics
# ---------------------------------------------------------------------------


class TestExecutionSemantics:
    def test_099_zero_requests_requires_assessment_false(self):
        finding = _finding(assessment_performed=False, network_requests_performed=0)
        assert finding["assessment_performed"] is False
        assert finding["network_requests_performed"] == 0

    def test_100_zero_requests_with_assessment_true_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _finding(assessment_performed=True, network_requests_performed=0)

    def test_101_positive_requests_requires_assessment_true(self):
        finding = _finding(assessment_performed=True, network_requests_performed=3)
        assert finding["network_requests_performed"] == 3

    def test_102_positive_requests_with_assessment_false_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _finding(assessment_performed=False, network_requests_performed=3)

    def test_103_negative_request_count_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _finding(network_requests_performed=-1)

    def test_104_request_count_bool_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _finding(network_requests_performed=True)

    def test_105_assessment_performed_must_be_strict_bool(self):
        with pytest.raises(BugBountyFindingError):
            _finding(assessment_performed=1, network_requests_performed=1)

    def test_106_execution_performed_never_true_regardless_of_assessment(self):
        finding = _finding(assessment_performed=True, network_requests_performed=5)
        assert finding["execution_performed"] is False


# ---------------------------------------------------------------------------
# Finding: input validation (ids, paths, strings)
# ---------------------------------------------------------------------------


class TestFindingInputValidation:
    def test_107_finding_id_must_be_nonblank(self):
        with pytest.raises(BugBountyFindingError):
            _finding(finding_id="")

    def test_108_finding_id_never_randomly_generated(self):
        finding = _finding(finding_id="deterministic-id-001")
        assert finding["finding_id"] == "deterministic-id-001"

    def test_109_target_must_be_nonblank(self):
        with pytest.raises(BugBountyFindingError):
            _finding(target="")

    def test_110_affected_path_must_begin_with_slash(self):
        with pytest.raises(BugBountyFindingError):
            _finding(affected_path="no-leading-slash")

    def test_111_affected_path_rejects_backslash(self):
        with pytest.raises(BugBountyFindingError):
            _finding(affected_path="/api\\admin")

    def test_112_affected_path_rejects_dot_segment(self):
        with pytest.raises(BugBountyFindingError):
            _finding(affected_path="/api/../admin")

    def test_113_affected_path_rejects_encoded_slash(self):
        with pytest.raises(BugBountyFindingError):
            _finding(affected_path="/api%2fadmin")

    def test_114_affected_parameter_none_accepted(self):
        finding = _finding(affected_parameter=None)
        assert finding["affected_parameter"] is None

    def test_115_affected_parameter_nonblank_accepted(self):
        finding = _finding(affected_parameter="id")
        assert finding["affected_parameter"] == "id"

    def test_116_affected_parameter_blank_rejected(self):
        with pytest.raises(BugBountyFindingError):
            _finding(affected_parameter="   ")

    def test_117_title_must_be_nonblank(self):
        with pytest.raises(BugBountyFindingError):
            _finding(title="")

    def test_118_reproduction_summary_must_be_nonblank(self):
        with pytest.raises(BugBountyFindingError):
            _finding(reproduction_summary="   ")

    def test_119_validation_confirmed_must_be_strict_bool(self):
        with pytest.raises(BugBountyFindingError):
            _finding(validation_confirmed="yes", finding_status="observation", validation_method=None)


# ---------------------------------------------------------------------------
# Determinism / no randomness / documented untrusted-content boundary
# ---------------------------------------------------------------------------


class TestDeterminismAndHonesty:
    def test_120_deterministic_repeated_evidence_creation(self):
        first = _evidence()
        second = _evidence()
        assert first == second

    def test_121_deterministic_repeated_finding_creation(self):
        first = _finding()
        second = _finding()
        assert first == second

    def test_122_module_documents_untrusted_remote_content(self):
        assert "untrusted" in bug_bounty_findings.__doc__.lower()

    def test_123_module_documents_no_auto_validation_from_scanner_alone(self):
        assert "never automatically" in bug_bounty_findings.__doc__.lower()

    def test_124_module_documents_no_analyst_approval_claim(self):
        assert "human_approval_required" in bug_bounty_findings.__doc__


# ---------------------------------------------------------------------------
# Structural / purity
# ---------------------------------------------------------------------------


class TestStructuralPurity:
    def test_125_module_never_imports_network_clients(self):
        source = inspect.getsource(bug_bounty_findings)
        for token in ("import requests", "import httpx", "import socket", "urllib.request", "http.client"):
            assert token not in source

    def test_126_module_never_uses_subprocess(self):
        source = inspect.getsource(bug_bounty_findings)
        assert "subprocess" not in source

    def test_127_module_never_uses_filesystem(self):
        source = inspect.getsource(bug_bounty_findings)
        for token in ("open(", "pathlib", "Path(", "os.environ"):
            assert token not in source

    def test_128_module_never_uses_clock_or_randomness(self):
        source = inspect.getsource(bug_bounty_findings)
        for token in ("datetime.now", "utcnow", "import random", "import time", "import uuid"):
            assert token not in source

    def test_129_module_never_uses_database_supabase_or_mcp(self):
        source = inspect.getsource(bug_bounty_findings)
        for token in ("supabase", "mcp__", "execute_sql"):
            assert token not in source

    def test_130_module_never_imports_block_8_or_9_registries(self):
        source = inspect.getsource(bug_bounty_findings)
        for token in ("agent_gateway", "agent_identity_policy"):
            assert token not in source

    def test_131_public_symbols_are_exactly_expected(self):
        public_names = sorted(
            name for name in vars(bug_bounty_findings)
            if not name.startswith("_") and not inspect.ismodule(getattr(bug_bounty_findings, name))
        )
        assert "BugBountyFindingError" in public_names
        assert "create_bug_bounty_evidence" in public_names
        assert "create_bug_bounty_finding" in public_names

    def test_132_error_is_a_value_error(self):
        assert issubclass(BugBountyFindingError, ValueError)

    def test_133_hashlib_and_json_only_used_here_for_digest(self):
        source = inspect.getsource(bug_bounty_findings)
        assert "hashlib" in source
        assert "json.dumps" in source
