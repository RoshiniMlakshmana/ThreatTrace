"""Focused tests for core.detection_rule_validation (Block 15H-I)."""

from __future__ import annotations

import pytest

from core.detection_rule_validation import (
    MAX_CONTENT_LENGTH,
    VALIDATION_METHODS,
    DetectionRuleValidationError,
    validate_rule_syntax,
)

_VALID_SIGMA = "title: Test\ndetection:\n  selection:\n    field: value\n  condition: selection\n"
_VALID_SPL = 'index=main sourcetype="app:log" | stats count by user'
_VALID_KQL = "SecurityEvent | where EventID == 4625 | summarize count() by Account"
_VALID_YARA = 'rule ExampleRule {\n  condition:\n    filesize < 100KB\n}'


class TestValidateRuleSyntax:
    def test_001_valid_sigma_passes(self):
        result = validate_rule_syntax(rule_format="sigma", rule_content=_VALID_SIGMA)
        assert result["syntax_valid"] is True
        assert result["issues"] == []

    def test_002_valid_spl_passes(self):
        result = validate_rule_syntax(rule_format="splunk_spl", rule_content=_VALID_SPL)
        assert result["syntax_valid"] is True

    def test_003_valid_kql_passes(self):
        result = validate_rule_syntax(rule_format="sentinel_kql", rule_content=_VALID_KQL)
        assert result["syntax_valid"] is True

    def test_004_valid_yara_passes(self):
        result = validate_rule_syntax(rule_format="yara", rule_content=_VALID_YARA)
        assert result["syntax_valid"] is True

    def test_005_sigma_missing_detection_block_invalid(self):
        result = validate_rule_syntax(rule_format="sigma", rule_content="title: Test\n")
        assert result["syntax_valid"] is False
        assert any("detection" in issue for issue in result["issues"])

    def test_006_yara_missing_condition_invalid(self):
        result = validate_rule_syntax(rule_format="yara", rule_content="rule Test { strings: $a = \"x\" }")
        assert result["syntax_valid"] is False

    def test_007_spl_no_recognizable_command_invalid(self):
        result = validate_rule_syntax(rule_format="splunk_spl", rule_content="just some random text with no spl keywords")
        assert result["syntax_valid"] is False

    def test_008_kql_no_pipe_invalid(self):
        result = validate_rule_syntax(rule_format="sentinel_kql", rule_content="SecurityEvent")
        assert result["syntax_valid"] is False

    def test_009_unbalanced_braces_invalid(self):
        result = validate_rule_syntax(rule_format="yara", rule_content="rule Test { condition: true")
        assert result["syntax_valid"] is False
        assert any("brace" in issue for issue in result["issues"])

    def test_010_validation_method_always_structural_only(self):
        result = validate_rule_syntax(rule_format="sigma", rule_content=_VALID_SIGMA)
        assert result["validation_method"] == "structural_validation_only"
        assert VALIDATION_METHODS == {"structural_validation_only"}

    def test_011_never_claims_tested_or_validated(self):
        result = validate_rule_syntax(rule_format="sigma", rule_content=_VALID_SIGMA)
        assert "tested" not in result.values()
        assert "validated" not in result.values()

    def test_012_execution_performed_always_false(self):
        result = validate_rule_syntax(rule_format="yara", rule_content=_VALID_YARA)
        assert result["execution_performed"] is False

    def test_013_unrecognized_format_raises(self):
        with pytest.raises(DetectionRuleValidationError):
            validate_rule_syntax(rule_format="powershell", rule_content="x")

    def test_014_blank_content_raises(self):
        with pytest.raises(DetectionRuleValidationError):
            validate_rule_syntax(rule_format="sigma", rule_content="   ")

    def test_015_oversized_content_raises(self):
        with pytest.raises(DetectionRuleValidationError):
            validate_rule_syntax(rule_format="sigma", rule_content="x" * (MAX_CONTENT_LENGTH + 1))

    def test_016_dangerous_yaml_tag_flagged_for_sigma(self):
        result = validate_rule_syntax(
            rule_format="sigma", rule_content="detection:\n  condition: !!python/object:os.system {}",
        )
        assert result["syntax_valid"] is False
        assert any("unsafe" in issue for issue in result["issues"])

    def test_017_deterministic_given_same_input(self):
        first = validate_rule_syntax(rule_format="sigma", rule_content=_VALID_SIGMA)
        second = validate_rule_syntax(rule_format="sigma", rule_content=_VALID_SIGMA)
        assert first == second

    def test_018_content_never_executed_just_a_dangerous_looking_command_string(self):
        # A shell-looking string embedded in generic_rule content must
        # never be executed -- this module only inspects text.
        result = validate_rule_syntax(rule_format="sigma", rule_content=_VALID_SIGMA + "\n# rm -rf /\n")
        assert result["execution_performed"] is False

    def test_019_checked_content_length_matches(self):
        result = validate_rule_syntax(rule_format="sigma", rule_content=_VALID_SIGMA)
        assert result["checked_content_length"] == len(_VALID_SIGMA)
