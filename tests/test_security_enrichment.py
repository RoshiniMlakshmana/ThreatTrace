"""Focused tests for core.security_enrichment -- the pure, deterministic
CWE/CVE -> ATT&CK enrichment binding (Block 15H-I).
"""

from __future__ import annotations

import pytest

from core.security_enrichment import (
    MAPPING_SOURCES,
    SecurityEnrichmentError,
    enrich_identifier,
    record_llm_proposed_enrichment,
)


class TestEnrichIdentifier:
    def test_001_source_provided_technique_is_confirmed_high_confidence(self):
        result = enrich_identifier(identifier_type="cwe", identifier="CWE-89", source_provided_technique="T1190")
        assert result["mapping_source"] == "source_provided"
        assert result["mapping_confidence"] == "high"
        assert result["human_review_required"] is False
        assert result["validation_status"] == "confirmed"
        assert result["attack_technique"] == "T1190"

    def test_002_local_dataset_mapping_is_medium_confidence_pending_review(self):
        result = enrich_identifier(identifier_type="cwe", identifier="CWE-89")
        assert result["mapping_source"] == "local_dataset"
        assert result["mapping_confidence"] == "medium"
        assert result["human_review_required"] is True
        assert result["validation_status"] == "candidate_pending_review"
        assert result["attack_technique"] == "T1190"

    def test_003_unknown_identifier_is_unmapped_never_guessed(self):
        result = enrich_identifier(identifier_type="cwe", identifier="CWE-99999")
        assert result["attack_technique"] is None
        assert result["mapping_source"] is None
        assert result["validation_status"] == "unmapped"

    def test_004_cve_identifier_type_never_uses_local_dataset(self):
        # The local dataset only maps CWE categories, never CVE numbers.
        result = enrich_identifier(identifier_type="cve", identifier="CVE-2026-0001")
        assert result["validation_status"] == "unmapped"

    def test_005_source_provided_always_wins_over_local_dataset(self):
        result = enrich_identifier(identifier_type="cwe", identifier="CWE-89", source_provided_technique="T9999.999")
        assert result["attack_technique"] == "T9999.999"
        assert result["mapping_source"] == "source_provided"

    def test_006_invalid_identifier_type_raises(self):
        with pytest.raises(SecurityEnrichmentError):
            enrich_identifier(identifier_type="owasp", identifier="A03:2021")

    def test_007_blank_identifier_raises(self):
        with pytest.raises(SecurityEnrichmentError):
            enrich_identifier(identifier_type="cwe", identifier="   ")

    def test_008_blank_source_provided_technique_raises(self):
        with pytest.raises(SecurityEnrichmentError):
            enrich_identifier(identifier_type="cwe", identifier="CWE-89", source_provided_technique="   ")

    def test_009_deterministic_given_same_input(self):
        first = enrich_identifier(identifier_type="cwe", identifier="CWE-79")
        second = enrich_identifier(identifier_type="cwe", identifier="CWE-79")
        assert first == second

    def test_010_unmapped_no_review_burden(self):
        result = enrich_identifier(identifier_type="cwe", identifier="CWE-99999")
        assert result["human_review_required"] is False


class TestLlmProposedEnrichment:
    def test_011_llm_proposal_always_low_confidence_pending_review(self):
        result = record_llm_proposed_enrichment(
            identifier_type="cwe", identifier="CWE-611", attack_technique="T1221",
            rationale="XML External Entity processing resembles template injection abuse patterns.",
        )
        assert result["mapping_source"] == "llm_proposed"
        assert result["mapping_confidence"] == "low"
        assert result["human_review_required"] is True
        assert result["validation_status"] == "candidate_pending_review"

    def test_012_never_promoted_to_confirmed_regardless_of_confident_rationale(self):
        result = record_llm_proposed_enrichment(
            identifier_type="cwe", identifier="CWE-611", attack_technique="T1221",
            rationale="This is absolutely certainly correct with 100% confidence.",
        )
        assert result["validation_status"] != "confirmed"
        assert result["mapping_confidence"] == "low"

    def test_013_blank_rationale_raises(self):
        with pytest.raises(SecurityEnrichmentError):
            record_llm_proposed_enrichment(identifier_type="cwe", identifier="CWE-611", attack_technique="T1221", rationale="  ")

    def test_014_blank_technique_raises(self):
        with pytest.raises(SecurityEnrichmentError):
            record_llm_proposed_enrichment(identifier_type="cwe", identifier="CWE-611", attack_technique="  ", rationale="x")

    def test_015_never_calls_an_llm_itself_pure_wrapper(self):
        # No network/subprocess access is even importable from this
        # module -- structural proof via its own declared symbols.
        import core.security_enrichment as module
        assert not hasattr(module, "requests")
        assert not hasattr(module, "subprocess")

    def test_016_mapping_sources_closed_vocabulary(self):
        assert MAPPING_SOURCES == {"source_provided", "local_dataset", "llm_proposed"}

    def test_017_exact_output_contract_fields(self):
        result = record_llm_proposed_enrichment(identifier_type="cwe", identifier="CWE-611", attack_technique="T1221", rationale="x")
        assert set(result.keys()) == {
            "enrichment_version", "enrichment_id", "identifier_type", "identifier", "attack_technique",
            "mapping_source", "mapping_confidence", "human_review_required", "validation_status", "rationale",
        }
