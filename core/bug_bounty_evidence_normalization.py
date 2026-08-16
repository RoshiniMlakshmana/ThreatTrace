"""Pure, deterministic Bug Bounty evidence normalization (Block 15G-CD).

This module answers exactly one question: *given a batch of already-
produced, tool-specific Bug Bounty results (the existing HTTP assessor's
own finding list, or a Nmap/Nuclei/ZAP/Burp `tool_result`), what does
each individual observation within them look like in one common,
tool-agnostic evidence contract?*

## A pure translator only -- it never reimplements a tool's own logic

This module performs no I/O of any kind, calls no adapter, evaluates no
policy, and never executes anything -- `execution_performed` is always
`False` in every result it can ever produce. It only reads already-
produced result dicts (shaped like `core.bug_bounty_assessment.
run_bug_bounty_assessment`'s own return value, or like
`adapters.bug_bounty_nmap`/`_nuclei`/`_zap`/`_burp`'s own `tool_result`
contract) and maps each observation within them into
`EVIDENCE_REQUIRED_FIELDS`. It never imports any of those modules --
following this project's established convention, it owns its own
private, minimal copy of the handful of fields it reads from each shape.

## No field is ever invented to complete the schema

Every normalized field either comes directly from the source
observation, is a direct closed-vocabulary translation of one already-
present source field (e.g. Nuclei's `"high"` severity -> this project's
own `"high"`), or is a deterministic derivation from already-present
structured data (e.g. `host`/`port`/`scheme` parsed from an already-
present `url`). A source tool that does not supply a concept at all
(Nmap has no notion of `confidence`) always leaves the corresponding
field `None` -- never a guess, never a default severity, never a
fabricated CVE/OWASP category.

## A bare-origin URL has a real path -- "/" -- never a guess

`_split_url` normalizes an HTTP(S) URL with no path segment at all
(`http://host`) to `path="/"`, identical to `http://host/` -- this is a
fact about URL semantics, not an inference, so it applies uniformly to
every caller (Nuclei/ZAP/Burp). A non-URL observation (Nmap's port-only
records, which never call `_split_url`) is unaffected and still carries
`path: None` -- "genuinely no path" and "root path" are kept distinct.

## A ZAP/Burp DAST observation's `vulnerability_class` is never left null

Unlike Nmap/Nuclei (which have no comparable structured signal),
ZAP/Burp alerts always carry a CWE. `_DAST_CWE_TO_VULNERABILITY_CLASS`
is a small, closed reverse mapping -- the exact inverse of only the
*unambiguous* entries in `core.bug_bounty_findings._OWASP_CWE_MAPPING`
(never imported; this module owns its own copy, per this file's
established convention) -- so a DAST alert's `vulnerability_class` is
either a defensible, already-established equivalence (`CWE-693` ->
`security_header_misconfiguration`, `CWE-942` -> `cors_misconfiguration`)
or the explicit generic `"dast_observation"` fallback. `CWE-200` is
deliberately excluded from the closed mapping (it is shared by two
distinct classes upstream, so reversing it would require guessing), and
title text is never used to infer a class. The generic fallback is
chosen specifically because it is **not** a member of
`core.bug_bounty_findings.VULNERABILITY_CLASSES` and cannot equal any
`core.juice_shop_ground_truth.DETECTOR_CAPABILITIES` value -- it can
never cause an accidental benchmark match.

## Timestamps are always caller-supplied

Like `core.pipeline_orchestrator.measure_duration_minutes`, this module
never calls a clock itself. `observed_at` is a required, caller-supplied
value (already captured by the caller's own clock) applied identically
to every evidence record's `first_observed`/`last_observed` in one
normalization call -- a single normalization pass has no way to know an
observation was already seen earlier, so the two are always equal here.
Distinguishing a genuinely repeated observation across multiple passes
is `core.bug_bounty_finding_correlation`'s job, not this module's.

## Evidence digest and evidence_id are content correlation, never authenticity

`evidence_id` (`"EV-"` + 16 lowercase hex characters) and
`evidence_digest` (`"sha256:"` + 64 lowercase hex characters) are both
derived from the exact same private, locally-owned canonical-JSON
SHA-256 digest over the record's own full content -- `evidence_id` is
simply that digest's first 16 hex characters, prefixed -- never imported
from `core.security_handoff`/`core.bug_bounty_findings`, following this
project's "every module owns its own copy of this exact validation
shape" convention. Deriving both from the same digest is deliberate: two
records can only ever share an `evidence_id` if their `evidence_digest`
also matches, i.e. they are genuinely identical content -- never merely
because they share a `source_tool`/rule/`url`/`title`. This matters in
practice: a real ZAP scan in this project's own live validation reported
the same rule at the same URL twice with different underlying evidence
text (two distinct timestamp occurrences), and correctly produced two
distinct `evidence_id`s rather than colliding into one and silently
losing an observation in `core.bug_bounty_finding_correlation`'s own
per-`evidence_id` indexing. Like every other digest in this project,
neither is ever a claim of cryptographic authenticity, remote-response
integrity, or non-repudiation -- content correlation only.

## Validation state reflects what the source tool itself asserted

`validation_state` is `"tool_confirmed"` only when the HTTP assessor's
own `validation.confirmed` was `True` (a real deterministic check that
module already performed); every other observation -- including every
Nmap/Nuclei/ZAP/Burp observation, and any HTTP assessor finding without
a confirmed validation -- is `"tool_asserted"` (the tool reported it, but
nothing beyond the tool's own report backs it) or `"unvalidated"`
(neither the source tool nor this module asserts anything). This module
never promotes an observation to a stronger validation state than its
source data actually supports, and never treats a passive scanner match
as equivalent to a deterministically confirmed header-presence check.

`BugBountyEvidenceNormalizationError` and `normalize_bug_bounty_evidence`
are this module's public symbols (plus `EVIDENCE_REQUIRED_FIELDS`,
`SOURCE_TOOLS`, `VALIDATION_STATES`, and `EVIDENCE_NORMALIZATION_VERSION`).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

EVIDENCE_NORMALIZATION_VERSION = "1"

SOURCE_TOOLS = frozenset({"http_assessor", "nmap", "nuclei", "zap", "burp_dast"})
VALIDATION_STATES = frozenset({"tool_confirmed", "tool_asserted", "unvalidated"})
TECHNICAL_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
CONFIDENCE_LEVELS = frozenset({"low", "medium", "high"})

EVIDENCE_REQUIRED_FIELDS = (
    "evidence_id", "source_tool", "source_observation_id", "observation_type",
    "host", "port", "scheme", "url", "path", "parameter", "method",
    "title", "description", "vulnerability_class", "cwe", "owasp_category", "cve",
    "technical_severity", "confidence", "service", "product", "version",
    "validation_state", "sanitized_evidence", "evidence_digest", "source_reference",
    "scope_reference", "first_observed", "last_observed", "execution_performed",
)

_FREE_TEXT_MAX_LENGTH = 512

# Private, per-tool severity/confidence vocabulary translations -- never
# shared with any adapter module. Unrecognized/absent values map to
# None, never a guessed default.
_NUCLEI_SEVERITY_MAP = {
    "critical": "critical", "high": "high", "medium": "medium", "low": "low",
    "info": None, "informational": None, "unknown": None,
}
_ZAP_BURP_RISK_MAP = {"high": "high", "medium": "medium", "low": "low", "informational": None, "information": None}
_ZAP_CONFIDENCE_MAP = {"high": "high", "medium": "medium", "low": "low", "confirmed": "high", "user confirmed": "high"}
_BURP_CONFIDENCE_MAP = {"certain": "high", "firm": "medium", "tentative": "low"}

# A DAST observation (ZAP/Burp) never carries this project's own
# `vulnerability_class` vocabulary directly -- only a CWE. This is a
# deliberately narrow, closed, non-fabricated reverse mapping: it is the
# exact inverse of the *unambiguous* entries in
# `core.bug_bounty_findings._OWASP_CWE_MAPPING` (never imported --
# following this module's own established "each module owns its own
# copy" convention) -- restricted to only the CWEs that map to exactly
# one `vulnerability_class` there. `CWE-200` is deliberately excluded:
# it is shared by two distinct classes there (`information_disclosure`
# and `exposed_metadata`), so reversing it would require guessing which
# one a bare CWE-200 DAST alert means -- this module never guesses.
# Every other DAST CWE (e.g. `CWE-264` for ZAP's own "Cross-Domain
# Misconfiguration", a broader access-control CWE distinct from
# `CWE-942`) intentionally has no entry and falls through to the
# generic `_DAST_GENERIC_VULNERABILITY_CLASS`/`_NUCLEI_GENERIC_
# VULNERABILITY_CLASS` below -- title text is never used to infer a
# class. Reused verbatim (not duplicated) for Nuclei's own CWE
# classification data below -- CWE-693 means "security header
# misconfiguration" regardless of which tool observed it; this is one
# real-world equivalence table, not two coincidentally-identical ones.
_DAST_CWE_TO_VULNERABILITY_CLASS: Mapping[str, str] = {
    "CWE-693": "security_header_misconfiguration",
    "CWE-942": "cors_misconfiguration",
}

# Used only when no closed CWE mapping above applies. Deliberately not a
# member of `core.bug_bounty_findings.VULNERABILITY_CLASSES` (and not
# equal to any `core.juice_shop_ground_truth.DETECTOR_CAPABILITIES`
# value) -- a generic fallback must never accidentally satisfy a
# benchmark case's `detector_capability` match. It shares its literal
# value with this module's own `observation_type: "dast_observation"`
# constant above by design: both mean "a real DAST tool observation
# without a confidently-mapped ThreatTrace-specific classification."
_DAST_GENERIC_VULNERABILITY_CLASS = "dast_observation"

# Same idea as _DAST_GENERIC_VULNERABILITY_CLASS, distinct literal value
# because Nuclei is architecturally a different observation_type
# ("known_pattern_match", template-signature matching -- not
# "dast_observation"). Also never a member of VULNERABILITY_CLASSES or
# DETECTOR_CAPABILITIES; a Nuclei match Nuclei's own classification data
# doesn't let us confidently bucket stays a generic, honestly-labeled
# observation rather than a guessed vulnerability class. CVE identifiers
# (when Nuclei supplies one) are preserved in the record's own `cve`
# field regardless of this fallback -- a missing vulnerability_class
# mapping never causes CVE evidence to be dropped.
_NUCLEI_GENERIC_VULNERABILITY_CLASS = "nuclei_template_match"


class BugBountyEvidenceNormalizationError(ValueError):
    """Raised when a supplied `source_results` entry, `scope_reference`,
    or `observed_at` is structurally invalid.

    Never raised because a source result contains zero observations, an
    unrecognized severity string (mapped to `None` instead), or a
    finding with `finding_status: "observation"` -- every one of those
    is a normal, successfully normalized result, not an error.
    """


def _raise(code: str, detail: str) -> None:
    raise BugBountyEvidenceNormalizationError(f"{code}: {detail}")


def _in_vocab(value: Any, vocabulary: frozenset[str]) -> bool:
    return isinstance(value, str) and value in vocabulary


def _clip(value: Any, *, max_length: int = _FREE_TEXT_MAX_LENGTH) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text[:max_length] if text else None


def _lookup(mapping: Mapping[str, str | None], raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    return mapping.get(raw.strip().lower())


def _split_url(url: str | None) -> tuple[str | None, str | None, int | None, str | None]:
    """Parse `url` into `(host, scheme, port, path)`. A bare-origin
    HTTP(S) URL (`http://host`, no path segment at all) has a genuine,
    well-defined path -- `"/"` -- per URL semantics, identical to
    `http://host/`; this is a fact about the URL, not a guess, so it is
    normalized to `"/"` here rather than left `None`. `None` is reserved
    for when there is genuinely no URL to derive a path from at all
    (e.g. Nmap's port-only observations, which never call this
    function). A non-HTTP(S) scheme's empty path is left `None` --
    the same "/" equivalence is only established for HTTP(S)."""
    if not isinstance(url, str) or not url.strip():
        return None, None, None, None
    parsed = urlsplit(url.strip())
    scheme = parsed.scheme or None
    path = parsed.path or None
    if path is None and scheme in ("http", "https"):
        path = "/"
    return parsed.hostname, scheme, parsed.port, path


def _canonical_digest_hex(value: Any, length: int | None = None) -> str:
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return digest[:length] if length else digest


def _finalize(record: dict[str, Any]) -> dict[str, Any]:
    # evidence_id and evidence_digest are both derived from the exact
    # same full-content digest -- evidence_id is just its first 16 hex
    # characters, prefixed. This is deliberate: two records can only
    # ever share an evidence_id if their evidence_digest also matches
    # (i.e. they are genuinely identical content), never merely because
    # they share a source_tool/rule/url/title. Two distinct ZAP alerts
    # for the same rule at the same URL with different evidence text
    # (a real, observed case -- see this module's test suite) therefore
    # always get distinct evidence_ids, so
    # core.bug_bounty_finding_correlation's own per-evidence_id indexing
    # can never silently collapse two genuinely different observations.
    digest_payload = {key: record[key] for key in EVIDENCE_REQUIRED_FIELDS if key not in ("evidence_id", "evidence_digest")}
    full_digest = _canonical_digest_hex(digest_payload)
    record["evidence_digest"] = "sha256:" + full_digest
    record["evidence_id"] = "EV-" + full_digest[:16]
    return record


# ---------------------------------------------------------------------------
# Per-source-tool normalizers -- each reads only the fixed, minimal set
# of fields its own adapter/module contract actually produces.
# ---------------------------------------------------------------------------


def _normalize_http_assessor_result(
    result: Any, *, scope_reference: str, observed_at: Any,
) -> list[dict[str, Any]]:
    if not isinstance(result, Mapping):
        _raise("INVALID_SOURCE_RESULT", "http_assessor result must be a mapping")
    findings = result.get("findings")
    if not isinstance(findings, list):
        _raise("INVALID_SOURCE_RESULT", "http_assessor result['findings'] must be a list")

    records: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        url = finding.get("target") if isinstance(finding.get("target"), str) else None
        host, scheme, port, _ = _split_url(url)
        evidence_list = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
        first_evidence = evidence_list[0] if evidence_list and isinstance(evidence_list[0], Mapping) else {}
        method = _clip(first_evidence.get("method"), max_length=16)
        sanitized_evidence = _clip(first_evidence.get("observation"))
        source_reference = first_evidence.get("evidence_digest") if isinstance(first_evidence.get("evidence_digest"), str) else None

        validation = finding.get("validation") if isinstance(finding.get("validation"), Mapping) else {}
        validation_state = "tool_confirmed" if validation.get("confirmed") is True else "unvalidated"

        technical_severity = finding.get("technical_severity")
        if not _in_vocab(technical_severity, TECHNICAL_SEVERITIES):
            technical_severity = None
        confidence = finding.get("confidence")
        if not _in_vocab(confidence, CONFIDENCE_LEVELS):
            confidence = None

        source_observation_id = finding.get("finding_id") if isinstance(finding.get("finding_id"), str) else None
        title = _clip(finding.get("title"))

        record = {
            "evidence_id": None,  # set in _finalize from the full-content digest
            "source_tool": "http_assessor",
            "source_observation_id": source_observation_id,
            "observation_type": "web_configuration",
            "host": host, "port": port, "scheme": scheme, "url": url,
            "path": _clip(finding.get("affected_path"), max_length=256),
            "parameter": _clip(finding.get("affected_parameter"), max_length=128),
            "method": method,
            "title": title,
            "description": None,
            "vulnerability_class": _clip(finding.get("vulnerability_class"), max_length=128),
            "cwe": _clip(finding.get("cwe"), max_length=32),
            "owasp_category": _clip(finding.get("owasp_category"), max_length=128),
            "cve": [],
            "technical_severity": technical_severity,
            "confidence": confidence,
            "service": None, "product": None, "version": None,
            "validation_state": validation_state,
            "sanitized_evidence": sanitized_evidence,
            "source_reference": source_reference,
            "scope_reference": scope_reference,
            "first_observed": observed_at,
            "last_observed": observed_at,
            "execution_performed": False,
        }
        records.append(_finalize(record))
    return records


def _normalize_nmap_result(result: Any, *, scope_reference: str, observed_at: Any) -> list[dict[str, Any]]:
    if not isinstance(result, Mapping):
        _raise("INVALID_SOURCE_RESULT", "nmap result must be a mapping")
    observations = result.get("observations")
    if not isinstance(observations, list):
        _raise("INVALID_SOURCE_RESULT", "nmap result['observations'] must be a list")
    target_host = result.get("target") if isinstance(result.get("target"), str) else None
    evidence_refs = result.get("evidence_references") if isinstance(result.get("evidence_references"), list) else []
    source_reference = evidence_refs[0] if evidence_refs and isinstance(evidence_refs[0], str) else None

    records: list[dict[str, Any]] = []
    for obs in observations:
        if not isinstance(obs, Mapping):
            continue
        port = obs.get("port") if isinstance(obs.get("port"), int) and not isinstance(obs.get("port"), bool) else None
        service = _clip(obs.get("service"), max_length=64)
        state = _clip(obs.get("state"), max_length=32)
        protocol = _clip(obs.get("protocol"), max_length=16)
        title = None
        if port is not None:
            title_parts = [f"Port {port}/{protocol or 'tcp'} {state or 'observed'}"]
            if service:
                title_parts.append(f"({service})")
            title = " ".join(title_parts)

        record = {
            "evidence_id": None,  # set in _finalize from the full-content digest
            "source_tool": "nmap",
            "source_observation_id": str(port) if port is not None else None,
            "observation_type": "service",
            "host": target_host, "port": port, "scheme": None, "url": None,
            "path": None, "parameter": None, "method": None,
            "title": title,
            "description": None,
            "vulnerability_class": None, "cwe": None, "owasp_category": None, "cve": [],
            "technical_severity": None, "confidence": None,
            "service": service, "product": _clip(obs.get("product"), max_length=128),
            "version": _clip(obs.get("version"), max_length=64),
            "validation_state": "tool_asserted",
            "sanitized_evidence": None,
            "source_reference": source_reference,
            "scope_reference": scope_reference,
            "first_observed": observed_at,
            "last_observed": observed_at,
            "execution_performed": False,
        }
        records.append(_finalize(record))
    return records


def _normalize_nuclei_result(result: Any, *, scope_reference: str, observed_at: Any) -> list[dict[str, Any]]:
    if not isinstance(result, Mapping):
        _raise("INVALID_SOURCE_RESULT", "nuclei result must be a mapping")
    observations = result.get("observations")
    if not isinstance(observations, list):
        _raise("INVALID_SOURCE_RESULT", "nuclei result['observations'] must be a list")
    evidence_refs = result.get("evidence_references") if isinstance(result.get("evidence_references"), list) else []
    source_reference = evidence_refs[0] if evidence_refs and isinstance(evidence_refs[0], str) else None

    records: list[dict[str, Any]] = []
    for obs in observations:
        if not isinstance(obs, Mapping):
            continue
        url = obs.get("target") if isinstance(obs.get("target"), str) else None
        host, scheme, port, path = _split_url(url)
        classification = obs.get("classification") if isinstance(obs.get("classification"), Mapping) else {}
        cwe_list = classification.get("cwe_id") if isinstance(classification.get("cwe_id"), list) else None
        cve_list = classification.get("cve_id") if isinstance(classification.get("cve_id"), list) else []
        cwe = _clip(cwe_list[0], max_length=32) if cwe_list else None
        template_id = obs.get("template_id") if isinstance(obs.get("template_id"), str) else None
        title = _clip(obs.get("title"))
        vulnerability_class = _DAST_CWE_TO_VULNERABILITY_CLASS.get(cwe, _NUCLEI_GENERIC_VULNERABILITY_CLASS)

        record = {
            "evidence_id": None,  # set in _finalize from the full-content digest
            "source_tool": "nuclei",
            "source_observation_id": template_id,
            "observation_type": "known_pattern_match",
            "host": host, "port": port, "scheme": scheme, "url": url, "path": path,
            "parameter": None, "method": None,
            "title": title,
            "description": None,
            "vulnerability_class": vulnerability_class,
            "cwe": cwe, "owasp_category": None,
            "cve": [str(item) for item in cve_list if isinstance(item, str)] if cve_list else [],
            "technical_severity": _lookup(_NUCLEI_SEVERITY_MAP, obs.get("severity")),
            "confidence": None,
            "service": None, "product": None, "version": None,
            "validation_state": "tool_asserted",
            "sanitized_evidence": None,
            "source_reference": source_reference,
            "scope_reference": scope_reference,
            "first_observed": observed_at,
            "last_observed": observed_at,
            "execution_performed": False,
        }
        records.append(_finalize(record))
    return records


def _normalize_dast_observations(
    result: Any, *, source_tool: str, scope_reference: str, observed_at: Any, risk_field: str, confidence_map: Mapping[str, str | None],
) -> list[dict[str, Any]]:
    if not isinstance(result, Mapping):
        _raise("INVALID_SOURCE_RESULT", f"{source_tool} result must be a mapping")
    observations = result.get("observations")
    if not isinstance(observations, list):
        _raise("INVALID_SOURCE_RESULT", f"{source_tool} result['observations'] must be a list")

    records: list[dict[str, Any]] = []
    for obs in observations:
        if not isinstance(obs, Mapping):
            continue
        url = obs.get("url") if isinstance(obs.get("url"), str) else None
        host, scheme, port, url_path = _split_url(url)
        path = _clip(obs.get("path"), max_length=256) or url_path
        rule_id = _clip(obs.get("rule_id"), max_length=64)
        title = _clip(obs.get("title"))
        source_reference = obs.get("evidence_reference") if isinstance(obs.get("evidence_reference"), str) else None
        cwe = _clip(obs.get("cwe"), max_length=32)
        vulnerability_class = _DAST_CWE_TO_VULNERABILITY_CLASS.get(cwe, _DAST_GENERIC_VULNERABILITY_CLASS)

        record = {
            "evidence_id": None,  # set in _finalize from the full-content digest
            "source_tool": source_tool,
            "source_observation_id": rule_id,
            "observation_type": "dast_observation",
            "host": host, "port": port, "scheme": scheme, "url": url, "path": path,
            "parameter": _clip(obs.get("parameter"), max_length=128),
            "method": _clip(obs.get("method"), max_length=16),
            "title": title,
            "description": None,
            "vulnerability_class": vulnerability_class,
            "cwe": cwe,
            "owasp_category": _clip(obs.get("owasp_category"), max_length=128),
            "cve": [],
            "technical_severity": _lookup(_ZAP_BURP_RISK_MAP, obs.get(risk_field)),
            "confidence": _lookup(confidence_map, obs.get("confidence")),
            "service": None, "product": None, "version": None,
            "validation_state": "tool_asserted",
            "sanitized_evidence": _clip(obs.get("sanitized_evidence")),
            "source_reference": source_reference,
            "scope_reference": scope_reference,
            "first_observed": observed_at,
            "last_observed": observed_at,
            "execution_performed": False,
        }
        records.append(_finalize(record))
    return records


_NORMALIZERS = {
    "http_assessor": _normalize_http_assessor_result,
    "nmap": _normalize_nmap_result,
    "nuclei": _normalize_nuclei_result,
    "zap": lambda result, *, scope_reference, observed_at: _normalize_dast_observations(
        result, source_tool="zap", scope_reference=scope_reference, observed_at=observed_at,
        risk_field="risk", confidence_map=_ZAP_CONFIDENCE_MAP,
    ),
    "burp_dast": lambda result, *, scope_reference, observed_at: _normalize_dast_observations(
        result, source_tool="burp_dast", scope_reference=scope_reference, observed_at=observed_at,
        risk_field="risk", confidence_map=_BURP_CONFIDENCE_MAP,
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def normalize_bug_bounty_evidence(*, source_results: Any, scope_reference: Any, observed_at: Any) -> list[dict[str, Any]]:
    """Deterministically normalize a batch of already-produced,
    tool-specific Bug Bounty results into a flat list of common-contract
    evidence records. Performs no I/O of any kind, executes nothing, and
    never calls any adapter or `core.bug_bounty_assessment` itself.

    `source_results` is required and keyword-only, and must be a list of
    mappings, each containing exactly `source_tool` (one of
    `SOURCE_TOOLS`) and `result` (the already-produced result this
    module reads -- for `"http_assessor"`, shaped like `core.
    bug_bounty_assessment.run_bug_bounty_assessment`'s own return value;
    for every other `source_tool`, shaped like that adapter's own
    `tool_result` contract). `scope_reference` must be a non-blank
    string (e.g. the analyst-approved target origin) and is echoed onto
    every record's `scope_reference` verbatim -- this module never
    derives scope itself. `observed_at` may be any value the caller's
    own clock produced (commonly a string or number); it is applied
    unchanged to every record's `first_observed`/`last_observed`.

    Returns a new list of dicts, each containing exactly the fields in
    `EVIDENCE_REQUIRED_FIELDS`. An `http_assessor` result with N findings
    yields N records; an adapter `tool_result` with N `observations`
    yields N records; a `tool_result` with zero observations (e.g. a
    `status: "tool_not_installed"`/`"unavailable"` result, or a clean
    Nuclei scan) yields zero records for that source -- this is a normal
    outcome, never an error.

    Neither `source_results` nor any nested value within it is ever
    mutated.

    Raises `BugBountyEvidenceNormalizationError` for a structurally
    invalid `source_results` entry (unrecognized `source_tool`,
    malformed `result` shape) or a blank `scope_reference`. Never raises
    because a source result reports zero observations, an unrecognized
    severity string, or an unconfirmed finding -- every one of those is
    a normal, successfully normalized (possibly empty, possibly
    `None`-heavy) result.
    """
    if not isinstance(source_results, list):
        _raise("INVALID_SOURCE_RESULTS", "source_results must be a list")
    if not isinstance(scope_reference, str) or not scope_reference.strip():
        _raise("INVALID_SCOPE_REFERENCE", "scope_reference must be a non-blank string")
    validated_scope_reference = scope_reference.strip()

    all_records: list[dict[str, Any]] = []
    for entry in source_results:
        if not isinstance(entry, Mapping) or set(entry) != {"source_tool", "result"}:
            _raise("INVALID_SOURCE_RESULTS", "each source_results entry must contain exactly source_tool/result")
        source_tool = entry.get("source_tool")
        if source_tool not in SOURCE_TOOLS:
            _raise("INVALID_SOURCE_RESULTS", "source_tool must be a recognized value")
        normalizer = _NORMALIZERS[source_tool]
        all_records.extend(
            normalizer(entry.get("result"), scope_reference=validated_scope_reference, observed_at=observed_at),
        )

    return all_records
