"""Pure, deterministic normalized Threat Intelligence contract + corroboration
model (Block 15H-I).

This module answers exactly two questions:

1. *Given one already-produced, source-specific threat-intelligence
   record (from `adapters.threat_intel_*`, or any object shaped like a
   source's own normalized output), what does it look like in one
   common, source-agnostic contract?* (`validate_threat_intelligence_record`)
2. *Given a batch of already-normalized records, which of them are
   corroborated by another independent source, which stand alone, and
   which actively disagree with each other?* (`compute_corroboration`)

## No field is ever invented

Every field in `TI_RECORD_REQUIRED_FIELDS` either comes directly from
the source, or is left `None`/an empty list when the source does not
supply it. This module never infers a CVE, CWE, ATT&CK technique, or IOC
that was not already present in its input, and never upgrades a
source's own stated confidence.

## A single low-confidence post never becomes high-confidence truth

`compute_corroboration` is the only place `corroboration_state` is ever
assigned, and it is entirely mechanical: it groups already-normalized
records by shared identity (a common CVE, or -- absent a CVE -- a common
IOC), then classifies each group by how many *distinct source types*
support it and whether any of them is in the fixed `AUTHORITATIVE_SOURCES`
set (`cisa_kev`, `nvd_cve` -- official government/canonical vulnerability
databases, never LLM-decided). One public OSINT post about a CVE is
`"single_source"` (or `"unconfirmed"` if that source's own
`source_reliability`/`information_credibility` is itself `"low"`/
`"unknown"`) regardless of how confidently it reads. This module never
lets an LLM assign or override `corroboration_state` -- it is not an
input field this module ever reads from a caller-supplied record's
existing value; it is always recomputed from the batch.

## Telegram and public OSINT are untrusted evidence, never "the dark web"

`source_type: "telegram_public_osint"` is documented, and treated
throughout this module and its adapters, as **untrusted public/community
OSINT** -- the same trust tier as any other unauthenticated public feed,
never described as, or conflated with, dark-web-derived intelligence.
This module never authenticates, verifies, or fetches anything about a
source itself; `source_reliability`/`information_credibility` are always
caller-supplied assessments, never independently confirmed here.

## No I/O, no execution, ever

This module performs no network, filesystem, environment-variable,
subprocess, system-clock, or randomness access. `execution_performed` is
not a field this module produces at all -- it is a pure data-shape and
corroboration computation, never a claim of having fetched or executed
anything (that is `adapters.threat_intel_*`'s own, separate concern).

`ThreatIntelligenceError`, `validate_threat_intelligence_record`, and
`compute_corroboration` are this module's public symbols (plus its fixed
vocabulary constants and `TI_RECORD_REQUIRED_FIELDS`).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

TI_RECORD_VERSION = "1"

SOURCE_TYPES = frozenset({
    "cisa_kev", "nvd_cve", "epss", "taxii", "misp", "opencti",
    "public_osint", "telegram_public_osint", "manual",
})

# Official, canonical government/community vulnerability databases only --
# never an OSINT feed, never LLM-decided, never expanded without a new
# checkpoint's explicit review.
AUTHORITATIVE_SOURCES = frozenset({"cisa_kev", "nvd_cve"})

EXPLOITATION_STATUSES = frozenset({"unknown", "poc_available", "exploited_in_wild", "weaponized"})
CONFIDENCE_LEVELS = frozenset({"low", "medium", "high"})
CORROBORATION_STATES = frozenset({"unconfirmed", "single_source", "corroborated", "authoritative_source", "conflicting"})
RELIABILITY_LEVELS = frozenset({"high", "medium", "low", "unknown"})

_IOC_FIELDS = ("ip", "domain", "url", "file_hash")
_ATTACK_FIELDS = ("tactic", "technique", "subtechnique")

TI_RECORD_REQUIRED_FIELDS = (
    "intel_version", "intel_id", "source_type", "source_name", "source_reference",
    "title", "summary", "published_at", "modified_at", "observed_at",
    "cve", "cwe", "owasp", "affected_products", "affected_versions",
    "ioc", "actor", "campaign", "attack", "behavioral_indicators",
    "exploitation_status", "known_exploited", "epss_score",
    "confidence", "corroboration_state", "evidence_references",
    "source_reliability", "information_credibility", "limitations",
)


class ThreatIntelligenceError(ValueError):
    """Raised when a supplied threat-intelligence record or corroboration
    input is structurally invalid.

    Every message begins with one of a fixed set of stable codes,
    including `INVALID_RECORD`, `INVALID_IOC`, `INVALID_ATTACK`,
    `INVALID_RECORDS_BATCH`. These are deterministic structural checks
    only -- never raised because a record's `confidence` is `"low"`,
    because `known_exploited` is `False`, or because a batch contains
    conflicting records -- every one of those is a normal, successfully
    represented result, not an error condition.
    """


def _raise(code: str, detail: str) -> None:
    raise ThreatIntelligenceError(f"{code}: {detail}")


def _in_vocab(value: Any, vocabulary: frozenset[str]) -> bool:
    return isinstance(value, str) and value in vocabulary


def _optional_nonblank_string(value: Any, code: str, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        _raise(code, f"{field_name!r} must be null or a non-blank string")
    return value.strip()


def _string_list(value: Any, code: str, field_name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        _raise(code, f"{field_name!r} must be a list of non-blank strings")
    return list(value)


def _validate_ioc(value: Any) -> dict[str, list[str]]:
    if not isinstance(value, Mapping) or set(value) != set(_IOC_FIELDS):
        _raise("INVALID_IOC", "ioc must contain exactly ip/domain/url/file_hash")
    return {field: _string_list(value.get(field), "INVALID_IOC", f"ioc.{field}") for field in _IOC_FIELDS}


def _validate_attack(value: Any) -> dict[str, list[str]]:
    if not isinstance(value, Mapping) or set(value) != set(_ATTACK_FIELDS):
        _raise("INVALID_ATTACK", "attack must contain exactly tactic/technique/subtechnique")
    return {field: _string_list(value.get(field), "INVALID_ATTACK", f"attack.{field}") for field in _ATTACK_FIELDS}


def validate_threat_intelligence_record(*, record: Any) -> dict[str, Any]:
    """Deterministically validate and normalize one caller-supplied
    threat-intelligence record. Performs no I/O of any kind.

    `record` is required and keyword-only, and must be a mapping
    containing exactly the fields in `TI_RECORD_REQUIRED_FIELDS`.
    `source_type` must be one of `SOURCE_TYPES`. `cve`/`cwe`/`owasp`/
    `affected_products`/`affected_versions`/`behavioral_indicators`/
    `evidence_references`/`limitations` must each be a list of non-blank
    strings (possibly empty). `ioc` must contain exactly `ip`/`domain`/
    `url`/`file_hash`, each a string list. `attack` must contain exactly
    `tactic`/`technique`/`subtechnique`, each a string list.
    `exploitation_status` must be one of `EXPLOITATION_STATUSES`.
    `known_exploited` must be a bool. `epss_score` must be `None` or a
    float in `[0.0, 1.0]`. `confidence` must be one of
    `CONFIDENCE_LEVELS`. `corroboration_state` must be one of
    `CORROBORATION_STATES` (this function trusts a caller-supplied value
    here -- only `compute_corroboration` ever *derives* one; a record
    passed to this function alone is validated as-is). `source_reliability`/
    `information_credibility` must each be one of `RELIABILITY_LEVELS`.

    Returns a new, normalized dict. Never mutates `record`.

    Raises `ThreatIntelligenceError` for any structurally invalid field.
    Never raises because a record's confidence is low, because IOC/CVE
    lists are empty, or because `known_exploited` is `False`.
    """
    if not isinstance(record, Mapping) or set(record) != set(TI_RECORD_REQUIRED_FIELDS):
        _raise("INVALID_RECORD", "record must contain exactly the required threat-intelligence fields")

    if record.get("intel_version") != TI_RECORD_VERSION:
        _raise("INVALID_RECORD", "intel_version must be '1'")

    intel_id = record.get("intel_id")
    if not isinstance(intel_id, str) or not intel_id.strip():
        _raise("INVALID_RECORD", "intel_id must be a non-blank string")

    if not _in_vocab(record.get("source_type"), SOURCE_TYPES):
        _raise("INVALID_RECORD", "source_type must be a recognized value")
    source_name = record.get("source_name")
    if not isinstance(source_name, str) or not source_name.strip():
        _raise("INVALID_RECORD", "source_name must be a non-blank string")
    source_reference = record.get("source_reference")
    if not isinstance(source_reference, str) or not source_reference.strip():
        _raise("INVALID_RECORD", "source_reference must be a non-blank string")

    title = record.get("title")
    if not isinstance(title, str) or not title.strip():
        _raise("INVALID_RECORD", "title must be a non-blank string")
    summary = _optional_nonblank_string(record.get("summary"), "INVALID_RECORD", "summary")

    published_at = record.get("published_at")
    modified_at = record.get("modified_at")
    observed_at = record.get("observed_at")
    for value, field_name in ((published_at, "published_at"), (modified_at, "modified_at"), (observed_at, "observed_at")):
        if value is not None and not isinstance(value, str):
            _raise("INVALID_RECORD", f"{field_name!r} must be null or a string timestamp")

    cve = _string_list(record.get("cve"), "INVALID_RECORD", "cve")
    cwe = _string_list(record.get("cwe"), "INVALID_RECORD", "cwe")
    owasp = _string_list(record.get("owasp"), "INVALID_RECORD", "owasp")
    affected_products = _string_list(record.get("affected_products"), "INVALID_RECORD", "affected_products")
    affected_versions = _string_list(record.get("affected_versions"), "INVALID_RECORD", "affected_versions")

    ioc = _validate_ioc(record.get("ioc"))
    actor = _optional_nonblank_string(record.get("actor"), "INVALID_RECORD", "actor")
    campaign = _optional_nonblank_string(record.get("campaign"), "INVALID_RECORD", "campaign")
    attack = _validate_attack(record.get("attack"))
    behavioral_indicators = _string_list(record.get("behavioral_indicators"), "INVALID_RECORD", "behavioral_indicators")

    if not _in_vocab(record.get("exploitation_status"), EXPLOITATION_STATUSES):
        _raise("INVALID_RECORD", "exploitation_status must be a recognized value")
    known_exploited = record.get("known_exploited")
    if known_exploited is not True and known_exploited is not False:
        _raise("INVALID_RECORD", "known_exploited must be a bool")

    epss_score = record.get("epss_score")
    if epss_score is not None:
        if isinstance(epss_score, bool) or not isinstance(epss_score, (int, float)):
            _raise("INVALID_RECORD", "epss_score must be null or a number")
        if not (0.0 <= float(epss_score) <= 1.0):
            _raise("INVALID_RECORD", "epss_score must be within [0.0, 1.0]")
        epss_score = float(epss_score)

    if not _in_vocab(record.get("confidence"), CONFIDENCE_LEVELS):
        _raise("INVALID_RECORD", "confidence must be a recognized value")
    if not _in_vocab(record.get("corroboration_state"), CORROBORATION_STATES):
        _raise("INVALID_RECORD", "corroboration_state must be a recognized value")

    evidence_references = _string_list(record.get("evidence_references"), "INVALID_RECORD", "evidence_references")

    if not _in_vocab(record.get("source_reliability"), RELIABILITY_LEVELS):
        _raise("INVALID_RECORD", "source_reliability must be a recognized value")
    if not _in_vocab(record.get("information_credibility"), RELIABILITY_LEVELS):
        _raise("INVALID_RECORD", "information_credibility must be a recognized value")

    limitations = _string_list(record.get("limitations"), "INVALID_RECORD", "limitations")

    return {
        "intel_version": TI_RECORD_VERSION,
        "intel_id": intel_id.strip(),
        "source_type": record["source_type"],
        "source_name": source_name.strip(),
        "source_reference": source_reference.strip(),
        "title": title.strip(),
        "summary": summary,
        "published_at": published_at,
        "modified_at": modified_at,
        "observed_at": observed_at,
        "cve": cve,
        "cwe": cwe,
        "owasp": owasp,
        "affected_products": affected_products,
        "affected_versions": affected_versions,
        "ioc": ioc,
        "actor": actor,
        "campaign": campaign,
        "attack": attack,
        "behavioral_indicators": behavioral_indicators,
        "exploitation_status": record["exploitation_status"],
        "known_exploited": known_exploited,
        "epss_score": epss_score,
        "confidence": record["confidence"],
        "corroboration_state": record["corroboration_state"],
        "evidence_references": evidence_references,
        "source_reliability": record["source_reliability"],
        "information_credibility": record["information_credibility"],
        "limitations": limitations,
    }


# ---------------------------------------------------------------------------
# Corroboration model.
# ---------------------------------------------------------------------------


def _record_identity(record: Mapping[str, Any]) -> str:
    """The identity a record is grouped by: its first CVE if present,
    else its first non-empty IOC value, else its own intel_id (meaning
    it is never grouped with anything else)."""
    if record["cve"]:
        return "cve:" + record["cve"][0]
    for field in _IOC_FIELDS:
        values = record["ioc"][field]
        if values:
            return f"ioc:{field}:{values[0]}"
    return "intel_id:" + record["intel_id"]


def compute_corroboration(*, records: Any) -> list[dict[str, Any]]:
    """Deterministically recompute `corroboration_state` across a batch
    of already-normalized threat-intelligence records, grouping by
    shared identity (a common CVE, or -- absent one -- a common IOC).
    Performs no I/O of any kind.

    `records` is required and keyword-only, and must be a list of
    mappings each shaped like `validate_threat_intelligence_record`'s
    own output (re-validated here).

    For each identity group: a group of size 1 is `"unconfirmed"` if
    that record's own `source_reliability` or `information_credibility`
    is `"low"`/`"unknown"`, else `"single_source"`. A group of size 2+
    is `"conflicting"` if any two members disagree on `known_exploited`
    for the same identity; else `"authoritative_source"` if any member's
    `source_type` is in `AUTHORITATIVE_SOURCES`; else `"corroborated"`.
    This is the only function in this project that ever assigns
    `corroboration_state` -- it is never read from an LLM or from a
    single source's own self-reported value.

    Returns a new list of records (in the original order) with
    `corroboration_state` recomputed; every other field is preserved
    unchanged. Neither `records` nor any nested value is ever mutated.

    Raises `ThreatIntelligenceError` for a non-list `records` or any
    structurally invalid entry. Never raises because a group is
    `"conflicting"` or because every record is `"unconfirmed"`.
    """
    if not isinstance(records, list):
        _raise("INVALID_RECORDS_BATCH", "records must be a list")
    validated = [validate_threat_intelligence_record(record=item) for item in records]

    groups: dict[str, list[dict[str, Any]]] = {}
    for record in validated:
        groups.setdefault(_record_identity(record), []).append(record)

    updated: list[dict[str, Any]] = []
    for record in validated:
        group = groups[_record_identity(record)]
        if len(group) == 1:
            weak = record["source_reliability"] in ("low", "unknown") or record["information_credibility"] in ("low", "unknown")
            state = "unconfirmed" if weak else "single_source"
        else:
            exploited_values = {member["known_exploited"] for member in group}
            if len(exploited_values) > 1:
                state = "conflicting"
            elif any(member["source_type"] in AUTHORITATIVE_SOURCES for member in group):
                state = "authoritative_source"
            else:
                state = "corroborated"
        updated.append({**record, "corroboration_state": state})

    return updated
