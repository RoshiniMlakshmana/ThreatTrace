"""Pure, deterministic tamper-evident audit chain (Block 14, module 1 of 2).

This module answers exactly two questions:

1. *Given an already-existing event this project already produced (an
   investigation decision, an approval decision, a shadow-execution
   result, a security-policy decision, a Decision Binding result, a
   security-evaluation result, or an analyst-feedback record), what
   does a deterministic, SHA-256-linked audit record about it look
   like?* (`create_audit_record`)
2. *Given a supplied sequence of such records, and optionally an
   independently-supplied expected head digest, is that sequence
   internally structurally/digest/linkage self-consistent, and does its
   head match the supplied anchor?* (`verify_audit_chain`)

## The exact, strongest honest claim this module makes

    Given a supplied sequence of audit records, ThreatTrace can detect
    whether the supplied records are internally structurally, digest,
    and linkage consistent, and whether their supplied head matches an
    independently supplied expected head digest.

This module never claims, and is NOT:

- authenticated logging;
- a digital signature;
- proof of authorship or of who wrote a record;
- trusted timestamping (`occurred_at` is caller-supplied, never
  independently attested);
- tamper *prevention* (nothing stops a party from constructing an
  entirely new, internally self-consistent alternate chain from a fresh
  genesis record -- see the trust-anchor limitation below);
- immutable storage (this module persists nothing at all);
- non-repudiation;
- replay protection (verifying the same chain twice always returns the
  same result, since this module keeps no state between calls);
- proof that a supplied chain is *the* true historical chain.

### The trust-anchor limitation, stated plainly

A hash chain only detects alteration relative to some digest the
verifier already trusts. If a party rewrites an entire chain from a new
genesis record onward, the resulting alternate chain verifies as fully
internally consistent by every check this module can perform --
`internal_chain_valid` means only that the *supplied* sequence is
self-consistent, never that it is the one true history. The optional
`expected_head_digest` parameter to `verify_audit_chain` lets a caller
compare the chain's actual head against a digest they already trust
from some source *outside* this module; a match (`trusted_anchor_
verified: True`) proves only that the chain's head equals that
caller-supplied value -- it does not prove the caller's own anchor was
itself trustworthy. This module has no way to know that.

A record digest is a SHA-256 *content-correlation* digest only, exactly
like Block 10's own `binding_digest`/`argument_digest` -- it never
provides authentication or a signature.

This module does not:

- read the system clock, an environment variable, or the filesystem;
- generate a random value of any kind;
- perform any I/O of any kind (no Supabase, no MCP, no SQL, no RPC, no
  subprocess, no network, no tool execution);
- persist anything -- `audit_persisted` is always `False`;
- recompute, rerun, or reinterpret the event it records. It never calls
  Block 8/9/10/Mutation-Freeze, the AI Security Evaluation Lab, or
  Analyst Feedback creation -- `event_reference` is a caller-supplied,
  opaque reference only, never looked up, never verified against
  Supabase or any other live state;
- import Block 10's private canonicalization helpers. This module owns
  its own copy of the identical canonical-JSON-SHA-256 algorithm,
  exactly matching this project's established convention that each
  module owns its own copy of this exact validation shape rather than
  sharing one.

`create_audit_record` and `verify_audit_chain` are this module's only
public functions. `create_audit_record` raises `AuditRecordError` only
for structurally malformed input. `verify_audit_chain` raises
`AuditRecordError` only for malformed *top-level* API input (`records`
not a list, or a malformed `expected_head_digest`) -- a structurally
malformed *individual* record inside an otherwise-valid list is never
an exception, only a normal `"invalid"` verification result with
`INVALID_RECORD_STRUCTURE` evidence, so that a corrupted record can be
surfaced as a verification finding rather than crashing verification
itself.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

AUDIT_VERSION = "1"
VERIFICATION_VERSION = "1"

EVENT_TYPES = frozenset({
    "investigation_decision",
    "approval_decision",
    "shadow_execution_result",
    "security_policy_decision",
    "decision_binding_result",
    "security_evaluation_result",
    "analyst_feedback",
})

_EVENT_SUMMARY_ALLOWED_KEYS = frozenset({"outcome", "case_type", "error_category"})

_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

_RECORD_REQUIRED_FIELDS = (
    "audit_version",
    "sequence",
    "event_type",
    "event_reference",
    "event_summary",
    "occurred_at",
    "previous_record_digest",
    "audit_persisted",
    "execution_performed",
    "record_digest",
)

# ---------------------------------------------------------------------------
# Fixed, closed verification-evidence vocabulary. Every code corresponds
# to exactly one specific check verify_audit_chain performs; each is
# emitted at most once per verification call, in this fixed order,
# regardless of how many individual records triggered it.
# ---------------------------------------------------------------------------

_EVIDENCE_CODE_ORDER = (
    "INVALID_RECORD_STRUCTURE",
    "GENESIS_LINK_INVALID",
    "SEQUENCE_MISMATCH",
    "PREVIOUS_DIGEST_MISMATCH",
    "DIGEST_MISMATCH",
    "TRUSTED_ANCHOR_MISMATCH",
)

_EVIDENCE_MESSAGES = MappingProxyType({
    "INVALID_RECORD_STRUCTURE": (
        "One or more supplied records do not match the expected audit record structure."
    ),
    "GENESIS_LINK_INVALID": (
        "The first supplied record's sequence/previous_record_digest does not match genesis "
        "semantics (sequence 1, previous_record_digest null)."
    ),
    "SEQUENCE_MISMATCH": (
        "A supplied record's sequence does not immediately follow the preceding record's sequence."
    ),
    "PREVIOUS_DIGEST_MISMATCH": (
        "A supplied record's previous_record_digest does not match the preceding record's "
        "actual record_digest."
    ),
    "DIGEST_MISMATCH": (
        "Recomputing a supplied record's digest from its own stored fields did not match its "
        "stored record_digest."
    ),
    "TRUSTED_ANCHOR_MISMATCH": (
        "The supplied expected_head_digest does not match the chain's actual head digest, or "
        "the chain is not internally valid."
    ),
})


class AuditRecordError(ValueError):
    """Raised when a supplied audit-record-construction input, or a
    top-level `verify_audit_chain` API input, is structurally invalid.

    For `create_audit_record`, this is raised only for malformed input:
    a non-int/blank/negative `sequence`, a `sequence` inconsistent with
    genesis semantics, an unrecognized `event_type`, a blank/non-string
    `event_reference`, a malformed `event_summary`, a malformed/
    timezone-naive `occurred_at`, or a malformed `previous_record_digest`.

    For `verify_audit_chain`, this is raised only for malformed
    *top-level* input: a `records` value that is not a list, or a
    malformed `expected_head_digest`. A structurally invalid
    *individual* record inside an otherwise-valid list is never raised
    -- it is represented through `INVALID_RECORD_STRUCTURE` evidence in
    a normal `"invalid"` verification result instead.
    """


# ---------------------------------------------------------------------------
# Deterministic canonical-JSON argument/record digesting -- a private
# copy of the same strict algorithm core.decision_binding uses,
# deliberately not imported from that module (its helpers are private,
# and every module in this project owns its own copy of this exact
# validation shape rather than sharing one). Floats are never a
# legitimate value anywhere in the audit record contract, so they are
# rejected here simply by falling through to the "unsupported type"
# branch -- no separate NaN/Infinity special-casing is needed.
# ---------------------------------------------------------------------------


class _CanonicalizationError(Exception):
    """Internal-only signal that a value could not be canonicalized."""


def _canonicalize(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return value
    if value is None:
        return None
    if isinstance(value, Mapping):
        canonical: dict[str, Any] = {}
        for key, nested in value.items():
            if not isinstance(key, str):
                raise _CanonicalizationError("object keys must be strings")
            canonical[key] = _canonicalize(nested)
        return canonical
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    raise _CanonicalizationError(f"unsupported value type: {type(value).__name__}")


def _canonical_json_digest(value: Any) -> str | None:
    try:
        canonical = _canonicalize(value)
    except _CanonicalizationError:
        return None
    text = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Narrow, private input validators.
# ---------------------------------------------------------------------------


def _try_parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(iso_text)
        except ValueError:
            return None
    else:
        return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None

    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_occurred_at(value: Any) -> str:
    parsed = _try_parse_timestamp(value)
    if parsed is None:
        raise AuditRecordError("occurred_at must be an aware datetime or an aware ISO-8601 string")
    return _format_timestamp(parsed)


def _validate_digest_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _DIGEST_PATTERN.fullmatch(value):
        raise AuditRecordError(
            f"{field_name} must be a string of the form 'sha256:' followed by 64 lowercase hexadecimal characters"
        )
    return value


def _validate_previous_record_digest(value: Any) -> str | None:
    if value is None:
        return None
    return _validate_digest_string(value, "previous_record_digest")


def _validate_sequence(value: Any, is_genesis: bool) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AuditRecordError("sequence must be an int")
    if value < 1:
        raise AuditRecordError("sequence must be >= 1")
    if is_genesis and value != 1:
        raise AuditRecordError("sequence must be exactly 1 when previous_record_digest is null (a genesis record)")
    if not is_genesis and value < 2:
        raise AuditRecordError("sequence must be >= 2 when previous_record_digest is supplied")
    return value


def _validate_event_type(value: Any) -> str:
    if not isinstance(value, str) or value not in EVENT_TYPES:
        raise AuditRecordError("event_type must be one of the recognized event types")
    return value


def _validate_event_reference(value: Any) -> str:
    if not isinstance(value, str):
        raise AuditRecordError("event_reference must be a string")
    if not value.strip():
        raise AuditRecordError("event_reference must not be blank")
    return value


def _validate_event_summary(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise AuditRecordError("event_summary must be a mapping or null")
    unknown_keys = set(value) - _EVENT_SUMMARY_ALLOWED_KEYS
    if unknown_keys:
        raise AuditRecordError(f"event_summary contains unrecognized key(s): {', '.join(sorted(unknown_keys))}")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(item, str):
            raise AuditRecordError(f"event_summary[{key!r}] must be a string")
        if not item.strip():
            raise AuditRecordError(f"event_summary[{key!r}] must not be blank")
        result[key] = item
    return result


# ---------------------------------------------------------------------------
# Audit record construction
# ---------------------------------------------------------------------------


def create_audit_record(
    *,
    sequence: Any,
    event_type: Any,
    event_reference: Any,
    event_summary: Any,
    occurred_at: Any,
    previous_record_digest: Any,
) -> dict[str, Any]:
    """Deterministically construct one SHA-256-linked audit record about
    an already-existing event, without ever recomputing that event's
    own result.

    All six parameters are required and keyword-only, and none has a
    hidden default. `previous_record_digest` must be `None` for a
    genesis record or a string of the form `"sha256:"` followed by 64
    lowercase hexadecimal characters for every later record; this
    function never reads any external state to determine what the
    "correct" prior digest should be -- that is `verify_audit_chain`'s
    own, separate concern. `sequence` must be an `int` (never `bool`)
    that is exactly `1` when `previous_record_digest` is `None`, or
    `>= 2` when it is not. `event_type` must be one of the seven
    recognized event types. `event_reference` must be a non-blank
    string; it is a claimed, opaque reference only, never validated
    against Supabase or any other live state. `event_summary` must be
    `None` or a flat mapping containing only the optional keys
    `outcome`, `case_type`, `error_category`, each a non-blank string
    -- no nested mapping, list, number, or boolean value is ever
    accepted, and no key beyond these three is ever accepted. This
    function never decides whether a supplied `event_summary` is
    substantively correct for the referenced event -- only its narrow
    structural shape. `occurred_at` must be an aware `datetime` or
    aware ISO-8601 string; this function never reads the system clock
    itself.

    Returns a new dict containing exactly `audit_version` (always
    `"1"`), `sequence`, `event_type`, `event_reference`,
    `event_summary`, `occurred_at`, `previous_record_digest`,
    `audit_persisted` (always `False`), `execution_performed` (always
    `False`), and `record_digest`. `record_digest` is computed as
    `"sha256:" + SHA256(canonical JSON bytes)` over every other field
    above -- never a digest of itself -- and is never accepted as a
    caller-supplied input.

    Raises `AuditRecordError` for any structurally invalid input. The
    returned `event_summary`, when not `None`, is always a freshly
    constructed dict -- the caller's own mapping is never mutated and
    never aliased.
    """
    validated_previous_record_digest = _validate_previous_record_digest(previous_record_digest)
    validated_sequence = _validate_sequence(sequence, validated_previous_record_digest is None)
    validated_event_type = _validate_event_type(event_type)
    validated_event_reference = _validate_event_reference(event_reference)
    validated_event_summary = _validate_event_summary(event_summary)
    validated_occurred_at = _validate_occurred_at(occurred_at)

    payload = {
        "audit_version": AUDIT_VERSION,
        "sequence": validated_sequence,
        "event_type": validated_event_type,
        "event_reference": validated_event_reference,
        "event_summary": validated_event_summary,
        "occurred_at": validated_occurred_at,
        "previous_record_digest": validated_previous_record_digest,
        "audit_persisted": False,
        "execution_performed": False,
    }

    result = dict(payload)
    result["record_digest"] = _canonical_json_digest(payload)
    return result


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------


def _try_extract_record_fields(value: Any) -> dict[str, Any] | None:
    """Structurally validate one claimed audit record, returning its
    extracted fields or `None` -- never raises. Used only by
    `verify_audit_chain`, so a single corrupted record can be reported
    as `INVALID_RECORD_STRUCTURE` evidence rather than crashing
    verification.
    """
    if not isinstance(value, Mapping):
        return None
    if set(value) != set(_RECORD_REQUIRED_FIELDS):
        return None
    if value.get("audit_version") != AUDIT_VERSION:
        return None

    sequence = value["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        return None

    event_type = value["event_type"]
    if not isinstance(event_type, str) or event_type not in EVENT_TYPES:
        return None

    event_reference = value["event_reference"]
    if not isinstance(event_reference, str) or not event_reference.strip():
        return None

    event_summary = value["event_summary"]
    if event_summary is not None:
        if not isinstance(event_summary, Mapping):
            return None
        if set(event_summary) - _EVENT_SUMMARY_ALLOWED_KEYS:
            return None
        for key, item in event_summary.items():
            if not isinstance(item, str) or not item.strip():
                return None
        event_summary = dict(event_summary)

    occurred_at = value["occurred_at"]
    if _try_parse_timestamp(occurred_at) is None:
        return None

    previous_record_digest = value["previous_record_digest"]
    if previous_record_digest is not None:
        if not isinstance(previous_record_digest, str) or not _DIGEST_PATTERN.fullmatch(previous_record_digest):
            return None

    if value["audit_persisted"] is not False:
        return None
    if value["execution_performed"] is not False:
        return None

    record_digest = value["record_digest"]
    if not isinstance(record_digest, str) or not _DIGEST_PATTERN.fullmatch(record_digest):
        return None

    return {
        "sequence": sequence,
        "event_type": event_type,
        "event_reference": event_reference,
        "event_summary": event_summary,
        "occurred_at": occurred_at,
        "previous_record_digest": previous_record_digest,
        "audit_persisted": False,
        "execution_performed": False,
        "record_digest": record_digest,
    }


def _recompute_record_digest(fields: Mapping[str, Any]) -> str | None:
    payload = {
        "audit_version": AUDIT_VERSION,
        "sequence": fields["sequence"],
        "event_type": fields["event_type"],
        "event_reference": fields["event_reference"],
        "event_summary": fields["event_summary"],
        "occurred_at": fields["occurred_at"],
        "previous_record_digest": fields["previous_record_digest"],
        "audit_persisted": False,
        "execution_performed": False,
    }
    return _canonical_json_digest(payload)


def _evidence(code: str) -> dict[str, Any]:
    return {"code": code, "severity": "blocking", "message": _EVIDENCE_MESSAGES[code]}


def verify_audit_chain(
    *,
    records: Any,
    expected_head_digest: Any = None,
) -> dict[str, Any]:
    """Deterministically verify whether a supplied sequence of audit
    records is internally structurally/digest/linkage self-consistent,
    and, when an `expected_head_digest` is supplied, whether the
    chain's actual head matches it.

    `records` is required and keyword-only, and must be a list (may be
    empty). `expected_head_digest` is optional and keyword-only; when
    supplied it must be a valid digest string. Either being malformed
    raises `AuditRecordError` -- this is the only case in which this
    function raises. A structurally invalid *individual* record inside
    an otherwise-valid `records` list is never an exception; it is
    represented through `INVALID_RECORD_STRUCTURE` evidence in a
    normal `"invalid"` result instead.

    Returns a new dict containing exactly `verification_version`
    (always `"1"`), `verification_outcome` (`"valid"` or `"invalid"`),
    `internal_chain_valid`, `trusted_anchor_verified`, `record_count`,
    `head_digest`, `observed_evidence`, `execution_performed` (always
    `False`).

    `internal_chain_valid` means only that the supplied sequence is
    structurally, digest, and linkage self-consistent -- never that it
    is the true historical chain. `trusted_anchor_verified` is `None`
    when no `expected_head_digest` was supplied; `True` only when one
    was supplied, the chain is internally valid, and its actual head
    equals that anchor; `False` when one was supplied but the chain is
    invalid, empty, or its head differs. A `True` value never proves
    the caller's own anchor was itself trustworthy -- this function has
    no way to know that.

    `verification_outcome` is `"valid"` only when `internal_chain_valid`
    is `True` and `trusted_anchor_verified` is not `False`; `"invalid"`
    otherwise. `observed_evidence` accumulates every applicable code
    from the fixed, closed vocabulary (`INVALID_RECORD_STRUCTURE`,
    `GENESIS_LINK_INVALID`, `SEQUENCE_MISMATCH`,
    `PREVIOUS_DIGEST_MISMATCH`, `DIGEST_MISMATCH`,
    `TRUSTED_ANCHOR_MISMATCH`), each emitted at most once per call,
    regardless of how many individual records triggered it.

    Never mutates the caller-supplied `records` list or any record
    within it.
    """
    if not isinstance(records, list):
        raise AuditRecordError("records must be a list")

    validated_anchor: str | None = None
    if expected_head_digest is not None:
        validated_anchor = _validate_digest_string(expected_head_digest, "expected_head_digest")

    triggered_codes: set[str] = set()
    record_count = len(records)
    head_digest: str | None = None

    if record_count == 0:
        internal_chain_valid = True
    else:
        extracted = [_try_extract_record_fields(record) for record in records]

        if any(fields is None for fields in extracted):
            triggered_codes.add("INVALID_RECORD_STRUCTURE")
            internal_chain_valid = False
        else:
            internal_chain_valid = True

            first = extracted[0]
            if first["sequence"] != 1 or first["previous_record_digest"] is not None:
                triggered_codes.add("GENESIS_LINK_INVALID")
                internal_chain_valid = False

            for index in range(1, record_count):
                previous_fields = extracted[index - 1]
                current_fields = extracted[index]
                if current_fields["sequence"] != previous_fields["sequence"] + 1:
                    triggered_codes.add("SEQUENCE_MISMATCH")
                    internal_chain_valid = False
                if current_fields["previous_record_digest"] != previous_fields["record_digest"]:
                    triggered_codes.add("PREVIOUS_DIGEST_MISMATCH")
                    internal_chain_valid = False

            for fields in extracted:
                if _recompute_record_digest(fields) != fields["record_digest"]:
                    triggered_codes.add("DIGEST_MISMATCH")
                    internal_chain_valid = False

            head_digest = extracted[-1]["record_digest"]

    if validated_anchor is None:
        trusted_anchor_verified: bool | None = None
    elif internal_chain_valid and head_digest == validated_anchor:
        trusted_anchor_verified = True
    else:
        trusted_anchor_verified = False
        triggered_codes.add("TRUSTED_ANCHOR_MISMATCH")

    verification_outcome = "valid" if internal_chain_valid and trusted_anchor_verified is not False else "invalid"
    observed_evidence = [_evidence(code) for code in _EVIDENCE_CODE_ORDER if code in triggered_codes]

    return {
        "verification_version": VERIFICATION_VERSION,
        "verification_outcome": verification_outcome,
        "internal_chain_valid": internal_chain_valid,
        "trusted_anchor_verified": trusted_anchor_verified,
        "record_count": record_count,
        "head_digest": head_digest,
        "observed_evidence": observed_evidence,
        "execution_performed": False,
    }
