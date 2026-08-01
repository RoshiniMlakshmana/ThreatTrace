"""Convert one already-selected Hayabusa `csv_timeline` row into an evidence
candidate suitable for submission to `core.evidence_cli`.

Scope, by design:

- Only analyst-selected `csv_timeline` rows are supported. `log_metrics` and
  `eid_metrics` rows are aggregate/statistical (log coverage, event
  frequency) rather than discrete observations, and are rejected here --
  they remain supporting context for a human/agent to reason about
  directly, not something this adapter converts into evidence.
- Real Hayabusa CSV column names are not assumed or hardcoded anywhere in
  this module (they are not documented in this repository). Any mapping
  from a normalized evidence field to a specific CSV column must be
  supplied explicitly by the caller via `field_aliases` -- this module
  never guesses, and never performs case-insensitive or approximate
  column matching.
- This adapter performs no file reading and no CSV parsing. It accepts an
  already-selected row (a plain mapping) and caller-supplied context.
- The entire original selected row is retained, unmodified, inside
  `details["hayabusa_row"]` -- no CSV column is ever silently discarded,
  and no column is ever promoted into a top-level field without an
  explicit alias.
- The returned dictionary is an *unnormalized* candidate. This adapter
  never calls `core.evidence_normalizer.normalize_evidence` itself --
  evidence normalization happens later, in the existing `/add-evidence`
  pipeline via `core.evidence_cli`.
- Source-trust assessment (`core.source_trust_policy`) happens later too,
  and is not performed here.
- Secret scanning remains the caller's responsibility (the same nested
  scan `/add-evidence` already performs before normalization); this
  adapter does not scan for secrets.
- No Supabase write occurs anywhere in this module.
- No MITRE ATT&CK mapping and no evidence hashing occur anywhere in this
  module: no `trust_level`, `confidence`, ATT&CK technique, evidence
  hash, or `integrity_verified` value is ever produced, because no trust
  judgment, confidence calculation, technique mapping, or integrity check
  has actually happened at this stage.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

_SUPPORTED_ANALYSIS_TYPES = frozenset({"csv_timeline"})

_ALIAS_TARGET_FIELDS = frozenset({
    "event_id",
    "host_name",
    "user_name",
    "process_name",
    "command_line",
    "ip_address",
    "file_hash",
    "observed_at",
})


class HayabusaEvidenceAdapterError(ValueError):
    """Raised when input to adapt_hayabusa_row() is structurally invalid."""


def _require_nonblank_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise HayabusaEvidenceAdapterError(f"{field_name} must be a string")
    stripped = value.strip()
    if not stripped:
        raise HayabusaEvidenceAdapterError(f"{field_name} must not be blank")
    return stripped


def _validate_source_location(value: Any) -> str:
    text = _require_nonblank_string(value, "source_location")
    normalized = text.replace("\\", "/")

    if normalized.startswith("//"):
        raise HayabusaEvidenceAdapterError("source_location must not be a UNC path")
    if normalized.startswith("/"):
        raise HayabusaEvidenceAdapterError("source_location must not be an absolute or rooted path")
    if len(text) >= 2 and text[1] == ":" and text[0].isalpha():
        raise HayabusaEvidenceAdapterError("source_location must not be drive-qualified or absolute")

    parts = normalized.split("/")
    if ".." in parts:
        raise HayabusaEvidenceAdapterError("source_location must not contain '..'")
    if "" in parts:
        raise HayabusaEvidenceAdapterError(
            "source_location must not contain empty path segments or end with a directory separator"
        )
    if not normalized.lower().endswith(".csv"):
        raise HayabusaEvidenceAdapterError("source_location must end with .csv")

    return normalized


def _validate_field_aliases(field_aliases: Any, row: Mapping[str, Any]) -> dict[str, str]:
    if field_aliases is None:
        return {}
    if not isinstance(field_aliases, Mapping):
        raise HayabusaEvidenceAdapterError("field_aliases must be a mapping")

    validated: dict[str, str] = {}
    used_columns: set[str] = set()

    for target_field, column_name in field_aliases.items():
        if target_field not in _ALIAS_TARGET_FIELDS:
            raise HayabusaEvidenceAdapterError(
                f"field_aliases key {target_field!r} is not a supported normalized field"
            )
        if not isinstance(column_name, str) or column_name.strip() == "":
            raise HayabusaEvidenceAdapterError(
                f"field_aliases[{target_field!r}] must be a non-empty string"
            )
        if column_name not in row:
            raise HayabusaEvidenceAdapterError(
                f"field_aliases[{target_field!r}] references column {column_name!r}, "
                "which is not present in the selected row"
            )
        if column_name in used_columns:
            raise HayabusaEvidenceAdapterError(
                f"CSV column {column_name!r} is aliased to more than one field"
            )
        used_columns.add(column_name)
        validated[target_field] = column_name

    return validated


def _copy_aliased_value(target_field: str, raw_value: Any) -> Any:
    if raw_value is None:
        return None
    if isinstance(raw_value, str) and raw_value.strip() == "":
        return None
    if target_field == "event_id":
        return str(raw_value)
    if target_field == "file_hash" and isinstance(raw_value, str):
        return raw_value.lower()
    return raw_value


def adapt_hayabusa_row(
    row: Mapping[str, Any],
    *,
    investigation_id: str,
    analysis_type: str,
    source_location: str,
    row_identifier: str,
    evidence_type: str,
    observed_at: str | None = None,
    supports_hypothesis: bool | None = None,
    field_aliases: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Adapt one already-selected Hayabusa csv_timeline row into an unnormalized
    evidence candidate.

    Only `analysis_type == "csv_timeline"` is supported; `log_metrics` and
    `eid_metrics` are rejected because their rows are aggregate/statistical,
    not discrete observations. Neither `row` nor `field_aliases` (nor any
    nested value within them) is ever mutated.

    Copies `event_id`, `host_name`, `user_name`, `process_name`,
    `command_line`, `ip_address`, `file_hash`, and `observed_at` only when
    explicitly aliased via `field_aliases` (or, for `observed_at` only,
    supplied directly) -- never guessed, never approximately matched. The
    complete original row is independently deep-copied into
    `details["hayabusa_row"]` so no column is ever discarded.

    Returns a new dict suitable for later submission to `core.evidence_cli`
    -- this function does not call `normalize_evidence`, does not assess
    source trust, does not scan for secrets, and does not write to Supabase.

    Raises HayabusaEvidenceAdapterError for any structurally invalid input:
    a non-mapping `row`, a blank/wrong-type required argument, an
    unsupported `analysis_type`, an invalid `source_location`, an invalid
    `field_aliases` shape or entry, or `observed_at` supplied both directly
    and via alias.
    """
    if not isinstance(row, Mapping):
        raise HayabusaEvidenceAdapterError("row must be a mapping")

    investigation_id = _require_nonblank_string(investigation_id, "investigation_id")
    analysis_type = _require_nonblank_string(analysis_type, "analysis_type")
    row_identifier = _require_nonblank_string(row_identifier, "row_identifier")
    evidence_type = _require_nonblank_string(evidence_type, "evidence_type")
    normalized_source_location = _validate_source_location(source_location)

    if analysis_type not in _SUPPORTED_ANALYSIS_TYPES:
        raise HayabusaEvidenceAdapterError(
            f"analysis_type must be one of {sorted(_SUPPORTED_ANALYSIS_TYPES)}, got {analysis_type!r}; "
            "aggregate metric types (log_metrics, eid_metrics) remain supporting context only, "
            "not evidence"
        )

    if observed_at is not None:
        if not isinstance(observed_at, str):
            raise HayabusaEvidenceAdapterError("observed_at must be a string or null")
        if observed_at.strip() == "":
            raise HayabusaEvidenceAdapterError("observed_at must not be blank when supplied")

    if supports_hypothesis is not None and not isinstance(supports_hypothesis, bool):
        raise HayabusaEvidenceAdapterError("supports_hypothesis must be true, false, or null")

    validated_aliases = _validate_field_aliases(field_aliases, row)

    if observed_at is not None and "observed_at" in validated_aliases:
        raise HayabusaEvidenceAdapterError(
            "observed_at must not be supplied both directly and via field_aliases"
        )

    observed_at_specified = observed_at is not None or "observed_at" in validated_aliases
    output_observed_at = observed_at

    aliased_values: dict[str, Any] = {}
    for target_field, column_name in validated_aliases.items():
        copied = _copy_aliased_value(target_field, row[column_name])
        if target_field == "observed_at":
            output_observed_at = copied
        else:
            aliased_values[target_field] = copied

    result: dict[str, Any] = {
        "investigation_id": investigation_id,
        "evidence_type": evidence_type,
        "source": "Hayabusa csv_timeline row",
        "source_type": "hayabusa",
        "source_identifier": row_identifier,
        "source_location": normalized_source_location,
        "assertion_type": "derived_fact",
        "supports_hypothesis": supports_hypothesis,
        "details": {"hayabusa_row": copy.deepcopy(dict(row))},
        "provenance": {
            "collector": "threattrace.hayabusa_evidence_adapter",
            "collection_method": "hayabusa:csv_timeline",
            "source_reference": f"{normalized_source_location}#row={row_identifier}",
            "transformation_steps": [
                "selected Hayabusa row accepted from caller",
                "complete original row preserved in details.hayabusa_row",
                "explicit field aliases applied",
            ],
        },
    }

    if observed_at_specified:
        result["observed_at"] = output_observed_at

    result.update(aliased_values)

    return result
