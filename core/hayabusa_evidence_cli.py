"""Command-line adapter for `core.hayabusa_evidence_adapter.adapt_hayabusa_row`.

Input is read from stdin, as a single JSON request object describing one
already-selected Hayabusa `csv_timeline` row plus caller-supplied metadata.
Output is an unnormalized evidence candidate written to stdout, as JSON.
Errors are written only to stderr.

- The caller must select one `csv_timeline` row before invocation -- this
  CLI does not read files or parse CSV itself.
- It does not scan for secrets.
- It does not normalize evidence (`normalize_evidence` / `core.evidence_cli`
  are never called here).
- It does not assess source trust (`assess_source_trust` /
  `core.source_trust_cli` are never called here).
- It does not access Supabase.
- It does not execute Hayabusa.
- It performs no MITRE ATT&CK mapping.
- It performs no evidence hashing.
- It performs no approval, audit, or execution action.

The returned candidate must later pass through `core.evidence_cli` and the
existing human-confirmed `/add-evidence` workflow before it can ever reach
Supabase.

Usage:

    py -m core.hayabusa_evidence_cli
    python3 -m core.hayabusa_evidence_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.hayabusa_evidence_adapter import HayabusaEvidenceAdapterError, adapt_hayabusa_row

_ADAPTER_ERROR_PREFIX = "Hayabusa evidence adaptation failed:"
_JSON_ERROR_PREFIX = "Invalid JSON input:"
_UNEXPECTED_ERROR_MESSAGE = "Hayabusa evidence adaptation failed."

_REQUIRED_REQUEST_FIELDS = (
    "row",
    "investigation_id",
    "analysis_type",
    "source_location",
    "row_identifier",
    "evidence_type",
)
_OPTIONAL_REQUEST_FIELDS = ("observed_at", "supports_hypothesis", "field_aliases")
_ALLOWED_REQUEST_FIELDS = frozenset(_REQUIRED_REQUEST_FIELDS + _OPTIONAL_REQUEST_FIELDS)


def main(
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Read one JSON request object from stdin, adapt it, and write the result to stdout.

    Returns 0 on success, 2 for invalid input (malformed/non-object/
    unknown-field/missing-required-field JSON, or a request that fails
    adapter validation), and 1 for any unexpected internal failure.
    """
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr

    try:
        raw_text = stdin.read()

        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            stderr.write(f"{_JSON_ERROR_PREFIX} {exc}\n")
            return 2

        if not isinstance(parsed, dict):
            stderr.write(f"{_JSON_ERROR_PREFIX} input must be a JSON object\n")
            return 2

        unknown_fields = set(parsed) - _ALLOWED_REQUEST_FIELDS
        if unknown_fields:
            stderr.write(
                f"{_JSON_ERROR_PREFIX} unrecognized field(s): {', '.join(sorted(unknown_fields))}\n"
            )
            return 2

        missing_fields = [field for field in _REQUIRED_REQUEST_FIELDS if field not in parsed]
        if missing_fields:
            stderr.write(
                f"{_JSON_ERROR_PREFIX} missing required field(s): {', '.join(missing_fields)}\n"
            )
            return 2

        try:
            result = adapt_hayabusa_row(
                parsed["row"],
                investigation_id=parsed["investigation_id"],
                analysis_type=parsed["analysis_type"],
                source_location=parsed["source_location"],
                row_identifier=parsed["row_identifier"],
                evidence_type=parsed["evidence_type"],
                observed_at=parsed.get("observed_at"),
                supports_hypothesis=parsed.get("supports_hypothesis"),
                field_aliases=parsed.get("field_aliases"),
            )
        except HayabusaEvidenceAdapterError as exc:
            stderr.write(f"{_ADAPTER_ERROR_PREFIX} {exc}\n")
            return 2

        stdout.write(json.dumps(result, sort_keys=True, ensure_ascii=False))
        stdout.write("\n")
        return 0
    except Exception:
        stderr.write(f"{_UNEXPECTED_ERROR_MESSAGE}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
