"""Command-line adapter for `core.evidence_normalizer.normalize_evidence`.

Input is accepted through stdin, as a single JSON object. Output is written
through stdout, as normalized JSON. Errors are written through stderr only.

This adapter performs structural normalization only:

- It does not scan for secrets. The caller must perform the secret scan
  before invoking it.
- It does not access Supabase.
- It does not perform MITRE ATT&CK mapping.
- It does not hash evidence.
- It does not execute security tools (Hayabusa or otherwise).

Usage:

    py -m core.evidence_cli
    python3 -m core.evidence_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.evidence_normalizer import EvidenceValidationError, normalize_evidence

_VALIDATION_ERROR_PREFIX = "Evidence validation failed:"
_JSON_ERROR_PREFIX = "Invalid JSON input:"
_UNEXPECTED_ERROR_MESSAGE = "Evidence normalization failed."


def main(
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Read one JSON object from stdin, normalize it, and write the result to stdout.

    Returns 0 on success, 2 for invalid input (malformed/non-object JSON, or
    a payload that fails evidence validation), and 1 for any unexpected
    internal failure.
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

        try:
            result = normalize_evidence(parsed)
        except EvidenceValidationError as exc:
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} {exc}\n")
            return 2

        stdout.write(json.dumps(result, sort_keys=True, ensure_ascii=False))
        stdout.write("\n")
        return 0
    except Exception:
        stderr.write(f"{_UNEXPECTED_ERROR_MESSAGE}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
