"""Command-line adapter for `core.source_trust_policy.assess_source_trust`.

Input is read from stdin, as a single JSON object representing a normalized
evidence record. Advisory output is written to stdout, as JSON. Errors are
written to stderr only.

This adapter is advisory only:

- The recommendation does not establish that the evidence is true.
- The CLI does not modify evidence.
- The CLI does not automatically replace `trust_level` on any record --
  adopting the recommendation remains a separate, explicit decision made
  elsewhere (e.g. by an analyst reviewing this output).
- It does not access Supabase.
- It performs no secret scanning. The caller must normalize and
  secret-scan evidence before invoking it.
- It performs no MITRE ATT&CK mapping.
- It performs no hashing.
- It performs no `confidence` calculation.
- It performs no approval, audit, or execution action.

Usage:

    py -m core.source_trust_cli
    python3 -m core.source_trust_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.source_trust_policy import SourceTrustPolicyError, assess_source_trust

_POLICY_ERROR_PREFIX = "Source trust assessment failed:"
_JSON_ERROR_PREFIX = "Invalid JSON input:"
_UNEXPECTED_ERROR_MESSAGE = "Source trust assessment failed."


def main(
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Read one JSON evidence object from stdin, assess it, and write the result to stdout.

    Returns 0 on success, 2 for invalid input (malformed/non-object JSON, or
    a payload that fails source-trust validation), and 1 for any unexpected
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
            result = assess_source_trust(parsed)
        except SourceTrustPolicyError as exc:
            stderr.write(f"{_POLICY_ERROR_PREFIX} {exc}\n")
            return 2

        stdout.write(json.dumps(result, sort_keys=True, ensure_ascii=False))
        stdout.write("\n")
        return 0
    except Exception:
        stderr.write(f"{_UNEXPECTED_ERROR_MESSAGE}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
