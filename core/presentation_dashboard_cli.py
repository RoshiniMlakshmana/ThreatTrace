"""Command-line adapter for
`core.presentation_dashboard.render_presentation_dashboard` (Block
15F-B).

Input is read from stdin, as a single JSON object containing exactly
three fields: `operation` (always `"render"`), `dashboard_data`,
`output_path`. On success, the rendered HTML document is written to
`output_path` on the local filesystem, and a small, fixed-shape
confirmation object is written to stdout as JSON. Errors are written
to stderr only.

## This CLI performs local file output only -- never network access

This is the **only** part of the Block 15F-B dashboard stack that
performs any I/O. `core.presentation_dashboard.
render_presentation_dashboard` itself remains pure -- this adapter
calls it once, then writes its return value to `output_path` on the
local filesystem. It never makes a network request, never contacts
Supabase/MCP, and never reads `output_path` from anywhere but the
caller's own supplied envelope. `output_path` must be a local
filesystem path -- any value containing a URL scheme separator
(`"://"`) is rejected before any file operation is attempted.

## Thin adapter boundary

This adapter is a thin wrapper only:

- It owns exactly one thing: the three-field top-level envelope shape,
  and the fixed literal `operation` value `"render"`. It never
  validates the *content* of `dashboard_data` itself -- after
  confirming the envelope has exactly these three keys and `operation`
  is `"render"`, `dashboard_data` is passed directly, completely
  unchanged, to `render_presentation_dashboard`. Every structural check
  on `dashboard_data` (the eleven-field contract, benchmark-summary
  shape, workflow-stage shape, research-limitations shape) belongs
  entirely to `core.presentation_dashboard`, never reimplemented here.
- It never wraps the rendered HTML, never modifies it, and never adds
  content to it -- the file written to `output_path` is exactly
  `render_presentation_dashboard`'s own return value, byte for byte.

Exit codes:

- 0 -- success; the HTML document was written to `output_path`, and
  stdout contains exactly one compact JSON object: `{"rendered": true,
  "output_path": "<output_path>"}`.
- 2 -- invalid input (malformed/non-object JSON, a missing/unknown
  `operation`, a missing/unknown top-level envelope field, an
  `output_path` that is not a non-blank local-path string, or a
  structurally invalid `dashboard_data` rejected by the core's own
  `PresentationDashboardError`); stdout is empty; stderr begins with
  `PRESENTATION_DASHBOARD_VALIDATION_FAILED`.
- 1 -- an unexpected internal failure, including a filesystem error
  while writing `output_path`; stdout is empty; stderr begins with
  `PRESENTATION_DASHBOARD_INTERNAL_FAILURE`.

Every stderr message is one of the two fixed prefixes above followed by
a short, non-sensitive detail -- never a raw traceback, an exception
class name, or the caller's entire `dashboard_data` payload.

Usage:

    py -m core.presentation_dashboard_cli
    python3 -m core.presentation_dashboard_cli
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TextIO

from core.presentation_dashboard import PresentationDashboardError, render_presentation_dashboard

_VALIDATION_ERROR_PREFIX = "PRESENTATION_DASHBOARD_VALIDATION_FAILED:"
_INTERNAL_ERROR_PREFIX = "PRESENTATION_DASHBOARD_INTERNAL_FAILURE:"

_ALLOWED_OPERATIONS = frozenset({"render"})

_RENDER_ENVELOPE_FIELDS = frozenset({"operation", "dashboard_data", "output_path"})


def _validate_output_path(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    if "://" in value:
        return None
    if "\x00" in value:
        return None
    return value


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, render one presentation
    dashboard, write it to the requested local `output_path`, and write
    a small confirmation object to stdout.

    Returns 0 on success, 2 for invalid input (malformed JSON,
    non-object JSON, a missing/unknown `operation`, a missing/unknown
    envelope field, an invalid `output_path`, or a structurally invalid
    `dashboard_data` rejected by the core's own
    `PresentationDashboardError`), and 1 for any unexpected internal
    failure, including a filesystem error while writing the file.
    """
    try:
        raw_text = stdin.read()

        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} invalid JSON input: {exc}\n")
            return 2

        if not isinstance(parsed, dict):
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} input must be a JSON object.\n")
            return 2

        operation = parsed.get("operation")
        if operation not in _ALLOWED_OPERATIONS:
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} operation must be 'render'.\n")
            return 2

        unknown_fields = set(parsed) - _RENDER_ENVELOPE_FIELDS
        if unknown_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} unrecognized field(s): {', '.join(sorted(unknown_fields))}\n"
            )
            return 2

        missing_fields = [field for field in _RENDER_ENVELOPE_FIELDS if field not in parsed]
        if missing_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} missing required field(s): {', '.join(sorted(missing_fields))}\n"
            )
            return 2

        output_path = _validate_output_path(parsed["output_path"])
        if output_path is None:
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} output_path must be a non-blank local filesystem path.\n")
            return 2

        try:
            html_document = render_presentation_dashboard(dashboard_data=parsed["dashboard_data"])
        except PresentationDashboardError as exc:
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} {exc}\n")
            return 2

        try:
            target_path = Path(output_path)
            if target_path.parent and str(target_path.parent) not in ("", "."):
                target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(html_document, encoding="utf-8")
        except Exception:
            stderr.write(f"{_INTERNAL_ERROR_PREFIX} unable to write output_path.\n")
            return 1

        stdout.write(json.dumps({"rendered": True, "output_path": output_path}, sort_keys=True, ensure_ascii=False))
        stdout.write("\n")
        return 0
    except Exception:
        stderr.write(f"{_INTERNAL_ERROR_PREFIX} unexpected failure.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
