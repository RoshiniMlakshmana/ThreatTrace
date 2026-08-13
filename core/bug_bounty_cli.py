"""Command-line adapter for the Block 15A Bug Bounty assessment engine
(checkpoint B2) -- the **human-invoked** real network assessment
surface.

Input is read from stdin, as a single JSON object containing exactly
seven fields: `operation` (always `"assess"`), `target`, `target_type`,
`allowed_origins`, `allowed_paths`, `excluded_paths`, `testing_profile`.
Output is the deterministic assessment result, written to stdout as
JSON. Errors are written to stderr only.

## This CLI CAN make real HTTP requests

Running this CLI can send real, bounded `GET`/`HEAD`/`OPTIONS` HTTP
requests to the caller-supplied `target` (and, within scope, a small
number of related URLs) -- see `core.bug_bounty_assessment` and
`adapters.bug_bounty_http` for the exact bounds (request cap, redirect
hop limit, rate limit, body-size limit). `target`/`allowed_origins`/
`allowed_paths`/`excluded_paths`/`testing_profile` are **caller-supplied
technical scope only** -- ThreatTrace does not authenticate, and has no
way to authenticate, that the caller was legally/organizationally
authorized to test the supplied target. `execution_performed: false` in
the returned result does **not** mean no network request happened --
it means no remediation was applied, no production configuration was
changed, no detection rule was created or applied, and no downstream
Blue/Purple action occurred. A real assessment request having occurred
is represented honestly through the result's own `assessment_performed`/
`network_requests_performed` fields instead.

## Thin adapter boundary

This adapter is a thin wrapper only:

- It owns exactly one thing: the seven-field top-level envelope shape,
  and the fixed literal `operation` value `"assess"`. It never
  validates `target`/`target_type`/`allowed_origins`/`allowed_paths`/
  `excluded_paths`/`testing_profile` itself, and never trims,
  lowercases, or otherwise normalizes any of them -- after confirming
  the envelope has exactly these seven keys and `operation` is
  `"assess"`, the six scope values are passed directly, unchanged, to
  `core.bug_bounty_scope.create_bug_bounty_scope`. `allowed_paths`/
  `excluded_paths` are required envelope keys (never omitted, never
  synthesized here) even though the pure scope API itself accepts
  `None` for either -- this keeps the caller's scope decision fully
  visible in every request, while still letting the caller explicitly
  supply `null` for either field when that is the value they intend.
- It never reimplements origin/path scope matching, finding validation,
  evidence redaction, assessment check logic, redirect handling, or
  request-cap/rate-limit enforcement -- every one of those belongs
  entirely to `core.bug_bounty_scope`, `core.bug_bounty_findings`
  (indirectly, via `core.bug_bounty_assessment`), and
  `core.bug_bounty_assessment` itself.
- It constructs exactly one real transport,
  `adapters.bug_bounty_http.BugBountyHttpTransport`, with its own fixed
  defaults (timeout, rate limit) -- this CLI accepts no caller-supplied
  transport configuration of any kind.
- Its output remains exactly `core.bug_bounty_assessment.
  run_bug_bounty_assessment`'s own result -- this adapter never wraps it
  in any additional envelope, never adds a `success`/`status` field, and
  never adds explanatory prose to stdout.

A returned assessment whose `findings` is empty, or which contains a
`REQUEST_FAILED`/blocked-redirect observation, is a normal, successful
CLI result -- never a CLI process failure.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object (the real
  `run_bug_bounty_assessment` result, regardless of how many findings
  it contains or which assessment-level evidence codes it carries).
- 2 -- invalid input (malformed/non-object JSON, a missing/unknown
  `operation`, a missing/unknown top-level envelope field, or a
  structurally invalid scope value rejected by the core's own
  `BugBountyScopeError`/`BugBountyAssessmentError`); stdout is empty;
  stderr begins with `BUG_BOUNTY_VALIDATION_FAILED`.
- 1 -- an unexpected internal failure before a valid assessment result
  could be produced; stdout is empty; stderr begins with
  `BUG_BOUNTY_INTERNAL_FAILURE`.

Usage:

    py -m core.bug_bounty_cli
    python3 -m core.bug_bounty_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from adapters.bug_bounty_http import BugBountyHttpTransport
from core.bug_bounty_assessment import BugBountyAssessmentError, run_bug_bounty_assessment
from core.bug_bounty_scope import BugBountyScopeError, create_bug_bounty_scope

_VALIDATION_ERROR_PREFIX = "BUG_BOUNTY_VALIDATION_FAILED:"
_INTERNAL_ERROR_PREFIX = "BUG_BOUNTY_INTERNAL_FAILURE:"

_ALLOWED_OPERATIONS = frozenset({"assess"})

_ASSESS_ENVELOPE_FIELDS = frozenset({
    "operation",
    "target",
    "target_type",
    "allowed_origins",
    "allowed_paths",
    "excluded_paths",
    "testing_profile",
})


def _build_transport() -> BugBountyHttpTransport:
    """Construct the one real transport this CLI ever uses. A separate,
    private, patchable seam -- tests replace this function with a fake
    transport factory so no test ever performs real network I/O; normal
    (non-test) execution always uses the real
    `adapters.bug_bounty_http.BugBountyHttpTransport`, with its own
    fixed defaults, never caller-configurable through this CLI.
    """
    return BugBountyHttpTransport()


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, run one real, bounded Bug
    Bounty assessment, and write the result to stdout.

    Returns 0 on success (including an assessment result with no
    findings, a `REQUEST_FAILED`/blocked-redirect observation, or any
    other normal assessment-level outcome -- every one of those is a
    successful result), 2 for invalid input (malformed JSON, non-object
    JSON, a missing/unknown `operation`, a missing/unknown envelope
    field, or a structurally invalid scope value rejected by the core's
    own `BugBountyScopeError`/`BugBountyAssessmentError`), and 1 for any
    unexpected internal failure.
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
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} operation must be 'assess'.\n")
            return 2

        unknown_fields = set(parsed) - _ASSESS_ENVELOPE_FIELDS
        if unknown_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} unrecognized field(s): {', '.join(sorted(unknown_fields))}\n"
            )
            return 2

        missing_fields = [field for field in _ASSESS_ENVELOPE_FIELDS if field not in parsed]
        if missing_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} missing required field(s): {', '.join(sorted(missing_fields))}\n"
            )
            return 2

        try:
            scope = create_bug_bounty_scope(
                target=parsed["target"],
                target_type=parsed["target_type"],
                allowed_origins=parsed["allowed_origins"],
                allowed_paths=parsed["allowed_paths"],
                excluded_paths=parsed["excluded_paths"],
                testing_profile=parsed["testing_profile"],
            )
            transport = _build_transport()
            result = run_bug_bounty_assessment(scope=scope, transport=transport)
        except (BugBountyScopeError, BugBountyAssessmentError) as exc:
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} {exc}\n")
            return 2

        stdout.write(json.dumps(result, sort_keys=True, ensure_ascii=False))
        stdout.write("\n")
        return 0
    except Exception:
        stderr.write(f"{_INTERNAL_ERROR_PREFIX} unexpected failure.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
