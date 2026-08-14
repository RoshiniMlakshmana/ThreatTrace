"""Command-line adapter for
`core.research_evaluation.evaluate_research_experiment` (Block 15E,
checkpoint B).

Input is read from stdin, as a single JSON object containing exactly
two fields: `operation` (always `"evaluate"`), `experiment`. Output is
the deterministic research-evaluation result, written to stdout as
JSON. Errors are written to stderr only.

## Security / research honesty

This CLI summarizes a caller-supplied batch of already-produced
ThreatTrace scenario records. It performs **no network request of any
kind** -- it is a pure, local, deterministic computation over whatever
`experiment` the caller supplies via stdin. It never conducts an
attack, never executes a security stage, never runs Bug Bounty/Red/
Blue/Purple, never queries or writes to Validated Security Experience
Memory, never invokes the Security Governor, and never creates or
consumes an approval -- every one of those is, at most, described by a
field already present in a caller-supplied scenario record, never
performed by this CLI. It never proves causality, never establishes
statistical significance, and never proves production security
improvement -- `evaluate_research_experiment`'s own
`research_limitations` field, always present in every result, states
this explicitly. It never generates a missing `duration_minutes`
value, never authenticates an `approval_state`, and never authenticates
an evidence reference -- every one of those remains exactly the
caller-supplied value it already was. It never trains, fine-tunes, or
updates any model. `execution_performed` does not appear in this
result at all, because no field in this contract describes an action
this CLI (or the underlying core) ever performs.

A result whose `governor_memory_protection.unsafe_reusable_violations`
is greater than zero is a normal, successfully computed research
observation -- never a CLI failure.

## Thin adapter boundary

This adapter is a thin wrapper only:

- It owns exactly one thing: the two-field top-level envelope shape,
  and the fixed literal `operation` value `"evaluate"`. It never
  validates the *content* of `experiment` itself -- after confirming
  the envelope has exactly these two keys and `operation` is
  `"evaluate"`, `experiment` is passed directly, completely unchanged,
  to `evaluate_research_experiment`. This adapter never trims,
  lowercases, reorders, or otherwise normalizes any nested value, never
  synthesizes a missing `experiment`/scenario field, and never infers
  any field from anything else -- every structural/vocabulary check
  (the three-field experiment contract, the seventeen-field scenario
  contract, every closed vocabulary, the severity-band delta
  consistency rule, the context/Governor baseline rules, every metric
  computation -- context-prioritization deltas, Governor
  intervention/decision counts, memory reuse/rejection counts, the
  Governor-to-Memory protection rate, handoff-stage/Red-Blue-revision
  counting, evidence-preservation counting, human-review counting, the
  validated-defensive-experience rate, MTVD, the stage-count proxy, and
  every ablation group) belongs entirely to `core.research_evaluation`,
  never reimplemented here.
- Its output remains exactly `evaluate_research_experiment`'s own
  result -- this adapter never wraps it in any additional envelope,
  never adds a `success`/`status` field, and never adds explanatory
  prose to stdout.

Exit codes:

- 0 -- success; stdout contains exactly one JSON object (the real
  `evaluate_research_experiment` result, regardless of its contents --
  including a result whose `governor_memory_protection
  .unsafe_reusable_violations` is greater than zero, which is a normal
  research observation, never a CLI failure).
- 2 -- invalid input (malformed/non-object JSON, a missing/unknown
  `operation`, a missing/unknown top-level envelope field, or a
  structurally invalid `experiment` rejected by the core's own
  `ResearchEvaluationError`); stdout is empty; stderr begins with
  `RESEARCH_EVALUATION_VALIDATION_FAILED`.
- 1 -- an unexpected internal failure; stdout is empty; stderr begins
  with `RESEARCH_EVALUATION_INTERNAL_FAILURE`.

Every stderr message is one of the two fixed prefixes above followed by
a short, non-sensitive detail -- never a raw traceback, an exception
class name, the caller's entire `experiment` payload, or any evidence
list.

Usage:

    py -m core.research_evaluation_cli
    python3 -m core.research_evaluation_cli
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from core.research_evaluation import ResearchEvaluationError, evaluate_research_experiment

_VALIDATION_ERROR_PREFIX = "RESEARCH_EVALUATION_VALIDATION_FAILED:"
_INTERNAL_ERROR_PREFIX = "RESEARCH_EVALUATION_INTERNAL_FAILURE:"

_ALLOWED_OPERATIONS = frozenset({"evaluate"})

_EVALUATE_ENVELOPE_FIELDS = frozenset({"operation", "experiment"})


def main(
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Read one JSON envelope from stdin, compute one deterministic
    research-evaluation result, and write it to stdout.

    Returns 0 on success (including a result whose
    `governor_memory_protection.unsafe_reusable_violations` is greater
    than zero -- a normal, successfully computed research observation),
    2 for invalid input (malformed JSON, non-object JSON, a
    missing/unknown `operation`, a missing/unknown envelope field, or a
    structurally invalid `experiment` rejected by the core's own
    `ResearchEvaluationError`), and 1 for any unexpected internal
    failure.
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
            stderr.write(f"{_VALIDATION_ERROR_PREFIX} operation must be 'evaluate'.\n")
            return 2

        unknown_fields = set(parsed) - _EVALUATE_ENVELOPE_FIELDS
        if unknown_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} unrecognized field(s): {', '.join(sorted(unknown_fields))}\n"
            )
            return 2

        missing_fields = [field for field in _EVALUATE_ENVELOPE_FIELDS if field not in parsed]
        if missing_fields:
            stderr.write(
                f"{_VALIDATION_ERROR_PREFIX} missing required field(s): {', '.join(sorted(missing_fields))}\n"
            )
            return 2

        try:
            result = evaluate_research_experiment(experiment=parsed["experiment"])
        except ResearchEvaluationError as exc:
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
