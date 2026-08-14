"""Pure, deterministic bounded structural rule validation (Block 15H-I).

This module answers exactly one question: *does one drafted detection
rule's content look structurally well-formed for its declared format --
and, honestly, how much does that actually prove?*

## structural_validation_only, always, in this checkpoint

Neither a real Sigma-schema validator (e.g. `pysigma`) nor a real YARA
compiler (`yara-python`) is a declared dependency of this project
(`requirements.txt` lists only `mcp`/`pytest`) -- this module never
imports one, following this project's established "no new dependency"
convention (`adapters.bug_bounty_http`'s own docstring states the same
policy). Every result this module returns therefore carries
`validation_method: "structural_validation_only"`, and every check it
performs is a bounded, stdlib-only, keyword/balance check -- never a
real schema/grammar parse, and never execution of the rule's own logic
against any data.

## What this module never claims

`validate_rule_syntax` never sets, and has no field for, `"tested"` or
`"validated"` -- those states require running a rule against real data
or a human review this module cannot perform. `syntax_valid: True` here
means only "this content passed a handful of bounded structural sanity
checks for its declared format" -- never "this rule will fire
correctly," never "this rule has no false positives," and never
"detection efficacy proven." `core.detection_rule.apply_validation_result`
is the only place a rule's own `validation_status` can ever be updated,
and a caller should only ever pass it `"syntax_validated"` (never
`"tested"`/`"validated"`) based on this module's own result.

## No I/O, no execution, ever

This module performs no network, filesystem, environment-variable,
subprocess, system-clock, or randomness access, and never executes any
part of the rule content it inspects -- every check is a bounded string/
structural inspection only.

`DetectionRuleValidationError` and `validate_rule_syntax` are this
module's public symbols (plus `VALIDATION_METHODS` and `MAX_CONTENT_LENGTH`).
"""

from __future__ import annotations

from typing import Any

VALIDATION_VERSION = "1"
VALIDATION_METHODS = frozenset({"structural_validation_only"})
MAX_CONTENT_LENGTH = 65_536

_RULE_FORMATS = frozenset({"sigma", "splunk_spl", "sentinel_kql", "yara"})


class DetectionRuleValidationError(ValueError):
    """Raised when a supplied `rule_format`/`rule_content` is
    structurally invalid at the input-shape level (not a syntax
    validation failure -- that is `syntax_valid: False` in the returned
    result, not an exception).

    Never raised because the content fails its own structural checks --
    that is always a normal, successfully-computed `syntax_valid: False`
    result with `issues` populated, not an error.
    """


def _raise(code: str, detail: str) -> None:
    raise DetectionRuleValidationError(f"{code}: {detail}")


def _balanced(content: str, open_char: str, close_char: str) -> bool:
    depth = 0
    for char in content:
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _check_sigma(content: str) -> list[str]:
    issues: list[str] = []
    if "detection:" not in content:
        issues.append("no 'detection:' key found -- Sigma rules require a detection block")
    if "condition" not in content:
        issues.append("no 'condition' found within the detection block")
    if "!!python/object" in content or "!!python/module" in content:
        issues.append("content contains a YAML unsafe-deserialization tag marker -- rejected")
    if not _balanced(content, "{", "}") or not _balanced(content, "[", "]"):
        issues.append("unbalanced braces/brackets")
    return issues


def _check_splunk_spl(content: str) -> list[str]:
    issues: list[str] = []
    known_commands = ("search", "where", "stats", "eval", "index=", "sourcetype=", "table", "rex")
    if not any(keyword in content for keyword in known_commands):
        issues.append("no recognizable SPL command keyword found (search/where/stats/eval/index=/...)")
    if content.count('"') % 2 != 0:
        issues.append("unbalanced double quotes")
    if not _balanced(content, "(", ")"):
        issues.append("unbalanced parentheses")
    return issues


def _check_sentinel_kql(content: str) -> list[str]:
    issues: list[str] = []
    if "|" not in content:
        issues.append("no pipe ('|') operator found -- KQL queries are typically pipe-chained")
    if not _balanced(content, "(", ")"):
        issues.append("unbalanced parentheses")
    if content.count('"') % 2 != 0:
        issues.append("unbalanced double quotes")
    return issues


def _check_yara(content: str) -> list[str]:
    issues: list[str] = []
    if "rule " not in content and not content.strip().startswith("rule"):
        issues.append("no 'rule' keyword found")
    if "condition:" not in content:
        issues.append("no 'condition:' section found")
    if not _balanced(content, "{", "}"):
        issues.append("unbalanced braces")
    return issues


_CHECKERS = {
    "sigma": _check_sigma,
    "splunk_spl": _check_splunk_spl,
    "sentinel_kql": _check_sentinel_kql,
    "yara": _check_yara,
}


def validate_rule_syntax(*, rule_format: Any, rule_content: Any) -> dict[str, Any]:
    """Perform one bounded structural check of `rule_content` against
    its declared `rule_format`. Performs no I/O of any kind, and never
    executes any part of `rule_content`.

    `rule_format` must be one of `sigma`/`splunk_spl`/`sentinel_kql`/
    `yara`. `rule_content` must be a non-blank string no longer than
    `MAX_CONTENT_LENGTH`.

    Returns a dict with `validation_version`, `rule_format`,
    `syntax_valid` (`True` only when zero `issues` were found),
    `validation_method` (always `"structural_validation_only"` in this
    checkpoint -- see module docstring), `issues` (a list of short,
    human-readable structural findings; empty when `syntax_valid` is
    `True`), `checked_content_length`, `execution_performed` (always
    `False` -- this function never runs the rule).

    Raises `DetectionRuleValidationError` for a structurally invalid
    `rule_format`/`rule_content` (unrecognized format, blank content, or
    content exceeding `MAX_CONTENT_LENGTH`). Never raises because the
    content fails its own structural checks.
    """
    if rule_format not in _RULE_FORMATS:
        _raise("INVALID_RULE_FORMAT", f"rule_format must be one of {sorted(_RULE_FORMATS)}")
    if not isinstance(rule_content, str) or not rule_content.strip():
        _raise("INVALID_RULE_CONTENT", "rule_content must be a non-blank string")
    if len(rule_content) > MAX_CONTENT_LENGTH:
        _raise("INVALID_RULE_CONTENT", f"rule_content must not exceed {MAX_CONTENT_LENGTH} characters")

    issues = _CHECKERS[rule_format](rule_content)

    return {
        "validation_version": VALIDATION_VERSION,
        "rule_format": rule_format,
        "syntax_valid": len(issues) == 0,
        "validation_method": "structural_validation_only",
        "issues": issues,
        "checked_content_length": len(rule_content),
        "execution_performed": False,
    }
