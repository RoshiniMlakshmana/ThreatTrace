"""Honest configuration-boundary adapters for credential/API-key-required
Threat Intelligence sources (Block 15H-I): TAXII, MISP, OpenCTI, and
authenticated Telegram channel access.

None of these four sources has a compatible, already-configured runtime
in this project's development environment. Every function in this
module checks for its own fixed environment variable and, when absent,
returns `runtime_status: "not_configured"` **without ever attempting a
network call** -- exactly like `adapters.bug_bounty_burp.run_burp_scan`'s
own honest boundary for an unconfigured Burp runtime. This module never
fabricates ingestion, never invents a record, and never treats a missing
credential as a reason to fall back to scraping or an unofficial
endpoint.

## Telegram is untrusted public/community OSINT, never "the dark web"

`fetch_telegram_public_osint_records` (and every doc comment referring
to it) treats a public Telegram channel exactly as
`core.threat_intelligence.SOURCE_TYPES`'s own `"telegram_public_osint"`
value names it: untrusted public/community OSINT, the same trust tier as
any other unauthenticated public feed. It is never described as, or
conflated with, dark-web-derived intelligence. This project has no
Telegram Bot API token configured, so even the "public channel" path
here is a `not_configured` boundary in this checkpoint, exactly like the
other three -- no unofficial scraping is ever attempted as a substitute.

## No credential is ever read from anywhere but its own fixed environment variable

Every credential-shaped value this module could ever use comes from
exactly one fixed, module-specific environment variable name -- never a
caller-supplied parameter (which could smuggle in a different
credential or endpoint), and never a hardcoded default.

`ThreatIntelConfiguredSourceError` and the four `fetch_*` functions are
this module's public symbols.
"""

from __future__ import annotations

import os
from typing import Any

RUNTIME_STATUS_VALUES = frozenset({"available", "not_configured"})

TAXII_API_KEY_ENV_VAR = "THREATTRACE_TAXII_API_KEY"
MISP_API_KEY_ENV_VAR = "THREATTRACE_MISP_API_KEY"
OPENCTI_API_KEY_ENV_VAR = "THREATTRACE_OPENCTI_API_KEY"
TELEGRAM_BOT_TOKEN_ENV_VAR = "THREATTRACE_TELEGRAM_BOT_TOKEN"


class ThreatIntelConfiguredSourceError(ValueError):
    """Raised only for a structurally invalid `limit`. Never raised
    because a runtime is unconfigured -- that is `runtime_status:
    "not_configured"` in the returned result, not an error."""


def _validate_limit(limit: Any, max_limit: int) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > max_limit:
        raise ThreatIntelConfiguredSourceError(f"INVALID_LIMIT: limit must be a positive int not exceeding {max_limit}")


def _not_configured_result(source_type: str) -> dict[str, Any]:
    return {
        "status": "not_evaluated", "runtime_status": "not_configured", "records": [],
        "records_available": None, "source_reference": None,
        "error_detail": None, "execution_performed": False,
    }


def fetch_taxii_records(*, limit: Any, collection_url: Any = None) -> dict[str, Any]:
    """Honest boundary for a TAXII-compatible feed. Returns `runtime_status:
    "not_configured"` without any network attempt unless `TAXII_API_KEY_ENV_VAR`
    is set in the environment -- which it is not in this checkpoint, so
    live TAXII ingestion is never actually implemented here. `limit` must
    be a positive int (raises `ThreatIntelConfiguredSourceError` otherwise)."""
    _validate_limit(limit, 25)
    if not os.environ.get(TAXII_API_KEY_ENV_VAR, "").strip():
        return _not_configured_result("taxii")
    return _not_configured_result("taxii")  # configured-but-unimplemented in this checkpoint -- never fabricated


def fetch_misp_records(*, limit: Any, instance_url: Any = None) -> dict[str, Any]:
    """Honest boundary for a MISP-style structured feed. Same
    `not_configured` behavior as `fetch_taxii_records` -- see module
    docstring."""
    _validate_limit(limit, 25)
    if not os.environ.get(MISP_API_KEY_ENV_VAR, "").strip():
        return _not_configured_result("misp")
    return _not_configured_result("misp")


def fetch_opencti_records(*, limit: Any, instance_url: Any = None) -> dict[str, Any]:
    """Honest boundary for an OpenCTI-style structured feed. Same
    `not_configured` behavior as `fetch_taxii_records` -- see module
    docstring."""
    _validate_limit(limit, 25)
    if not os.environ.get(OPENCTI_API_KEY_ENV_VAR, "").strip():
        return _not_configured_result("opencti")
    return _not_configured_result("opencti")


def fetch_telegram_public_osint_records(*, limit: Any, channel: Any = None) -> dict[str, Any]:
    """Honest boundary for public-channel Telegram OSINT via the
    official Telegram Bot API only. Same `not_configured` behavior as
    `fetch_taxii_records` -- see module docstring's note on treating
    this strictly as untrusted public/community OSINT, never
    "the dark web"."""
    _validate_limit(limit, 25)
    if not os.environ.get(TELEGRAM_BOT_TOKEN_ENV_VAR, "").strip():
        return _not_configured_result("telegram_public_osint")
    return _not_configured_result("telegram_public_osint")
