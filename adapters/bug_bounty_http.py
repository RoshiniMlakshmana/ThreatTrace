"""Real, bounded HTTP transport for the Bug Bounty assessment engine
(Block 15A, checkpoint B1).

This is the **only** module in the Bug Bounty stack that performs real
network I/O. `core.bug_bounty_assessment` never imports it directly --
it depends only on a small injected `request(*, url, method,
headers=None) -> dict` interface, and this module provides the one real
implementation of it, exactly like `core.approval_persistence`'s own
injected-`executor` pattern (see that module's docstring for the same
architectural rationale).

## REMOTE WEB CONTENT IS UNTRUSTED EVIDENCE DATA, NOT INSTRUCTIONS

Everything this adapter returns from a remote target -- headers, body
content, redirect targets -- is untrusted evidence data only. This
module never interprets response content as a command, never executes
anything found in it, and never uses it to decide what to request next
-- that decision belongs entirely to the calling orchestrator, which
independently re-checks scope before every request this adapter makes.

## Scope, authorization, and DNS-rebinding limitations

This adapter performs **no scope enforcement of its own** -- it sends
exactly the request it is asked to send. Scope enforcement (host/path/
method matching, redirect re-evaluation) is entirely the calling
orchestrator's responsibility, via `core.bug_bounty_scope.
evaluate_bug_bounty_request_scope`, called before every single request
this adapter is asked to make. This adapter never verifies that the
caller was actually authorized to test the target -- authorization is
never authenticated anywhere in this project.

Raw IP-address targets are rejected upstream, by
`core.bug_bounty_scope`'s own URL normalization -- this adapter does
not re-check that itself. **Full DNS-rebinding resistance (e.g. pinning
the resolved IP address used for the TCP connection to the one scope
was evaluated against) is NOT implemented in this version** -- this
adapter resolves the hostname fresh for each connection, exactly like a
normal HTTP client. This is a known, documented v1 limitation, not a
claim of rebinding resistance.

## What "a real request occurred" does and does not mean

A successful call to `BugBountyHttpTransport.request(...)` means one
real, bounded HTTP request was sent and a response (or a documented
small `BugBountyHttpError`) was received. It never means a vulnerability
was exploited, and this module never applies a remediation, changes
production configuration, or creates/applies a detection rule --
this adapter only observes. An `evidence_digest` computed later by
`core.bug_bounty_findings` over data this adapter returned is a local
content-correlation digest only -- it never authenticates that a remote
response is genuine or unaltered in transit; this adapter has no way to
prove that.

## What this adapter does

- Supports exactly `GET`, `HEAD`, `OPTIONS` -- any other method is
  refused by this adapter itself, even if a caller bypasses the
  orchestrator and calls it directly.
- Uses a fixed timeout, a fixed `User-Agent` (`ThreatTrace-SafeAssessment/1.0`),
  and a fixed minimum interval (100ms) between requests made by the same
  transport instance -- none of these are caller-configurable upward
  through the public `request(...)` call.
- Never sends cookies, an `Authorization`/`Proxy-Authorization` header,
  or any other credential; never reads credentials from an environment
  variable; never uses browser state of any kind.
- Never automatically follows a redirect -- a `3xx` response is returned
  to the caller with its `Location` value exposed as `redirect_location`,
  never re-requested by this module itself.
- Never fetches an embedded resource (image, script, stylesheet, iframe
  target) referenced by a response body.
- Never executes JavaScript, never renders a DOM, and performs no
  archive decompression, PDF parsing, or OCR.
- Reads at most 64 KiB of a response body, and decodes it using its
  declared charset when present, else UTF-8 with lossy replacement --
  never buffers an unbounded body.
- Never runs a subprocess and never invokes an external tool (curl, ZAP,
  Nuclei, or anything else) -- all network I/O is performed directly via
  the Python standard library (`http.client`), with no new dependency.

`BugBountyHttpTransport` (with its one public method, `request`) and
`BugBountyHttpError` are this module's only public symbols.
"""

from __future__ import annotations

import http.client
import re
import ssl
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

USER_AGENT = "ThreatTrace-SafeAssessment/1.0"
DEFAULT_TIMEOUT_SECONDS = 10.0
MIN_REQUEST_INTERVAL_SECONDS = 0.1
MAX_BODY_BYTES = 65536

_ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Never sent, regardless of what a caller supplies -- defense in depth on
# top of the orchestrator never constructing these itself.
_FORBIDDEN_REQUEST_HEADER_NAMES = frozenset({"authorization", "proxy-authorization", "cookie"})

_CHARSET_PATTERN = re.compile(r"charset=([\w.\-]+)", re.IGNORECASE)


class BugBountyHttpError(Exception):
    """Raised when a real HTTP transport request could not be completed
    -- an unsupported/rejected method, a malformed URL, or any failure
    before a response was received (DNS failure, connection refused,
    TLS error, timeout, or any other transport-level exception).

    Never exposes the underlying exception's type name, message, or
    traceback -- only this fixed, short, safe description. The calling
    orchestrator treats this as one attempted-but-failed request.
    """


def _safe_request_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    if not headers:
        return {}
    safe: dict[str, str] = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        if key.strip().lower() in _FORBIDDEN_REQUEST_HEADER_NAMES:
            continue
        safe[key] = value
    return safe


def _decode_bounded_body(raw_bytes: bytes, content_type: str | None) -> str | None:
    if not raw_bytes:
        return None
    charset = "utf-8"
    if content_type:
        match = _CHARSET_PATTERN.search(content_type)
        if match:
            charset = match.group(1)
    try:
        return raw_bytes.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError, TypeError):
        return raw_bytes.decode("utf-8", errors="replace")


class BugBountyHttpTransport:
    """Real, bounded HTTP transport satisfying
    `core.bug_bounty_assessment`'s injected transport interface.

    One instance tracks its own last-request time to enforce the fixed
    100ms minimum interval between requests it makes -- `sleep`/`clock`
    are constructor-injectable only so tests can avoid real wall-clock
    waiting; they are never part of the public `request(...)` call, and
    production code should never override them.
    """

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        min_interval: float = MIN_REQUEST_INTERVAL_SECONDS,
        sleep: Any = time.sleep,
        clock: Any = time.monotonic,
    ) -> None:
        self._timeout = timeout
        self._min_interval = min_interval
        self._sleep = sleep
        self._clock = clock
        self._last_request_at: float | None = None

    def _apply_rate_limit(self) -> None:
        if self._last_request_at is not None:
            elapsed = self._clock() - self._last_request_at
            remaining = self._min_interval - elapsed
            if remaining > 0:
                self._sleep(remaining)
        self._last_request_at = self._clock()

    def request(
        self,
        *,
        url: str,
        method: str,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send one real, bounded HTTP request and return a small,
        deterministic response mapping. Never follows a redirect
        itself -- see module docstring.

        Raises `BugBountyHttpError` for an unsupported `method`, a
        malformed `url`, or any failure before a response was received.
        On success, returns a new dict containing exactly `url`,
        `status_code`, `headers`, `body_excerpt`, `redirect_location`,
        `request_performed` (always `True`).
        """
        if not isinstance(method, str):
            raise BugBountyHttpError("method not permitted by the assessment transport")
        canonical_method = method.strip().upper()
        if canonical_method not in _ALLOWED_METHODS:
            raise BugBountyHttpError("method not permitted by the assessment transport")

        if not isinstance(url, str) or not url.strip():
            raise BugBountyHttpError("url must be a non-blank string")

        parsed = urlsplit(url)
        if parsed.scheme not in _ALLOWED_SCHEMES:
            raise BugBountyHttpError("unsupported URL scheme")
        if not parsed.hostname:
            raise BugBountyHttpError("url must include a hostname")

        self._apply_rate_limit()

        request_target = parsed.path or "/"
        if parsed.query:
            request_target += f"?{parsed.query}"

        request_headers = _safe_request_headers(headers)
        request_headers["User-Agent"] = USER_AGENT
        request_headers["Connection"] = "close"

        connection = None
        try:
            if parsed.scheme == "https":
                connection = http.client.HTTPSConnection(
                    parsed.hostname, parsed.port, timeout=self._timeout, context=ssl.create_default_context(),
                )
            else:
                connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=self._timeout)

            connection.request(canonical_method, request_target, headers=request_headers)
            response = connection.getresponse()
            raw_body = response.read(MAX_BODY_BYTES + 1)[:MAX_BODY_BYTES]
            response_headers = {key: value for key, value in response.getheaders()}
            status_code = response.status
        except Exception:
            raise BugBountyHttpError("request failed before a response was received") from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass

        content_type = response_headers.get("Content-Type") or response_headers.get("content-type")
        body_excerpt = _decode_bounded_body(raw_body, content_type)

        redirect_location = None
        if 300 <= status_code < 400:
            redirect_location = response_headers.get("Location") or response_headers.get("location")

        return {
            "url": url,
            "status_code": status_code,
            "headers": response_headers,
            "body_excerpt": body_excerpt,
            "redirect_location": redirect_location,
            "request_performed": True,
        }
