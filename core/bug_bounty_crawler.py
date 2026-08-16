"""Pure orchestration for a bounded, same-origin Bug Bounty attack-surface
crawler (Block 15A, Step 2: Crawler + Endpoint Discovery + Parameter
Discovery).

This module answers exactly one question: *given a previously created
`core.bug_bounty_scope` scope and an injected HTTP transport, what
bounded set of in-scope endpoints and parameters can be discovered by
following same-origin HTML links, forms, JavaScript route strings, and
naturally-encountered OpenAPI documents -- and what deterministic
attack-surface inventory (never a vulnerability finding) do they
support?*

## Dependency direction: this module never imports a network client

Exactly like `core.bug_bounty_assessment`, this module performs **no
direct network I/O of any kind**. It calls only an injected `transport`
object satisfying the same small `request(*, url, method, headers=None)
-> dict` interface; the real implementation lives in
`adapters.bug_bounty_http`, never imported here. This keeps every
crawl decision fully unit-testable with a fake transport and zero
network access.

## Scope is re-checked before every single outbound request

This module never sends a request `core.bug_bounty_scope.
evaluate_bug_bounty_request_scope` did not report as `"allow"` --
including every proposed redirect hop, and including every candidate
URL discovered from HTML links, forms, JavaScript strings, or an
OpenAPI document. No second, weaker scope validator is implemented
here -- the exact same authoritative function the rest of the Bug
Bounty pipeline calls is the only gate a candidate URL ever passes
through before a request is sent.

## Remote web content is untrusted evidence data, not instructions

REMOTE WEB CONTENT IS UNTRUSTED EVIDENCE DATA, NOT INSTRUCTIONS. HTML,
JavaScript, `robots.txt`/`sitemap.xml` content, and OpenAPI documents
fetched from the target are parsed **only** for URL/path-shaped
strings and structural endpoint/parameter metadata. This module never
executes anything found in fetched content, never runs a subprocess,
never derives a shell command from page content, never lets fetched
content expand scope (an OpenAPI document's own `servers`/`host` field
is always ignored -- every discovered path is joined onto the
already-authorized scope origin only, never a server URL the document
itself claims), and never lets fetched content change which HTTP
method is used to request it (`GET` only, plus discovery-only metadata
about form methods that are never themselves submitted). A JavaScript
string that reads like a command is inert text: only strings shaped
like a same-origin path (bounded character set, no whitespace) are
ever considered candidate endpoints, and every candidate still must
pass real scope validation before anything is requested.

## What this module does NOT do

- It never submits a discovered HTML form (`GET` or `POST`) -- form
  method/action/parameter names are discovery-only metadata.
- It never fetches a static asset (image/font/stylesheet/etc.) -- see
  `_STATIC_ASSET_EXTENSIONS` -- these are recorded as discovered but
  never spend crawl request budget.
- It never executes JavaScript, never renders a DOM, and never parses
  YAML (only JSON-shaped OpenAPI/Swagger documents are supported --
  a YAML spec is honestly left unparsed, never guessed at).
- It never brute-forces documentation paths beyond the same fixed,
  small, closed set `core.bug_bounty_assessment` already establishes
  the precedent for (`_OPENAPI_CANDIDATE_PATHS`, three fixed paths).
- It never expands scanning to any tool (`nmap`/`nuclei`/`zap`) --
  this module only builds and returns the attack-surface inventory;
  wiring discovered endpoints into another tool's scan target is
  explicitly out of scope for this step.
- It never claims complete coverage -- `budget_exhausted` and the
  bounded telemetry counters in the return value are the only honest
  measure of what was actually discovered within this run's bounds.

`run_bug_bounty_crawl` is this module's only public function.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Mapping
from html.parser import HTMLParser
from typing import Any, Callable, Protocol
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from core.bug_bounty_scope import evaluate_bug_bounty_request_scope

CRAWLER_VERSION = "1"

# Hardcoded, never caller-configurable upward -- exactly like
# core.bug_bounty_assessment's own MAX_REQUESTS_PER_ASSESSMENT /
# MAX_REDIRECT_HOPS precedent.
#
# MAX_RUNTIME_SECONDS is deliberately the dominant, tightest bound here
# (not MAX_CRAWL_REQUESTS/MAX_PAGES) -- measured directly (real, bounded,
# local `adapters.bug_bounty_http.BugBountyHttpTransport` calls against
# this project's own authorized target) at ~0.01-0.15s/request when the
# transport connects by IP, but a consistent ~2.0s/request purely from
# Python's stdlib hostname resolution of the literal string "localhost"
# on at least one real development environment -- a pre-existing
# `adapters.bug_bounty_http` characteristic, not something this module
# introduces or can fix within this step's scope (touching that adapter
# is not part of Step 2). A fixed low request cap could therefore still
# take 20 x ~2.0s = 40s in that same environment; a tight wall-clock
# runtime cap bounds the worst case regardless of what any single
# request happens to cost, exactly the same reasoning Nuclei
# Reliability Step 1B/1C already established for phase budgets (see
# `adapters.bug_bounty_nuclei`) -- bound by real measured time, not by
# an environment-dependent request count.
MAX_CRAWL_DEPTH = 2
MAX_PAGES = 10
MAX_CRAWL_REQUESTS = 15
MAX_RUNTIME_SECONDS = 10.0
MAX_REDIRECT_HOPS = 3
MAX_JS_FILES_INSPECTED = 8
MAX_JS_ROUTE_CANDIDATES_PER_FILE = 50
MAX_QUEUE_SIZE = 500

# Endpoint *registration* (unlike a real request) never itself performs
# network I/O, so it is never bounded by MAX_CRAWL_REQUESTS/MAX_PAGES/
# MAX_RUNTIME_SECONDS -- a single page linking to hundreds of static
# assets, a single over-sized OpenAPI document listing hundreds of
# paths, or hundreds of same-origin links beyond MAX_CRAWL_DEPTH could
# otherwise register an unbounded number of endpoint records purely in
# memory, with no request ever sent. This is the same class of risk
# Phase 34 warns about for requests, applied to registration instead --
# `_AttackSurfaceBuilder.register_endpoint` enforces this ceiling
# directly, independent of every other bound.
MAX_REGISTERED_ENDPOINTS = 200

# A small, closed, never-crawler-derived list -- the same "fixed
# metadata-path model" precedent core.bug_bounty_assessment already
# established for robots.txt/sitemap.xml/security.txt. Never brute
# forced beyond these three.
_OPENAPI_CANDIDATE_PATHS = ("/openapi.json", "/swagger.json", "/api-docs")

_ROBOTS_PATH = "/robots.txt"
_SITEMAP_PATH = "/sitemap.xml"

_STATIC_ASSET_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".map",
    ".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip",
})

_API_PATH_PREFIXES = ("/api", "/rest")

_DISCOVERY_SOURCES = frozenset({
    "html_link", "html_form", "javascript_static", "openapi", "redirect", "robots", "sitemap", "seed",
})

_PARAMETER_LOCATIONS = frozenset({"query", "path", "form", "json_body", "header", "cookie"})

_CRAWL_EVIDENCE_ORDER = (
    "CRAWL_COMPLETED",
    "PAGE_LIMIT_REACHED",
    "REQUEST_CAP_REACHED",
    "RUNTIME_LIMIT_REACHED",
    "DEPTH_LIMIT_REACHED",
    "OUT_OF_SCOPE_LINK_REJECTED",
    "OUT_OF_SCOPE_REDIRECT_REJECTED",
    "REDIRECT_LIMIT_REACHED",
    "REQUEST_FAILED",
    "PARSE_ERROR",
    "ENDPOINT_LIMIT_REACHED",
)

# JS route strings: a quoted literal composed only of a conservative,
# closed character set -- no whitespace, no natural-language
# punctuation -- so any instruction-shaped or command-shaped text
# (which always contains spaces) can never match. Bounded length keeps
# a single pathological literal from producing an oversized candidate.
_JS_ROUTE_PATTERN = re.compile(r'["\'](/[A-Za-z0-9_\-./{}]{1,200})["\']')

_HIDDEN_INPUT_TYPES_TO_SKIP_VALUE = frozenset({"password"})


class BugBountyCrawlerError(ValueError):
    """Raised when a supplied `scope` or `transport` is structurally
    unusable by this orchestrator -- the same narrow condition
    `core.bug_bounty_assessment.BugBountyAssessmentError` raises for
    its own `scope`/`transport` arguments.

    Never raised because a candidate URL was out of scope, because a
    transport request failed, or because zero endpoints were
    discovered -- every one of those is a normal, honestly-reported
    result, never an exception.
    """


class _Transport(Protocol):
    def request(
        self, *, url: str, method: str, headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        ...


# ---------------------------------------------------------------------------
# Narrow, private input validators.
# ---------------------------------------------------------------------------


def _validate_scope_argument(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BugBountyCrawlerError("scope must be a mapping")
    if "target" not in value or "testing_profile" not in value:
        raise BugBountyCrawlerError("scope must contain 'target' and 'testing_profile'")
    if not isinstance(value["target"], str) or not value["target"].strip():
        raise BugBountyCrawlerError("scope['target'] must be a non-blank string")
    return value


def _validate_transport_argument(value: Any) -> None:
    if not hasattr(value, "request") or not callable(value.request):
        raise BugBountyCrawlerError("transport must expose a callable request(...) method")


# ---------------------------------------------------------------------------
# Deterministic id generation -- never random.
# ---------------------------------------------------------------------------


def _endpoint_id(*, scheme: str, host: str, port: int, path: str, method: str) -> str:
    payload = "|".join((scheme, host, str(port), path, method))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"EP-{digest}"


def _parameter_id(*, endpoint_id: str, name: str, location: str) -> str:
    payload = "|".join((endpoint_id, name, location))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"PARAM-{digest}"


# ---------------------------------------------------------------------------
# URL helpers. Every candidate this module builds is a *proposal* only --
# evaluate_bug_bounty_request_scope is the sole authority on whether it
# is ever actually requested.
# ---------------------------------------------------------------------------


def _strip_fragment(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))


def _resolve_candidate(*, base_url: str, href: Any) -> str | None:
    if not isinstance(href, str):
        return None
    stripped = href.strip()
    if not stripped:
        return None
    try:
        joined = urljoin(base_url, stripped)
    except ValueError:
        return None
    return _strip_fragment(joined)


def _is_static_asset_path(path: str) -> bool:
    lowered = path.lower()
    for ext in _STATIC_ASSET_EXTENSIONS:
        if lowered.endswith(ext):
            return True
    return False


def _is_api_shaped_path(path: str) -> bool:
    lowered = path.lower()
    return any(lowered == prefix or lowered.startswith(prefix + "/") for prefix in _API_PATH_PREFIXES)


def _endpoint_identity(*, url: str, method: str) -> tuple[str, str, int, str, str] | None:
    """Build the (scheme, host, port, path, method) identity tuple used
    for endpoint dedup, from a URL already reported by
    `evaluate_bug_bounty_request_scope` as `normalized_url` (so scheme/
    host/default-port/path are already normalized). Applies one
    additional, purely-local normalization on top -- stripping exactly
    one trailing slash (except the bare root path) -- for dedup
    identity only; this never changes what is actually requested.
    """
    parsed = urlsplit(url)
    if not parsed.hostname:
        return None
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    return (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), path, method)


# ---------------------------------------------------------------------------
# Bounded HTML parsing -- stdlib html.parser only, no new dependency.
# A parse failure is caught by the caller and reported as PARSE_ERROR,
# never a crash.
# ---------------------------------------------------------------------------


class _DiscoveryHTMLParser(HTMLParser):
    """Extracts same-origin-candidate hrefs/srcs and form structures
    from one bounded HTML document. Never executes anything, never
    evaluates scope itself -- purely a structural extractor."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form_stack: list[dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key.lower(): (value or "") for key, value in attrs}
        tag_lower = tag.lower()

        if tag_lower in ("a", "link") and attr_map.get("href"):
            self.links.append(attr_map["href"])
        elif tag_lower == "iframe" and attr_map.get("src"):
            self.links.append(attr_map["src"])
        elif tag_lower == "script" and attr_map.get("src"):
            self.scripts.append(attr_map["src"])
        elif tag_lower == "form":
            self._form_stack.append({
                "action": attr_map.get("action", ""),
                "method": (attr_map.get("method") or "GET").strip().upper(),
                "inputs": [],
            })
        elif tag_lower in ("input", "textarea", "select") and self._form_stack:
            name = attr_map.get("name")
            if name:
                self._form_stack[-1]["inputs"].append({
                    "name": name, "type": attr_map.get("type", "text").lower() if tag_lower == "input" else tag_lower,
                })

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form_stack:
            self.forms.append(self._form_stack.pop())

    def close(self) -> None:
        super().close()
        while self._form_stack:
            self.forms.append(self._form_stack.pop())


def _parse_html(body: str) -> _DiscoveryHTMLParser | None:
    parser = _DiscoveryHTMLParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        return None
    return parser


# ---------------------------------------------------------------------------
# Passive JavaScript route extraction -- inert by construction (see
# module docstring): the pattern cannot match natural-language text
# because it forbids whitespace within the quoted literal.
# ---------------------------------------------------------------------------


def _extract_js_routes(body: str) -> list[str]:
    """Bounded to at most `MAX_JS_ROUTE_CANDIDATES_PER_FILE` unique
    candidates -- a large, real (or deliberately pathological) bundle
    can contain many thousands of quoted string literals; deduplicating
    and capping here keeps every downstream candidate (`urljoin` +
    scope evaluation) call bounded per file, independent of
    MAX_RUNTIME_SECONDS's own per-request-only granularity."""
    seen: set[str] = set()
    candidates: list[str] = []
    for match in _JS_ROUTE_PATTERN.finditer(body):
        if len(candidates) >= MAX_JS_ROUTE_CANDIDATES_PER_FILE:
            break
        candidate = match.group(1)
        if candidate == "/" or "//" in candidate or candidate in seen:
            continue
        seen.add(candidate)
        candidates.append(candidate)
    return candidates


# ---------------------------------------------------------------------------
# robots.txt / sitemap.xml passive parsing. Reuses the same "genuine
# resource, never HTTP-200-alone" evidence-quality discipline
# core.bug_bounty_assessment._is_genuine_metadata_resource already
# established for this project (see that module's own docstring for
# the SPA-fallback rationale) -- a catch-all single-page-app route
# answering every unmatched path with HTTP 200 must never be treated
# as a genuine robots.txt/sitemap.xml, so its content is never parsed
# for paths.
# ---------------------------------------------------------------------------

_ROBOTS_BODY_MARKERS = ("user-agent:", "disallow:", "allow:", "sitemap:")
_SITEMAP_BODY_MARKERS = ("<?xml", "<urlset", "<sitemapindex")

_ROBOTS_DIRECTIVE_PATTERN = re.compile(r"(?im)^\s*(disallow|allow)\s*:\s*(\S+)")
_SITEMAP_LOC_PATTERN = re.compile(r"(?is)<loc>\s*([^<\s]+)\s*</loc>")


def _looks_like_genuine_robots(*, content_type: str | None, body: str) -> bool:
    if content_type == "text/plain":
        return True
    lowered = body.lower()
    return any(marker in lowered for marker in _ROBOTS_BODY_MARKERS)


def _looks_like_genuine_sitemap(*, content_type: str | None, body: str) -> bool:
    if content_type in ("application/xml", "text/xml"):
        return True
    lowered = body.lower()
    return any(marker in lowered for marker in _SITEMAP_BODY_MARKERS)


def _extract_robots_paths(body: str) -> list[str]:
    paths: list[str] = []
    for _directive, value in _ROBOTS_DIRECTIVE_PATTERN.findall(body):
        if value.startswith("/") and value != "/":
            paths.append(value)
    return paths


def _extract_sitemap_locs(body: str) -> list[str]:
    return _SITEMAP_LOC_PATTERN.findall(body)


# ---------------------------------------------------------------------------
# OpenAPI / Swagger passive parsing -- JSON only. A discovered document's
# own `servers`/`host` is always ignored; every extracted path is joined
# onto the already-authorized scope origin only, so a malicious document
# can never claim a different scan target.
# ---------------------------------------------------------------------------

_OPENAPI_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})


def _parse_openapi_document(body: str) -> dict[str, Any] | None:
    try:
        document = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(document, dict):
        return None
    paths = document.get("paths")
    if not isinstance(paths, dict) or not paths:
        return None
    return document


def _openapi_body_properties(operation: Mapping[str, Any]) -> list[str]:
    names: list[str] = []
    request_body = operation.get("requestBody")
    if isinstance(request_body, Mapping):
        content = request_body.get("content")
        if isinstance(content, Mapping):
            json_content = content.get("application/json")
            if isinstance(json_content, Mapping):
                schema = json_content.get("schema")
                if isinstance(schema, Mapping):
                    properties = schema.get("properties")
                    if isinstance(properties, Mapping):
                        names.extend(str(key) for key in properties)
    return names


def _openapi_parameters(operation: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Returns (name, location) pairs from an OpenAPI/Swagger operation's
    own `parameters` list -- `in: query|path|header` map directly;
    `in: body` (Swagger 2 style) contributes its schema's own
    properties as `json_body` parameters."""
    results: list[tuple[str, str]] = []
    raw_parameters = operation.get("parameters")
    if not isinstance(raw_parameters, list):
        return results
    for entry in raw_parameters:
        if not isinstance(entry, Mapping):
            continue
        name = entry.get("name")
        location = entry.get("in")
        if not isinstance(name, str) or not name:
            continue
        if location == "body":
            schema = entry.get("schema")
            if isinstance(schema, Mapping):
                properties = schema.get("properties")
                if isinstance(properties, Mapping):
                    results.extend((str(key), "json_body") for key in properties)
            continue
        if location in ("query", "path", "header"):
            results.append((name, location))
    return results


# ---------------------------------------------------------------------------
# Attack-surface accumulator -- one instance per crawl, never reused.
# ---------------------------------------------------------------------------


class _AttackSurfaceBuilder:
    def __init__(self) -> None:
        self.endpoints: dict[tuple[str, str, int, str, str], dict[str, Any]] = {}
        self.parameters: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.duplicates_prevented = 0
        self.limit_reached = False

    def register_endpoint(
        self, *, identity: tuple[str, str, int, str, str], canonical_url: str, method: str,
        source: str, depth: int, discovered_from: str | None, is_static_asset: bool,
    ) -> dict[str, Any] | None:
        """Registers `identity` and returns its record, or returns
        `None` (never registering) once `MAX_REGISTERED_ENDPOINTS` has
        already been reached -- the one central choke point every
        endpoint-registration call site in this module goes through, so
        no single caller (BFS crawl, OpenAPI document parsing, an
        over-depth link/JS candidate, or a form) can register an
        unbounded number of endpoints purely in memory, independent of
        whether any real network request was ever involved."""
        existing = self.endpoints.get(identity)
        if existing is not None:
            self.duplicates_prevented += 1
            return existing

        if len(self.endpoints) >= MAX_REGISTERED_ENDPOINTS:
            self.limit_reached = True
            return None

        scheme, host, port, path, http_method = identity
        record = {
            "endpoint_id": _endpoint_id(scheme=scheme, host=host, port=port, path=path, method=http_method),
            "scheme": scheme, "host": host, "port": port, "path": path, "method": http_method,
            "canonical_url": canonical_url,
            "source": source,
            "discovered_from": discovered_from,
            "depth": depth,
            "content_type": None,
            "status_code": None,
            "is_static_asset": is_static_asset,
            "fetched": False,
        }
        self.endpoints[identity] = record
        return record

    def mark_fetched(self, *, identity: tuple[str, str, int, str, str], status_code: int | None, content_type: str | None) -> None:
        record = self.endpoints.get(identity)
        if record is not None:
            record["fetched"] = True
            record["status_code"] = status_code
            record["content_type"] = content_type

    def register_parameter(self, *, endpoint_id: str, name: str, location: str, source: str) -> None:
        if location not in _PARAMETER_LOCATIONS:
            return
        key = (endpoint_id, name, location)
        existing = self.parameters.get(key)
        if existing is not None:
            if source not in existing["sources"]:
                existing["sources"].append(source)
            return
        self.parameters[key] = {
            "parameter_id": _parameter_id(endpoint_id=endpoint_id, name=name, location=location),
            "endpoint_id": endpoint_id, "name": name, "location": location,
            "sources": [source], "data_type": "unknown",
        }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_bug_bounty_crawl(
    *, scope: Any, transport: Any, clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Deterministically run one bounded, same-origin attack-surface
    crawl of `scope["target"]`, using only the injected `transport`.

    Both `scope`/`transport` are keyword-only and required, matching
    `core.bug_bounty_assessment.run_bug_bounty_assessment`'s own
    contract exactly (`scope` shaped like `core.bug_bounty_scope.
    create_bug_bounty_scope`'s return value; `transport` exposing a
    callable `request(*, url, method, headers=None)`). `clock` is
    injectable (defaults to `time.monotonic`) purely so tests can avoid
    real wall-clock waiting while still exercising the runtime bound --
    production code should never override it.

    Every proposed request -- the seed page, every same-origin link,
    every JavaScript-derived candidate, every OpenAPI-derived path,
    the three fixed OpenAPI candidate paths, and every redirect hop --
    is independently re-evaluated through `core.bug_bounty_scope.
    evaluate_bug_bounty_request_scope` immediately before being sent; a
    request scope reports as anything other than `"allow"` is never
    sent. At most `MAX_CRAWL_REQUESTS` (15) outbound transport calls
    are made, across at most `MAX_PAGES` (10) distinct pages, to a
    maximum link depth of `MAX_CRAWL_DEPTH` (2) from the seed, within
    `MAX_RUNTIME_SECONDS` (10.0) of wall-clock time as measured by
    `clock`, with at most `MAX_REDIRECT_HOPS` (3) hops followed per
    originating request -- whichever bound is reached first stops
    further requests, but never discards endpoints/parameters already
    discovered (mirroring this project's established "partial results
    are never silently thrown away" principle, e.g.
    `adapters.bug_bounty_nuclei`'s own phase-timeout handling).
    `MAX_RUNTIME_SECONDS` is the practically dominant bound (see its own
    constant-level comment for the real measurement behind that
    choice).

    Returns a new dict containing exactly `crawler_version` (always
    `"1"`), `target`, `endpoints` (list of canonical endpoint records,
    `endpoint_id`/`scheme`/`host`/`port`/`path`/`method`/
    `canonical_url`/`source`/`discovered_from`/`depth`/`content_type`/
    `status_code`/`is_static_asset`/`fetched`), `parameters` (list of
    canonical parameter records, `parameter_id`/`endpoint_id`/`name`/
    `location`/`sources`/`data_type`), `attack_surface_summary`
    (`endpoint_count`/`parameter_count`/`form_count`/
    `api_endpoint_count`/`method_counts`/`discovery_sources`),
    `telemetry` (`pages_requested`/`pages_discovered`/
    `endpoints_discovered`/`parameters_discovered`/`forms_discovered`/
    `javascript_files_inspected`/`openapi_documents_found`/
    `duplicates_prevented`/`out_of_scope_links_rejected`/
    `redirects_rejected`/`parse_errors`/`runtime_seconds`/
    `max_depth_reached`/`budget_exhausted`), `observed_evidence` (a
    deduplicated, fixed-order list of crawl-level evidence codes),
    `crawl_performed` (`True` iff at least one transport request was
    actually attempted), `execution_performed` (always `False` -- a
    crawl only makes bounded `GET` discovery requests; it never
    submits a form, never applies a remediation, and never triggers
    any downstream tool execution itself).

    Raises `BugBountyCrawlerError` only for a structurally unusable
    `scope`/`transport` argument to this function itself -- exactly
    like `core.bug_bounty_assessment.BugBountyAssessmentError`.
    """
    validated_scope = _validate_scope_argument(scope)
    _validate_transport_argument(transport)

    target = validated_scope["target"]
    start_time = clock()

    builder = _AttackSurfaceBuilder()
    request_count = 0
    pages_requested = 0
    javascript_files_inspected = 0
    openapi_documents_found = 0
    out_of_scope_links_rejected = 0
    redirects_rejected = 0
    parse_errors = 0
    max_depth_reached = 0
    queue_duplicates_prevented = 0
    triggered_evidence: set[str] = set()

    visited_paths: set[tuple[str, str, int, str]] = set()
    queue: list[tuple[str, int, str | None, str]] = [(target, 0, None, "seed")]
    queue_seen: set[str] = {_strip_fragment(target)}

    def _budget_exhausted() -> str | None:
        if builder.limit_reached:
            return "ENDPOINT_LIMIT_REACHED"
        if request_count >= MAX_CRAWL_REQUESTS:
            return "REQUEST_CAP_REACHED"
        if pages_requested >= MAX_PAGES:
            return "PAGE_LIMIT_REACHED"
        if (clock() - start_time) >= MAX_RUNTIME_SECONDS:
            return "RUNTIME_LIMIT_REACHED"
        return None

    def _enqueue(url: str, depth: int, discovered_from: str | None, source: str) -> None:
        nonlocal queue_duplicates_prevented
        if len(queue) >= MAX_QUEUE_SIZE:
            return
        stripped = _strip_fragment(url)
        if stripped in queue_seen:
            queue_duplicates_prevented += 1
            return
        queue_seen.add(stripped)
        queue.append((stripped, depth, discovered_from, source))

    def _fetch(url: str, *, method: str = "GET") -> dict[str, Any] | None:
        nonlocal request_count
        exhausted = _budget_exhausted()
        if exhausted is not None:
            triggered_evidence.add(exhausted)
            return None

        scope_result = evaluate_bug_bounty_request_scope(scope=validated_scope, url=url, method=method)
        if scope_result["decision"] != "allow":
            return "OUT_OF_SCOPE"  # sentinel distinguished from None by caller

        try:
            response = transport.request(url=scope_result["normalized_url"], method=scope_result["method"], headers=None)
        except Exception:
            request_count += 1
            triggered_evidence.add("REQUEST_FAILED")
            return None

        request_count += 1
        response = dict(response)
        response["_normalized_url"] = scope_result["normalized_url"]
        return response

    def _fetch_with_redirects(
        url: str, *, method: str = "GET", depth: int = 0, discovered_from: str | None = None,
    ) -> dict[str, Any] | None:
        nonlocal out_of_scope_links_rejected, redirects_rejected

        current_url = url
        result = _fetch(current_url, method=method)
        if result == "OUT_OF_SCOPE":
            out_of_scope_links_rejected += 1
            triggered_evidence.add("OUT_OF_SCOPE_LINK_REJECTED")
            return None
        response = result

        hop_count = 0
        while response is not None and isinstance(response.get("status_code"), int) \
                and 300 <= response["status_code"] < 400 and response.get("redirect_location"):
            if hop_count >= MAX_REDIRECT_HOPS:
                triggered_evidence.add("REDIRECT_LIMIT_REACHED")
                return None
            next_url = _resolve_candidate(base_url=current_url, href=response["redirect_location"])
            if next_url is None:
                return None
            next_result = _fetch(next_url, method=method)
            if next_result == "OUT_OF_SCOPE":
                redirects_rejected += 1
                triggered_evidence.add("OUT_OF_SCOPE_REDIRECT_REJECTED")
                return None
            hop_count += 1
            current_url = next_url
            response = next_result

        if hop_count > 0 and response is not None and method == "GET":
            # A followed, in-scope redirect landed on a genuinely
            # different in-scope URL -- record it as its own discovered,
            # fetched endpoint (source="redirect") rather than only
            # silently updating the original pre-redirect entry's
            # fetched state.
            landed_result = _register_from_scope_result(
                url=current_url, method="GET", source="redirect", depth=depth, discovered_from=discovered_from,
            )
            if landed_result is not None:
                landed_identity, _is_static = landed_result
                builder.mark_fetched(
                    identity=landed_identity, status_code=response.get("status_code"),
                    content_type=_content_type_of(response),
                )

        return response

    def _content_type_of(response: Mapping[str, Any]) -> str | None:
        headers = response.get("headers")
        if not isinstance(headers, Mapping):
            return None
        for key, value in headers.items():
            if isinstance(key, str) and key.lower() == "content-type" and isinstance(value, str):
                return value.split(";", 1)[0].strip().lower()
        return None

    def _register_from_scope_result(*, url: str, method: str, source: str, depth: int, discovered_from: str | None) -> tuple[tuple[str, str, int, str, str], bool] | None:
        """Evaluate scope for a would-be-registered (not necessarily
        fetched) candidate and register it into the inventory if
        in-scope. Returns (identity, is_static_asset) or None if out of
        scope / malformed.

        Scope is always evaluated using `GET` as a bureaucratic
        stand-in method -- exactly the same reasoning as the form-
        handling block below: this function registers a candidate, it
        never sends a request with `method`, so evaluating scope with
        `safe_active`'s own restricted method allowlist (`GET`/`HEAD`/
        `OPTIONS`) against the candidate's REAL method (e.g. an
        OpenAPI `POST` operation) would otherwise spuriously reject it
        from ever being recorded at all."""
        scope_result = evaluate_bug_bounty_request_scope(scope=validated_scope, url=url, method="GET")
        if scope_result["decision"] != "allow" or scope_result["normalized_url"] is None:
            return None
        identity = _endpoint_identity(url=scope_result["normalized_url"], method=method)
        if identity is None:
            return None
        is_static = _is_static_asset_path(identity[3])
        record = builder.register_endpoint(
            identity=identity, canonical_url=scope_result["normalized_url"], method=method,
            source=source, depth=depth, discovered_from=discovered_from, is_static_asset=is_static,
        )
        if record is None:
            return None
        for name, _value in parse_qsl(urlsplit(scope_result["normalized_url"]).query, keep_blank_values=True):
            builder.register_parameter(endpoint_id=identity_endpoint_id(identity), name=name, location="query", source="discovered_url")
        return identity, is_static

    def identity_endpoint_id(identity: tuple[str, str, int, str, str]) -> str:
        scheme, host, port, path, method = identity
        return _endpoint_id(scheme=scheme, host=host, port=port, path=path, method=method)

    # --- Fixed, closed OpenAPI candidate paths -- always attempted,
    # exactly like core.bug_bounty_assessment's own metadata paths. ---
    def _try_openapi_document(url: str) -> None:
        nonlocal openapi_documents_found, parse_errors
        response = _fetch_with_redirects(url)
        if response is None or response.get("status_code") != 200:
            return
        body = response.get("body_excerpt")
        if not isinstance(body, str) or not body:
            return
        document = _parse_openapi_document(body)
        if document is None:
            return
        openapi_documents_found += 1
        paths = document.get("paths")
        for raw_path, operations in paths.items():
            if not isinstance(raw_path, str) or not raw_path.startswith("/") or not isinstance(operations, Mapping):
                continue
            openapi_url = _resolve_candidate(base_url=target, href=raw_path)
            if openapi_url is None:
                continue
            for raw_method, operation in operations.items():
                if not isinstance(raw_method, str) or raw_method.lower() not in _OPENAPI_HTTP_METHODS:
                    continue
                if not isinstance(operation, Mapping):
                    continue
                http_method = raw_method.upper()
                result = _register_from_scope_result(
                    url=openapi_url, method=http_method, source="openapi", depth=0, discovered_from=url,
                )
                if result is None:
                    continue
                identity, _is_static = result
                endpoint_id = identity_endpoint_id(identity)
                for name, location in _openapi_parameters(operation):
                    builder.register_parameter(endpoint_id=endpoint_id, name=name, location=location, source="openapi")
                for name in _openapi_body_properties(operation):
                    builder.register_parameter(endpoint_id=endpoint_id, name=name, location="json_body", source="openapi")

    # The seed target itself is always registered up front, unconditionally
    # and at zero network cost (its identity is already known from
    # `scope["target"]`) -- so even a pathologically tight budget that
    # gets fully consumed by the fixed OpenAPI probes below still leaves
    # the run's own target recorded in the inventory, never an empty
    # result for a crawl that was genuinely attempted.
    _register_from_scope_result(url=target, method="GET", source="seed", depth=0, discovered_from=None)

    for openapi_path in _OPENAPI_CANDIDATE_PATHS:
        openapi_url = _resolve_candidate(base_url=target, href=openapi_path)
        if openapi_url is not None:
            _try_openapi_document(openapi_url)

    # --- Bounded BFS crawl of HTML/JS pages. ---
    while queue:
        exhausted = _budget_exhausted()
        if exhausted is not None:
            triggered_evidence.add(exhausted)
            break

        url, depth, discovered_from, source = queue.pop(0)
        max_depth_reached = max(max_depth_reached, depth)

        candidate_identity_probe = evaluate_bug_bounty_request_scope(scope=validated_scope, url=url, method="GET")
        if candidate_identity_probe["decision"] != "allow" or candidate_identity_probe["normalized_url"] is None:
            out_of_scope_links_rejected += 1
            triggered_evidence.add("OUT_OF_SCOPE_LINK_REJECTED")
            continue

        identity = _endpoint_identity(url=candidate_identity_probe["normalized_url"], method="GET")
        if identity is None:
            continue
        is_static_asset = _is_static_asset_path(identity[3])
        registered = builder.register_endpoint(
            identity=identity, canonical_url=candidate_identity_probe["normalized_url"], method="GET",
            source=source, depth=depth, discovered_from=discovered_from, is_static_asset=is_static_asset,
        )
        if registered is None:
            triggered_evidence.add("ENDPOINT_LIMIT_REACHED")
            break
        for name, _value in parse_qsl(urlsplit(candidate_identity_probe["normalized_url"]).query, keep_blank_values=True):
            builder.register_parameter(endpoint_id=identity_endpoint_id(identity), name=name, location="query", source="discovered_url")

        if is_static_asset:
            continue
        if identity in visited_paths:
            continue
        if depth > MAX_CRAWL_DEPTH:
            triggered_evidence.add("DEPTH_LIMIT_REACHED")
            continue

        is_javascript = identity[3].lower().endswith(".js")
        if is_javascript and javascript_files_inspected >= MAX_JS_FILES_INSPECTED:
            continue

        response = _fetch_with_redirects(
            candidate_identity_probe["normalized_url"], depth=depth, discovered_from=discovered_from,
        )
        if response is None:
            continue
        visited_paths.add(identity)
        pages_requested += 1

        content_type = _content_type_of(response)
        builder.mark_fetched(identity=identity, status_code=response.get("status_code"), content_type=content_type)

        body = response.get("body_excerpt")
        if not isinstance(body, str) or not body:
            continue

        if is_javascript:
            javascript_files_inspected += 1
            for route in _extract_js_routes(body):
                candidate_url = _resolve_candidate(base_url=response["_normalized_url"], href=route)
                if candidate_url is None:
                    continue
                if depth + 1 <= MAX_CRAWL_DEPTH:
                    _enqueue(candidate_url, depth + 1, response["_normalized_url"], "javascript_static")
                else:
                    _register_from_scope_result(
                        url=candidate_url, method="GET", source="javascript_static",
                        depth=depth + 1, discovered_from=response["_normalized_url"],
                    )
            continue

        if identity[3] == _ROBOTS_PATH:
            # Never HTTP-200-alone: an SPA catch-all answering every
            # unmatched path with 200 must not be parsed as if it were
            # a genuine robots.txt (the previously identified weak-
            # evidence issue -- see core.bug_bounty_assessment).
            if _looks_like_genuine_robots(content_type=content_type, body=body):
                for extracted_path in _extract_robots_paths(body):
                    candidate_url = _resolve_candidate(base_url=response["_normalized_url"], href=extracted_path)
                    if candidate_url is None:
                        continue
                    if depth + 1 <= MAX_CRAWL_DEPTH:
                        _enqueue(candidate_url, depth + 1, response["_normalized_url"], "robots")
                    else:
                        _register_from_scope_result(
                            url=candidate_url, method="GET", source="robots",
                            depth=depth + 1, discovered_from=response["_normalized_url"],
                        )
            continue

        if identity[3] == _SITEMAP_PATH:
            if _looks_like_genuine_sitemap(content_type=content_type, body=body):
                for loc in _extract_sitemap_locs(body):
                    candidate_url = _resolve_candidate(base_url=response["_normalized_url"], href=loc)
                    if candidate_url is None:
                        continue
                    if depth + 1 <= MAX_CRAWL_DEPTH:
                        _enqueue(candidate_url, depth + 1, response["_normalized_url"], "sitemap")
                    else:
                        _register_from_scope_result(
                            url=candidate_url, method="GET", source="sitemap",
                            depth=depth + 1, discovered_from=response["_normalized_url"],
                        )
            continue

        if content_type is not None and "html" not in content_type and "xml" not in content_type:
            continue
        if content_type is None and not (isinstance(body, str) and "<" in body):
            continue

        parsed_html = _parse_html(body)
        if parsed_html is None:
            parse_errors += 1
            continue

        for href in parsed_html.links:
            candidate_url = _resolve_candidate(base_url=response["_normalized_url"], href=href)
            if candidate_url is None:
                continue
            if depth + 1 <= MAX_CRAWL_DEPTH:
                _enqueue(candidate_url, depth + 1, response["_normalized_url"], "html_link")
            else:
                _register_from_scope_result(
                    url=candidate_url, method="GET", source="html_link", depth=depth + 1,
                    discovered_from=response["_normalized_url"],
                )

        for src in parsed_html.scripts:
            candidate_url = _resolve_candidate(base_url=response["_normalized_url"], href=src)
            if candidate_url is None:
                continue
            if depth + 1 <= MAX_CRAWL_DEPTH:
                _enqueue(candidate_url, depth + 1, response["_normalized_url"], "html_link")

        for form in parsed_html.forms:
            action = form.get("action") or response["_normalized_url"]
            form_url = _resolve_candidate(base_url=response["_normalized_url"], href=action)
            if form_url is None:
                continue
            form_method = (form.get("method") or "GET").strip().upper()
            if form_method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                form_method = "GET"

            # Scope-validate the form's action URL using GET as a
            # bureaucratic stand-in method: a form's real method (e.g.
            # POST) is never itself sent -- forms are discovery-only,
            # never submitted (see module docstring) -- so evaluating
            # scope with the profile's own restricted safe_active
            # method allowlist would otherwise spuriously reject a
            # POST-actioned form from ever being recorded at all.
            scope_probe = evaluate_bug_bounty_request_scope(scope=validated_scope, url=form_url, method="GET")
            if scope_probe["decision"] != "allow" or scope_probe["normalized_url"] is None:
                continue
            form_identity = _endpoint_identity(url=scope_probe["normalized_url"], method=form_method)
            if form_identity is None:
                continue
            form_registered = builder.register_endpoint(
                identity=form_identity, canonical_url=scope_probe["normalized_url"], method=form_method,
                source="html_form", depth=depth + 1, discovered_from=response["_normalized_url"],
                is_static_asset=False,
            )
            if form_registered is None:
                continue
            endpoint_id = identity_endpoint_id(form_identity)
            for name, _value in parse_qsl(urlsplit(scope_probe["normalized_url"]).query, keep_blank_values=True):
                builder.register_parameter(endpoint_id=endpoint_id, name=name, location="query", source="discovered_url")
            for input_field in form.get("inputs", []):
                name = input_field.get("name")
                if isinstance(name, str) and name:
                    builder.register_parameter(endpoint_id=endpoint_id, name=name, location="form", source="html_form")

    runtime_seconds = clock() - start_time
    crawl_performed = request_count > 0

    if not (queue and _budget_exhausted() is not None):
        triggered_evidence.add("CRAWL_COMPLETED")

    endpoints = list(builder.endpoints.values())
    parameters = list(builder.parameters.values())

    method_counts: dict[str, int] = {}
    for endpoint in endpoints:
        method_counts[endpoint["method"]] = method_counts.get(endpoint["method"], 0) + 1

    api_endpoint_count = sum(
        1 for endpoint in endpoints
        if endpoint["source"] == "openapi" or _is_api_shaped_path(endpoint["path"])
        or (endpoint["content_type"] and "json" in endpoint["content_type"])
    )
    form_count = sum(1 for endpoint in endpoints if endpoint["source"] == "html_form")
    discovery_sources = sorted({endpoint["source"] for endpoint in endpoints})

    observed_evidence = [code for code in _CRAWL_EVIDENCE_ORDER if code in triggered_evidence]

    return {
        "crawler_version": CRAWLER_VERSION,
        "target": target,
        "endpoints": endpoints,
        "parameters": parameters,
        "attack_surface_summary": {
            "endpoint_count": len(endpoints),
            "parameter_count": len(parameters),
            "form_count": form_count,
            "api_endpoint_count": api_endpoint_count,
            "method_counts": method_counts,
            "discovery_sources": discovery_sources,
        },
        "telemetry": {
            "pages_requested": pages_requested,
            "pages_discovered": len(builder.endpoints),
            "endpoints_discovered": len(endpoints),
            "parameters_discovered": len(parameters),
            "forms_discovered": form_count,
            "javascript_files_inspected": javascript_files_inspected,
            "openapi_documents_found": openapi_documents_found,
            "duplicates_prevented": builder.duplicates_prevented + queue_duplicates_prevented,
            "out_of_scope_links_rejected": out_of_scope_links_rejected,
            "redirects_rejected": redirects_rejected,
            "parse_errors": parse_errors,
            "runtime_seconds": runtime_seconds,
            "max_depth_reached": max_depth_reached,
            "budget_exhausted": _budget_exhausted() is not None,
        },
        "observed_evidence": observed_evidence,
        "crawl_performed": crawl_performed,
        "execution_performed": False,
    }
