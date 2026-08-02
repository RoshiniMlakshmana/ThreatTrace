"""Strict Supabase MCP descriptor adapter and live-response normalizer for
the approval persistence operations.

This module connects the transport-neutral two-phase bridge in
`core.approval_bridge` to the *actual observed* contract of the
`mcp__supabase__execute_sql` tool (established by a live, read-only
capability probe) -- without ever giving Python direct access to MCP,
without executing SQL inside this process, and without adding a concrete
Supabase client anywhere.

It has exactly two responsibilities:

- `prepare_supabase_mcp_call`: turn one of the four exact operation
  descriptors already emitted by `core.approval_persistence` (via
  `core.approval_bridge`) into exactly one fixed-template SQL statement,
  wrapped in the exact tool-call request shape Claude needs to invoke
  `mcp__supabase__execute_sql`. Every table name, function name, and
  column name in the generated SQL comes from a fixed constant owned by
  this module -- never from caller-supplied text. This is not a generic
  SQL builder: only the four already-committed descriptor shapes are
  understood, and any deviation (wrong table, wrong function, added or
  missing field, wrong column order in a `returning`/`columns` list) is
  rejected before any SQL is generated.
- `normalize_supabase_mcp_response`: parse the actual observed
  `{"result": "<prose containing one <untrusted-data-UUID> block>"}` /
  `{"error": {...}}` tool-response shapes into the bridge's own canonical
  `{"kind": "rows", "rows": [...]}` / `{"kind": "transport_error"}`
  envelope. A tool-level error's contents are never inspected, logged,
  or returned -- only its structural presence is used to classify the
  response. Any malformed, ambiguous, or unparseable success response is
  also treated as a transport error (never silently reinterpreted as
  zero rows), and PostgreSQL `timestamptz` text (observed as
  space-separated, short-offset text, not directly compatible with this
  project's Python-3.10-targeted `datetime.fromisoformat` usage
  elsewhere) is reformatted to this project's own canonical UTC `Z` form
  before being handed back.

This module never imports `supabase`, `requests`, `socket`, `subprocess`,
`os`, or any MCP module; never creates a database client; never executes
SQL; never reads an environment variable; and never retries anything.
Row-level and record-level validation remain entirely the responsibility
of `core.approval_bridge` and `core.approval_persistence`, which this
module never duplicates or bypasses.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any


class ApprovalMcpAdapterError(Exception):
    """Raised for any failure at this adapter's own boundary -- a
    malformed or unsupported operation descriptor, an internal
    preparation failure, or an invalid call to
    `normalize_supabase_mcp_response` (an unsupported operation name or a
    non-mapping `tool_response`).

    Messages are always one of a small, fixed set of generic phrases --
    never a descriptor, a value, generated SQL, a row, a tool error, an
    ID, an identity, a payload, a URL, a token, a key, or a traceback.
    A malformed-but-structurally-a-mapping tool response is never raised
    as this exception -- it is classified as `{"kind": "transport_error"}`
    and returned normally instead, exactly as
    `core.approval_persistence`'s own executor-invocation boundary
    already treats any executor failure.
    """


_INVALID_DESCRIPTOR_MESSAGE = "Invalid approval MCP descriptor."
_PREPARE_FAILURE_MESSAGE = "Approval MCP request could not be prepared."
_INVALID_RESPONSE_MESSAGE = "Invalid approval MCP response."

_MCP_TOOL_NAME = "mcp__supabase__execute_sql"

_APPROVALS_TABLE_SQL = "public.approvals"
_RPC_FUNCTION_NAME = "consume_approval_and_update_investigation_state"
_RPC_FUNCTION_SQL = "public." + _RPC_FUNCTION_NAME

_RECORD_FIELDS = (
    "id",
    "investigation_id",
    "action_type",
    "action_payload",
    "requested_by",
    "requested_at",
    "status",
    "approved_by",
    "approved_at",
    "rejected_by",
    "rejected_at",
    "rejection_reason",
    "expires_at",
    "consumed_by",
    "consumed_at",
    "created_at",
)

_SUPPORTED_OPERATIONS = (
    "insert_pending_approval",
    "load_approval_record",
    "apply_approval_review_transition",
    "apply_approval_consumption",
)
_SUPPORTED_OPERATIONS_SET = frozenset(_SUPPORTED_OPERATIONS)

_OPERATION_TIMESTAMP_FIELDS: dict[str, tuple[str, ...]] = {
    "insert_pending_approval": ("requested_at", "expires_at", "created_at"),
    "load_approval_record": (
        "requested_at", "approved_at", "rejected_at", "expires_at", "consumed_at", "created_at",
    ),
    "apply_approval_review_transition": (
        "requested_at", "approved_at", "rejected_at", "expires_at", "consumed_at", "created_at",
    ),
    "apply_approval_consumption": (
        "requested_at", "approved_at", "rejected_at", "expires_at", "consumed_at", "created_at",
        "investigation_updated_at",
    ),
}

# ---------------------------------------------------------------------------
# Descriptor shape constants (mirroring core.approval_persistence exactly)
# ---------------------------------------------------------------------------

_INSERT_TOP_FIELDS = frozenset({"operation", "table", "values", "returning"})
_INSERT_REQUIRED_VALUE_FIELDS = frozenset(
    {"investigation_id", "action_type", "action_payload", "requested_by", "requested_at", "status"}
)
_INSERT_ALLOWED_VALUE_FIELDS = _INSERT_REQUIRED_VALUE_FIELDS | {"expires_at"}
_INSERT_COLUMN_ORDER = (
    "investigation_id", "action_type", "action_payload", "requested_by", "requested_at", "status", "expires_at",
)
_INSERT_COLUMN_TYPES = {
    "investigation_id": "uuid",
    "action_type": "text",
    "action_payload": "jsonb",
    "requested_by": "text",
    "requested_at": "timestamptz",
    "status": "text",
    "expires_at": "timestamptz",
}

_SELECT_TOP_FIELDS = frozenset({"operation", "table", "columns", "filters", "limit"})

_UPDATE_TOP_FIELDS = frozenset({"operation", "table", "values", "filters", "returning"})
_REVIEW_NULL_FILTER_FIELDS = (
    "approved_by", "approved_at", "rejected_by", "rejected_at", "rejection_reason", "consumed_by", "consumed_at",
)
_REVIEW_FILTER_FIELDS_SET = frozenset({"id", "status"} | set(_REVIEW_NULL_FILTER_FIELDS))
_APPROVE_SET_FIELDS = ("status", "approved_by", "approved_at")
_APPROVE_SET_TYPES = {"status": "text", "approved_by": "text", "approved_at": "timestamptz"}
_REJECT_SET_FIELDS = ("status", "rejected_by", "rejected_at", "rejection_reason")
_REJECT_SET_TYPES = {"status": "text", "rejected_by": "text", "rejected_at": "timestamptz", "rejection_reason": "text"}

_RPC_TOP_FIELDS = frozenset({"operation", "function", "parameters"})
_RPC_PARAMETER_ORDER = ("approval_id", "expected_investigation_id", "expected_action_type", "consumed_by", "consumed_at")
_RPC_PARAMETER_TYPES = {
    "approval_id": "uuid",
    "expected_investigation_id": "uuid",
    "expected_action_type": "text",
    "consumed_by": "text",
    "consumed_at": "timestamptz",
}


# ---------------------------------------------------------------------------
# Narrow value encoders -- the only path from a validated Python value to
# a SQL literal. No caller-supplied identifier is ever accepted; only
# these value encoders exist, and only for the exact types the four
# approval descriptors ever use.
# ---------------------------------------------------------------------------

_UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_CANONICAL_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


def _encode_uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    if not _UUID_PATTERN.match(value):
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    return f"'{value}'::uuid"


def _encode_text(value: Any) -> str:
    if not isinstance(value, str):
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def _encode_timestamptz(value: Any) -> str:
    if not isinstance(value, str):
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    if not _CANONICAL_TIMESTAMP_PATTERN.match(value):
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    escaped = value.replace("'", "''")
    return f"'{escaped}'::timestamptz"


def _encode_jsonb(value: Any) -> str:
    if not isinstance(value, Mapping):
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    text = json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    escaped = text.replace("'", "''")
    return f"'{escaped}'::jsonb"


def _encode_value(value: Any, type_name: str) -> str:
    if type_name == "uuid":
        return _encode_uuid(value)
    if type_name == "text":
        return _encode_text(value)
    if type_name == "timestamptz":
        return _encode_timestamptz(value)
    if type_name == "jsonb":
        return _encode_jsonb(value)
    raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)  # pragma: no cover -- unreachable, defense in depth


# ---------------------------------------------------------------------------
# Fixed SQL-statement builders -- one per descriptor category, never a
# generic CRUD/SQL builder.
# ---------------------------------------------------------------------------


def _build_insert_sql(descriptor: Mapping[str, Any]) -> str:
    if set(descriptor) != _INSERT_TOP_FIELDS:
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    if descriptor["operation"] != "insert" or descriptor["table"] != "approvals":
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)

    values = descriptor["values"]
    if not isinstance(values, Mapping):
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    value_fields = set(values)
    if not (_INSERT_REQUIRED_VALUE_FIELDS <= value_fields <= _INSERT_ALLOWED_VALUE_FIELDS):
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    if values["status"] != "pending":
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)

    if descriptor["returning"] != list(_RECORD_FIELDS):
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)

    columns = [name for name in _INSERT_COLUMN_ORDER if name in values]
    encoded_values = [_encode_value(values[name], _INSERT_COLUMN_TYPES[name]) for name in columns]

    return (
        "INSERT INTO " + _APPROVALS_TABLE_SQL + " (" + ", ".join(columns) + ") "
        "VALUES (" + ", ".join(encoded_values) + ") "
        "RETURNING " + ", ".join(_RECORD_FIELDS) + ";"
    )


def _build_select_sql(descriptor: Mapping[str, Any]) -> str:
    if set(descriptor) != _SELECT_TOP_FIELDS:
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    if descriptor["operation"] != "select" or descriptor["table"] != "approvals":
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    if descriptor["columns"] != list(_RECORD_FIELDS):
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    if descriptor["limit"] != 2:
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)

    filters = descriptor["filters"]
    if not isinstance(filters, Mapping) or set(filters) != {"id"}:
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)

    approval_id_literal = _encode_uuid(filters["id"])

    return (
        "SELECT " + ", ".join(_RECORD_FIELDS) + " FROM " + _APPROVALS_TABLE_SQL +
        " WHERE id = " + approval_id_literal + " LIMIT 2;"
    )


def _build_update_sql(descriptor: Mapping[str, Any]) -> str:
    if set(descriptor) != _UPDATE_TOP_FIELDS:
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    if descriptor["operation"] != "update" or descriptor["table"] != "approvals":
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    if descriptor["returning"] != list(_RECORD_FIELDS):
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)

    values = descriptor["values"]
    if not isinstance(values, Mapping):
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)

    if set(values) == set(_APPROVE_SET_FIELDS):
        if values["status"] != "approved":
            raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
        set_fields, set_types = _APPROVE_SET_FIELDS, _APPROVE_SET_TYPES
    elif set(values) == set(_REJECT_SET_FIELDS):
        if values["status"] != "rejected":
            raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
        set_fields, set_types = _REJECT_SET_FIELDS, _REJECT_SET_TYPES
    else:
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)

    filters = descriptor["filters"]
    if not isinstance(filters, Mapping) or set(filters) != _REVIEW_FILTER_FIELDS_SET:
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    if filters["status"] != "pending":
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    for field_name in _REVIEW_NULL_FILTER_FIELDS:
        if filters[field_name] is not None:
            raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)

    approval_id_literal = _encode_uuid(filters["id"])

    set_clause = ", ".join(f"{name} = {_encode_value(values[name], set_types[name])}" for name in set_fields)
    where_clause = " AND ".join(
        ["id = " + approval_id_literal, "status = " + _encode_text("pending")]
        + [f"{name} IS NULL" for name in _REVIEW_NULL_FILTER_FIELDS]
    )

    return (
        "UPDATE " + _APPROVALS_TABLE_SQL + " SET " + set_clause +
        " WHERE " + where_clause + " RETURNING " + ", ".join(_RECORD_FIELDS) + ";"
    )


def _build_rpc_sql(descriptor: Mapping[str, Any]) -> str:
    if set(descriptor) != _RPC_TOP_FIELDS:
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    if descriptor["operation"] != "rpc" or descriptor["function"] != _RPC_FUNCTION_NAME:
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)

    parameters = descriptor["parameters"]
    if not isinstance(parameters, Mapping) or set(parameters) != set(_RPC_PARAMETER_ORDER):
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    if parameters["expected_action_type"] != "update_investigation_state":
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)

    encoded_args = [_encode_value(parameters[name], _RPC_PARAMETER_TYPES[name]) for name in _RPC_PARAMETER_ORDER]

    return "SELECT * FROM " + _RPC_FUNCTION_SQL + "(" + ", ".join(encoded_args) + ");"


def prepare_supabase_mcp_call(descriptor: Mapping[str, Any]) -> dict[str, Any]:
    """Convert one exact, already-verified approval-persistence operation
    descriptor into exactly one `mcp__supabase__execute_sql` tool-call
    request.

    Only the four descriptor shapes already emitted by
    `core.approval_persistence` (via `core.approval_bridge`) are
    understood: a pending-approval insert, an approval-by-ID select, an
    approve/reject conditional update, or the atomic consumption RPC. No
    other operation name, table, function, column set, filter set, or
    `returning`/`columns` order is accepted -- every identifier used in
    the generated SQL comes from a fixed constant owned by this module,
    never from the descriptor's own text. JSON-object key order in the
    descriptor is never security-significant; list order (column and
    `returning` order) is always checked exactly.

    Returns exactly:

        {
            "tool": "mcp__supabase__execute_sql",
            "arguments": {"query": "<one fixed-template SQL statement>"},
        }

    Raises `ApprovalMcpAdapterError` for a non-mapping descriptor, an
    unsupported or malformed descriptor shape, an unsafe value (a
    non-canonical UUID or timestamp, a non-string text value, a
    non-mapping JSONB value), or any unexpected internal failure. Never
    mutates `descriptor` or any nested value within it.
    """
    if not isinstance(descriptor, Mapping):
        raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)

    operation = descriptor.get("operation")

    try:
        if operation == "insert":
            sql = _build_insert_sql(descriptor)
        elif operation == "select":
            sql = _build_select_sql(descriptor)
        elif operation == "update":
            sql = _build_update_sql(descriptor)
        elif operation == "rpc":
            sql = _build_rpc_sql(descriptor)
        else:
            raise ApprovalMcpAdapterError(_INVALID_DESCRIPTOR_MESSAGE)
    except ApprovalMcpAdapterError:
        raise
    except Exception:
        raise ApprovalMcpAdapterError(_PREPARE_FAILURE_MESSAGE) from None

    return {
        "tool": _MCP_TOOL_NAME,
        "arguments": {"query": sql},
    }


# ---------------------------------------------------------------------------
# Live-response parsing -- matches the actual observed
# mcp__supabase__execute_sql envelope exactly.
# ---------------------------------------------------------------------------

_UNTRUSTED_BLOCK_PATTERN = re.compile(
    r"<untrusted-data-([0-9a-fA-F-]{36})>\r?\n(.*?)\r?\n</untrusted-data-\1>",
    re.DOTALL,
)

_RESPONSE_TIMESTAMP_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(\.\d+)?([+-]\d{2}(?::?\d{2})?)?$"
)


def _parse_untrusted_block(result_text: str) -> list[Any] | None:
    """Extract and JSON-parse the single `<untrusted-data-UUID>...
    </untrusted-data-UUID>` block's contents. Requires the opening and
    closing UUIDs to match (the regex backreference already enforces
    this) and requires exactly one such block to exist. Never executes,
    evaluates, or otherwise treats the block's text as instructions --
    only `json.loads` is ever used on it."""
    matches = list(_UNTRUSTED_BLOCK_PATTERN.finditer(result_text))
    if len(matches) != 1:
        return None

    block_text = matches[0].group(2)
    try:
        parsed = json.loads(block_text)
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(parsed, list):
        return None
    return parsed


def _normalize_response_timestamp(value: Any) -> str | None:
    """Reformat the observed PostgreSQL `timestamptz` text shape (space
    or `T` separator, an optional fractional-seconds component, and a
    2-or-4-digit UTC offset with or without a colon) into a form
    guaranteed parseable by `datetime.fromisoformat` under this project's
    Python 3.10 compatibility target, then canonicalize to this project's
    own UTC `Z`-suffixed form. Returns None for any naive, malformed,
    padded, or non-string value -- never generates a replacement
    timestamp."""
    if not isinstance(value, str):
        return None
    if value.strip() != value or not value:
        return None

    match = _RESPONSE_TIMESTAMP_PATTERN.match(value)
    if match is None:
        return None

    date_part, time_part, fraction, offset = match.groups()
    if offset is None:
        return None

    sign = offset[0]
    offset_digits = offset[1:].replace(":", "")
    if len(offset_digits) == 2:
        hours, minutes = offset_digits, "00"
    elif len(offset_digits) == 4:
        hours, minutes = offset_digits[:2], offset_digits[2:]
    else:
        return None
    normalized_offset = f"{sign}{hours}:{minutes}"

    iso_text = f"{date_part}T{time_part}{fraction or ''}{normalized_offset}"

    try:
        parsed = datetime.fromisoformat(iso_text)
    except ValueError:
        return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_row(operation: str, row: Any) -> dict[str, Any] | None:
    if not isinstance(row, Mapping):
        return None

    normalized = copy.deepcopy(dict(row))
    for field_name in _OPERATION_TIMESTAMP_FIELDS[operation]:
        if field_name not in normalized:
            continue
        value = normalized[field_name]
        if value is None:
            continue
        canonical = _normalize_response_timestamp(value)
        if canonical is None:
            return None
        normalized[field_name] = canonical

    return normalized


def normalize_supabase_mcp_response(operation: str, tool_response: Mapping[str, Any]) -> dict[str, Any]:
    """Parse one actual `mcp__supabase__execute_sql` tool response into
    the bridge's own canonical executor-response envelope.

    `operation` must be exactly one of `insert_pending_approval`,
    `load_approval_record`, `apply_approval_review_transition`, or
    `apply_approval_consumption` -- used only to select which known
    timestamp fields may appear in that operation's returned rows; this
    function never duplicates full approval-record validation, which
    remains entirely `core.approval_bridge`/`core.approval_persistence`'s
    responsibility.

    A genuine success response is `{"result": "<prose containing exactly
    one <untrusted-data-UUID>...</untrusted-data-UUID> block, whose
    interior is a JSON array of row objects>"}`; the opening and closing
    UUIDs must match. A genuine tool-level failure is
    `{"error": {...}}` -- its contents are never inspected, logged, or
    returned. Any other shape (both keys present, neither present, an
    unknown outer key, a non-string `result`, a missing or duplicated
    untrusted-data block, mismatched UUIDs, non-JSON or non-list block
    content, a non-mapping row, or a malformed timestamp within a row)
    is treated exactly like a genuine tool-level error -- returned as a
    transport error, never silently reinterpreted as zero rows.

    Returns exactly one of:

        {"kind": "rows", "rows": [...]}
        {"kind": "transport_error"}

    Raises `ApprovalMcpAdapterError` only for an unsupported `operation`
    name or a non-mapping `tool_response` -- never for any malformed
    shape of the response's own content, and never with any part of
    `tool_response` included in the exception. Never mutates
    `tool_response` or any nested value within it; every returned row is
    an independently-owned deep copy.
    """
    if operation not in _SUPPORTED_OPERATIONS_SET:
        raise ApprovalMcpAdapterError(_INVALID_RESPONSE_MESSAGE)
    if not isinstance(tool_response, Mapping):
        raise ApprovalMcpAdapterError(_INVALID_RESPONSE_MESSAGE)

    has_result = "result" in tool_response
    has_error = "error" in tool_response

    if has_result == has_error:
        # Both present, or neither present -- either way, not a genuine
        # single-shape response.
        return {"kind": "transport_error"}

    if set(tool_response) - {"result", "error"}:
        return {"kind": "transport_error"}

    if has_error:
        if not isinstance(tool_response["error"], Mapping):
            return {"kind": "transport_error"}
        return {"kind": "transport_error"}

    result_value = tool_response["result"]
    if not isinstance(result_value, str):
        return {"kind": "transport_error"}

    rows = _parse_untrusted_block(result_value)
    if rows is None:
        return {"kind": "transport_error"}

    normalized_rows: list[dict[str, Any]] = []
    for row in rows:
        normalized_row = _normalize_row(operation, row)
        if normalized_row is None:
            return {"kind": "transport_error"}
        normalized_rows.append(normalized_row)

    return {"kind": "rows", "rows": normalized_rows}
