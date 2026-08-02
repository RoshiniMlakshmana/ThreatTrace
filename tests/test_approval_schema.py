"""Static tests for the `approvals` table in supabase/schema.sql.

These tests only read supabase/schema.sql as plain text and parse it with a
small, quote-aware, balanced-parenthesis-tracking helper -- they never
connect to Supabase or PostgreSQL, never execute SQL, and never install or
use a third-party SQL parser. Fragile whole-file substring checks are
deliberately avoided in favor of first isolating the exact `approvals`
table block, then running targeted structural checks only within it.
"""

import re
from pathlib import Path

import pytest

from core.approval_request import ACTION_TYPES
from core.approval_transition import APPROVAL_STATUSES

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "supabase" / "schema.sql"

EXPECTED_COLUMN_ORDER = (
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

EXPECTED_CONSTRAINT_NAMES = (
    "chk_approvals_status",
    "chk_approvals_action_type",
    "chk_approvals_action_payload_object",
    "chk_approvals_requested_by_nonblank",
    "chk_approvals_approved_by_nonblank",
    "chk_approvals_rejected_by_nonblank",
    "chk_approvals_consumed_by_nonblank",
    "chk_approvals_lifecycle_pending",
    "chk_approvals_lifecycle_approved",
    "chk_approvals_lifecycle_rejected",
    "chk_approvals_lifecycle_consumed",
    "chk_approvals_created_after_requested",
    "chk_approvals_expires_after_requested",
    "chk_approvals_approved_after_requested",
    "chk_approvals_rejected_after_requested",
    "chk_approvals_consumed_after_approved",
    "chk_approvals_approved_before_expires",
    "chk_approvals_consumed_before_expires",
)

EXISTING_TABLE_NAMES = (
    "investigations",
    "evidence",
    "attack_mappings",
    "handoffs",
    "detection_results",
    "retests",
)


# ---------------------------------------------------------------------------
# Robust, quote-aware SQL parsing helpers (test-only; no third-party parser)
# ---------------------------------------------------------------------------

def _read_schema_text():
    return SCHEMA_PATH.read_text(encoding="utf-8")


def _find_table_start(schema_text, table_name):
    pattern = re.compile(
        r"create\s+table\s+if\s+not\s+exists\s+" + re.escape(table_name) + r"\b",
        re.IGNORECASE,
    )
    match = pattern.search(schema_text)
    assert match is not None, f"could not locate 'create table if not exists {table_name}' in schema.sql"
    return match.end()


def _extract_table_block(schema_text, table_name):
    """Return the exact column/constraint body of one CREATE TABLE
    statement, using balanced-parenthesis tracking that correctly skips
    over nested constraint parentheses and single-quoted SQL string
    literals (including doubled '' escapes)."""
    start_search_pos = _find_table_start(schema_text, table_name)
    open_paren_index = schema_text.find("(", start_search_pos)
    assert open_paren_index != -1, f"no opening parenthesis found for table {table_name}"

    depth = 1
    in_string = False
    index = open_paren_index + 1
    length = len(schema_text)

    while index < length:
        char = schema_text[index]
        if in_string:
            if char == "'":
                if index + 1 < length and schema_text[index + 1] == "'":
                    index += 2
                    continue
                in_string = False
            index += 1
            continue

        if char == "'":
            in_string = True
            index += 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return schema_text[open_paren_index + 1 : index]
        index += 1

    raise AssertionError(f"no matching closing parenthesis found for table {table_name}")


def _split_top_level(text):
    """Split a table body on commas, but only at parenthesis depth zero and
    only outside single-quoted SQL string literals."""
    items = []
    depth = 0
    in_string = False
    current = []
    index = 0
    length = len(text)

    while index < length:
        char = text[index]
        if in_string:
            current.append(char)
            if char == "'":
                if index + 1 < length and text[index + 1] == "'":
                    current.append("'")
                    index += 2
                    continue
                in_string = False
            index += 1
            continue

        if char == "'":
            in_string = True
            current.append(char)
            index += 1
            continue
        if char == "(":
            depth += 1
            current.append(char)
        elif char == ")":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            items.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        index += 1

    tail = "".join(current).strip()
    if tail:
        items.append(tail)

    return items


def _normalize_sql(text):
    """Collapse all whitespace (including newlines) to single spaces,
    without altering the contents of single-quoted string literals."""
    result = []
    in_string = False
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if in_string:
            result.append(char)
            if char == "'":
                if index + 1 < length and text[index + 1] == "'":
                    result.append("'")
                    index += 2
                    continue
                in_string = False
            index += 1
            continue
        if char == "'":
            in_string = True
            result.append(char)
            index += 1
            continue
        if char.isspace():
            if not result or result[-1] != " ":
                result.append(" ")
        else:
            result.append(char)
        index += 1
    return "".join(result).strip()


def _strip_line_comments(text):
    """Remove `-- ...` line comments from a SQL fragment, without altering
    the contents of single-quoted string literals (this table body's own
    inline comments are never inside a string, but the scanner remains
    quote-aware for correctness)."""
    result = []
    in_string = False
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if in_string:
            result.append(char)
            if char == "'":
                if index + 1 < length and text[index + 1] == "'":
                    result.append("'")
                    index += 2
                    continue
                in_string = False
            index += 1
            continue
        if char == "'":
            in_string = True
            result.append(char)
            index += 1
            continue
        if char == "-" and index + 1 < length and text[index + 1] == "-":
            newline_index = text.find("\n", index)
            if newline_index == -1:
                break
            result.append("\n")
            index = newline_index + 1
            continue
        result.append(char)
        index += 1
    return "".join(result)


def _classify_items(items):
    """Split normalized top-level items into (columns, constraints), each
    as a list of normalized item strings, preserving original order."""
    columns = []
    constraints = []
    for item in items:
        normalized = _normalize_sql(item)
        if normalized.lower().startswith("constraint "):
            constraints.append(normalized)
        else:
            columns.append(normalized)
    return columns, constraints


def _column_name(column_item):
    return column_item.split()[0]


def _constraint_name(constraint_item):
    tokens = constraint_item.split()
    assert tokens[0].lower() == "constraint"
    return tokens[1]


def _quoted_values(text):
    """Extract every single-quoted string literal's contents from a SQL
    fragment, correctly un-escaping doubled '' sequences."""
    return [match.replace("''", "'") for match in re.findall(r"'((?:[^']|'')*)'", text)]


def _schema_text():
    return _read_schema_text()


def _approvals_body():
    return _strip_line_comments(_extract_table_block(_schema_text(), "approvals"))


def _approvals_items():
    return _split_top_level(_approvals_body())


def _approvals_columns_and_constraints():
    return _classify_items(_approvals_items())


def _constraint_map():
    _columns, constraints = _approvals_columns_and_constraints()
    return {_constraint_name(item): item for item in constraints}


def _create_trigger_statements(schema_text):
    """Return (trigger_name, table_name, function_name) for every actual
    CREATE TRIGGER ... ON <table> ... EXECUTE {FUNCTION|PROCEDURE}
    <function>( statement in the schema -- never a DROP TRIGGER statement,
    a comment, a GRANT/REVOKE statement, or a bare mention of a function
    name elsewhere."""
    pattern = re.compile(
        r"create\s+trigger\s+(\w+)\s+.*?\bon\s+(\w+)\s+.*?"
        r"execute\s+(?:function|procedure)\s+([\w.]+)\s*\(",
        re.IGNORECASE | re.DOTALL,
    )
    return [(m.group(1), m.group(2), m.group(3)) for m in pattern.finditer(schema_text)]


# ---------------------------------------------------------------------------
# 1-7: table presence and structure
# ---------------------------------------------------------------------------

def test_001_approvals_table_exists_exactly_once():
    schema_text = _schema_text()
    matches = re.findall(
        r"create\s+table\s+if\s+not\s+exists\s+approvals\b", schema_text, re.IGNORECASE
    )
    assert len(matches) == 1


def test_002_uses_create_table_if_not_exists():
    schema_text = _schema_text()
    assert re.search(r"create\s+table\s+if\s+not\s+exists\s+approvals\b", schema_text, re.IGNORECASE)


def test_003_table_extraction_handles_nested_parentheses():
    body = _approvals_body()
    # The body contains multiple nested check(...) expressions -- if
    # extraction had stopped early on a nested closing paren, the body
    # would be truncated before the final chk_approvals_consumed_before_expires
    # constraint.
    assert "chk_approvals_consumed_before_expires" in body


def test_004_table_block_is_syntactically_closed():
    schema_text = _schema_text()
    start = _find_table_start(schema_text, "approvals")
    open_paren_index = schema_text.find("(", start)
    # Re-running extraction must not raise -- confirms balanced parens.
    _extract_table_block(schema_text, "approvals")
    assert open_paren_index != -1


def test_005_exactly_sixteen_column_entries():
    columns, _constraints = _approvals_columns_and_constraints()
    assert len(columns) == 16


def test_006_exactly_eighteen_named_constraint_entries():
    _columns, constraints = _approvals_columns_and_constraints()
    assert len(constraints) == 18


def test_007_no_unexpected_top_level_table_entry():
    columns, constraints = _approvals_columns_and_constraints()
    column_names = {_column_name(item) for item in columns}
    constraint_names = {_constraint_name(item) for item in constraints}
    assert column_names == set(EXPECTED_COLUMN_ORDER)
    assert constraint_names == set(EXPECTED_CONSTRAINT_NAMES)


# ---------------------------------------------------------------------------
# 8: exact column order
# ---------------------------------------------------------------------------

def test_008_column_order_equals_exact_sixteen_field_sequence():
    columns, _constraints = _approvals_columns_and_constraints()
    assert tuple(_column_name(item) for item in columns) == EXPECTED_COLUMN_ORDER


# ---------------------------------------------------------------------------
# 9-30: column types and defaults
# ---------------------------------------------------------------------------

def _column_text_by_name():
    columns, _constraints = _approvals_columns_and_constraints()
    return {_column_name(item): item for item in columns}


def test_009_id_is_uuid_primary_key_with_gen_random_uuid():
    text = _column_text_by_name()["id"].lower()
    assert "uuid" in text
    assert "primary key" in text
    assert "gen_random_uuid()" in text


def test_010_investigation_id_is_uuid_not_null():
    text = _column_text_by_name()["investigation_id"].lower()
    assert text.startswith("investigation_id uuid")
    assert "not null" in text


def test_011_investigation_id_references_investigations():
    text = _column_text_by_name()["investigation_id"].lower()
    assert "references investigations (id)" in text or "references investigations(id)" in text


def test_012_investigation_foreign_key_uses_on_delete_cascade():
    text = _column_text_by_name()["investigation_id"].lower()
    assert "on delete cascade" in text


def test_013_action_type_is_text_not_null():
    text = _column_text_by_name()["action_type"].lower()
    assert text.startswith("action_type text")
    assert "not null" in text


def test_014_action_payload_is_jsonb_not_null():
    text = _column_text_by_name()["action_payload"].lower()
    assert text.startswith("action_payload jsonb")
    assert "not null" in text


def test_015_requested_by_is_text_not_null():
    text = _column_text_by_name()["requested_by"].lower()
    assert text.startswith("requested_by text")
    assert "not null" in text


def test_016_requested_at_is_timestamptz_not_null():
    text = _column_text_by_name()["requested_at"].lower()
    assert text.startswith("requested_at timestamptz")
    assert "not null" in text


def test_017_requested_at_has_no_default():
    text = _column_text_by_name()["requested_at"].lower()
    assert "default" not in text


def test_018_status_is_text_not_null():
    text = _column_text_by_name()["status"].lower()
    assert text.startswith("status text")
    assert "not null" in text


def test_019_status_defaults_to_pending():
    text = _column_text_by_name()["status"].lower()
    assert "default 'pending'" in text


def test_020_approved_by_is_nullable_text():
    text = _column_text_by_name()["approved_by"].lower()
    assert text.startswith("approved_by text")
    assert "not null" not in text


def test_021_approved_at_is_nullable_timestamptz():
    text = _column_text_by_name()["approved_at"].lower()
    assert text.startswith("approved_at timestamptz")
    assert "not null" not in text


def test_022_rejected_by_is_nullable_text():
    text = _column_text_by_name()["rejected_by"].lower()
    assert text.startswith("rejected_by text")
    assert "not null" not in text


def test_023_rejected_at_is_nullable_timestamptz():
    text = _column_text_by_name()["rejected_at"].lower()
    assert text.startswith("rejected_at timestamptz")
    assert "not null" not in text


def test_024_rejection_reason_is_nullable_text():
    text = _column_text_by_name()["rejection_reason"].lower()
    assert text.startswith("rejection_reason text")
    assert "not null" not in text


def test_025_expires_at_is_nullable_timestamptz():
    text = _column_text_by_name()["expires_at"].lower()
    assert text.startswith("expires_at timestamptz")
    assert "not null" not in text


def test_026_consumed_by_is_nullable_text():
    text = _column_text_by_name()["consumed_by"].lower()
    assert text.startswith("consumed_by text")
    assert "not null" not in text


def test_027_consumed_at_is_nullable_timestamptz():
    text = _column_text_by_name()["consumed_at"].lower()
    assert text.startswith("consumed_at timestamptz")
    assert "not null" not in text


def test_028_created_at_is_timestamptz_not_null():
    text = _column_text_by_name()["created_at"].lower()
    assert text.startswith("created_at timestamptz")
    assert "not null" in text


def test_029_created_at_defaults_to_now():
    text = _column_text_by_name()["created_at"].lower()
    assert "default now()" in text


def test_030_no_lifecycle_timestamp_has_a_default():
    columns = _column_text_by_name()
    for field in ("approved_at", "rejected_at", "expires_at", "consumed_at"):
        assert "default" not in columns[field].lower()


# ---------------------------------------------------------------------------
# 31-38: exact exclusions
# ---------------------------------------------------------------------------

def test_031_no_updated_at_column():
    columns, _constraints = _approvals_columns_and_constraints()
    assert "updated_at" not in {_column_name(item) for item in columns}


def test_032_no_target_type_column():
    columns, _constraints = _approvals_columns_and_constraints()
    assert "target_type" not in {_column_name(item) for item in columns}


def test_033_no_target_id_column():
    columns, _constraints = _approvals_columns_and_constraints()
    assert "target_id" not in {_column_name(item) for item in columns}


def test_034_no_action_hash_column():
    columns, _constraints = _approvals_columns_and_constraints()
    assert "action_hash" not in {_column_name(item) for item in columns}


def test_035_no_revoked_at_column():
    columns, _constraints = _approvals_columns_and_constraints()
    assert "revoked_at" not in {_column_name(item) for item in columns}


def test_036_no_authenticated_user_column():
    columns, _constraints = _approvals_columns_and_constraints()
    names = {_column_name(item) for item in columns}
    assert "user_id" not in names
    assert "auth_user_id" not in names


def test_037_no_transition_version_column():
    columns, _constraints = _approvals_columns_and_constraints()
    assert "transition_version" not in {_column_name(item) for item in columns}


def test_038_no_approval_version_column():
    columns, _constraints = _approvals_columns_and_constraints()
    assert "approval_version" not in {_column_name(item) for item in columns}
    assert "version" not in {_column_name(item) for item in columns}


# ---------------------------------------------------------------------------
# 39-42: constraint names
# ---------------------------------------------------------------------------

def test_039_constraint_name_set_equals_exact_eighteen():
    _columns, constraints = _approvals_columns_and_constraints()
    names = {_constraint_name(item) for item in constraints}
    assert names == set(EXPECTED_CONSTRAINT_NAMES)


def test_040_every_constraint_name_begins_with_chk_approvals():
    _columns, constraints = _approvals_columns_and_constraints()
    for item in constraints:
        assert _constraint_name(item).startswith("chk_approvals_")


def test_041_no_unnamed_check_exists_in_approvals_block():
    body = _approvals_body()
    # Every "check(" occurrence in the table body must be preceded
    # (ignoring the constraint's own preamble) by a named "constraint <name>"
    # -- i.e., check(...) never appears as a bare inline column-level check.
    columns, _constraints = _approvals_columns_and_constraints()
    for column_item in columns:
        assert "check" not in column_item.lower()


def test_042_no_nineteenth_named_check_exists():
    _columns, constraints = _approvals_columns_and_constraints()
    assert len(constraints) == len(EXPECTED_CONSTRAINT_NAMES)


# ---------------------------------------------------------------------------
# 43-50: vocabulary alignment
# ---------------------------------------------------------------------------

def test_043_parse_status_vocabulary():
    constraint_text = _constraint_map()["chk_approvals_status"]
    values = _quoted_values(constraint_text)
    assert values  # non-empty


def test_044_sql_status_values_equal_python_approval_statuses():
    constraint_text = _constraint_map()["chk_approvals_status"]
    values = set(_quoted_values(constraint_text))
    assert values == set(APPROVAL_STATUSES)


def test_045_completed_absent_from_status_vocabulary():
    constraint_text = _constraint_map()["chk_approvals_status"]
    values = set(_quoted_values(constraint_text))
    assert "completed" not in values


def test_046_expired_absent_from_status_vocabulary():
    constraint_text = _constraint_map()["chk_approvals_status"]
    values = set(_quoted_values(constraint_text))
    assert "expired" not in values


def test_047_revoked_absent_from_status_vocabulary():
    constraint_text = _constraint_map()["chk_approvals_status"]
    values = set(_quoted_values(constraint_text))
    assert "revoked" not in values


def test_048_parse_action_type_vocabulary():
    constraint_text = _constraint_map()["chk_approvals_action_type"]
    values = _quoted_values(constraint_text)
    assert values


def test_049_sql_action_type_values_equal_python_action_types():
    constraint_text = _constraint_map()["chk_approvals_action_type"]
    values = set(_quoted_values(constraint_text))
    assert values == set(ACTION_TYPES)


def test_050_update_investigation_state_present_exactly_once():
    constraint_text = _constraint_map()["chk_approvals_action_type"]
    values = _quoted_values(constraint_text)
    assert values.count("update_investigation_state") == 1


# ---------------------------------------------------------------------------
# 51-55: action-payload policy
# ---------------------------------------------------------------------------

def test_051_action_payload_must_be_a_json_object():
    constraint_text = _constraint_map()["chk_approvals_action_payload_object"].lower()
    assert "jsonb_typeof(action_payload) = 'object'" in constraint_text


def test_052_payload_constraint_uses_jsonb_typeof():
    constraint_text = _constraint_map()["chk_approvals_action_payload_object"].lower()
    assert "jsonb_typeof" in constraint_text


def test_053_payload_constraint_does_not_encode_status_confidence_keys():
    constraint_text = _constraint_map()["chk_approvals_action_payload_object"].lower()
    assert "'status'" not in constraint_text
    assert "'confidence'" not in constraint_text


def test_054_payload_constraint_does_not_duplicate_investigation_vocabularies():
    constraint_text = _constraint_map()["chk_approvals_action_payload_object"].lower()
    for value in ("'escalated'", "'investigating'", "'high'", "'medium'", "'low'"):
        assert value not in constraint_text


def test_055_no_other_constraint_performs_action_payload_business_validation():
    for name, text in _constraint_map().items():
        if name == "chk_approvals_action_payload_object":
            continue
        assert "action_payload" not in text.lower()


# ---------------------------------------------------------------------------
# 56-62: nonblank text
# ---------------------------------------------------------------------------

def test_056_requested_by_must_be_stored_trimmed_and_nonblank():
    text = _constraint_map()["chk_approvals_requested_by_nonblank"].lower()
    assert "btrim(requested_by)" in text
    assert "<> ''" in text


def test_057_approved_by_must_be_null_or_trimmed_nonblank():
    text = _constraint_map()["chk_approvals_approved_by_nonblank"].lower()
    assert "approved_by is null" in text
    assert "btrim(approved_by)" in text


def test_058_rejected_by_must_be_null_or_trimmed_nonblank():
    text = _constraint_map()["chk_approvals_rejected_by_nonblank"].lower()
    assert "rejected_by is null" in text
    assert "btrim(rejected_by)" in text


def test_059_consumed_by_must_be_null_or_trimmed_nonblank():
    text = _constraint_map()["chk_approvals_consumed_by_nonblank"].lower()
    assert "consumed_by is null" in text
    assert "btrim(consumed_by)" in text


def test_060_no_identity_casing_transformation_exists():
    body = _approvals_body().lower()
    assert "lower(requested_by)" not in body
    assert "lower(approved_by)" not in body
    assert "lower(rejected_by)" not in body
    assert "lower(consumed_by)" not in body
    assert "upper(requested_by)" not in body


def test_061_no_lower_identity_comparison_exists():
    body = _approvals_body().lower()
    assert "lower(approved_by) <> lower(requested_by)" not in body
    assert "lower(btrim(approved_by))" not in body


def test_062_no_sql_casefold_approximation_exists():
    body = _approvals_body().lower()
    assert "casefold" not in body


# ---------------------------------------------------------------------------
# 63-74: lifecycle branches
# ---------------------------------------------------------------------------

def test_063_pending_branch_requires_every_lifecycle_field_null():
    text = _constraint_map()["chk_approvals_lifecycle_pending"].lower()
    for field in (
        "approved_by is null", "approved_at is null", "rejected_by is null",
        "rejected_at is null", "rejection_reason is null", "consumed_by is null",
        "consumed_at is null",
    ):
        assert field in text
    assert "'pending'" in text


def test_064_approved_branch_requires_approved_by_and_approved_at():
    text = _constraint_map()["chk_approvals_lifecycle_approved"].lower()
    assert "approved_by is not null" in text
    assert "approved_at is not null" in text


def test_065_approved_branch_requires_rejection_and_consumption_null():
    text = _constraint_map()["chk_approvals_lifecycle_approved"].lower()
    for field in ("rejected_by is null", "rejected_at is null", "rejection_reason is null", "consumed_by is null", "consumed_at is null"):
        assert field in text


def test_066_rejected_branch_requires_rejected_by_and_rejected_at():
    text = _constraint_map()["chk_approvals_lifecycle_rejected"].lower()
    assert "rejected_by is not null" in text
    assert "rejected_at is not null" in text


def test_067_rejected_branch_requires_rejection_reason():
    text = _constraint_map()["chk_approvals_lifecycle_rejected"].lower()
    assert "rejection_reason is not null" in text


def test_068_rejected_branch_requires_rejection_reason_outer_trimmed():
    text = _constraint_map()["chk_approvals_lifecycle_rejected"].lower()
    assert "rejection_reason = btrim(rejection_reason)" in text


def test_069_rejected_branch_requires_rejection_reason_nonblank():
    text = _constraint_map()["chk_approvals_lifecycle_rejected"]
    assert "btrim(rejection_reason) <> ''" in text.lower()


def test_070_rejected_branch_requires_approval_and_consumption_null():
    text = _constraint_map()["chk_approvals_lifecycle_rejected"].lower()
    for field in ("approved_by is null", "approved_at is null", "consumed_by is null", "consumed_at is null"):
        assert field in text


def test_071_consumed_branch_requires_approved_metadata():
    text = _constraint_map()["chk_approvals_lifecycle_consumed"].lower()
    assert "approved_by is not null" in text
    assert "approved_at is not null" in text


def test_072_consumed_branch_requires_consumed_metadata():
    text = _constraint_map()["chk_approvals_lifecycle_consumed"].lower()
    assert "consumed_by is not null" in text
    assert "consumed_at is not null" in text


def test_073_consumed_branch_requires_rejection_fields_null():
    text = _constraint_map()["chk_approvals_lifecycle_consumed"].lower()
    assert "rejected_by is null" in text
    assert "rejected_at is null" in text
    assert "rejection_reason is null" in text


def test_074_each_branch_uses_its_own_named_constraint():
    names = set(_constraint_map().keys())
    assert {
        "chk_approvals_lifecycle_pending",
        "chk_approvals_lifecycle_approved",
        "chk_approvals_lifecycle_rejected",
        "chk_approvals_lifecycle_consumed",
    } <= names


# ---------------------------------------------------------------------------
# 75-84: chronology
# ---------------------------------------------------------------------------

def test_075_created_at_after_or_equal_requested_at():
    text = _constraint_map()["chk_approvals_created_after_requested"].lower()
    assert "created_at >= requested_at" in text


def test_076_expires_at_strictly_after_requested_at_when_present():
    text = _constraint_map()["chk_approvals_expires_after_requested"].lower()
    assert "expires_at is null" in text
    assert "expires_at > requested_at" in text


def test_077_approved_at_after_or_equal_requested_at_when_present():
    text = _constraint_map()["chk_approvals_approved_after_requested"].lower()
    assert "approved_at is null" in text
    assert "approved_at >= requested_at" in text


def test_078_rejected_at_after_or_equal_requested_at_when_present():
    text = _constraint_map()["chk_approvals_rejected_after_requested"].lower()
    assert "rejected_at is null" in text
    assert "rejected_at >= requested_at" in text


def test_079_consumed_at_requires_approved_at_and_is_after_or_equal():
    text = _constraint_map()["chk_approvals_consumed_after_approved"].lower()
    assert "approved_at is not null" in text
    assert "consumed_at >= approved_at" in text


def test_080_approved_at_strictly_before_expires_at_when_both_exist():
    text = _constraint_map()["chk_approvals_approved_before_expires"].lower()
    assert "approved_at < expires_at" in text


def test_081_consumed_at_strictly_before_expires_at_when_both_exist():
    text = _constraint_map()["chk_approvals_consumed_before_expires"].lower()
    assert "consumed_at < expires_at" in text


def test_082_no_rejected_at_before_expires_constraint_exists():
    for name, text in _constraint_map().items():
        if name == "chk_approvals_rejected_after_requested":
            continue
        assert "rejected_at" not in text.lower() or "expires_at" not in text.lower()


def test_083_approval_exactly_at_expiry_is_structurally_rejected():
    text = _constraint_map()["chk_approvals_approved_before_expires"].lower()
    assert "<=" not in text
    assert "approved_at < expires_at" in text


def test_084_consumption_exactly_at_expiry_is_structurally_rejected():
    text = _constraint_map()["chk_approvals_consumed_before_expires"].lower()
    assert "<=" not in text
    assert "consumed_at < expires_at" in text


# ---------------------------------------------------------------------------
# 85-88: two-person boundary
# ---------------------------------------------------------------------------

def test_085_no_db_two_person_check_exists():
    names = set(_constraint_map().keys())
    for name in names:
        assert "two_person" not in name
        assert "reviewer" not in name


def test_086_no_approved_by_requested_by_lower_comparison_exists():
    body = _approvals_body().lower()
    assert "lower(approved_by)" not in body
    assert "lower(requested_by)" not in body


def test_087_schema_comment_documents_python_casefold_ownership():
    schema_text = _schema_text()
    # Locate the approvals-specific documentation block (table/column
    # comments), not the whole file, to avoid a false match elsewhere.
    approved_by_comment_match = re.search(
        r"comment on column approvals\.approved_by is\s*'([^']*(?:''[^']*)*)'",
        schema_text,
        re.IGNORECASE | re.DOTALL,
    )
    assert approved_by_comment_match is not None
    comment_text = approved_by_comment_match.group(1).lower()
    assert "casefold" in comment_text


def test_088_schema_does_not_claim_sql_equivalence_with_python_casefold():
    schema_text = _schema_text()
    approved_by_comment_match = re.search(
        r"comment on column approvals\.approved_by is\s*'([^']*(?:''[^']*)*)'",
        schema_text,
        re.IGNORECASE | re.DOTALL,
    )
    comment_text = approved_by_comment_match.group(1).lower()
    assert "not equivalent" in comment_text


# ---------------------------------------------------------------------------
# 89-97: indexes
# ---------------------------------------------------------------------------

def _index_statements():
    schema_text = _schema_text()
    return re.findall(
        r"create\s+(unique\s+)?index\s+if\s+not\s+exists\s+(\S+)\s+on\s+(\S+)\s*\(([^)]*)\)",
        schema_text,
        re.IGNORECASE,
    )


def test_089_idx_approvals_investigation_id_exists_exactly_once():
    matches = [m for m in _index_statements() if m[1] == "idx_approvals_investigation_id"]
    assert len(matches) == 1


def test_090_idx_approvals_investigation_id_indexes_only_investigation_id():
    matches = [m for m in _index_statements() if m[1] == "idx_approvals_investigation_id"]
    assert matches[0][3].strip() == "investigation_id"


def test_091_idx_approvals_status_exists_exactly_once():
    matches = [m for m in _index_statements() if m[1] == "idx_approvals_status"]
    assert len(matches) == 1


def test_092_idx_approvals_status_indexes_only_status():
    matches = [m for m in _index_statements() if m[1] == "idx_approvals_status"]
    assert matches[0][3].strip() == "status"


def test_093_idx_approvals_created_at_exists_exactly_once():
    matches = [m for m in _index_statements() if m[1] == "idx_approvals_created_at"]
    assert len(matches) == 1


def test_094_idx_approvals_created_at_indexes_only_created_at():
    matches = [m for m in _index_statements() if m[1] == "idx_approvals_created_at"]
    assert matches[0][3].strip() == "created_at"


def test_095_no_other_approvals_index_exists():
    approvals_indexes = {m[1] for m in _index_statements() if m[2] == "approvals"}
    assert approvals_indexes == {
        "idx_approvals_investigation_id",
        "idx_approvals_status",
        "idx_approvals_created_at",
    }


def test_096_no_approvals_unique_index_exists():
    for is_unique, name, table, _cols in _index_statements():
        if table == "approvals":
            assert is_unique.strip() == ""


def test_097_no_approvals_partial_index_exists():
    schema_text = _schema_text()
    approvals_index_block = "\n".join(
        line for line in schema_text.splitlines() if "idx_approvals_" in line.lower()
    )
    assert "where" not in approvals_index_block.lower()


# ---------------------------------------------------------------------------
# 98-102: RLS and policies
# ---------------------------------------------------------------------------

def test_098_approvals_rls_enabled_exactly_once():
    schema_text = _schema_text()
    matches = re.findall(
        r"alter\s+table\s+approvals\s+enable\s+row\s+level\s+security", schema_text, re.IGNORECASE
    )
    assert len(matches) == 1


def test_099_no_create_policy_targets_approvals():
    schema_text = _schema_text()
    assert not re.search(r"create\s+policy\s+\S*\s+on\s+approvals\b", schema_text, re.IGNORECASE)
    assert "create policy" not in schema_text.lower()


def test_100_no_auth_uid_approval_policy_exists():
    schema_text = _schema_text()
    assert "auth.uid()" not in schema_text.lower()


def test_101_no_claimed_identity_column_used_as_authorization_predicate():
    schema_text = _schema_text()
    assert "using (" not in schema_text.lower()
    assert "with check (" not in schema_text.lower()


def test_102_no_grant_statement_targets_approvals():
    schema_text = _schema_text()
    assert not re.search(r"grant\s+.*\bapprovals\b", schema_text, re.IGNORECASE)


# ---------------------------------------------------------------------------
# 103-107: triggers and mutable timestamps
# ---------------------------------------------------------------------------

def test_103_no_approvals_updated_at_trigger_exists():
    schema_text = _schema_text()
    assert not re.search(r"trigger\s+\S*approvals\S*updated_at", schema_text, re.IGNORECASE)


def test_104_no_approvals_immutability_trigger_exists():
    schema_text = _schema_text()
    assert not re.search(r"create\s+trigger\s+\S*approvals\S*", schema_text, re.IGNORECASE)


def test_105_no_approvals_lifecycle_trigger_exists():
    schema_text = _schema_text()
    assert "trg_approvals" not in schema_text.lower()


def test_106_no_trigger_targets_approvals_or_invokes_the_consumption_rpc():
    # test_106 originally used a blanket regex ("no CREATE OR REPLACE
    # FUNCTION whose name contains 'approval' may exist"), which was only
    # ever a proxy for its real intent: approvals must never gain a
    # trigger-support function wired to a trigger, the way investigations
    # has set_investigations_updated_at(). That blanket proxy broke once
    # Block 5 added a legitimate, explicitly invoked RPC,
    # public.consume_approval_and_update_investigation_state -- a callable
    # function, never a trigger target and never trigger-invoked. This
    # corrected version inspects actual CREATE TRIGGER declarations only
    # (never comments, GRANT/REVOKE statements, or bare function-name
    # mentions), so an explicit approval RPC is allowed to exist while a
    # trigger on approvals, or a trigger invoking the consumption RPC,
    # remains forbidden.
    schema_text = _schema_text()
    triggers = _create_trigger_statements(schema_text)
    assert triggers, "expected at least the existing investigations updated_at trigger to be found"
    for _trigger_name, table_name, function_name in triggers:
        assert table_name.lower() != "approvals"
        assert function_name.lower() != "consume_approval_and_update_investigation_state"
        assert not function_name.lower().endswith(".consume_approval_and_update_investigation_state")


def test_107_no_generic_updated_at_column_or_behavior_was_copied():
    columns, _constraints = _approvals_columns_and_constraints()
    assert "updated_at" not in {_column_name(item) for item in columns}


# ---------------------------------------------------------------------------
# 108-115: fresh-install compatibility
# ---------------------------------------------------------------------------

def test_108_table_uses_if_not_exists():
    schema_text = _schema_text()
    assert re.search(r"create\s+table\s+if\s+not\s+exists\s+approvals\b", schema_text, re.IGNORECASE)


def test_109_every_approval_index_uses_if_not_exists():
    schema_text = _schema_text()
    for index_name in ("idx_approvals_investigation_id", "idx_approvals_status", "idx_approvals_created_at"):
        assert re.search(
            r"create\s+index\s+if\s+not\s+exists\s+" + re.escape(index_name) + r"\b",
            schema_text,
            re.IGNORECASE,
        )


def test_110_no_migration_file_is_referenced():
    schema_text = _schema_text()
    assert "migrations/" not in schema_text.lower()
    assert not (REPO_ROOT / "supabase" / "migrations").exists()


def test_111_existing_schema_remains_one_coherent_fresh_install_script():
    schema_text = _schema_text()
    assert "-- Safety: This script is idempotent" in schema_text


def test_112_approval_addition_does_not_alter_existing_table_definitions():
    schema_text = _schema_text()
    for table_name in EXISTING_TABLE_NAMES:
        body = _extract_table_block(schema_text, table_name)
        assert "approvals" not in body.lower()


def test_113_approvals_table_appears_before_its_indexes():
    schema_text = _schema_text()
    table_index = schema_text.lower().index("create table if not exists approvals")
    index_index = schema_text.lower().index("create index if not exists idx_approvals_investigation_id")
    assert table_index < index_index


def test_114_approvals_table_appears_before_its_rls_statement():
    schema_text = _schema_text()
    table_index = schema_text.lower().index("create table if not exists approvals")
    rls_index = schema_text.lower().index("alter table approvals enable row level security")
    assert table_index < rls_index


def test_115_approvals_index_definitions_appear_before_rls_enablement():
    schema_text = _schema_text()
    last_index_pos = schema_text.lower().rindex("create index if not exists idx_approvals_created_at")
    rls_pos = schema_text.lower().index("alter table approvals enable row level security")
    assert last_index_pos < rls_pos


# ---------------------------------------------------------------------------
# 116-121: existing-concept separation
# ---------------------------------------------------------------------------

def test_116_approvals_does_not_reuse_retests_approval_status():
    body = _approvals_body().lower()
    assert "approval_status" not in body


def test_117_completed_appears_in_retest_context_only():
    schema_text = _schema_text()
    retests_body = _extract_table_block(schema_text, "retests")
    assert "completed" in retests_body.lower()

    approvals_body = _approvals_body().lower()
    assert "completed" not in approvals_body


def test_118_approvals_does_not_reference_handoffs_handoff_status():
    body = _approvals_body().lower()
    assert "handoff_status" not in body
    assert "handoffs" not in body


def test_119_approvals_does_not_reference_decision_analysis_fields():
    body = _approvals_body().lower()
    for field in ("current_assessment", "decision_status", "hypothesis_id"):
        assert field not in body


def test_120_no_decision_analysis_table_was_added():
    schema_text = _schema_text()
    assert not re.search(r"create\s+table\s+if\s+not\s+exists\s+decision_analys", schema_text, re.IGNORECASE)


def test_121_no_approval_events_table_was_added():
    schema_text = _schema_text()
    assert not re.search(r"create\s+table\s+if\s+not\s+exists\s+approval_events", schema_text, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Existing-schema preservation
# ---------------------------------------------------------------------------

def test_existing_six_tables_remain_present():
    schema_text = _schema_text()
    for table_name in EXISTING_TABLE_NAMES:
        assert re.search(
            r"create\s+table\s+if\s+not\s+exists\s+" + re.escape(table_name) + r"\b",
            schema_text,
            re.IGNORECASE,
        ), f"{table_name} is missing from schema.sql"


def test_existing_tables_unchanged_column_counts():
    schema_text = _schema_text()
    expected_column_counts = {
        "investigations": 8,
        "evidence": 23,
        "attack_mappings": 7,
        "handoffs": 7,
        "detection_results": 7,
        "retests": 6,
    }
    for table_name, expected_count in expected_column_counts.items():
        body = _strip_line_comments(_extract_table_block(schema_text, table_name))
        items = _split_top_level(body)
        columns, _constraints = _classify_items(items)
        assert len(columns) == expected_count, f"{table_name} column count changed: {len(columns)}"


# ---------------------------------------------------------------------------
# 122-135: source and runtime boundary of this test module itself
# ---------------------------------------------------------------------------

def _this_module_ast():
    import ast

    return ast.parse(Path(__file__).read_text(encoding="utf-8"))


def _imported_module_names(tree):
    import ast

    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
    return names


def test_122_test_imports_no_supabase_client():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert not any(name == "supabase" or name.startswith("supabase.") for name in imported)


def test_123_test_imports_no_requests():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert "requests" not in imported


def test_124_test_imports_no_subprocess():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert "subprocess" not in imported


def test_125_test_imports_no_socket():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert "socket" not in imported


def test_126_test_imports_no_urllib():
    tree = _this_module_ast()
    imported = _imported_module_names(tree)
    assert not any(name == "urllib" or name.startswith("urllib.") for name in imported)


def test_127_test_executes_no_sql():
    import ast

    tree = _this_module_ast()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in ("execute", "executemany", "executescript")


def test_128_test_opens_no_database_connection():
    import ast

    tree = _this_module_ast()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr != "connect"


def test_129_test_performs_no_network_request():
    import ast

    tree = _this_module_ast()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in ("get", "post", "urlopen", "create_connection")


def test_130_test_performs_no_file_write():
    import ast

    tree = _this_module_ast()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in ("write_text", "write_bytes", "write")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            positional_mode = node.args[1] if len(node.args) > 1 else None
            if isinstance(positional_mode, ast.Constant) and isinstance(positional_mode.value, str):
                assert "w" not in positional_mode.value
                assert "a" not in positional_mode.value


def test_131_test_performs_no_schema_mutation():
    schema_snapshot = SCHEMA_PATH.read_text(encoding="utf-8")
    _schema_text()
    _approvals_body()
    assert SCHEMA_PATH.read_text(encoding="utf-8") == schema_snapshot


def _called_or_referenced_names(tree):
    """Collect actual Name/Attribute identifiers used in executable code --
    deliberately excludes string-literal (ast.Constant) contents, so a bare
    self-referential substring search against this test module's own
    assertion strings (e.g. the literal text "containment" used only to
    prove its own absence) can never produce a false positive."""
    import ast

    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
    return names


def test_132_test_performs_no_approval_persistence():
    tree = _this_module_ast()
    names = _called_or_referenced_names(tree)
    assert "validate_approval_request" not in names
    assert "validate_approval_transition" not in names


def test_133_test_performs_no_investigation_update():
    tree = _this_module_ast()
    names = _called_or_referenced_names(tree)
    assert "update" not in names


def test_134_test_performs_no_containment():
    tree = _this_module_ast()
    names = _called_or_referenced_names(tree)
    assert not any("containment" in name.lower() for name in names)


def test_135_test_performs_no_red_team_execution():
    tree = _this_module_ast()
    names = _called_or_referenced_names(tree)
    assert not any(name.lower() in ("execute_simulation", "run_atomic") for name in names)


# ---------------------------------------------------------------------------
# Additional source-boundary check: only approved imports at module scope
# ---------------------------------------------------------------------------

def test_module_only_imports_approved_symbols():
    import ast

    tree = _this_module_ast()
    top_level_imports = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level_imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top_level_imports.add(node.module)

    allowed = {"re", "pathlib", "pytest", "core.approval_request", "core.approval_transition"}
    assert top_level_imports <= allowed
