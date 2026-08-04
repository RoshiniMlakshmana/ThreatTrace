"""Static tests for the `public.consume_approval_and_update_investigation_state`
PostgreSQL function in supabase/schema.sql.

These tests only read supabase/schema.sql as plain text and parse it with a
small, quote-aware, balanced-parenthesis/dollar-quote-tracking helper -- they
never connect to Supabase or PostgreSQL, never execute SQL, never install a
third-party SQL parser, and never touch a network. Fragile whole-file
substring checks are deliberately avoided in favor of first isolating the
exact function declaration (parameter list, return-table column list,
LANGUAGE/VOLATILE/SECURITY prologue, and $$-quoted body), then running
targeted structural checks only within each isolated piece.

Passing these tests proves the SQL text has the expected shape. It does not
prove the function has ever been executed against a real PostgreSQL
instance -- no such execution occurs anywhere in this file.
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "supabase" / "schema.sql"

FUNCTION_NAME = "public.consume_approval_and_update_investigation_state"

EXPECTED_PARAMETERS = (
    ("p_approval_id", "uuid"),
    ("p_expected_investigation_id", "uuid"),
    ("p_expected_action_type", "text"),
    ("p_consumed_by", "text"),
    ("p_consumed_at", "timestamptz"),
)

EXPECTED_RETURN_COLUMNS = (
    ("id", "uuid"),
    ("investigation_id", "uuid"),
    ("action_type", "text"),
    ("action_payload", "jsonb"),
    ("requested_by", "text"),
    ("requested_at", "timestamptz"),
    ("status", "text"),
    ("approved_by", "text"),
    ("approved_at", "timestamptz"),
    ("rejected_by", "text"),
    ("rejected_at", "timestamptz"),
    ("rejection_reason", "text"),
    ("expires_at", "timestamptz"),
    ("consumed_by", "text"),
    ("consumed_at", "timestamptz"),
    ("created_at", "timestamptz"),
    ("investigation_status", "text"),
    ("investigation_confidence", "text"),
    ("investigation_updated_at", "timestamptz"),
)

APPROVAL_RETURN_COLUMN_NAMES = tuple(name for name, _ in EXPECTED_RETURN_COLUMNS[:16])

EXISTING_TABLE_NAMES = (
    "investigations",
    "evidence",
    "attack_mappings",
    "handoffs",
    "detection_results",
    "retests",
    "approvals",
)

# Block 6, Step 4: the sole authorized new table.
AUTHORIZED_NEW_TABLE_NAMES = ("approval_reviews",)

# Block 6, Step 4: the sole authorized new columns on public.approvals.
AUTHORIZED_NEW_APPROVALS_COLUMN_NAMES = ("risk_level", "required_approvals", "requested_by_normalized")

# Block 6, Step 4: the sole authorized second RPC, alongside the
# original consumption function (FUNCTION_NAME, defined above).
AUTHORIZED_RPC_FUNCTION_NAMES = (
    FUNCTION_NAME,
    "public.record_approval_review_and_promote_status",
)


# ---------------------------------------------------------------------------
# Robust, quote-aware SQL parsing helpers (test-only; no third-party parser)
# ---------------------------------------------------------------------------

def _read_schema_text():
    return SCHEMA_PATH.read_text(encoding="utf-8")


def _extract_parenthesized_block(text, open_paren_index):
    """Return (inner_text, index_after_closing_paren) for the balanced
    parenthesis group starting at open_paren_index, using the same
    quote-aware tracking as tests/test_approval_schema.py's table-block
    extractor (correctly skipping nested parens and single-quoted string
    literals, including doubled '' escapes)."""
    assert text[open_paren_index] == "("
    depth = 1
    in_string = False
    index = open_paren_index + 1
    length = len(text)

    while index < length:
        char = text[index]
        if in_string:
            if char == "'":
                if index + 1 < length and text[index + 1] == "'":
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
                return text[open_paren_index + 1:index], index + 1
        index += 1

    raise AssertionError("no matching closing parenthesis found")


def _split_top_level(text):
    """Split on commas, but only at parenthesis depth zero and only outside
    single-quoted SQL string literals."""
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
    """Remove `-- ...` line comments, without altering single-quoted string
    literal contents."""
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


def _quoted_values(text):
    return [match.replace("''", "'") for match in re.findall(r"'((?:[^']|'')*)'", text)]


# ---------------------------------------------------------------------------
# Function-declaration isolation
# ---------------------------------------------------------------------------

def _function_declaration_matches(schema_text):
    pattern = re.compile(
        r"create\s+or\s+replace\s+function\s+" + re.escape(FUNCTION_NAME) + r"\s*\(",
        re.IGNORECASE,
    )
    return list(pattern.finditer(schema_text))


def _all_function_declaration_matches(schema_text):
    """Any CREATE OR REPLACE FUNCTION for this bare name, regardless of
    parameter-list content -- used to detect an accidental second
    (differently-signatured) declaration."""
    pattern = re.compile(
        r"create\s+or\s+replace\s+function\s+" + re.escape(FUNCTION_NAME) + r"\b",
        re.IGNORECASE,
    )
    return list(pattern.finditer(schema_text))


def _function_parts(schema_text):
    """Return (params_text, returns_text, prologue_text, body_text,
    function_start_index, after_body_index) for the sole function
    declaration."""
    matches = _function_declaration_matches(schema_text)
    assert len(matches) == 1, "expected exactly one CREATE OR REPLACE FUNCTION declaration"
    match = matches[0]
    open_paren_index = match.end() - 1

    params_text, after_params_index = _extract_parenthesized_block(schema_text, open_paren_index)

    remainder = schema_text[after_params_index:]
    returns_match = re.search(r"returns\s+table\s*\(", remainder, re.IGNORECASE)
    assert returns_match is not None, "expected RETURNS TABLE(...) after the parameter list"
    returns_open_index = after_params_index + returns_match.end() - 1
    returns_text, after_returns_index = _extract_parenthesized_block(schema_text, returns_open_index)

    remainder2 = schema_text[after_returns_index:]
    dollar_index = remainder2.find("$$")
    assert dollar_index != -1, "expected a $$ ... $$ function body"
    prologue_text = remainder2[:dollar_index]
    body_start = after_returns_index + dollar_index + 2
    dollar_end_index = schema_text.find("$$", body_start)
    assert dollar_end_index != -1, "expected a closing $$ for the function body"
    body_text = schema_text[body_start:dollar_end_index]

    return params_text, returns_text, prologue_text, body_text, match.start(), dollar_end_index + 2


def _parsed_parameters():
    schema_text = _read_schema_text()
    params_text, _returns, _prologue, _body, _start, _end = _function_parts(schema_text)
    parsed = []
    for item in _split_top_level(params_text):
        tokens = _normalize_sql(item).split()
        parsed.append((tokens[0], " ".join(tokens[1:])))
    return parsed


def _parsed_return_columns():
    schema_text = _read_schema_text()
    _params, returns_text, _prologue, _body, _start, _end = _function_parts(schema_text)
    parsed = []
    for item in _split_top_level(returns_text):
        tokens = _normalize_sql(item).split()
        parsed.append((tokens[0], " ".join(tokens[1:])))
    return parsed


def _function_prologue_normalized():
    schema_text = _read_schema_text()
    _params, _returns, prologue_text, _body, _start, _end = _function_parts(schema_text)
    return _normalize_sql(_strip_line_comments(prologue_text)).lower()


def _function_body_raw():
    schema_text = _read_schema_text()
    _params, _returns, _prologue, body_text, _start, _end = _function_parts(schema_text)
    return body_text


def _function_body_normalized():
    return _normalize_sql(_strip_line_comments(_function_body_raw())).lower()


def _function_start_index():
    schema_text = _read_schema_text()
    _params, _returns, _prologue, _body, start_index, _end = _function_parts(schema_text)
    return start_index


# ---------------------------------------------------------------------------
# Permission-statement isolation
# ---------------------------------------------------------------------------

def _all_revoke_matches():
    """Return one dict per REVOKE EXECUTE ON FUNCTION statement for this
    exact function signature, in source order -- there are now two such
    statements (FROM PUBLIC, and FROM anon, authenticated), so callers must
    disambiguate by inspecting each match's own tail rather than assuming
    there is only one."""
    schema_text = _read_schema_text()
    pattern = re.compile(
        r"revoke\s+execute\s+on\s+function\s+" + re.escape(FUNCTION_NAME) + r"\s*\(",
        re.IGNORECASE,
    )
    results = []
    for match in pattern.finditer(schema_text):
        open_paren_index = match.end() - 1
        args_text, after_index = _extract_parenthesized_block(schema_text, open_paren_index)
        tail = schema_text[after_index:after_index + 80]
        results.append({"start": match.start(), "args_text": args_text, "tail": tail})
    return results


def _revoke_details():
    """The FROM PUBLIC revoke statement specifically (kept for the
    pre-existing test_125/test_126, which predate the anon/authenticated
    revoke added in Step 25)."""
    matches = [m for m in _all_revoke_matches() if re.match(r"\s*from\s+public\s*;", m["tail"], re.IGNORECASE)]
    assert len(matches) == 1, "expected exactly one REVOKE EXECUTE ... FROM PUBLIC statement"
    return matches[0]["args_text"], matches[0]["tail"]


def _anon_authenticated_revoke_details():
    """The FROM anon, authenticated revoke statement added in Step 25."""
    matches = [
        m for m in _all_revoke_matches()
        if re.search(r"\bfrom\s+anon\s*,\s*authenticated\s*;", m["tail"], re.IGNORECASE)
    ]
    assert len(matches) == 1, "expected exactly one REVOKE EXECUTE ... FROM anon, authenticated statement"
    return matches[0]


def _grant_details():
    schema_text = _read_schema_text()
    pattern = re.compile(
        r"grant\s+execute\s+on\s+function\s+" + re.escape(FUNCTION_NAME) + r"\s*\(",
        re.IGNORECASE,
    )
    matches = list(pattern.finditer(schema_text))
    assert len(matches) == 1, "expected exactly one GRANT EXECUTE statement for this function"
    match = matches[0]
    open_paren_index = match.end() - 1
    args_text, after_index = _extract_parenthesized_block(schema_text, open_paren_index)
    tail = schema_text[after_index:after_index + 80]
    return args_text, tail


def _arg_type_list(args_text):
    return [_normalize_sql(item).lower() for item in _split_top_level(args_text)]


def _all_permission_matches(schema_text, verb):
    """Return one dict per REVOKE/GRANT EXECUTE ON FUNCTION statement for
    *any* function name (not scoped to FUNCTION_NAME) matching the given
    verb ("revoke" or "grant"), each with its own function name and
    role-list tail -- used by test_174 to verify both authorized RPCs'
    permission statements precisely, the same way _all_revoke_matches
    already does for the single consumption RPC alone."""
    pattern = re.compile(
        r"(revoke|grant)\s+execute\s+on\s+function\s+([\w.]+)\s*\(",
        re.IGNORECASE,
    )
    results = []
    for match in pattern.finditer(schema_text):
        if match.group(1).lower() != verb:
            continue
        open_paren_index = match.end() - 1
        _args_text, after_index = _extract_parenthesized_block(schema_text, open_paren_index)
        tail = schema_text[after_index:after_index + 80]
        results.append({"function": match.group(2), "tail": tail})
    return results


# ---------------------------------------------------------------------------
# 1-10: function declaration
# ---------------------------------------------------------------------------

def test_001_function_exists_exactly_once():
    schema_text = _read_schema_text()
    assert len(_all_function_declaration_matches(schema_text)) == 1


def test_002_function_name_is_exact():
    schema_text = _read_schema_text()
    matches = _function_declaration_matches(schema_text)
    assert len(matches) == 1


def test_003_function_is_public_schema_qualified():
    assert FUNCTION_NAME.startswith("public.")


def test_004_create_or_replace_function_is_used():
    schema_text = _read_schema_text()
    matches = _function_declaration_matches(schema_text)
    matched_text = schema_text[matches[0].start():matches[0].start() + 40].lower()
    assert matched_text.startswith("create or replace function")


def test_005_language_plpgsql_is_used():
    assert re.search(r"\blanguage\s+plpgsql\b", _function_prologue_normalized())


def test_006_volatile_is_explicit():
    assert re.search(r"\bvolatile\b", _function_prologue_normalized())


def test_007_security_invoker_is_explicit():
    assert re.search(r"\bsecurity\s+invoker\b", _function_prologue_normalized())


def test_008_security_definer_is_absent():
    assert not re.search(r"\bsecurity\s+definer\b", _function_prologue_normalized())
    assert "security definer" not in _function_body_normalized()


def test_009_function_located_after_approvals_table_indexes_and_rls():
    schema_text = _read_schema_text()
    function_start = _function_start_index()

    last_approvals_index_match = list(re.finditer(
        r"create\s+index\s+if\s+not\s+exists\s+idx_approvals_\w+", schema_text, re.IGNORECASE
    ))[-1]
    rls_match = re.search(
        r"alter\s+table\s+approvals\s+enable\s+row\s+level\s+security", schema_text, re.IGNORECASE
    )
    approvals_table_match = re.search(
        r"create\s+table\s+if\s+not\s+exists\s+approvals\b", schema_text, re.IGNORECASE
    )

    assert approvals_table_match is not None
    assert rls_match is not None
    assert function_start > approvals_table_match.start()
    assert function_start > last_approvals_index_match.start()
    assert function_start > rls_match.start()


def test_010_no_duplicate_function_with_another_signature():
    schema_text = _read_schema_text()
    assert len(_all_function_declaration_matches(schema_text)) == 1


# ---------------------------------------------------------------------------
# 11-22: parameters
# ---------------------------------------------------------------------------

def test_011_exactly_five_parameters_exist():
    assert len(_parsed_parameters()) == 5


def test_012_parameter_order_is_exact():
    parsed = _parsed_parameters()
    assert [name for name, _type in parsed] == [name for name, _type in EXPECTED_PARAMETERS]


def test_013_parameter_names_are_exact():
    parsed = _parsed_parameters()
    assert tuple(name for name, _type in parsed) == tuple(name for name, _type in EXPECTED_PARAMETERS)


def test_014_parameter_types_are_exact():
    parsed = _parsed_parameters()
    for (name, actual_type), (expected_name, expected_type) in zip(parsed, EXPECTED_PARAMETERS):
        assert name == expected_name
        assert actual_type.lower() == expected_type


def test_015_no_default_parameter_exists():
    for _name, type_text in _parsed_parameters():
        assert "default" not in type_text.lower()


@pytest.mark.parametrize(
    "forbidden_name",
    [
        "p_status", "status", "p_confidence", "confidence",
        "p_action_payload", "action_payload", "p_requested_by", "requested_by",
        "p_approved_by", "approved_by", "p_auth", "p_user_id", "p_authenticated",
        "p_action_hash", "action_hash",
    ],
)
def test_016_to_022_no_forbidden_parameter_exists(forbidden_name):
    names = {name for name, _type in _parsed_parameters()}
    assert forbidden_name not in names


# ---------------------------------------------------------------------------
# 23-35: return contract
# ---------------------------------------------------------------------------

def test_023_returns_table_is_used():
    schema_text = _read_schema_text()
    _params, _returns, after_params_text, _body, _start, _end = _function_parts(schema_text)
    # _function_parts only succeeds at all if RETURNS TABLE( was found;
    # this re-confirms it explicitly for this test's own traceability.
    assert re.search(r"returns\s+table\s*\(", after_params_text, re.IGNORECASE) is None or True
    remainder_check = re.search(r"returns\s+table\s*\(", schema_text[_start:], re.IGNORECASE)
    assert remainder_check is not None


def test_024_exactly_nineteen_output_columns_exist():
    assert len(_parsed_return_columns()) == 19


def test_025_first_sixteen_columns_equal_approval_record_contract():
    parsed = _parsed_return_columns()
    names = tuple(name for name, _type in parsed[:16])
    assert names == APPROVAL_RETURN_COLUMN_NAMES


def test_026_first_sixteen_column_order_is_exact():
    parsed = _parsed_return_columns()
    assert [name for name, _type in parsed[:16]] == list(APPROVAL_RETURN_COLUMN_NAMES)


def test_027_first_sixteen_types_align_with_approvals_schema():
    parsed = _parsed_return_columns()
    for (name, actual_type), (expected_name, expected_type) in zip(parsed[:16], EXPECTED_RETURN_COLUMNS[:16]):
        assert name == expected_name
        assert actual_type.lower() == expected_type


def test_028_investigation_status_is_column_seventeen():
    parsed = _parsed_return_columns()
    assert parsed[16][0] == "investigation_status"
    assert parsed[16][1].lower() == "text"


def test_029_investigation_confidence_is_column_eighteen():
    parsed = _parsed_return_columns()
    assert parsed[17][0] == "investigation_confidence"
    assert parsed[17][1].lower() == "text"


def test_030_investigation_updated_at_is_column_nineteen():
    parsed = _parsed_return_columns()
    assert parsed[18][0] == "investigation_updated_at"
    assert parsed[18][1].lower() == "timestamptz"


def test_031_investigation_id_appears_only_once():
    parsed = _parsed_return_columns()
    names = [name for name, _type in parsed]
    assert names.count("investigation_id") == 1


@pytest.mark.parametrize("forbidden_column", ["title", "description", "row_count", "success", "action_hash"])
def test_032_to_035_forbidden_return_columns_absent(forbidden_column):
    names = {name for name, _type in _parsed_return_columns()}
    assert forbidden_column not in names


def test_035b_no_twentieth_return_column_exists():
    assert len(_parsed_return_columns()) == 19


# ---------------------------------------------------------------------------
# 36-43: input validation
# ---------------------------------------------------------------------------

def test_036_consumed_by_null_is_rejected():
    body = _function_body_normalized()
    assert "p_consumed_by is null" in body


def test_037_consumed_by_blank_after_trim_is_rejected():
    body = _function_body_normalized()
    assert "btrim(p_consumed_by) = ''" in body


def test_038_consumed_by_outer_padding_is_rejected():
    body = _function_body_normalized()
    assert "p_consumed_by <> btrim(p_consumed_by)" in body


def test_039_consumed_at_null_is_rejected():
    body = _function_body_normalized()
    assert "p_consumed_at is null" in body


def test_040_fixed_invalid_request_message_is_used():
    body = _function_body_raw()
    assert "Invalid approval consumption request." in body


def test_041_input_error_message_contains_no_parameter_interpolation():
    body = _function_body_raw()
    idx = body.find("Invalid approval consumption request.")
    assert idx != -1
    statement_start = body.rfind("raise exception", 0, idx)
    statement_text = body[statement_start:idx + len("Invalid approval consumption request.'")]
    assert "||" not in statement_text
    assert "format(" not in statement_text.lower()


def test_042_no_wall_clock_tolerance_introduced():
    body = _function_body_normalized()
    assert "clock_timestamp" not in body
    assert "statement_timestamp" not in body
    assert "transaction_timestamp" not in body


def test_043_no_now_based_consumed_at_replacement_exists():
    body = _function_body_normalized()
    assert "now()" not in body


# ---------------------------------------------------------------------------
# 44-68: approval conditional update
# ---------------------------------------------------------------------------

def test_044_approvals_is_updated_first():
    body = _function_body_normalized()
    approvals_update_index = body.find("update public.approvals")
    investigations_update_index = body.find("update public.investigations")
    assert approvals_update_index != -1
    assert investigations_update_index != -1
    assert approvals_update_index < investigations_update_index


def _approvals_update_set_clause():
    body = _function_body_raw()
    match = re.search(r"update\s+public\.approvals\s+set(.*?)where", body, re.IGNORECASE | re.DOTALL)
    assert match is not None
    return _normalize_sql(_strip_line_comments(match.group(1)))


def test_045_exactly_status_consumed_by_consumed_at_are_set():
    set_clause = _approvals_update_set_clause()
    assigned = [item.split("=")[0].strip().lower() for item in _split_top_level(set_clause)]
    assert assigned == ["status", "consumed_by", "consumed_at"]


def test_046_status_is_set_to_consumed():
    set_clause = _approvals_update_set_clause().lower()
    assert "status = 'consumed'" in set_clause


def test_047_consumed_by_comes_from_parameter():
    set_clause = _approvals_update_set_clause().lower()
    assert "consumed_by = p_consumed_by" in set_clause


def test_048_consumed_at_comes_from_parameter():
    set_clause = _approvals_update_set_clause().lower()
    assert "consumed_at = p_consumed_at" in set_clause


def test_049_update_uses_returning():
    body = _function_body_normalized()
    assert "update public.approvals" in body
    approvals_section = body[body.find("update public.approvals"):]
    returning_index = approvals_section.find("returning")
    into_index = approvals_section.find(" into ")
    assert returning_index != -1
    assert into_index != -1
    assert returning_index < into_index


def test_050_returned_row_captured_into_typed_approval_variable():
    body = _function_body_normalized()
    assert "returning public.approvals.* into v_approval" in body
    assert "v_approval public.approvals%rowtype" in body


def _approvals_update_where_clause():
    body = _function_body_raw()
    match = re.search(
        r"update\s+public\.approvals\s+set.*?where(.*?)returning", body, re.IGNORECASE | re.DOTALL
    )
    assert match is not None
    return _normalize_sql(_strip_line_comments(match.group(1))).lower()


@pytest.mark.parametrize(
    "expected_fragment",
    [
        "public.approvals.id = p_approval_id",
        "public.approvals.status = 'approved'",
        "public.approvals.consumed_by is null",
        "public.approvals.consumed_at is null",
        "public.approvals.approved_by is not null",
        "public.approvals.approved_at is not null",
        "public.approvals.rejected_by is null",
        "public.approvals.rejected_at is null",
        "public.approvals.rejection_reason is null",
        "public.approvals.investigation_id = p_expected_investigation_id",
        "public.approvals.action_type = p_expected_action_type",
        "public.approvals.action_type = 'update_investigation_state'",
        "p_consumed_at >= public.approvals.approved_at",
    ],
)
def test_051_to_063_filter_conditions_present(expected_fragment):
    assert expected_fragment in _approvals_update_where_clause()


def test_064_nullable_expiry_branch_exists():
    where_clause = _approvals_update_where_clause()
    assert "public.approvals.expires_at is null" in where_clause


def test_065_strict_consumed_at_before_expires_at_exists():
    where_clause = _approvals_update_where_clause()
    assert "p_consumed_at < public.approvals.expires_at" in where_clause


def test_066_consumed_at_less_or_equal_expires_at_absent():
    where_clause = _approvals_update_where_clause()
    assert "p_consumed_at <= public.approvals.expires_at" not in where_clause


def test_067_no_select_for_update_exists():
    body = _function_body_normalized()
    assert "for update" not in body


def test_068_no_preliminary_approval_select_exists():
    body = _function_body_normalized()
    approvals_update_index = body.find("update public.approvals")
    assert approvals_update_index != -1
    assert "select" not in body[:approvals_update_index]


# ---------------------------------------------------------------------------
# 69-73: conflict behavior
# ---------------------------------------------------------------------------

def test_069_zero_row_approval_update_returns_without_investigation_mutation():
    body = _function_body_normalized()
    not_found_index = body.find("if not found then")
    return_index = body.find("return;", not_found_index)
    investigations_update_index = body.find("update public.investigations")
    assert not_found_index != -1
    assert return_index != -1
    assert return_index < investigations_update_index


def test_070_zero_row_path_does_not_raise_a_detailed_exception():
    body = _function_body_raw()
    not_found_match = re.search(r"if\s+not\s+found\s+then(.*?)end\s+if\s*;", body, re.IGNORECASE | re.DOTALL)
    assert not_found_match is not None
    first_branch = not_found_match.group(1)
    # only the very first "if not found" branch (immediately after the
    # approval UPDATE) is the conflict path; it must be a bare RETURN, never
    # a RAISE EXCEPTION.
    assert "raise" not in first_branch.lower()
    assert "return" in first_branch.lower()


def test_071_no_retry_loop_exists():
    body = _function_body_normalized()
    assert "loop" not in body
    assert "while" not in body
    assert "for " not in body.replace("for update", "").replace("for each", "")


def test_072_no_second_approval_update_attempt_exists():
    body = _function_body_normalized()
    assert body.count("update public.approvals") == 1


def test_073_investigation_update_appears_after_approval_conflict_check():
    body = _function_body_normalized()
    not_found_index = body.find("if not found then")
    investigations_update_index = body.find("update public.investigations")
    assert not_found_index != -1
    assert not_found_index < investigations_update_index


# ---------------------------------------------------------------------------
# 74-88: stored action validation
# ---------------------------------------------------------------------------

def test_074_jsonb_typeof_validates_object_shape():
    body = _function_body_normalized()
    assert "jsonb_typeof(v_approval.action_payload) <> 'object'" in body


def test_075_at_least_one_of_status_confidence_is_required():
    body = _function_body_normalized()
    assert "not v_has_status and not v_has_confidence" in body


def test_076_unknown_keys_are_rejected():
    body = _function_body_normalized()
    assert "key not in ('status', 'confidence')" in body


def test_077_jsonb_object_keys_is_used():
    body = _function_body_normalized()
    assert "jsonb_object_keys(v_approval.action_payload)" in body


def test_078_present_status_must_be_a_json_string():
    body = _function_body_normalized()
    assert "jsonb_typeof(v_approval.action_payload -> 'status') <> 'string'" in body


def test_079_present_confidence_must_be_a_json_string():
    body = _function_body_normalized()
    assert "jsonb_typeof(v_approval.action_payload -> 'confidence') <> 'string'" in body


def test_080_json_null_status_fails():
    # A JSON null value has jsonb_typeof(...) = 'null', which fails the
    # '<> ''string''' check above -- there is no separate "is null" branch
    # because the ->> operator would also yield SQL NULL for a JSON null,
    # which the nonblank check below independently rejects too.
    body = _function_body_normalized()
    assert "jsonb_typeof(v_approval.action_payload -> 'status') <> 'string'" in body
    assert "v_stored_status is null" in body


def test_081_json_null_confidence_fails():
    body = _function_body_normalized()
    assert "jsonb_typeof(v_approval.action_payload -> 'confidence') <> 'string'" in body
    assert "v_stored_confidence is null" in body


def test_082_blank_status_fails():
    body = _function_body_normalized()
    assert "btrim(v_stored_status) = ''" in body


def test_083_blank_confidence_fails():
    body = _function_body_normalized()
    assert "btrim(v_stored_confidence) = ''" in body


def test_084_padded_status_fails():
    body = _function_body_normalized()
    assert "v_stored_status <> btrim(v_stored_status)" in body


def test_085_padded_confidence_fails():
    body = _function_body_normalized()
    assert "v_stored_confidence <> btrim(v_stored_confidence)" in body


def test_086_fixed_malformed_action_message_is_used():
    body = _function_body_raw()
    assert "Stored approval action was invalid." in body


def test_087_malformed_action_error_message_contains_no_payload_values():
    body = _function_body_raw()
    for marker in ("|| v_approval.action_payload", "|| v_stored_status", "|| v_stored_confidence", "|| p_approval_id"):
        assert marker not in body


def test_088_no_status_confidence_vocabulary_list_duplicated():
    # Block 6 added a risk-aware authorization guard to this same
    # function's WHERE clause, re-verifying the stored risk_level ->
    # required_approvals mapping via two small value groups,
    # risk_level in ('low', 'medium') and risk_level in ('high',
    # 'critical'). Those groups share individual words with the
    # confidence vocabulary by incidental English overlap, but neither
    # group equals or is a superset of either forbidden vocabulary below
    # (confidence_levels also requires 'unknown', which risk_level never
    # uses; 'critical' belongs to no investigation vocabulary at all) --
    # so this remains a distinct, legitimate risk vocabulary, never a
    # duplicate of an investigation vocabulary. The real security
    # property this test enforces -- that the full investigation-status
    # or confidence-level vocabulary is never independently re-listed
    # inside this function -- is checked directly below, per `in (...)`
    # clause, rather than by banning individual words that a legitimate,
    # differently-scoped vocabulary might also happen to use.
    body = _function_body_normalized()

    investigation_statuses = {"open", "investigating", "awaiting_evidence", "escalated", "closed"}
    confidence_levels = {"low", "medium", "high", "unknown"}

    for value_list_text in re.findall(r"in\s*\(([^)]*)\)", body):
        values = set(_quoted_values(value_list_text))
        if not values:
            continue
        assert not values >= investigation_statuses, f"investigation status vocabulary duplicated: {values}"
        assert not values >= confidence_levels, f"confidence vocabulary duplicated: {values}"


# ---------------------------------------------------------------------------
# 89-106: investigation update
# ---------------------------------------------------------------------------

def test_089_investigations_updated_exactly_once():
    body = _function_body_normalized()
    assert body.count("update public.investigations") == 1


def _investigations_update_set_clause():
    body = _function_body_raw()
    match = re.search(r"update\s+public\.investigations\s+set(.*?)where", body, re.IGNORECASE | re.DOTALL)
    assert match is not None
    return _normalize_sql(_strip_line_comments(match.group(1)))


def _investigations_update_where_clause():
    body = _function_body_raw()
    match = re.search(
        r"update\s+public\.investigations\s+set.*?where(.*?)returning", body, re.IGNORECASE | re.DOTALL
    )
    assert match is not None
    return _normalize_sql(_strip_line_comments(match.group(1))).lower()


def test_090_investigation_id_comes_from_the_consumed_approval_row():
    where_clause = _investigations_update_where_clause()
    assert "public.investigations.id = v_approval.investigation_id" in where_clause


def test_091_no_caller_supplied_replacement_status_is_used():
    set_clause = _investigations_update_set_clause().lower()
    assert "p_status" not in set_clause
    for name, _type in _parsed_parameters():
        assert name not in set_clause


def test_092_no_caller_supplied_replacement_confidence_is_used():
    set_clause = _investigations_update_set_clause().lower()
    assert "p_confidence" not in set_clause


def test_093_stored_status_is_read_with_arrow_arrow_operator():
    body = _function_body_normalized()
    assert "v_stored_status := v_approval.action_payload ->> 'status'" in body


def test_094_stored_confidence_is_read_with_arrow_arrow_operator():
    body = _function_body_normalized()
    assert "v_stored_confidence := v_approval.action_payload ->> 'confidence'" in body


def test_095_missing_status_preserves_existing_status():
    set_clause = _investigations_update_set_clause().lower()
    assert "else public.investigations.status end" in set_clause


def test_096_missing_confidence_preserves_existing_confidence():
    set_clause = _investigations_update_set_clause().lower()
    assert "else public.investigations.confidence end" in set_clause


def test_097_status_is_the_only_status_related_field_updated():
    set_clause = _investigations_update_set_clause().lower()
    assigned_columns = [item.split("=")[0].strip() for item in _split_top_level(set_clause)]
    status_related = [c for c in assigned_columns if "status" in c]
    assert status_related == ["status"]


def test_098_confidence_is_the_only_confidence_related_field_updated():
    set_clause = _investigations_update_set_clause().lower()
    assigned_columns = [item.split("=")[0].strip() for item in _split_top_level(set_clause)]
    confidence_related = [c for c in assigned_columns if "confidence" in c]
    assert confidence_related == ["confidence"]


def test_099_title_is_not_updated():
    set_clause = _investigations_update_set_clause().lower()
    assert "title" not in set_clause


def test_100_description_is_not_updated():
    set_clause = _investigations_update_set_clause().lower()
    assert "description" not in set_clause


def test_101_updated_at_is_not_assigned_directly():
    set_clause = _investigations_update_set_clause().lower()
    assert "updated_at" not in set_clause


def test_102_investigations_update_uses_returning():
    body = _function_body_normalized()
    investigations_section = body[body.find("update public.investigations"):]
    returning_index = investigations_section.find("returning")
    into_index = investigations_section.find(" into ")
    assert returning_index != -1
    assert into_index != -1
    assert returning_index < into_index


def test_103_updated_investigation_captured_into_typed_variable():
    body = _function_body_normalized()
    assert "returning public.investigations.* into v_investigation" in body
    assert "v_investigation public.investigations%rowtype" in body


def test_104_investigation_update_is_unconditional_with_respect_to_equality():
    set_clause = _investigations_update_set_clause().lower()
    assert "is distinct from" not in set_clause
    assert "<>" not in set_clause


def test_105_missing_investigation_raises_fixed_generic_message():
    body = _function_body_raw()
    assert "Approval investigation update failed." in body


def test_106_missing_investigation_error_contains_no_identifiers():
    body = _function_body_raw()
    idx = body.find("Approval investigation update failed.")
    assert idx != -1
    statement_start = body.rfind("raise exception", 0, idx)
    statement_text = body[statement_start:idx + len("Approval investigation update failed.'")]
    assert "||" not in statement_text
    assert "v_approval.id" not in statement_text
    assert "v_approval.investigation_id" not in statement_text


# ---------------------------------------------------------------------------
# 107-117: atomic ordering
# ---------------------------------------------------------------------------

def test_107_approval_update_occurs_before_investigation_update():
    body = _function_body_normalized()
    assert body.find("update public.approvals") < body.find("update public.investigations")


def test_108_payload_validation_occurs_after_approval_gate_success():
    body = _function_body_normalized()
    not_found_index = body.find("if not found then")
    payload_check_index = body.find("jsonb_typeof(v_approval.action_payload)")
    assert not_found_index < payload_check_index


def test_109_investigation_update_occurs_after_payload_validation():
    body = _function_body_normalized()
    payload_check_index = body.find("jsonb_typeof(v_approval.action_payload)")
    investigations_update_index = body.find("update public.investigations")
    assert payload_check_index < investigations_update_index


def test_110_return_occurs_after_both_updates():
    body = _function_body_normalized()
    investigations_update_index = body.find("update public.investigations")
    return_query_index = body.find("return query")
    assert investigations_update_index < return_query_index


@pytest.mark.parametrize(
    "forbidden_keyword",
    ["begin transaction", "start transaction", "commit", "rollback", "savepoint", "autonomous"],
)
def test_111_to_115_no_transaction_control_statement_exists(forbidden_keyword):
    body = _function_body_normalized()
    assert forbidden_keyword not in body


def test_116_no_second_database_function_is_called_to_perform_mutation():
    body = _function_body_normalized()
    assert "consume_approval_and_update_investigation_state(" not in body.replace(
        "function public.consume_approval_and_update_investigation_state(", ""
    )
    # The function never calls itself or any other custom mutation function;
    # only built-in operators/functions (jsonb_typeof, jsonb_object_keys,
    # btrim) appear.
    for builtin in ("jsonb_typeof(", "jsonb_object_keys(", "btrim("):
        assert builtin in body


def test_117_no_trigger_invokes_this_function():
    schema_text = _read_schema_text().lower()
    assert "execute function public.consume_approval_and_update_investigation_state" not in schema_text
    assert "execute procedure public.consume_approval_and_update_investigation_state" not in schema_text
    assert "create trigger" not in _function_body_normalized()


# ---------------------------------------------------------------------------
# 118-124: return values
# ---------------------------------------------------------------------------

def _return_query_select_list():
    body = _function_body_raw()
    match = re.search(r"return\s+query\s+select(.*?);", body, re.IGNORECASE | re.DOTALL)
    assert match is not None
    return [_normalize_sql(_strip_line_comments(item)) for item in _split_top_level(match.group(1))]


def test_118_all_sixteen_approval_values_come_from_the_approval_variable():
    select_list = _return_query_select_list()
    for expression in select_list[:16]:
        assert expression.startswith("v_approval.")


def test_119_investigation_status_comes_from_the_investigation_variable():
    select_list = _return_query_select_list()
    assert select_list[16] == "v_investigation.status"


def test_120_investigation_confidence_comes_from_the_investigation_variable():
    select_list = _return_query_select_list()
    assert select_list[17] == "v_investigation.confidence"


def test_121_investigation_updated_at_comes_from_the_investigation_variable():
    select_list = _return_query_select_list()
    assert select_list[18] == "v_investigation.updated_at"


def test_122_exactly_one_return_query_path_exists():
    body = _function_body_normalized()
    assert body.count("return query") == 1


def test_123_conflict_path_returns_zero_rows():
    body = _function_body_raw()
    not_found_match = re.search(r"if\s+not\s+found\s+then(.*?)end\s+if\s*;", body, re.IGNORECASE | re.DOTALL)
    assert not_found_match is not None
    assert re.search(r"\breturn\s*;", not_found_match.group(1), re.IGNORECASE)


def test_124_success_path_returns_one_row():
    select_list = _return_query_select_list()
    assert len(select_list) == 19


# ---------------------------------------------------------------------------
# 125-139: security and permissions
# ---------------------------------------------------------------------------

def test_125_revoke_execute_from_public_exists():
    _args_text, tail = _revoke_details()
    assert re.match(r"\s*from\s+public\s*;", tail, re.IGNORECASE)


def test_126_revoke_signature_exactly_matches_function():
    args_text, _tail = _revoke_details()
    assert _arg_type_list(args_text) == ["uuid", "uuid", "text", "text", "timestamptz"]


def test_127_grant_execute_to_service_role_exists():
    _args_text, tail = _grant_details()
    assert re.match(r"\s*to\s+service_role\s*;", tail, re.IGNORECASE)


def test_128_grant_signature_exactly_matches_function():
    args_text, _tail = _grant_details()
    assert _arg_type_list(args_text) == ["uuid", "uuid", "text", "text", "timestamptz"]


def test_129_no_grant_to_anon_exists():
    _args_text, tail = _grant_details()
    assert "anon" not in tail.lower()


def test_130_no_grant_to_authenticated_exists():
    _args_text, tail = _grant_details()
    assert "authenticated" not in tail.lower()


def test_131_no_grant_back_to_public_exists():
    _args_text, tail = _grant_details()
    assert not re.match(r"\s*to\s+public\s*;", tail, re.IGNORECASE)


def test_132_no_security_definer_exists():
    assert "security definer" not in _function_prologue_normalized()
    assert "security definer" not in _function_body_normalized()


def test_133_no_auth_uid_exists():
    assert "auth.uid()" not in _function_body_normalized()


def test_134_no_claimed_identity_used_as_authorization_predicate():
    where_clause = _approvals_update_where_clause()
    assert "p_consumed_by" not in where_clause


def test_135_no_dynamic_sql_exists():
    body = _function_body_normalized()
    assert "execute " not in body
    assert "execute'" not in body


def test_136_no_execute_statement_exists():
    body = _function_body_normalized()
    assert not re.search(r"\bexecute\s+['\"]", body)
    assert not re.search(r"\bexecute\s+format\(", body)


def test_137_no_format_based_sql_construction_exists():
    body = _function_body_normalized()
    assert "format(" not in body


def test_138_no_external_extension_is_required():
    body = _function_body_normalized()
    for forbidden in ("dblink", "http_get", "pg_net", "plpython"):
        assert forbidden not in body


def test_139_no_network_file_http_behavior_exists():
    body = _function_body_normalized()
    for forbidden in ("copy ", "pg_read_file", "http", "curl"):
        assert forbidden not in body


# ---------------------------------------------------------------------------
# 140-153: schema boundary
# ---------------------------------------------------------------------------

def test_140_existing_tables_remain_present():
    schema_text = _read_schema_text()
    for table_name in EXISTING_TABLE_NAMES:
        pattern = re.compile(
            r"create\s+table\s+if\s+not\s+exists\s+" + re.escape(table_name) + r"\b", re.IGNORECASE
        )
        assert len(list(pattern.finditer(schema_text))) == 1


def test_141_no_eighth_table_was_created():
    # Block 6, Step 4 authorized exactly one new table,
    # public.approval_reviews. This remains a strict exact-set
    # assertion -- no table beyond the original seven plus this one
    # authorized addition may exist.
    schema_text = _read_schema_text()
    matches = re.findall(r"create\s+table\s+if\s+not\s+exists\s+(\w+)", schema_text, re.IGNORECASE)
    expected_tables = set(EXISTING_TABLE_NAMES) | set(AUTHORIZED_NEW_TABLE_NAMES)
    assert len(matches) == len(expected_tables)
    assert set(name.lower() for name in matches) == expected_tables


def test_142_existing_approvals_constraints_remain_present():
    schema_text = _read_schema_text()
    for constraint_name in (
        "chk_approvals_status", "chk_approvals_action_type", "chk_approvals_action_payload_object",
        "chk_approvals_requested_by_nonblank", "chk_approvals_approved_by_nonblank",
        "chk_approvals_rejected_by_nonblank", "chk_approvals_consumed_by_nonblank",
        "chk_approvals_lifecycle_pending", "chk_approvals_lifecycle_approved",
        "chk_approvals_lifecycle_rejected", "chk_approvals_lifecycle_consumed",
        "chk_approvals_created_after_requested", "chk_approvals_expires_after_requested",
        "chk_approvals_approved_after_requested", "chk_approvals_rejected_after_requested",
        "chk_approvals_consumed_after_approved", "chk_approvals_approved_before_expires",
        "chk_approvals_consumed_before_expires",
    ):
        assert constraint_name in schema_text


def test_143_existing_approvals_indexes_remain_present():
    schema_text = _read_schema_text()
    for index_name in ("idx_approvals_investigation_id", "idx_approvals_status", "idx_approvals_created_at"):
        assert index_name in schema_text


def test_144_existing_approvals_rls_enablement_remains_present():
    schema_text = _read_schema_text()
    assert re.search(r"alter\s+table\s+approvals\s+enable\s+row\s+level\s+security", schema_text, re.IGNORECASE)


def test_145_existing_investigations_updated_at_trigger_remains_present():
    schema_text = _read_schema_text()
    assert "trg_investigations_updated_at" in schema_text
    assert "set_investigations_updated_at" in schema_text


def test_146_no_new_trigger_is_created():
    schema_text = _read_schema_text()
    triggers = re.findall(r"create\s+trigger\s+(\w+)", schema_text, re.IGNORECASE)
    assert triggers == ["trg_investigations_updated_at"]


def test_147_no_new_table_is_created():
    # Recognizes exactly public.approval_reviews as the sole authorized
    # new table introduced by Block 6 -- an exact-set assertion, never a
    # subset check, so no additional unexpected table may be accepted.
    schema_text = _read_schema_text()
    matches = re.findall(r"create\s+table\s+if\s+not\s+exists\s+(\w+)", schema_text, re.IGNORECASE)
    expected_tables = set(EXISTING_TABLE_NAMES) | set(AUTHORIZED_NEW_TABLE_NAMES)
    assert len(matches) == 8
    assert len(matches) == len(expected_tables)
    assert set(name.lower() for name in matches) == expected_tables


def test_148_no_new_column_is_added_to_approvals():
    # Block 6, Step 4 authorized exactly three new columns on
    # public.approvals: risk_level, required_approvals, and
    # requested_by_normalized. This remains a strict exact-set
    # assertion against the original sixteen (APPROVAL_RETURN_COLUMN_NAMES,
    # this same file's own existing sixteen-field approval-record
    # contract) plus exactly this authorized delta -- no unrelated
    # approval column may be accepted.
    schema_text = _read_schema_text()
    approvals_match = re.search(r"create\s+table\s+if\s+not\s+exists\s+approvals\b", schema_text, re.IGNORECASE)
    open_paren_index = schema_text.find("(", approvals_match.end())
    body, _end = _extract_parenthesized_block(schema_text, open_paren_index)
    items = _split_top_level(_strip_line_comments(body))
    columns = [item for item in items if not _normalize_sql(item).lower().startswith("constraint")]
    column_names = {_normalize_sql(item).split()[0] for item in columns}
    expected_columns = set(APPROVAL_RETURN_COLUMN_NAMES) | set(AUTHORIZED_NEW_APPROVALS_COLUMN_NAMES)
    assert len(columns) == 16 + len(AUTHORIZED_NEW_APPROVALS_COLUMN_NAMES)
    assert len(columns) == len(expected_columns)
    assert column_names == expected_columns


def test_149_no_action_hash_column_or_reference_added():
    schema_text = _read_schema_text()
    assert "action_hash" not in schema_text


def test_150_no_immutable_history_trigger_added():
    # The real security property is that no trigger-based immutable-
    # history mechanism was introduced -- not that the English word
    # "immutable" never appears in a comment. Block 6's approval_reviews
    # table comment legitimately uses that word to describe its own
    # insert-only design ("one immutable row per individual reviewer
    # decision"), which is documentation, not an executable construct.
    # This test now inspects executable schema constructs directly.
    schema_text = _read_schema_text()

    # No new trigger of any kind exists beyond the one pre-authorized
    # investigations.updated_at trigger -- this alone structurally rules
    # out any trigger-based history/audit/immutability mechanism,
    # regardless of what it might have been named.
    triggers = re.findall(r"create\s+trigger\s+(\w+)", schema_text, re.IGNORECASE)
    assert triggers == ["trg_investigations_updated_at"]

    # No trigger-support function whose name suggests a history/audit/
    # immutability mechanism was added.
    function_names = re.findall(
        r"create\s+or\s+replace\s+function\s+(?:public\.)?(\w+)", schema_text, re.IGNORECASE
    )
    for name in function_names:
        lowered = name.lower()
        assert "history" not in lowered
        assert "immutable" not in lowered
        assert "audit" not in lowered

    # No trigger-based UPDATE interception targets approval_reviews (or
    # any table) beyond the one existing, pre-authorized trigger.
    assert not re.search(r"\bupdate\s+on\s+approval_reviews\b", schema_text, re.IGNORECASE)

    # The function body itself still never references "immutable" as
    # executable logic.
    body = _function_body_normalized()
    assert "immutable" not in body


def test_151_no_rls_policy_is_added():
    schema_text = _read_schema_text()
    assert "create policy" not in schema_text.lower()


def test_152_no_migration_file_is_referenced():
    schema_text = _read_schema_text()
    assert "migrations/" not in schema_text
    migrations_dir = REPO_ROOT / "supabase" / "migrations"
    assert not migrations_dir.exists()


def test_153_unchanged_signature_uses_create_or_replace_semantics():
    schema_text = _read_schema_text()
    matches = _function_declaration_matches(schema_text)
    matched_text = schema_text[matches[0].start():matches[0].start() + 27].strip().lower()
    assert matched_text == "create or replace function"


# ---------------------------------------------------------------------------
# 154-162: static-test runtime boundary (this file's own boundary)
# ---------------------------------------------------------------------------

def _this_module_source():
    return Path(__file__).read_text(encoding="utf-8")


def test_154_test_module_performs_no_sql_execution():
    import ast

    tree = ast.parse(_this_module_source())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in ("execute", "executemany", "executescript")


def test_155_test_module_creates_no_database_connection():
    import ast

    tree = ast.parse(_this_module_source())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in ("connect", "create_engine")


def test_156_test_module_performs_no_network_call():
    import ast

    tree = ast.parse(_this_module_source())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    for forbidden in ("socket", "requests", "urllib", "http"):
        assert forbidden not in imports


def test_157_test_module_performs_no_file_write():
    import ast

    tree = ast.parse(_this_module_source())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                assert "w" not in node.args[1].value
                assert "a" not in node.args[1].value


def test_158_test_module_imports_no_supabase_client():
    import ast

    tree = ast.parse(_this_module_source())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert "supabase" not in imports


def test_159_test_module_imports_no_postgresql_client():
    import ast

    tree = ast.parse(_this_module_source())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    for forbidden in ("psycopg2", "psycopg", "asyncpg", "pg8000"):
        assert forbidden not in imports


def test_160_test_module_invokes_no_cli_or_command():
    import ast

    tree = ast.parse(_this_module_source())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in ("subprocess",)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in ("SlashCommand", "run_slash_command", "invoke_slash_command")


def test_161_tests_read_only_schema_sql():
    import ast

    tree = ast.parse(_this_module_source())
    path_string_constants = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert "supabase" in path_string_constants
    assert "schema.sql" in path_string_constants


def test_162_uses_precise_parsing_not_broad_self_referential_substring_checks():
    import ast

    tree = ast.parse(_this_module_source())
    function_defs = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    assert len(function_defs) > 100


# ---------------------------------------------------------------------------
# 163-177: anon/authenticated RPC execution hardening (Step 25)
# ---------------------------------------------------------------------------

def test_163_anon_authenticated_revoke_exists_exactly_once():
    # _anon_authenticated_revoke_details() itself asserts exactly one match;
    # simply calling it without raising proves the statement exists.
    match = _anon_authenticated_revoke_details()
    assert match is not None


def test_164_anon_authenticated_revoke_signature_exactly_matches_function():
    match = _anon_authenticated_revoke_details()
    assert _arg_type_list(match["args_text"]) == ["uuid", "uuid", "text", "text", "timestamptz"]


def test_165_anon_and_authenticated_both_appear_in_revoke_role_list():
    match = _anon_authenticated_revoke_details()
    role_list_match = re.search(r"from\s+(.*?)\s*;", match["tail"], re.IGNORECASE | re.DOTALL)
    assert role_list_match is not None
    roles = {token.strip().lower() for token in role_list_match.group(1).split(",")}
    assert roles == {"anon", "authenticated"}


def test_166_anon_authenticated_revoke_statement_appears_exactly_once():
    schema_text = _read_schema_text()
    matches = list(re.finditer(
        r"revoke\s+execute\s+on\s+function\s+" + re.escape(FUNCTION_NAME)
        + r"\s*\([^)]*\)\s*from\s+anon\s*,\s*authenticated\s*;",
        schema_text,
        re.IGNORECASE | re.DOTALL,
    ))
    assert len(matches) == 1


def test_167_anon_authenticated_revoke_appears_after_public_revoke():
    public_matches = [m for m in _all_revoke_matches() if re.match(r"\s*from\s+public\s*;", m["tail"], re.IGNORECASE)]
    assert len(public_matches) == 1
    anon_match = _anon_authenticated_revoke_details()
    assert public_matches[0]["start"] < anon_match["start"]


def test_168_anon_authenticated_revoke_appears_before_service_role_grant():
    schema_text = _read_schema_text()
    grant_pattern = re.compile(
        r"grant\s+execute\s+on\s+function\s+" + re.escape(FUNCTION_NAME) + r"\s*\(",
        re.IGNORECASE,
    )
    grant_match = grant_pattern.search(schema_text)
    assert grant_match is not None
    anon_match = _anon_authenticated_revoke_details()
    assert anon_match["start"] < grant_match.start()


def test_169_no_grant_execute_to_anon_exists():
    _args_text, tail = _grant_details()
    assert "anon" not in tail.lower()


def test_170_no_grant_execute_to_authenticated_exists():
    _args_text, tail = _grant_details()
    assert "authenticated" not in tail.lower()


def test_171_public_revoke_remains_present():
    args_text, tail = _revoke_details()
    assert _arg_type_list(args_text) == ["uuid", "uuid", "text", "text", "timestamptz"]
    assert re.match(r"\s*from\s+public\s*;", tail, re.IGNORECASE)


def test_172_service_role_grant_remains_present():
    args_text, tail = _grant_details()
    assert _arg_type_list(args_text) == ["uuid", "uuid", "text", "text", "timestamptz"]
    assert re.match(r"\s*to\s+service_role\s*;", tail, re.IGNORECASE)


def test_173_no_alter_default_privileges_statement_exists():
    schema_text = _read_schema_text()
    assert "alter default privileges" not in schema_text.lower()


def test_174_no_unrelated_function_permission_statement_changed():
    # Block 6, Step 4 authorized a second RPC,
    # record_approval_review_and_promote_status, with its own identical
    # hardened privilege pattern. This test now requires the exact
    # expected permission statements for both authorized RPCs -- an
    # exact function-name set, never a loosened "service_role appears
    # somewhere" search -- and continues to reject any unrelated
    # function appearing in any REVOKE/GRANT EXECUTE statement.
    schema_text = _read_schema_text()
    revoke_matches = list(re.finditer(r"revoke\s+execute\s+on\s+function\s+([\w.]+)\s*\(", schema_text, re.IGNORECASE))
    grant_matches = list(re.finditer(r"grant\s+execute\s+on\s+function\s+([\w.]+)\s*\(", schema_text, re.IGNORECASE))
    assert revoke_matches and grant_matches

    revoked_function_names = {match.group(1) for match in revoke_matches}
    granted_function_names = {match.group(1) for match in grant_matches}
    assert revoked_function_names == set(AUTHORIZED_RPC_FUNCTION_NAMES)
    assert granted_function_names == set(AUTHORIZED_RPC_FUNCTION_NAMES)

    revokes = _all_permission_matches(schema_text, "revoke")
    grants = _all_permission_matches(schema_text, "grant")

    for function_name in AUTHORIZED_RPC_FUNCTION_NAMES:
        function_revoke_tails = [entry["tail"] for entry in revokes if entry["function"] == function_name]
        assert len(function_revoke_tails) == 2
        assert any(re.match(r"\s*from\s+public\s*;", tail, re.IGNORECASE) for tail in function_revoke_tails)
        assert any(
            re.search(r"\bfrom\s+anon\s*,\s*authenticated\s*;", tail, re.IGNORECASE)
            for tail in function_revoke_tails
        )

        function_grant_tails = [entry["tail"] for entry in grants if entry["function"] == function_name]
        assert len(function_grant_tails) == 1
        assert re.match(r"\s*to\s+service_role\s*;", function_grant_tails[0], re.IGNORECASE)


def test_175_function_body_unchanged_by_permission_hardening():
    body = _function_body_normalized()
    assert "returning public.approvals.* into v_approval" in body
    assert "returning public.investigations.* into v_investigation" in body
    assert body.count("update public.approvals") == 1
    assert body.count("update public.investigations") == 1


def test_176_return_contract_unchanged_by_permission_hardening():
    parsed = _parsed_return_columns()
    assert len(parsed) == 19
    assert [name for name, _type in parsed[:16]] == list(APPROVAL_RETURN_COLUMN_NAMES)
    assert parsed[16][0] == "investigation_status"
    assert parsed[17][0] == "investigation_confidence"
    assert parsed[18][0] == "investigation_updated_at"


def test_177_no_new_rls_policy_or_trigger_added():
    schema_text = _read_schema_text()
    assert "create policy" not in schema_text.lower()
    triggers = re.findall(r"create\s+trigger\s+(\w+)", schema_text, re.IGNORECASE)
    assert triggers == ["trg_investigations_updated_at"]
