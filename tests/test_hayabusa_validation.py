"""Unit tests for the pure/validation helpers in mcp/hayabusa_server.py.

Loaded via importlib.util.spec_from_file_location (not `import mcp.hayabusa_server`)
because the project's top-level `mcp/` folder has no __init__.py and would otherwise
be confused with the installed `mcp` PyPI package during dotted-name import.
"""

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
HAYABUSA_SERVER_PATH = REPO_ROOT / "mcp" / "hayabusa_server.py"


def _load_hayabusa_server():
    spec = importlib.util.spec_from_file_location(
        "hayabusa_server_under_test", HAYABUSA_SERVER_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def hs(tmp_path, monkeypatch):
    """Load hayabusa_server.py with CLAUDE_PROJECT_DIR pointed at an isolated tmp_path tree."""
    (tmp_path / "evidence" / "evtx").mkdir(parents=True)
    (tmp_path / "output" / "hayabusa").mkdir(parents=True)
    (tmp_path / "tools" / "hayabusa").mkdir(parents=True)

    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))

    return _load_hayabusa_server()


# ---------------------------------------------------------------------------
# _truncate
# ---------------------------------------------------------------------------

def test_truncate_shorter_than_limit_unchanged(hs):
    assert hs._truncate("short", limit=10) == "short"


def test_truncate_at_limit_unchanged(hs):
    text = "1234567890"  # exactly 10 chars
    assert hs._truncate(text, limit=10) == text


def test_truncate_longer_than_limit_is_bounded(hs):
    text = "12345678901234"  # 14 chars
    result = hs._truncate(text, limit=10)
    assert result == "1234567890... [truncated, 4 more characters]"


# ---------------------------------------------------------------------------
# _validate_evtx_input
# ---------------------------------------------------------------------------

def test_evtx_valid_relative_file(hs):
    sample = hs.EVTX_DIR / "sample.evtx"
    sample.write_bytes(b"placeholder")

    result = hs._validate_evtx_input("sample.evtx")

    assert result.exists()
    assert result.is_relative_to(hs.EVTX_DIR.resolve())
    assert result.name == "sample.evtx"


def test_evtx_empty_input_rejected(hs):
    with pytest.raises(ValueError, match="empty"):
        hs._validate_evtx_input("")


def test_evtx_absolute_windows_path_rejected(hs):
    with pytest.raises(ValueError, match="absolute"):
        hs._validate_evtx_input(r"C:\Windows\system32\evil.evtx")


def test_evtx_absolute_unix_style_path_rejected(hs):
    with pytest.raises(ValueError, match="rooted"):
        hs._validate_evtx_input("/etc/passwd.evtx")


def test_evtx_parent_traversal_rejected(hs):
    with pytest.raises(ValueError, match="contain"):
        hs._validate_evtx_input("../evil.evtx")


def test_evtx_wrong_extension_rejected(hs):
    with pytest.raises(ValueError, match="extension"):
        hs._validate_evtx_input("sample.txt")


def test_evtx_missing_file_rejected(hs):
    with pytest.raises(ValueError, match="exist"):
        hs._validate_evtx_input("does_not_exist.evtx")


def test_evtx_nested_valid_relative_path(hs):
    nested_dir = hs.EVTX_DIR / "subdir"
    nested_dir.mkdir()
    nested_file = nested_dir / "nested.evtx"
    nested_file.write_bytes(b"placeholder")

    result = hs._validate_evtx_input("subdir/nested.evtx")

    assert result.exists()
    assert result.is_relative_to(hs.EVTX_DIR.resolve())
    assert result.name == "nested.evtx"


def test_evtx_symlink_rejected(hs):
    target = hs.EVTX_DIR.parent / "real_target.evtx"
    target.write_bytes(b"placeholder")
    link = hs.EVTX_DIR / "link.evtx"

    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable or requires elevated privileges")

    with pytest.raises(ValueError, match="symbolic"):
        hs._validate_evtx_input("link.evtx")


# ---------------------------------------------------------------------------
# _validate_output_name
# ---------------------------------------------------------------------------

def test_output_valid_csv_name(hs):
    result = hs._validate_output_name("result.csv")

    assert result.is_relative_to(hs.OUTPUT_DIR.resolve())
    assert result.name == "result.csv"


def test_output_empty_name_rejected(hs):
    with pytest.raises(ValueError, match="empty"):
        hs._validate_output_name("")


def test_output_wrong_extension_rejected(hs):
    with pytest.raises(ValueError, match="csv"):
        hs._validate_output_name("result.txt")


def test_output_nested_forward_slash_path_rejected(hs):
    with pytest.raises(ValueError, match="simple filename"):
        hs._validate_output_name("sub/result.csv")


def test_output_nested_backslash_path_rejected(hs):
    with pytest.raises(ValueError, match="simple filename"):
        hs._validate_output_name("sub\\result.csv")


def test_output_parent_traversal_rejected(hs):
    with pytest.raises(ValueError, match="simple filename"):
        hs._validate_output_name("../result.csv")


def test_output_absolute_windows_path_rejected(hs):
    with pytest.raises(ValueError, match="simple filename"):
        hs._validate_output_name(r"C:\result.csv")


def test_output_absolute_unix_style_path_rejected(hs):
    with pytest.raises(ValueError, match="simple filename"):
        hs._validate_output_name("/result.csv")
