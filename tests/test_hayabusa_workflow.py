"""Workflow tests for mcp/hayabusa_server.py: plan/execute boundary, authorization,
no-overwrite behavior, and the fixed analysis-type allowlist.

Loaded via importlib.util.spec_from_file_location (not `import mcp.hayabusa_server`)
because the project's top-level `mcp/` folder has no __init__.py and would otherwise
be confused with the installed `mcp` PyPI package during dotted-name import.

subprocess.run is always mocked. No real Hayabusa process is ever launched.
"""

import importlib.util
import subprocess
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


def _create_placeholder_exe(hs_module):
    hs_module.HAYABUSA_EXE.write_bytes(b"placeholder-exe")


def _create_placeholder_evtx(hs_module, name="sample.evtx"):
    path = hs_module.EVTX_DIR / name
    path.write_bytes(b"placeholder-evtx")
    return path


class RecordingRun:
    """Fake subprocess.run: never launches a real process, records calls, and
    writes a placeholder CSV to the requested -o path (simulating what the real
    Hayabusa binary would produce) before returning a successful CompletedProcess."""

    def __init__(self):
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        if "-o" in args:
            output_path = Path(args[args.index("-o") + 1])
            output_path.write_text("header1,header2\nval1,val2\n", encoding="utf-8")
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="mock stdout", stderr="")


def _forbidden_run(*args, **kwargs):
    raise AssertionError("subprocess.run must not be called for this code path")


# ---------------------------------------------------------------------------
# Planning boundary
# ---------------------------------------------------------------------------

def test_plan_valid_succeeds_without_subprocess(hs, monkeypatch):
    monkeypatch.setattr(hs.subprocess, "run", _forbidden_run)
    _create_placeholder_evtx(hs)

    result = hs.plan_evtx_analysis("sample.evtx", "csv_timeline", "result.csv")

    assert result["valid"] is True
    assert result["errors"] == []


def test_plan_never_executes_hayabusa(hs, monkeypatch):
    recorder = RecordingRun()
    monkeypatch.setattr(hs.subprocess, "run", recorder)
    _create_placeholder_evtx(hs)

    hs.plan_evtx_analysis("sample.evtx", "csv_timeline", "result.csv")
    hs.plan_evtx_analysis("does_not_exist.evtx", "bogus_type", "bad name.csv")

    assert recorder.calls == []


def test_plan_reports_selected_analysis_type(hs, monkeypatch):
    monkeypatch.setattr(hs.subprocess, "run", _forbidden_run)
    _create_placeholder_evtx(hs)

    result = hs.plan_evtx_analysis("sample.evtx", "log_metrics", "result.csv")

    assert result["analysis_type"] == "log_metrics"


def test_plan_identifies_intended_input_and_output(hs, monkeypatch):
    monkeypatch.setattr(hs.subprocess, "run", _forbidden_run)
    _create_placeholder_evtx(hs)

    result = hs.plan_evtx_analysis("sample.evtx", "eid_metrics", "result.csv")

    assert result["evtx_file"] == "sample.evtx"
    assert result["output_name"] == "result.csv"


def test_plan_reports_preexisting_output_without_overwriting(hs, monkeypatch):
    monkeypatch.setattr(hs.subprocess, "run", _forbidden_run)
    _create_placeholder_evtx(hs)
    existing_output = hs.OUTPUT_DIR / "result.csv"
    existing_output.write_text("original content", encoding="utf-8")

    result = hs.plan_evtx_analysis("sample.evtx", "csv_timeline", "result.csv")

    assert result["output_exists"] is True
    assert result["valid"] is False
    assert any("already exists" in err for err in result["errors"])
    assert existing_output.read_text(encoding="utf-8") == "original content"


def test_plan_invalid_analysis_type_rejected_and_no_subprocess(hs, monkeypatch):
    recorder = RecordingRun()
    monkeypatch.setattr(hs.subprocess, "run", recorder)
    _create_placeholder_evtx(hs)

    result = hs.plan_evtx_analysis("sample.evtx", "bogus_type", "result.csv")

    assert result["valid"] is False
    assert any("analysis_type" in err for err in result["errors"])
    assert recorder.calls == []


# ---------------------------------------------------------------------------
# Authorization boundary
# ---------------------------------------------------------------------------

def test_execute_wrong_authorization_rejected(hs, monkeypatch):
    monkeypatch.setattr(hs.subprocess, "run", _forbidden_run)

    result = hs.run_evtx_analysis("sample.evtx", "csv_timeline", "result.csv", "WRONG PHRASE")

    assert result["success"] is False
    assert "authorization" in result["error"].lower()


def test_execute_missing_or_empty_authorization_rejected(hs, monkeypatch):
    monkeypatch.setattr(hs.subprocess, "run", _forbidden_run)

    result = hs.run_evtx_analysis("sample.evtx", "csv_timeline", "result.csv", "")

    assert result["success"] is False
    assert "authorization" in result["error"].lower()


def test_execute_authorization_rejection_reports_not_executed(hs, monkeypatch):
    monkeypatch.setattr(hs.subprocess, "run", _forbidden_run)

    result = hs.run_evtx_analysis("sample.evtx", "csv_timeline", "result.csv", "WRONG PHRASE")

    assert result["hayabusa_executed"] is False


def test_execute_subprocess_never_called_when_authorization_fails(hs, monkeypatch):
    recorder = RecordingRun()
    monkeypatch.setattr(hs.subprocess, "run", recorder)

    hs.run_evtx_analysis("sample.evtx", "csv_timeline", "result.csv", "WRONG PHRASE")
    hs.run_evtx_analysis("sample.evtx", "csv_timeline", "result.csv", "")

    assert recorder.calls == []


# ---------------------------------------------------------------------------
# No-overwrite boundary
# ---------------------------------------------------------------------------

def test_execute_rejects_when_output_already_exists(hs, monkeypatch):
    monkeypatch.setattr(hs.subprocess, "run", _forbidden_run)
    _create_placeholder_exe(hs)
    _create_placeholder_evtx(hs)
    existing_output = hs.OUTPUT_DIR / "result.csv"
    existing_output.write_text("original content", encoding="utf-8")

    result = hs.run_evtx_analysis(
        "sample.evtx", "csv_timeline", "result.csv", hs.AUTHORIZATION_PHRASE
    )

    assert result["success"] is False
    assert "already exists" in result["error"]
    assert result["hayabusa_executed"] is False
    assert existing_output.read_text(encoding="utf-8") == "original content"


# ---------------------------------------------------------------------------
# Analysis allowlist
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("analysis_type", ["csv_timeline", "log_metrics", "eid_metrics"])
def test_execute_allowlisted_analysis_type(hs, monkeypatch, analysis_type):
    _create_placeholder_exe(hs)
    evtx_path = _create_placeholder_evtx(hs)
    recorder = RecordingRun()
    monkeypatch.setattr(hs.subprocess, "run", recorder)

    result = hs.run_evtx_analysis(
        "sample.evtx", analysis_type, "result.csv", hs.AUTHORIZATION_PHRASE
    )

    assert result["success"] is True
    assert len(recorder.calls) == 1

    args, kwargs = recorder.calls[0]
    expected_subcommand, expected_extra_flags = hs.ANALYSIS_COMMANDS[analysis_type]
    expected_input = str(evtx_path.resolve())
    expected_output = str((hs.OUTPUT_DIR / "result.csv").resolve())
    expected_args = (
        [str(hs.HAYABUSA_EXE), expected_subcommand, "-f", expected_input, "-o", expected_output]
        + expected_extra_flags
    )

    assert args == expected_args
    assert kwargs["shell"] is False
    assert kwargs["cwd"] == str(hs.HAYABUSA_DIR)


# ---------------------------------------------------------------------------
# Invalid execution request
# ---------------------------------------------------------------------------

def test_execute_unsupported_analysis_type_rejected(hs, monkeypatch):
    recorder = RecordingRun()
    monkeypatch.setattr(hs.subprocess, "run", recorder)

    result = hs.run_evtx_analysis(
        "sample.evtx", "bogus_type", "result.csv", hs.AUTHORIZATION_PHRASE
    )

    assert result["success"] is False
    assert result["hayabusa_executed"] is False
    assert recorder.calls == []
    assert not (hs.OUTPUT_DIR / "result.csv").exists()


# ---------------------------------------------------------------------------
# Plan versus execute proof
# ---------------------------------------------------------------------------

def test_plan_versus_execute_proof(hs, monkeypatch):
    """plan_evtx_analysis must never reach subprocess.run, even for fully valid inputs."""
    monkeypatch.setattr(hs.subprocess, "run", _forbidden_run)
    _create_placeholder_evtx(hs)

    result = hs.plan_evtx_analysis("sample.evtx", "csv_timeline", "result.csv")

    assert result["valid"] is True
