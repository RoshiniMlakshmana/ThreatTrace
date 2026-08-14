"""Tests for core.presentation_dashboard_cli -- the stdin/stdout JSON
adapter around core.presentation_dashboard (Block 15F-B).

No network access occurs anywhere in this file. Local file writes are
confined to pytest's own `tmp_path` fixture, never the repository.
"""

from __future__ import annotations

import json
from io import StringIO

import pytest

import core.presentation_dashboard_cli as presentation_dashboard_cli
from core.presentation_dashboard import render_presentation_dashboard


def _benchmark(**overrides):
    summary = {
        "true_positive_count": 5, "false_positive_count": 1, "false_negative_count": 0,
        "true_negative_count": 3, "precision": 0.8333333333, "recall": 1.0, "f1": 0.9090909091,
        "supported_ground_truth_count": 9,
    }
    summary.update(overrides)
    return summary


def _refined_benchmark(**overrides):
    summary = {
        "true_positive_count": 5, "false_positive_count": 0, "false_negative_count": 0,
        "true_negative_count": 4, "precision": 1.0, "recall": 1.0, "f1": 1.0,
        "supported_ground_truth_count": 9,
    }
    summary.update(overrides)
    return summary


def _stage(status="not_evaluated", note=None):
    return {"status": status, "note": note}


def _workflow():
    return {
        "bug_bounty": _stage("executed"),
        "context_prioritization": _stage(),
        "security_handoff": _stage(),
        "security_governor": _stage(),
        "validated_experience_memory": _stage(),
        "research_evaluation": _stage(),
    }


def _dashboard_data(**overrides):
    data = {
        "dashboard_version": "1",
        "project_name": "ThreatTrace",
        "target": "OWASP Juice Shop",
        "target_origin": "http://localhost:3000",
        "target_version_or_digest": "sha256:" + "a" * 64,
        "run_label": "Block 15F-A Controlled Benchmark",
        "baseline_benchmark": _benchmark(),
        "refined_benchmark": _refined_benchmark(),
        "research_evaluation": None,
        "security_workflow_summary": _workflow(),
        "research_limitations": ["Supported-capability benchmark only."],
    }
    data.update(overrides)
    return data


def _envelope(output_path, **overrides):
    envelope = {"operation": "render", "dashboard_data": _dashboard_data(), "output_path": str(output_path)}
    envelope.update(overrides)
    return envelope


def _run(raw_stdin_text):
    stdin = StringIO(raw_stdin_text)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = presentation_dashboard_cli.main(stdin=stdin, stdout=stdout, stderr=stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _assert_no_forbidden_content(rendered):
    forbidden = (
        "Traceback", "PresentationDashboardError", "ValueError", "RuntimeError",
        "KeyError", "AttributeError", "TypeError", "  File \"",
    )
    for text in forbidden:
        assert text not in rendered


# ---------------------------------------------------------------------------
# Success
# ---------------------------------------------------------------------------


class TestSuccess:
    def test_001_valid_render_exit_zero(self, tmp_path):
        output_path = tmp_path / "dashboard.html"
        exit_code, stdout, stderr = _run(json.dumps(_envelope(output_path)))
        assert exit_code == 0
        assert stderr == ""

    def test_002_stdout_confirmation_shape(self, tmp_path):
        output_path = tmp_path / "dashboard.html"
        _, stdout, _ = _run(json.dumps(_envelope(output_path)))
        result = json.loads(stdout)
        assert result == {"rendered": True, "output_path": str(output_path)}

    def test_003_output_file_exists(self, tmp_path):
        output_path = tmp_path / "dashboard.html"
        _run(json.dumps(_envelope(output_path)))
        assert output_path.exists()

    def test_004_output_file_content_equals_direct_core_render(self, tmp_path):
        output_path = tmp_path / "dashboard.html"
        data = _dashboard_data()
        direct_html = render_presentation_dashboard(dashboard_data=data)
        _run(json.dumps(_envelope(output_path, dashboard_data=data)))
        assert output_path.read_text(encoding="utf-8") == direct_html

    def test_005_creates_missing_parent_directories(self, tmp_path):
        output_path = tmp_path / "nested" / "dir" / "dashboard.html"
        exit_code, stdout, stderr = _run(json.dumps(_envelope(output_path)))
        assert exit_code == 0
        assert output_path.exists()

    def test_006_deterministic_stdout_across_calls(self, tmp_path):
        raw = json.dumps(_envelope(tmp_path / "a.html"))
        _, first, _ = _run(raw)
        raw2 = json.dumps(_envelope(tmp_path / "b.html"))
        _, second, _ = _run(raw2)
        first_parsed = json.loads(first)
        second_parsed = json.loads(second)
        assert first_parsed["rendered"] == second_parsed["rendered"] is True

    def test_007_stdout_is_exactly_one_json_object_plus_newline(self, tmp_path):
        _, stdout, _ = _run(json.dumps(_envelope(tmp_path / "dashboard.html")))
        assert stdout.endswith("\n")
        assert stdout.count("\n") == 1

    def test_008_output_keys_sorted(self, tmp_path):
        _, stdout, _ = _run(json.dumps(_envelope(tmp_path / "dashboard.html")))
        raw_keys = list(json.loads(stdout).keys())
        assert raw_keys == sorted(raw_keys)


# ---------------------------------------------------------------------------
# Envelope validation -> exit 2
# ---------------------------------------------------------------------------


class TestEnvelopeValidation:
    def test_009_malformed_json_exit_two(self):
        exit_code, stdout, stderr = _run("{not json")
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("PRESENTATION_DASHBOARD_VALIDATION_FAILED:")

    def test_010_top_level_array_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps([1, 2, 3]))
        assert exit_code == 2

    def test_011_missing_operation_exit_two(self, tmp_path):
        envelope = _envelope(tmp_path / "dashboard.html")
        del envelope["operation"]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_012_unsupported_operation_exit_two(self, tmp_path):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(tmp_path / "dashboard.html", operation="delete")))
        assert exit_code == 2

    def test_013_extra_field_exit_two(self, tmp_path):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(tmp_path / "dashboard.html", unexpected="x")))
        assert exit_code == 2

    def test_014_missing_dashboard_data_exit_two(self, tmp_path):
        envelope = _envelope(tmp_path / "dashboard.html")
        del envelope["dashboard_data"]
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_015_missing_output_path_exit_two(self):
        envelope = {"operation": "render", "dashboard_data": _dashboard_data()}
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_016_empty_stdin_exit_two(self):
        exit_code, stdout, stderr = _run("")
        assert exit_code == 2

    def test_017_empty_object_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps({}))
        assert exit_code == 2


# ---------------------------------------------------------------------------
# output_path validation
# ---------------------------------------------------------------------------


class TestOutputPathValidation:
    def test_018_blank_output_path_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope("   ")))
        assert exit_code == 2

    def test_019_non_string_output_path_exit_two(self):
        envelope = _envelope("dashboard.html")
        envelope["output_path"] = 123
        exit_code, stdout, stderr = _run(json.dumps(envelope))
        assert exit_code == 2

    def test_020_url_scheme_output_path_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope("http://example.test/dashboard.html")))
        assert exit_code == 2

    def test_021_null_byte_output_path_exit_two(self):
        exit_code, stdout, stderr = _run(json.dumps(_envelope("dash\x00board.html")))
        assert exit_code == 2


# ---------------------------------------------------------------------------
# Core validation delegated through unchanged -> exit 2
# ---------------------------------------------------------------------------


class TestCoreValidationDelegation:
    def test_022_malformed_dashboard_data_exit_two(self, tmp_path):
        exit_code, stdout, stderr = _run(json.dumps(_envelope(tmp_path / "dashboard.html", dashboard_data={"nope": "x"})))
        assert exit_code == 2
        assert stdout == ""
        assert stderr.startswith("PRESENTATION_DASHBOARD_VALIDATION_FAILED:")

    def test_023_dashboard_data_wrong_version_exit_two(self, tmp_path):
        data = _dashboard_data(dashboard_version="2")
        exit_code, stdout, stderr = _run(json.dumps(_envelope(tmp_path / "dashboard.html", dashboard_data=data)))
        assert exit_code == 2

    def test_024_no_file_written_on_validation_failure(self, tmp_path):
        output_path = tmp_path / "dashboard.html"
        _run(json.dumps(_envelope(output_path, dashboard_data={"nope": "x"})))
        assert not output_path.exists()


# ---------------------------------------------------------------------------
# Internal failure -> exit 1
# ---------------------------------------------------------------------------


class TestInternalFailure:
    def test_025_unexpected_render_exception_exit_one(self, monkeypatch, tmp_path):
        def _boom(*, dashboard_data):
            raise RuntimeError("boom")

        monkeypatch.setattr(presentation_dashboard_cli, "render_presentation_dashboard", _boom)
        exit_code, stdout, stderr = _run(json.dumps(_envelope(tmp_path / "dashboard.html")))
        assert exit_code == 1
        assert stdout == ""
        assert stderr.startswith("PRESENTATION_DASHBOARD_INTERNAL_FAILURE:")

    def test_026_internal_failure_never_leaks_exception_class(self, monkeypatch, tmp_path):
        def _boom(*, dashboard_data):
            raise RuntimeError("some internal detail")

        monkeypatch.setattr(presentation_dashboard_cli, "render_presentation_dashboard", _boom)
        _, _, stderr = _run(json.dumps(_envelope(tmp_path / "dashboard.html")))
        assert "RuntimeError" not in stderr
        assert "some internal detail" not in stderr

    def test_027_write_failure_exit_one(self, monkeypatch, tmp_path):
        from pathlib import Path

        def _boom_write_text(self, *args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(Path, "write_text", _boom_write_text)
        exit_code, stdout, stderr = _run(json.dumps(_envelope(tmp_path / "dashboard.html")))
        assert exit_code == 1
        assert stderr.startswith("PRESENTATION_DASHBOARD_INTERNAL_FAILURE:")

    def test_028_stdin_read_failure_exit_one(self):
        class _ExplodingStdin:
            def read(self):
                raise OSError("disk on fire")

        stdout = StringIO()
        stderr = StringIO()
        exit_code = presentation_dashboard_cli.main(stdin=_ExplodingStdin(), stdout=stdout, stderr=stderr)
        assert exit_code == 1
        assert stdout.getvalue() == ""
        assert stderr.getvalue().startswith("PRESENTATION_DASHBOARD_INTERNAL_FAILURE:")


# ---------------------------------------------------------------------------
# No leakage / no network / determinism
# ---------------------------------------------------------------------------


class TestNoLeakageAndNoNetwork:
    def test_029_validation_failure_no_forbidden_content(self):
        exit_code, stdout, stderr = _run("{not json")
        _assert_no_forbidden_content(stdout + stderr)

    def test_030_success_output_no_forbidden_content(self, tmp_path):
        _, stdout, stderr = _run(json.dumps(_envelope(tmp_path / "dashboard.html")))
        _assert_no_forbidden_content(stdout + stderr)

    def test_031_cli_module_imports_only_stdlib_and_dashboard_core(self):
        import ast
        import inspect

        source = inspect.getsource(presentation_dashboard_cli)
        tree = ast.parse(source)
        imported_modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module.split(".")[0])
        assert imported_modules <= {"__future__", "json", "sys", "pathlib", "typing", "core"}

    def test_032_module_never_imports_network_libraries(self):
        import ast
        import inspect

        source = inspect.getsource(presentation_dashboard_cli)
        tree = ast.parse(source)
        imported_modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module.split(".")[0])
        assert "http" not in imported_modules
        assert "urllib" not in imported_modules
        assert "socket" not in imported_modules
        assert "requests" not in imported_modules

    def test_033_module_has_main_guard(self):
        source_path = presentation_dashboard_cli.__file__
        with open(source_path, encoding="utf-8") as handle:
            content = handle.read()
        assert 'if __name__ == "__main__":' in content

    def test_034_no_secrets_in_stdout(self, tmp_path):
        data = _dashboard_data(security_workflow_summary=_workflow())
        _, stdout, _ = _run(json.dumps(_envelope(tmp_path / "dashboard.html", dashboard_data=data)))
        assert "password" not in stdout.lower()
        assert "cookie" not in stdout.lower()
        assert "authorization" not in stdout.lower()
