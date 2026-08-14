"""Focused packaging tests (Block 15L-16): confirm README-referenced
paths exist, `.env.example` contains no real secrets, `.gitignore`
covers the expected patterns, and the new startup-relevant modules are
importable. Deliberately light on prose-matching to avoid brittleness.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


class TestReadmeReferencedPathsExist:
    def test_001_readme_exists(self):
        assert (REPO_ROOT / "README.md").is_file()

    def test_002_every_relative_markdown_link_target_exists(self):
        readme = _read("README.md")
        # Matches [text](path) where path does not start with http(s):// or #
        links = re.findall(r"\]\(([^)]+)\)", readme)
        for link in links:
            if link.startswith(("http://", "https://", "#")):
                continue
            target = link.split("#", 1)[0]
            if not target:
                continue
            assert (REPO_ROOT / target).exists(), f"README references missing path: {target}"

    def test_003_key_docs_referenced(self):
        readme = _read("README.md")
        for doc in [
            "docs/architecture.md", "SECURITY.md", "docs/authorized-use.md",
            "docs/demo-runbook.md", "docs/block15jk-live-platform-dashboard.md",
        ]:
            assert doc in readme


class TestEnvExampleNoSecrets:
    def test_004_file_exists(self):
        assert (REPO_ROOT / ".env.example").is_file()

    def test_005_only_placeholder_values(self):
        content = _read(".env.example")
        for line in content.splitlines():
            if not line or line.strip().startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip()
            # Placeholders are always human-readable hints, never real-looking
            # opaque tokens: no long pure-hex/base64-looking unbroken run.
            assert not re.fullmatch(r"[A-Za-z0-9+/_-]{32,}", value), f"{key} looks like a real secret, not a placeholder"

    def test_006_documents_every_real_env_var_referenced_in_code(self):
        content = _read(".env.example")
        referenced = set()
        for directory in ("core", "adapters", "runtime"):
            for path in (REPO_ROOT / directory).rglob("*.py"):
                referenced |= set(re.findall(r"THREATTRACE_[A-Z0-9_]+", path.read_text(encoding="utf-8")))
        referenced.discard("THREATTRACE_REFLECTION_PROBE_15A")  # an inert marker string, not an env var
        for name in referenced:
            assert name in content, f"{name} is read by code but not documented in .env.example"


class TestGitignoreCoversExpectedPatterns:
    def test_007_file_exists(self):
        assert (REPO_ROOT / ".gitignore").is_file()

    @pytest.mark.parametrize("pattern", [".env", "__pycache__/", "*.pyc", ".venv/", "node_modules/", "*.exe", "*.zip"])
    def test_008_expected_patterns_present(self, pattern):
        content = _read(".gitignore")
        assert pattern in content

    def test_009_env_example_not_ignored(self):
        content = _read(".gitignore")
        assert "!.env.example" in content


class TestStartupCommandImportability:
    def test_010_backend_app_importable(self):
        import backend.app  # noqa: F401

    def test_011_runtime_bootstrap_importable(self):
        import runtime.bootstrap  # noqa: F401

    def test_012_runtime_tool_runtime_importable(self):
        import runtime.tool_runtime  # noqa: F401

    def test_013_backend_app_has_main(self):
        import backend.app
        assert callable(backend.app.main)

    def test_014_runtime_bootstrap_has_main(self):
        import runtime.bootstrap
        assert callable(runtime.bootstrap.main)


class TestArchitectureDocsLinked:
    def test_015_architecture_doc_exists(self):
        assert (REPO_ROOT / "docs" / "architecture.md").is_file()

    def test_016_architecture_doc_references_new_modules(self):
        content = _read("docs/architecture.md")
        for module in ["backend.orchestrator", "runtime.tool_runtime", "core.security_governor"]:
            assert module in content


class TestDashboardPathsExist:
    def test_017_live_dashboard_exists(self):
        assert (REPO_ROOT / "dashboard" / "live" / "index.html").is_file()

    def test_018_presentation_dashboard_still_exists_unmodified_path(self):
        assert (REPO_ROOT / "dashboard" / "threattrace-dashboard.html").is_file()


class TestVersionFile:
    def test_019_version_file_exists_and_is_nonempty(self):
        content = _read("VERSION").strip()
        assert content

    def test_020_version_referenced_from_readme(self):
        readme = _read("README.md")
        assert "VERSION" in readme


class TestDockerComposeExists:
    def test_021_compose_file_exists(self):
        assert (REPO_ROOT / "docker-compose.yml").is_file()

    def test_022_compose_binds_localhost_only(self):
        content = _read("docker-compose.yml")
        assert "127.0.0.1:3000:3000" in content
        # Never a bare host-port publish that binds all interfaces.
        assert re.search(r'"\d+:\d+"', content) is None
