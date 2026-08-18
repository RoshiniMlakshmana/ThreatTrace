"""Focused tests for the self-hosted Docker deployment refinement.

These are static/structural tests only -- they never require a live
Docker daemon or a running container (matching this project's
established rule that ordinary unit tests must not depend on live
Docker). Live validation of the actual built stack is a separate,
manual verification step (see docs/docker-self-hosted-deployment.md),
not part of this file.

Scope:
  - No host-Windows-path dependency anywhere in the runtime source that
    ships inside the Docker image (Nmap/Nuclei/ZAP discovery must work
    identically on the Debian-based container, which has no
    `C:\\Program Files`, no Npcap, no Windows PATH).
  - Dockerfile / docker-compose.yml never copy host binaries, never
    grant unneeded capabilities, never bind non-loopback.
  - The demo-target alias mechanism and the pre-existing localhost-only
    scope check compose correctly and never combine to authorize an
    arbitrary hostname.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from backend.models import RunModelError, resolve_execution_target, validate_local_only_target

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


class TestNoHostWindowsPathDependency:
    """runtime.tool_runtime and the adapters it drives must resolve tools
    purely via PATH lookup (shutil.which) / env vars -- never a hardcoded
    Windows install path -- so the exact same code works unmodified
    inside the Linux container.
    """

    @pytest.mark.parametrize("source_file", [
        "runtime/tool_runtime.py",
        "adapters/bug_bounty_nmap.py",
        "adapters/bug_bounty_nuclei.py",
        "adapters/bug_bounty_zap.py",
        "backend/app.py",
        "backend/orchestrator.py",
    ])
    def test_001_no_windows_install_paths_in_runtime_source(self, source_file):
        # "Npcap"/"Nmap" may legitimately appear in prose (docstrings,
        # detail strings explaining a host-native install step) -- what
        # must never appear is an actual hardcoded Windows drive-letter
        # path used as a lookup/fallback location.
        text = (REPO_ROOT / source_file).read_text(encoding="utf-8")
        assert "Program Files" not in text
        assert not re.search(r"[A-Za-z]:\\\\", text)

    def test_002_dockerfile_never_copies_host_binaries(self):
        text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "Program Files" not in text
        assert "C:\\" not in text
        assert "host.docker.internal" not in text


class TestDockerfileSafety:
    def test_003_no_privileged_capabilities_requested(self):
        text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "--cap-add" not in text
        assert "--privileged" not in text

    def test_004_runs_as_non_root_user(self):
        text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "USER threattrace" in text
        assert re.search(r"^USER\s+threattrace\s*$", text, re.MULTILINE)

    def test_005_healthcheck_defined(self):
        text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert "HEALTHCHECK" in text

    def test_005b_httpx_binary_installed_after_pip_install_not_before(self):
        # Regression guard for a real bug found during live Docker
        # validation: the Python `httpx` package (a transitive `mcp`
        # dependency) installs its own same-named `httpx` console-script
        # into /usr/local/bin. If the real ProjectDiscovery Go binary is
        # unzipped to that same path BEFORE `pip install` runs, pip
        # silently overwrites it with the broken Python CLI shim (which
        # errors without the `httpx[cli]` extra this project never
        # installs) -- `runtime.tool_runtime.check_httpx` then reports
        # `runtime_unavailable` even though a binary is present on PATH.
        # The httpx/Katana download step must appear strictly after the
        # `pip install -r requirements.txt` line in the Dockerfile.
        text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        pip_install_index = text.index("pip install --no-cache-dir -r requirements.txt")
        httpx_download_index = text.index("/tmp/httpx.zip")
        assert pip_install_index < httpx_download_index


class TestComposeSafety:
    def test_006_no_privileged_or_host_network_mode(self):
        text = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        assert "privileged: true" not in text
        assert "network_mode: host" not in text
        assert "network_mode:\n      - host" not in text

    def test_007_no_docker_socket_mount(self):
        text = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        assert "docker.sock" not in text

    def test_007b_no_added_capabilities(self):
        text = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        assert "cap_add" not in text
        assert "NET_ADMIN" not in text
        assert "NET_RAW" not in text

    def test_008_published_ports_bind_loopback_only(self):
        text = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        port_lines = [line for line in text.splitlines() if re.search(r'"\s*\d', line) and ":" in line and "ports:" not in line]
        published = [line for line in port_lines if re.search(r"\d+:\d+", line)]
        assert published, "expected at least one published port mapping"
        for line in published:
            assert "127.0.0.1:" in line, f"port mapping not bound to loopback: {line.strip()}"
            assert "0.0.0.0" not in line

    def test_009_expected_services_present(self):
        text = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        for service in ("threattrace:", "zap:", "juice-shop:"):
            assert service in text

    def test_010_isolated_network_declared(self):
        text = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        assert "threattrace-net" in text

    def test_011_backend_reaches_zap_by_service_name_not_loopback(self):
        text = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        assert "ZAP_API_URL: \"http://zap:8080\"" in text or "ZAP_API_URL: http://zap:8080" in text


class TestDemoTargetAliasComposition:
    """The additive alias mechanism (backend.models.resolve_execution_target)
    must never let a Docker-network hostname pass the pre-existing,
    unweakened localhost-only display-target check.
    """

    def test_012_juice_shop_hostname_rejected_as_display_target(self):
        with pytest.raises(RunModelError, match="INVALID_TARGET"):
            validate_local_only_target("http://juice-shop:3000")

    def test_013_public_targets_still_rejected_regardless_of_demo_config(self):
        env = {"THREATTRACE_DEMO_TARGET": "http://juice-shop:3000"}
        for target in ("http://example.com/", "http://8.8.8.8/", "http://10.0.0.5/"):
            with pytest.raises(RunModelError, match="INVALID_TARGET"):
                validate_local_only_target(target)
            # even if a caller could somehow reach resolve_execution_target
            # directly, a non-alias target is passed through unchanged --
            # never redirected anywhere.
            assert resolve_execution_target(display_target=target, env=env) == target

    def test_014_only_the_accepted_display_target_can_be_remapped(self):
        accepted = validate_local_only_target("http://localhost:3000/")
        env = {"THREATTRACE_DEMO_TARGET": "http://juice-shop:3000"}
        execution_target = resolve_execution_target(display_target=accepted, env=env)
        assert execution_target == "http://juice-shop:3000"
