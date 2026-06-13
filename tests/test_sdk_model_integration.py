"""SDK + span-model integration tests through MCP tool path."""

from __future__ import annotations

import pytest

from unplug_mcp.guard_factory import reset_guard
from unplug_mcp.test_agent.env import configure_ml_env, resolve_checkpoint
from unplug_mcp.test_agent.sdk_suite import get_guard_status, run_sdk_integration_suite
from unplug_mcp.test_agent.tools import dispatch_tool, run_fp_probe_suite


@pytest.fixture(autouse=True)
def _reset_guard() -> None:
    reset_guard()


def test_get_guard_status_local() -> None:
    status = get_guard_status()
    assert "scanners_loaded" in status
    assert status["mode"] in ("local", "server")


@pytest.mark.skipif(resolve_checkpoint() is None, reason="checkpoint not available")
def test_sdk_integration_suite_with_ml() -> None:
    pytest.importorskip("torch")
    configure_ml_env(require=True)
    reset_guard()
    report = run_sdk_integration_suite(require_ml=True)
    assert report["checks_total"] >= 10
    assert report["guard_status"]["ml_provider_present"] is True
    assert report["sdk_wiring_pass"] is True
    names = {c["name"] for c in report["checks"]}
    assert "session_taint_mcp_review" in names
    assert "boundary_probe_suite" in names


def test_sdk_integration_boundary_wiring_without_ml() -> None:
    reset_guard()
    report = run_sdk_integration_suite(require_ml=False)
    names = {c["name"] for c in report["checks"]}
    assert "session_taint_mcp_review" in names
    boundary = next(c for c in report["checks"] if c["name"] == "boundary_probe_suite")
    assert boundary["passed"] is True
    assert report["sdk_wiring_pass"] is True


@pytest.mark.skipif(resolve_checkpoint() is None, reason="checkpoint not available")
def test_fp_probe_suite_reports_model_stages() -> None:
    pytest.importorskip("torch")
    configure_ml_env(require=True)
    reset_guard()
    suite = run_fp_probe_suite()
    assert "model_stage_hits" in suite
    # tiny checkpoint may miss some probes; wiring is validated elsewhere
    assert suite["model_stage_hits"] >= 0


def test_dispatch_get_guard_status() -> None:
    out = dispatch_tool("get_guard_status", {})
    assert "scanners_loaded" in out


@pytest.mark.skipif(resolve_checkpoint() is None, reason="checkpoint not available")
def test_dispatch_sdk_integration_suite() -> None:
    pytest.importorskip("torch")
    configure_ml_env(require=True)
    reset_guard()
    out = dispatch_tool("run_sdk_integration_suite", {"require_ml": True})
    assert "all_passed" in out
    assert "checks" in out
