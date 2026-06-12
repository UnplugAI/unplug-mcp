"""Deterministic encoding probe battery — not exposed to the LLM test agent."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from unplug_mcp.guard_factory import reset_guard
from unplug_mcp.server import scan_text
from unplug_mcp.test_agent.env import WORKSPACE_ROOT, configure_ml_env

DEFAULT_ENCODING_PROBES = WORKSPACE_ROOT / "repos/unplug_exp/configs/encoding_probe_queries.json"


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def materialize_probe(probe: dict[str, Any]) -> str:
    fmt = probe.get("format", "literal")
    if fmt == "literal":
        return str(probe["text"])
    inner = str(probe["inner_text"])
    blob = _b64(inner)
    wrapper = str(probe.get("wrapper", "{blob}"))
    return wrapper.format(blob=blob)


def run_encoding_probe_suite(
    probes_path: Path | None = None,
    *,
    require_ml: bool = False,
) -> dict[str, Any]:
    """Run encoding probes via MCP scan_text (Guard encoding stage + optional ML)."""
    configure_ml_env(require=require_ml)
    path = probes_path or DEFAULT_ENCODING_PROBES
    if not path.is_file():
        return {"error": f"encoding probes not found: {path}", "results": []}

    probes = json.loads(path.read_text(encoding="utf-8"))
    reset_guard()
    rows: list[dict[str, Any]] = []
    tp = fp = tn = fn = 0
    encoding_hits = 0
    control_fp = 0

    for probe in probes:
        text = materialize_probe(probe)
        out = scan_text(text)
        expect = bool(probe.get("expect_detected"))
        detected = not out["safe"]
        encoding_findings = [f for f in out.get("findings", []) if f.get("stage") == "encoding"]
        if encoding_findings:
            encoding_hits += 1

        is_control = probe.get("suite") == "literal_control"
        if is_control and detected:
            control_fp += 1

        if expect and detected:
            tp += 1
            outcome = "tp"
        elif expect and not detected:
            fn += 1
            outcome = "fn"
        elif not expect and detected:
            fp += 1
            outcome = "fp"
        else:
            tn += 1
            outcome = "tn"

        rows.append(
            {
                "id": probe.get("id"),
                "format": probe.get("format"),
                "category": probe.get("category"),
                "suite": probe.get("suite", "encoding"),
                "expect_detected": expect,
                "outcome": outcome,
                "action": out["action"],
                "risk_score": out["risk_score"],
                "encoding_findings": len(encoding_findings),
                "stages": sorted({f.get("stage") for f in out.get("findings", [])}),
                "finding_count": out.get("finding_count"),
            }
        )

    encoding_rows = [r for r in rows if r.get("suite") != "literal_control"]
    enc_fp = sum(1 for r in encoding_rows if r["outcome"] == "fp")
    enc_fn = sum(1 for r in encoding_rows if r["outcome"] == "fn")

    return {
        "probes_file": str(path),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "encoding_stage_hits": encoding_hits,
        "all_probes_pass": fp == 0 and fn == 0,
        "encoding_probes_pass": enc_fp == 0 and enc_fn == 0,
        "literal_control_fp": control_fp,
        "results": rows,
    }
