"""FP probe battery — shared by tools and SDK suite."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from unplug_mcp.guard_factory import reset_guard
from unplug_mcp.server import scan_text
from unplug_mcp.test_agent.env import DEFAULT_PROBES


def run_fp_probe_suite(probes_path: Path | None = None) -> dict[str, Any]:
    path = probes_path or DEFAULT_PROBES
    if not path.is_file():
        return {"error": f"probes file not found: {path}", "results": []}
    probes = json.loads(path.read_text(encoding="utf-8"))
    reset_guard()
    rows: list[dict[str, Any]] = []
    tp = fp = tn = fn = 0
    for probe in probes:
        out = scan_text(probe["text"])
        expect = bool(probe.get("expect_detected"))
        detected = not out["safe"]
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
                "category": probe.get("category"),
                "expect_detected": expect,
                "outcome": outcome,
                "action": out["action"],
                "risk_score": out["risk_score"],
                "redacted_text": out.get("redacted_text"),
                "finding_count": out.get("finding_count"),
                "model_findings": sum(
                    1 for f in out.get("findings", []) if f.get("stage") == "model"
                ),
                "regex_findings": sum(
                    1 for f in out.get("findings", []) if f.get("stage") != "model"
                ),
                "findings": out.get("findings"),
            }
        )
    model_tp = sum(1 for r in rows if r.get("model_findings", 0) > 0 and r["expect_detected"])
    return {
        "probes_file": str(path),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "model_stage_hits": model_tp,
        "all_probes_pass": fp == 0 and fn == 0,
        "results": rows,
    }
