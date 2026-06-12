#!/usr/bin/env python3
"""Smoke test: MCP scan tools + optional unplug-server /v1/scan."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PROBES = ROOT / "repos/unplug_exp/configs/fp_probe_queries.json"


def _print_case(label: str, out: dict) -> None:
    print(f"\n=== {label} ===")
    print(f"safe={out['safe']} action={out['action']} risk={out['risk_score']}")
    print(f"findings={out['finding_count']} stages={out.get('stages_run')}")
    if out.get("redacted_text") is not None:
        print(f"redacted_text: {out['redacted_text']!r}")
    for f in out.get("findings", [])[:3]:
        print(
            f"  - [{f.get('stage')}] {f.get('subcategory')} "
            f"span={f.get('span_text')!r} tag={f.get('tag')}"
        )


def _run_mcp_local(probes: list[dict]) -> int:
    from unplug_mcp.guard_factory import reset_guard
    from unplug_mcp.server import scan_text

    reset_guard()
    fp = fn = 0
    for probe in probes:
        out = scan_text(probe["text"])
        expect = bool(probe.get("expect_detected"))
        detected = not out["safe"]
        if expect and not detected:
            fn += 1
        elif not expect and detected:
            fp += 1
        _print_case(probe["id"], out)
    print(f"\nMCP local probes: fp={fp} fn={fn}")
    return 0 if fp == 0 and fn == 0 else 1


def _run_server(probes: list[dict], base_url: str) -> int:
    from unplug import UnplugClient

    client = UnplugClient(base_url=base_url)
    health = client.health()
    print(f"server health: {json.dumps(health, indent=2)}")
    fp = fn = 0
    for probe in probes[:5]:
        result = client.scan(probe["text"])
        out = {
            "safe": result.safe,
            "action": result.action.value,
            "risk_score": result.risk_score,
            "finding_count": len(result.findings),
            "findings": [f.model_dump() for f in result.findings],
            "redacted_text": result.redacted_text,
            "stages_run": result.stages_run,
            "latency_ms": result.latency_ms,
            "has_redaction": result.redacted_text is not None,
        }
        expect = bool(probe.get("expect_detected"))
        detected = not result.safe
        if expect and not detected:
            fn += 1
        elif not expect and detected:
            fp += 1
        _print_case(f"server:{probe['id']}", out)
    client.close()
    print(f"\nServer probes (first 5): fp={fp} fn={fn}")
    return 0 if fp == 0 and fn == 0 else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP + server scan smoke test")
    parser.add_argument("--probes", type=Path, default=DEFAULT_PROBES)
    parser.add_argument("--server", action="store_true", help="Also hit UNPLUG_SERVER_URL")
    parser.add_argument("--subset", type=int, default=0, help="Limit probe count (0=all)")
    args = parser.parse_args()

    if not args.probes.is_file():
        print(f"probes not found: {args.probes}", file=sys.stderr)
        sys.exit(1)

    probes = json.loads(args.probes.read_text(encoding="utf-8"))
    if args.subset > 0:
        probes = probes[: args.subset]

    code = _run_mcp_local(probes)
    if args.server:
        url = os.environ.get("UNPLUG_SERVER_URL", "http://localhost:8080")
        code = max(code, _run_server(probes, url))
    sys.exit(code)


if __name__ == "__main__":
    main()
