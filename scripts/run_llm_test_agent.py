#!/usr/bin/env python3
"""Run LLM test agent (gpt-5.4-nano) against Unplug MCP scan tools."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from unplug.audit.boundary import default_boundary_probes_path, run_boundary_probe_suite
from unplug.audit.runner import run_audit
from unplug_mcp.test_agent.env import WORKSPACE_ROOT
from unplug_mcp.test_agent.runner import (
    run_encoding_only,
    run_llm_agent,
    run_probe_only,
    run_sdk_only,
    save_report,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Unplug LLM test agent")
    parser.add_argument(
        "--mode",
        choices=("probes", "sdk", "encoding", "boundary", "audit", "agent"),
        default="agent",
        help="probes=FP; sdk=SDK+ML; encoding=base64; boundary=session/profile gates; agent=LLM",
    )
    parser.add_argument("--max-turns", type=int, default=24)
    parser.add_argument("--out-dir", type=Path, default=Path("reports"))
    parser.add_argument("--model", default=None, help="Override OPENAI_TEST_AGENT_MODEL")
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Run unplug-audit wiring checks (alias: --mode audit)",
    )
    parser.add_argument(
        "--probes",
        action="store_true",
        help="Run FP, encoding, and boundary probe suites during audit",
    )
    parser.add_argument(
        "--require-ml",
        action="store_true",
        help="Require ML checkpoint loaded (audit + sdk/encoding modes)",
    )
    args = parser.parse_args()

    if args.model:
        import os

        os.environ["OPENAI_TEST_AGENT_MODEL"] = args.model

    if args.audit:
        args.mode = "audit"

    require_ml = args.require_ml or args.mode in ("sdk", "encoding")

    if args.mode == "audit":
        report = {
            "mode": "audit",
            "suite": run_audit(
                workspace_root=WORKSPACE_ROOT,
                include_probes=args.probes,
                require_ml=require_ml,
            ),
        }
        print(json.dumps(report["suite"], indent=2))
        path = save_report(report, args.out_dir)
        suite = report["suite"]
        print(
            f"\nreport: {path} wiring_pass={suite.get('wiring_pass')} "
            f"all_passed={suite.get('all_passed')}",
            file=sys.stderr,
        )
        sys.exit(0 if suite.get("wiring_pass") else 1)

    if args.mode == "boundary":
        path = default_boundary_probes_path(WORKSPACE_ROOT)
        suite = run_boundary_probe_suite(path)
        report = {"mode": "boundary", "suite": suite}
        print(json.dumps(suite, indent=2))
        out = save_report(report, args.out_dir)
        print(f"\nreport: {out} all_passed={suite.get('all_passed')}", file=sys.stderr)
        sys.exit(0 if suite.get("all_passed") else 1)

    if args.mode == "probes":
        report = {"mode": "probes", "suite": run_probe_only(require_ml=require_ml)}
        print(json.dumps(report["suite"], indent=2))
        path = save_report(report, args.out_dir)
        print(f"\nreport: {path}", file=sys.stderr)
        sys.exit(0 if report["suite"].get("all_probes_pass") else 1)

    if args.mode == "encoding":
        report = {"mode": "encoding", "suite": run_encoding_only(require_ml=require_ml)}
        print(json.dumps(report["suite"], indent=2))
        path = save_report(report, args.out_dir)
        print(
            f"\nreport: {path} encoding_probes_pass={report['suite'].get('encoding_probes_pass')} "
            f"encoding_stage_hits={report['suite'].get('encoding_stage_hits')} "
            f"literal_control_fp={report['suite'].get('literal_control_fp')}",
            file=sys.stderr,
        )
        sys.exit(0 if report["suite"].get("encoding_probes_pass") else 1)

    if args.mode == "sdk":
        report = {"mode": "sdk", "suite": run_sdk_only(require_ml=require_ml)}
        print(json.dumps(report["suite"], indent=2))
        path = save_report(report, args.out_dir)
        print(
            f"\nreport: {path} sdk_wiring_pass={report['suite'].get('sdk_wiring_pass')} "
            f"all_passed={report['suite'].get('all_passed')}",
            file=sys.stderr,
        )
        sys.exit(0 if report["suite"].get("sdk_wiring_pass") else 1)

    report = {"mode": "agent", "run": run_llm_agent(max_turns=args.max_turns)}
    print(report["run"].get("final_message") or "")
    path = save_report(report, args.out_dir)
    print(f"\nreport: {path}", file=sys.stderr)
    for tool_name in ("run_sdk_integration_suite", "run_fp_probe_suite"):
        hits = [c for c in report["run"].get("tool_calls", []) if c.get("name") == tool_name]
        if hits:
            result = hits[0]["result"]
            key = "all_passed" if tool_name == "run_sdk_integration_suite" else "all_probes_pass"
            print(f"{tool_name} {key}={result.get(key)}", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
