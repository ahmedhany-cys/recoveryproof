"""Command-line interface.

recoveryproof scenarios                 list bundled scenarios
recoveryproof analyze --scenario A      print a summary
recoveryproof report --scenario A --format pdf --out report.pdf
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from recoveryproof.compare import check_expectations
from recoveryproof.engine import analyze
from recoveryproof.loader import DEFAULT_DATA_DIR, InputError, load_inventory, load_policy, load_scenarios
from recoveryproof.models import Scenario
from recoveryproof.reporting import export_findings_json, export_full_json, export_plan_json, render_html, render_pdf
from recoveryproof.reporting.common import data_loss_text, recovery_estimate_text


def _scenario(code: str | None, data_dir: Path) -> Scenario | None:
    if not code or code.upper() in ("BL", "BASELINE"):
        return None
    for s in load_scenarios(data_dir):
        if s.code == code.upper() or s.id == code:
            return s
    raise InputError(f"unknown scenario '{code}'")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="recoveryproof", description="Evidence-based recovery readiness analysis")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scenarios", help="list bundled scenarios")
    a = sub.add_parser("analyze", help="print an analysis summary")
    a.add_argument("--scenario", default=None, help="scenario code (A-J) or id; omit for baseline")
    a.add_argument("--check", action="store_true", help="verify the scenario's expected outcome")
    r = sub.add_parser("report", help="write a report file")
    r.add_argument("--scenario", default=None)
    r.add_argument("--format", choices=["html", "pdf", "json", "findings-json", "plan-json"], default="html")
    r.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        if args.cmd == "scenarios":
            for s in load_scenarios(args.data_dir):
                print(f"{s.code:2} {s.id:38} {s.severity.value:8} {s.title}")
            return 0
        inv, policy = load_inventory(args.data_dir), load_policy(args.data_dir)
        scenario = _scenario(args.scenario, args.data_dir)
        result = analyze(inv, policy, scenario)
        if args.cmd == "analyze":
            m = result.metrics
            print(f"{result.scenario_title} [{result.scenario_id}]")
            print(f"  readiness        {m.readiness_score:g}/100 ({m.readiness_band})")
            print(f"  recovery time    {recovery_estimate_text(result)}")
            print(f"  data-loss        {data_loss_text(result)}")
            print(f"  findings         {m.findings_by_severity}")
            print(
                "  recovery order   "
                + " -> ".join(f"{s.asset_id}{' [BLOCKED]' if s.blocked else ''}" for s in result.plan.steps)
            )
            if args.check and scenario:
                checks = check_expectations(result, scenario)
                for c in checks:
                    print(f"  [{'PASS' if c.passed else 'FAIL'}] {c.name}: expected {c.expected}, actual {c.actual}")
                return 0 if all(c.passed for c in checks) else 1
            return 0
        out: Path = args.out
        if args.format == "pdf":
            out.write_bytes(render_pdf(result))
        else:
            text = {
                "html": render_html,
                "json": export_full_json,
                "findings-json": export_findings_json,
                "plan-json": export_plan_json,
            }[args.format](result)
            out.write_text(text, encoding="utf-8")
        print(f"wrote {out}")
        return 0
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
