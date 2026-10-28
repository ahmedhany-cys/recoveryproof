"""Write sample reports to docs/examples/ from the bundled synthetic data.

python scripts/generate_examples.py
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from recoveryproof.engine import analyze
from recoveryproof.loader import load_inventory, load_policy, load_scenarios
from recoveryproof.reporting import export_findings_json, export_plan_json, render_html, render_pdf

OUT = Path(__file__).resolve().parent.parent / "docs" / "examples"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    inv, policy = load_inventory(), load_policy()
    scenarios = {s.code: s for s in load_scenarios()}
    now = datetime.now(UTC).replace(microsecond=0)
    for code in ("BL", "A", "B", "C", "D", "E"):
        result = analyze(inv, policy, scenarios.get(code), generated_at=now)
        stem = f"report-{code.lower()}-{result.scenario_id.lower()}"
        (OUT / f"{stem}.html").write_text(render_html(result), encoding="utf-8")
        if code in ("BL", "D"):
            (OUT / f"{stem}.pdf").write_bytes(render_pdf(result))
            (OUT / f"{stem}-findings.json").write_text(export_findings_json(result), encoding="utf-8")
            (OUT / f"{stem}-plan.json").write_text(export_plan_json(result), encoding="utf-8")
    for p in sorted(OUT.iterdir()):
        print(f"{p.stat().st_size:>8}  {p.relative_to(OUT.parent.parent)}")


if __name__ == "__main__":
    main()
