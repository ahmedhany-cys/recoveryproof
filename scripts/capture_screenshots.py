"""Capture documentation screenshots from a *running* RecoveryProof server.

Drives a real Chrome browser (the locally installed Google Chrome via Playwright's
``channel="chrome"``; falls back to Playwright's bundled Chromium if installed),
navigates the live app, performs the UI interactions listed below and saves PNG
screenshots plus a JSON manifest describing what each image shows and how the
page state was verified before capture.

    streamlit run app.py --server.port 8501 &
    pip install -e ".[screenshots]"
    python scripts/capture_screenshots.py --base-url http://127.0.0.1:8501

Nothing is drawn or composited: every PNG is the browser's own rendering.
"""

from __future__ import annotations

import argparse
import json
import platform
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Shot:
    file: str
    path: str
    title: str
    state: str
    select: dict[str, str] = field(default_factory=dict)  # combobox aria-label -> option text
    segment: str | None = None  # segmented-control option to click
    scroll_to: str | None = None  # text to bring to the top of the viewport
    must_contain: list[str] = field(default_factory=list)


SHOTS = [
    Shot("01-executive-overview.png", "/?scenario=BL", "Executive Overview",
         "Baseline (no incident): readiness 85.7/100 Moderate, KPI cards and top remediation items.",
         must_contain=["Executive Overview", "85.7", "Highest-priority remediation"]),
    Shot("02-asset-inventory.png", "/assets?scenario=BL", "Asset Inventory",
         "Baseline: all 15 synthetic assets with criticality, RTO/RPO, dependencies and recovery evidence.",
         must_contain=["Asset Inventory", "15 of 15 assets shown"]),
    Shot("03-backup-health.png", "/backups?scenario=BL", "Backup Health",
         "Baseline: per-system recovery evidence, selected recovery point, RPO status and isolation.",
         must_contain=["Backup Health", "Recovery points (last 3 days)", "isolated vault"]),
    Shot("04-recovery-dependency-graph.png", "/dependencies?scenario=D", "Recovery Dependency Graph",
         "Scenario D with impact analysis on db-orders: blocked nodes in red, impacted dependents highlighted.",
         select={"Impact analysis — what if this system were unavailable?": "db-orders"},
         must_contain=["Impact if db-orders is unavailable", "3 dependent systems"]),
    Shot("05-ransomware-scenario.png", "/plan?scenario=A", "Scenario A — Ransomware with intact backups",
         "Recovery plan for Scenario A: dependency-ordered restore, Gantt with RTO markers, file-share RTO breach.",
         must_contain=["Ransomware with intact backups", "Recovery Plan", "1 d 6 h"]),
    Shot("06-compromised-backup-scenario.png", "/?scenario=B", "Scenario B — Compromised backup administrator",
         "Executive overview under Scenario B: readiness falls to 67.6 (Weak); critical ACC-002 findings.",
         must_contain=["Compromised backup administrator", "67.6"]),
    Shot("07-stale-backup-scenario.png", "/simulator?scenario=C", "Scenario C — Stale database backup",
         "Simulator before/after comparison for Scenario C: db-orders exposure 1 d 2 h vs 15 min RPO.",
         scroll_to="Before / after comparison",
         must_contain=["Stale database backup", "Before / after comparison", "expectation checks pass"]),
    Shot("08-unavailable-dependency-scenario.png", "/plan?scenario=D", "Scenario D — Critical dependency unavailable",
         "Recovery plan for Scenario D: db-orders unrecoverable, Orders API blocked although its backup is intact.",
         must_contain=["Critical dependency unavailable", "BLOCKED"]),
    Shot("09-corrupted-backup-scenario.png", "/backups?scenario=E", "Scenario E — Corrupted newest recovery point",
         "Backup drill-down for db-customers under Scenario E: newest point failed integrity, fallback to 07:00.",
         select={"System": "Customer Database (PostgreSQL)"}, scroll_to="Recovery point drill-down",
         must_contain=["Corrupted newest recovery point", "Recovery point drill-down", "Customer Database"]),
    Shot("10-remediation-findings.png", "/findings?scenario=B", "Findings & Remediation",
         "Scenario B findings with severity counts, filters and the ACC-002 finding detail with remediation.",
         select={"Finding": "F-ACC-002-app-erp"}, scroll_to="Finding detail",
         must_contain=["Findings & Remediation", "F-ACC-002-app-erp"]),
    Shot("11-evidence-explorer.png", "/evidence?scenario=E", "Evidence Explorer",
         "Tracing finding F-RP-003-db-customers to the scenario-injected integrity-failure evidence record.",
         select={"Finding": "F-RP-003-db-customers"},
         must_contain=["Evidence Explorer", "EV-E-SIM-01"]),
    Shot("12-recovery-report.png", "/reports?scenario=D", "Reports & Export",
         "Scenario D report page: HTML/PDF/JSON exports and the rendered executive report preview.",
         must_contain=["Reports & Export", "PDF report"]),
]  # fmt: skip


def wait_idle(page: Page, settle: float = 1.5) -> None:
    """Wait until Streamlit has finished re-running the script, then let charts settle."""
    page.wait_for_load_state("networkidle")
    deadline = time.time() + 30
    while time.time() < deadline:
        running = page.locator('[data-testid="stStatusWidget"]').count()
        if not running:
            break
        time.sleep(0.25)
    time.sleep(settle)


def body_text(page: Page) -> str:
    text = page.inner_text("body")
    for frame in page.frames[1:]:
        try:
            text += "\n" + frame.inner_text("body")
        except Exception:  # noqa: S112  # nosec B112 - cross-origin/detached frames are irrelevant
            continue
    return text


def capture(base_url: str, out_dir: Path, width: int, height: int, scale: float) -> list[dict[str, object]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, object]] = []
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(channel="chrome")
            engine = f"Google Chrome {browser.version} (Playwright channel=chrome)"
        except Exception:
            browser = p.chromium.launch()
            engine = f"Chromium {browser.version} (Playwright bundled)"
        ctx = browser.new_context(viewport={"width": width, "height": height}, device_scale_factor=scale,
                                  color_scheme="dark")  # fmt: skip
        page = ctx.new_page()
        for shot in SHOTS:
            page.goto(base_url.rstrip("/") + shot.path)
            page.wait_for_selector('[data-testid="stMain"]', timeout=60_000)
            wait_idle(page, settle=2.0)
            for label, option in shot.select.items():
                box = page.get_by_role("combobox", name=label).first
                box.click()
                box.fill(option)
                page.keyboard.press("Enter")
                wait_idle(page)
            if shot.segment:
                page.get_by_role("button", name=shot.segment).first.click()
                wait_idle(page)
            if shot.scroll_to:
                page.get_by_text(shot.scroll_to, exact=False).first.evaluate(
                    "el => el.scrollIntoView({block: 'start'})"
                )
                wait_idle(page, settle=1.0)
            text = body_text(page)
            # case-insensitive: some labels are uppercased by CSS. Table cells are drawn on a
            # canvas by Streamlit, so checks use text that exists in the DOM.
            missing = [m for m in shot.must_contain if m.lower() not in text.lower()]
            if "Page not found" in text or "Traceback" in text or "Error" in page.title():
                missing.append("(error page detected)")
            target = out_dir / shot.file
            page.screenshot(path=str(target))
            records.append(
                {
                    **asdict(shot),
                    "url": base_url.rstrip("/") + shot.path,
                    "captured_at": datetime.now(UTC).isoformat(timespec="seconds"),
                    "viewport": f"{width}x{height} @ {scale}x",
                    "browser": engine,
                    "verified_text_present": not missing,
                    "missing_text": missing,
                    "bytes": target.stat().st_size,
                }
            )
            status = "OK " if not missing else "WARN"
            print(f"[{status}] {shot.file} {missing or ''}")
        browser.close()
    return records


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8501")
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "screenshots")
    ap.add_argument("--width", type=int, default=1440)
    ap.add_argument("--height", type=int, default=960)
    ap.add_argument("--scale", type=float, default=1.5)
    args = ap.parse_args()
    records = capture(args.base_url, args.out, args.width, args.height, args.scale)
    manifest = {
        "generated_by": "scripts/capture_screenshots.py",
        "method": "Real browser screenshots of the locally running Streamlit app (no image editing).",
        "host": f"{platform.system()} {platform.machine()}",
        "screenshots": records,
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0 if all(r["verified_text_present"] for r in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
