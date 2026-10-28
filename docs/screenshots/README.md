# Screenshot manifest

Every image here is a real browser rendering of the locally running RecoveryProof app
(`streamlit run app.py`, `http://127.0.0.1:8501`). Nothing was drawn, edited or composited.

## How the 12 documentation screenshots were produced

| | |
|---|---|
| Script | [`scripts/capture_screenshots.py`](../../scripts/capture_screenshots.py) |
| Browser | Google Chrome 156.0.8078.49, driven by Playwright (`channel="chrome"`), dark color scheme |
| Viewport | 1440 × 960 CSS px at 1.5× device scale → 2160 × 1440 PNG |
| Captured | 2026-10-28, macOS arm64, against the same server instance used for interactive testing |
| Data | Bundled synthetic baseline (fictional "Northwind Logistics") — no secrets or personal data |
| Machine-readable record | [`manifest.json`](manifest.json): URL, interactions, browser, viewport, timestamp and the text checks per image |

Before each capture the script waits for Streamlit to finish rendering and confirms that
the expected text is present on the page (for example the scenario title and key values).
It also checks that no error page or traceback is showing. All 12 captures passed these
checks (`verified_text_present: true`). After capture, each image was also reviewed by eye.

| File | Page · state shown | Interaction before capture |
|---|---|---|
| `01-executive-overview.png` | Executive Overview · baseline, readiness 85.7 (Moderate) | — |
| `02-asset-inventory.png` | Asset Inventory · all 15 assets | — |
| `03-backup-health.png` | Backup Health · baseline evidence table + recovery-point chart | — |
| `04-recovery-dependency-graph.png` | Dependency Graph · Scenario D, impact analysis on `db-orders` | selected `db-orders` |
| `05-ransomware-scenario.png` | Recovery Plan · Scenario A (ransomware, intact backups) | — |
| `06-compromised-backup-scenario.png` | Executive Overview · Scenario B (readiness 67.6, Weak) | — |
| `07-stale-backup-scenario.png` | Scenario Simulator · Scenario C before/after vs baseline | scrolled to comparison |
| `08-unavailable-dependency-scenario.png` | Recovery Plan · Scenario D (both steps blocked) | — |
| `09-corrupted-backup-scenario.png` | Backup Health · Scenario E, `db-customers` drill-down | selected system, scrolled |
| `10-remediation-findings.png` | Findings & Remediation · Scenario B, `F-ACC-002-app-erp` | selected finding, scrolled |
| `11-evidence-explorer.png` | Evidence Explorer · Scenario E, trace `F-RP-003-db-customers` | selected finding |
| `12-recovery-report.png` | Reports & Export · Scenario D report preview | — |

Regenerate with:

```bash
pip install -e ".[screenshots]"
streamlit run app.py --server.port 8501 &
python scripts/capture_screenshots.py --base-url http://127.0.0.1:8501
```

## Built-in browser captures (`browser-pane/`)

During interactive testing the app was also driven in the Claude desktop app's built-in
browser pane. That pane saves its screenshots as 800 × 500 JPEGs, which are too small for
the README, so the 12 images above were captured separately with Chrome. Four pane captures
are kept as supporting evidence of the interactive session:

| File | What it shows |
|---|---|
| `a-run-scenario-c-via-button.jpg` | Simulator after clicking **Run scenario** for C. URL and sidebar switched to C; readiness 82.7. Captured *before* a later fix: the "Compare against" box here still showed a stale selection (fixed afterwards). |
| `b-sidebar-select-scenario-a.jpg` | Choosing Scenario A in the sidebar selector updates the whole overview (55% business impact). |
| `c-audit-trail-after-fix.jpg` | Audit trail listing `scenario.run`, `remediation.acknowledged` and `remediation.resolved`, with an intact hash chain. |
| `d-timeline-after-fix.jpg` | Incident timeline for Scenario B after the date-axis fix. |

Defects found during browser testing and fixed before the final captures:

1. The audit-trail grid inside an inactive `st.tabs` panel rendered with empty columns. Replaced with a segmented control.
2. The "Compare against" selector kept a stale value after a new scenario was picked. It is now keyed per selection.
3. Injected events were listed out of time order. Now sorted.
4. The timeline and recovery-point chart axes misbehaved with timezone-aware datetimes. They now plot naive UTC.
5. The before/after comparison reported "Unmet RTO: better" when the two plans restored different systems. It now flags the counts as not comparable.
6. The PDF report hid alternating table rows behind a navy fill (found while reviewing the rendered PDF).
