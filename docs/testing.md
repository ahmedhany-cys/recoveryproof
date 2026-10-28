# Testing

## Results (verified locally on 2026-10-28, Python 3.13.5, macOS arm64)

| Gate | Command | Result |
|---|---|---|
| Tests | `pytest` | **244 passed**, 0 failed, 0 skipped |
| Coverage, core engine | `coverage report --omit="*/ui/*"` | **99%** (branch coverage) |
| Coverage, overall incl. UI | `pytest --cov` | **95%** |
| Lint | `ruff check src tests scripts` | no issues |
| Format | `ruff format --check src tests scripts` | clean |
| Types | `mypy` (strict, pydantic plugin) | no issues in 27 source files |
| Security (code) | `bandit -c pyproject.toml -r src scripts` | no issues; 2 reviewed false positives annotated (`"pass"` enum value; deliberate skip of unreadable iframes in the screenshot script) |
| Security (deps) | `pip-audit --skip-editable` | no known vulnerabilities |
| CLI scenario checks | `recoveryproof analyze --scenario X --check` for A–J | all pass |
| Terraform template | `terraform fmt -check -recursive infra/terraform` | clean (not `init`/`validate`d, not applied) |

The CI workflow (`.github/workflows/ci.yml`) runs the same gates on Python 3.12 and 3.13,
plus an app-startup smoke test. The first run on GitHub passed
([run 40657113277](https://github.com/ahmedhany-cys/recoveryproof/actions/runs/40657113277), triggered by the first push on 2026-10-28):

| Job | Result | Duration |
|---|---|---|
| Lint, types and security | passed | 1m12s |
| Tests (Python 3.13), incl. coverage gates | passed | 1m01s |
| Tests (Python 3.12) | passed | 1m38s |
| App startup smoke test | passed | 40s |

## What the suite covers

| File | Focus |
|---|---|
| `test_models_loader.py` | Valid/invalid inventories, missing and unknown fields, naive timestamps, offset normalisation, ID patterns, duplicates, self/duplicate dependencies, unknown evidence references, repository rules; scenario validation; path traversal and symlink escape; size limits; invalid JSON/UTF-8; malformed scenario files; duplicate scenario IDs; time arithmetic and formatting |
| `test_backup.py` | Full evidence-evaluation matrix (claims without evidence, contradictions, latest-wins), immutability and exposure matrix, every eligibility reason, recovery-evidence levels, restore-test age, isolation states |
| `test_graph_plan.py` | Edge direction, missing deps, cycles and downstream blocking, priority ordering, shared dependencies, **property-based test (Hypothesis)**: on random DAGs the order respects every edge; plan timing, parallel branches, RTO boundary, unknown-duration propagation, blocked propagation, no fake "0 min" estimate |
| `test_scoring_findings.py` | Score weights, perfect = 100, no-backup boundary, unknown = no credit, band boundaries, criticality weighting, RPO boundaries (59/60/61 min), individual rules, metric/assessment consistency |
| `test_scenarios.py` | For **all 10 scenarios**: declared expectations, dependency-respecting order, determinism, baseline immutability, cross-scenario isolation, stable/unique finding IDs, evidence references resolve. Exact figures for baseline and A–E (e.g. C gap = 1 560 min; E fallback +60 min; D weighted impact 11) and error handling for bad scenario references |
| `test_reporting_audit.py` | HTML agrees with analysis and escapes `<script>`; PDF parses (pypdf) and contains the same numbers; JSON exports round-trip losslessly; comparison direction and plan-scope guard; audit-chain tamper and deletion detection; secret redaction; remediation lifecycle requiring verification; CLI commands and errors |
| `test_ui.py` | Streamlit AppTest: all 11 pages × 3 scenarios render without exceptions; full app shell with deep link; scenario run/reset; findings filter; acknowledge → refused resolve without verification → resolve with verification; inventory search; dependency impact analysis; malformed upload rejected |

## Browser testing

The running app was exercised in a real browser: the Claude desktop app's built-in browser
pane, plus Google Chrome driven by Playwright for the documentation screenshots.

- Every page opened for several scenarios via the sidebar, page links and `?scenario=` deep links.
- **Run scenario** (C) and **Reset to baseline** clicked; URL, sidebar, readiness and KPIs updated.
- Sidebar scenario selector changed the active scenario (A).
- Findings: **Acknowledge**, empty **resolve** (refused), resolve with a verification record (accepted).
- Audit trail showed the recorded actions with an intact hash chain.
- For all 10 scenarios, the Simulator's in-app expectation check reported all checks passing
  when rendered by the live server (A 14/14, B 13/13, C 7/7, D 8/8, E 8/8, F–J all pass).
- Download buttons were verified to render; their output is covered by the reporting tests.
  They were not clicked, to avoid writing files outside the project.

Defects found in the browser and fixed are listed in
[`screenshots/README.md`](screenshots/README.md#built-in-browser-captures-browser-pane).

## Running

```bash
pip install -e ".[dev]"
pytest                                   # everything (≈10 s)
pytest -m "not ui"                       # skip Streamlit AppTest
pytest --cov && coverage report --omit="*/ui/*"
```
