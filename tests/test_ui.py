"""Streamlit AppTest: every page renders for key scenarios, and critical controls
behave as documented (scenario run/reset, filters, remediation lifecycle)."""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parent.parent / "app.py")
PAGES = [
    "executive_overview", "asset_inventory", "backup_health", "dependency_graph", "scenario_simulator",
    "incident_timeline", "recovery_plan", "findings_remediation", "evidence_explorer", "reports_export", "methodology",
]  # fmt: skip

pytestmark = pytest.mark.ui


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECOVERYPROOF_STATE_DIR", str(tmp_path))


def _page(fn: str, scenario: str = "BL") -> AppTest:
    script = (
        "from recoveryproof.ui.state import init_state\n"
        "from recoveryproof.ui import pages\n"
        "init_state()\n"
        f"pages.{fn}()\n"
    )
    at = AppTest.from_string(script, default_timeout=90)
    at.query_params["scenario"] = scenario
    return at.run()


def _text(at: AppTest) -> str:
    parts = [m.value for m in at.markdown] + [str(h.proto.body) for h in at.get("html")]
    parts += [c.value for c in at.caption] + [s.value for s in at.subheader]
    return "\n".join(str(p) for p in parts)


@pytest.mark.parametrize("page", PAGES)
@pytest.mark.parametrize("scenario", ["BL", "B", "D"])
def test_page_renders(page: str, scenario: str) -> None:
    at = _page(page, scenario)
    assert not at.exception, at.exception


def test_full_app_shell_renders() -> None:
    at = AppTest.from_file(APP, default_timeout=90)
    at.query_params["scenario"] = "C"
    at.run()
    assert not at.exception
    assert at.sidebar.selectbox(key="sidebar_scenario").value == "SCN-C-STALE-DB-BACKUP"
    assert "82.7" in _text(at) or any("82.7" in str(h.proto.body) for h in at.get("html"))


def test_overview_shows_scenario_metrics() -> None:
    at = _page("executive_overview", "D")
    html = "\n".join(str(h.proto.body) for h in at.get("html"))
    assert "Critical dependency unavailable" in html
    assert "every recovery step is blocked" in html


def test_simulator_run_and_reset() -> None:
    at = _page("scenario_simulator", "BL")
    at.selectbox(key="sim_pick").select("SCN-E-CORRUPTED-NEWEST-POINT").run()
    at.button(key="sim_run").click().run()
    assert not at.exception
    assert at.session_state.scenario_id == "SCN-E-CORRUPTED-NEWEST-POINT"
    assert any("expectation checks pass" in s.value for s in at.success)
    at.button(key="sim_reset").click().run()
    assert at.session_state.scenario_id == "SCN-BASELINE"


def test_findings_filter_and_remediation_lifecycle() -> None:
    at = _page("findings_remediation", "BL")
    at.multiselect(key="fd_sev").set_value(["critical"]).run()
    assert "1 of 20 findings" in _text(at)
    at.multiselect(key="fd_sev").set_value(["critical", "high", "medium", "low", "info"]).run()
    at.selectbox(key="fd_pick").select("F-RP-005-db-customers").run()
    at.button(key="ack_F-RP-005-db-customers").click().run()
    assert "`acknowledged`" in _text(at)
    # resolving without a verification record must be refused
    at.button(key="FormSubmitter:resolve_F-RP-005-db-customers-Record verification and resolve").click().run()
    assert any("Not resolved: complete" in e.value for e in at.error)
    form_inputs = at.text_input
    form_inputs[-3].input("j.doe")
    form_inputs[-2].input("Restore test into isolated VPC")
    form_inputs[-1].input("EV-RST-NEW-1")
    at.button(key="FormSubmitter:resolve_F-RP-005-db-customers-Record verification and resolve").click().run()
    assert "`resolved`" in _text(at)


def test_inventory_search_filters_rows() -> None:
    at = _page("asset_inventory", "BL")
    at.text_input(key="inv_search").input("orders").run()
    assert "2 of 15 assets shown" in _text(at)


def test_dependency_impact_analysis() -> None:
    at = _page("dependency_graph", "BL")
    at.selectbox(key="dg_focus").select("idp-core").run()
    html = "\n".join(str(h.proto.body) for h in at.get("html"))
    assert "Impact if idp-core is unavailable" in html
    assert "6 dependent systems" in html


def test_upload_rejects_malformed_inventory() -> None:
    from recoveryproof.ui.state import accept_upload

    at = _page("executive_overview", "BL")  # creates a session so session_state exists
    assert not at.exception
    import streamlit as st

    st.session_state.clear()
    err = accept_upload("evil.json", b'{"organization": "x", "assets": "nope"}')
    assert err is not None and "failed validation" in err
