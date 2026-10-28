"""App shell: page config, sidebar controls and navigation."""

from __future__ import annotations

import streamlit as st

from recoveryproof import ANALYSIS_VERSION, __version__
from recoveryproof.scenarios import BASELINE_ID
from recoveryproof.ui import pages
from recoveryproof.ui.components import BAND_COLORS, inject_css
from recoveryproof.ui.state import accept_upload, clear_upload, get_ctx, init_state, set_scenario

PAGES = {
    "Overview": [
        st.Page(pages.executive_overview, title="Executive Overview", icon="📊", url_path="overview", default=True),
        st.Page(pages.asset_inventory, title="Asset Inventory", icon="🗂️", url_path="assets"),
        st.Page(pages.backup_health, title="Backup Health", icon="💾", url_path="backups"),
        st.Page(pages.dependency_graph, title="Dependency Graph", icon="🕸️", url_path="dependencies"),
    ],
    "Incident response": [
        st.Page(pages.scenario_simulator, title="Scenario Simulator", icon="🧪", url_path="simulator"),
        st.Page(pages.incident_timeline, title="Incident Timeline", icon="🕒", url_path="timeline"),
        st.Page(pages.recovery_plan, title="Recovery Plan", icon="🛠️", url_path="plan"),
        st.Page(pages.findings_remediation, title="Findings & Remediation", icon="🚩", url_path="findings"),
    ],
    "Evidence & reporting": [
        st.Page(pages.evidence_explorer, title="Evidence Explorer", icon="🔎", url_path="evidence"),
        st.Page(pages.reports_export, title="Reports & Export", icon="📄", url_path="reports"),
        st.Page(pages.methodology, title="Methodology", icon="📐", url_path="methodology"),
    ],
}


def _on_sidebar_scenario() -> None:
    set_scenario(st.session_state.sidebar_scenario, reason="scenario.select")


def sidebar() -> None:
    ctx = get_ctx()
    m = ctx.result.metrics
    with st.sidebar:
        st.markdown("### 🛡️ RecoveryProof\n<span style='color:#94a3b8'>Prove recovery before disaster strikes.</span>",
                    unsafe_allow_html=True)  # fmt: skip
        options = [BASELINE_ID] + [s.id for s in ctx.scenarios]
        labels = {BASELINE_ID: "Baseline — no incident"} | {s.id: f"{s.code} · {s.title}" for s in ctx.scenarios}
        st.session_state.sidebar_scenario = st.session_state.scenario_id
        st.selectbox("Active scenario", options, format_func=labels.__getitem__, key="sidebar_scenario",
                     on_change=_on_sidebar_scenario)  # fmt: skip
        color = BAND_COLORS.get(m.readiness_band, "#3b82f6")
        st.markdown(
            f"<div style='border:1px solid #1e2a44;border-left:4px solid {color};border-radius:8px;padding:.5rem .7rem;"
            f"font-size:.85rem'>Readiness <b style='font-size:1.1rem;color:#fff'>{m.readiness_score:g}</b> · "
            f"{m.readiness_band}<br><span style='color:#94a3b8'>{m.findings_by_severity['critical']} critical · "
            f"{m.findings_by_severity['high']} high findings</span></div>",
            unsafe_allow_html=True,
        )
        with st.expander("Data source", expanded=False):
            st.caption(ctx.data_source)
            up = st.file_uploader("Load inventory JSON (validated, max 2 MB)", type=["json"], key="inv_upload")
            if up is not None and st.button("Validate and use this file", key="use_upload"):
                err = accept_upload(up.name, up.getvalue())
                if err:
                    st.error(err)
                else:
                    st.success("Inventory accepted.")
                    st.rerun()
            if st.session_state.get("uploaded_inventory") and st.button("Use bundled synthetic data", key="clear_up"):
                clear_upload()
                st.rerun()
        st.caption(f"v{__version__} · analysis {ANALYSIS_VERSION} · all bundled data is synthetic")
    st.query_params["scenario"] = ctx.result.scenario_code if ctx.scenario else "BL"


def main() -> None:
    st.set_page_config(page_title="RecoveryProof", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
    inject_css()
    init_state()
    nav = st.navigation(PAGES, position="sidebar", expanded=True)
    sidebar()
    nav.run()
