"""Dashboard pages. Each page reads the shared :class:`Ctx`; no page computes
its own metrics — everything shown comes from the AnalysisResult."""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from pydantic import ValidationError

from recoveryproof.compare import check_expectations, compare
from recoveryproof.engine import READINESS_BANDS, SCORE_WEIGHTS
from recoveryproof.graph import build_graph, descendants
from recoveryproof.remediation import RemediationError, VerificationRecord
from recoveryproof.reporting import export_findings_json, export_full_json, export_plan_json, render_html, render_pdf
from recoveryproof.results import AnalysisResult
from recoveryproof.rules import RULES
from recoveryproof.scenarios import BASELINE_ID, apply_scenario
from recoveryproof.timeutil import fmt_minutes, fmt_ts, utc_now
from recoveryproof.ui import charts
from recoveryproof.ui.components import (
    SEVERITY_COLORS,
    banner,
    basis_badge,
    basis_legend,
    card,
    card_row,
    page_header,
    sev_badge,
)
from recoveryproof.ui.state import Ctx, audit_log, get_ctx, set_scenario

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def _chips(ctx: Ctx) -> list[tuple[str, str]]:
    r = ctx.result
    return [
        ("Scenario", f"{r.scenario_code} · {r.scenario_title}"),
        ("Incident", fmt_ts(r.incident_at)),
        ("Data as of", fmt_ts(r.as_of)),
        ("Source", "synthetic" if "synthetic" in ctx.data_source.lower() else "uploaded"),
    ]


def _scenario_banner(ctx: Ctx) -> None:
    if ctx.error:
        st.error(ctx.error)
    if ctx.scenario:
        banner(
            f"Simulated scenario active: {ctx.scenario.title}. Conditions marked 'simulated' are injected for this "
            "exercise; they are not observations of a real environment.",
            simulated=True,
        )


def _status(value: str) -> str:
    return {"met": "✅ met", "breached": "❌ breached", "unknown": "⚠️ unknown", "not_applicable": "— n/a"}.get(
        value, value
    )


# ------------------------------------------------------------------ overview


def executive_overview() -> None:
    ctx = get_ctx()
    r, m = ctx.result, ctx.result.metrics
    page_header("Executive Overview", "Can our critical systems actually be recovered?", _chips(ctx))
    _scenario_banner(ctx)
    left, right = st.columns([1, 2.2], gap="medium")
    with left:
        st.plotly_chart(charts.readiness_gauge(m.readiness_score, m.readiness_band), width="stretch")
        delta = m.readiness_score - ctx.baseline.metrics.readiness_score
        if ctx.scenario:
            st.caption(f"Change vs. baseline: {delta:+.1f} points")
        else:
            st.caption("Baseline: full-environment recovery rehearsal (no incident injected).")
    with right:
        card_row(
            [
                card("Critical systems", str(m.critical_systems), f"tier 0–1 of {m.assessed_systems} assessed"),
                card("Restore-tested", f"{m.verified_recovery} / {m.assessed_systems}", "verified recovery evidence",
                     accent="#22c55e"),
                card("Stale / missing points", str(m.stale_or_missing), "RPO breached or no eligible point",
                     accent="#f59e0b" if m.stale_or_missing else None),
                card("Integrity failures", str(m.integrity_failures), "recovery points failing checks",
                     accent="#ef4444" if m.integrity_failures else None),
            ]
        )  # fmt: skip
        st.write("")
        card_row(
            [
                card("Unmet RTO", str(m.rto_unmet), f"{m.rto_unknown} unknown · plan steps",
                     accent="#ef4444" if m.rto_unmet else None),
                card("Unmet RPO", str(m.rpo_unmet), f"{m.rpo_unknown} unknown · all systems",
                     accent="#ef4444" if m.rpo_unmet else None),
                card("Dependency failures", str(m.dependency_failures), "blocked by prerequisites",
                     accent="#ef4444" if m.dependency_failures else None),
                card("Business impact", f"{m.business_impact_pct:g}%", f"{len(m.impacted_assets)} systems affected"),
            ]
        )  # fmt: skip
        st.write("")
        c1, c2 = st.columns(2)
        p = r.plan
        if p.parallel_minutes is not None:
            est, est_note = fmt_minutes(p.parallel_minutes), "all restorable systems, parallel"
        elif p.parallel_lower_bound_minutes is not None:
            est = f"≥ {fmt_minutes(p.parallel_lower_bound_minutes)}"
            est_note = f"incomplete: duration unknown for {', '.join(p.unknown_duration_assets)}"
        else:
            est, est_note = "Unknown", "every recovery step is blocked"
        est_note += f" · serial {fmt_minutes(p.serial_minutes)} · {len(p.blocked_assets)} blocked"
        c1.html(card("Estimated recovery time (derived)", est, est_note))
        c2.html(card("Potential data-loss exposure (derived)", fmt_minutes(m.max_data_loss_minutes, "None measurable"),
                     f"{len(m.unbounded_data_loss_assets)} system(s) with no usable point" if
                     m.unbounded_data_loss_assets else "max across systems being restored"))  # fmt: skip

    st.subheader("Highest-priority remediation")
    recs = ctx.result.recommendations[:6]
    if not recs:
        st.success("No findings for this scenario.")
    for rec in recs:
        f = r.finding(rec.finding_id)
        st.html(
            f'<div class="rp-finding" style="--sev:{SEVERITY_COLORS[f.severity.value]}">'
            f"<h4>{sev_badge(f.severity.value)} &nbsp;{escape(f.title)} — {escape(f.asset_name)}</h4>"
            f'<div class="rp-kv">{escape(rec.action)}</div>'
            f'<div class="rp-kv" style="margin-top:.3rem"><span class="rp-mono">{escape(f.id)}</span> · '
            f"basis {basis_badge(f.basis.value)}</div></div>"
        )
    with st.expander("How is the readiness score calculated?"):
        st.markdown(
            "Each system scores up to 100: "
            + ", ".join(f"**{k}** {v:g}" for k, v in SCORE_WEIGHTS.items())
            + ". The overall score is the criticality-weighted mean (tier 0 = 4, tier 1 = 3, tier 2 = 2, tier 3 = 1). "
            "RTO credit is computed against a full-environment rehearsal so scores stay comparable across "
            "scenarios. **Unknown values earn no credit.** Bands: "
            + ", ".join(f"{label} ≥ {t:g}" for t, label in READINESS_BANDS)
            + "."
        )
        st.plotly_chart(charts.score_breakdown(r), width="stretch")
    st.html(f'<div style="margin-top:.6rem">{basis_legend()}</div>')


# ----------------------------------------------------------------- inventory


def asset_inventory() -> None:
    ctx = get_ctx()
    page_header("Asset Inventory", "Systems in scope, their objectives and dependencies.", _chips(ctx))
    _scenario_banner(ctx)
    inv = ctx.inventory
    by_id = {a.asset_id: a for a in ctx.result.assets}
    c1, c2, c3, c4 = st.columns([2, 1.3, 1.3, 1.1])
    query = c1.text_input("Search", placeholder="name, id or owner", key="inv_search")
    crits = c2.multiselect("Criticality", ["tier0", "tier1", "tier2", "tier3"], key="inv_crit")
    types = c3.multiselect("Type", sorted({a.asset_type.value for a in inv.assets}), key="inv_type")
    envs = c4.multiselect("Environment", sorted({a.environment.value for a in inv.assets}), key="inv_env")
    rows = []
    for a in inv.assets:
        hay = f"{a.id} {a.name} {a.owner}".lower()
        if query and query.lower() not in hay:
            continue
        if (crits and a.criticality.value not in crits) or (types and a.asset_type.value not in types):
            continue
        if envs and a.environment.value not in envs:
            continue
        x = by_id.get(a.id)
        rows.append(
            {
                "ID": a.id, "Name": a.name, "Type": a.asset_type.label, "Criticality": a.criticality.value,
                "Environment": a.environment.value, "Owner": a.owner,
                "RTO": fmt_minutes(a.rto_minutes, "undocumented"), "RPO": fmt_minutes(a.rpo_minutes, "undocumented"),
                "Depends on": ", ".join(a.depends_on) or "—", "Sensitivity": a.data_sensitivity.value,
                "State": (x.state.value if x else a.state.value),
                "Recovery evidence": x.recovery_evidence.label if x else "n/a (repository)",
                "Last verified": fmt_ts(a.last_verified_at, "never"), "Source": a.source,
            }
        )  # fmt: skip
    st.caption(f"{len(rows)} of {len(inv.assets)} assets shown · click a column header to sort")
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=min(560, 38 + 35 * len(rows)))
    else:
        st.info("No assets match the current filters.")

    st.subheader("Asset detail")
    ids = [r["ID"] for r in rows] or [a.id for a in inv.assets]
    aid = st.selectbox("Inspect asset", ids, key="inv_detail", format_func=lambda i: f"{i} — {inv.asset(i).name}")
    a = inv.asset(aid)
    g = build_graph(inv.assets)
    dependents = sorted(descendants(g, [aid]))
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"**{a.name}** · {a.criticality.label}  \n{a.description or '_No description._'}")
        st.markdown(
            f"- Owner: **{a.owner}**  \n- RTO **{fmt_minutes(a.rto_minutes, 'undocumented')}**, "
            f"RPO **{fmt_minutes(a.rpo_minutes, 'undocumented')}**  \n- Data sensitivity: {a.data_sensitivity.value}"
        )
        if a.backup:
            b = a.backup
            enc = {True: "yes", False: "**no**", None: "**undocumented**"}[b.encrypted]
            st.markdown(
                f"- Backup every {fmt_minutes(b.schedule_minutes)}, retention {b.retention_days} days, encrypted: {enc}"
                f"  \n- {len(b.recovery_points)} recovery points on record"
            )
        elif a.repository:
            rc = a.repository
            st.markdown(
                f"- Repository · separate account: {rc.separate_account} · immutability: **{rc.immutability.value}**"
                f"  \n- Delete-capable roles: {', '.join(rc.delete_capable_roles) or 'none'}"
                f"  \n- Governance-bypass roles: {', '.join(rc.governance_bypass_roles) or 'none'}"
            )
        else:
            st.warning("No backup policy configured.")
    with c2:
        st.markdown(f"**Requires (restore first):** {', '.join(a.depends_on) or 'nothing'}")
        st.markdown(f"**Required by (transitively):** {', '.join(dependents) or 'nothing'}")
        refs = sorted(set(a.evidence_refs))
        st.markdown(f"**Evidence references:** {', '.join(refs) or 'none'}")
        x = by_id.get(aid)
        if x:
            st.markdown(f"**Score:** {x.score:g} / 100 · {x.recovery_evidence.label}")
            st.bar_chart(pd.Series(x.score_breakdown, name="points"), horizontal=True, height=180)


# -------------------------------------------------------------- backup health


def backup_health() -> None:
    ctx = get_ctx()
    r = ctx.result
    page_header("Backup Health", "Freshness, integrity, restore testing and isolation, from evidence.", _chips(ctx))
    _scenario_banner(ctx)
    st.caption(
        "A recovery point is **eligible** only when an evidence record shows a passing integrity check, "
        "it is reachable, untouched by a compromised role and predates the incident. "
        "Integrity checks and end-to-end restore tests are tracked separately."
    )
    rows = []
    for a in r.assets:
        rows.append(
            {
                "System": a.name, "Tier": a.criticality.value, "Recovery evidence": a.recovery_evidence.label,
                "Newest point": fmt_ts(a.newest_point_at, "none"),
                "Selected point": a.selected_point_id or "none eligible",
                "Data-loss exposure": fmt_minutes(a.data_loss_minutes, "not bounded"),
                "RPO": fmt_minutes(a.rpo_minutes, "undocumented"), "RPO status": _status(a.rpo_status.value),
                "Isolation": a.isolation.value, "Last restore test": fmt_ts(a.last_restore_test_at, "never"),
                "Restore duration": fmt_minutes(a.restore_duration_minutes),
                "Duration basis": a.restore_duration_basis or "unknown",
            }
        )  # fmt: skip
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    # segmented control instead of st.tabs: only the visible view renders, so grids and
    # charts always measure correctly and the choice survives reruns
    view = st.segmented_control("View", ["Recovery points (last 3 days)", "RPO exposure"],
                                default="Recovery points (last 3 days)", key="bh_view")  # fmt: skip
    if view != "RPO exposure":
        st.plotly_chart(charts.recovery_points_chart(r), width="stretch")
        st.caption("◆ isolated vault · ● primary vault. Hover for eligibility reasons.")
    else:
        st.plotly_chart(charts.rpo_exposure_chart(r), width="stretch")
    st.subheader("Recovery point drill-down")
    aid = st.selectbox("System", [a.asset_id for a in r.assets], key="bh_asset", format_func=lambda i: r.asset(i).name)
    x = r.asset(aid)
    if not x.points:
        st.warning("This system has no recovery points.")
    else:
        pts = [
            {
                "Recovery point": p.recovery_point_id, "Created": fmt_ts(p.created_at),
                "Eligible": "✅" if p.eligible else "❌", "Why not": "; ".join(p.reasons) or "—",
                "Repository": p.repository_id, "Reported integrity": p.reported_integrity.value,
                "Effective integrity": p.effective_integrity.value, "Restore test": p.effective_restore_test.value,
                "Protection": p.protection,
                "Evidence": ", ".join(p.evidence_ids) or "none",
            }
            for p in x.points
        ]  # fmt: skip
        st.dataframe(pd.DataFrame(pts), hide_index=True, width="stretch")


# ---------------------------------------------------------- dependency graph


def dependency_graph() -> None:
    ctx = get_ctx()
    r = ctx.result
    page_header("Recovery Dependency Graph", "Arrows point from a dependency to the system that needs it.", _chips(ctx))
    _scenario_banner(ctx)
    ids = [a.asset_id for a in r.assets]
    c1, c2 = st.columns([2, 3])
    target = c1.selectbox(
        "Impact analysis — what if this system were unavailable?", ["(none)", *ids], key="dg_focus",
        format_func=lambda i: i if i == "(none)" else f"{i} — {r.asset(i).name}",
    )  # fmt: skip
    g = build_graph(ctx.inventory.assets)
    if target != "(none)":
        impacted = sorted(descendants(g, [target]))
        weight = sum(r.asset(i).criticality.weight for i in impacted if i in ids)
        c2.html(
            card(
                f"Impact if {target} is unavailable", f"{len(impacted)} dependent systems",
                f"criticality-weighted impact {weight} · " + (", ".join(impacted) or "no dependents"),
                accent="#ef4444" if impacted else "#22c55e",
            )
        )  # fmt: skip
        highlight = set(impacted) | {target}
    else:
        c2.caption(
            "🟢 operational · 🟡 impacted via dependency · 🟠 down (restorable) · 🔴 blocked / cycle · ⚪ repository"
        )
        highlight = set()
    st.plotly_chart(charts.dependency_graph(r, highlight, None if target == "(none)" else target), width="stretch")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("**Circular dependencies**")
        if r.graph.cycles:
            for cyc in r.graph.cycles:
                st.error(" → ".join([*cyc, cyc[0]]))
        else:
            st.success("None detected — a valid recovery order exists.")
    with c2:
        st.markdown("**Missing dependencies**")
        if r.graph.missing_dependencies:
            for a, d in r.graph.missing_dependencies:
                st.warning(f"{a} depends on uninventoried '{d}'")
        else:
            st.success("All dependencies resolve to inventoried assets.")
    with c3:
        st.markdown("**Shared critical dependencies**")
        if r.graph.shared_dependencies:
            st.dataframe(
                pd.DataFrame(
                    [{"Asset": s.asset_id, "Critical dependents": s.weighted_dependents,
                      "All dependents": len(s.transitive_dependents)} for s in r.graph.shared_dependencies]
                ),
                hide_index=True, width="stretch",
            )  # fmt: skip
        else:
            st.info("No asset exceeds the shared-dependency threshold.")


# -------------------------------------------------------- scenario simulator


def scenario_simulator() -> None:
    ctx = get_ctx()
    page_header("Scenario Simulator", "Run deterministic incident simulations and compare outcomes.", _chips(ctx))
    if ctx.error:
        st.error(ctx.error)
    options = [BASELINE_ID] + [s.id for s in ctx.scenarios]
    names = {BASELINE_ID: "Baseline — no incident"} | {s.id: f"{s.code} — {s.title}" for s in ctx.scenarios}
    current = st.session_state.get("scenario_id", BASELINE_ID)
    pick = st.selectbox("Scenario", options, index=options.index(current) if current in options else 0,
                        format_func=names.__getitem__, key="sim_pick")  # fmt: skip
    sc = ctx.scenario_by_id(pick)
    b1, b2, b3 = st.columns([1, 1, 4])
    if b1.button("▶ Run scenario", type="primary", disabled=pick == current, key="sim_run"):
        set_scenario(pick, reason="scenario.run")
        st.rerun()
    if b2.button("↺ Reset to baseline", disabled=current == BASELINE_ID, key="sim_reset"):
        set_scenario(BASELINE_ID, reason="scenario.reset")
        st.rerun()
    b3.caption(f"Active: **{names.get(current, current)}**" + ("" if pick == current else " · press Run to activate"))

    if sc:
        c1, c2 = st.columns([3, 2])
        with c1:
            st.html(
                f"<div class='rp-kv'>{sev_badge(sc.severity.value)} &nbsp; {escape(sc.category)} · "
                f"<span class='rp-mono'>{escape(sc.id)}</span>"
                + (f" · variation of {escape(sc.variation_of)}" if sc.variation_of else "")
                + "</div>"
            )
            st.markdown(sc.narrative)
        with c2:
            st.markdown("**Recommended immediate actions**")
            st.markdown("\n".join(f"- {a}" for a in sc.recommended_actions) or "_none_")
        st.markdown("**Injected failures (deterministic, simulated)**")
        st.dataframe(
            pd.DataFrame(
                [{"At": fmt_ts(i.at), "Type": i.type, "Description": i.description,
                  "Targets": ", ".join(getattr(i, "asset_ids", []) or getattr(i, "recovery_point_ids", []) or
                                       [getattr(i, "asset_id", "") or getattr(i, "repository_id", "") or
                                        getattr(i, "role", "")])} for i in sorted(sc.injections, key=lambda i: i.at)]
            ),
            hide_index=True, width="stretch",
        )  # fmt: skip
    else:
        st.markdown(ctx.baseline.scenario_narrative)

    st.divider()
    st.subheader("Before / after comparison")
    cmp_opts = [i for i in options if i != pick]
    # keyed per selection so the comparison always defaults to the baseline for a new pick
    against = st.selectbox("Compare selected scenario against", cmp_opts, format_func=names.__getitem__,
                           key=f"sim_against_{pick}")  # fmt: skip
    after = ctx.analyze_other(pick)
    before = ctx.analyze_other(against)
    diff = compare(before, after)
    mrows = []
    for d in diff.metrics:
        arrow = "" if d.worse is None else ("🔻 worse" if d.worse else "🔺 better")
        mrows.append({"Metric": d.label, names[against]: d.before, names[pick]: d.after, "Change": arrow or "—"})
    st.dataframe(pd.DataFrame(mrows), hide_index=True, width="stretch")
    if diff.scope_note:
        st.caption("ℹ️ " + diff.scope_note)
    st.markdown(f"**Per-system changes** ({len(diff.asset_changes)})")
    if diff.asset_changes:
        st.dataframe(
            pd.DataFrame([{"System": c.name, "Field": c.field, "Before": c.before, "After": c.after}
                          for c in diff.asset_changes]),
            hide_index=True, width="stretch", height=min(400, 38 + 35 * len(diff.asset_changes)),
        )  # fmt: skip
    else:
        st.info("No per-system differences.")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"**New findings** ({len(diff.new_findings)})")
        st.code("\n".join(diff.new_findings) or "none", language=None)
    with c2:
        st.markdown(f"**Cleared findings** ({len(diff.cleared_findings)})")
        st.code("\n".join(diff.cleared_findings) or "none", language=None)
    if sc:
        st.subheader("Expected vs. actual (regression check)")
        checks = check_expectations(after, sc)
        passed = sum(c.passed for c in checks)
        (st.success if passed == len(checks) else st.error)(f"{passed} / {len(checks)} expectation checks pass")
        st.dataframe(
            pd.DataFrame([{"Check": c.name, "Expected": c.expected, "Actual": c.actual,
                           "Result": "✅ pass" if c.passed else "❌ fail"} for c in checks]),
            hide_index=True, width="stretch",
        )  # fmt: skip


# ----------------------------------------------------------------- timeline


def incident_timeline() -> None:
    ctx = get_ctx()
    r = ctx.result
    page_header("Incident Timeline", "Evidence, recovery points, injected events and the projected recovery.",
                _chips(ctx))  # fmt: skip
    _scenario_banner(ctx)
    kinds_all = ["injection", "incident", "plan", "evidence", "recovery_point"]
    c1, c2 = st.columns([3, 2])
    kinds = c1.multiselect("Event types", kinds_all, default=["injection", "incident", "plan", "evidence"],
                           key="tl_kinds")  # fmt: skip
    asset_filter = c2.selectbox("System", ["(all)", *[a.asset_id for a in r.assets]], key="tl_asset")
    st.plotly_chart(charts.timeline_chart(r, kinds or kinds_all), width="stretch")
    events = [e for e in r.timeline if e.kind in (kinds or kinds_all)]
    if asset_filter != "(all)":
        events = [e for e in events if e.asset_id == asset_filter]
    rows = [
        {"Time (UTC)": fmt_ts(e.at, "—") if e.at else "blocked", "Offset": f"T+{fmt_minutes(e.offset_minutes)}" if
         e.offset_minutes is not None else "", "Type": e.kind, "System": e.asset_id or "", "Event": e.title,
         "Detail": e.detail, "Basis": e.basis.value, "Ref": e.ref_id or ""}
        for e in sorted(events, key=lambda e: (e.at is None, e.at or r.incident_at), reverse=True)  # newest first
    ]  # fmt: skip
    st.caption(f"{len(rows)} events")
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=420)


# --------------------------------------------------------------- recovery plan


def recovery_plan() -> None:
    ctx = get_ctx()
    r, p = ctx.result, ctx.result.plan
    page_header("Recovery Plan", "Dependency-respecting restore order with time estimates.", _chips(ctx))
    _scenario_banner(ctx)
    card_row(
        [
            card("Systems to restore", str(len(p.steps)),
                 "all protected systems" if p.scope == "all" else "taken down"),
            card("Parallel estimate", fmt_minutes(p.parallel_minutes) if p.parallel_minutes is not None else
                 (f"≥ {fmt_minutes(p.parallel_lower_bound_minutes)}" if p.parallel_lower_bound_minutes else "Unknown"),
                 "unlimited restore capacity"),
            card("Serial estimate", fmt_minutes(p.serial_minutes), "one system at a time"),
            card("Blocked steps", str(len(p.blocked_assets)), ", ".join(p.blocked_assets) or "none",
                 accent="#ef4444" if p.blocked_assets else "#22c55e"),
            card("Data-loss exposure", fmt_minutes(r.metrics.max_data_loss_minutes, "n/a"),
                 f"{len(r.metrics.unbounded_data_loss_assets)} with no usable point"
                 if r.metrics.unbounded_data_loss_assets else "max across systems being restored"),
        ]
    )  # fmt: skip
    if p.unknown_duration_assets:
        st.warning(
            f"Restore duration unknown for: {', '.join(p.unknown_duration_assets)} — the total is a lower bound."
        )
    for s in p.steps:
        if s.blocked:
            st.error(f"Step {s.order} · {s.name} is BLOCKED — {s.blocked_reason}")
    if any(not s.blocked for s in p.steps):
        st.plotly_chart(charts.plan_gantt(r), width="stretch")
    rows = [
        {"#": s.order, "Wave": s.wave or "—", "System": s.name, "Tier": s.criticality.value,
         "Prerequisites": ", ".join(s.depends_on) or "—", "Recovery point": s.recovery_point_id or "—",
         "Start": "BLOCKED" if s.blocked else f"T+{fmt_minutes(s.start_minute)}",
         "Ready": "—" if s.blocked else f"T+{fmt_minutes(s.finish_minute)}",
         "Duration basis": s.duration_basis or "unknown", "RTO": fmt_minutes(s.rto_minutes, "undocumented"),
         "RTO status": _status(s.rto_status.value)}
        for s in p.steps
    ]  # fmt: skip
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    with st.expander("Plan assumptions"):
        st.markdown("\n".join(f"- {a}" for a in p.assumptions))


# ------------------------------------------------------------------ findings


def _resolve_form(ctx: Ctx, fid: str) -> None:
    with st.form(f"resolve_{fid}", clear_on_submit=True):
        st.markdown("**Mark resolved (simulation)** — a verification record is required.")
        by = st.text_input("Verified by")
        method = st.text_input("Verification method", placeholder="e.g. restore test into isolated VPC")
        ref = st.text_input("Evidence reference", placeholder="e.g. ticket or evidence id")
        if st.form_submit_button("Record verification and resolve"):
            try:
                rec = VerificationRecord(verified_by=by, method=method, evidence_reference=ref, verified_at=utc_now())
                ctx.tracker.transition(fid, "resolved", verification=rec, scenario_id=ctx.result.scenario_id)
                st.success("Marked resolved with verification record.")
                st.rerun()
            except ValidationError as exc:
                fields = sorted({str(e["loc"][0]).replace("_", " ") for e in exc.errors()})
                st.error(f"Not resolved: complete {', '.join(fields)} (verified by ≥ 2 characters, method ≥ 5, "
                         "evidence reference ≥ 3).")  # fmt: skip
            except RemediationError as exc:
                st.error(f"Not resolved: {str(exc).splitlines()[0][:300]}")


def findings_remediation() -> None:
    ctx = get_ctx()
    r = ctx.result
    page_header("Findings & Remediation", "Every finding is traceable to a rule and its evidence.", _chips(ctx))
    _scenario_banner(ctx)
    counts = r.metrics.findings_by_severity
    card_row(
        [card(s.capitalize(), str(counts.get(s, 0)), "findings", accent=SEVERITY_COLORS[s]) for s in SEVERITIES[:4]]
    )
    c1, c2, c3, c4 = st.columns([2, 2, 2, 1.4])
    sevs = c1.multiselect("Severity", SEVERITIES, default=SEVERITIES, key="fd_sev")
    cats = c2.multiselect("Category", sorted({f.category for f in r.findings}), key="fd_cat")
    q = c3.text_input("Search", placeholder="asset, rule, text", key="fd_q")
    sort = c4.selectbox("Sort by", ["Priority", "Asset", "Rule"], key="fd_sort")
    recs = {x.finding_id: x for x in r.recommendations}
    items = [
        f for f in r.findings
        if f.severity.value in sevs and (not cats or f.category in cats)
        and (not q or q.lower() in f"{f.id} {f.asset_id} {f.asset_name} {f.title} {f.description}".lower())
    ]  # fmt: skip
    if sort == "Asset":
        items.sort(key=lambda f: (f.asset_id, f.severity.rank))
    elif sort == "Rule":
        items.sort(key=lambda f: (f.rule_id, f.asset_id))
    rows = []
    for f in items:
        st_entry = ctx.tracker.status(f.id)
        rows.append(
            {"Priority": recs[f.id].priority, "Severity": f.severity.value, "Finding": f.title, "System": f.asset_name,
             "Rule": f.rule_id, "Basis": f.basis.value, "Status": st_entry.status if st_entry else "open", "ID": f.id}
        )  # fmt: skip
    st.caption(f"{len(rows)} of {len(r.findings)} findings")
    if not rows:
        st.info("No findings match the filters.")
        return
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=min(420, 38 + 35 * len(rows)))

    st.subheader("Finding detail")
    fid = st.selectbox("Finding", [f.id for f in items], key="fd_pick",
                       format_func=lambda i: f"{i} — {r.finding(i).title}")  # fmt: skip
    f, rec = r.finding(fid), recs[fid]
    entry = ctx.tracker.status(fid)
    status = entry.status if entry else "open"
    st.html(
        f'<div class="rp-finding" style="--sev:{SEVERITY_COLORS[f.severity.value]}">'
        f"<h4>{sev_badge(f.severity.value)} &nbsp;{escape(f.title)} — {escape(f.asset_name)}</h4>"
        f"<div class='rp-kv'><span class='rp-mono'>{escape(f.id)}</span> · rule <b>{escape(f.rule_id)}</b> · "
        f"{escape(f.category)} · basis {basis_badge(f.basis.value)} · status <b>{escape(status)}</b></div>"
        f"<p style='margin:.6rem 0 .3rem'>{escape(f.description)}</p>"
        + (f"<div class='rp-kv'><b>Calculation:</b> {escape(f.calculation)}</div>" if f.calculation else "")
        + f"<div class='rp-kv' style='margin-top:.3rem'><b>Business impact:</b> {escape(f.business_impact)}</div>"
        f"<div class='rp-kv' style='margin-top:.3rem'><b>Evidence:</b> "
        f"<span class='rp-mono'>{escape(', '.join(f.evidence_ids) or 'none cited')}</span></div></div>"
    )
    c1, c2 = st.columns([3, 2])
    with c1:
        st.markdown(
            f"**Recommended action:** {rec.action}\n\n**Why:** {rec.reason}\n\n"
            f"**Verification procedure:** {rec.verification_procedure}\n\n**Expected outcome:** {rec.expected_outcome}"
        )
    with c2:
        st.markdown(f"**Remediation status (simulated environment):** `{status}`")
        if entry and entry.verification:
            v = entry.verification
            st.caption(f"Verified by {v.verified_by} on {fmt_ts(v.verified_at)} — {v.method} ({v.evidence_reference})")
            st.info("Marked resolved in the tracker. The finding keeps appearing until the underlying "
                    "evidence changes; a claimed fix is not treated as proof.")  # fmt: skip
        b1, b2 = st.columns(2)
        if status == "open" and b1.button("Acknowledge", key=f"ack_{fid}"):
            ctx.tracker.transition(fid, "acknowledged", scenario_id=r.scenario_id)
            st.rerun()
        if status != "open" and b2.button("Reopen", key=f"reopen_{fid}"):
            ctx.tracker.transition(fid, "open", scenario_id=r.scenario_id)
            st.rerun()
        if status != "resolved":
            _resolve_form(ctx, fid)


# ------------------------------------------------------------------ evidence


def evidence_explorer() -> None:
    ctx = get_ctx()
    r = ctx.result
    page_header("Evidence Explorer", "Inspect why each finding exists and the records behind it.", _chips(ctx))
    _scenario_banner(ctx)
    inv = apply_scenario(ctx.inventory, ctx.scenario).inventory if ctx.scenario else ctx.inventory
    ev_by_id = {e.id: e for e in inv.evidence}
    cited: dict[str, list[str]] = {}
    for f in r.findings:
        for eid in f.evidence_ids:
            cited.setdefault(eid, []).append(f.id)
    view = st.segmented_control("View", ["Trace a finding", "Evidence records", "Audit trail"],
                                default="Trace a finding", key="ev_view")  # fmt: skip
    if view in (None, "Trace a finding"):
        fid = st.selectbox("Finding", [f.id for f in r.findings], key="ev_finding",
                           format_func=lambda i: f"{i} — {r.finding(i).title}")  # fmt: skip
        if fid:
            f = r.finding(fid)
            rule = RULES[f.rule_id]
            c1, c2 = st.columns([2, 3])
            with c1:
                st.markdown(f"**Rule {rule.id} — {rule.title}**\n\n{rule.description}")
                st.markdown(
                    f"**Basis:** {f.basis.value} · **Severity:** {f.severity.value} · **Asset:** {f.asset_name}"
                )
                if f.calculation:
                    st.markdown(f"**Calculation:** {f.calculation}")
                st.caption(f"Analysis version {r.analysis_version} · scenario {r.scenario_id}")
            with c2:
                if not f.evidence_ids:
                    st.info(
                        "No evidence record is cited. This finding is raised because required evidence or "
                        "configuration is *missing* (basis: unknown) or because it is derived from other data."
                    )
                for eid in f.evidence_ids:
                    e = ev_by_id.get(eid)
                    if e is None:
                        continue
                    st.html(
                        f"<div class='rp-card' style='margin-bottom:.5rem'><div class='lbl'>{escape(e.id)} · "
                        f"{escape(e.kind.value)} · result <b>{escape(e.result.value)}</b></div>"
                        f"<div class='rp-kv' style='margin-top:.3rem'>{escape(e.summary)}</div>"
                        f"<div class='rp-kv'>Source: {escape(e.source)} · collected {escape(fmt_ts(e.collected_at))}"
                        f" · origin {escape(e.origin.value)}</div></div>"
                    )
    elif view == "Evidence records":
        c1, c2, c3, c4 = st.columns(4)
        kinds = c1.multiselect("Kind", sorted({e.kind.value for e in inv.evidence}), key="ev_kind")
        results = c2.multiselect("Result", ["pass", "fail", "inconclusive"], key="ev_result")
        origin = c3.selectbox("Origin", ["(all)", "baseline_synthetic", "scenario_injected"], key="ev_origin")
        q = c4.text_input("Search", key="ev_q", placeholder="id, asset, text")
        rows = [
            {"Evidence ID": e.id, "Kind": e.kind.value, "Asset": e.asset_id,
             "Recovery point": e.recovery_point_id or "",
             "Collected": fmt_ts(e.collected_at), "Result": e.result.value, "Origin": e.origin.value,
             "Cited by": ", ".join(cited.get(e.id, [])), "Summary": e.summary}
            for e in sorted(inv.evidence, key=lambda e: e.collected_at, reverse=True)
            if (not kinds or e.kind.value in kinds) and (not results or e.result.value in results)
            and (origin == "(all)" or e.origin.value == origin)
            and (not q or q.lower() in f"{e.id} {e.asset_id} {e.summary}".lower())
        ]  # fmt: skip
        st.caption(f"{len(rows)} of {len(inv.evidence)} evidence records")
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=460)
    else:
        ok, msg = ctx.audit.verify()
        (st.success if ok else st.error)(f"Hash chain: {msg}")
        st.caption(
            "Local, append-only, hash-chained log of simulated actions in this app. Tamper-evident for edits to "
            "earlier entries, but not tamper-proof enterprise audit storage."
        )
        entries = ctx.audit.entries()
        if entries:
            st.dataframe(
                pd.DataFrame([{"#": e.seq, "At": e.at[:19].replace("T", " ") + " UTC", "Action": e.action,
                               "Actor": e.actor, "Details": str(e.details), "Hash": e.hash[:16] + "…"}
                              for e in reversed(entries[-300:])]),
                hide_index=True, width="stretch", height=380,
            )  # fmt: skip
        else:
            st.info("No actions recorded yet. Running scenarios, exporting reports and changing remediation status "
                    "are recorded here.")  # fmt: skip


# ------------------------------------------------------------------- reports


def _log_export(fmt: str) -> None:
    st.session_state["_last_export"] = fmt
    audit_log().append("report.export", {"format": fmt, "scenario_id": st.session_state.get("scenario_id")})


@st.cache_data(show_spinner=False, max_entries=24)
def _render(result_json: str, kind: str) -> bytes:
    res = AnalysisResult.model_validate_json(result_json)
    if kind == "pdf":
        return render_pdf(res)
    text = {"html": render_html, "findings": export_findings_json, "plan": export_plan_json, "full": export_full_json}
    return text[kind](res).encode()


def reports_export() -> None:
    ctx = get_ctx()
    page_header("Reports & Export", "Executive reports and machine-readable exports from the same analysis.",
                _chips(ctx))  # fmt: skip
    _scenario_banner(ctx)
    stamp = st.session_state.setdefault("report_stamp", utc_now().replace(microsecond=0).isoformat())
    if st.button("Regenerate with current timestamp", key="rep_regen"):
        st.session_state.report_stamp = utc_now().replace(microsecond=0).isoformat()
        st.rerun()
    result = ctx.result.model_copy(update={"generated_at": datetime.fromisoformat(stamp).astimezone(UTC)})
    rj = result.model_dump_json()
    base = f"recoveryproof-{result.scenario_code.lower()}-{result.incident_at:%Y%m%d}"
    st.caption(
        f"Report generation timestamp: {fmt_ts(result.generated_at)} · analysis version {result.analysis_version}"
    )
    c = st.columns(5)
    c[0].download_button("⬇ HTML report", _render(rj, "html"), f"{base}.html", "text/html", key="dl_html",
                         on_click=_log_export, args=("html",), width="stretch")  # fmt: skip
    c[1].download_button("⬇ PDF report", _render(rj, "pdf"), f"{base}.pdf", "application/pdf", key="dl_pdf",
                         on_click=_log_export, args=("pdf",), width="stretch")  # fmt: skip
    c[2].download_button("⬇ Findings JSON", _render(rj, "findings"), f"{base}-findings.json", "application/json",
                         key="dl_findings", on_click=_log_export, args=("findings-json",), width="stretch")  # fmt: skip
    c[3].download_button("⬇ Recovery plan JSON", _render(rj, "plan"), f"{base}-plan.json", "application/json",
                         key="dl_plan", on_click=_log_export, args=("plan-json",), width="stretch")  # fmt: skip
    c[4].download_button("⬇ Full analysis JSON", _render(rj, "full"), f"{base}-analysis.json", "application/json",
                         key="dl_full", on_click=_log_export, args=("full-json",), width="stretch")  # fmt: skip
    st.subheader("Report preview")
    components.html(_render(rj, "html").decode(), height=900, scrolling=True)


# --------------------------------------------------------------- methodology


def methodology() -> None:
    ctx = get_ctx()
    page_header("Methodology & Assumptions", "How every number on this dashboard is produced.", _chips(ctx))
    st.markdown(
        """
### RTO and RPO
- **RTO (Recovery Time Objective)** — the maximum acceptable time to restore a service. RecoveryProof
  compares it with the *estimated ready time*: the time to wait for prerequisites plus the restore duration.
- **RPO (Recovery Point Objective)** — the maximum acceptable data loss, expressed as time. RecoveryProof
  compares it with *data-loss exposure* = incident time − newest **eligible** recovery point.

### What counts as recoverable
A recovery point is eligible only when (1) an evidence record shows a passing **integrity check**,
(2) its repository is reachable, (3) it was not exposed to a compromised role without **evidenced**
immutability, (4) it predates the incident and any trusted cutoff, and (5) the system has no restore blocker.
A reported "passed" with no evidence is treated as **unknown**. A system is **restore-tested** only if a
passing **end-to-end restore test** exists within the policy window. Integrity checks and restore tests are
kept separate.

### Dependency direction and recovery order
`depends_on` lists what must be available *before* a system can be restored, producing edges
`dependency → dependent`. The plan is a topological order; among ready systems higher criticality and shorter
RTO go first. Cycles and missing dependencies block the affected systems instead of producing a misleading order.
"""
    )
    st.markdown("### Readiness score")
    st.dataframe(
        pd.DataFrame(
            [
                {"Component": "Backup confidence", "Points": SCORE_WEIGHTS["backup"],
                 "How": "restore-tested 1.0 · integrity only 0.6 · unverified 0.2 · none 0"},
                {"Component": "RPO", "Points": SCORE_WEIGHTS["rpo"], "How": "full credit only when exposure ≤ RPO"},
                {"Component": "RTO", "Points": SCORE_WEIGHTS["rto"],
                 "How": "full credit when ready time ≤ RTO in a full-environment rehearsal"},
                {"Component": "Dependencies", "Points": SCORE_WEIGHTS["dependencies"],
                 "How": "no prerequisite blocked, missing or cyclic"},
                {"Component": "Isolation", "Points": SCORE_WEIGHTS["isolation"],
                 "How": "verified isolated copy 1.0 · claimed 0.5 · none 0"},
            ]
        ),
        hide_index=True, width="stretch",
    )  # fmt: skip
    st.markdown(
        "Overall = criticality-weighted mean (tier 0 = 4 … tier 3 = 1). Bands: "
        + ", ".join(f"**{label}** ≥ {t:g}" for t, label in READINESS_BANDS)
        + ". Unknown values earn no credit."
    )
    st.markdown("### Rule catalogue")
    st.dataframe(
        pd.DataFrame(
            [{"Rule": r.id, "Title": r.title, "Category": r.category,
              "Severity (tier 0/1/2/3)": " / ".join(s.value for s in r.severity_by_tier), "Description": r.description}
             for r in RULES.values()]
        ),
        hide_index=True, width="stretch", height=480,
    )  # fmt: skip
    st.markdown("### Evidence basis labels")
    st.html(basis_legend())
    st.markdown("### Assumptions")
    st.markdown("\n".join(f"- {a}" for a in ctx.result.assumptions + ctx.result.plan.assumptions))
    st.markdown("### Organisational policy in force")
    st.json(ctx.policy.model_dump(mode="json"), expanded=False)
    st.markdown(
        "### Limitations\nRecoveryProof is decision support. It does not perform restores, remove ransomware, "
        "revoke credentials or modify any system, and it does not guarantee recovery. Results are only as reliable "
        "as the evidence supplied."
    )
    st.caption(f"Analysis version {ctx.result.analysis_version}")
