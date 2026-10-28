"""Plotly figures, themed for the dark dashboard."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta

import networkx as nx
import plotly.graph_objects as go

from recoveryproof.results import AnalysisResult, Compliance
from recoveryproof.timeutil import fmt_minutes, fmt_ts
from recoveryproof.ui.components import BAND_COLORS, BASIS_COLORS, STATUS_COLORS

FONT = {"family": "Inter, -apple-system, Segoe UI, sans-serif", "color": "#cbd5e1", "size": 12}
GRID = "#1e2a44"


def _n(dt: datetime) -> datetime:
    """Plotly renders aware datetimes inconsistently; plot naive UTC instead (all data is UTC)."""
    return dt.astimezone(UTC).replace(tzinfo=None)


def _layout(fig: go.Figure, height: int, **kw: object) -> go.Figure:
    settings: dict[str, object] = {
        "height": height,
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(0,0,0,0)",
        "font": FONT,
        "margin": {"l": 10, "r": 10, "t": 30, "b": 10},
        "hoverlabel": {"bgcolor": "#0f1830", "bordercolor": "#334155", "font": {"color": "#e2e8f0"}},
    }
    fig.update_layout(**(settings | kw))
    return fig


def readiness_gauge(score: float, band: str) -> go.Figure:
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": " / 100", "font": {"size": 34, "color": "#fff"}},
            title={"text": f"Recovery readiness · {band}", "font": {"size": 14, "color": "#94a3b8"}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#475569", "tickfont": {"color": "#64748b"}},
                "bar": {"color": BAND_COLORS.get(band, "#3b82f6"), "thickness": 0.28},
                "bgcolor": "#0f1830",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 50], "color": "#2a1418"},
                    {"range": [50, 75], "color": "#2a2314"},
                    {"range": [75, 90], "color": "#13243a"},
                    {"range": [90, 100], "color": "#11291f"},
                ],
            },
        )
    )
    return _layout(fig, 250, margin={"l": 25, "r": 25, "t": 50, "b": 5})


def score_breakdown(result: AnalysisResult) -> go.Figure:
    comps = ["backup", "rpo", "rto", "dependencies", "isolation"]
    colors = ["#3b82f6", "#22c55e", "#38bdf8", "#a78bfa", "#f59e0b"]
    names = [a.name for a in result.assets]
    fig = go.Figure()
    for comp, color in zip(comps, colors, strict=True):
        fig.add_bar(
            y=names,
            x=[a.score_breakdown[comp] for a in result.assets],
            name=comp.capitalize() if comp != "rpo" and comp != "rto" else comp.upper(),
            orientation="h",
            marker_color=color,
            hovertemplate="%{y}<br>" + comp + ": %{x:.1f}<extra></extra>",
        )
    fig.update_layout(barmode="stack", legend={"orientation": "h", "y": 1.08})
    fig.update_xaxes(range=[0, 100], gridcolor=GRID, title="Score (max 100)")
    fig.update_yaxes(autorange="reversed")
    return _layout(fig, 40 + 28 * len(names))


def dependency_graph(result: AnalysisResult, highlight: set[str] | None = None, focus: str | None = None) -> go.Figure:
    """Layered layout: column = dependency depth, so arrows always point left-to-right
    (dependency -> dependent)."""
    g = nx.DiGraph()
    g.add_nodes_from(result.graph.nodes)
    g.add_edges_from(result.graph.edges)
    assets = {a.asset_id: a for a in result.assets}
    steps = {s.asset_id: s for s in result.plan.steps}
    cyc = {n for c in result.graph.cycles for n in c}
    depth: dict[str, int] = {}
    if nx.is_directed_acyclic_graph(g):
        for n in nx.topological_sort(g):
            preds = list(g.predecessors(n))
            depth[n] = 1 + max((depth[p] for p in preds), default=-1)
    else:
        depth = dict.fromkeys(g.nodes, 0)
    # repositories sit in their own column on the far left
    for n in g.nodes:
        if n not in assets:
            depth[n] = -1
    cols: dict[int, list[str]] = defaultdict(list)
    for n in sorted(g.nodes):
        cols[depth[n]].append(n)
    pos: dict[str, tuple[float, float]] = {}
    for d, nodes in cols.items():
        for i, n in enumerate(sorted(nodes)):
            pos[n] = (float(d), (len(nodes) - 1) / 2 - i)

    highlight = highlight or set()
    fig = go.Figure()
    for u, v in g.edges:
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        hot = u in highlight | ({focus} if focus else set()) and v in highlight
        fig.add_annotation(
            x=x1, y=y1, ax=x0, ay=y0, xref="x", yref="y", axref="x", ayref="y", showarrow=True,
            arrowhead=3, arrowsize=1.2, arrowwidth=2.2 if hot else 1.2, standoff=16, startstandoff=14,
            arrowcolor="#ef4444" if hot else "#475569",
        )  # fmt: skip
    xs, ys, colors, sizes, texts, hovers, lines = [], [], [], [], [], [], []
    for n in g.nodes:
        x, y = pos[n]
        a = assets.get(n)
        s = steps.get(n)
        if a is None:
            color, label, hover = "#64748b", n, f"<b>{n}</b><br>backup repository (restore source)"
            size = 20
        else:
            if n in cyc or (s and s.blocked):
                color = "#ef4444"
            elif a.state.value != "operational":
                color = "#f97316"
            elif a.impacted:
                color = "#eab308"
            else:
                color = "#22c55e"
            size = 34 - 4 * a.criticality.rank
            label = n
            ready = f"T+{fmt_minutes(s.finish_minute)}" if s and s.finish_minute is not None else "–"
            hover = (
                f"<b>{a.name}</b><br>{a.criticality.label}<br>state: {a.state.value}"
                f"<br>recovery evidence: {a.recovery_evidence.label}<br>estimated ready: {ready}"
                + (f"<br><b>blocked:</b> {s.blocked_reason}" if s and s.blocked else "")
            )
        xs.append(x)
        ys.append(y)
        colors.append(color)
        sizes.append(size)
        texts.append(label)
        hovers.append(hover)
        lines.append(3 if n == focus else (2 if n in highlight else 0))
    fig.add_scatter(
        x=xs, y=ys, mode="markers+text", text=texts, textposition="bottom center",
        textfont={"size": 11, "color": "#e2e8f0"}, hovertext=hovers, hoverinfo="text",
        marker={"color": colors, "size": sizes, "line": {"color": "#fff", "width": lines}}, showlegend=False,
    )  # fmt: skip
    fig.update_xaxes(visible=False, range=[min(depth.values()) - 0.6, max(depth.values()) + 0.6])
    fig.update_yaxes(visible=False)
    height = max(420, 95 * max(len(v) for v in cols.values()))
    return _layout(fig, height)


def plan_gantt(result: AnalysisResult) -> go.Figure:
    steps = [s for s in result.plan.steps if not s.blocked and s.start_minute is not None]
    fig = go.Figure()
    for s in steps:
        dur = s.duration_minutes or 0
        color = STATUS_COLORS.get(s.rto_status.value, "#3b82f6")
        fig.add_bar(
            y=[s.name], x=[dur], base=[s.start_minute], orientation="h", marker_color=color, showlegend=False,
            hovertemplate=(f"<b>{s.name}</b><br>start T+{fmt_minutes(s.start_minute)}<br>ready T+"
                           f"{fmt_minutes(s.finish_minute)}<br>RTO {fmt_minutes(s.rto_minutes, 'undocumented')}"
                           f" ({s.rto_status.value})<extra></extra>"),
        )  # fmt: skip
        if s.rto_minutes:
            fig.add_scatter(
                x=[s.rto_minutes], y=[s.name], mode="markers", showlegend=False,
                marker={"symbol": "line-ns-open", "size": 22, "color": "#f8fafc", "line": {"width": 2}},
                hovertemplate=f"RTO {fmt_minutes(s.rto_minutes)}<extra></extra>",
            )  # fmt: skip
    fig.update_xaxes(title="Minutes after recovery start (T+0) · white tick = RTO", gridcolor=GRID, rangemode="tozero")
    fig.update_yaxes(autorange="reversed")
    return _layout(fig, 60 + 34 * max(len(steps), 1))


def recovery_points_chart(result: AnalysisResult, days: int = 3) -> go.Figure:
    start = result.incident_at - timedelta(days=days)
    groups: dict[str, dict[str, list[object]]] = {}
    for a in result.assets:
        for p in a.points:
            if p.created_at < start:
                continue
            if p.recovery_point_id == a.selected_point_id:
                key = "Selected for recovery"
            elif p.eligible:
                key = "Eligible"
            elif p.effective_integrity.value == "failed":
                key = "Integrity failed"
            elif p.protection == "at_risk":
                key = "Untrusted (exposed to compromised role)"
            else:
                key = "Ineligible / unverified"
            g = groups.setdefault(key, {"x": [], "y": [], "t": [], "sym": []})
            g["x"].append(_n(p.created_at))
            g["y"].append(a.name)
            g["t"].append(f"{p.recovery_point_id}<br>{fmt_ts(p.created_at)}<br>{'; '.join(p.reasons) or 'eligible'}")
            g["sym"].append("diamond" if "isolated" in p.repository_id else "circle")
    colors = {
        "Selected for recovery": "#22c55e", "Eligible": "#38bdf8", "Integrity failed": "#ef4444",
        "Untrusted (exposed to compromised role)": "#a78bfa", "Ineligible / unverified": "#f59e0b",
    }  # fmt: skip
    fig = go.Figure()
    for key, g in groups.items():
        fig.add_scatter(
            x=g["x"], y=g["y"], mode="markers", name=key, hovertext=g["t"], hoverinfo="text",
            marker={"size": 12, "color": colors[key], "symbol": g["sym"], "line": {"width": 1, "color": "#0b1220"}},
        )  # fmt: skip
    fig.add_vline(x=_n(result.incident_at), line_color="#ef4444", line_dash="dash")
    fig.add_annotation(x=_n(result.incident_at), y=1.02, yref="paper", text="incident", showarrow=False,
                       font={"color": "#ef4444"})  # fmt: skip
    fig.update_xaxes(gridcolor=GRID, range=[_n(start), _n(result.incident_at + timedelta(hours=3))])
    fig.update_yaxes(gridcolor=GRID, autorange="reversed")
    fig.update_layout(legend={"orientation": "h", "y": -0.12})
    return _layout(fig, 120 + 30 * len(result.assets))


def timeline_chart(result: AnalysisResult, kinds: list[str]) -> go.Figure:
    lanes = {"evidence": "Evidence", "recovery_point": "Recovery points", "injection": "Injected (simulated)",
             "incident": "Incident", "plan": "Recovery plan (estimated)"}  # fmt: skip
    fig = go.Figure()
    for basis, color in BASIS_COLORS.items():
        ev = [e for e in result.timeline if e.at is not None and e.kind in kinds and e.basis.value == basis]
        if not ev:
            continue
        fig.add_scatter(
            x=[_n(e.at) for e in ev if e.at], y=[lanes[e.kind] for e in ev], mode="markers", name=basis,
            hovertext=[f"<b>{e.title}</b><br>{fmt_ts(e.at)}<br>{e.asset_id or ''}" for e in ev], hoverinfo="text",
            marker={"size": 11, "color": color, "line": {"width": 1, "color": "#0b1220"}},
        )  # fmt: skip
    fig.add_vline(x=_n(result.incident_at), line_color="#ef4444", line_dash="dash")
    t0 = _n(result.incident_at)
    fig.update_xaxes(gridcolor=GRID, range=[t0 - timedelta(days=2), t0 + timedelta(days=1.5)])
    fig.update_yaxes(gridcolor=GRID, categoryorder="array", categoryarray=list(lanes.values()))
    fig.update_layout(legend={"orientation": "h", "y": -0.2, "title": {"text": "basis "}})
    return _layout(fig, 340)


def rpo_exposure_chart(result: AnalysisResult) -> go.Figure:
    rows = [a for a in result.assets if a.rpo_minutes is not None]
    fig = go.Figure()
    fig.add_bar(
        x=[a.name for a in rows], y=[a.rpo_minutes for a in rows], name="RPO (tolerance)", marker_color="#334155",
        hovertemplate="%{x}<br>RPO %{y} min<extra></extra>",
    )  # fmt: skip
    fig.add_bar(
        x=[a.name for a in rows], y=[a.data_loss_minutes or 0 for a in rows], name="Data-loss exposure",
        marker_color=[STATUS_COLORS["breached"] if a.rpo_status is Compliance.BREACHED else STATUS_COLORS["met"]
                      for a in rows],
        hovertext=[fmt_minutes(a.data_loss_minutes, "no eligible point") for a in rows], hoverinfo="x+text",
    )  # fmt: skip
    fig.update_yaxes(type="log", title="minutes (log scale)", gridcolor=GRID)
    fig.update_layout(barmode="group", legend={"orientation": "h", "y": 1.12})
    return _layout(fig, 340)
