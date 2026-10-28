"""Visual building blocks. Every string interpolated into HTML is escaped,
because inventory data may come from an uploaded (untrusted) file."""

from __future__ import annotations

from html import escape

import streamlit as st

SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#22c55e",
    "info": "#94a3b8",
}
BASIS_COLORS = {"verified": "#22c55e", "simulated": "#a78bfa", "derived": "#38bdf8", "unknown": "#f59e0b"}
STATUS_COLORS = {
    "met": "#22c55e",
    "breached": "#ef4444",
    "unknown": "#f59e0b",
    "not_applicable": "#64748b",
    "operational": "#22c55e",
    "compromised": "#ef4444",
    "unavailable": "#f97316",
    "restore_verified": "#22c55e",
    "integrity_only": "#38bdf8",
    "unverified": "#f59e0b",
    "none": "#ef4444",
}
BAND_COLORS = {"Strong": "#22c55e", "Moderate": "#38bdf8", "Weak": "#f59e0b", "Critical": "#ef4444"}

CSS = """
<style>
:root { --rp-card:#111a2e; --rp-line:#1e2a44; --rp-muted:#94a3b8; --rp-ink:#e2e8f0; }
.block-container { padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1400px; }
h1, h2, h3 { letter-spacing: -0.01em; }
.rp-title { font-size: 1.65rem; font-weight: 700; margin: 0 0 .15rem; color: var(--rp-ink); }
.rp-sub { color: var(--rp-muted); margin-bottom: .9rem; font-size: .95rem; }
.rp-chips { display:flex; flex-wrap:wrap; gap:.4rem; margin:.2rem 0 1rem; }
.rp-chip { border:1px solid var(--rp-line); background:#0f1830; color:#cbd5e1; border-radius:999px;
           padding:.15rem .65rem; font-size:.78rem; white-space:nowrap; }
.rp-chip b { color:#fff; font-weight:600; }
.rp-card { background:var(--rp-card); border:1px solid var(--rp-line); border-radius:12px; padding:.85rem 1rem;
           height:100%; }
.rp-card .lbl { color:var(--rp-muted); font-size:.78rem; text-transform:uppercase; letter-spacing:.05em; }
.rp-card .val { font-size:1.75rem; font-weight:700; color:#fff; line-height:1.25; margin-top:.2rem; }
.rp-card .note { color:var(--rp-muted); font-size:.78rem; margin-top:.15rem; }
.rp-card.accent { border-left:4px solid var(--accent, #3b82f6); }
.rp-badge { display:inline-block; border-radius:6px; padding:.05rem .45rem; font-size:.72rem; font-weight:700;
            text-transform:uppercase; letter-spacing:.04em; color:#0b1220; }
.rp-finding { background:var(--rp-card); border:1px solid var(--rp-line); border-left:4px solid var(--sev);
              border-radius:10px; padding:.8rem 1rem; margin:.4rem 0 .8rem; }
.rp-finding h4 { margin:.1rem 0 .35rem; font-size:1.02rem; color:#fff; }
.rp-kv { color:var(--rp-muted); font-size:.82rem; }
.rp-kv b { color:#cbd5e1; font-weight:600; }
.rp-mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size:.8rem; }
.rp-banner { border:1px solid var(--rp-line); background:#0f1830; border-radius:10px; padding:.6rem .9rem;
             margin-bottom:.9rem; color:#cbd5e1; font-size:.88rem; }
.rp-banner.sim { border-color:#5b4b9a; background:#17142d; }
section[data-testid="stSidebar"] { border-right:1px solid var(--rp-line); }
div[data-testid="stMetricValue"] { font-size:1.5rem; }
</style>
"""


def inject_css() -> None:
    st.html(CSS)


def badge(text: str, color: str) -> str:
    return f'<span class="rp-badge" style="background:{color}">{escape(text)}</span>'


def sev_badge(sev: str) -> str:
    return badge(sev, SEVERITY_COLORS.get(sev, "#94a3b8"))


def basis_badge(basis: str) -> str:
    return badge(basis, BASIS_COLORS.get(basis, "#94a3b8"))


def page_header(title: str, subtitle: str, chips: list[tuple[str, str]] | None = None) -> None:
    chip_html = "".join(f'<span class="rp-chip">{escape(k)} <b>{escape(v)}</b></span>' for k, v in chips or [])
    st.html(
        f'<div class="rp-title">{escape(title)}</div><div class="rp-sub">{escape(subtitle)}</div>'
        f'<div class="rp-chips">{chip_html}</div>'
    )


def card(label: str, value: str, note: str = "", accent: str | None = None) -> str:
    style = f' style="--accent:{accent}"' if accent else ""
    cls = "rp-card accent" if accent else "rp-card"
    return (
        f'<div class="{cls}"{style}><div class="lbl">{escape(label)}</div>'
        f'<div class="val">{escape(value)}</div><div class="note">{escape(note)}</div></div>'
    )


def card_row(cards: list[str]) -> None:
    cols = st.columns(len(cards))
    for col, html in zip(cols, cards, strict=True):
        col.html(html)


def banner(text: str, simulated: bool = False) -> None:
    st.html(f'<div class="rp-banner{" sim" if simulated else ""}">{escape(text)}</div>')


def basis_legend() -> str:
    items = {
        "verified": "backed by an evidence record",
        "simulated": "injected by the active scenario",
        "derived": "calculated estimate",
        "unknown": "required data missing — nothing assumed",
    }
    return " ".join(f"{basis_badge(k)} <span class='rp-kv'>{escape(v)}</span>&nbsp;&nbsp;" for k, v in items.items())
