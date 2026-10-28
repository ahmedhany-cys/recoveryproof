"""PDF executive report built with fpdf2 (pure Python, no system libraries).

The built-in PDF fonts only cover Latin-1, so text is transliterated by
:func:`_latin1` (e.g. "→" becomes "->"). Content comes from the same helpers as
the HTML report.
"""

from __future__ import annotations

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace

from recoveryproof.reporting.common import (
    LIMITATIONS,
    confidence_statement,
    data_loss_text,
    executive_summary,
    kpis,
    recovery_estimate_text,
    unverified_assumptions,
)
from recoveryproof.results import AnalysisResult
from recoveryproof.timeutil import fmt_minutes, fmt_ts

_TRANSLIT = {
    "→": "->",
    "←": "<-",
    "—": "-",
    "–": "-",
    "−": "-",
    "≤": "<=",
    "≥": ">=",
    "…": "...",
    "·": "-",
    "‘": "'",
    "’": "'",
    "“": '"',
    "”": '"',
    "×": "x",
    "✓": "OK",
    "✗": "X",
    "•": "-",
}
NAVY = (11, 23, 48)
SEV_COLORS = {
    "critical": (185, 28, 28),
    "high": (194, 65, 12),
    "medium": (161, 98, 7),
    "low": (21, 128, 61),
    "info": (71, 85, 105),
}


def _latin1(text: str) -> str:
    for k, v in _TRANSLIT.items():
        text = text.replace(k, v)
    return text.encode("latin-1", "replace").decode("latin-1")


class _Report(FPDF):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self.result = result
        self.set_auto_page_break(auto=True, margin=16)
        self.set_margins(14, 14, 14)
        self.set_title(_latin1(f"RecoveryProof report - {result.scenario_title}"))
        self.set_author("RecoveryProof")
        self.set_creator(f"RecoveryProof {result.analysis_version}")

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "", 8)
        self.set_text_color(100, 116, 139)
        self.cell(
            0,
            6,
            _latin1(f"RecoveryProof - {self.result.scenario_title} - {self.result.scenario_id}"),
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.ln(2)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(100, 116, 139)
        self.cell(
            0,
            6,
            _latin1(
                f"Generated {fmt_ts(self.result.generated_at)} - analysis {self.result.analysis_version}"
                f" - page {self.page_no()}/{{nb}}"
            ),
            align="C",
        )

    # helpers -------------------------------------------------------------
    def h2(self, text: str) -> None:
        self.ln(3)
        self.set_font("Helvetica", "B", 12.5)
        self.set_text_color(*NAVY)
        self.cell(0, 8, _latin1(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(226, 232, 240)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(2)

    def para(self, text: str, size: float = 9.5, style: str = "", color: tuple[int, int, int] = (15, 23, 42)) -> None:
        self.set_font("Helvetica", style, size)
        self.set_text_color(*color)
        self.multi_cell(0, 4.8, _latin1(text), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def bullets(self, items: list[str], size: float = 9.5) -> None:
        for it in items:
            self.set_font("Helvetica", "", size)
            self.set_text_color(15, 23, 42)
            self.multi_cell(0, 4.8, _latin1(f"-  {it}"), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def grid(self, headers: list[str], rows: list[list[str]], widths: tuple[float, ...], size: float = 7.5) -> None:
        self.set_font("Helvetica", "", size)
        self.set_text_color(15, 23, 42)
        # Explicit colours: the cover band leaves the fill colour set to navy, which fpdf2
        # would otherwise reuse for body cells and hide their text.
        self.set_fill_color(255, 255, 255)
        self.set_draw_color(203, 213, 225)
        heading = FontFace(emphasis="BOLD", color=(255, 255, 255), fill_color=NAVY)
        with self.table(
            col_widths=widths,
            text_align="LEFT",
            line_height=3.9,
            first_row_as_headings=True,
            headings_style=heading,
            borders_layout="HORIZONTAL_LINES",
        ) as t:
            t.row([_latin1(h) for h in headers])
            for r in rows:
                t.row([_latin1(c) for c in r])
        self.ln(1)


def render_pdf(result: AnalysisResult) -> bytes:
    pdf = _Report(result)
    pdf.alias_nb_pages()
    pdf.add_page()

    # cover band
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, pdf.w, 46, style="F")
    pdf.set_xy(14, 10)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(147, 197, 253)
    pdf.cell(0, 5, "RECOVERYPROOF - DISASTER RECOVERY READINESS REPORT", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 9, _latin1(result.scenario_title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(203, 213, 225)
    pdf.multi_cell(
        0,
        4.3,
        align="L",
        text=_latin1(
            f"{result.organization} - Scenario {result.scenario_id} - Incident {fmt_ts(result.incident_at)} - "
            f"Data as of {fmt_ts(result.as_of)}\n"
            f"Data source: {result.data_source} - Analysis {result.analysis_version} - "
            f"Generated {fmt_ts(result.generated_at)}"
        ),
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.set_y(52)

    pdf.h2("1. Executive summary")
    pdf.bullets(executive_summary(result))
    pdf.ln(1)
    ks = kpis(result)
    pdf.grid(["Metric", "Value", "Note"], [[k.label, k.value, k.note] for k in ks], (60, 35, 87), size=8.5)

    pdf.h2("2. Incident description")
    pdf.para(result.scenario_narrative)
    inj = [e for e in result.timeline if e.kind == "injection"]
    if inj:
        pdf.ln(1)
        pdf.grid(
            ["Time (UTC)", "Injected condition (simulated)", "Detail"],
            [[fmt_ts(e.at), e.title, e.detail] for e in inj],
            (30, 50, 102),
        )

    pdf.h2("3. Assessment scope and asset impact")
    scope = (
        "all protected systems (full-recovery rehearsal)"
        if result.plan.scope == "all"
        else "systems taken down by the incident"
    )
    pdf.para(
        f"{len(result.assets)} protected systems assessed. Plan scope: {scope}. "
        f"Business capability impacted: {result.metrics.business_impact_pct:g}% (criticality-weighted)."
    )
    impacted = [a for a in result.assets if a.impacted]
    if impacted:
        pdf.grid(
            ["System", "Tier", "State", "Being restored", "Blocked"],
            [
                [
                    a.name,
                    a.criticality.value,
                    a.state.value,
                    "yes" if a.in_plan_scope else "no (dependency)",
                    "; ".join(a.blocked_reasons) if a.restore_blocked else "no",
                ]
                for a in impacted
            ],
            (50, 14, 24, 26, 68),
        )

    pdf.h2("4. Recovery readiness, backup findings and RTO/RPO compliance")
    rows = []
    for a in result.assets:
        ready = (
            f"T+{fmt_minutes(a.estimated_ready_minute)}"
            if a.estimated_ready_minute is not None
            else ("blocked" if a.restore_blocked else "n/a")
        )
        rows.append(
            [
                a.name,
                a.criticality.value,
                a.recovery_evidence.label,
                a.selected_point_id or "none eligible",
                fmt_minutes(a.data_loss_minutes, "not bounded"),
                f"{a.rpo_status.value} ({fmt_minutes(a.rpo_minutes, 'undoc.')})",
                ready,
                f"{a.rto_status.value.replace('_', ' ')} ({fmt_minutes(a.rto_minutes, 'undoc.')})",
                f"{a.score:g}",
            ]
        )
    pdf.grid(
        ["System", "Tier", "Evidence", "Selected point", "Data loss", "RPO", "Ready", "RTO", "Score"],
        rows,
        (30, 10, 19, 33, 16, 22, 15, 26, 11),
        size=6.6,
    )
    pdf.para(
        "Score = criticality-weighted mean of per-system scores: backup confidence 35, RPO 20, RTO in a "
        "full-recovery rehearsal 20, dependencies 15, isolation 10. Unknown values earn no credit.",
        size=7.5,
        color=(71, 85, 105),
    )

    pdf.h2("5. Recovery dependency order")
    serial = f" (serial: {fmt_minutes(result.plan.serial_minutes)})" if result.plan.serial_minutes is not None else ""
    pdf.para(
        f"Estimated recovery time: {recovery_estimate_text(result)}{serial}. "
        f"Potential data-loss exposure: {data_loss_text(result)}.",
        style="B",
    )
    prow = []
    for s in result.plan.steps:
        if s.blocked:
            timing = ["BLOCKED", "", s.blocked_reason or ""]
        else:
            timing = [
                f"T+{fmt_minutes(s.start_minute)}",
                f"T+{fmt_minutes(s.finish_minute)}",
                s.duration_basis or "unknown",
            ]
        prow.append(
            [
                str(s.order),
                str(s.wave or "-"),
                s.name,
                ", ".join(s.depends_on) or "-",
                s.recovery_point_id or "-",
                *timing,
                s.rto_status.value,
            ]
        )
    pdf.grid(
        ["#", "Wave", "System", "Prerequisites", "Recovery point", "Start", "Ready", "Basis", "RTO"],
        prow,
        (6, 9, 30, 30, 33, 14, 14, 30, 16),
        size=6.6,
    )
    pdf.bullets(result.plan.assumptions, size=7.5)

    pdf.h2("6. Findings and remediation recommendations")
    for rec in result.recommendations:
        f = result.finding(rec.finding_id)
        if pdf.get_y() > pdf.h - 60:
            pdf.add_page()
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.set_text_color(*SEV_COLORS[f.severity.value])
        pdf.multi_cell(
            0,
            5,
            _latin1(f"[{f.severity.value.upper()}] {f.title} - {f.asset_name}"),
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        pdf.para(
            f"{f.id} | rule {f.rule_id} | basis: {f.basis.value} | priority {rec.priority}",
            size=7.5,
            color=(100, 116, 139),
        )
        pdf.para(f.description, size=8.5)
        if f.calculation:
            pdf.para(f"Calculation: {f.calculation}", size=8, color=(71, 85, 105))
        pdf.para(f"Business impact: {f.business_impact}", size=8.5)
        pdf.para(
            f"Action: {rec.action}  Verify by: {rec.verification_procedure}  Expected outcome: {rec.expected_outcome}",
            size=8.5,
        )
        if f.evidence_ids:
            pdf.para(f"Evidence: {', '.join(f.evidence_ids)}", size=7.5, color=(71, 85, 105))
        pdf.ln(2)

    pdf.h2("7. Evidence references")
    ev = sorted({e for f in result.findings for e in f.evidence_ids})
    pdf.para(", ".join(ev) or "none", size=7.5)

    pdf.h2("8. Unverified assumptions")
    pdf.bullets(unverified_assumptions(result) + result.assumptions, size=8.5)

    pdf.h2("9. Limitations and confidence")
    pdf.para(confidence_statement(result))
    pdf.bullets(LIMITATIONS, size=8.5)
    return bytes(pdf.output())
