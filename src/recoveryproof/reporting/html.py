"""Self-contained HTML executive report (no external assets, prints cleanly)."""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, select_autoescape

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

_env = Environment(
    loader=PackageLoader("recoveryproof", "reporting/templates"),
    autoescape=select_autoescape(["html", "j2"]),  # all data is escaped: inputs are untrusted
    trim_blocks=True,
    lstrip_blocks=True,
)
_env.filters["mins"] = fmt_minutes
_env.filters["ts"] = fmt_ts


def render_html(result: AnalysisResult) -> str:
    template = _env.get_template("report.html.j2")
    return template.render(
        r=result,
        kpis=kpis(result),
        summary=executive_summary(result),
        estimate=recovery_estimate_text(result),
        data_loss=data_loss_text(result),
        unverified=unverified_assumptions(result),
        confidence=confidence_statement(result),
        limitations=LIMITATIONS,
        impacted=[a for a in result.assets if a.impacted],
        evidence_ids=sorted({e for f in result.findings for e in f.evidence_ids}),
    )
