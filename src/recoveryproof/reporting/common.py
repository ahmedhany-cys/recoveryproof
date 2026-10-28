"""Shared report content so HTML and PDF say exactly the same things."""

from __future__ import annotations

from dataclasses import dataclass

from recoveryproof.results import AnalysisResult, Compliance
from recoveryproof.timeutil import fmt_minutes, fmt_ts

LIMITATIONS = [
    "RecoveryProof is a decision-support tool. It does not perform, guarantee or replace tested "
    "enterprise backup and recovery.",
    "Conclusions are only as good as the evidence supplied; missing evidence is reported as unknown, never as success.",
    "Time estimates exclude detection, triage, forensic preservation and business validation, and "
    "assume restore capacity as stated in the plan assumptions.",
    "The local audit trail is tamper-evident (hash-chained), not tamper-proof.",
]


@dataclass(frozen=True)
class Kpi:
    label: str
    value: str
    note: str


def recovery_estimate_text(result: AnalysisResult) -> str:
    m, p = result.metrics, result.plan
    if not p.steps:
        return "No systems require restoration"
    if m.est_recovery_parallel_minutes is None and m.est_recovery_lower_bound_minutes is None:
        return "Cannot be estimated: every recovery step is blocked"
    if m.est_recovery_parallel_minutes is None:
        unknown = ", ".join(p.unknown_duration_assets)
        text = f"At least {fmt_minutes(m.est_recovery_lower_bound_minutes)} (durations unknown for: {unknown})"
    else:
        text = fmt_minutes(m.est_recovery_parallel_minutes)
    if p.blocked_assets:
        text += f"; {len(p.blocked_assets)} system(s) cannot be restored"
    return text


def data_loss_text(result: AnalysisResult) -> str:
    m = result.metrics
    base = fmt_minutes(m.max_data_loss_minutes, unknown="None measurable")
    if m.unbounded_data_loss_assets:
        base += f"; no usable recovery point for {', '.join(m.unbounded_data_loss_assets)} (loss not bounded)"
    return base


def kpis(result: AnalysisResult) -> list[Kpi]:
    m = result.metrics
    return [
        Kpi("Recovery readiness", f"{m.readiness_score:g} / 100", m.readiness_band),
        Kpi(
            "Restore-tested systems",
            f"{m.verified_recovery} / {m.assessed_systems}",
            "evidence-backed end-to-end tests",
        ),
        Kpi("Stale or missing recovery points", str(m.stale_or_missing), "RPO breached or no eligible point"),
        Kpi("Integrity failures", str(m.integrity_failures), "recovery points failing verification"),
        Kpi("Unmet RTO", str(m.rto_unmet), f"{m.rto_unknown} unknown"),
        Kpi("Unmet RPO", str(m.rpo_unmet), f"{m.rpo_unknown} unknown"),
        Kpi("Dependency failures", str(m.dependency_failures), "blocked by prerequisites, cycles or gaps"),
        Kpi("Business capability impacted", f"{m.business_impact_pct:g}%", "criticality-weighted"),
    ]


def executive_summary(result: AnalysisResult) -> list[str]:
    m, p = result.metrics, result.plan
    crit = m.findings_by_severity.get("critical", 0)
    high = m.findings_by_severity.get("high", 0)
    lines = [
        f"Recovery readiness is {m.readiness_score:g}/100 ({m.readiness_band}). {m.verified_recovery} of "
        f"{m.assessed_systems} systems have evidence of a recent successful end-to-end restore test.",
        f"The recovery plan covers {len(p.steps)} system(s). "
        f"Estimated time to restore: {recovery_estimate_text(result)}.",
        f"Potential data-loss exposure for systems being restored: {data_loss_text(result)}.",
        f"{crit} critical and {high} high-severity findings were raised. "
        f"{m.rpo_unmet} system(s) would lose more data than their RPO allows; "
        f"{m.rto_unmet} plan step(s) miss their RTO.",
    ]
    if p.blocked_assets:
        lines.append(
            f"Blocked: {', '.join(p.blocked_assets)}. "
            "These cannot be restored with the current evidence and dependencies."
        )
    if m.impacted_assets:
        lines.append(
            f"Systems affected by the incident (directly or through dependencies): {', '.join(m.impacted_assets)}."
        )
    return lines


def unverified_assumptions(result: AnalysisResult) -> list[str]:
    out = []
    for a in result.assets:
        if a.rto_minutes is None or a.rpo_minutes is None:
            out.append(f"{a.name}: RTO/RPO undocumented; compliance not assessed.")
        if a.restore_duration_basis == "estimated":
            out.append(
                f"{a.name}: restore duration {fmt_minutes(a.restore_duration_minutes)} "
                "is an estimate, not a measurement."
            )
        if a.restore_duration_minutes is None:
            out.append(f"{a.name}: restore duration unknown.")
    for s in result.plan.steps:
        if s.rto_status is Compliance.UNKNOWN and not s.blocked:
            out.append(f"{s.name}: ready time cannot be computed (unknown duration upstream or undocumented RTO).")
    return sorted(set(out))


def confidence_statement(result: AnalysisResult) -> str:
    m = result.metrics
    share = m.verified_recovery / m.assessed_systems if m.assessed_systems else 0
    level = "High" if share >= 0.8 else "Moderate" if share >= 0.5 else "Low"
    return (
        f"{level} confidence: {m.verified_recovery}/{m.assessed_systems} systems have restore-tested evidence; "
        f"{m.rpo_unknown} RPO and {m.rto_unknown} RTO values could not be evaluated. Report generated "
        f"{fmt_ts(result.generated_at)} from analysis version {result.analysis_version}."
    )
