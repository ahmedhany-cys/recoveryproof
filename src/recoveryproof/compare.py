"""Before/after comparison between two analysis results and expectation checks."""

from __future__ import annotations

from dataclasses import dataclass, field

from recoveryproof.models import Scenario
from recoveryproof.results import AnalysisResult, Compliance
from recoveryproof.timeutil import fmt_minutes


@dataclass(frozen=True)
class MetricDelta:
    label: str
    before: str
    after: str
    worse: bool | None  # None = not comparable / unchanged


@dataclass(frozen=True)
class AssetChange:
    asset_id: str
    name: str
    field: str
    before: str
    after: str


@dataclass(frozen=True)
class Comparison:
    metrics: list[MetricDelta]
    asset_changes: list[AssetChange]
    new_findings: list[str]
    cleared_findings: list[str]
    # RTO results depend on which systems the plan restores; when the two analyses
    # restore different sets, RTO counts and RTO-001 findings are not comparable.
    scope_note: str | None = None
    not_comparable_findings: list[str] = field(default_factory=list)


def _num(v: float | int | None) -> str:
    return "Unknown" if v is None else (f"{v:g}" if isinstance(v, float) else str(v))


def compare(before: AnalysisResult, after: AnalysisResult) -> Comparison:
    b, a = before.metrics, after.metrics
    scopes_differ = {s.asset_id for s in before.plan.steps} != {s.asset_id for s in after.plan.steps}

    def delta(
        label: str, x: float | None, y: float | None, higher_is_worse: bool, as_duration: bool = False
    ) -> MetricDelta:
        def show(v: float | None) -> str:
            return fmt_minutes(int(v)) if as_duration and v is not None else _num(v)

        worse: bool | None = None
        if x is not None and y is not None and x != y:
            worse = (y > x) if higher_is_worse else (y < x)
        return MetricDelta(label, show(x), show(y), worse)

    metrics = [
        delta("Readiness score", b.readiness_score, a.readiness_score, higher_is_worse=False),
        delta("Restore-tested systems", b.verified_recovery, a.verified_recovery, higher_is_worse=False),
        delta("Stale or missing recovery points", b.stale_or_missing, a.stale_or_missing, higher_is_worse=True),
        delta("Integrity failures", b.integrity_failures, a.integrity_failures, True),
        delta("Unmet RTO (plan steps)", b.rto_unmet, a.rto_unmet, True)
        if not scopes_differ
        else MetricDelta("Unmet RTO (plan steps) — different plan scopes", str(b.rto_unmet), str(a.rto_unmet), None),
        delta("Unmet RPO", b.rpo_unmet, a.rpo_unmet, True),
        delta("Dependency failures", b.dependency_failures, a.dependency_failures, True),
        delta("Business capability impacted (%)", b.business_impact_pct, a.business_impact_pct, True),
        delta("Max data-loss exposure", b.max_data_loss_minutes, a.max_data_loss_minutes, True, as_duration=True),
        delta("Critical findings", b.findings_by_severity["critical"], a.findings_by_severity["critical"], True),
    ]

    changes: list[AssetChange] = []
    for xa in after.assets:
        try:
            xb = before.asset(xa.asset_id)
        except KeyError:
            continue
        pairs = [
            ("State", xb.state.value, xa.state.value),
            ("Selected recovery point", xb.selected_point_id or "none", xa.selected_point_id or "none"),
            ("Data-loss exposure", fmt_minutes(xb.data_loss_minutes), fmt_minutes(xa.data_loss_minutes)),
            ("RPO", xb.rpo_status.value, xa.rpo_status.value),
            ("Recovery evidence", xb.recovery_evidence.label, xa.recovery_evidence.label),
            ("Score", f"{xb.score:g}", f"{xa.score:g}"),
        ]
        for name, x, y in pairs:
            if x != y:
                changes.append(AssetChange(xa.asset_id, xa.name, name, x, y))

    plan_dependent = (
        {f.id for f in [*before.findings, *after.findings] if f.rule_id == "RTO-001"} if scopes_differ else set()
    )
    before_ids = {f.id for f in before.findings} - plan_dependent
    after_ids = {f.id for f in after.findings}
    after_ids -= plan_dependent
    note = None
    if scopes_differ:
        note = (
            f"The two plans restore different sets of systems ({before.plan.scope} vs {after.plan.scope}), so RTO "
            "counts and RTO-001 findings are not compared. Readiness scores remain comparable: their RTO component "
            "always uses a full-environment rehearsal."
        )
    return Comparison(
        metrics,
        changes,
        sorted(after_ids - before_ids),
        sorted(before_ids - after_ids),
        note,
        sorted(plan_dependent),
    )


@dataclass(frozen=True)
class ExpectationCheck:
    name: str
    expected: str
    actual: str
    passed: bool


def check_expectations(result: AnalysisResult, scenario: Scenario) -> list[ExpectationCheck]:
    """Compare an analysis result with the scenario's declared expected outcome."""
    e = scenario.expected
    checks: list[ExpectationCheck] = []
    score = result.metrics.readiness_score
    if e.readiness_min is not None:
        checks.append(
            ExpectationCheck("Readiness ≥ minimum", f"≥ {e.readiness_min:g}", f"{score:g}", score >= e.readiness_min)
        )
    if e.readiness_max is not None:
        checks.append(
            ExpectationCheck("Readiness ≤ maximum", f"≤ {e.readiness_max:g}", f"{score:g}", score <= e.readiness_max)
        )
    blocked = sorted(result.plan.blocked_assets)
    checks.append(
        ExpectationCheck(
            "Blocked recovery steps",
            ", ".join(e.blocked_assets) or "none",
            ", ".join(blocked) or "none",
            blocked == sorted(e.blocked_assets),
        )
    )
    if e.rto_breaches or scenario.plan_scope == "affected":
        rto = sorted(s.asset_id for s in result.plan.steps if s.rto_status is Compliance.BREACHED)
        checks.append(
            ExpectationCheck(
                "RTO breaches",
                ", ".join(e.rto_breaches) or "none",
                ", ".join(rto) or "none",
                rto == sorted(e.rto_breaches),
            )
        )
    if e.rpo_breaches:
        rpo = sorted(x.asset_id for x in result.assets if x.rpo_status is Compliance.BREACHED)
        checks.append(
            ExpectationCheck(
                "RPO breaches", ", ".join(e.rpo_breaches), ", ".join(rpo) or "none", rpo == sorted(e.rpo_breaches)
            )
        )
    rules = {f.rule_id for f in result.findings}
    for r in e.required_rules:
        checks.append(
            ExpectationCheck(f"Finding {r} raised", "present", "present" if r in rules else "absent", r in rules)
        )
    for aid, rp in e.selected_points.items():
        actual = result.asset(aid).selected_point_id
        checks.append(ExpectationCheck(f"Selected point for {aid}", rp or "none", actual or "none", actual == rp))
    order = [s.asset_id for s in result.plan.steps]
    for first, then in e.order_constraints:
        ok = first in order and then in order and order.index(first) < order.index(then)
        checks.append(ExpectationCheck(f"{first} restored before {then}", "yes", "yes" if ok else "no", ok))
    return checks
