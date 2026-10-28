"""Analysis engine: turns a (simulated) inventory into findings, a plan and metrics.

The engine is pure and deterministic: identical inputs produce identical output,
except for ``generated_at`` which records when a report was produced.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

import networkx as nx

from recoveryproof import ANALYSIS_VERSION
from recoveryproof.backup import (
    BACKUP_CONFIDENCE,
    CheckOutcome,
    EvidenceIndex,
    PointContext,
    RestoreTestSummary,
    assess_points,
    immutability_verified,
    isolation_status,
    recovery_evidence_level,
    restore_test_summary,
)
from recoveryproof.graph import (
    build_graph,
    cycle_blocked_nodes,
    descendants,
    find_cycles,
    missing_dependencies,
    shared_dependencies,
)
from recoveryproof.models import (
    Asset,
    AssetState,
    CheckStatus,
    EvidenceKind,
    EvidenceOrigin,
    EvidenceResult,
    ImmutabilityMode,
    Inventory,
    OrgPolicy,
    Scenario,
    Severity,
)
from recoveryproof.planner import StepInput, build_plan
from recoveryproof.results import (
    AnalysisResult,
    AssetAssessment,
    Basis,
    Compliance,
    Finding,
    GraphAssessment,
    Isolation,
    Metrics,
    PlanStep,
    PointAssessment,
    Recommendation,
    RecoveryEvidence,
    RecoveryPlan,
    SharedDependency,
    TimelineEvent,
)
from recoveryproof.rules import RULES
from recoveryproof.scenarios import SimulationState, apply_scenario, baseline_state
from recoveryproof.timeutil import fmt_minutes, fmt_ts, minutes_between, utc_now

SCORE_WEIGHTS = {"backup": 35.0, "rpo": 20.0, "rto": 20.0, "dependencies": 15.0, "isolation": 10.0}
ISOLATION_CREDIT = {Isolation.VERIFIED: 1.0, Isolation.CLAIMED: 0.5, Isolation.NONE: 0.0}
READINESS_BANDS = [(90.0, "Strong"), (75.0, "Moderate"), (50.0, "Weak"), (0.0, "Critical")]

GENERAL_ASSUMPTIONS = [
    "All infrastructure, backup and evidence data in this analysis is synthetic unless the "
    "data source states otherwise.",
    "A recovery point counts as recoverable only when an evidence record shows a passing "
    "integrity check; reported status without evidence is treated as unknown.",
    "Restore-tested means a passing end-to-end restore test exists within the policy window; "
    "it validates the procedure, not every individual recovery point.",
    "Unknown values earn no score credit and are reported as 'Unknown' rather than assumed.",
    "Data-loss exposure is the time between the incident and the newest eligible recovery "
    "point; transactions in flight and replication lag are not modelled.",
    "All timestamps are UTC.",
]


def band_for(score: float) -> str:
    for threshold, label in READINESS_BANDS:
        if score >= threshold:
            return label
    return "Critical"  # pragma: no cover - unreachable, 0.0 threshold catches all


def _lower(sev: Severity) -> Severity:
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    return order[min(order.index(sev) + 1, len(order) - 2)]


@dataclass
class _Work:
    """Intermediate per-asset results before plan-dependent fields are known."""

    points: list[PointAssessment]
    rts: RestoreTestSummary
    selected: PointAssessment | None
    newest: PointAssessment | None
    level: RecoveryEvidence
    duration: int | None
    basis: str | None
    data_loss: int | None
    rpo_status: Compliance
    rpo_gap: int | None
    own_blocker: str | None
    isolation: Isolation
    issues: list[tuple[str, CheckOutcome, str]]


def analyze(
    inventory: Inventory,
    policy: OrgPolicy | None = None,
    scenario: Scenario | None = None,
    *,
    generated_at: datetime | None = None,
    data_source: str = "Bundled synthetic baseline",
) -> AnalysisResult:
    policy = policy or OrgPolicy()
    state = apply_scenario(inventory, scenario) if scenario else baseline_state(inventory)
    return _analyze_state(state, policy, generated_at or utc_now(), data_source)


def _analyze_state(
    state: SimulationState, policy: OrgPolicy, generated_at: datetime, data_source: str
) -> AnalysisResult:
    inv = state.inventory
    assets = inv.asset_map()
    index = EvidenceIndex.build(inv)
    g = build_graph(inv.assets)
    missing_pairs = missing_dependencies(inv.assets)
    missing: dict[str, list[str]] = {}
    for aid, dep in missing_pairs:
        missing.setdefault(aid, []).append(dep)
    cycles = find_cycles(g)
    cycle_blocked = cycle_blocked_nodes(g, cycles)
    shared = shared_dependencies(g, assets, policy.shared_dependency_threshold)
    protected = [a for a in inv.assets if not a.is_repository]
    pctx = PointContext(state.incident_at, state.trusted_before, state.compromised_roles)

    # ---------------------------------------------------------------- per asset
    work: dict[str, _Work] = {}
    for a in protected:
        points, issues = assess_points(a, assets, index, pctx)
        rts = restore_test_summary(a, index, inv.as_of, policy.restore_test_max_age_days)
        selected = next((p for p in points if p.eligible), None)
        newest = next((p for p in points if p.created_at <= state.incident_at), None)
        duration: int | None = None
        basis: str | None = None
        if rts.latest_passing and rts.latest_passing.measured_minutes:
            duration, basis = rts.latest_passing.measured_minutes, f"measured ({rts.latest_passing.id})"
        elif a.backup and a.backup.restore_duration_minutes:
            duration, basis = a.backup.restore_duration_minutes, a.backup.restore_duration_basis
        data_loss = minutes_between(selected.created_at, state.incident_at) if selected else None
        rpo_gap: int | None = None
        if a.rpo_minutes is None:
            rpo_status = Compliance.UNKNOWN
        elif data_loss is None:
            rpo_status = Compliance.BREACHED
        else:
            rpo_gap = data_loss - a.rpo_minutes
            rpo_status = Compliance.MET if rpo_gap <= 0 else Compliance.BREACHED
        own_blocker: str | None = None
        if a.restore_blocker:
            own_blocker = f"cannot be restored: {a.restore_blocker}"
        elif selected is None:
            own_blocker = "no eligible recovery point"
        work[a.id] = _Work(
            points=points,
            rts=rts,
            selected=selected,
            newest=newest,
            level=recovery_evidence_level(selected, points, rts.recent_pass),
            duration=duration,
            basis=basis,
            data_loss=data_loss,
            rpo_status=rpo_status,
            rpo_gap=rpo_gap,
            own_blocker=own_blocker,
            isolation=isolation_status(a, assets, index, points),
            issues=issues,
        )

    # ------------------------------------------------------------------- plan
    down = sorted(a.id for a in protected if a.state is not AssetState.OPERATIONAL)
    scope = [a.id for a in protected] if state.plan_scope == "all" else down

    def step_input(aid: str) -> StepInput:
        w = work[aid]
        return StepInput(
            asset=assets[aid],
            recovery_point_id=w.selected.recovery_point_id if w.selected else None,
            duration=w.duration,
            duration_basis=w.basis,
            own_blocker=w.own_blocker,
        )

    # Plan uses the graph of protected assets only (repositories are restore sources,
    # not restore targets).
    pg = g.subgraph(a.id for a in protected).copy()
    plan = build_plan(pg, scope, {aid: step_input(aid) for aid in scope}, cycle_blocked, missing, state.plan_scope)
    # Readiness is a capability measure, so RTO credit always comes from a full-environment
    # rehearsal (every protected asset lost at once), independent of which assets this
    # particular scenario took down. Scores are therefore comparable across scenarios.
    all_ids = [a.id for a in protected]
    rehearsal = (
        plan
        if state.plan_scope == "all"
        else build_plan(pg, all_ids, {aid: step_input(aid) for aid in all_ids}, cycle_blocked, missing, "all")
    )
    rehearsal_steps = {s.asset_id: s for s in rehearsal.steps}
    steps = {s.asset_id: s for s in plan.steps}
    impacted = sorted(set(down) | (descendants(pg, down) & {a.id for a in protected}))

    # dependency health independent of plan scope (used for score)
    def deps_ok(aid: str) -> bool:
        if aid in cycle_blocked or missing.get(aid):
            return False
        for anc in descendants(pg.reverse(copy=False), [aid]):
            if missing.get(anc) or anc in cycle_blocked or work[anc].own_blocker:
                return False
        return True

    # ------------------------------------------------------------ assessments
    assessments: list[AssetAssessment] = []
    for a in protected:
        w = work[a.id]
        step = steps.get(a.id)
        if step is not None:
            rto_status, ready = step.rto_status, step.finish_minute
        else:
            rto_status, ready = Compliance.NOT_APPLICABLE, None
        rto_credit = rehearsal_steps[a.id].rto_status is Compliance.MET
        breakdown = {
            "backup": round(SCORE_WEIGHTS["backup"] * BACKUP_CONFIDENCE[w.level], 2),
            "rpo": SCORE_WEIGHTS["rpo"] if w.rpo_status is Compliance.MET else 0.0,
            "rto": SCORE_WEIGHTS["rto"] if rto_credit else 0.0,
            "dependencies": SCORE_WEIGHTS["dependencies"] if deps_ok(a.id) else 0.0,
            "isolation": SCORE_WEIGHTS["isolation"] * ISOLATION_CREDIT[w.isolation],
        }
        assessments.append(
            AssetAssessment(
                asset_id=a.id,
                name=a.name,
                asset_type=a.asset_type.value,
                criticality=a.criticality,
                state=a.state,
                in_plan_scope=step is not None,
                impacted=a.id in impacted,
                rto_minutes=a.rto_minutes,
                rpo_minutes=a.rpo_minutes,
                newest_point_id=w.newest.recovery_point_id if w.newest else None,
                newest_point_at=w.newest.created_at if w.newest else None,
                selected_point_id=w.selected.recovery_point_id if w.selected else None,
                selected_point_at=w.selected.created_at if w.selected else None,
                selected_repository_id=w.selected.repository_id if w.selected else None,
                recovery_evidence=w.level,
                last_restore_test_at=w.rts.latest.collected_at if w.rts.latest else None,
                last_restore_test_evidence=w.rts.latest.id if w.rts.latest else None,
                data_loss_minutes=w.data_loss,
                rpo_status=w.rpo_status,
                rpo_gap_minutes=w.rpo_gap,
                rto_status=rto_status,
                estimated_ready_minute=ready,
                rto_gap_minutes=ready - a.rto_minutes if ready is not None and a.rto_minutes is not None else None,
                restore_duration_minutes=w.duration,
                restore_duration_basis=w.basis,
                restore_blocked=bool(step and step.blocked),
                blocked_reasons=[step.blocked_reason] if step and step.blocked_reason else [],
                isolation=w.isolation,
                backup_confidence=BACKUP_CONFIDENCE[w.level],
                score=round(sum(breakdown.values()), 1),
                score_breakdown=breakdown,
                points=w.points,
            )
        )
    by_id = {x.asset_id: x for x in assessments}

    findings = _findings(
        state, policy, assets, by_id, {k: v.issues for k, v in work.items()}, plan, pg, missing, cycles, shared, index
    )
    recommendations = _recommendations(findings, assets)

    total_w = sum(assets[x.asset_id].criticality.weight for x in assessments)
    readiness = (
        round(sum(x.score * assets[x.asset_id].criticality.weight for x in assessments) / total_w, 1)
        if total_w
        else 0.0
    )
    dependency_failures = (
        {
            s.asset_id
            for s in plan.steps
            if s.blocked and s.blocked_reason and not s.blocked_reason.startswith(("no eligible", "cannot be restored"))
        }
        | set(cycle_blocked)
        | set(missing)
    )
    scope_assess = [x for x in assessments if x.in_plan_scope]
    known_loss = [x.data_loss_minutes for x in scope_assess if x.data_loss_minutes is not None]
    weights_total = sum(assets[x.asset_id].criticality.weight for x in assessments)
    impact_w = sum(assets[i].criticality.weight for i in impacted)
    sev_counts = {s.value: 0 for s in Severity}
    for f in findings:
        sev_counts[f.severity.value] += 1
    metrics = Metrics(
        readiness_score=readiness,
        readiness_band=band_for(readiness),
        critical_systems=sum(1 for x in assessments if x.criticality.rank <= 1),
        assessed_systems=len(assessments),
        verified_recovery=sum(1 for x in assessments if x.recovery_evidence is RecoveryEvidence.RESTORE_VERIFIED),
        stale_or_missing=sum(
            1 for x in assessments if x.selected_point_id is None or x.rpo_status is Compliance.BREACHED
        ),
        integrity_failures=sum(1 for x in assessments for p in x.points if p.effective_integrity is CheckStatus.FAILED),
        rto_unmet=sum(1 for s in plan.steps if s.rto_status is Compliance.BREACHED),
        rto_unknown=sum(1 for s in plan.steps if s.rto_status is Compliance.UNKNOWN),
        rpo_unmet=sum(1 for x in assessments if x.rpo_status is Compliance.BREACHED),
        rpo_unknown=sum(1 for x in assessments if x.rpo_status is Compliance.UNKNOWN),
        dependency_failures=len(dependency_failures),
        est_recovery_parallel_minutes=plan.parallel_minutes,
        est_recovery_lower_bound_minutes=plan.parallel_lower_bound_minutes,
        est_recovery_serial_minutes=plan.serial_minutes,
        max_data_loss_minutes=max(known_loss) if known_loss else None,
        unbounded_data_loss_assets=sorted(x.asset_id for x in scope_assess if x.selected_point_id is None),
        business_impact_pct=round(100.0 * impact_w / weights_total, 1) if weights_total else 0.0,
        impacted_assets=impacted,
        findings_by_severity=sev_counts,
    )
    sc = state.scenario
    return AnalysisResult(
        analysis_version=ANALYSIS_VERSION,
        generated_at=generated_at,
        organization=inv.organization,
        data_source=data_source,
        as_of=inv.as_of,
        incident_at=state.incident_at,
        scenario_id=state.scenario_id,
        scenario_code=sc.code if sc else "BL",
        scenario_title=sc.title if sc else "Baseline readiness (full-environment recovery rehearsal)",
        scenario_narrative=sc.narrative
        if sc
        else (
            "No incident is injected. Every protected asset is assessed as if the whole "
            "environment had to be restored from backup at the inventory's as-of time."
        ),
        scenario_severity=sc.severity if sc else None,
        assets=assessments,
        findings=findings,
        recommendations=recommendations,
        plan=plan,
        graph=GraphAssessment(
            nodes=sorted(g.nodes),
            edges=sorted(g.edges),
            missing_dependencies=missing_pairs,
            cycles=cycles,
            shared_dependencies=shared,
        ),
        metrics=metrics,
        timeline=_timeline(state, assessments, plan, index),
        assumptions=list(GENERAL_ASSUMPTIONS),
    )


# ------------------------------------------------------------------ findings


def _findings(
    state: SimulationState,
    policy: OrgPolicy,
    assets: dict[str, Asset],
    by_id: dict[str, AssetAssessment],
    point_issues: dict[str, list[tuple[str, CheckOutcome, str]]],
    plan: RecoveryPlan,
    pg: nx.DiGraph,
    missing: dict[str, list[str]],
    cycles: list[list[str]],
    shared: list[SharedDependency],
    index: EvidenceIndex,
) -> list[Finding]:
    out: dict[str, Finding] = {}

    def impact_text(asset: Asset, extra: str = "") -> str:
        deps = sorted(nx.descendants(pg, asset.id)) if asset.id in pg else []
        parts = [asset.criticality.label + "."]
        if deps:
            names = ", ".join(assets[d].name for d in deps[:6]) + (" …" if len(deps) > 6 else "")
            parts.append(f"{len(deps)} dependent system(s): {names}.")
        if extra:
            parts.append(extra)
        return " ".join(parts)

    def add(
        rule_id: str,
        asset: Asset,
        description: str,
        basis: Basis,
        *,
        evidence: list[str] | None = None,
        calculation: str | None = None,
        severity: Severity | None = None,
        qualifier: str | None = None,
        impact: str = "",
    ) -> None:
        r = RULES[rule_id]
        fid = f"F-{rule_id}-{asset.id}" + (f"-{qualifier}" if qualifier else "")
        out[fid] = Finding(
            id=fid,
            rule_id=rule_id,
            title=r.title,
            severity=severity or r.severity(asset.criticality),
            category=r.category,
            asset_id=asset.id,
            asset_name=asset.name,
            description=description,
            business_impact=impact_text(asset, impact),
            evidence_ids=sorted(set(evidence or [])),
            calculation=calculation,
            basis=basis,
        )

    steps = {s.asset_id: s for s in plan.steps}
    simulated_ids = {e.id for e in index.by_id.values() if e.origin is EvidenceOrigin.SCENARIO_INJECTED}

    for aid, x in by_id.items():
        a = assets[aid]
        ev_refs = sorted({e for p in x.points for e in p.evidence_ids})
        if a.rto_minutes is None or a.rpo_minutes is None:
            missing_obj = [n for n, v in (("RTO", a.rto_minutes), ("RPO", a.rpo_minutes)) if v is None]
            add("RTO-002", a, f"{' and '.join(missing_obj)} not documented for {a.name}.", Basis.UNKNOWN)
        if a.backup is None:
            add("RP-001", a, f"{a.name} has no backup policy and no recovery points.", Basis.UNKNOWN)
        elif x.selected_point_id is None:
            reasons = (
                "; ".join(f"{p.recovery_point_id}: {', '.join(p.reasons)}" for p in x.points[:4])
                or "no recovery points exist"
            )
            sim = (
                any(p.protection == "at_risk" for p in x.points)
                or a.restore_blocker
                or any(e in simulated_ids for e in ev_refs)
            )
            add(
                "RP-001",
                a,
                f"No eligible recovery point for {a.name}. {reasons}.",
                Basis.SIMULATED if sim else Basis.VERIFIED,
                evidence=ev_refs[:8],
            )
        newest = next((p for p in x.points if p.created_at <= state.incident_at), None)
        if newest:
            if newest.effective_integrity is CheckStatus.FAILED:
                calc = None
                if x.selected_point_at:
                    extra = minutes_between(x.selected_point_at, newest.created_at)
                    calc = (
                        f"Fell back from {newest.recovery_point_id} ({fmt_ts(newest.created_at)}) to "
                        f"{x.selected_point_id} ({fmt_ts(x.selected_point_at)}): +{fmt_minutes(extra)} "
                        "of additional data-loss exposure."
                    )
                add(
                    "RP-003",
                    a,
                    f"Newest recovery point {newest.recovery_point_id} failed integrity verification.",
                    Basis.SIMULATED if set(newest.evidence_ids) & simulated_ids else Basis.VERIFIED,
                    evidence=newest.evidence_ids,
                    calculation=calc,
                )
            elif newest.effective_integrity in (CheckStatus.UNKNOWN, CheckStatus.NOT_RUN):
                add(
                    "RP-004",
                    a,
                    f"Newest recovery point {newest.recovery_point_id} ({fmt_ts(newest.created_at)}) has "
                    f"integrity status '{newest.effective_integrity.value}' and is not counted as recoverable.",
                    Basis.UNKNOWN,
                    evidence=newest.evidence_ids,
                )
        for rp_id, outcome, check in point_issues.get(aid, []):
            if outcome.issue == "claim_without_evidence":
                add(
                    "EV-001",
                    a,
                    f"{rp_id}: backup platform reports the {check} as passed, but no evidence record supports it.",
                    Basis.UNKNOWN,
                    qualifier=rp_id,
                )
            else:
                add(
                    "EV-002",
                    a,
                    f"{rp_id}: reported {check} status contradicts evidence; treated as '{outcome.status.value}'.",
                    Basis.VERIFIED,
                    evidence=outcome.evidence_ids,
                    qualifier=rp_id,
                )
        if x.selected_point_id and x.rpo_status is Compliance.BREACHED and x.rpo_minutes is not None:
            add(
                "RP-002",
                a,
                f"Newest eligible recovery point for {a.name} is {fmt_minutes(x.data_loss_minutes)} old at the "
                f"time of the incident; RPO is {fmt_minutes(x.rpo_minutes)}.",
                Basis.DERIVED,
                calculation=(
                    f"Incident {fmt_ts(state.incident_at)} − eligible point {x.selected_point_id} "
                    f"{fmt_ts(x.selected_point_at)} = {fmt_minutes(x.data_loss_minutes)} exposure; "
                    f"RPO {fmt_minutes(x.rpo_minutes)}; gap {fmt_minutes(x.rpo_gap_minutes)}."
                ),
                impact=(
                    f"Potential data loss of {fmt_minutes(x.data_loss_minutes)} exceeds tolerance by "
                    f"{fmt_minutes(x.rpo_gap_minutes)}."
                ),
            )
        if a.backup is not None:
            rts_ev = x.last_restore_test_evidence
            latest = index.by_id.get(rts_ev) if rts_ev else None
            if latest is not None and latest.result is EvidenceResult.FAIL:
                add(
                    "RP-006",
                    a,
                    f"Most recent restore test ({fmt_ts(latest.collected_at)}) failed: {latest.summary}",
                    Basis.VERIFIED,
                    evidence=[latest.id],
                )
            elif not work_recent_pass(index, aid, state.inventory.as_of, policy.restore_test_max_age_days):
                passing = sorted(
                    (
                        e
                        for e in index.by_asset.get(aid, [])
                        if e.kind is EvidenceKind.RESTORE_TEST and e.result is EvidenceResult.PASS
                    ),
                    key=lambda e: (e.collected_at, e.id),
                )
                if passing:
                    age = (state.inventory.as_of - passing[-1].collected_at).days
                    detail = f"last passing test {fmt_ts(passing[-1].collected_at)}, {age} days before assessment"
                else:
                    detail = "no passing restore test on record"
                add(
                    "RP-005",
                    a,
                    f"No passing end-to-end restore test within {policy.restore_test_max_age_days} days "
                    f"for {a.name} ({detail}).",
                    Basis.VERIFIED if passing else Basis.UNKNOWN,
                    evidence=[passing[-1].id] if passing else [],
                )
            if a.criticality in policy.require_isolated_copy and x.isolation is not Isolation.VERIFIED:
                add(
                    "ISO-001",
                    a,
                    f"{a.criticality.label} assets require an isolated, immutable copy; isolation status is "
                    f"'{x.isolation.value}'.",
                    Basis.VERIFIED if x.isolation is Isolation.NONE else Basis.UNKNOWN,
                )
            if a.data_sensitivity in policy.require_encryption_for and a.backup.encrypted is not True:
                sev = RULES["ENC-001"].severity(a.criticality)
                if a.backup.encrypted is None:
                    sev = _lower(sev)
                state_txt = "not documented" if a.backup.encrypted is None else "disabled"
                add(
                    "ENC-001",
                    a,
                    f"Backup encryption is {state_txt} for {a.data_sensitivity.value} data.",
                    Basis.UNKNOWN if a.backup.encrypted is None else Basis.VERIFIED,
                    severity=sev,
                )
            min_ret = policy.min_retention_days.get(a.criticality)
            if min_ret and a.backup.retention_days < min_ret:
                add(
                    "RET-001",
                    a,
                    f"Retention is {a.backup.retention_days} days; policy minimum for "
                    f"{a.criticality.value} is {min_ret} days.",
                    Basis.VERIFIED,
                    calculation=f"{a.backup.retention_days} d < {min_ret} d required",
                )
            if x.restore_duration_minutes is None:
                add("RTO-003", a, f"No measured or estimated restore duration for {a.name}.", Basis.UNKNOWN)
        exposed = [p for p in x.points if p.protection == "at_risk"]
        if exposed:
            sev = RULES["ACC-002"].severity(a.criticality)
            if x.selected_point_id:
                sev = _lower(sev)
            roles = ", ".join(sorted(state.compromised_roles))
            remaining = (
                f"Newest protected eligible point: {x.selected_point_id} ({fmt_ts(x.selected_point_at)})."
                if x.selected_point_id
                else "No protected recovery point remains."
            )
            add(
                "ACC-002",
                a,
                f"{len(exposed)} recovery point(s) for {a.name} are reachable by compromised role(s) "
                f"[{roles}] without evidenced immutability: "
                f"{', '.join(p.recovery_point_id for p in exposed)}. {remaining}",
                Basis.SIMULATED,
                severity=sev,
                evidence=sorted({e for p in exposed for e in p.evidence_ids})[:8],
            )
        step = steps.get(aid)
        if (
            step
            and not step.blocked
            and step.rto_status is Compliance.BREACHED
            and step.finish_minute is not None
            and step.rto_minutes
        ):
            wait = step.start_minute or 0
            add(
                "RTO-001",
                a,
                f"{a.name} is estimated to be ready at T+{fmt_minutes(step.finish_minute)}, beyond its RTO of "
                f"{fmt_minutes(step.rto_minutes)}.",
                Basis.DERIVED,
                calculation=(
                    f"wait for prerequisites {fmt_minutes(wait)} + restore {fmt_minutes(step.duration_minutes)} "
                    f"({step.duration_basis}) = {fmt_minutes(step.finish_minute)}; "
                    f"RTO {fmt_minutes(step.rto_minutes)}; "
                    f"over by {fmt_minutes(step.finish_minute - step.rto_minutes)}."
                ),
            )
        if missing.get(aid):
            add("DEP-001", a, f"{a.name} depends on uninventoried asset(s): {', '.join(missing[aid])}.", Basis.UNKNOWN)

    # shared dependencies lacking restore verification
    for sd in shared:
        aid = sd.asset_id
        if aid in by_id and by_id[aid].recovery_evidence is not RecoveryEvidence.RESTORE_VERIFIED:
            a = assets[aid]
            add(
                "DEP-004",
                a,
                f"{sd.weighted_dependents} critical system(s) depend on {a.name}, whose recovery evidence "
                f"is '{by_id[aid].recovery_evidence.label}'.",
                Basis.DERIVED,
            )

    for cycle in cycles:
        a = assets[cycle[0]]
        add(
            "DEP-002",
            a,
            "Circular dependency: " + " -> ".join([*cycle, cycle[0]]) + ". No valid recovery order exists "
            "for these assets or anything that depends on them.",
            Basis.VERIFIED,
            qualifier="CYCLE",
        )

    blocked_steps = {s.asset_id: s for s in plan.steps if s.blocked}
    for aid, s in blocked_steps.items():
        if s.blocked_reason and s.blocked_reason.startswith(("no eligible", "cannot be restored")):
            dependents = sorted(nx.descendants(pg, aid))
            if not dependents:
                continue
            blocked_dep = [d for d in dependents if d in blocked_steps]
            intact = [d for d in blocked_dep if by_id[d].selected_point_id]
            a = assets[aid]
            desc = (
                f"{a.name} cannot be restored ({s.blocked_reason}). {len(dependents)} dependent system(s) cannot "
                f"return to service: {', '.join(dependents)}."
            )
            if intact:
                desc += (
                    f" {', '.join(intact)} have intact, eligible backups of their own, but restoring them alone "
                    "is insufficient while this prerequisite is unavailable."
                )
            w = sum(assets[d].criticality.weight for d in dependents)
            add(
                "DEP-003",
                a,
                desc,
                Basis.SIMULATED if a.restore_blocker or state.scenario else Basis.DERIVED,
                calculation=f"Transitive dependents: {len(dependents)}; criticality-weighted impact: {w} "
                f"(tier0=4, tier1=3, tier2=2, tier3=1).",
                evidence=list(a.evidence_refs),
            )

    # repository-level findings
    for repo in assets.values():
        cfg = repo.repository
        if cfg is None:
            continue
        affected = sorted(aid for aid, x in by_id.items() if any(p.repository_id == repo.id for p in x.points))
        if repo.state is not AssetState.OPERATIONAL:
            add(
                "REPO-001",
                repo,
                f"{repo.name} is {repo.state.value}; recovery points for {len(affected)} asset(s) are "
                f"inaccessible: {', '.join(affected)}.",
                Basis.SIMULATED,
            )
        claims_immutability = cfg.immutability in (ImmutabilityMode.GOVERNANCE, ImmutabilityMode.COMPLIANCE)
        if claims_immutability and not immutability_verified(repo, index):
            add(
                "ISO-002",
                repo,
                f"{repo.name} declares {cfg.immutability.value}-mode immutability, but no passing "
                "configuration evidence exists.",
                Basis.UNKNOWN,
                evidence=cfg.immutability_evidence_ids,
            )
        if cfg.immutability is ImmutabilityMode.GOVERNANCE and cfg.governance_bypass_roles:
            add(
                "ISO-003",
                repo,
                f"Governance-mode retention on {repo.name} can be bypassed by: "
                f"{', '.join(cfg.governance_bypass_roles)}.",
                Basis.VERIFIED,
                evidence=cfg.immutability_evidence_ids,
            )
        extra_roles = sorted(set(cfg.delete_capable_roles) - set(policy.approved_backup_delete_roles))
        if extra_roles:
            add(
                "ACC-001",
                repo,
                f"Unapproved role(s) can delete recovery points in {repo.name}: {', '.join(extra_roles)}. "
                f"Approved: {', '.join(policy.approved_backup_delete_roles)}.",
                Basis.VERIFIED,
                evidence=list(repo.evidence_refs),
            )

    return sorted(out.values(), key=lambda f: (f.severity.rank, assets[f.asset_id].criticality.rank, f.rule_id, f.id))


def work_recent_pass(index: EvidenceIndex, asset_id: str, as_of: datetime, max_age_days: int) -> bool:
    tests = sorted(
        (e for e in index.by_asset.get(asset_id, []) if e.kind is EvidenceKind.RESTORE_TEST),
        key=lambda e: (e.collected_at, e.id),
    )
    return (
        bool(tests)
        and tests[-1].result is EvidenceResult.PASS
        and as_of - tests[-1].collected_at <= timedelta(days=max_age_days)
    )


def _recommendations(findings: list[Finding], assets: dict[str, Asset]) -> list[Recommendation]:
    recs = []
    for i, f in enumerate(findings, start=1):
        r = RULES[f.rule_id]
        recs.append(
            Recommendation(
                id="REC-" + f.id[2:],
                finding_id=f.id,
                rule_id=f.rule_id,
                severity=f.severity,
                asset_id=f.asset_id,
                evidence_ids=f.evidence_ids,
                business_impact=f.business_impact,
                action=r.action,
                reason=r.reason,
                verification_procedure=r.verification,
                expected_outcome=r.expected_outcome,
                priority=i,
            )
        )
    return recs


def _timeline(
    state: SimulationState, assessments: list[AssetAssessment], plan: RecoveryPlan, index: EvidenceIndex
) -> list[TimelineEvent]:
    events: list[TimelineEvent] = list(state.events)
    for x in assessments:
        for p in x.points:
            basis = Basis.VERIFIED if p.effective_integrity is CheckStatus.PASSED else Basis.UNKNOWN
            if p.effective_integrity is CheckStatus.FAILED:
                basis = (
                    Basis.SIMULATED
                    if any(
                        index.by_id[e].origin.value == "scenario_injected" for e in p.evidence_ids if e in index.by_id
                    )
                    else Basis.VERIFIED
                )
            status = "eligible" if p.eligible else "ineligible: " + "; ".join(p.reasons)
            events.append(
                TimelineEvent(
                    at=p.created_at,
                    kind="recovery_point",
                    asset_id=x.asset_id,
                    ref_id=p.recovery_point_id,
                    title=f"Recovery point {p.recovery_point_id}",
                    detail=status,
                    basis=basis,
                )
            )
    for ev in index.by_id.values():
        events.append(
            TimelineEvent(
                at=ev.collected_at,
                kind="evidence",
                asset_id=ev.asset_id,
                ref_id=ev.id,
                title=f"{ev.kind.value.replace('_', ' ').capitalize()}: {ev.result.value}",
                detail=ev.summary,
                basis=Basis.SIMULATED if ev.origin.value == "scenario_injected" else Basis.VERIFIED,
            )
        )
    for s in plan.steps:
        _add_plan_event(events, s, state.incident_at)
    return sorted(events, key=lambda e: (e.at is None, e.at or state.incident_at, e.kind, e.ref_id or ""))


def _add_plan_event(events: list[TimelineEvent], s: PlanStep, t0: datetime) -> None:
    if s.blocked:
        events.append(
            TimelineEvent(
                at=None,
                offset_minutes=None,
                kind="plan",
                asset_id=s.asset_id,
                ref_id=f"STEP-{s.order}",
                title=f"Step {s.order}: {s.name} BLOCKED",
                detail=s.blocked_reason or "",
                basis=Basis.DERIVED,
            )
        )
        return
    at = t0 + timedelta(minutes=s.finish_minute) if s.finish_minute is not None else None
    detail = (
        f"Restore from {s.recovery_point_id}; start T+{fmt_minutes(s.start_minute)}, "
        f"ready T+{fmt_minutes(s.finish_minute)} "
        f"(RTO {fmt_minutes(s.rto_minutes, 'undocumented')}: {s.rto_status.value})"
    )
    events.append(
        TimelineEvent(
            at=at,
            offset_minutes=s.finish_minute,
            kind="plan",
            asset_id=s.asset_id,
            ref_id=f"STEP-{s.order}",
            title=f"Step {s.order}: {s.name} ready (estimated)",
            detail=detail,
            basis=Basis.DERIVED,
        )
    )
