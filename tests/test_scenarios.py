"""Scenario regression tests: every scenario's declared outcome, plus exact
figures for the five required scenarios."""

from __future__ import annotations

import pytest

from recoveryproof.compare import check_expectations, compare
from recoveryproof.engine import analyze
from recoveryproof.models import AssetState, Inventory, OrgPolicy, Scenario
from recoveryproof.results import AnalysisResult, Compliance
from recoveryproof.scenarios import ScenarioError, apply_scenario
from tests.conftest import FIXED_NOW

ALL_CODES = list("ABCDEFGHIJ")


@pytest.mark.parametrize("code", ALL_CODES)
def test_declared_expectations_hold(
    code: str, results: dict[str, AnalysisResult], scenarios: dict[str, Scenario]
) -> None:
    failed = [c for c in check_expectations(results[code], scenarios[code]) if not c.passed]
    assert not failed, [f"{c.name}: expected {c.expected}, got {c.actual}" for c in failed]


@pytest.mark.parametrize("code", ALL_CODES)
def test_recovery_order_respects_dependencies(
    code: str, results: dict[str, AnalysisResult], baseline: Inventory
) -> None:
    r = results[code]
    pos = {s.asset_id: s.order for s in r.plan.steps}
    for s in r.plan.steps:
        for dep in baseline.asset(s.asset_id).depends_on:
            if dep in pos:
                assert pos[dep] < pos[s.asset_id], f"{dep} must be restored before {s.asset_id}"
                if not s.blocked:
                    dep_step = next(x for x in r.plan.steps if x.asset_id == dep)
                    assert not dep_step.blocked
                    assert s.start_minute is None or (dep_step.finish_minute or 0) <= s.start_minute


@pytest.mark.parametrize("code", ALL_CODES)
def test_scenarios_are_deterministic(
    code: str,
    baseline: Inventory,
    policy: OrgPolicy,
    scenarios: dict[str, Scenario],
    results: dict[str, AnalysisResult],
) -> None:
    again = analyze(baseline, policy, scenarios[code], generated_at=FIXED_NOW)
    assert again.model_dump() == results[code].model_dump()


def test_applying_scenarios_never_mutates_baseline(baseline: Inventory, scenarios: dict[str, Scenario]) -> None:
    before = baseline.model_dump_json()
    for sc in scenarios.values():
        apply_scenario(baseline, sc)
    assert baseline.model_dump_json() == before


def test_running_one_scenario_does_not_change_another(
    baseline: Inventory, policy: OrgPolicy, scenarios: dict[str, Scenario]
) -> None:
    first = analyze(baseline, policy, scenarios["A"], generated_at=FIXED_NOW).model_dump()
    for code in "BCDE":
        analyze(baseline, policy, scenarios[code], generated_at=FIXED_NOW)
    assert analyze(baseline, policy, scenarios["A"], generated_at=FIXED_NOW).model_dump() == first


def test_finding_ids_unique_and_stable(results: dict[str, AnalysisResult]) -> None:
    for r in results.values():
        ids = [f.id for f in r.findings]
        assert len(ids) == len(set(ids))
        assert all(f.id.startswith(f"F-{f.rule_id}-{f.asset_id}") for f in r.findings)
        assert [rec.finding_id for rec in r.recommendations] == ids
    # The same underlying issue keeps the same id across scenarios.
    assert "F-ISO-001-app-erp" in {f.id for f in results["BL"].findings}
    assert "F-ISO-001-app-erp" in {f.id for f in results["A"].findings}


def test_every_finding_evidence_reference_resolves(
    results: dict[str, AnalysisResult], baseline: Inventory, scenarios: dict[str, Scenario]
) -> None:
    for code, r in results.items():
        inv = apply_scenario(baseline, scenarios[code]).inventory if code != "BL" else baseline
        known = {e.id for e in inv.evidence}
        for f in r.findings:
            assert set(f.evidence_ids) <= known, f"{code}: {f.id} cites unknown evidence"


# ------------------------------------------------------------- baseline


def test_baseline_figures(results: dict[str, AnalysisResult]) -> None:
    r = results["BL"]
    assert r.scenario_id == "SCN-BASELINE"
    assert r.metrics.readiness_score == pytest.approx(85.7)
    assert r.metrics.readiness_band == "Moderate"
    assert r.metrics.business_impact_pct == 0.0
    assert r.plan.scope == "all" and len(r.plan.steps) == 13
    # hr-portal has no restore duration, so the full estimate is honestly unknown
    assert r.metrics.est_recovery_parallel_minutes is None
    assert r.plan.unknown_duration_assets == ["hr-portal"]
    rules = {f.rule_id for f in r.findings}
    assert {"EV-001", "EV-002", "ISO-003", "ACC-001", "RET-001", "ENC-001", "RTO-002", "RTO-003"} <= rules


def test_baseline_unverified_claim_is_not_counted(results: dict[str, AnalysisResult]) -> None:
    siem = results["BL"].asset("logging-siem")
    # newest point is "passed" according to the backup tool but has no evidence
    assert siem.newest_point_id == "RP-SIEM-202610200800-P"
    assert siem.selected_point_id == "RP-SIEM-202610200700-P"
    assert siem.data_loss_minutes == 120 and siem.rpo_status is Compliance.BREACHED


# ------------------------------------------------------------- scenario A


def test_a_ransomware_intact(results: dict[str, AnalysisResult]) -> None:
    r = results["A"]
    assert sorted(s.asset_id for s in r.plan.steps) == sorted(
        ["web-storefront", "app-orders-api", "db-orders", "db-customers", "app-erp", "file-share"]
    )
    steps = {s.asset_id: s for s in r.plan.steps}
    assert steps["db-orders"].finish_minute == 75
    assert steps["app-orders-api"].start_minute == 75 and steps["app-orders-api"].finish_minute == 100
    assert steps["web-storefront"].start_minute == 100 and steps["web-storefront"].finish_minute == 130
    assert steps["file-share"].finish_minute == 1800 and steps["file-share"].duration_basis == "estimated"
    assert r.metrics.est_recovery_parallel_minutes == 1800
    assert r.metrics.max_data_loss_minutes == 480  # file-share daily backup at 01:00
    assert r.asset("db-orders").data_loss_minutes == 15
    assert not r.plan.blocked_assets
    # readiness is a capability measure: intact backups mean no loss of capability
    assert r.metrics.readiness_score == results["BL"].metrics.readiness_score
    assert r.metrics.business_impact_pct == 55.0


# ------------------------------------------------------------- scenario B


def test_b_compromised_backup_admin(results: dict[str, AnalysisResult]) -> None:
    r = results["B"]
    # Isolated compliance-mode copies survive; primary-vault points are untrusted.
    db = r.asset("db-orders")
    assert db.selected_repository_id == "vault-isolated"
    assert db.data_loss_minutes == 480 and db.rpo_gap_minutes == 465
    assert all(p.protection == "at_risk" for p in db.points if p.repository_id == "vault-primary")
    assert all(p.protection == "not_exposed" for p in db.points if p.repository_id == "vault-isolated")
    assert r.asset("app-erp").selected_point_id is None
    titles = [e.title for e in r.timeline if e.kind == "injection"]
    assert "RP-ERP-202610200800-P deleted" in titles
    assert "Deletion of RP-DBORD-202610200100-I blocked" in titles
    acc = r.finding("F-ACC-002-app-erp")
    assert acc.severity.value == "critical" and acc.basis.value == "simulated"
    assert r.finding("F-ACC-002-db-orders").severity.value == "high"  # a protected point remains
    assert r.metrics.readiness_score < results["BL"].metrics.readiness_score - 15


# ------------------------------------------------------------- scenario C


def test_c_stale_database_backup(results: dict[str, AnalysisResult]) -> None:
    r = results["C"]
    db = r.asset("db-orders")
    assert db.selected_point_id == "RP-DBORD-202610190645-P"
    assert db.data_loss_minutes == 26 * 60 + 15  # 2026-10-19 06:45 -> 2026-10-20 09:00
    assert db.rpo_minutes == 15
    assert db.rpo_gap_minutes == 1560  # exceeds RPO by exactly 26 hours
    f = r.finding("F-RP-002-db-orders")
    assert "gap 1 d 2 h" in (f.calculation or "")
    assert set(r.metrics.impacted_assets) == {"db-orders", "app-orders-api", "web-storefront", "app-erp"}
    assert "Orders API Service" in f.business_impact


# ------------------------------------------------------------- scenario D


def test_d_unavailable_dependency(results: dict[str, AnalysisResult]) -> None:
    r = results["D"]
    api = r.asset("app-orders-api")
    assert api.selected_point_id is not None  # its own backup is intact...
    assert api.restore_blocked  # ...but it still cannot return to service
    assert "db-orders" in api.blocked_reasons[0]
    dep = r.finding("F-DEP-003-db-orders")
    assert "app-orders-api" in dep.description and "insufficient" in dep.description
    assert "criticality-weighted impact: 11" in (dep.calculation or "")  # api 4 + storefront 4 + erp 3
    assert r.metrics.est_recovery_parallel_minutes is None
    assert set(r.metrics.impacted_assets) == {"db-orders", "app-orders-api", "web-storefront", "app-erp"}


# ------------------------------------------------------------- scenario E


def test_e_corrupted_newest_point(results: dict[str, AnalysisResult]) -> None:
    before, after = results["BL"].asset("db-customers"), results["E"].asset("db-customers")
    assert before.selected_point_id == "RP-DBCUS-202610200800-P"
    assert after.selected_point_id == "RP-DBCUS-202610200700-P"
    assert after.data_loss_minutes == 120 and after.rpo_gap_minutes == 60
    f = results["E"].finding("F-RP-003-db-customers")
    assert f.basis.value == "simulated"
    assert "+1 h of additional data-loss exposure" in (f.calculation or "")
    assert results["E"].metrics.integrity_failures == results["BL"].metrics.integrity_failures + 1
    diff = compare(results["BL"], results["E"])
    changed = {(c.asset_id, c.field) for c in diff.asset_changes}
    assert ("db-customers", "Selected recovery point") in changed
    assert "F-RP-003-db-customers" in diff.new_findings


# ------------------------------------------------------------- variations


def test_f_dwell_time_excludes_points_after_cutoff(results: dict[str, AnalysisResult]) -> None:
    r = results["F"]
    for a in r.assets:
        if a.selected_point_at is not None:
            assert a.selected_point_at.isoformat() <= "2026-10-20T03:00:00+00:00"


def test_h_identity_restored_first(results: dict[str, AnalysisResult]) -> None:
    assert results["H"].plan.steps[0].asset_id == "idp-core"


def test_j_dependent_impact_without_restore(results: dict[str, AnalysisResult]) -> None:
    r = results["J"]
    hr = r.asset("hr-portal")
    assert hr.state is AssetState.OPERATIONAL and hr.impacted and not hr.in_plan_scope


# ------------------------------------------------------------- errors


def test_scenario_with_unknown_asset_is_rejected(baseline: Inventory, scenarios: dict[str, Scenario]) -> None:
    bad = scenarios["A"].model_copy(deep=True)
    bad.injections[0].asset_ids = ["does-not-exist"]  # type: ignore[union-attr]
    with pytest.raises(ScenarioError, match="unknown assets"):
        apply_scenario(baseline, bad)


def test_scenario_with_unknown_point_is_rejected(baseline: Inventory, scenarios: dict[str, Scenario]) -> None:
    bad = scenarios["E"].model_copy(deep=True)
    bad.injections[1].recovery_point_ids = ["RP-NOPE-1"]  # type: ignore[union-attr]
    with pytest.raises(ScenarioError, match="unknown recovery points"):
        apply_scenario(baseline, bad)


def test_repository_outage_requires_repository(baseline: Inventory, scenarios: dict[str, Scenario]) -> None:
    bad = scenarios["G"].model_copy(deep=True)
    bad.injections[0].repository_id = "db-orders"  # type: ignore[union-attr]
    with pytest.raises(ScenarioError, match="not a backup repository"):
        apply_scenario(baseline, bad)


def test_backup_job_failure_requires_backup(baseline: Inventory, scenarios: dict[str, Scenario]) -> None:
    bad = scenarios["C"].model_copy(deep=True)
    bad.injections[0].asset_id = "aws-s3-exports"  # type: ignore[union-attr]
    with pytest.raises(ScenarioError, match="no backup policy"):
        apply_scenario(baseline, bad)
