"""Score boundaries, metric derivation and individual rules."""

from __future__ import annotations

import pytest

from recoveryproof.engine import READINESS_BANDS, SCORE_WEIGHTS, analyze, band_for
from recoveryproof.models import OrgPolicy, Severity
from recoveryproof.results import AnalysisResult, Compliance, RecoveryEvidence
from recoveryproof.rules import RULES
from tests.helpers import asset, ev, inventory, point, repo, simple_chain, verified_point


def _isolated_perfect_asset() -> tuple[list[dict], list[dict]]:  # type: ignore[type-arg]
    p, e = verified_point("db-a", "RP-A-1", 10, repo_id="iso")
    rt = ev("EV-RT", "db-a", kind="restore_test", result="pass", minutes_before=1440, measured=20)
    imm = ev("EV-IMM", "iso", kind="immutability_config", result="pass")
    assets = [
        repo("iso", separate=True, immutability="compliance", evidence="EV-IMM"),
        asset("db-a", points=[p], rto=60, rpo=60, duration=None),
    ]
    return assets, [e, rt, imm]


class TestScoreBoundaries:
    def test_weights_sum_to_100(self) -> None:
        assert sum(SCORE_WEIGHTS.values()) == 100

    def test_perfect_asset_scores_100(self) -> None:
        r = analyze(inventory(*_isolated_perfect_asset()))
        assert r.asset("db-a").score == 100.0
        assert r.metrics.readiness_score == 100.0 and r.metrics.readiness_band == "Strong"
        assert r.findings == []

    def test_asset_without_any_backup_scores_only_dependency_credit(self) -> None:
        r = analyze(inventory([asset("db-a", backup=False)]))
        x = r.asset("db-a")
        assert x.score_breakdown == {"backup": 0.0, "rpo": 0.0, "rto": 0.0, "dependencies": 15.0, "isolation": 0.0}
        assert x.rpo_status is Compliance.BREACHED and x.data_loss_minutes is None
        assert r.metrics.unbounded_data_loss_assets == ["db-a"]

    def test_unknowns_earn_no_credit(self) -> None:
        r = analyze(inventory([repo(), asset("db-a", rto=None, rpo=None, points=[point("RP-A-1", 10)])]))
        x = r.asset("db-a")
        assert x.rpo_status is Compliance.UNKNOWN
        assert x.score_breakdown["rpo"] == 0 and x.score_breakdown["rto"] == 0
        assert x.score_breakdown["backup"] == pytest.approx(35 * 0.2)

    @pytest.mark.parametrize(
        ("score", "band"),
        [
            (100, "Strong"),
            (90, "Strong"),
            (89.9, "Moderate"),
            (75, "Moderate"),
            (74.9, "Weak"),
            (50, "Weak"),
            (49.9, "Critical"),
            (0, "Critical"),
        ],
    )
    def test_band_boundaries(self, score: float, band: str) -> None:
        assert band_for(score) == band
        assert READINESS_BANDS[-1][0] == 0

    def test_readiness_is_criticality_weighted(self) -> None:
        assets, evidence = _isolated_perfect_asset()
        assets.append(asset("low-b", crit="tier3", backup=False))
        r = analyze(inventory(assets, evidence))
        # tier0 weight 4 at 100, tier3 weight 1 at 15 => (400 + 15) / 5 = 83
        assert r.metrics.readiness_score == 83.0


class TestRpo:
    @pytest.mark.parametrize(
        ("age", "rpo", "status", "gap"), [(59, 60, "met", -1), (60, 60, "met", 0), (61, 60, "breached", 1)]
    )
    def test_rpo_boundary(self, age: int, rpo: int, status: str, gap: int) -> None:
        p, e = verified_point("db-a", "RP-A-1", age)
        x = analyze(inventory([repo(), asset("db-a", rpo=rpo, points=[p])], [e])).asset("db-a")
        assert x.data_loss_minutes == age
        assert x.rpo_status is Compliance(status)
        assert x.rpo_gap_minutes == gap

    def test_rpo_zero_requires_point_at_incident(self) -> None:
        p, e = verified_point("db-a", "RP-A-1", 0)
        assert (
            analyze(inventory([repo(), asset("db-a", rpo=0, points=[p])], [e])).asset("db-a").rpo_status
            is Compliance.MET
        )


class TestRules:
    def _ids(self, r: AnalysisResult) -> set[str]:
        return {f.id for f in r.findings}

    def test_rule_catalogue_consistent(self) -> None:
        for rid, rule in RULES.items():
            assert rule.id == rid
            assert len(rule.severity_by_tier) == 4
            assert rule.action and rule.verification and rule.expected_outcome

    def test_retention_encryption_isolation(self) -> None:
        p, e = verified_point("db-a", "RP-A-1", 10)
        inv = inventory(
            [repo(), asset("db-a", points=[p], retention=7, encrypted=False, sensitivity="restricted")], [e]
        )
        ids = self._ids(analyze(inv, OrgPolicy()))
        assert {"F-RET-001-db-a", "F-ENC-001-db-a", "F-ISO-001-db-a", "F-RP-005-db-a"} <= ids

    def test_encryption_unknown_is_one_level_lower(self) -> None:
        p, e = verified_point("db-a", "RP-A-1", 10)
        off = analyze(inventory([repo(), asset("db-a", points=[p], encrypted=False, sensitivity="restricted")], [e]))
        unk = analyze(inventory([repo(), asset("db-a", points=[p], encrypted=None, sensitivity="restricted")], [e]))
        assert off.finding("F-ENC-001-db-a").severity is Severity.HIGH
        assert unk.finding("F-ENC-001-db-a").severity is Severity.MEDIUM

    def test_restore_test_failure(self) -> None:
        p, e = verified_point("db-a", "RP-A-1", 10)
        rt = ev("EV-RT", "db-a", kind="restore_test", result="fail", minutes_before=60)
        r = analyze(inventory([repo(), asset("db-a", points=[p])], [e, rt]))
        assert "F-RP-006-db-a" in self._ids(r)
        assert "F-RP-005-db-a" not in self._ids(r)

    def test_repository_findings(self) -> None:
        imm = ev("EV-IMM", "vault", kind="immutability_config", result="pass")
        inv = inventory(
            [
                repo(
                    immutability="governance",
                    evidence="EV-IMM",
                    delete_roles=["backup-admin", "dev-team"],
                    bypass_roles=["backup-admin"],
                )
            ],
            [imm],
        )
        ids = self._ids(analyze(inv))
        assert {"F-ISO-003-vault", "F-ACC-001-vault"} <= ids
        unevidenced = inventory([repo(immutability="compliance")])
        assert "F-ISO-002-vault" in self._ids(analyze(unevidenced))

    def test_shared_dependency_without_restore_test(self) -> None:
        assets, evidence = [repo()], []
        p, e = verified_point("core-a", "RP-CORE-1", 5)
        assets.append(asset("core-a", points=[p]))
        evidence.append(e)
        for i in range(3):
            assets.append(asset(f"dep-{i}", deps=["core-a"], backup=False))
        r = analyze(inventory(assets, evidence), OrgPolicy(shared_dependency_threshold=3))
        assert "F-DEP-004-core-a" in self._ids(r)
        assert r.graph.shared_dependencies[0].asset_id == "core-a"

    def test_findings_sorted_by_severity(self, results: dict[str, AnalysisResult]) -> None:
        for r in results.values():
            ranks = [f.severity.rank for f in r.findings]
            assert ranks == sorted(ranks)
            assert [rec.priority for rec in r.recommendations] == list(range(1, len(r.recommendations) + 1))


class TestMetricsDerivation:
    def test_metrics_agree_with_assessments(self, results: dict[str, AnalysisResult]) -> None:
        for r in results.values():
            m = r.metrics
            assert m.assessed_systems == len(r.assets)
            assert m.verified_recovery == sum(
                a.recovery_evidence is RecoveryEvidence.RESTORE_VERIFIED for a in r.assets
            )
            assert m.rpo_unmet == sum(a.rpo_status is Compliance.BREACHED for a in r.assets)
            assert m.rto_unmet == sum(s.rto_status is Compliance.BREACHED for s in r.plan.steps)
            assert sum(m.findings_by_severity.values()) == len(r.findings)
            assert 0 <= m.readiness_score <= 100

    def test_restore_tested_requires_eligible_point(self) -> None:
        inv = simple_chain()
        inv.asset("db-b").restore_blocker = "lost"
        assert analyze(inv).asset("db-b").recovery_evidence is RecoveryEvidence.NONE
