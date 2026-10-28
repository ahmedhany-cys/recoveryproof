"""Evidence evaluation, recovery-point eligibility, immutability and isolation."""

from __future__ import annotations

from datetime import timedelta

import pytest

from recoveryproof.backup import (
    EvidenceIndex,
    PointContext,
    assess_points,
    evaluate_check,
    immutability_verified,
    recovery_evidence_level,
    repository_exposure,
)
from recoveryproof.engine import analyze
from recoveryproof.models import CheckStatus, Evidence
from recoveryproof.results import Isolation, RecoveryEvidence
from tests.helpers import T0, asset, ev, inventory, point, repo, verified_point


def _ev(result: str, minutes_before: int = 0) -> Evidence:
    return Evidence.model_validate(
        ev("EV-X-" + str(minutes_before), "db-a", result=result, minutes_before=minutes_before)
    )


class TestEvaluateCheck:
    @pytest.mark.parametrize(
        ("reported", "results", "status", "issue"),
        [
            ("passed", ["pass"], "passed", None),
            ("passed", [], "unknown", "claim_without_evidence"),  # backup existence/claims are not proof
            ("failed", [], "failed", None),
            ("not_run", [], "not_run", None),
            ("unknown", [], "unknown", None),
            ("passed", ["fail"], "failed", "contradiction"),
            ("failed", ["pass"], "unknown", "contradiction"),  # conservative
            ("passed", ["inconclusive"], "unknown", None),
            ("not_run", ["pass"], "passed", None),
            ("passed", ["fail", "pass"], "passed", None),  # latest evidence wins (re-verified)
            ("passed", ["pass", "fail"], "failed", "contradiction"),
        ],
    )
    def test_matrix(self, reported: str, results: list[str], status: str, issue: str | None) -> None:
        evs = [_ev(r, minutes_before=100 - i) for i, r in enumerate(results)]
        out = evaluate_check(CheckStatus(reported), evs)
        assert out.status == CheckStatus(status)
        assert out.issue == issue


class TestImmutability:
    def _inv(self, mode: str, result: str | None, bypass: list[str] | None = None, delete: list[str] | None = None):
        evidence = [ev("EV-IMM", "vault", kind="immutability_config", result=result)] if result else []
        return inventory(
            [repo(immutability=mode, evidence="EV-IMM" if result else None, bypass_roles=bypass, delete_roles=delete)],
            evidence,
        )

    @pytest.mark.parametrize(
        ("mode", "result", "verified"),
        [
            ("compliance", "pass", True),
            ("governance", "pass", True),
            ("compliance", "fail", False),
            ("compliance", None, False),
            ("none", "pass", False),
            ("unknown", "pass", False),
        ],
    )
    def test_immutability_verified(self, mode: str, result: str | None, verified: bool) -> None:
        inv = self._inv(mode, result)
        assert immutability_verified(inv.asset("vault"), EvidenceIndex.build(inv)) is verified

    @pytest.mark.parametrize(
        ("mode", "result", "delete", "bypass", "roles", "expected"),
        [
            ("compliance", "pass", ["backup-admin"], [], {"backup-admin"}, "protected"),
            ("governance", "pass", ["backup-admin"], ["backup-admin"], {"backup-admin"}, "at_risk"),
            ("governance", "pass", ["backup-admin"], ["root"], {"backup-admin"}, "protected"),
            ("compliance", None, ["backup-admin"], [], {"backup-admin"}, "at_risk"),  # claimed, not evidenced
            ("none", None, ["backup-admin"], [], {"backup-admin"}, "at_risk"),
            ("none", None, ["backup-admin"], [], {"someone-else"}, "not_exposed"),
            ("none", None, ["backup-admin"], [], set(), "not_exposed"),
        ],
    )
    def test_exposure(
        self, mode: str, result: str | None, delete: list[str], bypass: list[str], roles: set[str], expected: str
    ) -> None:
        inv = self._inv(mode, result, bypass=bypass, delete=delete)
        assert repository_exposure(inv.asset("vault"), roles, EvidenceIndex.build(inv)) == expected


class TestEligibility:
    def _assess(self, inv, roles=None, trusted_before=None, incident=T0):  # type: ignore[no-untyped-def]
        ctx = PointContext(incident, trusted_before, roles or set())
        return assess_points(inv.asset("db-a"), inv.asset_map(), EvidenceIndex.build(inv), ctx)

    def test_verified_point_is_eligible(self) -> None:
        p, e = verified_point("db-a", "RP-A-1", 30)
        points, issues = self._assess(inventory([repo(), asset("db-a", points=[p])], [e]))
        assert points[0].eligible and points[0].reasons == []
        assert issues == []

    def test_unknown_integrity_is_not_eligible(self) -> None:
        points, issues = self._assess(inventory([repo(), asset("db-a", points=[point("RP-A-1", 30)])]))
        assert not points[0].eligible
        assert "integrity unknown" in points[0].reasons
        assert issues[0][1].issue == "claim_without_evidence"

    def test_failed_restore_test_makes_point_ineligible(self) -> None:
        p, e = verified_point("db-a", "RP-A-1", 30)
        rt = ev("EV-RT", "db-a", kind="restore_test", rp="RP-A-1", result="fail")
        points, _ = self._assess(inventory([repo(), asset("db-a", points=[p])], [e, rt]))
        assert "restore test failed" in points[0].reasons

    def test_point_after_incident_and_cutoff(self) -> None:
        p1, e1 = verified_point("db-a", "RP-A-1", 10)
        p2, e2 = verified_point("db-a", "RP-A-2", 100)
        p3, e3 = verified_point("db-a", "RP-A-3", 300)
        inv = inventory([repo(), asset("db-a", points=[p1, p2, p3])], [e1, e2, e3])
        points, _ = self._assess(inv, trusted_before=T0 - timedelta(minutes=200), incident=T0 - timedelta(minutes=50))
        by = {p.recovery_point_id: p for p in points}
        assert "created after the incident" in by["RP-A-1"].reasons
        assert any("trusted cutoff" in r for r in by["RP-A-2"].reasons)
        assert by["RP-A-3"].eligible

    def test_unavailable_or_missing_repository(self) -> None:
        p, e = verified_point("db-a", "RP-A-1", 30)
        inv = inventory([repo(state="unavailable"), asset("db-a", points=[p])], [e])
        assert "repository 'vault' is unavailable" in self._assess(inv)[0][0].reasons
        p2, e2 = verified_point("db-a", "RP-A-2", 30, repo_id="ghost-vault")
        inv2 = inventory([asset("db-a", points=[p2])], [e2])
        assert "not an inventoried backup repository" in self._assess(inv2)[0][0].reasons[0]

    def test_compromised_role_makes_points_untrusted(self) -> None:
        p, e = verified_point("db-a", "RP-A-1", 30)
        inv = inventory([repo(delete_roles=["backup-admin"]), asset("db-a", points=[p])], [e])
        points, _ = self._assess(inv, roles={"backup-admin"})
        assert points[0].protection == "at_risk" and not points[0].eligible

    def test_restore_blocker(self) -> None:
        p, e = verified_point("db-a", "RP-A-1", 30)
        inv = inventory([repo(), asset("db-a", points=[p], restore_blocker="key destroyed")], [e])
        assert "restore blocked: key destroyed" in self._assess(inv)[0][0].reasons


class TestRecoveryEvidenceLevels:
    def test_levels(self) -> None:
        p, e = verified_point("db-a", "RP-A-1", 30)
        inv = inventory([repo(), asset("db-a", points=[p])], [e])
        points, _ = assess_points(
            inv.asset("db-a"), inv.asset_map(), EvidenceIndex.build(inv), PointContext(T0, None, set())
        )
        assert recovery_evidence_level(points[0], points, True) is RecoveryEvidence.RESTORE_VERIFIED
        assert recovery_evidence_level(points[0], points, False) is RecoveryEvidence.INTEGRITY_ONLY
        assert recovery_evidence_level(None, [], False) is RecoveryEvidence.NONE

    def test_unverified_level_when_only_unknown_integrity(self) -> None:
        inv = inventory([repo(), asset("db-a", points=[point("RP-A-1", 30, integrity="not_run")])])
        x = analyze(inv).asset("db-a")
        assert x.recovery_evidence is RecoveryEvidence.UNVERIFIED
        assert x.backup_confidence == 0.2
        assert x.selected_point_id is None  # unverified points are never selected

    def test_restore_test_older_than_policy_is_not_verified(self) -> None:
        p, e = verified_point("db-a", "RP-A-1", 30)
        old = ev("EV-RT", "db-a", kind="restore_test", result="pass", minutes_before=91 * 1440, measured=40)
        x = analyze(inventory([repo(), asset("db-a", points=[p])], [e, old])).asset("db-a")
        assert x.recovery_evidence is RecoveryEvidence.INTEGRITY_ONLY
        assert x.restore_duration_minutes == 40  # still the best measured duration available
        assert x.restore_duration_basis == "measured (EV-RT)"


class TestIsolation:
    def test_isolation_states(self) -> None:
        p1, e1 = verified_point("db-a", "RP-A-1", 30, repo_id="iso")
        imm = ev("EV-IMM", "iso", kind="immutability_config", result="pass")
        verified = inventory(
            [repo("iso", separate=True, immutability="compliance", evidence="EV-IMM"), asset("db-a", points=[p1])],
            [e1, imm],
        )
        assert analyze(verified).asset("db-a").isolation is Isolation.VERIFIED
        claimed = inventory([repo("iso", separate=True, immutability="compliance"), asset("db-a", points=[p1])], [e1])
        assert analyze(claimed).asset("db-a").isolation is Isolation.CLAIMED
        same_account = inventory([repo("iso", separate=False), asset("db-a", points=[p1])], [e1])
        assert analyze(same_account).asset("db-a").isolation is Isolation.NONE
