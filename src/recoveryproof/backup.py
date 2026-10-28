"""Backup assessment: evidence evaluation and recovery-point eligibility.

Key principle: *a backup existing is not proof it can be recovered*. A point is
only eligible when evidence shows its integrity check passed, it is reachable,
it has not been exposed to a compromised principal without evidenced
immutability, and it predates the incident / trusted cutoff.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal

from recoveryproof.models import (
    Asset,
    AssetState,
    CheckStatus,
    Evidence,
    EvidenceKind,
    EvidenceResult,
    ImmutabilityMode,
    Inventory,
    RecoveryPoint,
    sorted_by_time,
)
from recoveryproof.results import Isolation, PointAssessment, RecoveryEvidence

Protection = Literal["not_exposed", "protected", "at_risk"]


@dataclass
class EvidenceIndex:
    by_id: dict[str, Evidence]
    by_point: dict[str, list[Evidence]]
    by_asset: dict[str, list[Evidence]]

    @classmethod
    def build(cls, inventory: Inventory) -> EvidenceIndex:
        by_point: dict[str, list[Evidence]] = defaultdict(list)
        by_asset: dict[str, list[Evidence]] = defaultdict(list)
        for ev in inventory.evidence:
            by_asset[ev.asset_id].append(ev)
            if ev.recovery_point_id:
                by_point[ev.recovery_point_id].append(ev)
        return cls({e.id: e for e in inventory.evidence}, dict(by_point), dict(by_asset))

    def for_point(self, rp: RecoveryPoint, kind: EvidenceKind) -> list[Evidence]:
        linked = {e.id: e for e in self.by_point.get(rp.id, []) if e.kind is kind}
        for ev_id in rp.evidence_ids:
            ev = self.by_id.get(ev_id)
            if ev is not None and ev.kind is kind:
                linked[ev.id] = ev
        return sorted(linked.values(), key=lambda e: (e.collected_at, e.id))


@dataclass
class CheckOutcome:
    status: CheckStatus
    issue: Literal["claim_without_evidence", "contradiction"] | None
    evidence_ids: list[str] = field(default_factory=list)


_RESULT_TO_STATUS = {
    EvidenceResult.PASS: CheckStatus.PASSED,
    EvidenceResult.FAIL: CheckStatus.FAILED,
    EvidenceResult.INCONCLUSIVE: CheckStatus.UNKNOWN,
}


def evaluate_check(reported: CheckStatus, evidence: list[Evidence]) -> CheckOutcome:
    """Combine a tool-reported status with evidence records, conservatively.

    * The latest evidence record decides the evidenced status.
    * A reported pass with no evidence is downgraded to ``unknown``.
    * A reported failure is trusted even without evidence.
    * A disagreement is a contradiction; the more pessimistic status wins
      (a reported failure contradicted by passing evidence becomes ``unknown``).
    """
    ids = [e.id for e in evidence]
    if not evidence:
        if reported is CheckStatus.PASSED:
            return CheckOutcome(CheckStatus.UNKNOWN, "claim_without_evidence", ids)
        return CheckOutcome(reported, None, ids)
    evidenced = _RESULT_TO_STATUS[evidence[-1].result]
    if reported is CheckStatus.PASSED and evidenced is CheckStatus.FAILED:
        return CheckOutcome(CheckStatus.FAILED, "contradiction", ids)
    if reported is CheckStatus.FAILED and evidenced is CheckStatus.PASSED:
        return CheckOutcome(CheckStatus.UNKNOWN, "contradiction", ids)
    return CheckOutcome(evidenced, None, ids)


def immutability_verified(repo: Asset, index: EvidenceIndex) -> bool:
    cfg = repo.repository
    if cfg is None or cfg.immutability in (ImmutabilityMode.NONE, ImmutabilityMode.UNKNOWN):
        return False
    evs = [index.by_id[e] for e in cfg.immutability_evidence_ids if e in index.by_id]
    evs = [e for e in evs if e.kind is EvidenceKind.IMMUTABILITY_CONFIG]
    if not evs:
        return False
    return max(evs, key=lambda e: (e.collected_at, e.id)).result is EvidenceResult.PASS


def repository_exposure(repo: Asset, roles: set[str], index: EvidenceIndex) -> Protection:
    """Can any compromised role delete/alter points in ``repo``?

    Compliance-mode immutability (evidenced) protects against every role.
    Governance mode only protects against roles that cannot bypass it.
    Missing or unevidenced immutability protects against nobody.
    """
    cfg = repo.repository
    if not roles or cfg is None:
        return "not_exposed"
    reaching = roles & (set(cfg.delete_capable_roles) | set(cfg.governance_bypass_roles))
    if not reaching:
        return "not_exposed"
    if immutability_verified(repo, index):
        if cfg.immutability is ImmutabilityMode.COMPLIANCE:
            return "protected"
        if cfg.immutability is ImmutabilityMode.GOVERNANCE and not (roles & set(cfg.governance_bypass_roles)):
            return "protected"
    return "at_risk"


@dataclass
class PointContext:
    incident_at: datetime
    trusted_before: datetime | None
    compromised_roles: set[str]


def assess_points(
    asset: Asset, assets: dict[str, Asset], index: EvidenceIndex, ctx: PointContext
) -> tuple[list[PointAssessment], list[tuple[str, CheckOutcome, str]]]:
    """Assess every recovery point of ``asset`` (newest first).

    Returns the assessments and a list of evidence issues
    ``(recovery_point_id, outcome, check_name)`` for finding generation.
    """
    if asset.backup is None:
        return [], []
    out: list[PointAssessment] = []
    issues: list[tuple[str, CheckOutcome, str]] = []
    for rp in sorted_by_time(asset.backup.recovery_points):
        integrity = evaluate_check(rp.reported_integrity, index.for_point(rp, EvidenceKind.INTEGRITY_CHECK))
        restore = evaluate_check(rp.reported_restore_test, index.for_point(rp, EvidenceKind.RESTORE_TEST))
        for outcome, name in ((integrity, "integrity check"), (restore, "restore test")):
            if outcome.issue:
                issues.append((rp.id, outcome, name))
        reasons: list[str] = []
        repo = assets.get(rp.repository_id)
        protection: Protection = "not_exposed"
        if repo is None or not repo.is_repository:
            reasons.append(f"repository '{rp.repository_id}' is not an inventoried backup repository")
        else:
            if repo.state is not AssetState.OPERATIONAL:
                reasons.append(f"repository '{repo.id}' is {repo.state.value}")
            protection = repository_exposure(repo, ctx.compromised_roles, index)
            if protection == "at_risk":
                reasons.append("reachable by a compromised role without evidenced immutability (untrusted)")
        if integrity.status is not CheckStatus.PASSED:
            reasons.append(f"integrity {integrity.status.value.replace('_', ' ')}")
        if restore.status is CheckStatus.FAILED:
            reasons.append("restore test failed")
        if rp.created_at > ctx.incident_at:
            reasons.append("created after the incident")
        elif ctx.trusted_before and rp.created_at > ctx.trusted_before:
            reasons.append("created after the trusted cutoff (possible attacker persistence)")
        if asset.restore_blocker:
            reasons.append(f"restore blocked: {asset.restore_blocker}")
        out.append(
            PointAssessment(
                recovery_point_id=rp.id,
                created_at=rp.created_at,
                repository_id=rp.repository_id,
                reported_integrity=rp.reported_integrity,
                effective_integrity=integrity.status,
                effective_restore_test=restore.status,
                protection=protection,
                eligible=not reasons,
                reasons=reasons,
                evidence_ids=sorted(set(integrity.evidence_ids + restore.evidence_ids)),
            )
        )
    return out, issues


@dataclass
class RestoreTestSummary:
    latest: Evidence | None
    latest_passing: Evidence | None
    recent_pass: bool


def restore_test_summary(asset: Asset, index: EvidenceIndex, as_of: datetime, max_age_days: int) -> RestoreTestSummary:
    tests = sorted(
        (e for e in index.by_asset.get(asset.id, []) if e.kind is EvidenceKind.RESTORE_TEST),
        key=lambda e: (e.collected_at, e.id),
    )
    latest = tests[-1] if tests else None
    passing = [e for e in tests if e.result is EvidenceResult.PASS]
    latest_passing = passing[-1] if passing else None
    recent = (
        latest is not None
        and latest.result is EvidenceResult.PASS
        and as_of - latest.collected_at <= timedelta(days=max_age_days)
    )
    return RestoreTestSummary(latest, latest_passing, recent)


def recovery_evidence_level(
    selected: PointAssessment | None, points: list[PointAssessment], recent_restore_pass: bool
) -> RecoveryEvidence:
    if selected is not None:
        return RecoveryEvidence.RESTORE_VERIFIED if recent_restore_pass else RecoveryEvidence.INTEGRITY_ONLY
    # Points whose *only* problem is unknown integrity are worth surfacing, but they
    # still earn no "recoverable" status.
    for p in points:
        if p.reasons and all(r.startswith("integrity unknown") or r.startswith("integrity not run") for r in p.reasons):
            return RecoveryEvidence.UNVERIFIED
    return RecoveryEvidence.NONE


BACKUP_CONFIDENCE = {
    RecoveryEvidence.RESTORE_VERIFIED: 1.0,
    RecoveryEvidence.INTEGRITY_ONLY: 0.6,
    RecoveryEvidence.UNVERIFIED: 0.2,
    RecoveryEvidence.NONE: 0.0,
}


def isolation_status(
    asset: Asset, assets: dict[str, Asset], index: EvidenceIndex, points: list[PointAssessment]
) -> Isolation:
    """``verified`` if a non-failed point lives in a separate-account repository with
    evidenced immutability; ``claimed`` if separate account but immutability is not
    evidenced; otherwise ``none``."""
    status = Isolation.NONE
    for p in points:
        if p.effective_integrity is CheckStatus.FAILED:
            continue
        repo = assets.get(p.repository_id)
        if repo is None or repo.repository is None or not repo.repository.separate_account:
            continue
        if immutability_verified(repo, index):
            return Isolation.VERIFIED
        status = Isolation.CLAIMED
    return status
