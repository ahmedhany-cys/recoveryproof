"""Scenario simulation: apply injected failures to a copy of the baseline.

Applying a scenario never mutates the baseline inventory. The same baseline and
scenario always produce the same simulated state (no randomness, no wall clock).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from recoveryproof.backup import EvidenceIndex, repository_exposure
from recoveryproof.models import (
    AssetState,
    BackupJobFailure,
    CheckStatus,
    CompromiseAssets,
    CompromisePrincipal,
    CorruptRecoveryPoints,
    DeleteRecoveryPoints,
    Evidence,
    EvidenceKind,
    EvidenceOrigin,
    EvidenceResult,
    Inventory,
    MarkUnrecoverable,
    RepositoryOutage,
    Scenario,
)
from recoveryproof.results import Basis, TimelineEvent

BASELINE_ID = "SCN-BASELINE"


class ScenarioError(ValueError):
    """A scenario references assets or recovery points that do not exist."""


@dataclass
class SimulationState:
    inventory: Inventory
    scenario: Scenario | None
    incident_at: datetime
    trusted_before: datetime | None
    plan_scope: Literal["affected", "all"]
    compromised_roles: set[str] = field(default_factory=set)
    events: list[TimelineEvent] = field(default_factory=list)
    removed_points: dict[str, str] = field(default_factory=dict)

    @property
    def scenario_id(self) -> str:
        return self.scenario.id if self.scenario else BASELINE_ID


def baseline_state(inventory: Inventory) -> SimulationState:
    """No incident: assess recovery of every asset as if the environment were lost
    at the inventory's ``as_of`` time (a full-recovery rehearsal)."""
    return SimulationState(
        inventory=inventory.model_copy(deep=True),
        scenario=None,
        incident_at=inventory.as_of,
        trusted_before=None,
        plan_scope="all",
    )


def apply_scenario(inventory: Inventory, scenario: Scenario) -> SimulationState:
    inv = inventory.model_copy(deep=True)
    assets = inv.asset_map()
    points = {rp.id: (a.id, rp) for a in inv.assets if a.backup for rp in a.backup.recovery_points}
    state = SimulationState(
        inventory=inv,
        scenario=scenario,
        incident_at=scenario.incident_at,
        trusted_before=scenario.trusted_before,
        plan_scope=scenario.plan_scope,
    )
    counter = 0

    def new_evidence(asset_id: str, rp_id: str | None, kind: EvidenceKind, at: datetime, summary: str) -> str:
        nonlocal counter
        counter += 1
        ev_id = f"EV-{scenario.code}-SIM-{counter:02d}"
        inv.evidence.append(
            Evidence(
                id=ev_id,
                kind=kind,
                asset_id=asset_id,
                recovery_point_id=rp_id,
                collected_at=at,
                source=f"Scenario {scenario.code} injection (simulated)",
                summary=summary,
                result=EvidenceResult.FAIL,
                origin=EvidenceOrigin.SCENARIO_INJECTED,
            )
        )
        return ev_id

    def require_assets(ids: list[str]) -> None:
        unknown = sorted(set(ids) - set(assets))
        if unknown:
            raise ScenarioError(f"scenario {scenario.id} references unknown assets: {', '.join(unknown)}")

    def require_points(ids: list[str]) -> None:
        unknown = sorted(set(ids) - set(points))
        if unknown:
            raise ScenarioError(f"scenario {scenario.id} references unknown recovery points: {', '.join(unknown)}")

    def event(at: datetime, title: str, detail: str, asset_id: str | None = None, ref: str | None = None) -> None:
        state.events.append(
            TimelineEvent(
                at=at,
                kind="injection",
                asset_id=asset_id,
                ref_id=ref,
                title=title,
                detail=detail,
                basis=Basis.SIMULATED,
            )
        )

    for inj in sorted(scenario.injections, key=lambda i: i.at):
        if isinstance(inj, CompromiseAssets):
            require_assets(inj.asset_ids)
            for aid in inj.asset_ids:
                assets[aid].state = AssetState.COMPROMISED
            event(inj.at, f"{len(inj.asset_ids)} asset(s) compromised", inj.description, ref=",".join(inj.asset_ids))
        elif isinstance(inj, MarkUnrecoverable):
            require_assets(inj.asset_ids)
            for aid in inj.asset_ids:
                assets[aid].state = AssetState.UNAVAILABLE
                assets[aid].restore_blocker = inj.reason
                new_evidence(aid, None, EvidenceKind.INCIDENT_OBSERVATION, inj.at, f"{inj.reason}. {inj.description}")
            event(inj.at, "Asset(s) unrecoverable", f"{inj.reason}. {inj.description}", ref=",".join(inj.asset_ids))
        elif isinstance(inj, BackupJobFailure):
            require_assets([inj.asset_id])
            backup = assets[inj.asset_id].backup
            if backup is None:
                raise ScenarioError(f"asset '{inj.asset_id}' has no backup policy to fail")
            kept = []
            for rp in backup.recovery_points:
                if rp.created_at >= inj.failing_since:
                    state.removed_points[rp.id] = "backup job failed; point was never created"
                else:
                    kept.append(rp)
            backup.recovery_points = kept
            new_evidence(
                inj.asset_id,
                None,
                EvidenceKind.BACKUP_JOB_LOG,
                inj.at,
                f"Backup jobs failing since {inj.failing_since.isoformat()}. {inj.description}",
            )
            event(inj.at, "Backup job failures discovered", inj.description, inj.asset_id)
        elif isinstance(inj, CorruptRecoveryPoints):
            require_points(inj.recovery_point_ids)
            for rp_id in inj.recovery_point_ids:
                aid, rp = points[rp_id]
                ev = new_evidence(
                    aid,
                    rp_id,
                    EvidenceKind.INTEGRITY_CHECK,
                    inj.at,
                    f"Integrity verification failed for {rp_id}. {inj.description}",
                )
                rp.reported_integrity = CheckStatus.FAILED
                rp.evidence_ids.append(ev)
                event(inj.at, f"Integrity failure on {rp_id}", inj.description, aid, rp_id)
        elif isinstance(inj, CompromisePrincipal):
            state.compromised_roles.add(inj.role)
            event(inj.at, f"Role '{inj.role}' compromised", inj.description, ref=inj.role)
        elif isinstance(inj, RepositoryOutage):
            require_assets([inj.repository_id])
            if not assets[inj.repository_id].is_repository:
                raise ScenarioError(f"'{inj.repository_id}' is not a backup repository")
            assets[inj.repository_id].state = AssetState.UNAVAILABLE
            event(inj.at, f"Repository {inj.repository_id} unavailable", inj.description, inj.repository_id)
        elif isinstance(inj, DeleteRecoveryPoints):
            require_points(inj.recovery_point_ids)
            index = EvidenceIndex.build(inv)
            for rp_id in inj.recovery_point_ids:
                aid, rp = points[rp_id]
                repo = assets.get(rp.repository_id)
                exposure = repository_exposure(repo, {inj.actor}, index) if repo else "at_risk"
                if exposure != "at_risk":
                    why = (
                        "evidenced immutability prevented deletion"
                        if exposure == "protected"
                        else "role has no delete permission on the repository"
                    )
                    event(
                        inj.at,
                        f"Deletion of {rp_id} blocked",
                        f"Attempt by '{inj.actor}': {why}. {inj.description}",
                        aid,
                        rp_id,
                    )
                    continue
                backup = assets[aid].backup
                if backup is None:  # pragma: no cover - points always belong to a backup policy
                    continue
                backup.recovery_points = [p for p in backup.recovery_points if p.id != rp_id]
                state.removed_points[rp_id] = f"deleted by '{inj.actor}'"
                event(inj.at, f"{rp_id} deleted", f"Deleted by '{inj.actor}'. {inj.description}", aid, rp_id)

    state.events.append(
        TimelineEvent(
            at=scenario.incident_at,
            kind="incident",
            asset_id=None,
            ref_id=scenario.id,
            title="Incident declared / recovery starts",
            detail=scenario.title,
            basis=Basis.SIMULATED,
        )
    )
    return state
