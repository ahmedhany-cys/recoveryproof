"""Builders for small, hand-checkable inventories used by unit tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from recoveryproof.models import Inventory

T0 = datetime(2026, 1, 10, 12, 0, tzinfo=UTC)


def iso(dt: datetime) -> str:
    return dt.isoformat()


def repo(
    rid: str = "vault",
    *,
    separate: bool = False,
    immutability: str = "none",
    evidence: str | None = None,
    delete_roles: list[str] | None = None,
    bypass_roles: list[str] | None = None,
    state: str = "operational",
) -> dict[str, Any]:
    return {
        "id": rid,
        "name": f"Repo {rid}",
        "asset_type": "backup_repository",
        "criticality": "tier0",
        "environment": "shared",
        "owner": "ops",
        "state": state,
        "repository": {
            "separate_account": separate,
            "immutability": immutability,
            "immutability_evidence_ids": [evidence] if evidence else [],
            "delete_capable_roles": delete_roles or [],
            "governance_bypass_roles": bypass_roles or [],
        },
    }


def asset(
    aid: str,
    *,
    deps: list[str] | None = None,
    crit: str = "tier0",
    rto: int | None = 120,
    rpo: int | None = 60,
    points: list[dict[str, Any]] | None = None,
    duration: int | None = 30,
    sensitivity: str = "internal",
    retention: int = 35,
    encrypted: bool | None = True,
    backup: bool = True,
    **extra: Any,
) -> dict[str, Any]:
    a: dict[str, Any] = {
        "id": aid,
        "name": aid.replace("-", " ").title(),
        "asset_type": "database",
        "criticality": crit,
        "environment": "production",
        "owner": "team",
        "rto_minutes": rto,
        "rpo_minutes": rpo,
        "depends_on": deps or [],
        "data_sensitivity": sensitivity,
        **extra,
    }
    if backup:
        b: dict[str, Any] = {
            "schedule_minutes": 60,
            "retention_days": retention,
            "encrypted": encrypted,
            "recovery_points": points or [],
        }
        if duration is not None:
            b["restore_duration_minutes"] = duration
            b["restore_duration_basis"] = "estimated"
        a["backup"] = b
    return a


def point(
    rp_id: str,
    minutes_before: int,
    *,
    repo_id: str = "vault",
    integrity: str = "passed",
    evidence: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": rp_id,
        "created_at": iso(T0 - timedelta(minutes=minutes_before)),
        "repository_id": repo_id,
        "reported_integrity": integrity,
        "evidence_ids": evidence or [],
    }


def ev(
    eid: str,
    asset_id: str,
    *,
    kind: str = "integrity_check",
    rp: str | None = None,
    result: str = "pass",
    minutes_before: int = 0,
    measured: int | None = None,
) -> dict[str, Any]:
    e: dict[str, Any] = {
        "id": eid,
        "kind": kind,
        "asset_id": asset_id,
        "recovery_point_id": rp,
        "collected_at": iso(T0 - timedelta(minutes=minutes_before)),
        "source": "test",
        "summary": "test evidence",
        "result": result,
    }
    if measured is not None:
        e["measured_minutes"] = measured
    return e


def verified_point(
    aid: str, rp_id: str, minutes_before: int, repo_id: str = "vault"
) -> tuple[dict[str, Any], dict[str, Any]]:
    """A recovery point with passing integrity evidence."""
    eid = "EV-" + rp_id[3:]
    return point(rp_id, minutes_before, repo_id=repo_id, evidence=[eid]), ev(
        eid, aid, rp=rp_id, minutes_before=minutes_before - 5
    )


def inventory(assets: list[dict[str, Any]], evidence: list[dict[str, Any]] | None = None) -> Inventory:
    return Inventory.model_validate(
        {"organization": "Test Org", "as_of": iso(T0), "assets": assets, "evidence": evidence or []}
    )


def simple_chain(durations: tuple[int | None, ...] = (10, 20, 30)) -> Inventory:
    """id-a -> db-b -> app-c, all with verified points and restore tests."""
    names = ["id-a", "db-b", "app-c"]
    assets, evidence = [repo()], []
    for i, (name, dur) in enumerate(zip(names, durations, strict=True)):
        p, e = verified_point(name, f"RP-{name.upper()}-1", 30)
        evidence.append(e)
        if dur is not None:
            evidence.append(
                ev(
                    f"EV-RT-{name.upper()}",
                    name,
                    kind="restore_test",
                    result="pass",
                    minutes_before=60 * 24,
                    measured=dur,
                )
            )
        assets.append(asset(name, deps=[names[i - 1]] if i else [], points=[p], duration=None))
    return inventory(assets, evidence)
