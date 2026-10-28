"""Recovery plan: dependency-respecting order, waves and time estimates."""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from recoveryproof.graph import ancestors_in, priority_order
from recoveryproof.models import Asset
from recoveryproof.results import Compliance, PlanStep, RecoveryPlan

PLAN_ASSUMPTIONS = [
    "Recovery starts when the incident is declared (T+0). Detection, triage, forensic "
    "hold and decision time are not included in estimates.",
    "The parallel estimate assumes unlimited restore capacity, so independent assets "
    "restore simultaneously; the serial estimate assumes one asset at a time. Reality "
    "lies between the two.",
    "Restore durations come from the most recent passing restore test where one was "
    "measured; otherwise the documented estimate is used. Unknown durations are not guessed.",
    "An asset may start restoring only after every prerequisite in the plan has finished.",
    "Assets outside the plan scope are assumed to remain operational.",
]


@dataclass
class StepInput:
    asset: Asset
    recovery_point_id: str | None
    duration: int | None
    duration_basis: str | None
    own_blocker: str | None


def build_plan(
    g: nx.DiGraph,
    scope: list[str],
    inputs: dict[str, StepInput],
    cycle_blocked: dict[str, str],
    missing: dict[str, list[str]],
    scope_kind: str,
) -> RecoveryPlan:
    scope_set = set(scope)
    order = [n for n in priority_order(g, exclude=cycle_blocked) if n in scope_set]
    order += sorted(n for n in scope_set if n in cycle_blocked)

    finish: dict[str, int | None] = {}
    wave: dict[str, int | None] = {}
    blocked: dict[str, str] = {}
    steps: list[PlanStep] = []

    for idx, node in enumerate(order, start=1):
        si = inputs[node]
        prereqs = sorted(ancestors_in(g, node, scope_set))
        direct = sorted(d for d in si.asset.depends_on if d in scope_set)
        reason: str | None = None
        if node in cycle_blocked:
            reason = cycle_blocked[node]
        elif missing.get(node):
            reason = f"depends on uninventoried asset(s): {', '.join(missing[node])}"
        elif si.own_blocker:
            reason = si.own_blocker
        else:
            blocking = [p for p in prereqs if p in blocked]
            if blocking:
                reason = f"waiting on blocked prerequisite(s): {', '.join(blocking)}"
        start: int | None
        if reason:
            blocked[node] = reason
            finish[node] = None
            wave[node] = None
            start = None
            end = None
        else:
            prereq_finish = [finish[p] for p in prereqs]
            start = (
                0
                if not prereqs
                else (None if any(f is None for f in prereq_finish) else max(f for f in prereq_finish if f is not None))
            )
            end = start + si.duration if start is not None and si.duration is not None else None
            finish[node] = end
            wave[node] = 1 + max((wave[p] or 0) for p in prereqs) if prereqs else 1
        rto = si.asset.rto_minutes
        if reason:
            rto_status = Compliance.BREACHED if rto is not None else Compliance.UNKNOWN
        elif rto is None or end is None:
            rto_status = Compliance.UNKNOWN
        else:
            rto_status = Compliance.MET if end <= rto else Compliance.BREACHED
        steps.append(
            PlanStep(
                order=idx,
                asset_id=node,
                name=si.asset.name,
                criticality=si.asset.criticality,
                wave=wave[node],
                depends_on=direct,
                recovery_point_id=si.recovery_point_id,
                start_minute=start,
                finish_minute=end,
                duration_minutes=si.duration,
                duration_basis=si.duration_basis,
                rto_minutes=rto,
                rto_status=rto_status,
                blocked=reason is not None,
                blocked_reason=reason,
            )
        )

    runnable = [s for s in steps if not s.blocked]
    unknown = sorted(s.asset_id for s in runnable if s.finish_minute is None)
    known_finishes = [s.finish_minute for s in runnable if s.finish_minute is not None]
    durations = [s.duration_minutes for s in runnable]
    if not steps:
        parallel, serial, lower = 0, 0, 0
    elif not runnable:
        parallel, serial, lower = None, None, None  # nothing can be restored: no estimate
    else:
        parallel = max(known_finishes, default=0) if not unknown else None
        serial = sum(d for d in durations if d is not None) if all(d is not None for d in durations) else None
        lower = max(known_finishes, default=0)
    return RecoveryPlan(
        scope="all" if scope_kind == "all" else "affected",
        steps=steps,
        parallel_minutes=parallel,
        parallel_lower_bound_minutes=lower,
        serial_minutes=serial,
        unknown_duration_assets=unknown,
        blocked_assets=sorted(blocked),
        assumptions=list(PLAN_ASSUMPTIONS),
    )
