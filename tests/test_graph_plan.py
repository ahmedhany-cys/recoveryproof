"""Dependency graph, recovery ordering and recovery-time calculations."""

from __future__ import annotations

import networkx as nx
from hypothesis import given, settings
from hypothesis import strategies as st

from recoveryproof.engine import analyze
from recoveryproof.graph import (
    build_graph,
    cycle_blocked_nodes,
    find_cycles,
    missing_dependencies,
    priority_order,
    shared_dependencies,
)
from recoveryproof.models import Asset
from recoveryproof.results import Compliance
from tests.helpers import asset, inventory, simple_chain, verified_point


def _assets(spec: dict[str, list[str]], crit: dict[str, str] | None = None) -> list[Asset]:
    crit = crit or {}
    return [Asset.model_validate(asset(n, deps=d, crit=crit.get(n, "tier1"), backup=False)) for n, d in spec.items()]


class TestGraph:
    def test_edge_direction_dependency_to_dependent(self) -> None:
        g = build_graph(_assets({"id-a": [], "db-b": ["id-a"], "app-c": ["db-b"]}))
        assert set(g.edges) == {("id-a", "db-b"), ("db-b", "app-c")}

    def test_missing_dependencies(self) -> None:
        assets = _assets({"app-c": ["db-b", "ghost-x"], "db-b": []})
        assert missing_dependencies(assets) == [("app-c", "ghost-x")]
        assert ("ghost-x", "app-c") not in build_graph(assets).edges

    def test_cycles_detected_and_downstream_blocked(self) -> None:
        g = build_graph(_assets({"a-1": ["c-3"], "b-2": ["a-1"], "c-3": ["b-2"], "d-4": ["c-3"], "e-5": []}))
        cycles = find_cycles(g)
        assert cycles == [["a-1", "b-2", "c-3"]]
        blocked = cycle_blocked_nodes(g, cycles)
        assert set(blocked) == {"a-1", "b-2", "c-3", "d-4"}
        assert "part of circular dependency" in blocked["a-1"]
        assert "depends on an asset in a circular dependency" in blocked["d-4"]
        assert priority_order(g, exclude=blocked) == ["e-5"]

    def test_priority_prefers_criticality_then_rto(self) -> None:
        assets = [
            Asset.model_validate(asset("low-a", crit="tier3", rto=10, backup=False)),
            Asset.model_validate(asset("crit-slow", crit="tier0", rto=500, backup=False)),
            Asset.model_validate(asset("crit-fast", crit="tier0", rto=30, backup=False)),
        ]
        assert priority_order(build_graph(assets)) == ["crit-fast", "crit-slow", "low-a"]

    def test_shared_dependencies(self) -> None:
        spec = {"core-a": [], "s-1": ["core-a"], "s-2": ["core-a"], "s-3": ["s-1"], "leaf-x": []}
        assets = _assets(spec)
        shared = shared_dependencies(build_graph(assets), {a.id: a for a in assets}, threshold=3)
        assert [s.asset_id for s in shared] == ["core-a"]
        assert shared[0].transitive_dependents == ["s-1", "s-2", "s-3"]

    @settings(max_examples=60, deadline=None)
    @given(st.integers(min_value=2, max_value=12), st.data())
    def test_property_order_respects_every_edge(self, n: int, data: st.DataObject) -> None:
        # random DAG: node i may only depend on nodes with smaller index
        spec: dict[str, list[str]] = {}
        for i in range(n):
            deps = data.draw(st.lists(st.integers(0, max(i - 1, 0)), max_size=3, unique=True)) if i else []
            spec[f"n-{i}"] = [f"n-{d}" for d in deps if d < i]
        g = build_graph(_assets(spec))
        order = priority_order(g)
        pos = {node: k for k, node in enumerate(order)}
        assert sorted(order) == sorted(spec)
        assert all(pos[u] < pos[v] for u, v in g.edges)
        assert nx.is_directed_acyclic_graph(g)


class TestPlan:
    def test_chain_timing_and_waves(self) -> None:
        r = analyze(simple_chain((10, 20, 30)))
        steps = {s.asset_id: s for s in r.plan.steps}
        assert [s.asset_id for s in r.plan.steps] == ["id-a", "db-b", "app-c"]
        assert (steps["id-a"].start_minute, steps["id-a"].finish_minute) == (0, 10)
        assert (steps["db-b"].start_minute, steps["db-b"].finish_minute) == (10, 30)
        assert (steps["app-c"].start_minute, steps["app-c"].finish_minute) == (30, 60)
        assert [steps[n].wave for n in ("id-a", "db-b", "app-c")] == [1, 2, 3]
        assert r.plan.parallel_minutes == 60
        assert r.plan.serial_minutes == 60
        assert steps["app-c"].duration_basis == "measured (EV-RT-APP-C)"

    def test_parallel_branches(self) -> None:
        names = {"root-a": [], "left-b": ["root-a"], "right-c": ["root-a"], "join-d": ["left-b", "right-c"]}
        durs = {"root-a": 10, "left-b": 50, "right-c": 20, "join-d": 5}
        assets, evidence = (
            [
                {
                    "id": "vault",
                    "name": "v",
                    "asset_type": "backup_repository",
                    "criticality": "tier0",
                    "environment": "shared",
                    "owner": "o",
                    "repository": {},
                }
            ],
            [],
        )
        for n, deps in names.items():
            p, e = verified_point(n, f"RP-{n.upper()}-1", 10)
            evidence.append(e)
            assets.append(asset(n, deps=deps, points=[p], duration=durs[n], rto=1000))
        r = analyze(inventory(assets, evidence))
        steps = {s.asset_id: s for s in r.plan.steps}
        assert steps["join-d"].start_minute == 60  # waits for the slower branch (10 + 50)
        assert steps["join-d"].finish_minute == 65
        assert r.plan.parallel_minutes == 65
        assert r.plan.serial_minutes == 85

    def test_rto_breach_due_to_dependency_wait(self) -> None:
        inv = simple_chain((10, 20, 30))
        inv.asset("app-c").rto_minutes = 45  # ready at 60 > 45
        r = analyze(inv)
        assert r.asset("app-c").rto_status is Compliance.BREACHED
        assert r.asset("app-c").rto_gap_minutes == 15
        f = r.finding("F-RTO-001-app-c")
        assert "over by 15 min" in (f.calculation or "")

    def test_rto_exactly_met_is_compliant(self) -> None:
        inv = simple_chain((10, 20, 30))
        inv.asset("app-c").rto_minutes = 60
        assert analyze(inv).asset("app-c").rto_status is Compliance.MET

    def test_unknown_duration_propagates(self) -> None:
        r = analyze(simple_chain((10, None, 30)))
        steps = {s.asset_id: s for s in r.plan.steps}
        assert steps["db-b"].finish_minute is None
        assert steps["app-c"].start_minute is None
        assert steps["app-c"].rto_status is Compliance.UNKNOWN
        assert r.plan.parallel_minutes is None
        assert r.plan.parallel_lower_bound_minutes == 10
        assert r.plan.unknown_duration_assets == ["app-c", "db-b"]
        assert "F-RTO-003-db-b" in {f.id for f in r.findings}

    def test_blocked_dependency_blocks_dependents(self) -> None:
        inv = simple_chain()
        inv.asset("id-a").restore_blocker = "key material lost"
        r = analyze(inv)
        steps = {s.asset_id: s for s in r.plan.steps}
        assert steps["id-a"].blocked and "key material lost" in (steps["id-a"].blocked_reason or "")
        assert steps["app-c"].blocked and "id-a" in (steps["app-c"].blocked_reason or "")
        assert r.plan.parallel_minutes is None  # nothing restorable: no fake "0 min"
        assert r.metrics.dependency_failures == 2
        dep = r.finding("F-DEP-003-id-a")
        assert "db-b" in dep.description and "insufficient" in dep.description

    def test_cycle_produces_no_misleading_order(self) -> None:
        p1, e1 = verified_point("a-1", "RP-A1-1", 5)
        p2, e2 = verified_point("b-2", "RP-B2-1", 5)
        inv = inventory(
            [
                {
                    "id": "vault",
                    "name": "v",
                    "asset_type": "backup_repository",
                    "criticality": "tier0",
                    "environment": "shared",
                    "owner": "o",
                    "repository": {},
                },
                asset("a-1", deps=["b-2"], points=[p1]),
                asset("b-2", deps=["a-1"], points=[p2]),
            ],
            [e1, e2],
        )
        r = analyze(inv)
        assert all(s.blocked for s in r.plan.steps)
        assert r.graph.cycles == [["a-1", "b-2"]]
        assert "F-DEP-002-a-1-CYCLE" in {f.id for f in r.findings}
        assert all(s.wave is None for s in r.plan.steps)

    def test_missing_dependency_blocks_and_reports(self) -> None:
        p, e = verified_point("app-c", "RP-C-1", 5)
        inv = inventory(
            [
                {
                    "id": "vault",
                    "name": "v",
                    "asset_type": "backup_repository",
                    "criticality": "tier0",
                    "environment": "shared",
                    "owner": "o",
                    "repository": {},
                },
                asset("app-c", deps=["ghost-db"], points=[p]),
            ],
            [e],
        )
        r = analyze(inv)
        assert r.plan.steps[0].blocked
        assert "uninventoried" in (r.plan.steps[0].blocked_reason or "")
        assert r.graph.missing_dependencies == [("app-c", "ghost-db")]
        assert "F-DEP-001-app-c" in {f.id for f in r.findings}

    def test_empty_plan(self) -> None:
        inv = simple_chain()
        from recoveryproof.planner import build_plan

        plan = build_plan(build_graph(inv.assets), [], {}, {}, {}, "affected")
        assert plan.steps == [] and plan.parallel_minutes == 0
