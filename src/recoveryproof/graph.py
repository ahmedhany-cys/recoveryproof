"""Dependency graph analysis.

Edges point from a dependency to its dependent (``dependency -> dependent``), so a
topological order of the graph is a valid restore order: every asset appears
after everything it needs.
"""

from __future__ import annotations

from collections.abc import Iterable

import networkx as nx

from recoveryproof.models import Asset
from recoveryproof.results import SharedDependency


def build_graph(assets: Iterable[Asset]) -> nx.DiGraph:
    """Directed graph of inventoried assets. Unknown dependencies are skipped
    (they are reported by :func:`missing_dependencies`)."""
    assets = list(assets)
    known = {a.id for a in assets}
    g: nx.DiGraph = nx.DiGraph()
    for a in assets:
        g.add_node(a.id, criticality=a.criticality.weight, rto=a.rto_minutes)
    for a in assets:
        for dep in a.depends_on:
            if dep in known:
                g.add_edge(dep, a.id)
    return g


def missing_dependencies(assets: Iterable[Asset]) -> list[tuple[str, str]]:
    """``(asset_id, missing_dependency_id)`` pairs, sorted."""
    assets = list(assets)
    known = {a.id for a in assets}
    return sorted((a.id, d) for a in assets for d in a.depends_on if d not in known)


def find_cycles(g: nx.DiGraph) -> list[list[str]]:
    """Strongly connected components with more than one node (self loops are
    rejected by schema validation). Each cycle is sorted for stable output."""
    sccs = [sorted(c) for c in nx.strongly_connected_components(g) if len(c) > 1]
    return sorted(sccs)


def cycle_blocked_nodes(g: nx.DiGraph, cycles: list[list[str]]) -> dict[str, str]:
    """Nodes that cannot be ordered: cycle members and everything downstream."""
    blocked: dict[str, str] = {}
    for cycle in cycles:
        label = " -> ".join([*cycle, cycle[0]])
        for node in cycle:
            blocked[node] = f"part of circular dependency ({label})"
        for node in cycle:
            for desc in nx.descendants(g, node):
                blocked.setdefault(desc, f"depends on an asset in a circular dependency ({label})")
    return blocked


def priority_order(g: nx.DiGraph, exclude: Iterable[str] = ()) -> list[str]:
    """Deterministic topological order of the acyclic part of ``g``.

    Among assets whose prerequisites are satisfied, higher criticality comes first,
    then the shorter RTO, then the asset id.
    """
    excluded = set(exclude)
    dag = g.subgraph(n for n in g.nodes if n not in excluded).copy()

    def key(node: str) -> tuple[int, int, str]:
        data = dag.nodes[node]
        rto = data.get("rto")
        return (-int(data.get("criticality", 0)), rto if rto is not None else 10**9, node)

    return list(nx.lexicographical_topological_sort(dag, key=key))


def ancestors_in(g: nx.DiGraph, node: str, subset: set[str]) -> set[str]:
    """Transitive prerequisites of ``node`` restricted to ``subset``."""
    return nx.ancestors(g, node) & subset if node in g else set()


def descendants(g: nx.DiGraph, nodes: Iterable[str]) -> set[str]:
    out: set[str] = set()
    for n in nodes:
        if n in g:
            out |= nx.descendants(g, n)
    return out


def shared_dependencies(g: nx.DiGraph, assets: dict[str, Asset], threshold: int) -> list[SharedDependency]:
    """Assets whose failure would cascade to many critical systems.

    ``weighted_dependents`` counts transitive dependents in tier 0/1 only. Assets at or
    above ``threshold`` are returned, most impactful first.
    """
    out: list[SharedDependency] = []
    for node in g.nodes:
        deps = sorted(nx.descendants(g, node))
        weighted = sum(1 for d in deps if assets[d].criticality.rank <= 1)
        if weighted >= threshold:
            out.append(SharedDependency(asset_id=node, transitive_dependents=deps, weighted_dependents=weighted))
    return sorted(out, key=lambda s: (-s.weighted_dependents, s.asset_id))
