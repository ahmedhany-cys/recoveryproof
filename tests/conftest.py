from __future__ import annotations

from datetime import UTC, datetime

import pytest

from recoveryproof.engine import analyze
from recoveryproof.loader import load_inventory, load_policy, load_scenarios
from recoveryproof.models import Inventory, OrgPolicy, Scenario
from recoveryproof.results import AnalysisResult

FIXED_NOW = datetime(2026, 10, 20, 10, 0, tzinfo=UTC)


@pytest.fixture(scope="session")
def baseline() -> Inventory:
    return load_inventory()


@pytest.fixture(scope="session")
def policy() -> OrgPolicy:
    return load_policy()


@pytest.fixture(scope="session")
def scenarios() -> dict[str, Scenario]:
    return {s.code: s for s in load_scenarios()}


@pytest.fixture(scope="session")
def results(baseline: Inventory, policy: OrgPolicy, scenarios: dict[str, Scenario]) -> dict[str, AnalysisResult]:
    out = {"BL": analyze(baseline, policy, generated_at=FIXED_NOW)}
    for code, sc in scenarios.items():
        out[code] = analyze(baseline, policy, sc, generated_at=FIXED_NOW)
    return out
