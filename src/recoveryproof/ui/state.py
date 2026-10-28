"""Session state, cached data loading and the shared page context."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

import streamlit as st

from recoveryproof.audit import AuditLog
from recoveryproof.engine import analyze
from recoveryproof.loader import (
    DEFAULT_DATA_DIR,
    InputError,
    load_inventory,
    load_policy,
    load_scenarios,
    parse_model,
)
from recoveryproof.models import Inventory, OrgPolicy, Scenario
from recoveryproof.remediation import RemediationTracker
from recoveryproof.results import AnalysisResult
from recoveryproof.scenarios import BASELINE_ID, ScenarioError

DATA_DIR = Path(os.environ.get("RECOVERYPROOF_DATA_DIR", str(DEFAULT_DATA_DIR)))
STATE_DIR = Path(os.environ.get("RECOVERYPROOF_STATE_DIR", str(DEFAULT_DATA_DIR.parent / "var")))
BUNDLED_LABEL = "Bundled synthetic baseline"


@st.cache_data(show_spinner=False)
def _bundled() -> tuple[Inventory, OrgPolicy, list[Scenario]]:
    return load_inventory(DATA_DIR), load_policy(DATA_DIR), load_scenarios(DATA_DIR)


@st.cache_data(show_spinner=False, max_entries=64)
def _analyze(inv_json: str, policy_json: str, scenario_json: str | None, source: str) -> AnalysisResult:
    inv = Inventory.model_validate_json(inv_json)
    policy = OrgPolicy.model_validate_json(policy_json)
    scenario = Scenario.model_validate_json(scenario_json) if scenario_json else None
    return analyze(inv, policy, scenario, data_source=source)


@dataclass
class Ctx:
    inventory: Inventory
    policy: OrgPolicy
    scenarios: list[Scenario]
    scenario: Scenario | None
    result: AnalysisResult
    baseline: AnalysisResult
    data_source: str
    audit: AuditLog
    tracker: RemediationTracker
    error: str | None = None

    def scenario_by_id(self, sid: str) -> Scenario | None:
        return next((s for s in self.scenarios if s.id == sid), None)

    def analyze_other(self, sid: str) -> AnalysisResult:
        return run_analysis(self.inventory, self.policy, self.scenario_by_id(sid), self.data_source)


def run_analysis(inv: Inventory, policy: OrgPolicy, scenario: Scenario | None, source: str) -> AnalysisResult:
    return _analyze(
        inv.model_dump_json(), policy.model_dump_json(), scenario.model_dump_json() if scenario else None, source
    )


def audit_log() -> AuditLog:
    return AuditLog(STATE_DIR / "audit.jsonl")


def init_state() -> None:
    ss = st.session_state
    if "scenario_id" not in ss:
        # Deep links: ?scenario=B selects a scenario on first load.
        code = st.query_params.get("scenario", "")
        _, _, scenarios = _bundled()
        match = next((s for s in scenarios if s.code == code.upper() or s.id == code), None)
        ss.scenario_id = match.id if match else BASELINE_ID
    ss.setdefault("uploaded_inventory", None)
    ss.setdefault("uploaded_name", None)


def set_scenario(scenario_id: str, *, reason: str) -> None:
    st.session_state.scenario_id = scenario_id
    audit_log().append(reason, {"scenario_id": scenario_id})


def accept_upload(name: str, raw: bytes) -> str | None:
    """Validate an uploaded inventory. Returns an error message or None on success."""
    try:
        inv = parse_model(raw, Inventory, label=name[:80])
    except InputError as exc:
        return str(exc)
    st.session_state.uploaded_inventory = inv.model_dump_json()
    st.session_state.uploaded_name = name[:80]
    digest = hashlib.sha256(raw).hexdigest()[:12]
    audit_log().append("data.upload", {"file": name[:80], "sha256_prefix": digest, "assets": len(inv.assets)})
    return None


def clear_upload() -> None:
    st.session_state.uploaded_inventory = None
    st.session_state.uploaded_name = None
    audit_log().append("data.reset_to_bundled", {})


def get_ctx() -> Ctx:
    inventory, policy, scenarios = _bundled()
    source = BUNDLED_LABEL
    if st.session_state.get("uploaded_inventory"):
        inventory = Inventory.model_validate_json(st.session_state.uploaded_inventory)
        source = f"Uploaded file '{st.session_state.uploaded_name}' (user-supplied, not independently verified)"
    sid = st.session_state.get("scenario_id", BASELINE_ID)
    scenario = next((s for s in scenarios if s.id == sid), None)
    audit = audit_log()
    tracker = RemediationTracker(STATE_DIR / "remediation.json", audit)
    baseline = run_analysis(inventory, policy, None, source)
    error = None
    try:
        result = run_analysis(inventory, policy, scenario, source)
    except ScenarioError as exc:
        error = f"Scenario cannot be applied to this inventory: {exc}. Showing baseline instead."
        scenario, result = None, baseline
        st.session_state.scenario_id = BASELINE_ID
    return Ctx(inventory, policy, scenarios, scenario, result, baseline, source, audit, tracker, error)
