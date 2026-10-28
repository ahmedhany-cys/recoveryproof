"""Analysis output model.

These models are what the dashboard, the HTML/PDF reports and the JSON export
all render, which guarantees that every surface shows the same numbers.

``Basis`` labels where a statement comes from:

* ``verified``  – backed by an evidence record whose result supports it
* ``simulated`` – produced by an injected scenario condition
* ``derived``   – calculated from other data (an estimate, not an observation)
* ``unknown``   – required information is missing; nothing is assumed
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from recoveryproof.models import AssetState, CheckStatus, Criticality, Severity


class Basis(StrEnum):
    VERIFIED = "verified"
    SIMULATED = "simulated"
    DERIVED = "derived"
    UNKNOWN = "unknown"


class Compliance(StrEnum):
    MET = "met"
    BREACHED = "breached"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class RecoveryEvidence(StrEnum):
    RESTORE_VERIFIED = "restore_verified"  # integrity-verified point + recent passing restore test
    INTEGRITY_ONLY = "integrity_only"  # integrity-verified point, no recent restore test
    UNVERIFIED = "unverified"  # only points with unknown integrity remain
    NONE = "none"  # no usable recovery point at all

    @property
    def label(self) -> str:
        return {
            "restore_verified": "Restore-tested",
            "integrity_only": "Integrity only",
            "unverified": "Not verified",
            "none": "No usable point",
        }[self.value]


class Isolation(StrEnum):
    VERIFIED = "verified"
    CLAIMED = "claimed"
    NONE = "none"


class Out(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PointAssessment(Out):
    recovery_point_id: str
    created_at: datetime
    repository_id: str
    reported_integrity: CheckStatus
    effective_integrity: CheckStatus
    effective_restore_test: CheckStatus
    protection: Literal["not_exposed", "protected", "at_risk"]
    eligible: bool
    reasons: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class AssetAssessment(Out):
    asset_id: str
    name: str
    asset_type: str
    criticality: Criticality
    state: AssetState
    in_plan_scope: bool
    impacted: bool
    rto_minutes: int | None
    rpo_minutes: int | None
    newest_point_id: str | None
    newest_point_at: datetime | None
    selected_point_id: str | None
    selected_point_at: datetime | None
    selected_repository_id: str | None
    recovery_evidence: RecoveryEvidence
    last_restore_test_at: datetime | None
    last_restore_test_evidence: str | None
    data_loss_minutes: int | None
    rpo_status: Compliance
    rpo_gap_minutes: int | None
    rto_status: Compliance
    estimated_ready_minute: int | None
    rto_gap_minutes: int | None
    restore_duration_minutes: int | None
    restore_duration_basis: str | None
    restore_blocked: bool
    blocked_reasons: list[str] = Field(default_factory=list)
    isolation: Isolation
    backup_confidence: float
    score: float
    score_breakdown: dict[str, float]
    points: list[PointAssessment] = Field(default_factory=list)


class Finding(Out):
    id: str
    rule_id: str
    title: str
    severity: Severity
    category: str
    asset_id: str
    asset_name: str
    description: str
    business_impact: str
    evidence_ids: list[str] = Field(default_factory=list)
    calculation: str | None = None
    basis: Basis


class Recommendation(Out):
    id: str
    finding_id: str
    rule_id: str
    severity: Severity
    asset_id: str
    evidence_ids: list[str]
    business_impact: str
    action: str
    reason: str
    verification_procedure: str
    expected_outcome: str
    status: Literal["open", "acknowledged", "resolved"] = "open"
    priority: int


class PlanStep(Out):
    order: int
    asset_id: str
    name: str
    criticality: Criticality
    wave: int | None
    depends_on: list[str]
    recovery_point_id: str | None
    start_minute: int | None
    finish_minute: int | None
    duration_minutes: int | None
    duration_basis: str | None
    rto_minutes: int | None
    rto_status: Compliance
    blocked: bool
    blocked_reason: str | None = None


class RecoveryPlan(Out):
    scope: Literal["affected", "all"]
    steps: list[PlanStep]
    parallel_minutes: int | None
    parallel_lower_bound_minutes: int | None
    serial_minutes: int | None
    unknown_duration_assets: list[str]
    blocked_assets: list[str]
    assumptions: list[str]


class SharedDependency(Out):
    asset_id: str
    transitive_dependents: list[str]
    weighted_dependents: int


class GraphAssessment(Out):
    nodes: list[str]
    edges: list[tuple[str, str]]
    missing_dependencies: list[tuple[str, str]]
    cycles: list[list[str]]
    shared_dependencies: list[SharedDependency]


class TimelineEvent(Out):
    at: datetime | None
    offset_minutes: int | None = None
    kind: Literal["recovery_point", "evidence", "injection", "incident", "plan"]
    asset_id: str | None
    ref_id: str | None
    title: str
    detail: str
    basis: Basis


class Metrics(Out):
    readiness_score: float
    readiness_band: str
    critical_systems: int
    assessed_systems: int
    verified_recovery: int
    stale_or_missing: int
    integrity_failures: int
    rto_unmet: int
    rto_unknown: int
    rpo_unmet: int
    rpo_unknown: int
    dependency_failures: int
    est_recovery_parallel_minutes: int | None
    est_recovery_lower_bound_minutes: int | None
    est_recovery_serial_minutes: int | None
    max_data_loss_minutes: int | None
    unbounded_data_loss_assets: list[str]
    business_impact_pct: float
    impacted_assets: list[str]
    findings_by_severity: dict[str, int]


class AnalysisResult(Out):
    analysis_version: str
    generated_at: datetime
    organization: str
    data_source: str
    as_of: datetime
    incident_at: datetime
    scenario_id: str
    scenario_code: str
    scenario_title: str
    scenario_narrative: str
    scenario_severity: Severity | None
    assets: list[AssetAssessment]
    findings: list[Finding]
    recommendations: list[Recommendation]
    plan: RecoveryPlan
    graph: GraphAssessment
    metrics: Metrics
    timeline: list[TimelineEvent]
    assumptions: list[str]

    def asset(self, asset_id: str) -> AssetAssessment:
        for a in self.assets:
            if a.asset_id == asset_id:
                return a
        raise KeyError(asset_id)

    def finding(self, finding_id: str) -> Finding:
        for f in self.findings:
            if f.id == finding_id:
                return f
        raise KeyError(finding_id)
