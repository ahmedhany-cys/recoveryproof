"""Validated input data model: inventory, evidence, policy and scenarios.

Everything loaded from disk or uploaded by a user passes through these models.
They forbid unknown fields, require timezone-aware timestamps and enforce
referential integrity that must hold for the data to be meaningful. Problems the
*analysis* should report on (for example a dependency on an asset that does not
exist) are deliberately **not** rejected here — they become findings instead.

Dependency direction
--------------------
``Asset.depends_on`` lists the assets that must be available *before* this asset
can be restored. In the dependency graph this becomes an edge
``dependency -> dependent`` (e.g. ``idp-core -> db-orders -> app-orders-api``).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeInt,
    PositiveInt,
    model_validator,
)

from recoveryproof.timeutil import to_utc

UtcDatetime = Annotated[AwareDatetime, AfterValidator(to_utc)]
AssetId = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
RecoveryPointId = Annotated[str, Field(pattern=r"^RP-[A-Z0-9][A-Z0-9-]{1,62}$")]
EvidenceId = Annotated[str, Field(pattern=r"^EV-[A-Z0-9][A-Z0-9-]{1,62}$")]
RoleName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
ShortText = Annotated[str, Field(min_length=1, max_length=200)]
LongText = Annotated[str, Field(min_length=1, max_length=4000)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# --------------------------------------------------------------------------- enums


class Criticality(StrEnum):
    TIER0 = "tier0"
    TIER1 = "tier1"
    TIER2 = "tier2"
    TIER3 = "tier3"

    @property
    def weight(self) -> int:
        return {"tier0": 4, "tier1": 3, "tier2": 2, "tier3": 1}[self.value]

    @property
    def label(self) -> str:
        return {
            "tier0": "Tier 0 · Mission critical",
            "tier1": "Tier 1 · Business critical",
            "tier2": "Tier 2 · Important",
            "tier3": "Tier 3 · Supporting",
        }[self.value]

    @property
    def rank(self) -> int:
        """0 for the most critical tier."""
        return int(self.value[-1])


class AssetType(StrEnum):
    WEB_APP = "web_app"
    APP_SERVER = "app_server"
    DATABASE = "database"
    IDENTITY = "identity"
    INFRASTRUCTURE = "infrastructure"
    SECURITY = "security"
    INTERNAL_APP = "internal_app"
    FILE_STORAGE = "file_storage"
    BACKUP_REPOSITORY = "backup_repository"
    LOGGING = "logging"
    MONITORING = "monitoring"
    CLOUD_RESOURCE = "cloud_resource"

    @property
    def label(self) -> str:
        return self.value.replace("_", " ").title()


class Environment(StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    DR = "dr"
    SHARED = "shared"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class CheckStatus(StrEnum):
    """Status of an integrity check or restore test."""

    PASSED = "passed"
    FAILED = "failed"
    UNKNOWN = "unknown"
    NOT_RUN = "not_run"


class EvidenceKind(StrEnum):
    INTEGRITY_CHECK = "integrity_check"
    RESTORE_TEST = "restore_test"
    IMMUTABILITY_CONFIG = "immutability_config"
    ACCESS_REVIEW = "access_review"
    BACKUP_JOB_LOG = "backup_job_log"
    ENCRYPTION_CONFIG = "encryption_config"
    INCIDENT_OBSERVATION = "incident_observation"


class EvidenceResult(StrEnum):
    PASS = "pass"  # noqa: S105  # nosec B105 - evidence result value, not a credential
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class EvidenceOrigin(StrEnum):
    BASELINE_SYNTHETIC = "baseline_synthetic"
    SCENARIO_INJECTED = "scenario_injected"


class ImmutabilityMode(StrEnum):
    NONE = "none"
    GOVERNANCE = "governance"  # privileged roles may bypass retention
    COMPLIANCE = "compliance"  # no role can shorten retention or delete
    UNKNOWN = "unknown"


class AssetState(StrEnum):
    OPERATIONAL = "operational"
    COMPROMISED = "compromised"
    UNAVAILABLE = "unavailable"


# ------------------------------------------------------------------ inventory


class RecoveryPoint(StrictModel):
    id: RecoveryPointId
    created_at: UtcDatetime
    repository_id: AssetId
    reported_integrity: CheckStatus = CheckStatus.NOT_RUN
    reported_restore_test: CheckStatus = CheckStatus.NOT_RUN
    evidence_ids: list[EvidenceId] = Field(default_factory=list)
    size_gb: float | None = Field(default=None, ge=0)


class BackupPolicy(StrictModel):
    schedule_minutes: PositiveInt
    retention_days: PositiveInt
    encrypted: bool | None = None  # None = not documented
    restore_duration_minutes: PositiveInt | None = None
    restore_duration_basis: Literal["measured", "estimated"] | None = None
    recovery_points: list[RecoveryPoint] = Field(default_factory=list)

    @model_validator(mode="after")
    def _basis_requires_duration(self) -> BackupPolicy:
        if (self.restore_duration_minutes is None) != (self.restore_duration_basis is None):
            raise ValueError("restore_duration_minutes and restore_duration_basis must be provided together")
        return self


class RepositoryConfig(StrictModel):
    separate_account: bool | None = None
    immutability: ImmutabilityMode = ImmutabilityMode.UNKNOWN
    immutability_evidence_ids: list[EvidenceId] = Field(default_factory=list)
    delete_capable_roles: list[RoleName] = Field(default_factory=list)
    governance_bypass_roles: list[RoleName] = Field(default_factory=list)


class Asset(StrictModel):
    id: AssetId
    name: ShortText
    asset_type: AssetType
    criticality: Criticality
    environment: Environment
    owner: ShortText
    description: str = Field(default="", max_length=1000)
    rto_minutes: PositiveInt | None = None
    rpo_minutes: NonNegativeInt | None = None
    depends_on: list[AssetId] = Field(default_factory=list)
    data_sensitivity: Sensitivity = Sensitivity.INTERNAL
    backup: BackupPolicy | None = None
    repository: RepositoryConfig | None = None
    state: AssetState = AssetState.OPERATIONAL
    restore_blocker: str | None = Field(default=None, max_length=500)
    last_verified_at: UtcDatetime | None = None
    evidence_refs: list[EvidenceId] = Field(default_factory=list)
    source: Literal["synthetic", "aws_readonly_import"] = "synthetic"

    @model_validator(mode="after")
    def _consistency(self) -> Asset:
        if self.id in self.depends_on:
            raise ValueError(f"asset '{self.id}' cannot depend on itself")
        if len(set(self.depends_on)) != len(self.depends_on):
            raise ValueError(f"asset '{self.id}' lists a dependency more than once")
        is_repo = self.asset_type is AssetType.BACKUP_REPOSITORY
        if is_repo and self.repository is None:
            raise ValueError(f"backup repository '{self.id}' requires a 'repository' block")
        if not is_repo and self.repository is not None:
            raise ValueError(f"'repository' block is only valid for backup repositories ({self.id})")
        if is_repo and self.backup is not None:
            raise ValueError(f"backup repository '{self.id}' cannot itself declare a backup policy")
        return self

    @property
    def is_repository(self) -> bool:
        return self.asset_type is AssetType.BACKUP_REPOSITORY


class Evidence(StrictModel):
    id: EvidenceId
    kind: EvidenceKind
    asset_id: AssetId
    recovery_point_id: RecoveryPointId | None = None
    collected_at: UtcDatetime
    source: ShortText
    summary: LongText
    result: EvidenceResult
    measured_minutes: PositiveInt | None = None
    origin: EvidenceOrigin = EvidenceOrigin.BASELINE_SYNTHETIC


class Inventory(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    organization: ShortText
    description: str = Field(default="", max_length=2000)
    as_of: UtcDatetime
    assets: list[Asset] = Field(min_length=1, max_length=500)
    evidence: list[Evidence] = Field(default_factory=list, max_length=10000)

    @model_validator(mode="after")
    def _referential_integrity(self) -> Inventory:
        ids = [a.id for a in self.assets]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate asset ids: {', '.join(dupes)}")
        ev_ids = [e.id for e in self.evidence]
        dupes = sorted({i for i in ev_ids if ev_ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate evidence ids: {', '.join(dupes)}")
        rp_ids: list[str] = []
        for asset in self.assets:
            if asset.backup:
                rp_ids.extend(rp.id for rp in asset.backup.recovery_points)
        dupes = sorted({i for i in rp_ids if rp_ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate recovery point ids: {', '.join(dupes)}")
        known_assets = set(ids)
        known_rps = set(rp_ids)
        known_ev = set(ev_ids)
        for ev in self.evidence:
            if ev.asset_id not in known_assets:
                raise ValueError(f"evidence {ev.id} references unknown asset '{ev.asset_id}'")
            if ev.recovery_point_id and ev.recovery_point_id not in known_rps:
                raise ValueError(f"evidence {ev.id} references unknown recovery point '{ev.recovery_point_id}'")
        for asset in self.assets:
            refs = list(asset.evidence_refs)
            if asset.repository:
                refs += asset.repository.immutability_evidence_ids
            if asset.backup:
                for rp in asset.backup.recovery_points:
                    refs += rp.evidence_ids
            missing = sorted(set(refs) - known_ev)
            if missing:
                raise ValueError(f"asset '{asset.id}' references unknown evidence: {', '.join(missing)}")
        return self

    def asset(self, asset_id: str) -> Asset:
        for a in self.assets:
            if a.id == asset_id:
                return a
        raise KeyError(asset_id)

    def asset_map(self) -> dict[str, Asset]:
        return {a.id: a for a in self.assets}


# --------------------------------------------------------------------- policy


class OrgPolicy(StrictModel):
    """Organisation-wide recovery policy the analysis evaluates against."""

    restore_test_max_age_days: PositiveInt = 90
    min_retention_days: dict[Criticality, PositiveInt] = Field(
        default_factory=lambda: {
            Criticality.TIER0: 35,
            Criticality.TIER1: 30,
            Criticality.TIER2: 14,
            Criticality.TIER3: 7,
        }
    )
    require_isolated_copy: list[Criticality] = Field(default_factory=lambda: [Criticality.TIER0, Criticality.TIER1])
    require_encryption_for: list[Sensitivity] = Field(
        default_factory=lambda: [Sensitivity.CONFIDENTIAL, Sensitivity.RESTRICTED]
    )
    approved_backup_delete_roles: list[RoleName] = Field(default_factory=lambda: ["backup-admin"])
    shared_dependency_threshold: PositiveInt = 3


# ------------------------------------------------------------------ scenarios


class _InjectionBase(StrictModel):
    at: UtcDatetime
    description: LongText


class CompromiseAssets(_InjectionBase):
    """Production assets are encrypted/destroyed and must be restored from backup."""

    type: Literal["compromise_assets"]
    asset_ids: list[AssetId] = Field(min_length=1)


class MarkUnrecoverable(_InjectionBase):
    """Assets are down *and* cannot be restored (e.g. their backup key was destroyed)."""

    type: Literal["mark_unrecoverable"]
    asset_ids: list[AssetId] = Field(min_length=1)
    reason: ShortText


class BackupJobFailure(_InjectionBase):
    """Backup jobs silently failed: no recovery points exist after ``failing_since``."""

    type: Literal["backup_job_failure"]
    asset_id: AssetId
    failing_since: UtcDatetime


class CorruptRecoveryPoints(_InjectionBase):
    """Integrity verification of the listed recovery points fails."""

    type: Literal["corrupt_recovery_points"]
    recovery_point_ids: list[RecoveryPointId] = Field(min_length=1)


class CompromisePrincipal(_InjectionBase):
    """An attacker controls a role and may delete/alter recovery points it can reach."""

    type: Literal["compromise_principal"]
    role: RoleName


class RepositoryOutage(_InjectionBase):
    type: Literal["repository_outage"]
    repository_id: AssetId


class DeleteRecoveryPoints(_InjectionBase):
    type: Literal["delete_recovery_points"]
    recovery_point_ids: list[RecoveryPointId] = Field(min_length=1)
    actor: RoleName


Injection = Annotated[
    CompromiseAssets
    | MarkUnrecoverable
    | BackupJobFailure
    | CorruptRecoveryPoints
    | CompromisePrincipal
    | RepositoryOutage
    | DeleteRecoveryPoints,
    Field(discriminator="type"),
]


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """0 for the most severe."""
        return ["critical", "high", "medium", "low", "info"].index(self.value)


class ScenarioExpectation(StrictModel):
    """Expected analysis outcome, used for regression testing and in-app checks."""

    readiness_max: float | None = Field(default=None, ge=0, le=100)
    readiness_min: float | None = Field(default=None, ge=0, le=100)
    blocked_assets: list[AssetId] = Field(default_factory=list)
    rpo_breaches: list[AssetId] = Field(default_factory=list)
    rto_breaches: list[AssetId] = Field(default_factory=list)
    required_rules: list[str] = Field(default_factory=list)
    selected_points: dict[AssetId, RecoveryPointId | None] = Field(default_factory=dict)
    order_constraints: list[tuple[AssetId, AssetId]] = Field(
        default_factory=list,
        description="Pairs (before, after) that must hold in the recovery order.",
    )


class Scenario(StrictModel):
    id: Annotated[str, Field(pattern=r"^SCN-[A-Z0-9][A-Z0-9-]{1,62}$")]
    code: Annotated[str, Field(pattern=r"^[A-Z][0-9]?$")]
    title: ShortText
    category: ShortText
    narrative: LongText
    severity: Severity
    incident_at: UtcDatetime
    plan_scope: Literal["affected", "all"] = "affected"
    trusted_before: UtcDatetime | None = None
    variation_of: str | None = None
    injections: list[Injection] = Field(min_length=1, max_length=50)
    recommended_actions: list[ShortText] = Field(default_factory=list)
    expected: ScenarioExpectation = Field(default_factory=ScenarioExpectation)

    @model_validator(mode="after")
    def _times(self) -> Scenario:
        for inj in self.injections:
            if inj.at > self.incident_at:
                raise ValueError(f"injection '{inj.type}' at {inj.at.isoformat()} is after incident_at")
        if self.trusted_before and self.trusted_before > self.incident_at:
            raise ValueError("trusted_before must not be after incident_at")
        return self


def sorted_by_time(points: list[RecoveryPoint]) -> list[RecoveryPoint]:
    """Newest first, ties broken by id for determinism."""
    return sorted(points, key=lambda p: (p.created_at, p.id), reverse=True)


def latest(values: list[datetime]) -> datetime | None:
    return max(values) if values else None
