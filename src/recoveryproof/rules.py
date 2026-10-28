"""Catalogue of analysis rules.

Every finding references exactly one rule. A rule defines its severity per
criticality tier and the remediation guidance attached to its findings, so the
link from finding -> recommendation is deterministic and reviewable.
"""

from __future__ import annotations

from dataclasses import dataclass

from recoveryproof.models import Criticality, Severity

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    description: str
    severity_by_tier: tuple[Severity, Severity, Severity, Severity]
    action: str
    reason: str
    verification: str
    expected_outcome: str

    def severity(self, criticality: Criticality) -> Severity:
        return self.severity_by_tier[criticality.rank]


RULES: dict[str, Rule] = {
    r.id: r
    for r in [
        Rule(
            "RP-001",
            "No usable recovery point",
            "Backup availability",
            "No recovery point is eligible for restore: none exist, or every existing point "
            "failed verification, is unverified, inaccessible or potentially tampered with.",
            (C, C, H, M),
            "Establish a working backup for this asset and produce at least one "
            "integrity-verified recovery point in an isolated repository.",
            "Without an eligible recovery point the asset cannot be restored after loss.",
            "Run a backup job, record a passing integrity check, and confirm the point "
            "appears as eligible in RecoveryProof.",
            "Asset shows an eligible recovery point and RP-001 is no longer raised.",
        ),
        Rule(
            "RP-002",
            "Recovery point objective breached",
            "RPO compliance",
            "The newest eligible recovery point is older than the asset's RPO allows at the time of the incident.",
            (C, H, M, L),
            "Correct the backup schedule or failing jobs so that the backup interval is "
            "shorter than the RPO, and alert on missed backups.",
            "Restoring from the newest eligible point would lose more data than the business has agreed to tolerate.",
            "Review backup job logs for the last 7 days and confirm a verified recovery point "
            "exists within the RPO window.",
            "Data-loss exposure is at or below the RPO.",
        ),
        Rule(
            "RP-003",
            "Newest recovery point failed integrity verification",
            "Backup integrity",
            "The most recent recovery point failed integrity verification; recovery must fall back to an older point.",
            (H, H, M, L),
            "Investigate the cause of corruption, quarantine the failed point and trigger a "
            "fresh backup with integrity verification.",
            "A corrupted newest point silently increases data loss and may indicate tampering or storage faults.",
            "Re-run integrity verification on a new recovery point and record the result.",
            "Newest recovery point passes integrity verification.",
        ),
        Rule(
            "RP-004",
            "Newest recovery point integrity not verified",
            "Backup integrity",
            "The newest recovery point has no passing integrity check, so it is not counted as recoverable.",
            (H, M, M, L),
            "Enable automated integrity verification (checksum/test mount) on every recovery "
            "point and store the results as evidence.",
            "Backup existence is not proof of recoverability; unverified points cannot be "
            "relied on during an incident.",
            "Confirm an integrity-check evidence record with result 'pass' exists for the newest point.",
            "Newest point is integrity-verified and selected for recovery.",
        ),
        Rule(
            "RP-005",
            "No recent end-to-end restore test",
            "Restore testing",
            "No passing end-to-end restore test exists within the policy window. Integrity "
            "checks alone do not prove the system can be restored and brought into service.",
            (H, H, M, L),
            "Schedule and perform an end-to-end restore test into an isolated environment, "
            "including application-level validation.",
            "Untested restores frequently fail on missing dependencies, keys, or runbook gaps.",
            "Record the restore test result and measured duration as evidence.",
            "Asset recovery evidence becomes 'Restore-tested' with a measured duration.",
        ),
        Rule(
            "RP-006",
            "Restore test failed",
            "Restore testing",
            "The most recent restore test failed.",
            (C, H, M, L),
            "Diagnose and fix the restore failure, update the runbook, and repeat the test.",
            "A failed restore test is direct evidence that recovery would not succeed.",
            "Repeat the restore test and record a passing result.",
            "Latest restore test passes.",
        ),
        Rule(
            "EV-001",
            "Status claimed without supporting evidence",
            "Evidence quality",
            "The backup platform reports a successful check, but no evidence record supports "
            "it. The claim is treated as unknown.",
            (M, M, L, L),
            "Investigate missing backup evidence and ensure verification results are exported to the evidence store.",
            "Unsupported claims cannot be audited and may hide failed or skipped checks.",
            "Locate or regenerate the evidence record and link it to the recovery point.",
            "Claim is backed by an evidence record.",
        ),
        Rule(
            "EV-002",
            "Contradictory evidence",
            "Evidence quality",
            "The reported status disagrees with the evidence record. The more conservative interpretation is used.",
            (H, H, M, L),
            "Investigate the contradiction between the backup platform and the evidence store; re-run verification.",
            "Contradictions may indicate tampering, tooling faults or reporting errors.",
            "Re-verify the recovery point and confirm reported status and evidence agree.",
            "Reported status and evidence agree.",
        ),
        Rule(
            "ISO-001",
            "No verified isolated recovery copy",
            "Isolation & immutability",
            "Policy requires an isolated, immutable copy for this tier, but no recovery point "
            "exists in a separate-account repository with evidenced immutability.",
            (H, H, M, L),
            "Create an isolated backup copy in a separate account/tenant with compliance-mode immutability.",
            "Ransomware operators routinely target backups reachable from production credentials.",
            "Confirm a recovery point exists in the isolated repository and that its "
            "immutability configuration is evidenced.",
            "Isolation status becomes 'verified'.",
        ),
        Rule(
            "ISO-002",
            "Immutability claimed but not evidenced",
            "Isolation & immutability",
            "The repository declares immutability but no passing configuration evidence exists.",
            (H, H, H, H),
            "Export the repository's object-lock/vault-lock configuration as evidence and review it.",
            "Immutability that cannot be demonstrated cannot be relied on.",
            "Record an immutability-configuration evidence record with result 'pass'.",
            "Repository immutability is evidenced.",
        ),
        Rule(
            "ISO-003",
            "Retention lock can be bypassed by privileged roles",
            "Isolation & immutability",
            "The repository uses governance-mode retention, which listed roles can bypass to "
            "delete or shorten retention of recovery points.",
            (M, M, M, M),
            "Move critical recovery points to compliance-mode retention or remove bypass "
            "permissions from day-to-day administrator roles.",
            "A compromised administrator could delete 'immutable' backups.",
            "Review the repository policy and confirm bypass permissions are restricted to a break-glass role.",
            "No standing role can bypass retention.",
        ),
        Rule(
            "ACC-001",
            "Unapproved roles can delete recovery points",
            "Access control",
            "Roles outside the approved backup-administration set hold delete permissions on the repository.",
            (H, H, H, H),
            "Reduce backup-administrator privileges: remove delete permissions from "
            "unapproved roles and require multi-party approval for deletion.",
            "Every additional delete-capable role widens the blast radius of a credential compromise.",
            "Perform an access review and record it as evidence.",
            "Only approved roles can delete recovery points.",
        ),
        Rule(
            "ACC-002",
            "Compromised principal can delete or alter recovery points",
            "Access control",
            "A compromised role can reach recovery points for this asset that are not "
            "protected by evidenced immutability. Those points are treated as untrusted until "
            "re-verified.",
            (C, C, H, M),
            "Revoke the compromised role's sessions (manually, through the identity "
            "provider), then re-verify the integrity of every exposed recovery point.",
            "Points the attacker could have altered cannot be trusted for restore.",
            "Re-run integrity verification on exposed points from a trusted environment and "
            "review deletion events in the audit log.",
            "Exposed points are re-verified or replaced by points in protected storage.",
        ),
        Rule(
            "ENC-001",
            "Backup encryption absent or undocumented",
            "Encryption",
            "Backups of sensitive data are not encrypted, or encryption is not documented.",
            (H, H, M, M),
            "Enable encryption at rest for backups using a managed key with restricted "
            "access, and document the configuration.",
            "Unencrypted backups of sensitive data create a data-exposure risk if the repository is accessed.",
            "Record an encryption-configuration evidence record.",
            "Backup encryption is enabled and evidenced.",
        ),
        Rule(
            "RET-001",
            "Retention below policy minimum",
            "Retention",
            "Backup retention is shorter than the policy minimum for this tier, which may not "
            "cover attacker dwell time.",
            (M, M, L, L),
            "Improve recovery-point retention to meet the policy minimum.",
            "Short retention can leave only compromised points available after a long dwell time.",
            "Confirm the retention setting and the oldest available recovery point.",
            "Retention meets policy minimum.",
        ),
        Rule(
            "DEP-001",
            "Missing dependency",
            "Dependencies",
            "The asset depends on an asset that is not in the inventory, so its recovery "
            "prerequisites cannot be assessed.",
            (H, H, H, H),
            "Add the missing dependency to the inventory or correct the dependency reference.",
            "Undocumented prerequisites cause failed or stalled recoveries.",
            "Re-run the analysis and confirm no missing dependencies are reported.",
            "All dependencies resolve to inventoried assets.",
        ),
        Rule(
            "DEP-002",
            "Circular dependency",
            "Dependencies",
            "Assets depend on each other in a cycle, so no valid recovery order exists without a documented exception.",
            (C, C, C, C),
            "Break the cycle: identify which component can start in a degraded mode and "
            "document it as an explicit recovery exception.",
            "A cycle means none of the involved systems can be restored first.",
            "Re-run the analysis and confirm the cycle is gone or explicitly documented.",
            "A valid recovery order exists.",
        ),
        Rule(
            "DEP-003",
            "Unrecoverable dependency blocks dependent systems",
            "Dependencies",
            "A required dependency cannot be restored, so dependent systems cannot be "
            "returned to service even if their own backups are intact.",
            (C, C, C, C),
            "Restore or validate the critical dependency first (alternative recovery source, "
            "key recovery, or rebuild), then resume the dependent recovery.",
            "Application recovery alone is insufficient when its prerequisites are lost.",
            "Demonstrate a successful restore of the dependency in an isolated environment.",
            "Dependency becomes restorable and dependents are unblocked.",
        ),
        Rule(
            "DEP-004",
            "Shared critical dependency lacks a restore test",
            "Dependencies",
            "Many critical systems depend on this asset, but its own recovery has not been "
            "proven by a recent end-to-end restore test.",
            (H, H, H, H),
            "Restore or validate this critical dependency with a full restore test and document its recovery runbook.",
            "A failure here cascades to every dependent system.",
            "Record a passing restore test for the dependency.",
            "Dependency is restore-tested.",
        ),
        Rule(
            "RTO-001",
            "Estimated recovery exceeds RTO",
            "RTO compliance",
            "The estimated time until this asset is back in service, including waiting for "
            "its dependencies, exceeds its recovery time objective.",
            (C, H, M, L),
            "Shorten the recovery path: pre-stage restore infrastructure, parallelise "
            "dependency restores, or renegotiate the RTO with the business owner.",
            "Missing the RTO extends business outage beyond the agreed tolerance.",
            "Measure the restore duration in a test and recompute the recovery plan.",
            "Estimated ready time is within the RTO.",
        ),
        Rule(
            "RTO-002",
            "RTO or RPO not documented",
            "Recovery governance",
            "The asset has no documented RTO and/or RPO, so compliance cannot be assessed.",
            (M, M, L, L),
            "Document a missing RTO and RPO with the business owner.",
            "Without objectives, recovery cannot be prioritised or tested against a target.",
            "Confirm RTO and RPO values are recorded in the inventory.",
            "RTO/RPO compliance can be evaluated.",
        ),
        Rule(
            "RTO-003",
            "Restore duration unknown",
            "RTO compliance",
            "No measured or estimated restore duration exists, so recovery time cannot be "
            "estimated for this asset or anything that depends on it.",
            (H, M, L, L),
            "Perform a restore test to measure the restore duration.",
            "Unknown durations make the overall recovery estimate incomplete.",
            "Record a restore test with a measured duration.",
            "Restore duration is measured.",
        ),
        Rule(
            "REPO-001",
            "Backup repository unavailable",
            "Backup availability",
            "A backup repository is unavailable; recovery points stored there cannot be used.",
            (C, C, C, C),
            "Restore access to the repository or fail over to an isolated copy.",
            "Recovery points that cannot be reached do not help recovery.",
            "Confirm the repository is reachable and list its recovery points.",
            "Repository available.",
        ),
    ]
}


def rule(rule_id: str) -> Rule:
    return RULES[rule_id]
