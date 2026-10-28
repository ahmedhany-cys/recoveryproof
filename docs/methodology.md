# Methodology

Analysis version **2026.10.1**. All calculations are deterministic and covered by tests.
All timestamps are UTC.

## 1. Evidence evaluation

Each recovery point has a status *reported* by the backup tool (integrity, restore test) and
zero or more *evidence records*. The effective status is decided conservatively:

| Reported | Latest evidence | Effective | Issue raised |
|---|---|---|---|
| passed | pass | passed | — |
| passed | none | **unknown** | EV-001 claim without evidence |
| passed | fail | failed | EV-002 contradiction |
| failed | pass | **unknown** | EV-002 contradiction |
| failed | none | failed | — |
| any | inconclusive | unknown | — |

Integrity checks and end-to-end restore tests are evaluated separately.

## 2. Recovery-point eligibility

A point is **eligible** only if all of the following hold:

1. effective integrity is `passed`;
2. its restore test (if any) did not fail;
3. its repository is inventoried and operational;
4. it is not exposed to a compromised role (see §3);
5. it was created at or before the incident, and at or before any trusted cutoff;
6. the asset has no restore blocker (for example a destroyed encryption key).

The **selected** point is the newest eligible one. When a newer point is ineligible, the
reasons are listed (RP-003 for failed integrity, RP-004 for unverified integrity).

## 3. Isolation, immutability and compromised principals

- Immutability is **verified** only if an `immutability_config` evidence record passes.
- Under a compromised role, a repository's points are **at risk** unless verified
  *compliance* mode is in place, or verified *governance* mode where the role cannot bypass
  governance. Roles with no delete/bypass permission do not expose the repository.
- Isolation: **verified** if a usable point sits in a separate-account repository with
  verified immutability; **claimed** if separate-account without evidence; otherwise **none**.

## 4. Recovery evidence level and backup confidence

| Level | Condition | Confidence |
|---|---|---|
| Restore-tested | eligible point exists **and** latest restore test passed within `restore_test_max_age_days` (90) | 1.0 |
| Integrity only | eligible point exists, no recent passing restore test | 0.6 |
| Not verified | only points whose sole problem is unknown integrity | 0.2 |
| No usable point | nothing eligible | 0.0 |

## 5. RPO — data-loss exposure

```
exposure = incident_at − selected_point.created_at        (minutes, floored)
gap      = exposure − RPO
RPO met  ⇔ gap ≤ 0
```
No eligible point → breached, with exposure *not bounded*. RPO undocumented → unknown.
RPO is evaluated for every system as standing exposure at the incident time.

## 6. RTO — recovery plan timing

For each step in dependency order:

```
duration = latest passing restore test's measured minutes
           else documented estimate, else unknown
start    = max(finish of every in-plan prerequisite), or 0 if none
finish   = start + duration
RTO met  ⇔ finish ≤ RTO
```

- A step is **blocked** if it is in or downstream of a cycle, depends on an uninventoried
  asset, has no eligible point, has a restore blocker, or any prerequisite is blocked.
  Blocked steps count as RTO breaches.
- Unknown durations propagate: dependants get unknown start/finish, and the plan reports
  a **lower bound**.
- **Parallel estimate** = max finish (unlimited restore capacity). **Serial estimate** = sum of
  durations (one team). Neither includes detection, triage or validation time.
- If every step is blocked the estimate is **unknown**, never zero.

Two plans are built. The *scenario plan* restores the assets the scenario took down (or all
assets for "all"-scope scenarios). It drives RTO findings and the Recovery Plan page. The
*rehearsal plan* always restores everything and feeds only the readiness score's RTO component.

## 7. Readiness score

Per system (max 100):

| Component | Weight | Credit |
|---|---|---|
| Backup confidence | 35 | §4 |
| RPO | 20 | full if met |
| RTO | 20 | full if met in the rehearsal plan |
| Dependencies | 15 | full if no prerequisite (transitively) is blocked, missing or cyclic |
| Isolation | 10 | verified 1.0 · claimed 0.5 · none 0 |

Overall = Σ(score × weight) / Σ weight, with weight tier0 = 4, tier1 = 3, tier2 = 2, tier3 = 1.
Bands: Strong ≥ 90, Moderate ≥ 75, Weak ≥ 50, Critical < 50.

## 8. Other metrics

| Metric | Definition |
|---|---|
| Critical systems | tier 0–1 protected systems |
| Stale or missing | systems with no eligible point or RPO breached |
| Integrity failures | recovery points whose effective integrity failed |
| Dependency failures | blocked for dependency reasons + cycle members + assets with missing deps |
| Business impact | criticality-weighted share of systems that are down or depend (transitively) on a down system |
| Max data-loss exposure | max exposure among systems in the plan; systems with no point listed separately |

## 9. Rule catalogue (23 rules)

| Rule | Title | Severity t0/t1/t2/t3 |
|---|---|---|
| RP-001 | No usable recovery point | critical/critical/high/medium |
| RP-002 | Recovery point objective breached | critical/high/medium/low |
| RP-003 | Newest recovery point failed integrity verification | high/high/medium/low |
| RP-004 | Newest recovery point integrity not verified | high/medium/medium/low |
| RP-005 | No recent end-to-end restore test | high/high/medium/low |
| RP-006 | Restore test failed | critical/high/medium/low |
| EV-001 | Status claimed without supporting evidence | medium/medium/low/low |
| EV-002 | Contradictory evidence | high/high/medium/low |
| ISO-001 | No verified isolated recovery copy | high/high/medium/low |
| ISO-002 | Immutability claimed but not evidenced | high |
| ISO-003 | Retention lock can be bypassed by privileged roles | medium |
| ACC-001 | Unapproved roles can delete recovery points | high |
| ACC-002 | Compromised principal can delete or alter recovery points | critical/critical/high/medium (one level lower if a protected point remains) |
| ENC-001 | Backup encryption absent or undocumented | high/high/medium/medium (one level lower when undocumented) |
| RET-001 | Retention below policy minimum | medium/medium/low/low |
| DEP-001 | Missing dependency | high |
| DEP-002 | Circular dependency | critical |
| DEP-003 | Unrecoverable dependency blocks dependent systems | critical |
| DEP-004 | Shared critical dependency lacks a restore test | high |
| RTO-001 | Estimated recovery exceeds RTO | critical/high/medium/low |
| RTO-002 | RTO or RPO not documented | medium/medium/low/low |
| RTO-003 | Restore duration unknown | high/medium/low/low |
| REPO-001 | Backup repository unavailable | critical |

Finding IDs are stable: `F-<rule>-<asset>[-<qualifier>]`. The same issue keeps the same ID
across runs and scenarios. Recommendation IDs mirror them (`REC-…`).

## 10. Basis labels

- **verified**: supported by an evidence record.
- **simulated**: caused by a scenario injection.
- **derived**: a calculation from other data (an estimate, not an observation).
- **unknown**: required data is missing; nothing is assumed.

## 11. Assumptions

- Recovery starts at incident declaration (T+0).
- Assets outside the plan scope stay operational.
- Restore-tested validates the procedure within the policy window, not every point.
- Data-loss exposure ignores in-flight transactions and replication lag.
- All bundled data is synthetic.
