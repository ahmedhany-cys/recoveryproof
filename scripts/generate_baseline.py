"""Generate the deterministic synthetic baseline inventory.

The output (data/baseline/inventory.json) is committed so the application never
needs to run this script; it exists so reviewers can see exactly how the
synthetic data was constructed and regenerate it after edits.

    python scripts/generate_baseline.py

Every value here is fictional. "Northwind Logistics" is a made-up company.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from recoveryproof.models import Inventory  # noqa: E402

AS_OF = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
PRIMARY = "vault-primary"
ISOLATED = "vault-isolated"

evidence: list[dict[str, Any]] = []


def ts(s: str) -> str:
    """'10-20 08:45' -> ISO timestamp in 2026, UTC."""
    month_day, hm = s.split(" ")
    month, day = month_day.split("-")
    hour, minute = hm.split(":")
    return datetime(2026, int(month), int(day), int(hour), int(minute), tzinfo=UTC).isoformat().replace("+00:00", "Z")


def stamp(s: str) -> str:
    return ts(s).replace("-", "").replace(":", "").replace("T", "")[:12]


def add_evidence(**kw: Any) -> str:
    evidence.append(kw)
    return str(kw["id"])


# Isolated copies carry the same created_at as the backup they were copied from:
# created_at is the point-in-time of the data, which is what RPO depends on.
def point(
    code: str,
    asset_id: str,
    when: str,
    repo: str = PRIMARY,
    *,
    integrity: str = "pass",  # pass | fail | none (claimed without evidence) | not_run
    size_gb: float | None = None,
) -> dict[str, Any]:
    suffix = "I" if repo == ISOLATED else "P"
    rp_id = f"RP-{code}-{stamp(when)}-{suffix}"
    rp: dict[str, Any] = {"id": rp_id, "created_at": ts(when), "repository_id": repo, "evidence_ids": []}
    if size_gb is not None:
        rp["size_gb"] = size_gb
    if integrity == "not_run":
        rp["reported_integrity"] = "not_run"
    elif integrity == "none":
        rp["reported_integrity"] = "passed"  # claimed by the backup tool, no evidence exported
    else:
        rp["reported_integrity"] = "passed"
        ev = add_evidence(
            id=f"EV-INT-{code}-{stamp(when)}-{suffix}",
            kind="integrity_check",
            asset_id=asset_id,
            recovery_point_id=rp_id,
            collected_at=_plus_minutes(ts(when), 20),
            source="Backup platform checksum verification export (synthetic)",
            summary=(
                f"Block-level checksum validation of {rp_id} "
                + ("completed: all blocks match." if integrity == "pass" else "FAILED: checksum mismatch on 3 blocks.")
            ),
            result=integrity,
        )
        rp["evidence_ids"].append(ev)
    return rp


def _plus_minutes(iso: str, minutes: int) -> str:
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (dt + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def restore_test(code: str, asset_id: str, when: str, minutes: int, rp_id: str | None, result: str = "pass") -> str:
    return add_evidence(
        id=f"EV-RST-{code}-{stamp(when)}",
        kind="restore_test",
        asset_id=asset_id,
        recovery_point_id=rp_id,
        collected_at=ts(when),
        source="DR test runbook execution record (synthetic)",
        summary=(
            "End-to-end restore into isolated test environment "
            + ("succeeded; application health checks passed" if result == "pass" else "failed")
            + f". Measured duration {minutes} min."
        ),
        result=result,
        measured_minutes=minutes,
    )


def backup(
    schedule: int,
    retention: int,
    points: list[dict[str, Any]],
    *,
    encrypted: bool | None = True,
    estimate: int | None = None,
) -> dict[str, Any]:
    b: dict[str, Any] = {
        "schedule_minutes": schedule,
        "retention_days": retention,
        "encrypted": encrypted,
        "recovery_points": points,
    }
    if estimate is not None:
        b["restore_duration_minutes"] = estimate
        b["restore_duration_basis"] = "estimated"
    return b


def asset(**kw: Any) -> dict[str, Any]:
    kw.setdefault("environment", "production")
    kw.setdefault("depends_on", [])
    kw.setdefault("evidence_refs", [])
    return kw


def build() -> dict[str, Any]:
    assets: list[dict[str, Any]] = []

    # --- dns-core -----------------------------------------------------------
    pts = [point("DNS", "dns-core", w) for w in ("10-20 02:00", "10-19 02:00", "10-18 02:00", "10-01 02:00")]
    pts.append(point("DNS", "dns-core", "10-20 02:00", ISOLATED))
    rt = restore_test("DNS", "dns-core", "10-03 10:00", 15, pts[3]["id"])
    assets.append(
        asset(
            id="dns-core",
            name="Core DNS & Network Services",
            asset_type="infrastructure",
            criticality="tier0",
            owner="Network Engineering",
            description="Internal DNS, DHCP and core routing configuration.",
            rto_minutes=30,
            rpo_minutes=1440,
            data_sensitivity="internal",
            backup=backup(1440, 35, pts),
            evidence_refs=[rt],
        )
    )

    # --- idp-core -----------------------------------------------------------
    pts = [
        point("IDP", "idp-core", "10-20 08:30"),
        point("IDP", "idp-core", "10-20 07:30", integrity="fail"),
        point("IDP", "idp-core", "10-20 06:30"),
        point("IDP", "idp-core", "09-27 08:30"),
        point("IDP", "idp-core", "10-20 01:30", ISOLATED),
    ]
    rt = restore_test("IDP", "idp-core", "09-28 14:00", 45, pts[3]["id"])
    assets.append(
        asset(
            id="idp-core",
            name="Identity Provider & SSO",
            asset_type="identity",
            criticality="tier0",
            owner="Identity & Access Management",
            description="Workforce and customer SSO, MFA and directory.",
            rto_minutes=60,
            rpo_minutes=60,
            depends_on=["dns-core"],
            data_sensitivity="restricted",
            backup=backup(60, 35, pts),
            evidence_refs=[rt],
        )
    )

    # --- kms-secrets --------------------------------------------------------
    pts = [point("KMS", "kms-secrets", w) for w in ("10-20 08:00", "10-20 04:00", "10-20 00:00", "08-29 08:00")]
    pts.append(point("KMS", "kms-secrets", "10-20 00:00", ISOLATED))
    rt = restore_test("KMS", "kms-secrets", "08-30 11:00", 25, pts[3]["id"])
    assets.append(
        asset(
            id="kms-secrets",
            name="Secrets & Key Management",
            asset_type="security",
            criticality="tier0",
            owner="Security Engineering",
            description="Secrets vault and encryption keys used by databases and services.",
            rto_minutes=45,
            rpo_minutes=240,
            depends_on=["dns-core"],
            data_sensitivity="restricted",
            backup=backup(240, 35, pts),
            evidence_refs=[rt],
        )
    )

    # --- db-orders ----------------------------------------------------------
    pts = [
        point("DBORD", "db-orders", w, size_gb=820.0)
        for w in ("10-20 08:45", "10-20 08:30", "10-20 08:15", "10-19 06:45", "10-12 02:00")
    ]
    pts.append(point("DBORD", "db-orders", "10-20 01:00", ISOLATED, size_gb=818.0))
    rt = restore_test("DBORD", "db-orders", "10-12 09:00", 75, pts[4]["id"])
    assets.append(
        asset(
            id="db-orders",
            name="Orders Database (PostgreSQL)",
            asset_type="database",
            criticality="tier0",
            owner="Data Platform",
            description="System of record for customer orders and fulfilment status.",
            rto_minutes=120,
            rpo_minutes=15,
            depends_on=["dns-core", "kms-secrets"],
            data_sensitivity="confidential",
            backup=backup(15, 35, pts),
            evidence_refs=[rt],
        )
    )

    # --- db-customers -------------------------------------------------------
    pts = [point("DBCUS", "db-customers", w, size_gb=460.0) for w in ("10-20 08:00", "10-20 07:00", "10-20 06:00")]
    pts.append(point("DBCUS", "db-customers", "10-20 01:00", ISOLATED, size_gb=459.0))
    rt = restore_test("DBCUS", "db-customers", "06-15 13:00", 95, None)
    assets.append(
        asset(
            id="db-customers",
            name="Customer Database (PostgreSQL)",
            asset_type="database",
            criticality="tier0",
            owner="Data Platform",
            description="Customer accounts, addresses and preferences (PII).",
            rto_minutes=120,
            rpo_minutes=60,
            depends_on=["dns-core", "kms-secrets"],
            data_sensitivity="restricted",
            backup=backup(60, 14, pts),
            evidence_refs=[rt],
        )
    )

    # --- app-orders-api -----------------------------------------------------
    pts = [point("ORDAPI", "app-orders-api", w) for w in ("10-20 02:00", "10-19 02:00", "10-05 02:00")]
    pts.append(point("ORDAPI", "app-orders-api", "10-20 02:00", ISOLATED))
    rt = restore_test("ORDAPI", "app-orders-api", "10-05 12:00", 25, pts[2]["id"])
    assets.append(
        asset(
            id="app-orders-api",
            name="Orders API Service",
            asset_type="app_server",
            criticality="tier0",
            owner="Commerce Engineering",
            description="Stateless order-processing API (images, config, certificates).",
            rto_minutes=150,
            rpo_minutes=1440,
            depends_on=["db-orders", "idp-core", "kms-secrets"],
            data_sensitivity="confidential",
            backup=backup(1440, 35, pts),
            evidence_refs=[rt],
        )
    )

    # --- web-storefront -----------------------------------------------------
    pts = [point("WEB", "web-storefront", w) for w in ("10-20 02:00", "10-19 02:00", "10-05 02:00")]
    pts.append(point("WEB", "web-storefront", "10-20 02:00", ISOLATED))
    rt = restore_test("WEB", "web-storefront", "10-05 15:00", 30, pts[2]["id"])
    assets.append(
        asset(
            id="web-storefront",
            name="Customer Storefront",
            asset_type="web_app",
            criticality="tier0",
            owner="Commerce Engineering",
            description="Public e-commerce website and checkout.",
            rto_minutes=180,
            rpo_minutes=1440,
            depends_on=["app-orders-api", "db-customers", "idp-core"],
            data_sensitivity="internal",
            backup=backup(1440, 35, pts),
            evidence_refs=[rt],
        )
    )

    # --- app-erp ------------------------------------------------------------
    pts = [point("ERP", "app-erp", "10-20 08:00", integrity="not_run")]
    pts += [point("ERP", "app-erp", w) for w in ("10-20 04:00", "10-20 00:00", "09-10 00:00")]
    rt = restore_test("ERP", "app-erp", "09-10 16:00", 120, pts[3]["id"])
    assets.append(
        asset(
            id="app-erp",
            name="Internal ERP",
            asset_type="internal_app",
            criticality="tier1",
            owner="Business Applications",
            description="Finance, purchasing and inventory management.",
            rto_minutes=480,
            rpo_minutes=240,
            depends_on=["db-orders", "idp-core"],
            data_sensitivity="confidential",
            backup=backup(240, 30, pts),
            evidence_refs=[rt],
        )
    )

    # --- file-share ---------------------------------------------------------
    pts = [point("FILES", "file-share", w, size_gb=4096.0) for w in ("10-20 01:00", "10-19 01:00", "10-18 01:00")]
    assets.append(
        asset(
            id="file-share",
            name="Corporate File Storage",
            asset_type="file_storage",
            criticality="tier2",
            owner="Workplace IT",
            description="Department file shares (~4 TB).",
            rto_minutes=1440,
            rpo_minutes=1440,
            depends_on=["idp-core"],
            data_sensitivity="confidential",
            backup=backup(1440, 30, pts, encrypted=None, estimate=1800),
        )
    )

    # --- logging-siem -------------------------------------------------------
    pts = [point("SIEM", "logging-siem", "10-20 08:00", integrity="none")]
    pts += [point("SIEM", "logging-siem", w) for w in ("10-20 07:00", "10-20 06:00")]
    pts.append(point("SIEM", "logging-siem", "10-20 02:00", ISOLATED))
    rt = restore_test("SIEM", "logging-siem", "09-20 10:00", 90, None)
    assets.append(
        asset(
            id="logging-siem",
            name="Central Logging & SIEM",
            asset_type="logging",
            criticality="tier1",
            owner="Security Operations",
            description="Security event collection, detection rules and log archive.",
            rto_minutes=240,
            rpo_minutes=60,
            depends_on=["dns-core"],
            data_sensitivity="confidential",
            backup=backup(60, 90, pts),
            evidence_refs=[rt],
        )
    )

    # --- monitoring ---------------------------------------------------------
    pts = [point("MON", "monitoring", w) for w in ("10-20 00:00", "10-19 00:00")]
    assets.append(
        asset(
            id="monitoring",
            name="Monitoring & Alerting",
            asset_type="monitoring",
            criticality="tier2",
            owner="Site Reliability Engineering",
            description="Metrics, dashboards and on-call alerting.",
            rto_minutes=480,
            rpo_minutes=1440,
            depends_on=["dns-core", "idp-core"],
            data_sensitivity="internal",
            backup=backup(1440, 14, pts, estimate=60),
        )
    )

    # --- hr-portal ----------------------------------------------------------
    pts = [point("HR", "hr-portal", w) for w in ("10-19 23:00", "10-18 23:00")]
    assets.append(
        asset(
            id="hr-portal",
            name="HR Self-Service Portal",
            asset_type="internal_app",
            criticality="tier3",
            owner="People Systems",
            description="Leave requests and payslip downloads. RTO/RPO never agreed.",
            depends_on=["idp-core", "file-share"],
            data_sensitivity="restricted",
            backup=backup(1440, 30, pts),
        )
    )

    # --- aws-s3-exports -----------------------------------------------------
    assets.append(
        asset(
            id="aws-s3-exports",
            name="Analytics Export Bucket (AWS S3)",
            asset_type="cloud_resource",
            criticality="tier3",
            owner="Data Analytics",
            description="Synthetic AWS-style resource: nightly analytics exports. No backup configured.",
            rto_minutes=2880,
            rpo_minutes=1440,
            data_sensitivity="internal",
        )
    )

    # --- repositories -------------------------------------------------------
    imm_p = add_evidence(
        id="EV-IMM-PRIMARY",
        kind="immutability_config",
        asset_id=PRIMARY,
        collected_at=ts("10-15 09:00"),
        source="Vault lock configuration export (synthetic)",
        summary="Vault lock in GOVERNANCE mode, 35-day minimum retention. Roles backup-admin and platform-admin "
        "hold the bypass-governance-retention permission.",
        result="pass",
    )
    acc_p = add_evidence(
        id="EV-ACC-PRIMARY",
        kind="access_review",
        asset_id=PRIMARY,
        collected_at=ts("10-01 09:00"),
        source="Quarterly access review (synthetic)",
        summary="Delete permission on primary vault held by: backup-admin, platform-admin. "
        "platform-admin access flagged as excessive but not yet removed.",
        result="fail",
    )
    assets.append(
        asset(
            id=PRIMARY,
            name="Primary Backup Vault",
            asset_type="backup_repository",
            criticality="tier0",
            environment="shared",
            owner="Infrastructure Operations",
            description="Same-account backup vault receiving all scheduled backups.",
            data_sensitivity="restricted",
            evidence_refs=[acc_p],
            repository={
                "separate_account": False,
                "immutability": "governance",
                "immutability_evidence_ids": [imm_p],
                "delete_capable_roles": ["backup-admin", "platform-admin"],
                "governance_bypass_roles": ["backup-admin", "platform-admin"],
            },
        )
    )
    imm_i = add_evidence(
        id="EV-IMM-ISOLATED",
        kind="immutability_config",
        asset_id=ISOLATED,
        collected_at=ts("10-15 09:30"),
        source="Vault lock configuration export (synthetic)",
        summary="Vault lock in COMPLIANCE mode in a separate recovery account; 35-day retention cannot be "
        "shortened by any principal. No delete permissions granted.",
        result="pass",
    )
    assets.append(
        asset(
            id=ISOLATED,
            name="Isolated Recovery Vault",
            asset_type="backup_repository",
            criticality="tier0",
            environment="dr",
            owner="Security Engineering",
            description="Logically air-gapped copy in a dedicated recovery account (daily copies).",
            data_sensitivity="restricted",
            repository={
                "separate_account": True,
                "immutability": "compliance",
                "immutability_evidence_ids": [imm_i],
                "delete_capable_roles": [],
                "governance_bypass_roles": [],
            },
        )
    )

    # last_verified_at = newest passing integrity evidence per asset
    for a in assets:
        times = [
            e["collected_at"]
            for e in evidence
            if e["asset_id"] == a["id"] and e["kind"] == "integrity_check" and e["result"] == "pass"
        ]
        if times:
            a["last_verified_at"] = max(times)

    return {
        "schema_version": "1.0",
        "organization": "Northwind Logistics (fictional)",
        "description": "Synthetic enterprise environment for demonstrating RecoveryProof. All data is fictional.",
        "as_of": AS_OF.isoformat().replace("+00:00", "Z"),
        "assets": assets,
        "evidence": sorted(evidence, key=lambda e: (e["collected_at"], e["id"])),
    }


def main() -> None:
    data = build()
    Inventory.model_validate(data)  # fail loudly if the generator produces invalid data
    out = ROOT / "data" / "baseline" / "inventory.json"
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)}: {len(data['assets'])} assets, {len(data['evidence'])} evidence records")


if __name__ == "__main__":
    main()
