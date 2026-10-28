"""Remediation tracking for the simulated environment.

Status moves ``open -> acknowledged -> resolved``. Resolving requires a
verification record (who verified, how, and what evidence they observed); the
tracker refuses to mark a risk remediated without one. Marking a recommendation
resolved never alters the analysis input: the finding keeps being raised until
the underlying data changes, so a claimed fix stays visibly distinct from
evidence of a fix.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from recoveryproof.audit import AuditLog
from recoveryproof.timeutil import utc_now

Status = Literal["open", "acknowledged", "resolved"]
_ALLOWED: dict[str, set[str]] = {
    "open": {"acknowledged", "resolved"},
    "acknowledged": {"open", "resolved"},
    "resolved": {"open"},
}


class VerificationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    verified_by: str = Field(min_length=2, max_length=100)
    method: str = Field(min_length=5, max_length=500)
    evidence_reference: str = Field(min_length=3, max_length=500)
    verified_at: datetime


class RemediationEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    status: Status = "open"
    note: str = ""
    updated_at: datetime
    verification: VerificationRecord | None = None


class RemediationError(ValueError):
    pass


class RemediationTracker:
    """JSON-file backed status store (one file per data directory)."""

    def __init__(self, path: Path, audit: AuditLog | None = None) -> None:
        self.path = path
        self.audit = audit
        self._entries: dict[str, RemediationEntry] = {}
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            self._entries = {k: RemediationEntry.model_validate(v) for k, v in raw.items()}

    def status(self, finding_id: str) -> RemediationEntry | None:
        return self._entries.get(finding_id)

    def all(self) -> dict[str, RemediationEntry]:
        return dict(self._entries)

    def transition(
        self,
        finding_id: str,
        new_status: Status,
        *,
        note: str = "",
        verification: VerificationRecord | None = None,
        scenario_id: str = "",
    ) -> RemediationEntry:
        current = self._entries.get(finding_id)
        old: Status = current.status if current else "open"
        if new_status == old:
            raise RemediationError(f"{finding_id} is already '{old}'")
        if new_status not in _ALLOWED[old]:
            raise RemediationError(f"cannot move {finding_id} from '{old}' to '{new_status}'")
        if new_status == "resolved" and verification is None:
            raise RemediationError(
                "a verification record (verified by, method, evidence reference) is required before a "
                "finding can be marked resolved"
            )
        entry = RemediationEntry(
            finding_id=finding_id,
            status=new_status,
            note=note[:1000],
            updated_at=utc_now(),
            verification=verification if new_status == "resolved" else None,
        )
        self._entries[finding_id] = entry
        self._save()
        if self.audit:
            self.audit.append(
                f"remediation.{new_status}",
                {
                    "finding_id": finding_id,
                    "from": old,
                    "to": new_status,
                    "scenario_id": scenario_id,
                    "note": note[:300],
                    "verification": verification.model_dump(mode="json") if verification else None,
                },
            )
        return entry

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {k: v.model_dump(mode="json") for k, v in self._entries.items()}
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".remediation-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.path)  # atomic on POSIX and Windows
