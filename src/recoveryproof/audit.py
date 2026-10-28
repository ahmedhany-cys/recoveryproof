"""Append-only local audit trail.

Each entry is a JSON line holding the SHA-256 of the previous entry, so editing or
removing an earlier line breaks the chain and :meth:`AuditLog.verify` reports it.

This is *tamper-evident local logging for a demo application*. It is not
tamper-proof enterprise audit storage: anyone with file-system access can rewrite
the whole file. Production deployments should ship events to WORM storage or a
SIEM.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from recoveryproof.timeutil import utc_now

GENESIS = "0" * 64
_SECRET_HINTS = ("password", "secret", "token", "access_key", "credential", "api_key")


def _redact(value: Any) -> Any:
    """Never write anything that looks like a secret to the audit log."""
    if isinstance(value, dict):
        return {
            k: ("[REDACTED]" if any(h in k.lower() for h in _SECRET_HINTS) else _redact(v)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, str) and len(value) > 2000:
        return value[:2000] + "…"
    return value


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    at: str
    actor: str
    action: str
    details: dict[str, Any]
    prev_hash: str
    hash: str


def _digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def entries(self) -> list[AuditEntry]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(AuditEntry(**json.loads(line)))
        return out

    def append(
        self, action: str, details: dict[str, Any] | None = None, actor: str = "local-user", at: datetime | None = None
    ) -> AuditEntry:
        with self._lock:
            existing = self.entries()
            prev = existing[-1].hash if existing else GENESIS
            payload = {
                "seq": len(existing) + 1,
                "at": (at or utc_now()).isoformat(),
                "actor": actor[:100],
                "action": action[:100],
                "details": _redact(details or {}),
                "prev_hash": prev,
            }
            entry = AuditEntry(**payload, hash=_digest(payload))
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:  # append-only by construction
                fh.write(json.dumps(entry.__dict__, sort_keys=True) + "\n")
            return entry

    def verify(self) -> tuple[bool, str]:
        prev = GENESIS
        for i, e in enumerate(self.entries(), start=1):
            payload = {k: v for k, v in e.__dict__.items() if k != "hash"}
            if e.seq != i:
                return False, f"sequence gap at entry {i} (found {e.seq})"
            if e.prev_hash != prev:
                return False, f"chain broken at entry {e.seq}: previous hash mismatch"
            if _digest(payload) != e.hash:
                return False, f"entry {e.seq} was modified (hash mismatch)"
            prev = e.hash
        return True, "chain intact"
