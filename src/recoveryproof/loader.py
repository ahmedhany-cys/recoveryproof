"""Safe loading of untrusted JSON input files.

* Only JSON is accepted (no pickle/YAML object construction, no code execution).
* File paths are resolved and must stay inside an allowed base directory.
* Input size is capped before parsing.
* Validation errors are converted to short, readable messages.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ValidationError

from recoveryproof.models import Inventory, OrgPolicy, Scenario

MAX_INPUT_BYTES = 2 * 1024 * 1024
PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_DATA_DIR = PACKAGE_ROOT.parent.parent / "data"


class InputError(ValueError):
    """Raised for any unreadable, unsafe or invalid input. Message is user-safe."""


def safe_path(base_dir: Path, relative: str | Path) -> Path:
    """Resolve ``relative`` under ``base_dir`` and refuse anything that escapes it."""
    base = base_dir.resolve()
    candidate = (base / relative).resolve()
    if candidate != base and base not in candidate.parents:
        raise InputError(f"path '{relative}' is outside the allowed data directory")
    return candidate


def format_validation_error(err: ValidationError, limit: int = 8) -> str:
    lines = []
    for e in err.errors()[:limit]:
        loc = ".".join(str(p) for p in e["loc"]) or "(root)"
        lines.append(f"{loc}: {e['msg']}")
    more = len(err.errors()) - limit
    if more > 0:
        lines.append(f"... and {more} more error(s)")
    return "; ".join(lines)


def parse_model[M: BaseModel](raw: bytes | str, model: type[M], label: str = "input") -> M:
    data = raw.encode() if isinstance(raw, str) else raw
    if len(data) > MAX_INPUT_BYTES:
        raise InputError(f"{label} is larger than {MAX_INPUT_BYTES // 1024} KiB")
    try:
        obj = json.loads(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise InputError(f"{label} is not valid UTF-8 text") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{label} is not valid JSON (line {exc.lineno}, column {exc.colno}): {exc.msg}") from exc
    if not isinstance(obj, dict):
        raise InputError(f"{label} must contain a JSON object at the top level")
    try:
        return model.model_validate(obj)
    except ValidationError as exc:
        raise InputError(f"{label} failed validation: {format_validation_error(exc)}") from exc


def load_model[M: BaseModel](base_dir: Path, relative: str | Path, model: type[M]) -> M:
    path = safe_path(base_dir, relative)
    if path.suffix.lower() != ".json":
        raise InputError(f"'{relative}' is not a .json file")
    if not path.is_file():
        raise InputError(f"'{relative}' does not exist")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise InputError(f"'{relative}' is larger than {MAX_INPUT_BYTES // 1024} KiB")
    return parse_model(path.read_bytes(), model, label=str(relative))


def load_inventory(data_dir: Path = DEFAULT_DATA_DIR, name: str = "baseline/inventory.json") -> Inventory:
    return load_model(data_dir, name, Inventory)


def load_policy(data_dir: Path = DEFAULT_DATA_DIR, name: str = "policy.json") -> OrgPolicy:
    return load_model(data_dir, name, OrgPolicy)


def load_scenarios(data_dir: Path = DEFAULT_DATA_DIR, folder: str = "scenarios") -> list[Scenario]:
    """Load every scenario file, sorted by scenario code. Duplicate ids are rejected."""
    directory = safe_path(data_dir, folder)
    scenarios = [
        load_model(data_dir, p.relative_to(data_dir.resolve()), Scenario) for p in sorted(directory.glob("*.json"))
    ]
    ids = [s.id for s in scenarios]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise InputError(f"duplicate scenario ids: {', '.join(dupes)}")
    return sorted(scenarios, key=lambda s: (len(s.code), s.code))
