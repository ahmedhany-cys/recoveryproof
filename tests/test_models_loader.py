"""Input validation, safe loading and time handling."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from recoveryproof.loader import (
    MAX_INPUT_BYTES,
    InputError,
    load_model,
    load_scenarios,
    parse_model,
    safe_path,
)
from recoveryproof.models import Inventory, Scenario
from recoveryproof.timeutil import fmt_minutes, fmt_ts, minutes_between, to_utc
from tests.helpers import asset, ev, inventory, point, repo


class TestInventoryValidation:
    def test_bundled_baseline_is_valid(self, baseline: Inventory) -> None:
        assert len(baseline.assets) == 15
        assert baseline.as_of.tzinfo is not None

    def test_minimal_valid_inventory(self) -> None:
        inv = inventory([repo(), asset("db-a", points=[point("RP-A-1", 10)])])
        assert inv.asset("db-a").backup is not None

    def test_missing_required_field(self) -> None:
        bad = asset("db-a")
        del bad["criticality"]
        with pytest.raises(ValidationError, match="criticality"):
            inventory([bad])

    def test_unknown_field_rejected(self) -> None:
        with pytest.raises(ValidationError, match="Extra inputs"):
            inventory([asset("db-a", surprise=True)])

    def test_naive_timestamp_rejected(self) -> None:
        with pytest.raises(ValidationError, match="timezone"):
            Inventory.model_validate({"organization": "x", "as_of": "2026-01-01T00:00:00", "assets": [asset("db-a")]})

    def test_offset_timestamps_normalised_to_utc(self) -> None:
        inv = Inventory.model_validate(
            {"organization": "x", "as_of": "2026-01-01T05:30:00+05:30", "assets": [asset("db-a", backup=False)]}
        )
        assert inv.as_of.utcoffset() == timedelta(0)
        assert inv.as_of.hour == 0

    @pytest.mark.parametrize("bad_id", ["DB-A", "a", "-db", "db_a", "x" * 70])
    def test_invalid_asset_id(self, bad_id: str) -> None:
        with pytest.raises(ValidationError):
            inventory([asset(bad_id)])

    def test_duplicate_asset_ids(self) -> None:
        with pytest.raises(ValidationError, match="duplicate asset ids: db-a"):
            inventory([asset("db-a"), asset("db-a")])

    def test_duplicate_recovery_point_ids(self) -> None:
        with pytest.raises(ValidationError, match="duplicate recovery point"):
            inventory([repo(), asset("db-a", points=[point("RP-X-1", 1)]), asset("db-b", points=[point("RP-X-1", 2)])])

    def test_self_dependency_rejected(self) -> None:
        with pytest.raises(ValidationError, match="cannot depend on itself"):
            inventory([asset("db-a", deps=["db-a"])])

    def test_duplicate_dependency_rejected(self) -> None:
        with pytest.raises(ValidationError, match="more than once"):
            inventory([asset("db-b", backup=False), asset("db-a", deps=["db-b", "db-b"])])

    def test_missing_dependency_is_not_a_validation_error(self) -> None:
        # Missing dependencies are an analysis finding (DEP-001), not a schema error.
        inv = inventory([asset("db-a", deps=["ghost-system"])])
        assert inv.asset("db-a").depends_on == ["ghost-system"]

    def test_unknown_evidence_reference(self) -> None:
        with pytest.raises(ValidationError, match="unknown evidence"):
            inventory([repo(), asset("db-a", points=[point("RP-A-1", 1, evidence=["EV-NOPE"])])])

    def test_evidence_for_unknown_asset(self) -> None:
        with pytest.raises(ValidationError, match="unknown asset"):
            inventory([asset("db-a")], [ev("EV-01", "ghost")])

    def test_evidence_for_unknown_point(self) -> None:
        with pytest.raises(ValidationError, match="unknown recovery point"):
            inventory([asset("db-a")], [ev("EV-01", "db-a", rp="RP-NOPE")])

    def test_repository_block_rules(self) -> None:
        bad_repo = repo()
        del bad_repo["repository"]
        with pytest.raises(ValidationError, match="requires a 'repository' block"):
            inventory([bad_repo])
        not_repo = asset("db-a", repository={"immutability": "none"})
        with pytest.raises(ValidationError, match="only valid for backup repositories"):
            inventory([not_repo])

    def test_duration_requires_basis(self) -> None:
        a = asset("db-a")
        a["backup"]["restore_duration_basis"] = None
        with pytest.raises(ValidationError, match="provided together"):
            inventory([a])

    def test_negative_rpo_rejected(self) -> None:
        with pytest.raises(ValidationError):
            inventory([asset("db-a", rpo=-5)])


class TestScenarioValidation:
    def _scenario(self, **over: object) -> dict[str, object]:
        base: dict[str, object] = {
            "id": "SCN-T-TEST",
            "code": "T",
            "title": "t",
            "category": "c",
            "narrative": "n",
            "severity": "high",
            "incident_at": "2026-01-10T12:00:00Z",
            "injections": [
                {"type": "compromise_assets", "at": "2026-01-10T11:00:00Z", "asset_ids": ["db-a"], "description": "d"}
            ],
        }
        base.update(over)
        return base

    def test_valid(self) -> None:
        assert Scenario.model_validate(self._scenario()).code == "T"

    def test_injection_after_incident_rejected(self) -> None:
        data = self._scenario(
            injections=[
                {"type": "compromise_assets", "at": "2026-01-10T13:00:00Z", "asset_ids": ["db-a"], "description": "d"}
            ]
        )
        with pytest.raises(ValidationError, match="after incident_at"):
            Scenario.model_validate(data)

    def test_unknown_injection_type(self) -> None:
        data = self._scenario(injections=[{"type": "rm_rf", "at": "2026-01-10T11:00:00Z", "description": "d"}])
        with pytest.raises(ValidationError, match="rm_rf"):
            Scenario.model_validate(data)

    def test_trusted_before_after_incident(self) -> None:
        with pytest.raises(ValidationError, match="trusted_before"):
            Scenario.model_validate(self._scenario(trusted_before="2026-01-11T00:00:00Z"))

    def test_empty_injections_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Scenario.model_validate(self._scenario(injections=[]))


class TestLoader:
    def test_path_traversal_blocked(self, tmp_path: Path) -> None:
        with pytest.raises(InputError, match="outside the allowed"):
            safe_path(tmp_path, "../../etc/passwd")
        with pytest.raises(InputError, match="outside the allowed"):
            safe_path(tmp_path, "/etc/passwd")

    def test_symlink_escape_blocked(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside.json"
        outside.write_text("{}")
        base = tmp_path / "base"
        base.mkdir()
        (base / "link.json").symlink_to(outside)
        with pytest.raises(InputError, match="outside the allowed"):
            load_model(base, "link.json", Inventory)

    def test_non_json_extension(self, tmp_path: Path) -> None:
        (tmp_path / "x.yaml").write_text("a: 1")
        with pytest.raises(InputError, match=r"not a \.json file"):
            load_model(tmp_path, "x.yaml", Inventory)

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(InputError, match="does not exist"):
            load_model(tmp_path, "nope.json", Inventory)

    def test_oversized_input(self) -> None:
        with pytest.raises(InputError, match="larger than"):
            parse_model(b" " * (MAX_INPUT_BYTES + 1), Inventory)

    def test_oversized_file(self, tmp_path: Path) -> None:
        (tmp_path / "big.json").write_bytes(b" " * (MAX_INPUT_BYTES + 1))
        with pytest.raises(InputError, match="larger than"):
            load_model(tmp_path, "big.json", Inventory)

    def test_invalid_json(self) -> None:
        with pytest.raises(InputError, match="not valid JSON"):
            parse_model("{not json", Inventory)

    def test_invalid_utf8(self) -> None:
        with pytest.raises(InputError, match="UTF-8"):
            parse_model(b"\xff\xfe\x00", Inventory)

    def test_top_level_must_be_object(self) -> None:
        with pytest.raises(InputError, match="JSON object"):
            parse_model("[1, 2]", Inventory)

    def test_validation_errors_are_readable(self) -> None:
        with pytest.raises(InputError) as exc:
            parse_model(
                json.dumps({"organization": "x", "as_of": "2026-01-01T00:00:00Z", "assets": [{"id": "BAD"}]}),
                Inventory,
                label="upload.json",
            )
        msg = str(exc.value)
        assert msg.startswith("upload.json failed validation")
        assert "assets.0.id" in msg

    def test_validation_error_list_is_truncated(self) -> None:
        bad_assets = [{"id": f"BAD{i}"} for i in range(10)]
        with pytest.raises(InputError, match=r"more error"):
            parse_model(
                json.dumps({"organization": "x", "as_of": "2026-01-01T00:00:00Z", "assets": bad_assets}), Inventory
            )

    def test_malformed_scenario_file(self, tmp_path: Path) -> None:
        (tmp_path / "scenarios").mkdir()
        (tmp_path / "scenarios" / "bad.json").write_text('{"id": "SCN-X", "code": "X"}')
        with pytest.raises(InputError, match="failed validation"):
            load_scenarios(tmp_path)

    def test_duplicate_scenario_ids(self, tmp_path: Path, scenarios: dict[str, Scenario]) -> None:
        d = tmp_path / "scenarios"
        d.mkdir()
        payload = scenarios["A"].model_dump_json()
        (d / "one.json").write_text(payload)
        (d / "two.json").write_text(payload)
        with pytest.raises(InputError, match="duplicate scenario ids"):
            load_scenarios(tmp_path)

    def test_bundled_scenarios_load_in_code_order(self, scenarios: dict[str, Scenario]) -> None:
        assert list(scenarios) == list("ABCDEFGHIJ")


class TestTime:
    def test_to_utc_rejects_naive(self) -> None:
        with pytest.raises(ValueError, match="timezone"):
            to_utc(datetime(2026, 1, 1))

    def test_minutes_between_across_offsets(self) -> None:
        a = datetime(2026, 1, 1, 10, 0, tzinfo=timezone(timedelta(hours=2)))  # 08:00 UTC
        b = datetime(2026, 1, 1, 8, 45, tzinfo=timezone.utc)  # noqa: UP017
        assert minutes_between(a, b) == 45
        assert minutes_between(b, a) == -45

    def test_minutes_floor(self) -> None:
        a = datetime(2026, 1, 1, 8, 0, tzinfo=timezone.utc)  # noqa: UP017
        assert minutes_between(a, a + timedelta(seconds=119)) == 1

    @pytest.mark.parametrize(
        ("minutes", "text"),
        [
            (None, "Unknown"),
            (0, "0 min"),
            (45, "45 min"),
            (60, "1 h"),
            (135, "2 h 15 min"),
            (1440, "1 d"),
            (1500, "1 d 1 h"),
            (1575, "1 d 2 h 15 min"),
            (1441, "1 d 1 min"),
            (-90, "-1 h 30 min"),
        ],
    )
    def test_fmt_minutes(self, minutes: int | None, text: str) -> None:
        assert fmt_minutes(minutes) == text

    def test_fmt_ts(self) -> None:
        dt = datetime(2026, 1, 1, 10, 0, tzinfo=timezone(timedelta(hours=2)))
        assert fmt_ts(dt) == "2026-01-01 08:00 UTC"
        assert fmt_ts(None) == "Unknown"
