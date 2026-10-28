"""Reports, exports, remediation lifecycle, audit trail and CLI."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pypdf import PdfReader

from recoveryproof.audit import AuditLog
from recoveryproof.cli import main
from recoveryproof.compare import compare
from recoveryproof.engine import analyze
from recoveryproof.remediation import RemediationError, RemediationTracker, VerificationRecord
from recoveryproof.reporting import export_findings_json, export_full_json, export_plan_json, render_html, render_pdf
from recoveryproof.reporting.common import recovery_estimate_text
from recoveryproof.results import AnalysisResult
from tests.helpers import asset, inventory


class TestReports:
    @pytest.mark.parametrize("code", ["BL", "A", "B", "C", "D", "E"])
    def test_html_agrees_with_analysis(self, code: str, results: dict[str, AnalysisResult]) -> None:
        r = results[code]
        html = render_html(r)
        assert f"{r.metrics.readiness_score:g} / 100" in html
        assert r.scenario_id in html
        assert recovery_estimate_text(r).split(";")[0] in html
        for f in r.findings:
            assert f.id in html
        for s in r.plan.steps:
            assert s.name.replace("&", "&amp;") in html

    def test_html_escapes_untrusted_input(self) -> None:
        evil = asset("db-a", backup=False)
        evil["name"] = "<script>alert('x')</script>"
        html = render_html(analyze(inventory([evil])))
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    @pytest.mark.parametrize("code", ["BL", "B", "D"])
    def test_pdf_is_valid_and_agrees(self, code: str, results: dict[str, AnalysisResult]) -> None:
        r = results[code]
        pdf = render_pdf(r)
        assert pdf.startswith(b"%PDF-")
        reader = PdfReader(io.BytesIO(pdf))
        assert len(reader.pages) >= 3
        text = "\n".join(page.extract_text() for page in reader.pages)
        assert f"Recovery readiness is {r.metrics.readiness_score:g}/100" in text
        assert r.scenario_id in text

    def test_json_exports(self, results: dict[str, AnalysisResult]) -> None:
        r = results["D"]
        findings = json.loads(export_findings_json(r))
        assert findings["format"] == "recoveryproof.findings"
        assert [f["id"] for f in findings["findings"]] == [f.id for f in r.findings]
        assert len(findings["recommendations"]) == len(r.findings)
        plan = json.loads(export_plan_json(r))
        assert plan["recovery_plan"]["blocked_assets"] == ["app-orders-api", "db-orders"]
        full = AnalysisResult.model_validate_json(export_full_json(r))
        assert full == r  # lossless round trip

    def test_compare_metrics_direction(self, results: dict[str, AnalysisResult]) -> None:
        diff = compare(results["BL"], results["B"])
        readiness = next(m for m in diff.metrics if m.label == "Readiness score")
        assert readiness.worse is True
        same = compare(results["BL"], results["BL"])
        assert all(m.worse is None for m in same.metrics) and not same.asset_changes


class TestAuditAndRemediation:
    def test_audit_chain_and_tamper_detection(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        log.append("scenario.run", {"scenario": "A"})
        log.append("report.export", {"format": "pdf", "api_key": "should-not-appear"})
        assert log.verify() == (True, "chain intact")
        raw = (tmp_path / "audit.jsonl").read_text()
        assert "should-not-appear" not in raw and "[REDACTED]" in raw
        lines = raw.splitlines()
        lines[0] = lines[0].replace('"A"', '"B"')
        (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
        ok, msg = log.verify()
        assert not ok and "modified" in msg

    def test_audit_detects_deleted_entry(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        for i in range(3):
            log.append("x", {"i": i})
        lines = (tmp_path / "audit.jsonl").read_text().splitlines()
        (tmp_path / "audit.jsonl").write_text("\n".join([lines[0], lines[2]]) + "\n")
        assert not log.verify()[0]

    def test_resolution_requires_verification(self, tmp_path: Path) -> None:
        audit = AuditLog(tmp_path / "audit.jsonl")
        tracker = RemediationTracker(tmp_path / "rem.json", audit)
        tracker.transition("F-RP-005-db-a", "acknowledged", note="scheduled")
        with pytest.raises(RemediationError, match="verification record"):
            tracker.transition("F-RP-005-db-a", "resolved")
        rec = VerificationRecord(
            verified_by="j.doe",
            method="Restore test in isolated VPC",
            evidence_reference="EV-RST-NEW",
            verified_at=datetime(2026, 10, 21, tzinfo=UTC),
        )
        entry = tracker.transition("F-RP-005-db-a", "resolved", verification=rec)
        assert entry.status == "resolved" and entry.verification == rec
        reloaded = RemediationTracker(tmp_path / "rem.json")
        assert reloaded.status("F-RP-005-db-a").status == "resolved"  # type: ignore[union-attr]
        assert [e.action for e in audit.entries()] == ["remediation.acknowledged", "remediation.resolved"]

    def test_invalid_transitions(self, tmp_path: Path) -> None:
        tracker = RemediationTracker(tmp_path / "rem.json")
        with pytest.raises(RemediationError, match="already 'open'"):
            tracker.transition("F-X", "open")
        tracker.transition("F-X", "acknowledged")
        tracker.transition("F-X", "open")
        assert tracker.all()["F-X"].status == "open"

    def test_verification_record_validation(self) -> None:
        with pytest.raises(ValueError, match="at least"):
            VerificationRecord(verified_by="j", method="x", evidence_reference="y", verified_at=datetime.now(UTC))


class TestCli:
    def test_scenarios_and_analyze(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["scenarios"]) == 0
        assert "SCN-A-RANSOMWARE-INTACT" in capsys.readouterr().out
        assert main(["analyze", "--scenario", "C", "--check"]) == 0
        out = capsys.readouterr().out
        assert "[FAIL]" not in out and "readiness" in out

    @pytest.mark.parametrize("fmt", ["html", "pdf", "json", "findings-json", "plan-json"])
    def test_report_formats(self, fmt: str, tmp_path: Path) -> None:
        out = tmp_path / f"r.{fmt}"
        assert main(["report", "--scenario", "D", "--format", fmt, "--out", str(out)]) == 0
        assert out.stat().st_size > 500

    def test_unknown_scenario(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["analyze", "--scenario", "Z"]) == 2
        assert "unknown scenario" in capsys.readouterr().err


def test_compare_does_not_claim_rto_improvement_across_plan_scopes(results: dict[str, AnalysisResult]) -> None:
    diff = compare(results["BL"], results["C"])  # full rehearsal vs. only db-orders restored
    rto = next(m for m in diff.metrics if m.label.startswith("Unmet RTO"))
    assert rto.worse is None and "different plan scopes" in rto.label
    assert diff.scope_note and "not compared" in diff.scope_note
    assert not any(fid.startswith("F-RTO-001") for fid in diff.cleared_findings + diff.new_findings)
    assert "F-RTO-001-db-customers" in diff.not_comparable_findings
    same_scope = compare(results["A"], results["F"])  # both restore the same six systems
    assert same_scope.scope_note is None
