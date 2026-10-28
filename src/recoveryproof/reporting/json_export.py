"""Machine-readable JSON exports."""

from __future__ import annotations

import json
from typing import Any

from recoveryproof.results import AnalysisResult


def _envelope(result: AnalysisResult, kind: str, payload: dict[str, Any]) -> str:
    doc = {
        "format": f"recoveryproof.{kind}",
        "format_version": 1,
        "analysis_version": result.analysis_version,
        "generated_at": result.generated_at.isoformat(),
        "organization": result.organization,
        "data_source": result.data_source,
        "scenario_id": result.scenario_id,
        "scenario_title": result.scenario_title,
        "as_of": result.as_of.isoformat(),
        "incident_at": result.incident_at.isoformat(),
        **payload,
    }
    return json.dumps(doc, indent=2, default=str)


def export_findings_json(result: AnalysisResult) -> str:
    return _envelope(
        result,
        "findings",
        {
            "findings": [f.model_dump(mode="json") for f in result.findings],
            "recommendations": [r.model_dump(mode="json") for r in result.recommendations],
        },
    )


def export_plan_json(result: AnalysisResult) -> str:
    return _envelope(result, "recovery_plan", {"recovery_plan": result.plan.model_dump(mode="json")})


def export_full_json(result: AnalysisResult) -> str:
    return result.model_dump_json(indent=2)
