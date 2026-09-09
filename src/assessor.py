from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .controls import CONTROLS
from .models import AssessmentResult


def assess_inventory(records: Iterable[dict[str, Any]]) -> AssessmentResult:
    result = AssessmentResult()
    for record in records:
        for control in CONTROLS:
            control(record, result)
    return result


def summarize(result: AssessmentResult) -> dict[str, object]:
    counts = result.counts_by_severity()
    return {
        "posture_score": result.posture_score(len(CONTROLS)),
        "total_findings": len(result.findings),
        "severity_counts": counts,
        "evaluated_controls": sorted(result.evaluated_controls),
        "critical_resources": sorted({
            finding.resource for finding in result.findings if finding.severity == "critical"
        }),
    }
