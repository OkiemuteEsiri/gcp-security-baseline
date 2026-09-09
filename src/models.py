from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
}


@dataclass(frozen=True)
class Finding:
    control_id: str
    title: str
    severity: str
    resource: str
    project_id: str
    evidence: str
    recommendation: str
    attack_techniques: tuple[str, ...] = ()

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHTS[self.severity]


@dataclass
class AssessmentResult:
    findings: list[Finding] = field(default_factory=list)
    evaluated_controls: set[str] = field(default_factory=set)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.evaluated_controls.add(finding.control_id)

    def mark_evaluated(self, control_id: str) -> None:
        self.evaluated_controls.add(control_id)

    def counts_by_severity(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_WEIGHTS}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def posture_score(self, total_controls: int) -> int:
        """Return a bounded 0-100 posture score.

        The score is intentionally explainable rather than statistically derived.
        Findings subtract severity-weighted points from a 100-point baseline.
        """
        if total_controls <= 0:
            return 100
        penalty = sum(finding.weight for finding in self.findings)
        max_penalty = total_controls * SEVERITY_WEIGHTS["critical"]
        normalized_penalty = min(100.0, (penalty / max_penalty) * 100)
        return round(100 - normalized_penalty)


def require_fields(record: dict[str, Any], fields: tuple[str, ...], context: str) -> None:
    missing = [field for field in fields if field not in record]
    if missing:
        raise ValueError(f"{context} missing required fields: {', '.join(missing)}")
