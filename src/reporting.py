from __future__ import annotations

from .assessor import summarize
from .models import AssessmentResult


def render_markdown(result: AssessmentResult) -> str:
    summary = summarize(result)
    lines = [
        "# GCP Security Baseline Assessment",
        "",
        f"Posture score: **{summary['posture_score']}/100**",
        f"Total findings: **{summary['total_findings']}**",
        "",
        "## Severity summary",
        "",
    ]
    for severity, count in summary["severity_counts"].items():
        lines.append(f"- {severity.title()}: {count}")
    lines.extend(["", "## Findings", ""])
    if not result.findings:
        lines.append("No findings were identified in the supplied synthetic inventory.")
    for finding in sorted(result.findings, key=lambda item: item.weight, reverse=True):
        techniques = ", ".join(finding.attack_techniques) if finding.attack_techniques else "N/A"
        lines.extend([
            f"### {finding.control_id} — {finding.title}",
            "",
            f"- Severity: **{finding.severity.upper()}**",
            f"- Project: `{finding.project_id}`",
            f"- Resource: `{finding.resource}`",
            f"- ATT&CK context: {techniques}",
            f"- Evidence: {finding.evidence}",
            f"- Remediation: {finding.recommendation}",
            "",
        ])
    return "\n".join(lines)
