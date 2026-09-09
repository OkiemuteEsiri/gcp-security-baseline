from __future__ import annotations

from typing import Any, Callable

from .models import AssessmentResult, Finding, require_fields


Control = Callable[[dict[str, Any], AssessmentResult], None]


def _project(record: dict[str, Any]) -> str:
    return str(record.get("project_id", "unknown-project"))


def check_public_storage(record: dict[str, Any], result: AssessmentResult) -> None:
    control_id = "GCP-STO-001"
    if record.get("type") != "storage_bucket":
        return
    require_fields(record, ("name", "project_id", "public"), control_id)
    result.mark_evaluated(control_id)
    if record["public"]:
        result.add(Finding(
            control_id=control_id,
            title="Public Cloud Storage bucket",
            severity="high",
            resource=record["name"],
            project_id=_project(record),
            evidence="Bucket is marked public in the synthetic inventory.",
            recommendation="Remove public principals, enforce uniform bucket-level access, and validate business-required sharing through approved controls.",
            attack_techniques=("T1530",),
        ))


def check_bucket_access_model(record: dict[str, Any], result: AssessmentResult) -> None:
    control_id = "GCP-STO-002"
    if record.get("type") != "storage_bucket":
        return
    require_fields(record, ("name", "project_id", "uniform_bucket_level_access"), control_id)
    result.mark_evaluated(control_id)
    if not record["uniform_bucket_level_access"]:
        result.add(Finding(
            control_id=control_id,
            title="Uniform bucket-level access disabled",
            severity="medium",
            resource=record["name"],
            project_id=_project(record),
            evidence="Legacy object ACL behavior remains available.",
            recommendation="Enable uniform bucket-level access and migrate exceptions to IAM-based authorization.",
        ))


def check_service_account_keys(record: dict[str, Any], result: AssessmentResult) -> None:
    control_id = "GCP-IAM-001"
    if record.get("type") != "service_account":
        return
    require_fields(record, ("name", "project_id", "user_managed_keys"), control_id)
    result.mark_evaluated(control_id)
    keys = int(record["user_managed_keys"])
    if keys > 0:
        severity = "high" if keys > 1 else "medium"
        result.add(Finding(
            control_id=control_id,
            title="User-managed service account keys present",
            severity=severity,
            resource=record["name"],
            project_id=_project(record),
            evidence=f"Synthetic inventory reports {keys} user-managed key(s).",
            recommendation="Prefer short-lived workload identity; rotate and remove unnecessary long-lived service account keys.",
            attack_techniques=("T1552.001", "T1078.004"),
        ))


def check_overprivileged_iam(record: dict[str, Any], result: AssessmentResult) -> None:
    control_id = "GCP-IAM-002"
    if record.get("type") != "iam_binding":
        return
    require_fields(record, ("name", "project_id", "role", "members"), control_id)
    result.mark_evaluated(control_id)
    broad_roles = {"roles/owner", "roles/editor"}
    if record["role"] in broad_roles:
        result.add(Finding(
            control_id=control_id,
            title="Broad primitive IAM role assigned",
            severity="high",
            resource=record["name"],
            project_id=_project(record),
            evidence=f"Binding grants {record['role']} to {len(record['members'])} principal(s).",
            recommendation="Replace primitive roles with least-privilege predefined or custom roles and validate access through role review.",
            attack_techniques=("T1098", "T1078.004"),
        ))


def check_external_admin_member(record: dict[str, Any], result: AssessmentResult) -> None:
    control_id = "GCP-IAM-003"
    if record.get("type") != "iam_binding":
        return
    require_fields(record, ("name", "project_id", "role", "members", "approved_domains"), control_id)
    result.mark_evaluated(control_id)
    if record["role"] not in {"roles/owner", "roles/editor", "roles/resourcemanager.projectIamAdmin"}:
        return
    approved = tuple(record["approved_domains"])
    external = [member for member in record["members"] if "@" in member and not member.endswith(approved)]
    if external:
        result.add(Finding(
            control_id=control_id,
            title="External principal holds high-impact IAM role",
            severity="critical",
            resource=record["name"],
            project_id=_project(record),
            evidence=f"High-impact role includes {len(external)} principal(s) outside approved domains.",
            recommendation="Validate business need, remove unnecessary external administrative access, and enforce domain-restricted sharing where appropriate.",
            attack_techniques=("T1078.004",),
        ))


def check_firewall_admin_exposure(record: dict[str, Any], result: AssessmentResult) -> None:
    control_id = "GCP-NET-001"
    if record.get("type") != "firewall_rule":
        return
    require_fields(record, ("name", "project_id", "source_ranges", "allowed_ports"), control_id)
    result.mark_evaluated(control_id)
    internet = "0.0.0.0/0" in record["source_ranges"] or "::/0" in record["source_ranges"]
    admin_ports = {22, 3389}
    exposed = admin_ports.intersection({int(port) for port in record["allowed_ports"]})
    if internet and exposed:
        result.add(Finding(
            control_id=control_id,
            title="Administrative service exposed to the internet",
            severity="critical",
            resource=record["name"],
            project_id=_project(record),
            evidence=f"Internet source range permits administrative port(s): {sorted(exposed)}.",
            recommendation="Remove direct internet administration, use IAP/VPN/bastion patterns, and restrict source ranges to approved management paths.",
            attack_techniques=("T1133", "T1021"),
        ))


def check_sql_public_ip(record: dict[str, Any], result: AssessmentResult) -> None:
    control_id = "GCP-DB-001"
    if record.get("type") != "cloud_sql":
        return
    require_fields(record, ("name", "project_id", "public_ip", "authorized_networks"), control_id)
    result.mark_evaluated(control_id)
    if record["public_ip"]:
        severity = "critical" if "0.0.0.0/0" in record["authorized_networks"] else "high"
        result.add(Finding(
            control_id=control_id,
            title="Cloud SQL instance uses public IP",
            severity=severity,
            resource=record["name"],
            project_id=_project(record),
            evidence=f"Public IP enabled; authorized networks: {record['authorized_networks']}.",
            recommendation="Prefer private IP connectivity and narrowly scoped authorized networks; validate application connectivity after migration.",
            attack_techniques=("T1190",),
        ))


def check_audit_logging(record: dict[str, Any], result: AssessmentResult) -> None:
    control_id = "GCP-LOG-001"
    if record.get("type") != "project_logging":
        return
    require_fields(record, ("name", "project_id", "admin_activity", "data_access", "sink_enabled"), control_id)
    result.mark_evaluated(control_id)
    if not record["admin_activity"] or not record["sink_enabled"]:
        result.add(Finding(
            control_id=control_id,
            title="Core audit logging coverage incomplete",
            severity="high",
            resource=record["name"],
            project_id=_project(record),
            evidence=f"admin_activity={record['admin_activity']}, sink_enabled={record['sink_enabled']}.",
            recommendation="Ensure Admin Activity logging is retained and export security-relevant logs to a protected centralized sink.",
            attack_techniques=("T1562.008",),
        ))
    elif not record["data_access"]:
        result.add(Finding(
            control_id=control_id,
            title="Data Access audit logging disabled",
            severity="medium",
            resource=record["name"],
            project_id=_project(record),
            evidence="Data Access audit logging is disabled in the synthetic baseline record.",
            recommendation="Enable appropriate Data Access logs for high-value services, balancing security visibility, volume, and cost.",
            attack_techniques=("T1562.008",),
        ))


CONTROLS: tuple[Control, ...] = (
    check_public_storage,
    check_bucket_access_model,
    check_service_account_keys,
    check_overprivileged_iam,
    check_external_admin_member,
    check_firewall_admin_exposure,
    check_sql_public_ip,
    check_audit_logging,
)
