# Example GCP Security Baseline Assessment

> Synthetic example only. No production tenant, credentials, or client data are used.

## Executive summary

The synthetic environment contains several material posture weaknesses concentrated in internet exposure and identity governance. Highest-priority remediation is to remove unrestricted administrative access and public database connectivity, followed by reducing broad IAM roles and eliminating long-lived service-account keys.

## Representative findings

| Control | Severity | Resource | Risk |
|---|---|---|---|
| GCP-NET-001 | Critical | allow-admin-anywhere | SSH exposed to the internet |
| GCP-DB-001 | Critical | orders-db | Cloud SQL public IP with unrestricted network |
| GCP-IAM-003 | Critical | prod-editors | External principal with high-impact role |
| GCP-IAM-002 | High | prod-editors | Primitive Editor role in use |
| GCP-STO-001 | High | customer-export-archive | Public storage bucket |
| GCP-IAM-001 | High | legacy-ci service account | Multiple user-managed keys |
| GCP-LOG-001 | Medium | prod-audit-config | Data Access logging disabled |

## Remediation sequence

1. Remove unrestricted administrative ingress and move privileged administration to IAP/VPN-controlled paths.
2. Migrate Cloud SQL to private connectivity and validate application access.
3. Review the external privileged principal, remove unnecessary access, and replace primitive roles with least privilege.
4. Remove public storage access and enable uniform bucket-level authorization.
5. Replace long-lived service-account keys with workload identity or other short-lived authentication.
6. Enable appropriate Data Access logging for high-value services and validate centralized retention.

## Validation criteria

- No `0.0.0.0/0` or `::/0` exposure exists for SSH/RDP administration.
- Cloud SQL no longer relies on unrestricted public connectivity.
- No unapproved external principal retains Owner, Editor, or Project IAM Admin-like access.
- Public bucket access is removed and uniform bucket-level access is enabled.
- User-managed service-account keys are eliminated or formally justified and rotated.
- Required audit telemetry is present in the protected logging destination.
