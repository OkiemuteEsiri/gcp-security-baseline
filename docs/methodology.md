# Assessment Methodology

## Scope

The baseline focuses on a deliberately small but high-signal set of GCP control families: IAM, storage, network exposure, managed database exposure, and audit logging.

## Control design principles

- **Explainable:** every finding includes evidence and a remediation recommendation.
- **Deterministic:** identical inventory produces identical findings.
- **Fail closed on malformed in-scope records:** required fields are validated rather than silently ignored.
- **Context-aware:** severity changes when exposure or privilege materially increases risk.
- **Non-invasive:** no live scanning, exploitation, or tenant authentication is performed.

## Risk model

Severity weighting is used only for portfolio-level posture summarization:

- Critical: 10
- High: 7
- Medium: 4
- Low: 1

The posture score starts from 100 and applies a normalized penalty based on the number and severity of findings relative to the implemented control catalog. The score is intentionally transparent and should not be interpreted as a probabilistic breach prediction.

## Control families

### Identity and access management
- user-managed service account keys
- primitive Owner/Editor grants
- external principals with high-impact roles

### Storage
- public buckets
- uniform bucket-level access

### Network
- internet-exposed SSH/RDP firewall rules

### Data services
- Cloud SQL public IP and unrestricted authorized networks

### Logging
- Admin Activity retention/export coverage
- Data Access logging visibility

## ATT&CK context

Relevant findings may reference:
- T1078.004 — Cloud Accounts
- T1098 — Account Manipulation
- T1552.001 — Credentials In Files
- T1133 — External Remote Services
- T1021 — Remote Services
- T1190 — Exploit Public-Facing Application
- T1530 — Data from Cloud Storage
- T1562.008 — Disable or Modify Cloud Logs

These mappings describe possible adversary relevance; they are not evidence that those techniques occurred.

## Remediation and validation workflow

1. Confirm the asset, owner, and business purpose.
2. Validate whether the finding is intended or exception-backed.
3. Apply least-privilege or exposure-reduction remediation.
4. Re-run the assessment against updated inventory.
5. Confirm the specific control no longer produces a finding.
6. Record residual risk and any approved exception expiry date.
7. For material changes, validate application connectivity and logging after remediation.

## Limitations

This lab does not evaluate every CIS Google Cloud Benchmark control, organization policies, Kubernetes posture, Secret Manager, KMS rotation, VPC Service Controls, SCC configuration, or live IAM inheritance. It is a focused engineering demonstration rather than a certification scanner.
