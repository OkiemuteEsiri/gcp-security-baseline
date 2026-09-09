# GCP Security Baseline

A recruiter-facing **Cloud Security Engineering** project that evaluates a realistic synthetic Google Cloud inventory against an explainable defensive security baseline. The project demonstrates how cloud posture findings can be normalized, prioritized, reported, remediated, and revalidated without connecting to a live tenant.

> **Safety boundary:** this repository uses synthetic data only. It performs no live tenant scanning, exploitation, credential collection, or production targeting.

## Problem statement

Cloud environments accumulate risk through excessive IAM permissions, long-lived credentials, public storage, exposed administrative services, public database paths, and incomplete audit visibility. Native controls can identify individual weaknesses, but security teams still need a repeatable engineering workflow that converts configuration state into prioritized findings and clear remediation actions.

This repository implements that workflow as code.

## What the project demonstrates

- defensive GCP configuration assessment
- explainable security-control engineering
- IAM and service-account key governance
- Cloud Storage exposure analysis
- VPC firewall review
- Cloud SQL exposure analysis
- audit-logging posture checks
- severity-weighted posture scoring
- ATT&CK-aligned security context
- synthetic evidence handling
- remediation and revalidation methodology
- automated unit testing and report-generation smoke tests
- least-privilege GitHub Actions permissions

## Architecture

```text
Synthetic GCP Inventory
        |
        v
  Record Validation
        |
        v
 Security Control Catalog
        |
        v
 Assessment Engine
   |            |
   v            v
Findings     Posture Metrics
   |            |
   +------v-----+
          |
          v
   Markdown Reporting
          |
          v
 Remediation / Revalidation
```

Implementation details are documented in [`docs/architecture.md`](docs/architecture.md).

## Repository structure

```text
.github/workflows/ci.yml     CI security and quality checks
data/synthetic_inventory.json
src/models.py                domain model and severity weighting
src/controls.py              GCP security controls
src/assessor.py              assessment and summarization engine
src/reporting.py             Markdown report rendering
src/cli.py                   command-line interface
tests/test_assessor.py       unit tests
docs/architecture.md         component and trust-boundary design
docs/methodology.md          risk, ATT&CK, remediation methodology
reports/example-assessment.md
```

## Implemented controls

| ID | Domain | Control | Typical risk |
|---|---|---|---|
| GCP-STO-001 | Storage | Public bucket detection | High |
| GCP-STO-002 | Storage | Uniform bucket-level access | Medium |
| GCP-IAM-001 | IAM | User-managed service-account keys | Medium–High |
| GCP-IAM-002 | IAM | Primitive Owner/Editor role use | High |
| GCP-IAM-003 | IAM | External high-impact administrator | Critical |
| GCP-NET-001 | Network | Internet-exposed SSH/RDP | Critical |
| GCP-DB-001 | Database | Cloud SQL public connectivity | High–Critical |
| GCP-LOG-001 | Logging | Audit logging coverage | Medium–High |

## Usage

Requires Python 3.11+ and uses only the Python standard library.

```bash
python -m unittest discover -s tests -v
python -m src.cli data/synthetic_inventory.json
python -m src.cli data/synthetic_inventory.json --output reports/generated-assessment.md
```

## Risk model

The project uses a deliberately transparent scoring approach rather than a black-box model:

- Critical finding weight: 10
- High: 7
- Medium: 4
- Low: 1

A 100-point baseline is reduced by a normalized severity penalty. The score is useful for consistent portfolio-level comparison, but it is **not** represented as a breach probability or compliance certification.

## MITRE ATT&CK context

Where technically relevant, findings include ATT&CK references such as:

- **T1078.004 — Cloud Accounts**
- **T1098 — Account Manipulation**
- **T1552.001 — Credentials In Files**
- **T1133 — External Remote Services**
- **T1021 — Remote Services**
- **T1190 — Exploit Public-Facing Application**
- **T1530 — Data from Cloud Storage**
- **T1562.008 — Disable or Modify Cloud Logs**

These mappings indicate adversary relevance only; they do not claim that an attack occurred.

## Methodology

The workflow follows six stages:

1. normalize and validate the inventory;
2. evaluate independent security controls;
3. assign risk based on observable configuration context;
4. produce evidence-backed findings;
5. remediate using least privilege and exposure reduction;
6. re-run the assessment to verify the control no longer fails.

See [`docs/methodology.md`](docs/methodology.md) for detailed design decisions, validation logic, limitations, and remediation guidance.

## Example assessment

The included synthetic scenario intentionally contains several material weaknesses: unrestricted administrative ingress, externally privileged IAM, public Cloud SQL connectivity, public storage, long-lived service-account keys, and incomplete data-access logging.

The example executive report in [`reports/example-assessment.md`](reports/example-assessment.md) shows how those weaknesses are prioritized and translated into validation criteria.

## CI/CD security controls

The GitHub Actions workflow:

- uses read-only repository permissions;
- runs the complete `unittest` suite;
- performs a synthetic end-to-end CLI/report smoke test;
- introduces no cloud credentials or external tenant access.

A workflow file being present does not itself prove CI success; workflow status should be checked separately for the relevant commit.

## Design decisions

### Deterministic findings
Identical synthetic inventory produces identical findings, making remediation validation and regression testing straightforward.

### Required-field validation
Malformed in-scope records fail explicitly instead of silently producing false assurance.

### Independent controls
Each security control can evolve without coupling assessment logic to a specific provider SDK.

### Evidence before conclusions
Findings describe observed configuration state. They do not claim exploit success, compromise, or unauthorized access.

## Limitations

This is not a full CIS Google Cloud Benchmark implementation and does not currently cover every organization-policy, GKE, KMS, Secret Manager, VPC Service Controls, SCC, IAM-inheritance, or data-residency control. It also intentionally excludes authenticated collectors and production remediation automation.

## Skills demonstrated

- Google Cloud security concepts
- cloud IAM governance
- security-control engineering
- secure Python design
- configuration-risk analysis
- ATT&CK mapping
- test-driven defensive tooling
- technical documentation
- executive security reporting
- remediation validation
- DevSecOps quality gates

## Roadmap

- add organization-policy controls
- add GKE posture assessment
- add KMS/Secret Manager controls
- model IAM inheritance and effective privilege
- add exception-expiry governance
- add SARIF/JSON output formats
- add policy-as-code examples
- add optional read-only Cloud Asset Inventory adapter with strict credential safeguards

## Ethical use

Use this repository only for authorized security engineering, training, defensive assessment, and portfolio demonstration. The supplied inventory is fictional and intentionally contains no employer, customer, or production data.
