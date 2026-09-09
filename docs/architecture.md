# Architecture

## Purpose

This project models a defensive GCP posture-assessment pipeline using synthetic inventory. It is designed to demonstrate cloud-security engineering patterns without connecting to live tenants or production APIs.

## Components

1. **Inventory layer** — JSON records represent Cloud Storage, IAM bindings, service accounts, VPC firewall rules, Cloud SQL, and project logging configuration.
2. **Domain model** — `src/models.py` defines findings, severity weighting, assessment state, and validation helpers.
3. **Control catalog** — `src/controls.py` implements independent, explainable controls.
4. **Assessment engine** — `src/assessor.py` applies controls to inventory and produces posture metrics.
5. **Reporting layer** — `src/reporting.py` converts findings into recruiter- and stakeholder-readable Markdown.
6. **CLI** — `src/cli.py` supports repeatable local assessment and report generation.
7. **Quality gate** — unit tests and GitHub Actions validate expected control behavior.

## Trust boundaries

- The repository never authenticates to Google Cloud.
- All inventory is explicitly synthetic.
- Findings are configuration-risk indicators, not claims of compromise.
- ATT&CK mappings are contextual references showing how weaknesses may relate to adversary behaviors.

## Production extension points

A production implementation could add authenticated collectors using least-privilege read-only service identities, Cloud Asset Inventory exports, Security Command Center findings, organization-policy evaluation, encrypted evidence storage, exception workflows, and ticketing integration. Those integrations are intentionally excluded here to avoid credentials and production targeting.
