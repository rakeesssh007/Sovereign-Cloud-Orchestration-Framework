# Sovereign Cloud Orchestration Framework (SCOF)

An AWS Terraform Policy-as-Code compliance framework. A shared Rego/OPA policy library enforces selected technical controls derived from India's DPDP Act, relevant RBI requirements and GDPR, through:

- a developer-side CLI linter with lightweight VS Code feedback, and
- a GitHub Actions pull-request gate that evaluates Terraform plan JSON with OPA/Conftest.

Status: work in progress.

## Repository layout

| Folder | Purpose |
|---|---|
| `policies/` | Shared Rego policy library |
| `tests/` | Compliant and non-compliant fixtures |
| `terraform/` | Terraform reference configurations (S3, RDS, EC2, KMS, IAM) |
| `router/` | Jurisdiction/sector policy routing |
| `cli/` | Developer CLI compliance linter |
| `vscode/` | Lightweight VS Code integration |
| `.github/workflows/` | CI/CD compliance gate |
| `experiments/` | Latency and accuracy evaluation |
| `docs/` | Architecture, regulation mapping, methodology |
