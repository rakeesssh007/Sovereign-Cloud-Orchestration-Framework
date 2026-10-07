# Sovereign Cloud Orchestration Framework (SCOF)

An AWS Terraform policy-as-code framework. One shared Rego/OPA policy library checks Terraform plan JSON against technical controls derived from India's DPDP Act and Rules, RBI directions and the GDPR. The same rules run in two places:

- a **developer-side CLI linter**, with diagnostics in VS Code through built-in tasks, and
- a **GitHub Actions pull-request gate** that evaluates plan JSON with OPA/Conftest and, with branch protection, keeps non-compliant changes from being merged.

A small **router** selects which controls apply, and which region allow-list is used, from a deployment's jurisdiction and sector.

**Status: research prototype.** The framework runs end to end. The evaluation (accuracy, false positives and negatives, latency) is still being completed, and the files in `experiments/` come from development fixtures only, not from the final evaluation.

> **Not legal advice.** The controls are technical interpretations of legal texts. They do not establish that a deployment is compliant. The sources, our interpretation, the Terraform attribute, the rule and the fixture for every control are recorded in [`docs/regulation-mapping/regulation_control_matrix.md`](docs/regulation-mapping/regulation_control_matrix.md).

## How it works

```text
Terraform code ---> scof_lint (CLI / VS Code task) --+
                                                     +--> shared Rego library --> OPA or Conftest --> violations
Pull request ---> terraform plan ---> plan JSON -----+
                  (GitHub Actions gate)
```

Both paths produce a Terraform plan as JSON and evaluate it with the same policy library, so a rule that passes in the editor passes in CI. More detail is in [`docs/architecture/architecture.md`](docs/architecture/architecture.md).

## Controls

| Control | What it checks | Notes |
|---|---|---|
| `REGION-RESTRICTION` | The AWS provider region is in the allow-list of the deployment context | India (finance) and EU lists; the region must be a literal value |
| `DATA-ENCRYPTION` | S3 uses KMS encryption, RDS storage is encrypted, EC2 root volumes are encrypted | |
| `KEY-OWNERSHIP` | Referenced KMS keys are customer-managed, not AWS-managed aliases | Our interpretation, not a legal requirement |
| `KEY-ROTATION` | `aws_kms_key` has rotation enabled | Our interpretation, not a legal requirement |
| `IAM-NO-WILDCARD-ADMIN` | No IAM policy allows all actions on all resources; no `AdministratorAccess` attachment | |
| `LOG-RETENTION` | CloudWatch log groups keep logs for at least 365 days (never-expire passes) | India contexts only |
| `ACCESS-EXPOSURE` | S3 public access block flags are all true; RDS is not publicly accessible | Detects explicit exposure only |
| `BACKUP-RESILIENCE` | RDS `backup_retention_period` is set explicitly to at least 1 | The 1-day threshold is our technical baseline, not a numeric requirement of any regulation |

Which controls run depends on the deployment context (`router/policy-routing/control_sets.json`):

| Context | Controls enabled |
|---|---|
| `india-finance` (India, finance sector) | all eight |
| `eu` (EU) | all except `LOG-RETENTION` |
| `india` | test-only: all except `REGION-RESTRICTION`. The router never produces it. |

Healthcare is not supported.

## Requirements

Terraform, OPA, Conftest and Python 3 on your `PATH`. CI uses Terraform 1.16.4, OPA 1.21.1, Conftest 0.71.0 and Python 3.14.

No AWS account or credentials are needed. Plans run with mock credentials and the provider's offline settings. Only downloading the AWS provider needs internet access. The provider version is pinned by the committed `.terraform.lock.hcl` files (hashicorp/aws 6.67.0, for `windows_amd64` and `linux_amd64`).

Optional: if the directory `C:\Work\Tools\tf-plugin-cache` exists, the tool uses it as a Terraform plugin cache. Change `PLUGIN_CACHE` in `cli/compliance-linter/scof_core.py` to use another location.

## Usage

### Lint a Terraform directory

```powershell
python cli/compliance-linter/scof_lint.py --dir tests/non_compliant/rds_unencrypted --context india-finance
```

Violations print as `file:line:column: error: [CONTROL] message`, followed by a summary line with stage timings. Exit code: 0 passed, 1 policy violations, 2 tooling error.

Useful options: `--engine opa|conftest` (default `opa`), `--format text|json|github`, `--plan <plan.json>` to evaluate an existing plan, `--save-plan <path>`, and `--watch` to re-lint whenever a `.tf` file changes.

### Resolve a deployment to a context

```powershell
python router/policy-routing/scof_router.py --jurisdiction india --sector finance --controls
python router/policy-routing/scof_router.py --jurisdiction eu --controls
python router/policy-routing/scof_router.py --list
```

The router fails closed: an unknown, missing or ambiguous deployment is an error, never a default context.

### VS Code

Open the repository root in VS Code, open a `.tf` file, then run **Terminal > Run Task > SCOF: watch this folder (save-time)** and choose a context. Violations appear in the editor and the Problems panel after each save. The tasks live in `.vscode/tasks.json`; the same file is kept in `vscode/lightweight-editor-integration/` for reuse in other repositories. Feedback is save-time, not as-you-type, because each run executes `terraform plan` and `terraform show`.

### Tests

```powershell
opa fmt --list policies
opa test policies
python -m unittest discover -s cli/compliance-linter -p "test_*.py"
python -m unittest discover -s router/policy-routing -p "test_*.py"
python scripts/run_manifest.py --engine both --refresh
python scripts/ci_gate.py --engine conftest
```

`run_manifest.py` runs every fixture in `tests/manifest.csv` through both engines and compares the result with the expected one, and with each other. `ci_gate.py` evaluates every deployable configuration under `terraform/` as the CI does.

## Continuous integration

`.github/workflows/compliance-gate.yml` runs three jobs on pull requests and pushes to `main`:

| Job (required check) | What it does |
|---|---|
| `Policy and tool tests` | Rego format, check and unit tests; Python tests |
| `Compliance gate` | Plans every configuration in `router/policy-routing/targets.json`, evaluates it with Conftest in its routed context, and fails on any violation |
| `Fixture self-test` | Runs all development fixtures through both engines and compares them with the manifest |

With branch protection requiring these checks, a change that violates a control cannot be merged. The gate blocks the merge, not `terraform apply`: this project never applies infrastructure, and OPA itself does not block `apply`.

## Repository layout

| Path | Purpose |
|---|---|
| `policies/` | Shared Rego library with unit tests |
| `router/policy-routing/` | Routing, region allow-lists, control sets, deployable targets, context files |
| `cli/compliance-linter/` | Linter and the shared result consumer `scof_core.py`, with tests |
| `.vscode/`, `vscode/` | VS Code tasks and problem matcher |
| `tests/` | Development fixtures (`compliant/`, `non_compliant/`) and `manifest.csv` |
| `terraform/` | Deployable reference configurations checked by the gate |
| `scripts/` | CI gate, manifest runner, message audit, watch-mode test |
| `experiments/` | Development-fixture results and latency collection (not the final evaluation) |
| `docs/` | Architecture and the regulation-to-control matrix |
| `.github/workflows/` | CI compliance gate |

## Limitations

- AWS only, eight controls over a small set of resource types: S3, RDS, EC2, KMS, IAM and CloudWatch log groups. This is a focused prototype and does not claim complete regulatory coverage.
- Several controls are interpretations without a legal requirement for the exact setting (see the matrix). DPDP Rules, Rule 6 comes into force about 13 May 2027.
- The detection is on plan JSON for the listed attributes. Values unknown at plan time are denied where the rule needs them, and some forms of exposure are not detected (for example public bucket policies).
- Healthcare routing is not implemented.
- Editor feedback takes the time of a Terraform plan; as-you-type feedback is not implemented.
