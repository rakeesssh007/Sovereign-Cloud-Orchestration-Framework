# Sovereign Cloud Orchestration Framework (SCOF)

An AWS Terraform policy-as-code framework. One shared Rego/OPA policy library checks Terraform plan JSON against technical controls derived from India's DPDP Act and Rules, RBI directions and the GDPR. The same rules run in two places:

- a **developer-side CLI linter**, with diagnostics in VS Code through built-in tasks, and
- a **GitHub Actions pull-request gate** that evaluates plan JSON with OPA and Conftest and, with branch protection, keeps non-compliant changes from being merged.

Every check runs on **both engines, OPA and Conftest, and passes only if their findings are identical**. If the engines disagree, or either one fails, the result is a tool error (exit code 2) and never a pass. This applies to the command line tool, the VS Code task and the pull request gate.

A small **router** selects which controls apply, and which region allow-list is used, from a deployment's jurisdiction and sector.

SCOF is a research prototype. It runs end to end, but it covers a focused set of controls and resource types and is not a complete compliance product.

> **Not legal advice.** The controls are technical interpretations of legal texts. They do not establish that a deployment is compliant. The sources, our interpretation, the Terraform attribute and the rule for every control are recorded in [`docs/regulation-mapping/regulation_control_matrix.md`](docs/regulation-mapping/regulation_control_matrix.md).

## How it works

```text
Terraform code ---> scof_lint (CLI / VS Code task) --+
                                                     +--> shared Rego library --> OPA and Conftest (must agree) --> violations
Pull request ---> terraform plan ---> plan JSON -----+
                  (GitHub Actions gate)
```

Both paths produce a Terraform plan as JSON and evaluate it with the same policy library, so a rule that passes in the editor passes in CI. More detail is in [`docs/architecture/architecture.md`](docs/architecture/architecture.md).

## Controls

| Control | What it checks | Notes |
|---|---|---|
| `REGION-RESTRICTION` | The AWS provider region is in the allow-list of the deployment context | India (finance) and EU lists; the region must be a literal value |
| `DATA-ENCRYPTION` | S3 buckets use KMS encryption; RDS storage, standalone EBS volumes and EC2 block devices are encrypted | |
| `KEY-OWNERSHIP` | Referenced KMS keys are customer-managed, not AWS-managed aliases | Our interpretation, not a legal requirement |
| `KEY-ROTATION` | `aws_kms_key` has rotation enabled | Our interpretation, not a legal requirement |
| `IAM-NO-WILDCARD-ADMIN` | No IAM policy allows all actions on all resources; no `AdministratorAccess` attachment | A policy that is unknown at plan time is denied |
| `LOG-RETENTION` | CloudWatch log groups keep logs for at least 365 days (never-expire passes) | India contexts only |
| `ACCESS-EXPOSURE` | S3 public access block flags are all true; RDS is not publicly accessible | Detects explicit exposure only |
| `BACKUP-RESILIENCE` | RDS `backup_retention_period` is set explicitly to at least 1 | The 1-day threshold is our technical baseline, not a numeric requirement of any regulation |

Which controls run depends on the deployment context (`router/policy-routing/control_sets.json`):

| Context | Controls enabled |
|---|---|
| `india-finance` (India, finance sector) | all eight |
| `eu` (EU) | all except `LOG-RETENTION` |
| `india-healthcare` (India, healthcare sector) | all except `REGION-RESTRICTION` |
| `india` (India, no sector) | all except `REGION-RESTRICTION` |

`india` is the sector-neutral India context, as `eu` is for the EU: a deployment in India without a sector gets the base controls and `LOG-RETENTION`, with no region allow-list. A sector is optional for India and EU; an unsupported sector is an error, not a silent fallback. No healthcare-specific control exists: `india-healthcare` applies the same controls as `india`.

## Requirements

Terraform, OPA, Conftest and Python 3 on your `PATH`. CI uses Terraform 1.16.4, OPA 1.21.1, Conftest 0.71.0 and Python 3.14.

If OPA or Conftest is missing, install the pinned versions (Windows, PowerShell; then open a new terminal):

```powershell
$bin = "$env:USERPROFILE\.scof\bin"; New-Item -ItemType Directory -Force $bin | Out-Null
Invoke-WebRequest https://github.com/open-policy-agent/opa/releases/download/v1.21.1/opa_windows_amd64.exe -OutFile "$bin\opa.exe"
Invoke-WebRequest https://github.com/open-policy-agent/conftest/releases/download/v0.71.0/conftest_0.71.0_Windows_x86_64.zip -OutFile "$bin\conftest.zip"
Expand-Archive "$bin\conftest.zip" -DestinationPath $bin -Force; Remove-Item "$bin\conftest.zip"
[Environment]::SetEnvironmentVariable("Path", "$([Environment]::GetEnvironmentVariable('Path','User'));$bin", "User")
```

Linux (macOS Apple silicon: use `opa_darwin_arm64` and `conftest_0.71.0_Darwin_arm64.tar.gz`):

```bash
mkdir -p ~/.local/bin
curl -sSfL -o ~/.local/bin/opa https://github.com/open-policy-agent/opa/releases/download/v1.21.1/opa_linux_amd64 && chmod +x ~/.local/bin/opa
curl -sSfL https://github.com/open-policy-agent/conftest/releases/download/v0.71.0/conftest_0.71.0_Linux_x86_64.tar.gz | tar -xz -C ~/.local/bin conftest
```

Check with `opa version` and `conftest --version`. Each release page also publishes SHA-256 checksums (`<file>.sha256` for OPA, `checksums.txt` for Conftest) if you want to verify the downloads. As an alternative to changing `PATH`, point `SCOF_OPA` and `SCOF_CONFTEST` at the executables.

No AWS account or credentials are needed. Plans always run with mock credentials and the provider's offline settings; any AWS credentials in your environment are ignored. Only downloading the AWS provider needs internet access. The provider version is pinned by the committed `.terraform.lock.hcl` files (hashicorp/aws 6.67.0, for `windows_amd64` and `linux_amd64`).

SCOF uses a shared Terraform plugin cache so the AWS provider (about 800 MB) is downloaded once. By default the cache is created at `~/.scof/tf-plugin-cache` on the first run; set `SCOF_TF_PLUGIN_CACHE` to use another directory. Once the cache holds the provider version pinned in a folder's `.terraform.lock.hcl`, SCOF points Terraform at that single copy (a Terraform `dev_overrides` setting, applied only to SCOF's own Terraform calls), so checked folders do not get their own copy. The first run in an empty cache installs the provider normally.

## Usage

### Lint a Terraform directory

```powershell
python cli/compliance-linter/scof_lint.py --dir <path-to-your-terraform-directory> --context <context>
```

`--dir` is the folder that holds your `.tf` files (run `terraform init` there once). `--context` is one of `india-finance`, `eu`, `india-healthcare` or `india`; it selects the controls and the region allow-list (see Controls). For example, a configuration that uses an India region reports a `REGION-RESTRICTION` violation under `eu`, which allows only EU regions.

Violations print as `file:line:column: error: [CONTROL] message`, followed by a summary line with stage timings. Exit code: 0 passed, 1 policy violations, 2 tooling error.

Useful options: `--engine both|opa|conftest` (default `both`: both engines must agree; `opa` or `conftest` run a single engine without the cross-check), `--format text|json|github`, `--plan <plan.json>` to evaluate an existing plan, `--save-plan <path>`, and `--watch` to re-lint whenever a `.tf` file changes.

### Resolve a deployment to a context

```powershell
python router/policy-routing/scof_router.py --jurisdiction india --sector finance --controls
python router/policy-routing/scof_router.py --jurisdiction eu --controls
python router/policy-routing/scof_router.py --jurisdiction india --controls
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
python scripts/verify_control_catalogue_hash.py
python scripts/ci_gate.py --engine both
```

`verify_control_catalogue_hash.py` checks the control catalogue: its content hash, that it has eight controls, and that each control's text is an exact copy of its section in the matrix. `ci_gate.py` evaluates every deployable configuration under `terraform/` as the CI does.

## Continuous integration

`.github/workflows/compliance-gate.yml` runs two jobs on pull requests and pushes to `main`:

| Job (required check) | What it does |
|---|---|
| `Policy and tool tests` | Rego check, format and unit tests; Python tests; control catalogue check |
| `Compliance gate` | Plans every configuration in `router/policy-routing/targets.json`, evaluates it with OPA and Conftest in its routed context, and fails on any violation or on any disagreement between the engines |

With branch protection requiring these checks, a change that violates a control cannot be merged. The gate blocks the merge, not `terraform apply`: this project never applies infrastructure, and OPA itself does not block `apply`.

## Repository layout

| Path | Purpose |
|---|---|
| `policies/` | Shared Rego library with unit tests |
| `router/policy-routing/` | Routing, known contexts, region allow-lists, control sets, deployable targets, context files |
| `cli/compliance-linter/` | Linter and the shared result consumer `scof_core.py`, with tests |
| `.vscode/`, `vscode/` | VS Code tasks and problem matcher |
| `terraform/` | Deployable reference configurations checked by the gate |
| `scripts/` | CI gate and control catalogue check |
| `docs/` | Architecture and the regulation-to-control matrix |
| `.github/workflows/` | CI compliance gate |

## Limitations

- AWS only, eight controls over a small set of resource types: S3, RDS, EC2, KMS, IAM and CloudWatch log groups. This is a focused prototype and does not claim complete regulatory coverage.
- Several controls are interpretations without a legal requirement for the exact setting (see the matrix). DPDP Rules, Rule 6 comes into force about 13 May 2027.
- The detection is on plan JSON for the listed attributes. Values unknown at plan time are denied where the rule needs them, and some forms of exposure are not detected (for example public bucket policies).
- Only root-module Terraform configurations are supported. The encryption and key-ownership checks look each resource up in the root module, so a resource inside a Terraform module is reported as unencrypted or without a customer-managed key even when it has both.
- The `india-healthcare` and `india` contexts add no healthcare-specific or sector-specific control; no source reviewed supports a universal India-only hosting requirement, so neither applies a region restriction.
- Editor feedback takes the time of a Terraform plan; as-you-type feedback is not implemented.
