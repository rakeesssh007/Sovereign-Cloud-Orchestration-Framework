# SCOF architecture

SCOF checks Terraform plans against one shared Rego policy library. Two enforcement paths use that library, and a small router decides which controls and parameters apply.

## Two paths, one policy library

```text
Developer path:  .tf files --> scof_lint.py --> terraform plan + show --> plan JSON --+
                                                                                      +--> scof_core --> OPA and Conftest (must agree) --> policies/
CI path:         pull request --> ci_gate.py --> scof_lint.py (same code) ------------+
```

The CI gate calls the same linter as the developer. `scof_core.py` is the only module that runs the engines and parses their results, so both paths agree by construction.

## Components

| Component | Location | Role |
|---|---|---|
| Policy library | `policies/` | One Rego package per control; `main.rego` combines them |
| Shared consumer | `cli/compliance-linter/scof_core.py` | Generates plan JSON, runs OPA and Conftest and requires identical findings, parses results, maps violations to source lines |
| CLI linter | `cli/compliance-linter/scof_lint.py` | Command line and `--watch` mode |
| Router | `router/policy-routing/scof_router.py` | Maps jurisdiction and sector to a deployment context |
| Routing data | `router/policy-routing/*.json` | `routing.json`, `region_allowlists.json`, `control_sets.json`, `targets.json`, `contexts/<context>.json` |
| CI gate | `scripts/ci_gate.py`, `.github/workflows/compliance-gate.yml` | Evaluates deployable configurations on pull requests |
| Catalogue check | `scripts/verify_control_catalogue_hash.py` | Checks the control catalogue and its copy of the matrix text |

## How a check runs

1. `terraform init`, `plan` and `show -json` produce plan JSON. Credentials are always mock (any real AWS credentials in the environment are removed) and the provider runs offline, so no AWS account is involved. Each external process has a 600-second timeout.
2. The deployment context supplies data to the policies: `data.context`, `data.known_contexts`, `data.region_allowlists` and `data.control_sets`.
3. `main.deny` collects the violations of every control that the context's control set enables.
4. Each violation is a string, `CONTROL-ID: resource address: reason`. `scof_core.py` parses it, finds the source line, and the CLI prints it as a diagnostic.

## Routing and control sets

- `routing.json` maps a jurisdiction (and sector) to a context: `india` and `finance` give `india-finance`; `india` and `healthcare` give `india-healthcare`; `india` with no sector gives `india`; `eu` gives `eu`.
- `region_allowlists.json` holds the allowed regions per context, and `control_sets.json` lists the controls enabled per context.
- `contexts/<context>.json` holds `{"context": "<name>"}`, which is passed to the engines.
- `targets.json` lists the deployable configurations the gate checks and the deployment each belongs to.

The routing fails closed:
- The router raises an error for an unknown, missing or ambiguous deployment, and never falls back to a default.
- If no context is given or the context is unknown, `REGION-RESTRICTION` reports it and every control runs.
- If a known context has no control set, every control runs and a `CONTROL-SET` violation is reported.
- A deployable directory with `.tf` files that is not declared in `targets.json`, or a declared target without `.tf` files, makes the gate fail.

## Engines

By default every check runs on both engines. OPA and Conftest load the same policy directory and data, and the result is accepted only if both return exactly the same findings. If they differ, or if either one fails, `scof_core.py` raises a tool error (exit code 2): the result is never a pass and never a policy verdict. This applies to the CLI, the VS Code task and the CI gate. A single engine can still be chosen with `--engine opa` or `--engine conftest` for diagnostics.

## Exit codes

`scof_lint.py` and `ci_gate.py`: 0 all passed, 1 policy violations, 2 tooling, routing or coverage error. A tooling error is never reported as a policy verdict.

## What the gate does and does not do

The CI gate fails a pull request check when a configuration violates an enabled control. With branch protection requiring that check, the change cannot be merged. It does not run `terraform apply`, and OPA does not block `apply`: prevention comes from blocking the merge.

## Known limits

- AWS only, with the controls and resource types listed in the README.
- Values that are unknown at plan time cannot be verified by every rule. Where a rule needs a known value, an unknown value is denied.
- Only root-module configurations are supported; resources inside Terraform modules are reported as unencrypted or without a customer-managed key even when they have both.
- Provider versions are pinned by the committed lock files. The matrix records each control's legal basis and which parts are our interpretation.
