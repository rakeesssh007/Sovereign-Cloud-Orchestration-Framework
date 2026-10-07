# SCOF architecture

SCOF checks Terraform plans against one shared Rego policy library. Two enforcement paths use that library, and a small router decides which controls and parameters apply.

## Two paths, one policy library

```text
Developer path:  .tf files --> scof_lint.py --> terraform plan + show --> plan JSON --+
                                                                                      +--> scof_core --> OPA / Conftest --> policies/
CI path:         pull request --> ci_gate.py --> scof_lint.py (same code) ------------+
```

The CI gate calls the same linter as the developer. `scof_core.py` is the only module that runs the engines and parses their results, so both paths agree by construction.

## Components

| Component | Location | Role |
|---|---|---|
| Policy library | `policies/` | One Rego package per control; `main.rego` combines them |
| Shared consumer | `cli/compliance-linter/scof_core.py` | Generates plan JSON, runs OPA or Conftest, parses results, maps violations to source lines |
| CLI linter | `cli/compliance-linter/scof_lint.py` | Command line and `--watch` mode |
| Router | `router/policy-routing/scof_router.py` | Maps jurisdiction and sector to a deployment context |
| Routing data | `router/policy-routing/*.json` | `routing.json`, `region_allowlists.json`, `control_sets.json`, `targets.json`, `contexts/<context>.json` |
| CI gate | `scripts/ci_gate.py`, `.github/workflows/compliance-gate.yml` | Evaluates deployable configurations on pull requests |
| Fixtures | `tests/` | Compliant and non-compliant Terraform fixtures, with `manifest.csv` |

## How a check runs

1. `terraform init`, `plan` and `show -json` produce plan JSON. Credentials are mock and the provider runs offline, so no AWS account is involved.
2. The deployment context supplies data to the policies: `data.context`, `data.known_contexts`, `data.region_allowlists` and `data.control_sets`.
3. `main.deny` collects the violations of every control that the context's control set enables.
4. Each violation is a string, `CONTROL-ID: resource address: reason`. `scof_core.py` parses it, finds the source line, and the CLI prints it as a diagnostic.

## Routing and control sets

- `routing.json` maps a jurisdiction (and sector) to a context: `india` and `finance` give `india-finance`; `eu` gives `eu`.
- `region_allowlists.json` holds the allowed regions per context, and `control_sets.json` lists the controls enabled per context.
- `contexts/<context>.json` holds `{"context": "<name>"}`, which is passed to the engines.
- `targets.json` lists the deployable configurations the gate checks and the deployment each belongs to.

The routing fails closed:
- The router raises an error for an unknown, missing or ambiguous deployment, and never falls back to a default.
- If no context is given or the context is unknown, `REGION-RESTRICTION` reports it and every control runs.
- If a known context has no control set, every control runs and a `CONTROL-SET` violation is reported.
- A deployable directory that is not declared in `targets.json`, or a target without `main.tf`, makes the gate fail.
- The test-only `india` context is known to the policies but is never produced by the router.

## Engines

OPA (run by the CLI) and Conftest (run by the CI gate) load the same policy directory and data. The fixture self-test runs every fixture through both and fails if their results differ.

## Exit codes

`scof_lint.py` and `ci_gate.py`: 0 all passed, 1 policy violations, 2 tooling, routing or coverage error. A tooling error is never reported as a policy verdict.

## What the gate does and does not do

The CI gate fails a pull request check when a configuration violates an enabled control. With branch protection requiring that check, the change cannot be merged. It does not run `terraform apply`, and OPA does not block `apply`: prevention comes from blocking the merge.

## Known limits

- AWS only, with the controls and resource types listed in the README.
- Values that are unknown at plan time cannot be verified by every rule. Where a rule needs a known value, an unknown value is denied.
- Provider versions are pinned by the committed lock files. The matrix records each control's legal basis and which parts are our interpretation.
