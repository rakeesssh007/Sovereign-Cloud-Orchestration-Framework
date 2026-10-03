# Lightweight VS Code integration

No custom extension. Uses VS Code built-in tasks and a problem matcher around `cli/compliance-linter/scof_lint.py`.

Setup: copy `tasks.json` to `.vscode/tasks.json` in the repository root.
Use: open a `.tf` file, then Terminal > Run Task > "SCOF: watch this folder (save-time)", choose a context.
Each save of a `.tf` file in that folder re-runs plan + policy evaluation; violations appear in the editor and Problems panel.
The editor-time latency includes `terraform plan`.