#!/usr/bin/env python3
"""Generate Terraform plan JSON (tfplan.json) for every independent fixture.

Plan generation only: this does not run OPA, Conftest or any SCOF evaluator.
One scratch working directory is initialised once from the committed lock file (provider 6.67.0)
so that the 800 MB provider is not copied into every fixture folder.
Usage: python generate_plans.py <scratch_workdir> [fixtures_dir]
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIX = ROOT / "evaluation" / "independent" / "fixtures"


def run(cmd, cwd, env):
    return subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True, encoding="utf-8", errors="replace")


def main():
    work = Path(sys.argv[1]).resolve()
    fix = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else FIX
    work.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.setdefault("TF_PLUGIN_CACHE_DIR", r"C:\Work\Tools\tf-plugin-cache")
    env["TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE"] = "true"
    env["TF_IN_AUTOMATION"] = "1"
    tf = shutil.which("terraform") or "terraform"
    failures = []
    for d in sorted(p for p in fix.iterdir() if (p / "main.tf").is_file()):
        out = d / "tfplan.json"
        if out.exists():
            print("exists, kept:", d.name)
            continue
        for old in work.glob("*.tf"):
            old.unlink()
        shutil.copyfile(d / "main.tf", work / "main.tf")
        shutil.copyfile(d / ".terraform.lock.hcl", work / ".terraform.lock.hcl")
        if not (work / ".terraform").is_dir():
            r = run([tf, "init", "-input=false", "-no-color"], work, env)
            if r.returncode:
                sys.exit("terraform init failed:\n" + r.stdout[-1500:] + r.stderr[-1500:])
        planfile = work / "tfplan.bin"
        r = run([tf, "plan", "-input=false", "-no-color", "-lock=false", f"-out={planfile}"], work, env)
        if r.returncode:
            failures.append((d.name, (r.stdout + r.stderr)[-700:]))
            print("PLAN FAILED:", d.name)
            continue
        r = run([tf, "show", "-json", str(planfile)], work, env)
        if r.returncode:
            failures.append((d.name, (r.stdout + r.stderr)[-700:]))
            print("SHOW FAILED:", d.name)
            continue
        out.write_text(r.stdout, encoding="utf-8", newline="\n")
        print("ok:", d.name)
    for name, tail in failures:
        print("\n=== FAILURE", name, "===\n", tail)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
