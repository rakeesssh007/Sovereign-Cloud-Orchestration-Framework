#!/usr/bin/env python3
"""CI hard gate for the deployable Terraform configurations under terraform/ (D-031).

For every target in router/policy-routing/targets.json the deployment context is resolved by the
router, then the shared CLI (cli/compliance-linter/scof_lint.py) evaluates the configuration. This
script never reads violation text (D-026); it only uses the CLI exit code (0 pass, 1 policy
violations, 2 tooling error).

Coverage fails closed: a terraform/ directory with a main.tf and no declared deployment context, or
a declared target without a main.tf, is an error and nothing is evaluated.

Exit code: 0 all targets pass, 1 at least one policy violation, 2 tooling, routing or coverage error.
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINT = ROOT / "cli" / "compliance-linter" / "scof_lint.py"
ROUTER_DIR = ROOT / "router" / "policy-routing"
TARGETS_FILE = ROUTER_DIR / "targets.json"

sys.path.insert(0, str(ROUTER_DIR))
import scof_router  # noqa: E402


def die(message):
    print("SCOF CI GATE ERROR: " + message, flush=True)
    sys.exit(2)


def norm_dir(value):
    return str(value).replace("\\", "/").strip("/")


def load_targets(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        die("cannot read targets file (" + str(exc) + ")")
    targets = data.get("targets") if isinstance(data, dict) else None
    if not isinstance(targets, list) or not targets:
        die("targets file has no targets")
    out = []
    for t in targets:
        if not isinstance(t, dict) or "dir" not in t or "jurisdiction" not in t:
            die("every target needs 'dir' and 'jurisdiction'")
        out.append({"dir": norm_dir(t["dir"]), "jurisdiction": t["jurisdiction"], "sector": t.get("sector")})
    return out


def discover(tf_root):
    found = set()
    for p in tf_root.rglob("main.tf"):
        if ".terraform" in p.parts:
            continue
        found.add(p.parent.relative_to(ROOT).as_posix())
    return found


def main():
    ap = argparse.ArgumentParser(description="SCOF CI gate for terraform/ configurations")
    ap.add_argument("--engine", choices=["opa", "conftest"], default="conftest")
    ap.add_argument("--targets", default=str(TARGETS_FILE))
    ap.add_argument("--out", default=str(ROOT / "ci-results" / "gate_summary.json"))
    args = ap.parse_args()

    targets = load_targets(args.targets)
    declared = {t["dir"] for t in targets}
    discovered = discover(ROOT / "terraform")
    problems = []
    for d in sorted(discovered - declared):
        problems.append(d + " has a main.tf but no declared deployment context in targets.json")
    for d in sorted(declared - discovered):
        problems.append(d + " is declared in targets.json but has no main.tf")
    if problems:
        for p in problems:
            print("SCOF CI GATE ERROR: " + p, flush=True)
        sys.exit(2)

    print("SCOF CI GATE engine=" + args.engine + " targets=" + str(len(targets)), flush=True)
    results = []
    started = time.perf_counter()
    for t in targets:
        label = t["dir"]
        try:
            context = scof_router.resolve(t["jurisdiction"], t["sector"])
        except scof_router.RouterError as exc:
            print("::error file=" + label + "/main.tf::routing failed (" + str(exc) + ")", flush=True)
            results.append({"dir": label, "context": "", "status": "TOOL-ERROR", "exit_code": 2, "seconds": 0.0})
            continue
        print("--- " + label + " (context " + context + ")", flush=True)
        cmd = [sys.executable, str(LINT), "--dir", str(ROOT / label), "--context", context,
               "--engine", args.engine, "--format", "github"]
        t0 = time.perf_counter()
        code = subprocess.run(cmd, cwd=ROOT).returncode
        secs = time.perf_counter() - t0
        status = "PASS" if code == 0 else ("FAIL" if code == 1 else "TOOL-ERROR")
        results.append({"dir": label, "context": context, "status": status, "exit_code": code, "seconds": round(secs, 1)})
        print("--- " + label + ": " + status + " in " + format(secs, ".1f") + "s", flush=True)

    total = time.perf_counter() - started
    print("\nSCOF CI GATE SUMMARY", flush=True)
    for r in results:
        print("  " + r["status"].ljust(10) + " " + r["dir"].ljust(18) + " context=" + (r["context"] or "-").ljust(14)
              + " " + format(r["seconds"], ".1f") + "s", flush=True)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"engine": args.engine, "total_seconds": round(total, 1), "results": results},
                              indent=2) + "\n", encoding="utf-8")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("### SCOF compliance gate (" + args.engine + ")\n\n| target | context | result | seconds |\n|---|---|---|---|\n")
            for r in results:
                fh.write("| " + r["dir"] + " | " + (r["context"] or "-") + " | " + r["status"] + " | " + str(r["seconds"]) + " |\n")

    if any(r["status"] == "TOOL-ERROR" for r in results):
        print("SCOF CI GATE RESULT: ERROR", flush=True)
        return 2
    if any(r["status"] == "FAIL" for r in results):
        print("SCOF CI GATE RESULT: FAIL", flush=True)
        return 1
    print("SCOF CI GATE RESULT: PASS", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())