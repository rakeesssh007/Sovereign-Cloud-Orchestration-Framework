#!/usr/bin/env python3
"""SCOF compliance linter (developer-side). Uses the shared Rego library via scof_core.

Exit codes: 0 = pass, 1 = policy violations, 2 = tooling error.
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scof_core as core  # noqa: E402


def out(text):
    print(text, flush=True)


def run_once(args, markers=False):
    t0 = time.perf_counter()
    if markers:
        out("SCOF-LINT-BEGIN")
    try:
        res = core.lint(context=args.context, engine=args.engine,
                        tf_dir=args.dir or args.tf_dir, plan=args.plan, save_plan=args.save_plan)
    except core.ScofError as exc:
        elapsed = time.perf_counter() - t0
        if markers:
            tfs = sorted(Path(args.dir).resolve().glob("*.tf"))
            target = tfs[0] if tfs else Path(args.dir).resolve()
            out(f"{target}:1:1: error: [SCOF-TOOL-ERROR] {' '.join(str(exc).split())}")
            out(f"SCOF-LINT-END total={elapsed:.3f}s status=tool-error")
        else:
            print(f"SCOF tool error: {exc}", file=sys.stderr)
        return 2
    elapsed = time.perf_counter() - t0
    t = res.timings
    stages = f"plan={t['plan_s']:.3f}s show={t['show_s']:.3f}s eval={t['eval_s']:.3f}s"
    if args.format == "json" and not markers:
        out(json.dumps(res.to_dict(), indent=2))
    else:
        for v in res.violations:
            out(core.github_annotation(v) if args.format == "github" and not markers else core.diagnostic_line(v))
        status = "PASS" if res.passed else f"FAIL ({len(res.violations)} violation(s))"
        out(f"SCOF: {status} context={res.context} engine={res.engine} {stages} total={elapsed:.3f}s")
    if markers:
        out(f"SCOF-LINT-END total={elapsed:.3f}s {stages} violations={len(res.violations)}")
    return 0 if res.passed else 1


def snapshot(d):
    return {str(p): (p.stat().st_mtime_ns, p.stat().st_size) for p in Path(d).glob("*.tf")}


def watch(args):
    d = Path(args.dir).resolve()
    out(f"SCOF watching {d} (context={args.context}, engine={args.engine}). Ctrl+C to stop.")
    last = None
    try:
        while True:
            snap = snapshot(d)
            if snap != last:
                if last is not None:
                    time.sleep(0.1)  # let the editor finish writing
                last = snapshot(d)
                run_once(args, markers=True)
            time.sleep(args.poll)
    except KeyboardInterrupt:
        out("SCOF watch stopped.")
    return 0


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="SCOF Terraform compliance linter")
    ap.add_argument("--dir", help="Terraform directory (runs terraform plan)")
    ap.add_argument("--plan", help="Existing plan JSON (skips terraform)")
    ap.add_argument("--tf-dir", help="Terraform directory used only for source lines when --plan is given")
    ap.add_argument("--context", required=True, help="Deployment context, e.g. india-finance or eu")
    ap.add_argument("--engine", choices=["opa", "conftest"], default="opa")
    ap.add_argument("--format", choices=["text", "json", "github"], default="text")
    ap.add_argument("--save-plan", help="Write the generated plan JSON to this path")
    ap.add_argument("--watch", action="store_true", help="Re-lint whenever a .tf file changes")
    ap.add_argument("--poll", type=float, default=0.3, help="Watch poll interval in seconds")
    args = ap.parse_args(argv)
    if bool(args.dir) == bool(args.plan):
        ap.error("give exactly one of --dir or --plan")
    if args.watch:
        if not args.dir:
            ap.error("--watch requires --dir")
        return watch(args)
    return run_once(args)


if __name__ == "__main__":
    sys.exit(main())