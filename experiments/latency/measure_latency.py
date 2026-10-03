#!/usr/bin/env python3
"""Measure policy-evaluation latency (cached plan) and end-to-end CLI latency
(terraform plan + show + OPA) on the development fixtures. Local machine only."""
import argparse
import csv
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "cli" / "compliance-linter"))
import scof_core as core  # noqa: E402


def pct(vals, q):
    s = sorted(vals)
    k = (len(s) - 1) * q
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def version(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True)
        return ((p.stdout or p.stderr).strip().splitlines() or ["?"])[0]
    except Exception as exc:  # noqa: BLE001
        return f"unavailable ({exc})"


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-eval", type=int, default=20, help="policy-only runs per fixture per engine")
    ap.add_argument("--n-e2e", type=int, default=3, help="end-to-end runs per fixture")
    args = ap.parse_args()

    rows = core.load_manifest()
    plans_dir = ROOT / "experiments" / "plans"
    res_dir = ROOT / "experiments" / "results"
    res_dir.mkdir(parents=True, exist_ok=True)
    raw = []

    for row in rows:
        name, ctx = row["fixture"], row["context"]
        d = core.fixture_dir(row)
        plan = plans_dir / f"{name}.json"
        core.generate_plan(d, plan)  # warm-up (also runs init if needed); not recorded
        for engine in ("opa", "conftest"):
            core.evaluate(engine, plan, ctx)  # warm-up, not recorded
            for i in range(args.n_eval):
                _, s = core.evaluate(engine, plan, ctx)
                raw.append({"fixture": name, "context": ctx, "kind": f"eval_{engine}", "run": i + 1,
                            "plan_s": "", "show_s": "", "eval_s": s, "total_s": s})
        for i in range(args.n_e2e):
            with tempfile.TemporaryDirectory() as td:
                pj = Path(td) / "plan.json"
                t0 = time.perf_counter()
                tm = core.generate_plan(d, pj)
                _, s = core.evaluate("opa", pj, ctx)
                total = time.perf_counter() - t0
            raw.append({"fixture": name, "context": ctx, "kind": "e2e_opa", "run": i + 1,
                        "plan_s": tm["plan_s"], "show_s": tm["show_s"], "eval_s": s, "total_s": total})
        print(f"measured {name}", flush=True)

    cols = ["fixture", "context", "kind", "run", "plan_s", "show_s", "eval_s", "total_s"]
    with open(res_dir / "latency_raw.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(raw)

    summary = []
    for kind, metrics in (("eval_opa", ["eval_s"]), ("eval_conftest", ["eval_s"]),
                          ("e2e_opa", ["total_s", "plan_s", "show_s", "eval_s"])):
        subset = [r for r in raw if r["kind"] == kind]
        for m in metrics:
            vals = [r[m] for r in subset]
            summary.append({"kind": kind, "metric": m, "n": len(vals),
                            "mean_s": statistics.mean(vals), "median_s": statistics.median(vals),
                            "p95_s": pct(vals, 0.95), "min_s": min(vals), "max_s": max(vals),
                            "frac_under_1s": sum(1 for v in vals if v < 1.0) / len(vals)})
    scols = ["kind", "metric", "n", "mean_s", "median_s", "p95_s", "min_s", "max_s", "frac_under_1s"]
    with open(res_dir / "latency_summary.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=scols)
        w.writeheader()
        for r in summary:
            w.writerow({k: (f"{v:.4f}" if isinstance(v, float) else v) for k, v in r.items()})

    env = [f"platform: {platform.platform()}", f"python: {platform.python_version()}",
           f"processor: {platform.processor()}", f"opa: {version([core.find_binary('opa'), 'version'])}",
           f"conftest: {version([core.find_binary('conftest'), '--version'])}",
           f"terraform: {version([core.find_binary('terraform'), 'version'])}",
           f"n_eval={args.n_eval} n_e2e={args.n_e2e} fixtures={len(rows)}",
           "fixtures: development set (D-024); local machine, not CI"]
    (res_dir / "latency_env.txt").write_text("\n".join(env) + "\n", encoding="utf-8")

    print("\nkind            metric    n    mean    median  p95     min     max     <1s")
    for r in summary:
        print(f"{r['kind']:15} {r['metric']:8} {r['n']:4} {r['mean_s']:7.3f} {r['median_s']:7.3f} "
              f"{r['p95_s']:7.3f} {r['min_s']:7.3f} {r['max_s']:7.3f} {r['frac_under_1s']:5.2f}")
    print("\nWritten to experiments/results/latency_{raw,summary}.csv and latency_env.txt")


if __name__ == "__main__":
    main()