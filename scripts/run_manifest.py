#!/usr/bin/env python3
"""Run every tests/manifest.csv fixture through the shared consumer (D-021).
These are DEVELOPMENT fixtures (D-024): results are not the paper's accuracy figure."""
import argparse
import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cli" / "compliance-linter"))
import scof_core as core  # noqa: E402


def run_engine(engine, rows, plans_dir, refresh):
    results = []
    for row in rows:
        name, ctx, exp = core.fixture_name(row), row["context"], row["expected"].upper()
        exp_controls = sorted(c for c in re.split(r"[;,|\s]+", row["violated_controls"]) if c)
        try:
            plan = plans_dir / f"{name}.json"
            if refresh or not plan.is_file():
                core.generate_plan(core.fixture_dir(row), plan)
            msgs, _ = core.evaluate(engine, plan, ctx)
        except core.ScofError as exc:
            sys.exit(f"ERROR in fixture {name} ({engine}): {exc}")
        viols = core.to_violations(msgs)
        actual = sorted({v.control for v in viols})
        flagged = bool(viols)
        if exp == "FAIL":
            outcome = "TP" if flagged else "FN"
        else:
            outcome = "FP" if flagged else "TN"
        results.append({
            "fixture": name, "context": ctx, "expected": exp,
            "expected_control": ";".join(exp_controls), "actual_controls": ";".join(actual),
            "n_violations": len(viols), "outcome": outcome,
            "control_match": actual == exp_controls,
            "unparsed": sum(1 for v in viols if not v.parsed),
            "engine": engine, "messages": msgs,
        })
    return results


def report(engine, results):
    print(f"\n=== Engine: {engine} (development fixtures, D-024) ===")
    print(f"{'fixture':28} {'context':14} {'exp':5} {'expected_control':24} {'actual_controls':24} {'n':>2} {'outcome':7} ctl_match")
    for r in results:
        print(f"{r['fixture']:28} {r['context']:14} {r['expected']:5} {r['expected_control']:24} "
              f"{r['actual_controls']:24} {r['n_violations']:>2} {r['outcome']:7} {r['control_match']}")
    counts = {k: sum(1 for r in results if r["outcome"] == k) for k in ("TP", "TN", "FP", "FN")}
    ctl_bad = sum(1 for r in results if not r["control_match"])
    unparsed = sum(r["unparsed"] for r in results)
    print(f"Summary: TP={counts['TP']} TN={counts['TN']} FP={counts['FP']} FN={counts['FN']} "
          f"control_mismatches={ctl_bad} unparsed={unparsed}")
    out = ROOT / "experiments" / "accuracy" / f"dev_{engine}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    cols = [c for c in results[0] if c != "messages"]
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in results:
            w.writerow({c: r[c] for c in cols})
    print(f"Written to {out.relative_to(ROOT)}")
    ok = counts["FP"] == 0 and counts["FN"] == 0 and ctl_bad == 0 and unparsed == 0
    return ok


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", choices=["opa", "conftest", "both"], default="both")
    ap.add_argument("--refresh", action="store_true", help="regenerate cached plans")
    args = ap.parse_args()
    try:
        rows = core.load_manifest()
    except core.ScofError as exc:
        sys.exit(str(exc))
    plans_dir = ROOT / "experiments" / "plans"
    engines = ["opa", "conftest"] if args.engine == "both" else [args.engine]
    all_ok = True
    by_engine = {}
    for e in engines:
        by_engine[e] = run_engine(e, rows, plans_dir, args.refresh)
        all_ok &= report(e, by_engine[e])
    if len(engines) == 2:
        diff = [a["fixture"] for a, b in zip(by_engine["opa"], by_engine["conftest"])
                if a["messages"] != b["messages"]]
        if diff:
            print(f"\nENGINE PARITY: DIFFERENT for {diff}")
            all_ok = False
        else:
            print("\nENGINE PARITY: identical")
    print("ALL FIXTURES MATCH THE MANIFEST" if all_ok else "MISMATCHES FOUND (see above)")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())