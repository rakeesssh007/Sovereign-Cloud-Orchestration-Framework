#!/usr/bin/env python3
"""Run the frozen SCOF evaluator once over the independent dataset and compute Design B metrics.

Requires: expected_labels.csv signed off and hashed (checked against --expect-sha256).
Evaluation goes through scof_core.lint (the shared core), never through any GUI.
Writes raw per-case results and a summary under evaluation/independent/results/<timestamp>/.
Usage: python run_eval.py --expect-sha256 <hash of expected_labels.csv>
"""
import argparse
import csv
import hashlib
import json
import math
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "cli" / "compliance-linter"))
import scof_core as core  # noqa: E402

OUT = ROOT / "evaluation" / "independent"
CONTROL_SETS = json.loads((ROOT / "router" / "policy-routing" / "control_sets.json").read_text(encoding="utf-8"))["control_sets"]


def wilson(k, n, z=1.959964):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - m) / d, (c + m) / d)


def classify(row, F, err):
    if err:
        return "ERROR"
    exp = row["intended_control"]
    if row["case_type"] == "NON_COMPLIANT":
        if exp in F:
            return "EXACT" if F == {exp} else "EXTRA"
        return "MISATTRIBUTED" if F else "MISSED"
    if row["case_type"] == "COMPLIANT":
        return "CLEAN" if not F else "SPURIOUS"
    return "LEAK_CLEAN" if not F else "LEAK_FINDING"


def tallies(items):
    """TP/FN/TN/FP from classified results of one engine."""
    c = Counter(x["klass"] for x in items)
    return dict(TP=c["EXACT"] + c["EXTRA"] + c["CAUGHT_EXACT"] + c["CAUGHT_WITH_EXTRA"],
                FN=c["MISSED"] + c["MISATTRIBUTED"] + c["MISSED_OTHER_FIRED"],
                TN=c["CLEAN"], FP=c["SPURIOUS"])


def rate_line(label, t):
    pos, neg = t["TP"] + t["FN"], t["TN"] + t["FP"]
    det = f"{t['TP']}/{pos} = {100*t['TP']/pos:.1f}%" if pos else "n/a"
    fpr = f"{t['FP']}/{neg} = {100*t['FP']/neg:.1f}%" if neg else "n/a"
    return f"| {label} | {t['TP']} | {t['FN']} | {t['TN']} | {t['FP']} | {det} | {fpr} |"


def explore(outdir, expect, commit, headline=None):
    """Exploratory strata: reported separately, never pooled with the headline rates."""
    path = OUT / "exploratory_labels.csv"
    h = hashlib.sha256(path.read_bytes()).hexdigest()
    if h != expect.lower():
        sys.exit(f"exploratory_labels.csv hash mismatch: {h}")
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    res = []
    for r in rows:
        for engine in ("opa", "conftest"):
            err, F = "", set()
            try:
                F = {v.control for v in core.lint(r["context"], engine=engine, plan=ROOT / r["plan_file"]).violations}
            except Exception as exc:  # noqa: BLE001
                err = f"{type(exc).__name__}: {exc}"
            exp, ctl = r["expected_status"], r["intended_control"]
            if err:
                k = "ERROR"
            elif exp == "FAIL":
                k = ("CAUGHT_EXACT" if F == {ctl} else "CAUGHT_WITH_EXTRA") if ctl in F else ("MISSED_OTHER_FIRED" if F else "MISSED")
            else:
                k = "CLEAN" if not F else "SPURIOUS"
            res.append(dict(case_id=r["case_id"], stratum=r["stratum"], engine=engine, expected=exp, intended=ctl,
                            observed=";".join(sorted(F)), klass=k, error=err))
    with (outdir / "exploratory_raw_results.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(res[0]))
        w.writeheader()
        w.writerows(res)
    out = [f"# Exploratory results (separate from the headline rates; never pooled)", "",
           f"- Freeze commit at run time: `{commit}`", f"- exploratory_labels.csv SHA-256: `{h}`", ""]
    for st in ("X1_BOUNDARY", "X2_DECLARED_GAP"):
        out += [f"## {st}", "", "| Case | Engine | Expected | Intended | Observed | Class |", "|---|---|---|---|---|---|"]
        for x in (x for x in res if x["stratum"] == st):
            out.append(f"| {x['case_id']} | {x['engine']} | {x['expected']} | {x['intended'] or '-'} | {x['observed'] or '-'} | {x['klass']} {x['error']} |")
        out.append("")
    if headline:
        out += ["## Presentation table (pre-declared in the evaluation plan, section 5a)", "",
                "Leakage rows are excluded. Only the first row is the H1 decision set; the others are descriptive.", ""]
        for engine in ("opa", "conftest"):
            hl = headline[engine]
            x1 = tallies([x for x in res if x["engine"] == engine and x["stratum"] == "X1_BOUNDARY"])
            x2 = tallies([x for x in res if x["engine"] == engine and x["stratum"] == "X2_DECLARED_GAP"])
            add = lambda *ts: {k: sum(t[k] for t in ts) for k in ("TP", "FN", "TN", "FP")}
            out += [f"### Engine: {engine}", "", "| Set | TP | FN | TN | FP | Detection | False-positive rate |",
                    "|---|---:|---:|---:|---:|---|---|",
                    rate_line("Headline (H1 decision set)", hl),
                    rate_line("X1 boundary stratum alone", x1),
                    rate_line("X2 declared-gap stratum alone (misses are known limitations)", x2),
                    rate_line("Headline + X1 (pre-declared sensitivity)", add(hl, x1)),
                    rate_line("All rows incl. X2 (descriptive, not an H1 test)", add(hl, x1, x2)), ""]
    (outdir / "exploratory_summary.md").write_text("\n".join(out), encoding="utf-8")
    print("\n".join(out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--expect-sha256", required=True)
    ap.add_argument("--expect-exploratory-sha256", help="also run exploratory_labels.csv (reported separately, never pooled)")
    a = ap.parse_args()
    labels = OUT / "expected_labels.csv"
    h = hashlib.sha256(labels.read_bytes()).hexdigest()
    if h != a.expect_sha256.lower():
        sys.exit(f"expected_labels.csv hash mismatch: {h}")
    rows = list(csv.DictReader(labels.open(encoding="utf-8")))
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = OUT / "results" / stamp
    outdir.mkdir(parents=True)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    raw = []
    for r in rows:
        for engine in ("opa", "conftest"):
            err, F, msgs = "", set(), []
            try:
                res = core.lint(r["context"], engine=engine, plan=ROOT / r["plan_file"])
                F = {v.control for v in res.violations}
                msgs = [v.raw for v in res.violations]
            except Exception as exc:  # noqa: BLE001 - any tool failure is recorded, never counted as a negative
                err = f"{type(exc).__name__}: {exc}"
            raw.append(dict(case_id=r["case_id"], case_type=r["case_type"], context=r["context"], engine=engine,
                            intended=r["intended_control"], expected_status=r["expected_status"],
                            observed=";".join(sorted(F)), klass=classify(r, F, err), error=err,
                            messages=" | ".join(msgs)))
    with (outdir / "raw_results.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(raw[0]))
        w.writeheader()
        w.writerows(raw)

    by = defaultdict(dict)
    for x in raw:
        by[x["case_id"]][x["engine"]] = x
    lines = [f"# Independent evaluation results ({stamp})", "",
             f"- Freeze commit at run time: `{commit}`", f"- expected_labels.csv SHA-256: `{h}`",
             f"- Rows: {len(rows)}; engine runs: {len(raw)}", ""]
    parity = sum(1 for c, d in by.items() if d["opa"]["observed"] == d["conftest"]["observed"] and not d["opa"]["error"] and not d["conftest"]["error"])
    errors = [x for x in raw if x["klass"] == "ERROR"]
    lines += [f"- OPA/Conftest parity: {parity}/{len(by)} cases identical", f"- Tool errors: {len(errors)}/{len(raw)} runs", ""]
    for engine in ("opa", "conftest"):
        rs = [x for x in raw if x["engine"] == engine]
        cnt = Counter(x["klass"] for x in rs)
        nc = sum(cnt[k] for k in ("EXACT", "EXTRA", "MISATTRIBUTED", "MISSED"))
        cl = cnt["CLEAN"] + cnt["SPURIOUS"]
        strict = cnt["EXACT"] + cnt["EXTRA"]
        gate = strict + cnt["MISATTRIBUTED"]
        lo, hi = wilson(strict, nc)
        flo, fhi = wilson(cnt["SPURIOUS"], cl)
        lines += [f"## Engine: {engine}", "", f"Case classes: {dict(cnt)}", "",
                  f"- Strict detection rate: {strict}/{nc} = {100*strict/nc:.1f}% (Wilson 95% {100*lo:.1f}-{100*hi:.1f}%); target >= 90%",
                  f"- Gate-level detection rate: {gate}/{nc} = {100*gate/nc:.1f}%",
                  f"- Attribution accuracy: {cnt['EXACT']}/{nc} = {100*cnt['EXACT']/nc:.1f}%",
                  f"- False-positive rate: {cnt['SPURIOUS']}/{cl} = {100*cnt['SPURIOUS']/cl:.1f}% (Wilson 95% {100*flo:.1f}-{100*fhi:.1f}%); target <= 5%", ""]
        leak = [x for x in rs if x["klass"] in ("LEAK_FINDING",)]
        disabled = [(x["case_id"], c) for x in rs if x["observed"] for c in x["observed"].split(";")
                    if c in {*(k for v in CONTROL_SETS.values() for k in v)} and c not in CONTROL_SETS.get(x["context"], [])]
        lines += [f"- Leakage rows with findings: {len(leak)}; findings for controls disabled in the context: {len(disabled)}", ""]
        # control-level confusion over NC and C rows
        conf = defaultdict(Counter)
        for x in rs:
            if x["klass"] == "ERROR" or x["case_type"] == "LEAKAGE":
                continue
            F = set(x["observed"].split(";")) - {""}
            for c in CONTROL_SETS[x["context"]]:
                e, o = (c == x["intended"]), (c in F)
                conf[c]["TP" if e and o else "FN" if e else "FP" if o else "TN"] += 1
        lines += ["| Control | TP | FN | FP | TN |", "|---|---:|---:|---:|---:|"]
        for c in sorted(conf):
            k = conf[c]
            lines.append(f"| {c} | {k['TP']} | {k['FN']} | {k['FP']} | {k['TN']} |")
        lines += ["", "Non-EXACT, non-CLEAN cases (named):"]
        odd = [x for x in rs if x["klass"] not in ("EXACT", "CLEAN", "LEAK_CLEAN")]
        lines += [f"- {x['case_id']} [{x['klass']}] intended={x['intended'] or '-'} observed={x['observed'] or '-'} {x['error']}" for x in odd] or ["- none"]
        lines.append("")
    (outdir / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print("written:", outdir)
    if a.expect_exploratory_sha256:
        headline = {e: tallies([x for x in raw if x["engine"] == e and x["case_type"] != "LEAKAGE"]) for e in ("opa", "conftest")}
        explore(outdir, a.expect_exploratory_sha256, commit, headline)


if __name__ == "__main__":
    main()
