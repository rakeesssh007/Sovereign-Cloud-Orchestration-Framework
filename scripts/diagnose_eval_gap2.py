#!/usr/bin/env python3
"""Second latency-gap diagnostic: where do the ~1.1 s go after a fresh terraform run?
Local machine, one development fixture. Reports measurements only."""
import hashlib
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cli" / "compliance-linter"))
import scof_core as core  # noqa: E402

ROUNDS = 3
SLEEP = 30
results = {}


def opa_run(plan, ctx):
    cmd = [core.find_binary("opa"), "eval", "--metrics", "-f", "json", "-i", str(plan),
           "-d", str(core.POLICY_DIR), "-d", str(core.ALLOWLISTS),
           "-d", str(core.context_file(ctx)), "data.main.deny"]
    t0 = time.perf_counter()
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    wall = time.perf_counter() - t0
    if p.returncode != 0:
        sys.exit("opa failed: " + (p.stderr or p.stdout)[-400:])
    metrics = json.loads(p.stdout).get("metrics", {})
    timers = {k: v for k, v in metrics.items() if k.startswith("timer_") and isinstance(v, (int, float))}
    return wall, timers


def record(label, plan, ctx):
    wall, timers = opa_run(plan, ctx)
    inner = sum(timers.values()) / 1e9
    results.setdefault(label, []).append((wall, inner, timers))
    print(f"  {label:42} wall={wall:6.3f}s opa_timers_sum={inner:6.3f}s", flush=True)


def fingerprint(path):
    raw = path.read_bytes()
    doc = json.loads(raw.decode("utf-8"))
    doc.pop("timestamp", None)
    return hashlib.sha256(raw).hexdigest()[:12], len(raw), json.dumps(doc, sort_keys=True)


def main():
    row = core.load_manifest()[0]
    d, ctx = core.fixture_dir(row), row["context"]
    work = ROOT / "scratch" / "diag2"
    work.mkdir(parents=True, exist_ok=True)
    base = work / "base.json"
    core.generate_plan(d, base)
    opa_run(base, ctx)  # warm-up
    b_hash, b_size, b_norm = fingerprint(base)
    print(f"fixture={row['fixture']} context={ctx} base: sha={b_hash} bytes={b_size}\n")
    for i in range(1, ROUNDS + 1):
        print(f"round {i}")
        record("1 base plan, before terraform", base, ctx)
        g = work / f"gen_{i}.json"
        core.generate_plan(d, g)
        h, size, norm = fingerprint(g)
        print(f"  generated plan: sha={h} bytes={size} identical_bytes={h == b_hash} "
              f"identical_ignoring_timestamp={norm == b_norm}")
        record("2 BASE plan right after terraform", base, ctx)
        record("3 NEW plan right after terraform", g, ctx)
        record("4 NEW plan again, immediately", g, ctx)
        print(f"  ...sleeping {SLEEP} s", flush=True)
        time.sleep(SLEEP)
        record(f"5 NEW plan after {SLEEP} s", g, ctx)
        record(f"6 BASE plan after {SLEEP} s", base, ctx)
    print("\nSummary (median over rounds)")
    for label in sorted(results):
        walls = [r[0] for r in results[label]]
        inner = [r[1] for r in results[label]]
        tops = results[label][-1][2]
        top = sorted(tops.items(), key=lambda kv: kv[1], reverse=True)[:3]
        print(f"{label:42} wall={statistics.median(walls):6.3f}s opa_timers={statistics.median(inner):6.3f}s "
              f"top_timers(last run)={[(k.replace('timer_rego_', '').replace('_ns', ''), round(v / 1e9, 3)) for k, v in top]}")
    print("\nHow to read this (apply only what the numbers show):")
    print(" - 2 slow AND 3 slow: the slowdown follows terraform runs and is not tied to the plan file.")
    print(" - 2 fast AND 3 slow: it depends on the newly generated plan; compare the 'identical' lines above.")
    print(" - 4 fast: first use of a new file is slow, repeated use is fast.")
    print(" - wall large but opa_timers small: time is spent outside OPA's own evaluation (start-up / file access).")
    print(" - opa_timers large: time is spent inside OPA (see top_timers).")
    print(" - nothing slow here: the gap did not reproduce; report that instead of guessing.")


if __name__ == "__main__":
    main()