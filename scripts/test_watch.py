#!/usr/bin/env python3
"""Verify the --watch mode end to end without VS Code and measure save-to-END latency externally.
Uses a scratch copy of a development fixture (D-024). Local machine only."""
import argparse
import csv
import queue
import re
import shutil
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINT = ROOT / "cli" / "compliance-linter" / "scof_lint.py"
SRC = ROOT / "tests" / "non_compliant" / "s3_wrong_region"
WORK = ROOT / "scratch" / "watchtest"
END_RE = re.compile(r"^SCOF-LINT-END total=([0-9.]+)s")
VIOL_RE = re.compile(r"violations=(\d+)")
DIAG_RE = re.compile(r": error: \[([A-Z0-9-]+)\] ")
REGION_RE = re.compile(r'(provider\s+"aws"\s*\{[^}]*?region\s*=\s*)"([^"]*)"', re.S)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--context", default="india-finance")
    ap.add_argument("--cycles", type=int, default=5)
    ap.add_argument("--allowed-region", default="ap-south-1")
    args = ap.parse_args()

    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    for f in SRC.glob("*.tf"):
        shutil.copy(f, WORK / f.name)
    lock = SRC / ".terraform.lock.hcl"
    if lock.exists():
        shutil.copy(lock, WORK / lock.name)

    target, original = None, None
    for f in sorted(WORK.glob("*.tf")):
        text = f.read_text(encoding="utf-8")
        if REGION_RE.search(text):
            target, original = f, text
            break
    if target is None:
        sys.exit("Could not find a provider \"aws\" region assignment in the fixture copy")

    def with_region(r):
        return REGION_RE.sub(lambda m: m.group(1) + '"' + r + '"', original, count=1)

    proc = subprocess.Popen([sys.executable, "-u", str(LINT), "--dir", str(WORK),
                             "--context", args.context, "--watch"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace", bufsize=1)
    q = queue.Queue()

    def reader():
        for line in proc.stdout:
            q.put((time.perf_counter(), line.rstrip("\r\n")))
        q.put(None)

    threading.Thread(target=reader, daemon=True).start()

    def drain(quiet=0.6):
        while True:
            try:
                item = q.get(timeout=quiet)
            except queue.Empty:
                return
            if item is None:
                raise RuntimeError("watcher exited unexpectedly")

    def wait_end(timeout):
        lines, deadline = [], time.perf_counter() + timeout
        while True:
            rem = deadline - time.perf_counter()
            if rem <= 0:
                raise TimeoutError("no SCOF-LINT-END within timeout")
            try:
                item = q.get(timeout=rem)
            except queue.Empty:
                raise TimeoutError("no SCOF-LINT-END within timeout")
            if item is None:
                raise RuntimeError("watcher exited unexpectedly")
            t, line = item
            lines.append(line)
            if END_RE.match(line):
                return t, lines

    records = []

    def analyse(label, t_write, t_end, lines, expect_violations, expect_tool_error, measured=True):
        end = next(l for l in lines if END_RE.match(l))
        internal = float(END_RE.match(end).group(1))
        mv = VIOL_RE.search(end)
        n_end = int(mv.group(1)) if mv else None
        tool_err = any("[SCOF-TOOL-ERROR]" in l for l in lines)
        n_diag = sum(1 for l in lines if DIAG_RE.search(l) and "SCOF-TOOL-ERROR" not in l)
        if expect_tool_error:
            ok = tool_err and "status=tool-error" in end
        else:
            ok = (not tool_err) and n_end == expect_violations and n_diag == expect_violations
        records.append({"cycle": label, "measured": measured, "ok": ok,
                        "external_s": round(t_end - t_write, 3), "internal_s": internal,
                        "overhead_s": round((t_end - t_write) - internal, 3),
                        "violations_end": n_end, "diagnostics": n_diag, "tool_error": tool_err})
        print(f"{'OK ' if ok else 'BAD'} {label:22} external={t_end - t_write:6.3f}s internal={internal:6.3f}s "
              f"violations={n_end} diag_lines={n_diag} tool_error={tool_err}", flush=True)

    def cycle(label, new_text, expect_violations=0, expect_tool_error=False):
        drain()
        t_write = time.perf_counter()
        target.write_text(new_text, encoding="utf-8")
        t_end, lines = wait_end(180)
        analyse(label, t_write, t_end, lines, expect_violations, expect_tool_error)

    try:
        print("Waiting for the initial lint (includes terraform init)...", flush=True)
        t0 = time.perf_counter()
        t_end, lines = wait_end(300)
        analyse("initial(incl. init)", t0, t_end, lines, 1, False, measured=False)
        for i in range(1, args.cycles + 1):
            cycle(f"fix-{i}", with_region(args.allowed_region), 0)
            cycle(f"break-{i}", original, 1)
        cycle("syntax-error", original + "\n}}}\n", expect_tool_error=True)
        cycle("restore-after-error", original, 1)
        # informational: two saves 50 ms apart
        drain()
        target.write_text(with_region(args.allowed_region), encoding="utf-8")
        time.sleep(0.05)
        target.write_text(with_region(args.allowed_region) + "\n# touch\n", encoding="utf-8")
        begins, last = 0, time.perf_counter()
        while time.perf_counter() - last < 8:
            try:
                item = q.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:
                break
            last = time.perf_counter()
            begins += item[1].startswith("SCOF-LINT-BEGIN")
        print(f"INFO two saves 50 ms apart produced {begins} lint run(s)")
        cycle("restore-final", original, 1)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    out = ROOT / "experiments" / "results" / "watch_latency.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(records[0]))
        w.writeheader()
        w.writerows(records)
    meas = [r for r in records if r["measured"] and r["cycle"].startswith(("fix", "break"))]
    for key in ("external_s", "internal_s", "overhead_s"):
        vals = [r[key] for r in meas]
        print(f"{key:12} n={len(vals)} mean={statistics.mean(vals):.3f} median={statistics.median(vals):.3f} "
              f"min={min(vals):.3f} max={max(vals):.3f}")
    bad = [r["cycle"] for r in records if not r["ok"]]
    print(f"Written to {out.relative_to(ROOT)}")
    print("WATCH BEHAVIOUR: all checks passed" if not bad else f"WATCH BEHAVIOUR: FAILED cycles {bad}")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())