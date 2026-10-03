#!/usr/bin/env python3
"""Why is OPA evaluation ~0.06 s on a cached plan but ~1 s inside the end-to-end run?
Measures three conditions on one development fixture. Local machine only."""
import shutil
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cli" / "compliance-linter"))
import scof_core as core  # noqa: E402


def show(label, vals):
    print(f"{label:46} n={len(vals):2} median={statistics.median(vals):.3f} "
          f"min={min(vals):.3f} max={max(vals):.3f}", flush=True)


def main():
    row = core.load_manifest()[0]
    d, ctx = core.fixture_dir(row), row["context"]
    work = ROOT / "scratch" / "diag"
    work.mkdir(parents=True, exist_ok=True)
    base = work / "plan.json"
    core.generate_plan(d, base)

    def ev(p):
        return core.evaluate_opa(p, ctx)[1]

    ev(base)  # warm-up
    show("A cached plan, same file", [ev(base) for _ in range(15)])
    b = []
    for i in range(15):
        q = work / f"fresh_{i}.json"
        shutil.copyfile(base, q)
        b.append(ev(q))
    show("B freshly copied file each run", b)
    c = []
    for i in range(4):
        p = work / f"gen_{i}.json"
        core.generate_plan(d, p)
        c.append(ev(p))
    show("C eval immediately after terraform", c)
    c2 = []
    for i in range(4):
        p = work / f"gen_sleep_{i}.json"
        core.generate_plan(d, p)
        time.sleep(5)
        c2.append(ev(p))
    show("C2 eval 5 s after terraform", c2)
    print("\nInterpretation (apply only what the numbers show):")
    print(" - B >> A: a freshly written file is slow to read (antivirus/indexing).")
    print(" - C >> A and C2 ~ A: the machine is busy right after terraform; eval is not slow by itself.")
    print(" - C ~ C2 >> A: the plan JSON from terraform differs from the cached one in a way that matters.")
    print(" - All ~ A: the gap is not reproduced here; report that instead of guessing.")


if __name__ == "__main__":
    main()