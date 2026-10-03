#!/usr/bin/env python3
"""Collect raw GitHub Actions timings for the compliance workflow. Measured values only.

GitHub reports whole-second timestamps, so every duration has about one second of resolution.
Requires the GitHub CLI (gh), logged in, run from inside the repository.
Usage: python experiments/latency/collect_ci_latency.py [--limit 20]
Writes experiments/results/ci_latency_raw.csv and prints a per-job summary.
"""
import argparse
import csv
import json
import statistics
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
WORKFLOW = "compliance-gate.yml"
OUT = ROOT / "experiments" / "results" / "ci_latency_raw.csv"


def gh_json(args):
    proc = subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8", cwd=ROOT)
    if proc.returncode != 0:
        sys.exit("gh failed: " + proc.stderr.strip())
    return json.loads(proc.stdout)


def parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None


def seconds(start, end):
    a, b = parse(start), parse(end)
    return "" if a is None or b is None else int((b - a).total_seconds())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()
    runs = gh_json(["run", "list", "--workflow", WORKFLOW, "--limit", str(args.limit),
                    "--json", "databaseId,event,headBranch,conclusion,status"])
    rows = []
    for run in runs:
        if run["status"] != "completed":
            continue
        jobs = gh_json(["api", "repos/{owner}/{repo}/actions/runs/" + str(run["databaseId"]) + "/jobs?per_page=100"])
        for job in jobs["jobs"]:
            base = [run["databaseId"], run["event"], run["headBranch"], run["conclusion"], job["name"], job["conclusion"]]
            rows.append(base + ["(job total)", job["conclusion"], seconds(job["started_at"], job["completed_at"])])
            for step in job.get("steps", []):
                rows.append(base + [step["name"], step["conclusion"], seconds(step.get("started_at"), step.get("completed_at"))])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["run_id", "event", "branch", "run_conclusion", "job", "job_conclusion", "step", "step_conclusion", "seconds"])
        w.writerows(rows)
    print("Wrote " + str(len(rows)) + " rows to " + str(OUT))
    groups = {}
    for row in rows:
        if row[6] == "(job total)" and row[5] == "success" and row[8] != "":
            groups.setdefault((row[1], row[4]), []).append(row[8])
    print("\nJob totals (successful jobs only, seconds, ~1 s resolution):")
    for (event, job), vals in sorted(groups.items()):
        print("  " + event.ljust(18) + job.ljust(28) + "n=" + str(len(vals)) + " median=" + str(statistics.median(vals))
              + " min=" + str(min(vals)) + " max=" + str(max(vals)))


if __name__ == "__main__":
    main()