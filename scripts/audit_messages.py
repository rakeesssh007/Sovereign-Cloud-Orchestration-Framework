#!/usr/bin/env python3
"""Audit real Rego messages against the message contract (parsed, known control, address shape, round trip)."""
import csv
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cli" / "compliance-linter"))
import scof_core as core  # noqa: E402


def build_scenarios(rows, plans_dir, tmp):
    contexts = core.list_contexts()
    scenarios = []  # (name, plan, data_files, must_violate)
    base_plan = None
    for row in rows:
        plan = plans_dir / f"{row['fixture']}.json"
        if not plan.is_file():
            core.generate_plan(core.fixture_dir(row), plan)
        if base_plan is None and row["expected"].upper() == "PASS":
            base_plan = plan
        for ctx in contexts:
            scenarios.append((f"{row['fixture']} @ {ctx}", plan, [core.ALLOWLISTS, core.context_file(ctx)], False))
    if base_plan is None:
        sys.exit("no compliant fixture plan available for synthetic scenarios")
    # synthetic: provider region is not a literal
    plan = json.loads(base_plan.read_text(encoding="utf-8"))
    try:
        plan["configuration"]["provider_config"]["aws"]["expressions"]["region"] = {"references": ["var.aws_region"]}
        mutated = tmp / "nonliteral_region.json"
        mutated.write_text(json.dumps(plan), encoding="utf-8")
        for ctx in contexts:
            scenarios.append((f"nonliteral-region @ {ctx}", mutated, [core.ALLOWLISTS, core.context_file(ctx)], True))
    except KeyError as exc:
        print(f"SKIPPED nonliteral-region scenario: plan shape lacks {exc}")
    scenarios.append(("missing-context", base_plan, [core.ALLOWLISTS], True))
    bogus = tmp / "bogus_context.json"
    bogus.write_text(json.dumps({"context": "bogus-context"}), encoding="utf-8")
    scenarios.append(("unknown-context", base_plan, [core.ALLOWLISTS, bogus], True))
    return scenarios


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    try:
        rows = core.load_manifest()
        seen = {}
        failclosed_problems = []
        with tempfile.TemporaryDirectory() as td:
            for name, plan, data, must_violate in build_scenarios(rows, ROOT / "experiments" / "plans", Path(td)):
                msgs, _ = core.evaluate_opa_with_data(plan, data)
                if must_violate and not msgs:
                    failclosed_problems.append(name)
                for m in msgs:
                    seen.setdefault(m, []).append(name)
    except core.ScofError as exc:
        sys.exit(f"ERROR: {exc}")

    records, bad = [], 0
    print(f"\n{len(seen)} distinct real message(s):\n")
    for raw in sorted(seen):
        v = core.parse_message(raw)
        problems = []
        if not v.parsed:
            problems.append("unparsed")
        if v.control not in core.KNOWN_CONTROLS:
            problems.append("unknown-control")
        if not v.address:
            problems.append("no-address")
        elif not core.is_address_shaped(v.address):
            problems.append("address-not-resource-shaped")
        if v.parsed and v.address and f"{v.control}: {v.address}: {v.reason}" != raw:
            problems.append("round-trip-mismatch")
        bad += bool(problems)
        print(f"[{'OK ' if not problems else 'BAD'}] {v.control} | address={v.address!r} | scenarios={len(seen[raw])}")
        print(f"      raw: {raw}")
        if problems:
            print(f"      problems: {', '.join(problems)}")
        records.append({"raw": raw, "control": v.control, "address": v.address, "parsed": v.parsed,
                        "address_shaped": core.is_address_shaped(v.address), "problems": ";".join(problems),
                        "n_scenarios": len(seen[raw]), "example_scenario": seen[raw][0]})
    out = ROOT / "experiments" / "accuracy" / "message_audit.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(records[0]) if records else ["raw"])
        w.writeheader()
        w.writerows(records)
    print(f"\nWritten to {out.relative_to(ROOT)}")
    ok = True
    if failclosed_problems:
        ok = False
        print(f"FAIL-CLOSED CHECK FAILED (no violation produced): {failclosed_problems}")
    else:
        print("FAIL-CLOSED CHECK: missing context, unknown context and non-literal region all produced a violation")
    if bad:
        ok = False
        print(f"CONTRACT AUDIT: {bad} message(s) do not conform. Do NOT add parser heuristics: "
              "report these to the supervisor/assistant and evaluate structured Rego output.")
    else:
        print(f"CONTRACT AUDIT: all {len(seen)} distinct real messages conform to the string contract")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())