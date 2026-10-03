#!/usr/bin/env python3
"""SCOF policy router: resolves a deployment (jurisdiction, sector) to a deployment context.

The context name selects the region allow-list in region_allowlists.json (D-015) and is the value
the Rego library reads from data.context (D-023). The router fails closed (D-022): an empty,
unknown or ambiguous deployment raises RouterError and no context is returned.

Usage:
  python router/policy-routing/scof_router.py --jurisdiction india --sector finance
  python router/policy-routing/scof_router.py --jurisdiction eu
  python router/policy-routing/scof_router.py --list
Add --write to also (re)generate contexts/<context>.json.
Exit codes: 0 resolved, 2 router error.
"""
import argparse
import json
import sys
from pathlib import Path

ROUTER_DIR = Path(__file__).resolve().parent
ROUTES_FILE = ROUTER_DIR / "routing.json"
ALLOWLISTS_FILE = ROUTER_DIR / "region_allowlists.json"
CONTEXT_DIR = ROUTER_DIR / "contexts"


class RouterError(Exception):
    """Routing could not be completed. Never a policy verdict."""


def _norm(value):
    return (value or "").strip().lower()


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RouterError("cannot read " + Path(path).name + " (" + str(exc) + ")") from exc


def known_contexts(allowlists_file=ALLOWLISTS_FILE):
    data = _read_json(allowlists_file)
    known = data.get("known_contexts") if isinstance(data, dict) else None
    if not known:
        raise RouterError("region_allowlists.json has no known_contexts")
    return sorted(known)


def load_routes(routes_file=ROUTES_FILE):
    data = _read_json(routes_file)
    raw = data.get("routes") if isinstance(data, dict) else None
    if not isinstance(raw, list) or not raw:
        raise RouterError("routing.json has no routes")
    routes = []
    for entry in raw:
        if not isinstance(entry, dict) or not entry.get("jurisdiction") or not entry.get("context"):
            raise RouterError("every route needs a jurisdiction and a context")
        routes.append({
            "jurisdiction": _norm(entry["jurisdiction"]),
            "sector": _norm(entry.get("sector")),
            "context": entry["context"],
        })
    return routes


def resolve(jurisdiction, sector=None, routes_file=ROUTES_FILE, allowlists_file=ALLOWLISTS_FILE):
    """Return the context name for a deployment, or raise RouterError."""
    j, s = _norm(jurisdiction), _norm(sector)
    if not j:
        raise RouterError("no jurisdiction supplied")
    label = "jurisdiction '" + j + "', sector '" + (s or "(none)") + "'"
    matches = [r for r in load_routes(routes_file) if r["jurisdiction"] == j and r["sector"] == s]
    if not matches:
        raise RouterError("no route for " + label)
    if len(matches) > 1:
        raise RouterError("ambiguous routes for " + label)
    context = matches[0]["context"]
    if context not in known_contexts(allowlists_file):
        raise RouterError("route for " + label + " points to unknown context '" + context + "'")
    return context


def context_json(context):
    """Exact text of a context data file (D-023 shape)."""
    return json.dumps({"context": context}, separators=(",", ":")) + "\n"


def write_context_file(context, out_dir=CONTEXT_DIR, allowlists_file=ALLOWLISTS_FILE):
    if context not in known_contexts(allowlists_file):
        raise RouterError("unknown context '" + str(context) + "'")
    path = Path(out_dir) / (context + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(context_json(context), encoding="utf-8", newline="\n")
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description="Resolve a deployment to a SCOF context")
    ap.add_argument("--jurisdiction")
    ap.add_argument("--sector")
    ap.add_argument("--write", action="store_true", help="also write contexts/<context>.json")
    ap.add_argument("--list", action="store_true", help="list the configured routes")
    args = ap.parse_args(argv)
    try:
        if args.list:
            for r in load_routes():
                print(r["jurisdiction"] + " / " + (r["sector"] or "(none)") + " -> " + r["context"])
            return 0
        context = resolve(args.jurisdiction, args.sector)
        if args.write:
            write_context_file(context)
        print(context)
        return 0
    except RouterError as exc:
        print("SCOF router error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())