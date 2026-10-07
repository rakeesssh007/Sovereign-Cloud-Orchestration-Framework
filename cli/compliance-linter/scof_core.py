"""SCOF shared policy-result consumer.

The CLI, the VS Code watcher, the manifest runner and the latency script all
import this module. None of them may split violation messages on their own.

Contract: "CONTROL-ID: resource address: reason"
"""
from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "policies"
ROUTER_DIR = REPO_ROOT / "router" / "policy-routing"
ALLOWLISTS = ROUTER_DIR / "region_allowlists.json"
CONTROL_SETS = ROUTER_DIR / "control_sets.json"
CONTEXT_DIR = ROUTER_DIR / "contexts"
PLUGIN_CACHE = Path(r"C:\Work\Tools\tf-plugin-cache")
MANIFEST_COLUMNS = ["fixture", "expected", "context", "violated_controls"]
KNOWN_CONTROLS = {"REGION-RESTRICTION", "DATA-ENCRYPTION", "KEY-OWNERSHIP",
                  "KEY-ROTATION", "IAM-NO-WILDCARD-ADMIN", "CONTROL-SET",
                  "LOG-RETENTION", "ACCESS-EXPOSURE", "BACKUP-RESILIENCE"}


class ScofError(Exception):
    """Tooling problem (missing binary, terraform failure, bad engine output).
    This is never a policy verdict."""


@dataclass
class Violation:
    control: str
    address: str
    reason: str
    raw: str
    parsed: bool = True
    file: str = ""
    line: int = 0


@dataclass
class LintResult:
    context: str
    engine: str
    violations: list = field(default_factory=list)
    timings: dict = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict:
        return {
            "context": self.context,
            "engine": self.engine,
            "passed": self.passed,
            "timings": self.timings,
            "violations": [
                {"control": v.control, "address": v.address, "reason": v.reason,
                 "raw": v.raw, "parsed": v.parsed, "file": v.file, "line": v.line}
                for v in self.violations
            ],
        }


# ---------------------------------------------------------------- parsing

_CONTROL_RE = re.compile(r"^(?P<control>[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+): (?P<rest>.*)$", re.DOTALL)


def _split_address(rest: str):
    """Split 'address: reason' at the first ': ' that is outside [] and quotes."""
    depth = 0
    in_quote = False
    for i, ch in enumerate(rest):
        if ch == '"' and (i == 0 or rest[i - 1] != "\\"):
            in_quote = not in_quote
        elif not in_quote:
            if ch == "[":
                depth += 1
            elif ch == "]" and depth:
                depth -= 1
            elif ch == ":" and depth == 0 and rest[i + 1:i + 2] == " ":
                return rest[:i], rest[i + 2:]
    return None


def parse_message(raw: str) -> Violation:
    m = _CONTROL_RE.match(raw)
    if not m:
        return Violation("UNPARSED", "", raw, raw, parsed=False)
    rest = m.group("rest")
    split = _split_address(rest)
    if split is None:
        return Violation(m.group("control"), "", rest, raw)
    return Violation(m.group("control"), split[0], split[1], raw)


def to_violations(messages) -> list:
    return [parse_message(m) for m in sorted(set(messages))]


_IDX = r'\[(?:"(?:[^"\\]|\\.)*"|[^\]"])*\]'
_ADDR_SHAPE = re.compile(
    r'^(?:module\.[A-Za-z0-9_-]+(?:' + _IDX + r')?\.)*'
    r'(?:data\.)?[a-z][a-z0-9_]*\.[A-Za-z0-9_-]+(?:' + _IDX + r')?$')


def is_address_shaped(address: str) -> bool:
    """True if the text looks like a Terraform resource address. Used for validation
    and auditing only; the parser itself never depends on it."""
    return bool(_ADDR_SHAPE.match(address or ""))


def github_annotation(v: Violation) -> str:
    """GitHub Actions workflow-command line for one violation (CI consumer)."""
    try:
        rel = Path(v.file).resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        rel = Path(v.file).as_posix()
    addr = f"{v.address}: " if v.address else ""
    msg = " ".join(f"[{v.control}] {addr}{v.reason}".split()).replace("%", "%25")
    return f"::error file={rel},line={v.line or 1}::{msg}"


# ---------------------------------------------------------------- processes

def find_binary(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise ScofError(f"'{name}' was not found on PATH. Install it or open a new terminal.")
    return path


def _run(cmd, env=None):
    t0 = time.perf_counter()
    p = subprocess.run(cmd, env=env, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return p, time.perf_counter() - t0


def _tail(p, n: int = 15) -> str:
    err = (p.stderr or "").strip().splitlines()
    out = (p.stdout or "").strip().splitlines()
    return "\n".join((err or out)[-n:])


def _tf_env() -> dict:
    env = os.environ.copy()
    env.setdefault("AWS_ACCESS_KEY_ID", "mock")
    env.setdefault("AWS_SECRET_ACCESS_KEY", "mock")
    env.setdefault("AWS_EC2_METADATA_DISABLE", "true")
    env.setdefault("TF_IN_AUTOMATION", "1")
    if PLUGIN_CACHE.is_dir():
        env.setdefault("TF_PLUGIN_CACHE_DIR", str(PLUGIN_CACHE))
        env.setdefault("TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE", "true")
    return env


def generate_plan(tf_dir, plan_json_path) -> dict:
    """terraform init (once) + plan + show -json. Returns stage timings."""
    tf_dir = Path(tf_dir).resolve()
    if not list(tf_dir.glob("*.tf")):
        raise ScofError(f"No .tf files in {tf_dir}")
    tf = find_binary("terraform")
    env = _tf_env()
    if not (tf_dir / ".terraform").is_dir():
        p, _ = _run([tf, f"-chdir={tf_dir}", "init", "-input=false", "-no-color"], env)
        if p.returncode != 0:
            raise ScofError("terraform init failed:\n" + _tail(p))
    with tempfile.TemporaryDirectory() as td:
        planfile = str(Path(td) / "tfplan")
        p, t_plan = _run([tf, f"-chdir={tf_dir}", "plan", "-input=false", "-no-color",
                          "-lock=false", f"-out={planfile}"], env)
        if p.returncode != 0:
            raise ScofError("terraform plan failed:\n" + _tail(p))
        p, t_show = _run([tf, f"-chdir={tf_dir}", "show", "-json", planfile], env)
        if p.returncode != 0:
            raise ScofError("terraform show failed:\n" + _tail(p))
    out = Path(plan_json_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(p.stdout, encoding="utf-8")
    return {"plan_s": t_plan, "show_s": t_show}


def list_contexts() -> list:
    return sorted(p.stem for p in CONTEXT_DIR.glob("*.json"))


def context_file(context: str) -> Path:
    f = CONTEXT_DIR / f"{context}.json"
    if not f.is_file():
        raise ScofError(f"Unknown context '{context}'. Available: {', '.join(list_contexts()) or 'none'}")
    return f


def evaluate_opa(plan_json, context):
    return evaluate_opa_with_data(plan_json, [ALLOWLISTS, CONTROL_SETS, context_file(context)])


def evaluate_opa_with_data(plan_json, data_files):
    """Low-level OPA call with explicit data files (also used by the message audit)."""
    cmd = [find_binary("opa"), "eval", "-f", "json", "-i", str(plan_json), "-d", str(POLICY_DIR)]
    for f in data_files:
        cmd += ["-d", str(f)]
    cmd.append("data.main.deny")
    p, secs = _run(cmd)
    if p.returncode != 0:
        raise ScofError("opa eval failed:\n" + _tail(p))
    try:
        doc = json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        raise ScofError(f"opa returned invalid JSON: {exc}")
    result = doc.get("result")
    if not result:
        raise ScofError("data.main.deny is undefined: the policies were not loaded correctly")
    value = result[0]["expressions"][0]["value"]
    return sorted(set(value)), secs


def evaluate_conftest(plan_json, context):
    ctx = context_file(context)
    cmd = [find_binary("conftest"), "test", str(plan_json), "--policy", str(POLICY_DIR),
           "--data", str(ALLOWLISTS), "--data", str(CONTROL_SETS), "--data", str(ctx), "--output", "json", "--no-color"]
    p, secs = _run(cmd)
    if not (p.stdout or "").strip():
        raise ScofError("conftest produced no output:\n" + _tail(p))
    try:
        doc = json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        raise ScofError(f"conftest returned invalid JSON: {exc}\n" + _tail(p))
    msgs = [f["msg"] for r in doc for f in (r.get("failures") or [])]
    return sorted(set(msgs)), secs


def evaluate(engine: str, plan_json, context):
    if engine == "opa":
        return evaluate_opa(plan_json, context)
    if engine == "conftest":
        return evaluate_conftest(plan_json, context)
    raise ScofError(f"Unknown engine '{engine}' (use opa or conftest)")


# ---------------------------------------------------------------- locations

_ADDR_RE = re.compile(r"^(?P<type>[a-z0-9_]+)\.(?P<name>[A-Za-z0-9_-]+)")


def find_location(tf_dir, v: Violation):
    """Best-effort source line for a violation (root module only)."""
    files = sorted(Path(tf_dir).glob("*.tf"))
    patterns = []
    m = _ADDR_RE.match(v.address) if v.address else None
    if m:
        patterns.append(re.compile(r'^\s*resource\s+"' + re.escape(m.group("type"))
                                   + r'"\s+"' + re.escape(m.group("name")) + r'"'))
    if v.control == "REGION-RESTRICTION":
        patterns.append(re.compile(r'^\s*provider\s+"aws"'))
    for pat in patterns:
        for f in files:
            for n, text in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if pat.match(text):
                    return f, n
    return (files[0] if files else Path(tf_dir)), 1


# ---------------------------------------------------------------- pipeline

def lint(context, engine="opa", tf_dir=None, plan=None, save_plan=None) -> LintResult:
    t0 = time.perf_counter()
    timings = {"plan_s": 0.0, "show_s": 0.0}
    tmp = None
    try:
        if plan:
            plan_path = Path(plan).resolve()
            if not plan_path.is_file():
                raise ScofError(f"Plan file not found: {plan_path}")
        else:
            if tf_dir is None:
                raise ScofError("Either a Terraform directory or a plan file is required")
            if save_plan:
                plan_path = Path(save_plan).resolve()
            else:
                tmp = tempfile.TemporaryDirectory()
                plan_path = Path(tmp.name) / "plan.json"
            timings.update(generate_plan(tf_dir, plan_path))
        msgs, eval_s = evaluate(engine, plan_path, context)
    finally:
        if tmp is not None:
            tmp.cleanup()
    violations = to_violations(msgs)
    for v in violations:
        if tf_dir is not None:
            f, n = find_location(tf_dir, v)
            v.file, v.line = str(Path(f).resolve()), n
        else:
            v.file, v.line = str(plan_path), 1
    timings["eval_s"] = eval_s
    timings["total_s"] = time.perf_counter() - t0
    return LintResult(context, engine, violations, timings)


def diagnostic_line(v: Violation) -> str:
    """Compiler-style line consumed by the VS Code problem matcher."""
    reason = " ".join(v.reason.split())
    addr = f"{v.address}: " if v.address else ""
    return f"{v.file}:{v.line}:1: error: [{v.control}] {addr}{reason}"


# ---------------------------------------------------------------- manifest

def load_manifest() -> list:
    path = REPO_ROOT / "tests" / "manifest.csv"
    if not path.is_file():
        raise ScofError(f"Manifest not found: {path}")
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)
        header = reader.fieldnames or []
    missing = [c for c in MANIFEST_COLUMNS if c not in header]
    if missing:
        raise ScofError(f"manifest.csv is missing columns {missing}; header is {header}")
    return [{k: (v or "").strip() for k, v in r.items() if k is not None} for r in rows]


def fixture_name(row: dict) -> str:
    """Bare fixture name, whether the manifest holds 'x' or 'tests/compliant/x'."""
    raw = row["fixture"].replace("\\", "/").strip().strip("/")
    return raw.rsplit("/", 1)[-1]


def fixture_dir(row: dict) -> Path:
    raw = row["fixture"].replace("\\", "/").strip().strip("/")
    # 1) the manifest gave a path (repo-relative, or relative to tests/)
    if "/" in raw:
        for base in (REPO_ROOT, REPO_ROOT / "tests"):
            d = base / raw
            if d.is_dir():
                return d
    # 2) bare name: look in the folder matching the expectation first
    name = fixture_name(row)
    first = "compliant" if row["expected"].upper() == "PASS" else "non_compliant"
    second = "non_compliant" if first == "compliant" else "compliant"
    for sub in (first, second):
        d = REPO_ROOT / "tests" / sub / name
        if d.is_dir():
            return d
    raise ScofError(f"Fixture directory not found for '{row['fixture']}'")