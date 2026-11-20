"""SCOF shared policy-result consumer.

The CLI, the VS Code watcher and the CI gate all import this module. None of
them may split violation messages on their own.

Contract: "CONTROL-ID: resource address: reason"
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import scof_findings

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "policies"
ROUTER_DIR = REPO_ROOT / "router" / "policy-routing"
ALLOWLISTS = ROUTER_DIR / "region_allowlists.json"
KNOWN_CONTEXTS = ROUTER_DIR / "known_contexts.json"
CONTROL_SETS = ROUTER_DIR / "control_sets.json"
CONTEXT_DIR = ROUTER_DIR / "contexts"
# Shared Terraform plugin cache: SCOF_TF_PLUGIN_CACHE if set, else a default folder in the user's home.
_cache_dir = os.environ.get("SCOF_TF_PLUGIN_CACHE") or str(Path.home() / ".scof" / "tf-plugin-cache")
PLUGIN_CACHE = Path(_cache_dir).expanduser()
PROCESS_TIMEOUT_S = 600
KNOWN_CONTROLS = set(scof_findings._KNOWN_CONTROL_IDS)


class ScofError(Exception):
    """Tooling problem (missing binary, terraform failure, bad engine output).
    This is never a policy verdict."""


class EngineDisagreement(ScofError):
    """OPA and Conftest returned different findings for the same plan and context.
    The result cannot be trusted, so it is a tooling error and never a pass."""


@dataclass
class Violation:
    control: str
    address: str
    reason: str
    raw: str
    parsed: bool = True
    file: str = ""
    line: int = 0
    enrichment: dict = field(default_factory=dict)


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
                {
                    "control": v.control, "address": v.address, "reason": v.reason,
                    "raw": v.raw, "parsed": v.parsed, "file": v.file, "line": v.line,
                    **{k: value for k, value in v.enrichment.items() if k != "violation"},
                }
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
    env_vars = {
        "terraform": "SCOF_TERRAFORM",
        "opa": "SCOF_OPA",
        "conftest": "SCOF_CONFTEST",
    }
    override = os.environ.get(env_vars.get(name.lower(), ""))

    if override:
        configured = Path(override).expanduser()
        if not configured.is_file():
            raise ScofError(
                f"{env_vars[name.lower()]} points to a missing executable: {configured}"
            )
        return str(configured.resolve())

    path = shutil.which(name)
    if not path:
        raise ScofError(
            f"'{name}' was not found on PATH. Install it or open a new terminal."
        )
    return path


def _run(cmd, env=None, timeout=None):
    timeout = timeout or PROCESS_TIMEOUT_S
    t0 = time.perf_counter()
    try:
        p = subprocess.run(cmd, env=env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise ScofError(f"{Path(cmd[0]).name} did not finish within {timeout} seconds") from exc
    return p, time.perf_counter() - t0


def _tail(p, n: int = 15) -> str:
    err = (p.stderr or "").strip().splitlines()
    out = (p.stdout or "").strip().splitlines()
    return "\n".join((err or out)[-n:])


def _platform_dir() -> str:
    system = {"windows": "windows", "linux": "linux", "darwin": "darwin"}.get(platform.system().lower())
    arch = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine().lower())
    return f"{system}_{arch}" if system and arch else ""


def _provider_override(tf_dir) -> str | None:
    """CLI config that points hashicorp/aws at the cached provider, so tf_dir gets no copy of it.

    Only used when the cache already holds the version pinned in the lock file and aws is the only
    provider; otherwise None and Terraform installs the provider normally (filling the cache).
    shortcut: aws only, because every reference configuration uses it; add providers when one needs it.
    """
    if not tf_dir:
        return None
    try:
        lock = (Path(tf_dir) / ".terraform.lock.hcl").read_text(encoding="utf-8")
    except OSError:
        return None
    names = re.findall(r'^provider "([^"]+)"', lock, re.M)
    m = re.search(r'^provider "registry\.terraform\.io/hashicorp/aws" \{\s*version\s*=\s*"([0-9][^"/\\]*)"', lock, re.M)
    plat = _platform_dir()
    if names != ["registry.terraform.io/hashicorp/aws"] or not m or not plat:
        return None
    pdir = PLUGIN_CACHE / "registry.terraform.io" / "hashicorp" / "aws" / m.group(1) / plat
    if not any(pdir.glob("terraform-provider-aws*")):
        return None
    text = f'provider_installation {{\n  dev_overrides {{\n    "hashicorp/aws" = "{pdir.as_posix()}"\n  }}\n  direct {{}}\n}}\n'
    rc = Path.home() / ".scof" / f"override-aws-{m.group(1)}-{plat}.tfrc"
    try:
        rc.parent.mkdir(parents=True, exist_ok=True)
        if not rc.is_file() or rc.read_text(encoding="utf-8") != text:
            rc.write_text(text, encoding="utf-8")
    except OSError:
        return None
    return str(rc)


def _tf_env(tf_dir=None) -> dict:
    env = os.environ.copy()
    # Always mock: a developer's real AWS credentials must never reach a plan.
    env.update(AWS_ACCESS_KEY_ID="mock", AWS_SECRET_ACCESS_KEY="mock", AWS_EC2_METADATA_DISABLE="true")
    for name in ("AWS_SESSION_TOKEN", "AWS_PROFILE"):
        env.pop(name, None)
    env.setdefault("TF_IN_AUTOMATION", "1")
    if PLUGIN_CACHE:
        try:
            PLUGIN_CACHE.mkdir(parents=True, exist_ok=True)  # the first run downloads into it, later runs reuse it
        except OSError:
            pass  # shortcut: no cache, Terraform then downloads per folder as before
    if PLUGIN_CACHE and PLUGIN_CACHE.is_dir():
        env.setdefault("TF_PLUGIN_CACHE_DIR", str(PLUGIN_CACHE))
        env.setdefault("TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE", "true")
        if "TF_CLI_CONFIG_FILE" not in env:  # a developer's own CLI config always wins
            override = _provider_override(tf_dir)
            if override:
                env["TF_CLI_CONFIG_FILE"] = override
    return env


def generate_plan(tf_dir, plan_json_path) -> dict:
    """terraform init (once) + plan + show -json. Returns stage timings."""
    tf_dir = Path(tf_dir).resolve()
    if not list(tf_dir.glob("*.tf")):
        raise ScofError(f"No .tf files in {tf_dir}")
    tf = find_binary("terraform")
    env = _tf_env(tf_dir)
    if not (tf_dir / ".terraform").is_dir():
        p, _ = _run([tf, f"-chdir={tf_dir}", "init", "-input=false", "-no-color"], env)
        if p.returncode != 0:
            raise ScofError("terraform init failed:\n" + _tail(p))
        # That init filled the shared cache. From here on point at the cached provider and drop the
        # per-folder copy init just made (only this run's own folder: .terraform did not exist before).
        env = _tf_env(tf_dir)
        if "TF_CLI_CONFIG_FILE" in env and "TF_CLI_CONFIG_FILE" not in os.environ:
            shutil.rmtree(tf_dir / ".terraform", ignore_errors=True)
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
    return evaluate_opa_with_data(plan_json, [ALLOWLISTS, KNOWN_CONTEXTS, CONTROL_SETS, context_file(context)])


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
           "--data", str(ALLOWLISTS), "--data", str(KNOWN_CONTEXTS), "--data", str(CONTROL_SETS), "--data", str(ctx), "--output", "json", "--no-color"]
    p, secs = _run(cmd)
    if not (p.stdout or "").strip():
        raise ScofError("conftest produced no output:\n" + _tail(p))
    try:
        doc = json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        raise ScofError(f"conftest returned invalid JSON: {exc}\n" + _tail(p))
    msgs = [f["msg"] for r in doc for f in (r.get("failures") or [])]
    return sorted(set(msgs)), secs


ENGINES = ("opa", "conftest")


def evaluate_both(plan_json, context):
    """Run OPA and Conftest on the same plan and context and require identical findings.

    Returns (messages, seconds) only when both engines ran successfully and returned exactly the same
    set of violation messages. If either engine fails, or the two sets differ, raise ScofError
    (EngineDisagreement for a difference): the result is a tooling error, never a pass.
    """
    results, errors, total = {}, {}, 0.0
    for name in ENGINES:
        try:
            msgs, secs = evaluate(name, plan_json, context)
        except ScofError as exc:
            errors[name] = str(exc)
            continue
        results[name] = msgs
        total += secs
    if errors:
        detail = "; ".join(f"{n}: {' '.join(e.split())[:200]}" for n, e in errors.items())
        raise ScofError("Both engines must run successfully; no result was produced (" + detail + ")")
    if results["opa"] != results["conftest"]:
        only_opa = sorted(set(results["opa"]) - set(results["conftest"]))
        only_cft = sorted(set(results["conftest"]) - set(results["opa"]))
        parts = []
        if only_opa:
            parts.append("only OPA reported: " + " | ".join(only_opa)[:300])
        if only_cft:
            parts.append("only Conftest reported: " + " | ".join(only_cft)[:300])
        raise EngineDisagreement("ENGINE-DISAGREEMENT: OPA and Conftest gave different findings (" + "; ".join(parts) + ")")
    return results["opa"], total


def evaluate(engine: str, plan_json, context):
    if engine == "opa":
        return evaluate_opa(plan_json, context)
    if engine == "conftest":
        return evaluate_conftest(plan_json, context)
    if engine == "both":
        return evaluate_both(plan_json, context)
    raise ScofError(f"Unknown engine '{engine}' (use opa, conftest or both)")


# ---------------------------------------------------------------- locations

_ADDR_RE = re.compile(r"^(?P<type>[a-z0-9_]+)\.(?P<name>[A-Za-z0-9_-]+)")


def find_location(tf_dir, v: Violation, lines_cache=None):
    """Best-effort source line for a violation (root module only).

    Pass one dict as lines_cache across calls to read each .tf file only once."""
    cache = {} if lines_cache is None else lines_cache
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
            if f not in cache:
                cache[f] = f.read_text(encoding="utf-8", errors="replace").splitlines()
            for n, text in enumerate(cache[f], 1):
                if pat.match(text):
                    return f, n
    return (files[0] if files else Path(tf_dir)), 1


# ---------------------------------------------------------------- pipeline

def lint(context, engine="both", tf_dir=None, plan=None, save_plan=None) -> LintResult:
    try:
        scof_findings.validate_configuration()
    except RuntimeError as exc:
        raise ScofError(f"Enrichment configuration error: {exc}") from exc
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
    enrichment_results = scof_findings.enrich_all([v.raw for v in violations], context)
    for v, enrichment in zip(violations, enrichment_results):
        # Keep the raw violation string in v.raw; append only structured metadata.
        v.enrichment = {
            key: value for key, value in enrichment.items() if key != "violation"
        }
    lines_cache = {}
    for v in violations:
        if tf_dir is not None:
            f, n = find_location(tf_dir, v, lines_cache)
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
