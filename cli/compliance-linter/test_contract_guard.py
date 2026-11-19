"""Contract guard: no consumer other than scof_core.py may parse violation strings.
Add the marker  scof-contract-ok: <reason>  to a line that splits on a colon for an unrelated purpose."""
import re
import unittest
from pathlib import Path

import scof_core as core

ROOT = core.REPO_ROOT
PATTERNS = [re.compile(p) for p in (
    r'\.split\(\s*["\x27]:',
    r'-split\s*["\x27]:',
    r'\.partition\(\s*["\x27]:',
    r'\.Split\(\s*["\x27]:',
    r'\bcut\s+-d\s*["\x27]?:',
    r'\bawk\s+-F\s*["\x27]?:',
    r'IndexOf\(\s*["\x27]:',
)]
SKIP_DIRS = {".git", ".terraform", "scratch", "__pycache__", "deprecated", "plans", "node_modules"}
SKIP_FILES = {"scof_core.py", "test_contract_guard.py"}
SUFFIXES = {".py", ".ps1", ".yml", ".yaml", ".sh"}


class ContractGuard(unittest.TestCase):
    def test_no_independent_colon_parsing(self):
        offenders, scanned = [], []
        for p in ROOT.rglob("*"):
            if not p.is_file() or p.suffix not in SUFFIXES or p.name in SKIP_FILES:
                continue
            if any(part in SKIP_DIRS for part in p.relative_to(ROOT).parts):
                continue
            scanned.append(p.name)
            for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if "scof-contract-ok" in line:
                    continue
                if any(pat.search(line) for pat in PATTERNS):
                    offenders.append(f"{p.relative_to(ROOT)}:{n}: {line.strip()}")
        self.assertIn("scof_lint.py", scanned, "guard did not scan the CLI; check SKIP_DIRS")
        self.assertEqual([], offenders, "independent colon parsing found:\n" + "\n".join(offenders))


    def test_shared_core_owns_finding_enrichment(self):
        core_source = Path(core.__file__).read_text(encoding="utf-8")
        self.assertRegex(core_source, r"(?m)^import scof_findings$")
        self.assertIn("scof_findings.enrich_all(", core_source)

    def test_existing_finding_fields_remain_before_enrichment(self):
        finding = core.Violation(
            "DATA-ENCRYPTION", "aws_s3_bucket.x", "not encrypted", "original raw",
            enrichment={"enrichment_status": "OK", "basis_label": "INTERPRETATION"},
        )
        payload = core.LintResult("eu", "opa", [finding]).to_dict()
        row = payload["violations"][0]
        keys = list(row)
        self.assertEqual(
            keys[:7],
            ["control", "address", "reason", "raw", "parsed", "file", "line"],
        )
        self.assertEqual(row["raw"], "original raw")
        self.assertEqual(row["enrichment_status"], "OK")
        self.assertEqual(row["basis_label"], "INTERPRETATION")


if __name__ == "__main__":
    unittest.main()