"""D-021 guard: no consumer other than scof_core.py may parse violation strings.
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
        self.assertEqual([], offenders, "independent colon parsing found (D-021):\n" + "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()