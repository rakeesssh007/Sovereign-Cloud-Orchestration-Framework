"""Tests for the coverage rules of the CI gate (scripts/ci_gate.py)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import ci_gate  # noqa: E402


def make_repo(root: Path, folders: dict, declared: list) -> Path:
    for name, files in folders.items():
        (root / "terraform" / name).mkdir(parents=True)
        for f in files:
            (root / "terraform" / name / f).write_text("# test\n", encoding="utf-8")
    targets = root / "targets.json"
    targets.write_text(json.dumps({"targets": [{"dir": f"terraform/{d}", "jurisdiction": "eu"} for d in declared]}),
                       encoding="utf-8")
    return targets


class CoverageTests(unittest.TestCase):
    def run_gate(self, folders, declared):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            targets = make_repo(root, folders, declared)
            argv = ["ci_gate", "--targets", str(targets), "--out", str(root / "out.json")]
            with patch.object(ci_gate, "ROOT", root), patch.object(sys, "argv", argv):
                with self.assertRaises(SystemExit) as ctx:
                    ci_gate.main()
            return ctx.exception.code

    def test_folder_without_main_tf_is_still_found(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_repo(root, {"billing": ["storage.tf"]}, [])
            with patch.object(ci_gate, "ROOT", root):
                self.assertEqual(ci_gate.discover(root / "terraform"), {"terraform/billing"})

    def test_undeclared_terraform_folder_is_an_error(self):
        self.assertEqual(self.run_gate({"billing": ["storage.tf"]}, ["other"]), 2)

    def test_declared_target_without_tf_files_is_an_error(self):
        self.assertEqual(self.run_gate({"other": ["notes.txt"]}, ["other"]), 2)


if __name__ == "__main__":
    unittest.main()
