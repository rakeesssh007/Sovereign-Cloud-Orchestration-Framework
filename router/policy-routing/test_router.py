import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import scof_router as r  # noqa: E402


class RoutingTests(unittest.TestCase):
    def _tmp_routes(self, obj):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        p = Path(d) / "routes.json"
        p.write_text(json.dumps(obj), encoding="utf-8")
        return p

    def test_india_finance(self):
        self.assertEqual(r.resolve("india", "finance"), "india-finance")

    def test_eu_without_sector(self):
        self.assertEqual(r.resolve("eu"), "eu")

    def test_case_and_whitespace(self):
        self.assertEqual(r.resolve("  India ", " FINANCE "), "india-finance")

    def test_eu_with_sector_fails_closed(self):
        with self.assertRaises(r.RouterError):
            r.resolve("eu", "finance")

    def test_india_without_sector_fails_closed(self):
        with self.assertRaises(r.RouterError):
            r.resolve("india")

    def test_healthcare_is_not_routed(self):
        with self.assertRaises(r.RouterError):
            r.resolve("india", "healthcare")

    def test_unknown_jurisdiction(self):
        with self.assertRaises(r.RouterError):
            r.resolve("mars", "finance")

    def test_missing_jurisdiction(self):
        for value in ("", "   ", None):
            with self.assertRaises(r.RouterError):
                r.resolve(value, "finance")

    def test_route_to_unknown_context(self):
        p = self._tmp_routes({"routes": [{"jurisdiction": "mars", "sector": "finance", "context": "mars-finance"}]})
        with self.assertRaises(r.RouterError):
            r.resolve("mars", "finance", routes_file=p)

    def test_ambiguous_routes(self):
        route = {"jurisdiction": "eu", "sector": None, "context": "eu"}
        p = self._tmp_routes({"routes": [route, route]})
        with self.assertRaises(r.RouterError):
            r.resolve("eu", routes_file=p)

    def test_missing_routes_file(self):
        with self.assertRaises(r.RouterError):
            r.resolve("eu", routes_file=HERE / "does_not_exist.json")

    def test_unrouted_known_contexts_are_only_the_base_only_context(self):
        routed = {x["context"] for x in r.load_routes()}
        self.assertTrue(routed <= set(r.known_contexts()))
        self.assertEqual(set(r.known_contexts()) - routed, {"india"})

    def test_committed_context_files_match_generated(self):
        for ctx in r.known_contexts():
            on_disk = (r.CONTEXT_DIR / (ctx + ".json")).read_bytes().replace(b"\r\n", b"\n")
            self.assertEqual(on_disk, r.context_json(ctx).encode("utf-8"), ctx)

    def test_write_context_file_shape(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = r.write_context_file("eu", out_dir=d)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"context": "eu"})

    def test_write_rejects_unknown_context(self):
        with self.assertRaises(r.RouterError):
            r.write_context_file("bogus-context", out_dir=tempfile.gettempdir())

    def _cli(self, *args):
        return subprocess.run([sys.executable, str(HERE / "scof_router.py"), *args],
                              capture_output=True, text=True)

    def test_cli_success(self):
        done = self._cli("--jurisdiction", "india", "--sector", "finance")
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout.strip(), "india-finance")

    def test_cli_error_exit_code(self):
        done = self._cli("--jurisdiction", "india", "--sector", "healthcare")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout.strip(), "")
        self.assertIn("router error", done.stderr)


class ControlSetTests(unittest.TestCase):
    def _tmp_sets(self, obj):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        p = Path(d) / "control_sets.json"
        p.write_text(json.dumps(obj), encoding="utf-8")
        return p

    def test_every_known_context_has_a_control_set(self):
        for ctx in r.known_contexts():
            self.assertTrue(r.controls_for(ctx), ctx)

    def test_control_sets_cover_exactly_the_known_contexts(self):
        self.assertEqual(set(r.load_control_sets()), set(r.known_contexts()))

    def test_region_control_differs_by_context(self):
        self.assertIn("REGION-RESTRICTION", r.controls_for("eu"))
        self.assertIn("REGION-RESTRICTION", r.controls_for("india-finance"))
        self.assertNotIn("REGION-RESTRICTION", r.controls_for("india"))

    def test_unknown_context_has_no_control_set(self):
        with self.assertRaises(r.RouterError):
            r.controls_for("bogus-context")

    def test_missing_control_sets_file_fails_closed(self):
        with self.assertRaises(r.RouterError):
            r.controls_for("eu", control_sets_file=HERE / "does_not_exist.json")

    def test_empty_control_set_fails_closed(self):
        p = self._tmp_sets({"control_sets": {"eu": []}})
        with self.assertRaises(r.RouterError):
            r.controls_for("eu", control_sets_file=p)

    def test_duplicate_control_ids_fail_closed(self):
        p = self._tmp_sets({"control_sets": {"eu": ["A", "A"]}})
        with self.assertRaises(r.RouterError):
            r.controls_for("eu", control_sets_file=p)

    def test_non_list_control_set_fails_closed(self):
        p = self._tmp_sets({"control_sets": {"eu": "REGION-RESTRICTION"}})
        with self.assertRaises(r.RouterError):
            r.controls_for("eu", control_sets_file=p)

    def test_cli_controls_flag(self):
        done = subprocess.run([sys.executable, str(HERE / "scof_router.py"), "--jurisdiction", "eu", "--controls"],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0)
        lines = done.stdout.strip().splitlines()
        self.assertEqual(lines[0], "eu")
        self.assertIn("REGION-RESTRICTION", lines[1])


if __name__ == "__main__":
    unittest.main()