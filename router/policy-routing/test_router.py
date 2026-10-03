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

    def test_every_known_context_is_routable(self):
        self.assertEqual(set(r.known_contexts()), {x["context"] for x in r.load_routes()})

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


if __name__ == "__main__":
    unittest.main()