import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import scof_core as core


def _load(name):
    return json.loads((core.ROUTER_DIR / name).read_text(encoding="utf-8"))


class ControlSetConsistency(unittest.TestCase):
    def setUp(self):
        self.sets = _load("control_sets.json")["control_sets"]
        allow = _load("region_allowlists.json")
        self.known = set(allow["known_contexts"])
        self.lists = allow["region_allowlists"]

    def test_sets_cover_exactly_the_known_contexts(self):
        self.assertEqual(set(self.sets), self.known)

    def test_every_listed_control_is_a_known_control(self):
        for ctx, controls in self.sets.items():
            self.assertTrue(controls, ctx)
            self.assertEqual(len(controls), len(set(controls)), ctx)
            self.assertLessEqual(set(controls), core.KNOWN_CONTROLS, ctx)

    def test_every_enforced_control_is_enabled_somewhere(self):
        enabled = set()
        for controls in self.sets.values():
            enabled |= set(controls)
        self.assertEqual(enabled, core.KNOWN_CONTROLS - {"CONTROL-SET"})

    def test_region_control_matches_region_allowlists(self):
        for ctx, controls in self.sets.items():
            self.assertEqual("REGION-RESTRICTION" in controls, ctx in self.lists, ctx)


class ControlSetWiring(unittest.TestCase):
    """The control-set data file must reach both engines through scof_core."""

    def setUp(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        self.plan = d / "plan.json"
        self.plan.write_text(json.dumps({
            "format_version": "1.2",
            "planned_values": {"root_module": {}},
            "resource_changes": [],
            "configuration": {
                "provider_config": {"aws": {"name": "aws",
                                            "expressions": {"region": {"constant_value": "us-east-1"}}}},
                "root_module": {"resources": []},
            },
        }), encoding="utf-8")
        self.narrow = d / "control_sets.json"
        self.narrow.write_text(json.dumps({"control_sets": {
            "india": ["DATA-ENCRYPTION"],
            "india-finance": ["DATA-ENCRYPTION"],
            "eu": ["DATA-ENCRYPTION"],
        }}), encoding="utf-8")

    def _engines(self):
        engines = ["opa"]
        try:
            core.find_binary("conftest")
            engines.append("conftest")
        except Exception:
            pass
        return engines

    def _region_msgs(self, engine):
        msgs, _ = core.evaluate(engine, self.plan, "india-finance")
        return [m for m in msgs if m.startswith("REGION-RESTRICTION")]

    def test_region_control_reported_when_enabled(self):
        for engine in self._engines():
            self.assertEqual(len(self._region_msgs(engine)), 1, engine)

    def test_region_control_not_reported_when_context_set_excludes_it(self):
        with mock.patch.object(core, "CONTROL_SETS", self.narrow):
            for engine in self._engines():
                self.assertEqual(self._region_msgs(engine), [], engine)


if __name__ == "__main__":
    unittest.main()
