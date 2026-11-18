import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scof_core as core


class ParseMessageTests(unittest.TestCase):
    def test_simple(self):
        v = core.parse_message("CONTROL-ID: aws_s3_bucket.data: missing encryption")
        self.assertEqual((v.control, v.address, v.reason, v.parsed),
                         ("CONTROL-ID", "aws_s3_bucket.data", "missing encryption", True))

    def test_colons_in_reason(self):
        raw = "DATA-ENCRYPTION: aws_s3_bucket_server_side_encryption_configuration.data: sse_algorithm must be aws:kms, found AES256"
        v = core.parse_message(raw)
        self.assertEqual(v.address, "aws_s3_bucket_server_side_encryption_configuration.data")
        self.assertEqual(v.reason, "sse_algorithm must be aws:kms, found AES256")

    def test_quoted_value_with_colon_space_in_reason(self):
        v = core.parse_message('CONTROL-ID: aws_s3_bucket.data: value is "foo: bar"')
        self.assertEqual(v.address, "aws_s3_bucket.data")
        self.assertEqual(v.reason, 'value is "foo: bar"')

    def test_module_address_with_colon_in_index(self):
        v = core.parse_message('CONTROL-ID: module.storage["prod:eu"]: wrong region')
        self.assertEqual(v.address, 'module.storage["prod:eu"]')
        self.assertEqual(v.reason, "wrong region")

    def test_index_key_with_colon_space(self):
        v = core.parse_message('KEY-OWNERSHIP: aws_s3_bucket.data["a: b"]: uses an AWS-managed key')
        self.assertEqual(v.address, 'aws_s3_bucket.data["a: b"]')
        self.assertEqual(v.reason, "uses an AWS-managed key")

    def test_escaped_quote_inside_index(self):
        v = core.parse_message('CONTROL-ID: aws_s3_bucket.data["a\\"b: c"]: bad')
        self.assertEqual(v.address, 'aws_s3_bucket.data["a\\"b: c"]')
        self.assertEqual(v.reason, "bad")

    def test_numeric_index(self):
        v = core.parse_message("DATA-ENCRYPTION: aws_instance.app[0]: root volume unencrypted")
        self.assertEqual(v.address, "aws_instance.app[0]")

    def test_provider_address(self):
        v = core.parse_message('REGION-RESTRICTION: provider aws: region "eu-central-1" is not allowed')
        self.assertEqual((v.control, v.address), ("REGION-RESTRICTION", "provider aws"))

    def test_unparsed_is_kept(self):
        v = core.parse_message("something unexpected: here")
        self.assertEqual(v.control, "UNPARSED")
        self.assertFalse(v.parsed)
        self.assertEqual(v.reason, "something unexpected: here")

    def test_lowercase_control_is_unparsed(self):
        self.assertFalse(core.parse_message("data-encryption: a.b: r").parsed)

    def test_control_with_digits(self):
        self.assertEqual(core.parse_message("KEY-ROTATION-2: aws_kms_key.k: r").control, "KEY-ROTATION-2")

    def test_empty_reason(self):
        v = core.parse_message("CONTROL-ID: aws_s3_bucket.data: ")
        self.assertEqual((v.address, v.reason), ("aws_s3_bucket.data", ""))

    def test_multiline_reason(self):
        v = core.parse_message("CONTROL-ID: a.b: line one\nline two")
        self.assertEqual(v.reason, "line one\nline two")

    def test_control_without_address_or_colon_space(self):
        v = core.parse_message("IAM-NO-WILDCARD-ADMIN: policy grants wildcard admin")
        self.assertEqual((v.address, v.reason), ("", "policy grants wildcard admin"))

    def test_known_ambiguity_address_less_message_with_colon_space(self):
        # Inherent limit of the string contract: the parser reads "key must rotate" as the
        # address. It is detected by is_address_shaped, and the real-message audit
        # (scripts/audit_messages.py) is what shows whether any real message does this.
        v = core.parse_message("KEY-ROTATION: key must rotate: see policy")
        self.assertEqual(v.address, "key must rotate")
        self.assertFalse(core.is_address_shaped(v.address))

    def test_to_violations_dedups_and_sorts(self):
        vs = core.to_violations(["B-X: a: r", "A-X: a: r", "A-X: a: r"])
        self.assertEqual([v.control for v in vs], ["A-X", "B-X"])

    def test_round_trip(self):
        raws = [
            "CONTROL-ID: aws_s3_bucket.data: missing encryption",
            'CONTROL-ID: aws_s3_bucket.data: value is "foo: bar"',
            'CONTROL-ID: module.storage["prod:eu"]: wrong region',
            "CONTROL-ID: aws_s3_bucket.data: ",
        ]
        for raw in raws:
            with self.subTest(raw=raw):
                v = core.parse_message(raw)
                self.assertEqual(f"{v.control}: {v.address}: {v.reason}", raw)


class AddressShapeTests(unittest.TestCase):
    def test_valid_addresses(self):
        for a in ["aws_s3_bucket.data", "aws_instance.app[0]", 'aws_s3_bucket.data["a: b"]',
                  'module.storage["prod:eu"].aws_s3_bucket.data', "data.aws_iam_policy_document.x"]:
            with self.subTest(address=a):
                self.assertTrue(core.is_address_shaped(a))

    def test_invalid_addresses(self):
        for a in ["provider aws", "", "key must rotate", "context"]:
            with self.subTest(address=a):
                self.assertFalse(core.is_address_shaped(a))


class LocationTests(unittest.TestCase):
    TF = 'provider "aws" {\n  region = "eu-central-1"\n}\n\nresource "aws_s3_bucket" "data" {\n}\n'

    def _dir(self):
        td = tempfile.TemporaryDirectory()
        (Path(td.name) / "main.tf").write_text(self.TF, encoding="utf-8")
        return td

    def test_resource_line(self):
        with self._dir() as d:
            f, n = core.find_location(d, core.Violation("DATA-ENCRYPTION", "aws_s3_bucket.data", "r", "raw"))
            self.assertEqual(n, 5)

    def test_provider_line(self):
        with self._dir() as d:
            f, n = core.find_location(d, core.Violation("REGION-RESTRICTION", "provider aws", "r", "raw"))
            self.assertEqual(n, 1)

    def test_fallback_line(self):
        with self._dir() as d:
            f, n = core.find_location(d, core.Violation("DATA-ENCRYPTION", "aws_x.y", "r", "raw"))
            self.assertEqual((f.name, n), ("main.tf", 1))

class ExecutableOverrideTests(unittest.TestCase):
    def test_explicit_executable_path_is_used(self):
        with tempfile.TemporaryDirectory() as td:
            executable = Path(td) / "opa.exe"
            executable.write_text("test executable placeholder", encoding="utf-8")
            with patch.dict(os.environ, {"SCOF_OPA": str(executable)}):
                self.assertEqual(core.find_binary("opa"), str(executable.resolve()))

    def test_missing_executable_override_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "does-not-exist.exe"
            with patch.dict(os.environ, {"SCOF_OPA": str(missing)}):
                with self.assertRaises(core.ScofError):
                    core.find_binary("opa")

    def test_missing_path_executable_fails(self):
        with (
            patch.dict(os.environ, {"SCOF_OPA": ""}),
            patch.object(core.shutil, "which", return_value=None),
        ):
            with self.assertRaises(core.ScofError):
                core.find_binary("opa")

    def test_unset_executable_override_uses_path(self):
        path_result = str(Path(tempfile.gettempdir()) / "opa")
        with (
            patch.dict(os.environ, {"SCOF_OPA": ""}),
            patch.object(core.shutil, "which", return_value=path_result),
        ):
            self.assertEqual(core.find_binary("opa"), path_result)


class PluginCacheOverrideTests(unittest.TestCase):
    def test_plugin_cache_environment_override_is_loaded(self):
        """The module-level cache path is initialized from the environment."""
        original_cache = core.PLUGIN_CACHE
        with tempfile.TemporaryDirectory() as td:
            try:
                with patch.dict(os.environ, {"SCOF_TF_PLUGIN_CACHE": td}):
                    importlib.reload(core)
                    self.assertEqual(core.PLUGIN_CACHE, Path(td).expanduser())
            finally:
                # Restore the imported module's original configuration so this
                # test cannot leak state into later tests.
                with patch.dict(
                    os.environ,
                    {"SCOF_TF_PLUGIN_CACHE": str(original_cache)},
                ):
                    importlib.reload(core)

    def test_missing_plugin_cache_is_not_passed_to_terraform(self):
        with tempfile.TemporaryDirectory() as td:
            missing_cache = Path(td) / "missing-cache"
            with (
                patch.object(core, "PLUGIN_CACHE", missing_cache),
                patch.dict(os.environ, {}, clear=True),
            ):
                env = core._tf_env()
            self.assertNotIn("TF_PLUGIN_CACHE_DIR", env)
            self.assertNotIn("TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE", env)

    def test_existing_plugin_cache_directory_is_passed_to_terraform(self):
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td)
            with (
                patch.object(core, "PLUGIN_CACHE", cache),
                patch.dict(os.environ, {}, clear=True),
            ):
                env = core._tf_env()
            self.assertEqual(env["TF_PLUGIN_CACHE_DIR"], str(cache))
            self.assertEqual(
                env["TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE"], "true"
            )

class EnrichmentConfigurationTests(unittest.TestCase):
    def test_invalid_enrichment_configuration_is_a_tooling_error(self):
        with patch.object(
            core.scof_findings,
            "validate_configuration",
            side_effect=RuntimeError("bad catalogue"),
        ):
            with self.assertRaisesRegex(core.ScofError, "Enrichment configuration error"):
                core.lint(context="eu", plan="unused.json")

if __name__ == "__main__":
    unittest.main()