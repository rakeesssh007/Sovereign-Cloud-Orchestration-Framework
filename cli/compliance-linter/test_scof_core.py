import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()