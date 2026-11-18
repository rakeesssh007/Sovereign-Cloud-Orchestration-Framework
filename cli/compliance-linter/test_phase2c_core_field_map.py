"""Tests for resource-type extraction in the shared core."""
import pathlib
import sys
import unittest
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import scof_core as core  # noqa: E402

class ResourceTypeExtractionTests(unittest.TestCase):
    def test_simple_resource_address(self):
        self.assertEqual(core._resource_type_from_address("aws_db_instance.main"), "aws_db_instance")
    def test_module_resource_address(self):
        self.assertEqual(core._resource_type_from_address('module.storage.aws_s3_bucket.data["logs"]'), "aws_s3_bucket")
    def test_provider_or_invalid_address_has_no_resource_type(self):
        self.assertEqual(core._resource_type_from_address("provider aws"), "")
        self.assertEqual(core._resource_type_from_address(""), "")

if __name__ == "__main__":
    unittest.main()
