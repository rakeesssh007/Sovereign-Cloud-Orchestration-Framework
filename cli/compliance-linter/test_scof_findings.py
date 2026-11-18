"""Unit tests for SCOF finding enrichment (Phase 2C)."""

import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import scof_findings as sf  # noqa: E402


CATALOGUE = {
    "controls": {
        "DATA-ENCRYPTION": {
            "basis_label": "INTERPRETATION",
            "sources": ["S2", "S5"],
            "legal_requirement": "Security measures; encryption is an example.",
            "scof_interpretation": "SSE with AWS KMS is the SCOF baseline.",
            "applicability": "Base control; legal scope remains conditional.",
            "limitations": "KMS is stricter than a generic encryption duty.",
            "contexts": {
                "india-healthcare": {
                    "basis_label": "INTERPRETATION",
                    "sources": ["S2", "S5"],
                    "legal_requirement": "Healthcare context source wording.",
                    "scof_interpretation": "Healthcare context interpretation.",
                    "applicability": "Healthcare context.",
                    "limitations": "DPDP Rule 6 is future-effective.",
                }
            },
        },
        "LOG-RETENTION": {
            "contexts": {
                "india-healthcare": {
                    "basis_label": "INTERPRETATION",
                    "sources": ["S2", "S42", "S43"],
                    "legal_requirement": "CERT-In and scheduled DPDP duties have distinct scope.",
                    "scof_interpretation": "365-day CloudWatch project baseline.",
                    "applicability": "Healthcare entity and workload applicability must be checked.",
                    "limitations": "Does not prove full ICT logging or legal compliance.",
                },
                "india-finance": {
                    "basis_label": "INTERPRETATION",
                    "sources": ["S2", "S42", "S43"],
                    "legal_requirement": "Finance source wording.",
                    "scof_interpretation": "365-day CloudWatch project baseline.",
                    "applicability": "Finance entity and activity applicability must be checked.",
                    "limitations": "Does not prove full ICT logging or legal compliance.",
                },
            }
        },
        "REGION-RESTRICTION": {
            "contexts": {
                "india-finance": {
                    "basis_label": "INTERPRETATION",
                    "sources": ["S1"],
                    "legal_requirement": "Narrow payment-system-data localisation scope.",
                    "scof_interpretation": "India-region technical proxy.",
                    "applicability": "Only in-scope payment-system providers and data.",
                    "limitations": "Does not model foreign-leg exceptions.",
                }
            }
        },
    }
}


class TestControlIdExtraction(unittest.TestCase):
    def test_known_prefix(self):
        self.assertEqual(
            sf._extract_control_id("DATA-ENCRYPTION: aws_db_instance.x: RDS instance must set storage_encrypted = true"),
            "DATA-ENCRYPTION",
        )

    def test_provider_pseudo_subject(self):
        self.assertEqual(
            sf._extract_control_id("REGION-RESTRICTION: provider.aws: wrong region"),
            "REGION-RESTRICTION",
        )

    def test_colons_after_prefix_do_not_change_id(self):
        msg = 'DATA-ENCRYPTION: module.x.bucket["a:b"]: not encrypted'
        self.assertEqual(sf._extract_control_id(msg), "DATA-ENCRYPTION")

    def test_malformed_and_non_string(self):
        self.assertIsNone(sf._extract_control_id("malformed"))
        self.assertIsNone(sf._extract_control_id(""))
        self.assertIsNone(sf._extract_control_id(None))
        self.assertIsNone(sf._extract_control_id(12))


class TestEnrichment(unittest.TestCase):
    def test_original_violation_is_preserved_exactly(self):
        msg = "DATA-ENCRYPTION: aws_s3_bucket.x: S3 bucket must use KMS encryption (sse_algorithm aws:kms)"
        result = sf.enrich(msg, "india-finance", CATALOGUE)
        self.assertEqual(result["violation"], msg)

    def test_enriches_common_control(self):
        result = sf.enrich(
            "DATA-ENCRYPTION: aws_db_instance.x: RDS instance must set storage_encrypted = true",
            "india-finance",
            CATALOGUE,
        )
        self.assertEqual(result["enrichment_status"], "OK")
        self.assertEqual(result["basis_label"], "INTERPRETATION")
        self.assertEqual(result["sources"], ["S2", "S5"])
        self.assertIn("KMS", result["scof_interpretation"])

    def test_context_specific_healthcare_entry(self):
        result = sf.enrich(
            "LOG-RETENTION: aws_cloudwatch_log_group.x: retains logs for 30 days, less than the SCOF baseline of 365 days",
            "india-healthcare",
            CATALOGUE,
        )
        self.assertEqual(result["enrichment_status"], "OK")
        self.assertIn("Healthcare", result["applicability"])
        self.assertIn("S42", result["sources"])

    def test_context_specific_finance_entry(self):
        result = sf.enrich(
            "LOG-RETENTION: aws_cloudwatch_log_group.x: retains logs for 30 days, less than the SCOF baseline of 365 days",
            "india-finance",
            CATALOGUE,
        )
        self.assertEqual(result["enrichment_status"], "OK")
        self.assertIn("Finance", result["legal_requirement"])

    def test_falls_back_to_top_level_entry(self):
        result = sf.enrich(
            "DATA-ENCRYPTION: aws_db_instance.x: RDS instance must set storage_encrypted = true", "eu", CATALOGUE
        )
        self.assertEqual(result["enrichment_status"], "OK")
        self.assertEqual(result["sources"], ["S2", "S5"])

    def test_unknown_control_fails_closed(self):
        result = sf.enrich("MADE-UP: resource.x: reason", "eu", CATALOGUE)
        self.assertEqual(result["enrichment_status"], "UNKNOWN")
        self.assertNotIn("basis_label", result)

    def test_malformed_message_fails_closed(self):
        result = sf.enrich("no control prefix", "eu", CATALOGUE)
        self.assertEqual(result["enrichment_status"], "UNKNOWN")
        self.assertIsNone(result["control_id"])

    def test_registered_but_uncatalogued_control_is_unknown(self):
        result = sf.enrich(
            "CONTROL-SET: context.deployment: no control set defined for context 'eu'; every control is evaluated", "eu", CATALOGUE
        )
        self.assertEqual(result["enrichment_status"], "UNKNOWN")

    def test_known_control_with_unregistered_message_fails_closed(self):
        result = sf.enrich(
            "DATA-ENCRYPTION: aws_db_instance.x: invented message text",
            "eu", CATALOGUE
        )
        self.assertEqual(result["enrichment_status"], "UNKNOWN")
        self.assertNotIn("basis_label", result)

    def test_audit_spelling_does_not_override_policy_template(self):
        result = sf.enrich(
            "BACKUP-RESILIENCE: aws_db_instance.x: backup_retention_period is not set to a known value at plan time; set it explicitly to at least 1",
            "eu", CATALOGUE
        )
        self.assertEqual(result["enrichment_status"], "UNKNOWN")

    def test_ui_field_map_hook_is_empty(self):
        result = sf.enrich(
            "DATA-ENCRYPTION: aws_db_instance.x: RDS instance must set storage_encrypted = true",
            "india-healthcare",
            CATALOGUE,
        )
        self.assertEqual(result["ui_field_ids"], {})
        self.assertEqual(sf.ui_field_ids("DATA-ENCRYPTION", "eu"), {})

    def test_unknown_context_uses_top_level_if_available(self):
        result = sf.enrich(
            "DATA-ENCRYPTION: aws_db_instance.x: RDS instance must set storage_encrypted = true",
            "not-a-context",
            CATALOGUE,
        )
        self.assertEqual(result["enrichment_status"], "OK")


class TestEnrichAll(unittest.TestCase):
    def test_preserves_order_and_original_messages(self):
        messages = [
            "DATA-ENCRYPTION: aws_db_instance.a: RDS instance must set storage_encrypted = true",
            "LOG-RETENTION: aws_cloudwatch_log_group.b: retains logs for 30 days, less than the SCOF baseline of 365 days",
            "MADE-UP: resource.c: unknown",
        ]
        results = sf.enrich_all(messages, "india-healthcare", CATALOGUE)
        self.assertEqual([r["violation"] for r in results], messages)
        self.assertEqual(
            [r["enrichment_status"] for r in results], ["OK", "OK", "UNKNOWN"]
        )

    def test_empty_list(self):
        self.assertEqual(sf.enrich_all([], "eu", CATALOGUE), [])

    def test_catalogue_load_failure_is_reported_for_known_ids(self):
        messages = ["DATA-ENCRYPTION: bucket.x: RDS instance must set storage_encrypted = true", "MADE-UP: x: issue"]
        with tempfile.TemporaryDirectory() as tmp:
            missing = pathlib.Path(tmp) / "missing.json"
            # Exercise the same fail-closed behaviour without changing process env.
            original = sf._catalogue_path
            sf._catalogue_path = lambda: missing
            try:
                results = sf.enrich_all(messages, "eu")
            finally:
                sf._catalogue_path = original
        self.assertEqual(results[0]["enrichment_status"], "CATALOGUE_ERROR")
        self.assertEqual(results[1]["enrichment_status"], "UNKNOWN")
        self.assertEqual(results[0]["violation"], messages[0])

    def test_missing_catalogue_entry_is_unknown(self):
        minimal = {"controls": {}}
        result = sf.enrich(
            "DATA-ENCRYPTION: bucket.x: RDS instance must set storage_encrypted = true", "eu", minimal
        )
        self.assertEqual(result["enrichment_status"], "UNKNOWN")


class TestCatalogueLoader(unittest.TestCase):
    def test_missing_file_raises_runtime_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError):
                sf._load_catalogue(pathlib.Path(tmp) / "missing.json")

    def test_malformed_json_raises_runtime_error(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", encoding="utf-8", delete=False
        ) as handle:
            handle.write("{not json")
            name = handle.name
        try:
            with self.assertRaises(RuntimeError):
                sf._load_catalogue(name)
        finally:
            pathlib.Path(name).unlink(missing_ok=True)

    def test_invalid_catalogue_shape_raises_runtime_error(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", encoding="utf-8", delete=False
        ) as handle:
            handle.write('{"wrong": {}}')
            name = handle.name
        try:
            with self.assertRaises(RuntimeError):
                sf._load_catalogue(name)
        finally:
            pathlib.Path(name).unlink(missing_ok=True)


class TestUiFieldMapEquivalence(unittest.TestCase):
    MESSAGE = "DATA-ENCRYPTION: aws_db_instance.x: RDS instance must set storage_encrypted = true"

    def test_with_map_changes_only_ui_field_ids(self):
        import json
        import os
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            map_path = pathlib.Path(tmp) / "scof_ui_map.json"
            map_path.write_text(json.dumps({"version": 1, "mappings": [{
                "control_id": "DATA-ENCRYPTION",
                "resource_type": "aws_db_instance",
                "field_ids": ["storage.encryption.enabled", "storage.encryption.key"],
            }]}), encoding="utf-8")
            with patch.dict(os.environ, {}, clear=True):
                without_map = sf.enrich_all([self.MESSAGE], "india-healthcare", CATALOGUE,
                                            resource_types=["aws_db_instance"])[0]
            with patch.dict(os.environ, {"SCOF_UI_FIELD_MAP": str(map_path)}, clear=True):
                with_map = sf.enrich_all([self.MESSAGE], "india-healthcare", CATALOGUE,
                                         resource_types=["aws_db_instance"])[0]
        expected_ids = {"field_ids": ["storage.encryption.enabled", "storage.encryption.key"]}
        self.assertEqual(with_map["ui_field_ids"], expected_ids)
        self.assertEqual(without_map["ui_field_ids"], {})
        without_map.pop("ui_field_ids")
        with_map.pop("ui_field_ids")
        self.assertEqual(with_map, without_map)

    def test_missing_or_invalid_map_returns_no_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = pathlib.Path(tmp) / "missing.json"
            invalid = pathlib.Path(tmp) / "invalid.json"
            invalid.write_text("not-json", encoding="utf-8")
            self.assertEqual(sf._load_ui_field_map(missing), {})
            self.assertEqual(sf._load_ui_field_map(invalid), {})

    def test_resource_type_mismatch_returns_no_ids(self):
        mapping = {("DATA-ENCRYPTION", "aws_db_instance"): ["field.one"]}
        self.assertEqual(sf.ui_field_ids("DATA-ENCRYPTION", "eu", "aws_s3_bucket", mapping), {})


class TestProductionCatalogueCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalogue = sf._load_catalogue()

    def test_catalogue_has_eight_controls_and_version_metadata(self):
        self.assertEqual(len(self.catalogue["controls"]), 8)
        meta = self.catalogue["_meta"]
        for key in ("version", "content_hash", "matrix_commit", "status_as_of", "change_log"):
            self.assertIn(key, meta)
        self.assertEqual(meta["version"], "1.3.0")

    def test_three_production_context_compositions(self):
        expected = {
            "eu": {"REGION-RESTRICTION", "DATA-ENCRYPTION", "KEY-OWNERSHIP", "KEY-ROTATION",
                   "IAM-NO-WILDCARD-ADMIN", "ACCESS-EXPOSURE", "BACKUP-RESILIENCE"},
            "india-finance": {"REGION-RESTRICTION", "DATA-ENCRYPTION", "KEY-OWNERSHIP", "KEY-ROTATION",
                              "IAM-NO-WILDCARD-ADMIN", "LOG-RETENTION", "ACCESS-EXPOSURE", "BACKUP-RESILIENCE"},
            "india-healthcare": {"DATA-ENCRYPTION", "KEY-OWNERSHIP", "KEY-ROTATION",
                                 "IAM-NO-WILDCARD-ADMIN", "LOG-RETENTION", "ACCESS-EXPOSURE", "BACKUP-RESILIENCE"},
        }
        controls = self.catalogue["controls"]
        for context, expected_ids in expected.items():
            actual = set()
            for control_id, entry in controls.items():
                contexts = entry.get("contexts", {})
                if not contexts or context in contexts:
                    actual.add(control_id)
            self.assertEqual(actual, expected_ids, context)


    def test_matrix_text_is_exactly_copied_for_all_eight_controls(self):
        import re
        matrix_path = pathlib.Path(__file__).resolve().parents[2] / "docs" / "regulation-mapping" / "regulation_control_matrix.md"
        matrix = matrix_path.read_text(encoding="utf-8")
        for control_id, entry in self.catalogue["controls"].items():
            with self.subTest(control=control_id):
                match = re.search(rf"(?m)^### {re.escape(control_id)}\s*$", matrix)
                self.assertIsNotNone(match)
                next_heading = re.search(r"(?m)^#{2,3} ", matrix[match.end():])
                end = match.end() + next_heading.start() if next_heading else len(matrix)
                self.assertEqual(entry.get("matrix_text"), matrix[match.start():end].rstrip("\n"))

    def test_source_last_updated_matches_matrix_header(self):
        import re
        matrix_path = pathlib.Path(__file__).resolve().parents[2] / "docs" / "regulation-mapping" / "regulation_control_matrix.md"
        first_line = matrix_path.read_text(encoding="utf-8").splitlines()[2]
        match = re.search(r"Last updated: (\d{4}-\d{2}-\d{2})", first_line)
        self.assertIsNotNone(match)
        self.assertEqual(self.catalogue["_meta"]["source_last_updated"], match.group(1))

    def test_every_source_mapping_has_legal_status(self):
        for control_id, entry in self.catalogue["controls"].items():
            for node in [entry, *entry.get("contexts", {}).values()]:
                for mapping in node.get("source_mappings", []):
                    with self.subTest(control=control_id, source=mapping.get("source_id")):
                        self.assertTrue(mapping.get("legal_status"))
class TestConfigurationValidation(unittest.TestCase):
    def test_valid_configuration_loads_catalogue_and_registry(self):
        with (
            patch.object(sf, "_load_catalogue", return_value=CATALOGUE) as catalogue,
            patch.object(sf, "_load_message_registry", return_value=[]) as registry,
        ):
            sf.validate_configuration()

        catalogue.assert_called_once()
        registry.assert_called_once()

    def test_catalogue_failure_is_propagated(self):
        with (
            patch.object(sf, "_load_catalogue", side_effect=RuntimeError("bad catalogue")),
            patch.object(sf, "_load_message_registry", return_value=[]),
        ):
            with self.assertRaisesRegex(RuntimeError, "bad catalogue"):
                sf.validate_configuration()

    def test_registry_failure_is_propagated(self):
        with (
            patch.object(sf, "_load_catalogue", return_value=CATALOGUE),
            patch.object(sf, "_load_message_registry", side_effect=RuntimeError("bad registry")),
        ):
            with self.assertRaisesRegex(RuntimeError, "bad registry"):
                sf.validate_configuration()

if __name__ == "__main__":
    unittest.main()
