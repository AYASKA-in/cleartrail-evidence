"""Adversarial tests for untrusted evidence packages and safe export publication."""
import copy
import csv
import hashlib
import io
import json
import os
import stat
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from cleartrail.core import Store, canonical, collect_run
from cleartrail.reports import bundle_bytes, controls_csv, csv_cell, export_bundle, report_html, verify_bundle


class ReportSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run = collect_run(Store(self.root / "demo.sqlite3"), {"organization": "Security test organization"}, demo=True)
        self.payload = bundle_bytes(self.run)
        with zipfile.ZipFile(io.BytesIO(self.payload)) as archive:
            self.files = {name: archive.read(name) for name in archive.namelist()}

    def package(self, files=None, *, rehash=False, special=None):
        files = dict(self.files if files is None else files)
        if rehash:
            manifest = json.loads(files["manifest.json"])
            manifest["files"] = {name: hashlib.sha256(content).hexdigest() for name, content in files.items() if name != "manifest.json"}
            files["manifest.json"] = canonical(manifest)
        target = self.root / "package.zip"
        with zipfile.ZipFile(target, "w") as archive:
            for name, content in files.items():
                archive.writestr(special if special is not None and special.filename == name else name, content)
        return target

    def modified_manifest(self, changes):
        manifest = json.loads(self.files["manifest.json"])
        manifest.update(changes)
        return self.package({**self.files, "manifest.json": canonical(manifest)})

    def modified_run(self, change):
        run = copy.deepcopy(self.run)
        change(run)
        return self.package({**self.files, "run.json": json.dumps(run).encode()}, rehash=True)

    def test_new_bundle_reports_and_csv_are_bound_to_snapshot(self):
        result = verify_bundle(self.package())
        self.assertTrue(result["valid"])
        self.assertTrue(result["rendered_views_verified"])
        self.assertFalse(result["trusted_manifest_matched"])
        self.assertEqual(result["manifest_sha256"], hashlib.sha256(self.files["manifest.json"]).hexdigest())

    def test_trusted_manifest_hash_matches_case_insensitively(self):
        expected = hashlib.sha256(self.files["manifest.json"]).hexdigest()
        self.assertTrue(verify_bundle(self.package(), expected.upper())["trusted_manifest_matched"])

    def test_mismatching_external_manifest_pin_fails(self):
        with self.assertRaisesRegex(ValueError, "independently trusted"):
            verify_bundle(self.package(), "0" * 64)

    def test_invalid_external_manifest_pins_are_rejected(self):
        for expected in (True, 1234, "", "z" * 64, "0" * 63, " " + "0" * 64):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                verify_bundle(self.package(), expected)

    def test_saved_snapshot_export_is_reproducible(self):
        self.assertEqual(self.payload, bundle_bytes(self.run))

    def test_legacy_bundle_remains_readable_with_explicit_rendering_limitation(self):
        legacy = {key: value for key, value in self.run.items() if key in {"id", "organization", "collected_at", "demo", "checks", "evidence", "summary", "schema_version", "scope"}}
        legacy["schema_version"] = 1
        files = {**self.files, "run.json": json.dumps(legacy).encode(), "report.html": b"Legacy report formatting"}
        manifest = {key: value for key, value in json.loads(files["manifest.json"]).items() if key in {"schema_version", "run_id", "collected_at", "demo", "integrity", "files"}}
        manifest["schema_version"] = 1
        files["manifest.json"] = canonical(manifest)
        result = verify_bundle(self.package(files, rehash=True))
        self.assertTrue(result["valid"])
        self.assertFalse(result["rendered_views_verified"])

    def test_manifest_schema_never_accepts_boolean_or_unknown_version(self):
        for schema in (True, False, 0, 3, "2"):
            with self.subTest(schema=schema), self.assertRaisesRegex(ValueError, "schema"):
                verify_bundle(self.modified_manifest({"schema_version": schema}))

    def test_manifest_demo_is_strict_boolean(self):
        for value in (1, "true", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                verify_bundle(self.modified_manifest({"demo": value}))

    def test_manifest_rejects_unknown_rendering_implementation(self):
        generator = {"name": "cleartrail", "version": "untrusted", "render_schema_version": 1}
        with self.assertRaisesRegex(ValueError, "generator"):
            verify_bundle(self.modified_manifest({"generator": generator}))

    def test_manifest_collection_time_must_match_snapshot(self):
        with self.assertRaisesRegex(ValueError, "metadata"):
            verify_bundle(self.modified_manifest({"collected_at": "2000-01-01T00:00:00+00:00"}))

    def test_manifest_provenance_must_match_snapshot(self):
        with self.assertRaisesRegex(ValueError, "provenance"):
            verify_bundle(self.modified_manifest({"catalog_version": "forged-catalog"}))

    def test_duplicate_manifest_keys_are_rejected(self):
        content = self.files["manifest.json"][:-1] + b',"demo":true}'
        with self.assertRaises(ValueError):
            verify_bundle(self.package({**self.files, "manifest.json": content}))

    def test_duplicate_snapshot_keys_are_rejected_after_valid_file_hash(self):
        content = self.files["run.json"].rstrip()[:-1] + b',"demo":true}'
        with self.assertRaises(ValueError):
            verify_bundle(self.package({**self.files, "run.json": content}, rehash=True))

    def test_nonfinite_json_is_rejected_after_valid_file_hash(self):
        content = self.files["run.json"].rstrip()[:-1] + b',"unexpected":NaN}'
        with self.assertRaises(ValueError):
            verify_bundle(self.package({**self.files, "run.json": content}, rehash=True))

    def test_invalid_unicode_is_clean_validation_error(self):
        with self.assertRaises(ValueError):
            verify_bundle(self.package({**self.files, "run.json": b"\xff\xfe"}, rehash=True))

    def test_rehashed_false_report_is_not_accepted(self):
        for name, content in (("report.html", b"<h1>All controls pass</h1>"), ("controls.csv", b"Control,Status\r\nGH-MFA,pass")):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "does not match"):
                verify_bundle(self.package({**self.files, name: content}, rehash=True))

    def test_rehashed_false_summary_is_not_accepted(self):
        with self.assertRaises(ValueError):
            verify_bundle(self.modified_run(lambda run: run["summary"].update(passed=14)))

    def test_rehashed_false_control_result_is_not_accepted(self):
        with self.assertRaises(ValueError):
            verify_bundle(self.modified_run(lambda run: run["checks"][0].update(status="fail")))

    def test_rehashed_unknown_evidence_reference_is_not_accepted(self):
        with self.assertRaises(ValueError):
            verify_bundle(self.modified_run(lambda run: run["checks"][0]["evidence_ids"].append("ev_" + "0" * 20)))

    def test_rehashed_evidence_index_mismatch_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, "Evidence index"):
            verify_bundle(self.package({**self.files, "evidence.json": b"[]"}, rehash=True))

    def test_invalid_snapshot_cannot_be_exported(self):
        self.run["summary"]["passed"] = 999
        with self.assertRaises(ValueError):
            bundle_bytes(self.run)

    def test_rejects_symlink_members_without_extracting_them(self):
        info = zipfile.ZipInfo("report.html")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaisesRegex(ValueError, "ordinary"):
            verify_bundle(self.package(special=info))

    def test_duplicate_member_names_are_rejected_without_extraction(self):
        target = self.root / "duplicates.zip"
        with zipfile.ZipFile(target, "w") as archive:
            for name, content in self.files.items():
                archive.writestr("report.html" if name == "controls.csv" else name, content)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify_bundle(target)

    def test_rejects_unsupported_compression(self):
        info = zipfile.ZipInfo("report.html")
        info.compress_type = zipfile.ZIP_BZIP2
        with self.assertRaisesRegex(ValueError, "ordinary"):
            verify_bundle(self.package(special=info))

    def test_rejects_encrypted_members_from_directory_metadata(self):
        target = self.package()
        content = bytearray(target.read_bytes())
        position = content.index(b"PK\x01\x02")
        flags = struct.unpack_from("<H", content, position + 8)[0]
        struct.pack_into("<H", content, position + 8, flags | 1)
        target.write_bytes(content)
        with self.assertRaisesRegex(ValueError, "unencrypted"):
            verify_bundle(target)

    def test_directory_count_is_bounded_before_zipfile_parsing(self):
        target = self.package()
        content = bytearray(target.read_bytes())
        position = content.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", content, position + 8, 60000, 60000)
        target.write_bytes(content)
        with patch("cleartrail.reports.zipfile.ZipFile") as parser:
            with self.assertRaisesRegex(ValueError, "directory"):
                verify_bundle(target)
        parser.assert_not_called()

    def test_directory_declared_member_size_is_bounded_before_decompression(self):
        target = self.package()
        content = bytearray(target.read_bytes())
        position = content.index(b"PK\x01\x02")
        struct.pack_into("<L", content, position + 24, 33 * 1024 * 1024)
        target.write_bytes(content)
        with self.assertRaisesRegex(ValueError, "size limit"):
            verify_bundle(target)

    def test_excessive_compression_ratio_is_rejected(self):
        target = self.package()
        content = bytearray(target.read_bytes())
        position = content.index(b"PK\x01\x02")
        struct.pack_into("<L", content, position + 20, 1)
        target.write_bytes(content)
        with self.assertRaisesRegex(ValueError, "compression ratio"):
            verify_bundle(target)

    def test_archive_trailing_data_is_rejected(self):
        target = self.package()
        target.write_bytes(target.read_bytes() + b"unmanifested trailing content")
        with self.assertRaises(ValueError):
            verify_bundle(target)

    def test_truncated_archive_is_clean_validation_error(self):
        target = self.root / "truncated.zip"
        target.write_bytes(self.payload[:-12])
        with self.assertRaises(ValueError):
            verify_bundle(target)

    def test_corrupt_deflate_stream_is_clean_validation_error(self):
        content = bytearray(self.payload)
        name_length, extra_length = struct.unpack_from("<HH", content, 26)
        data_offset = 30 + name_length + extra_length
        content[data_offset] ^= 0xFF
        target = self.root / "corrupt-deflate.zip"
        target.write_bytes(content)
        with self.assertRaises(ValueError):
            verify_bundle(target)

    def test_successful_export_publishes_a_complete_valid_bundle(self):
        target = self.root / "complete.zip"
        export_bundle(self.run, target)
        self.assertTrue(verify_bundle(target)["valid"])
        self.assertFalse(list(self.root.glob(".cleartrail-export-*")))

    def test_export_generation_failure_leaves_no_target_or_temporary_file(self):
        self.run["summary"]["passed"] = 999
        target = self.root / "invalid.zip"
        with self.assertRaises(ValueError):
            export_bundle(self.run, target)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob(".cleartrail-export-*")))

    def test_export_publish_failure_cleans_private_temporary_file(self):
        target = self.root / "publish-failed.zip"
        with patch("cleartrail.reports._publish_exclusive", side_effect=OSError("simulated publication failure")):
            with self.assertRaises(OSError):
                export_bundle(self.run, target)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob(".cleartrail-export-*")))

    def test_export_fsync_failure_never_publishes_partial_bundle(self):
        target = self.root / "flush-failed.zip"
        with patch("cleartrail.reports.os.fsync", side_effect=OSError("simulated flush failure")):
            with self.assertRaises(OSError):
                export_bundle(self.run, target)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob(".cleartrail-export-*")))

    def test_export_never_overwrites_existing_package(self):
        target = self.root / "existing.zip"
        target.write_bytes(b"preserve existing evidence")
        with self.assertRaises(FileExistsError):
            export_bundle(self.run, target)
        self.assertEqual(target.read_bytes(), b"preserve existing evidence")
        self.assertFalse(list(self.root.glob(".cleartrail-export-*")))

    @unittest.skipIf(os.name == "nt", "Windows symlink creation requires an optional local privilege")
    def test_export_does_not_follow_destination_symlink(self):
        protected = self.root / "protected.txt"
        protected.write_bytes(b"preserve")
        target = self.root / "linked.zip"
        target.symlink_to(protected)
        with self.assertRaises(FileExistsError):
            export_bundle(self.run, target)
        self.assertEqual(protected.read_bytes(), b"preserve")
        self.assertTrue(target.is_symlink())

    @unittest.skipIf(os.name == "nt", "Windows uses ACLs rather than POSIX file modes")
    def test_export_permissions_are_private_on_posix(self):
        target = self.root / "private.zip"
        export_bundle(self.run, target)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_csv_formula_prevention_handles_all_leading_controls(self):
        for prefix in [chr(number) for number in range(32)] + ["\x7f", "\ufeff", "\u200b", " \t\x01", "\u202e"]:
            for formula in ("=1+1", "+1+1", "-1+1", "@SUM(1)"):
                with self.subTest(prefix=repr(prefix), formula=formula):
                    self.assertTrue(csv_cell(prefix + formula).startswith("'"))

    def test_csv_framework_columns_do_not_depend_on_dictionary_order(self):
        run = copy.deepcopy(self.run)
        frameworks = run["checks"][0]["frameworks"]
        run["checks"][0]["frameworks"] = dict(reversed(list(frameworks.items())))
        row = list(csv.reader(io.StringIO(controls_csv(run).decode("utf-8-sig"))))[1]
        self.assertEqual(row[4:6], [frameworks["SOC 2"], frameworks["ISO 27001:2022"]])

    def test_html_is_escaped_and_blocks_active_remote_content(self):
        run = copy.deepcopy(self.run)
        run["organization"] = '<img src="https://attacker.invalid" onerror="alert(1)">'
        run["evidence"][0]["data"] = {"note": "</pre><script>alert(1)</script>"}
        report = report_html(run).decode()
        self.assertNotIn("<script>", report)
        self.assertNotIn('<img src="https://attacker.invalid"', report)
        self.assertIn("Content-Security-Policy", report)
        self.assertIn("default-src 'none'", report)
        self.assertIn("Collection provenance", report)


if __name__ == "__main__":
    unittest.main()
