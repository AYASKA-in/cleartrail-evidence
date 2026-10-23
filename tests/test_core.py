import hashlib
import io
import json
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPCookieProcessor
from http.cookiejar import CookieJar

from cleartrail.core import Store, canonical, collect_run
from cleartrail.reports import bundle_bytes, controls_csv, export_bundle, report_html, verify_bundle
from cleartrail.server import create_server
from cleartrail.__main__ import load_config


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "evidence.sqlite3")


class CoreTests(StoreTestCase):
    def test_no_sources_never_produces_a_pass(self):
        run = collect_run(self.store, {})
        self.assertEqual(run["summary"]["passed"], 0)
        self.assertEqual(run["summary"]["unknown"], 11)
        self.assertEqual(run["summary"]["manual"], 3)

    def test_demo_is_explicit_and_does_not_call_collectors(self):
        with patch("cleartrail.connectors.collect") as collect:
            run = collect_run(self.store, {}, True)
        collect.assert_not_called()
        self.assertTrue(all(e["demo"] for e in run["evidence"]))
        self.assertEqual(run["summary"]["total"], 14)
        self.assertEqual(run["summary"]["failed"], 3)
        self.assertEqual(self.store.latest(), run)

    def test_partial_collection_cannot_pass(self):
        rows = [dict(control_id="GH-MFA", provider="github", resource="org", status=s, summary=s, data={}, source="mock") for s in ("pass", "unknown")]
        with patch("cleartrail.connectors.collect", return_value=rows):
            run = collect_run(self.store, {"providers": {"github": {"org": "example"}}})
        check = next(c for c in run["checks"] if c["id"] == "GH-MFA")
        self.assertEqual(check["status"], "unknown")
        self.assertTrue(check["has_unknown"])

    def test_failure_and_coverage_gap_both_remain_visible(self):
        rows = [dict(control_id="GH-MFA", provider="github", resource="org", status=s, summary=s, data={}, source="mock") for s in ("fail", "unknown")]
        with patch("cleartrail.connectors.collect", return_value=rows):
            run = collect_run(self.store, {"providers": {"github": {}}})
        check = next(c for c in run["checks"] if c["id"] == "GH-MFA")
        self.assertEqual(check["status"], "fail")
        self.assertTrue(check["has_unknown"])

    def test_upstream_exception_never_reaches_evidence(self):
        with patch("cleartrail.connectors.collect", side_effect=RuntimeError("super-secret-token")):
            run = collect_run(self.store, {"providers": {"github": {"org": "example"}}})
        self.assertNotIn("super-secret-token", json.dumps(run))
        self.assertEqual(run["summary"]["passed"], 0)

    def test_attestations_are_snapshot_bound_and_never_automatic_pass(self):
        old = collect_run(self.store, {})
        self.store.attest("MAN-POLICY", "Alex", "Reviewed policy on 2026-10-23; document SEC-01.")
        self.assertEqual(self.store.latest(), old)
        run = collect_run(self.store, {})
        record = next(e for e in run["evidence"] if e["control_id"] == "MAN-POLICY")
        self.assertEqual(record["status"], "manual")
        self.assertFalse(record["data"]["independently_verified"])
        self.assertEqual(len(self.store.history()), 2)

    def test_bad_attestations_rejected(self):
        for cid, owner, note in [("GH-MFA", "Owner", "Note"), ("MAN-POLICY", "", "Note"), ("MAN-POLICY", "Owner", "x"*4001)]:
            with self.assertRaises(ValueError):
                self.store.attest(cid, owner, note)

    def test_demo_and_live_modes_cannot_share_a_database(self):
        collect_run(self.store, {}, True)
        with self.assertRaisesRegex(ValueError, "different mode"):
            collect_run(self.store, {}, False)
        with self.assertRaisesRegex(ValueError, "different mode"):
            create_server(self.store, {}, False, port=0)

    def test_configuration_rejects_invalid_types(self):
        path = Path(self.temp.name) / "config.json"
        for config in ({"organization": None}, {"organization": " "}, {"providers": {"aws": {"enabled": "false"}}}, {"providers": {"github": {"org": []}}}):
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)


class ReportTests(StoreTestCase):
    def make_run(self):
        return collect_run(self.store, {"organization": "<script>alert('bad')</script>"}, True)

    def test_bundle_round_trip_and_escape(self):
        run = self.make_run()
        target = Path(self.temp.name) / "report.zip"
        export_bundle(run, target)
        verified = verify_bundle(target)
        self.assertTrue(verified["valid"])
        self.assertTrue(verified["demo"])
        report = report_html(run).decode()
        self.assertNotIn("<script>", report)
        self.assertIn("SYNTHETIC DEMONSTRATION", report)

    def test_bundle_refuses_overwrite(self):
        target = Path(self.temp.name) / "report.zip"
        export_bundle(self.make_run(), target)
        with self.assertRaises(FileExistsError):
            export_bundle(self.make_run(), target)

    def rewrite(self, updates):
        source = zipfile.ZipFile(io.BytesIO(bundle_bytes(self.make_run())))
        files = {name: source.read(name) for name in source.namelist()}
        source.close()
        updates(files)
        target = Path(self.temp.name) / "modified.zip"
        with zipfile.ZipFile(target, "w") as archive:
            for name, content in files.items():
                archive.writestr(name, content)
        return target

    def test_modified_file_fails_verification(self):
        target = self.rewrite(lambda files: files.update({"controls.csv": b"modified"}))
        with self.assertRaisesRegex(ValueError, "integrity failed"):
            verify_bundle(target)

    def test_unexpected_member_fails_verification(self):
        target = self.rewrite(lambda files: files.update({"../unexpected.txt": b"no extraction"}))
        with self.assertRaises(ValueError):
            verify_bundle(target)

    def test_non_object_manifest_is_a_clean_validation_error(self):
        target = self.rewrite(lambda files: files.update({"manifest.json": b"[]"}))
        with self.assertRaisesRegex(ValueError, "manifest object"):
            verify_bundle(target)

    def test_evidence_change_with_updated_file_manifest_fails_record_hash(self):
        def update(files):
            run = json.loads(files["run.json"])
            run["evidence"][0]["data"] = {"tampered": True}
            files["run.json"] = json.dumps(run).encode()
            manifest = json.loads(files["manifest.json"])
            manifest["files"]["run.json"] = hashlib.sha256(files["run.json"]).hexdigest()
            files["manifest.json"] = canonical(manifest)
        with self.assertRaisesRegex(ValueError, "record integrity"):
            verify_bundle(self.rewrite(update))

    def test_csv_formula_values_are_neutralized(self):
        run = self.make_run()
        run["checks"][0]["title"] = "=HYPERLINK(\"https://example.com\")"
        self.assertIn("'=HYPERLINK", controls_csv(run).decode("utf-8-sig"))


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "test.sqlite3")
        collect_run(self.store, {}, True)
        config = {"providers": {"github": {"org": "example", "token": "secret-do-not-expose"}}}
        self.server = create_server(self.store, config, demo=True, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:" + str(self.server.server_port)
        self.opener = build_opener(HTTPCookieProcessor(CookieJar()))
        login = Request(self.base + "/api/session", data=json.dumps({"token": self.server.bootstrap_token}).encode(), headers={"Origin": self.base, "Content-Type": "application/json"}, method="POST")
        with self.opener.open(login) as response:
            response.read()
        with self.opener.open(self.base + "/api/state") as response:
            self.state = json.load(response)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def test_config_secrets_not_returned(self):
        self.assertNotIn("secret-do-not-expose", json.dumps(self.state))
        self.assertNotIn("token", self.state["config"]["providers"]["github"])

    def test_mutations_need_origin_and_session_token(self):
        for headers in ({}, {"Origin": self.base}, {"Origin": "https://evil.example", "X-ClearTrail-Token": self.state["csrf"]}):
            req = Request(self.base+"/api/scan", data=b"{}", headers=headers, method="POST")
            with self.assertRaises(HTTPError) as error:
                self.opener.open(req)
            self.assertEqual(error.exception.code, 403)

    def test_rebinding_host_rejected(self):
        req = Request(self.base+"/api/state", headers={"Host": "evil.example"})
        with self.assertRaises(HTTPError) as error:
            self.opener.open(req)
        self.assertEqual(error.exception.code, 403)

    def test_attest_endpoint_records_note(self):
        req = Request(self.base+"/api/attest", data=json.dumps({"control_id":"MAN-ACCESS", "owner":"Alex", "note":"Reviewed SEC-02."}).encode(), headers={"Origin":self.base,"X-ClearTrail-Token":self.state["csrf"], "Content-Type":"application/json"}, method="POST")
        with self.opener.open(req) as response:
            self.assertTrue(json.load(response)["saved"])
        self.assertIn("MAN-ACCESS", self.store.attestations())

    def test_bundle_and_ui_assets_served_with_security_headers(self):
        for route in ("/", "/app.js", "/style.css", "/api/export"):
            with self.opener.open(self.base+route) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
                content = response.read()
                self.assertTrue(content)
        with self.opener.open(self.base+"/api/export") as response:
            archive = zipfile.ZipFile(io.BytesIO(response.read()))
            self.assertIn("manifest.json", archive.namelist())


if __name__ == "__main__":
    unittest.main()
