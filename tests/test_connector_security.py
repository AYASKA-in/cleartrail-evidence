"""Adversarial API fixtures exercise scope, credentials, and false assurance.

These tests deliberately never use live credentials or external account APIs.
"""

import io
import json
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlparse

from cleartrail import connectors as c
import test_connectors as fixtures

github_api = fixtures.github_api
github_repo = fixtures.github_repo


class TransportSecurityTests(unittest.TestCase):
    def response(self, opener, body=b'{"ok":true}'):
        response = opener.return_value.open.return_value.__enter__.return_value
        response.read.return_value = body
        response.headers = {}
        return response

    def test_authorization_never_sent_to_other_origin_or_plaintext(self):
        for url in ("http://api.github.com/x", "https://api.github.com.evil.invalid/x",
                    "https://api.github.com:443/x", "https://user@api.github.com/x",
                    "https://api.github.com/x#fragment", "https://admin.googleapis.com.evil.invalid/x",
                    "https://[invalid", "https://api.github.com/x\nHeader: injected"):
            with self.subTest(url=url), patch.object(c, "build_opener") as opener:
                with self.assertRaises(c.CollectionError):
                    c._http_json(url, "credential", c._Budget())
                opener.assert_not_called()

    def test_invalid_header_token_never_reaches_network(self):
        with patch.object(c, "build_opener") as opener:
            with self.assertRaises(c.CollectionError):
                c._http_json("https://api.github.com/x", "secret\r\nX: injected", c._Budget())
            opener.assert_not_called()

    def test_redirect_handler_refuses_cross_origin_and_same_origin(self):
        handler = c._NoRedirect()
        for url in ("https://evil.invalid", "https://api.github.com/other"):
            self.assertIsNone(handler.redirect_request(None, None, 302, "redirect", {}, url))

    def test_ambiguous_duplicate_keys_and_nonfinite_values_are_rejected(self):
        for body in (b'{"enabled":false,"enabled":true}', b'{"value":NaN}', b'{"value":Infinity}', b'{"value":1e999}'):
            with self.subTest(body=body), patch.object(c, "build_opener") as opener:
                self.response(opener, body)
                with self.assertRaises(c.CollectionError):
                    c._http_json("https://api.github.com/x", "credential", c._Budget())

    def test_transient_get_is_retried_without_changing_origin(self):
        with patch.object(c, "build_opener") as opener, patch.object(c.time, "sleep") as sleep:
            context = opener.return_value.open.return_value
            self.response(opener)
            opener.return_value.open.side_effect = [
                HTTPError("https://api.github.com/x", 503, "secret", {}, io.BytesIO(b"secret")), context]
            result, _ = c._http_json("https://api.github.com/x", "credential", c._Budget())
            self.assertEqual(result, {"ok": True})
            self.assertEqual(opener.return_value.open.call_count, 2)
            sleep.assert_called_once_with(0.25)
            self.assertEqual({call.args[0].full_url for call in opener.return_value.open.call_args_list},
                             {"https://api.github.com/x"})

    def test_long_or_invalid_retry_after_does_not_block_collection(self):
        for retry_after in ("600", "Tomorrow", "-1", "0.1"):
            with self.subTest(retry_after=retry_after), patch.object(c, "build_opener") as opener, patch.object(c.time, "sleep") as sleep:
                opener.return_value.open.side_effect = HTTPError(
                    "https://api.github.com/x", 429, "secret", {"Retry-After": retry_after}, io.BytesIO(b"secret"))
                with self.assertRaises(c.CollectionError):
                    c._http_json("https://api.github.com/x", "credential", c._Budget())
                self.assertEqual(opener.return_value.open.call_count, 1)
                sleep.assert_not_called()

    def test_retries_and_total_request_budget_are_bounded(self):
        with patch.object(c, "build_opener") as opener, patch.object(c.time, "sleep"):
            opener.return_value.open.side_effect = HTTPError(
                "https://api.github.com/x", 503, "secret", {}, io.BytesIO(b"secret"))
            with self.assertRaises(c.CollectionError):
                c._http_json("https://api.github.com/x", "credential", c._Budget())
            self.assertEqual(opener.return_value.open.call_count, c.HTTP_ATTEMPTS)
        budget = c._Budget()
        budget.requests = c.MAX_HTTP_REQUESTS
        with patch.object(c, "build_opener") as opener:
            with self.assertRaises(c.CollectionError):
                c._http_json("https://api.github.com/x", "credential", budget)
            opener.assert_not_called()

    def test_response_arriving_after_deadline_cannot_become_evidence(self):
        budget = c._Budget()
        def late_read(_size):
            budget.deadline = 0
            return b'{"enabled":true}'
        with patch.object(c, "build_opener") as opener:
            self.response(opener).read.side_effect = late_read
            with self.assertRaises(c.CollectionError):
                c._http_json("https://api.github.com/x", "credential", budget)

    def test_secret_redaction_covers_dictionary_keys_and_nested_values(self):
        with patch.dict("os.environ", {"GITHUB_TOKEN": "canary-secret"}, clear=True):
            redacted = c._redact({"prefix-canary-secret": ["canary-secret", {"canary-secret": True}]})
        self.assertNotIn("canary-secret", json.dumps(redacted))

    def test_unexpected_provider_error_is_generic_and_covers_all_controls(self):
        with patch.object(c, "_github", side_effect=RuntimeError("raw-secret")):
            result = c.collect("github", {"org": "acme"})
        self.assertTrue(all(row["status"] == "unknown" for row in result))
        self.assertEqual({row["control_id"] for row in result}, set(c.CONTROL_IDS["github"]))
        self.assertNotIn("raw-secret", json.dumps(result))

    def test_all_rows_have_absolute_utc_observation_timestamp(self):
        before = datetime.now(timezone.utc)
        result = c.collect("github", {})
        after = datetime.now(timezone.utc)
        for row in result:
            observed = datetime.fromisoformat(row["observed_at"])
            self.assertEqual(observed.utcoffset().total_seconds(), 0)
            self.assertLessEqual(before, observed)
            self.assertLessEqual(observed, after)


class GitHubScopeSecurityTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict("os.environ", {"GITHUB_TOKEN": "canary-secret"}, clear=True)
        env.start()
        self.addCleanup(env.stop)

    def collect_with_inventory(self, inventory, config=None):
        normal = github_api()
        def request(url, *args):
            if urlparse(url).path == "/orgs/acme/repos":
                return inventory, {}
            return normal(url, *args)
        with patch.object(c, "_http_json", side_effect=request):
            return c.collect("github", config or {"org": "acme"})

    def test_repository_missing_owner_or_mismatched_full_name_is_gap(self):
        for item in ({"name": "app", "default_branch": "main"},
                     dict(github_repo(), owner={"login": "other"}),
                     dict(github_repo(), full_name="other/app"), github_repo("../app"), github_repo("..")):
            with self.subTest(item=item):
                rows = self.collect_with_inventory([item])
                self.assertEqual([row["status"] for row in rows[1:]], ["unknown"] * 3)

    def test_case_variant_duplicate_is_an_incomplete_inventory(self):
        rows = self.collect_with_inventory([github_repo(), github_repo("App")])
        self.assertEqual(sum(row["data"].get("complete") is False for row in rows), 3)

    def test_mfa_cannot_pass_for_wrong_organization(self):
        with patch.object(c, "_http_json", side_effect=github_api(
                org_info={"login": "wrong-org", "two_factor_requirement_enabled": True})):
            rows = c.collect("github", {"org": "acme"})
        self.assertEqual(rows[0]["status"], "unknown")

    def test_expected_repositories_missing_from_token_visibility_are_unknown(self):
        rows = self.collect_with_inventory([github_repo()], {"org": "acme", "expected_repositories": ["app", "private-app"]})
        gaps = [row for row in rows if row["resource"] == "acme/private-app"]
        self.assertEqual(len(gaps), 3)
        self.assertTrue(all(row["status"] == "unknown" for row in gaps))
        self.assertTrue(all(row["data"]["expected_repository_visible"] is False for row in gaps))

    def test_expected_repository_configuration_is_strict(self):
        for expected in ("app", ["../app"], ["app", "APP"], [None], ["."]):
            with self.subTest(expected=expected), patch.object(c, "_http_json") as request:
                rows = c.collect("github", {"org": "acme", "expected_repositories": expected})
                self.assertTrue(all(row["status"] == "unknown" for row in rows))
                request.assert_not_called()

    def test_full_page_without_link_still_checks_for_truncation(self):
        normal = github_api()
        pages = []
        def request(url, *args):
            parsed = urlparse(url)
            if parsed.path == "/orgs/acme/repos":
                page = parse_qs(parsed.query)["page"][0]
                pages.append(page)
                return ([github_repo("repo" + str(index)) for index in range(100)] if page == "1" else []), {}
            return normal(url, *args)
        with patch.object(c, "_http_json", side_effect=request):
            rows = c.collect("github", {"org": "acme"})
        self.assertEqual(pages, ["1", "2"])
        self.assertEqual(len(rows), 301)

    def test_branch_protection_is_not_bound_to_a_mismatched_branch(self):
        normal = github_api()
        def request(url, *args):
            if urlparse(url).path.endswith("/branches/main"):
                return {"name": "other", "protected": True}, {}
            return normal(url, *args)
        with patch.object(c, "_http_json", side_effect=request):
            rows = c.collect("github", {"org": "acme"})
        self.assertEqual([row["status"] for row in rows[1:]], ["unknown"] * 3)

    def test_malformed_ci_and_coerced_boolean_review_count_never_pass(self):
        bad_checks = ({"contexts": [None]}, {"contexts": [""]}, {"checks": [{}]},
                      {"checks": [{"context": "ci", "app_id": True}]}, {"contexts": ["ci"], "checks": "invalid"})
        for checks in bad_checks:
            with self.subTest(checks=checks):
                rows = c._github_protection("scope", {"required_status_checks": checks}, "source")
                self.assertEqual(rows[1]["status"], "unknown")
        for count in (True, "1", 7, -1, 1.0):
            with self.subTest(count=count):
                rows = c._github_protection("scope", {"required_pull_request_reviews": {"required_approving_review_count": count}}, "source")
                self.assertEqual(rows[0]["status"], "unknown")

    def test_concrete_api_sources_and_visibility_limits_travel_with_evidence(self):
        rows = self.collect_with_inventory([github_repo()])
        self.assertIn("https://api.github.com/orgs/acme", rows[0]["source"])
        self.assertIn("https://api.github.com/repos/acme/app/branches/main/protection", rows[1]["source"])
        self.assertTrue(all(row["data"]["organization_wide_visibility_verified"] is False for row in rows))


class WorkspaceScopeSecurityTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict("os.environ", {"GOOGLE_ACCESS_TOKEN": "canary-secret"}, clear=True)
        env.start()
        self.addCleanup(env.stop)

    def test_customer_scoped_hashes_prevent_cross_customer_identity_mixing(self):
        resources = []
        for customer in ("C123", "C456"):
            user = fixtures.GoogleTests.user(customerId=customer)
            with patch.object(c, "_http_json", return_value=({"users": [user]}, {})):
                result = c.collect("google", {})
            resources.append(result[0]["resource"])
            self.assertEqual(result[0]["data"]["customer_id"], customer)
        self.assertNotEqual(*resources)

    def test_missing_customer_or_wrong_customer_cannot_produce_pass(self):
        for configured, returned in (("C456", "C123"), ("my_customer", None)):
            user = fixtures.GoogleTests.user(customerId=returned)
            with self.subTest(configured=configured), patch.object(c, "_http_json", return_value=({"users": [user]}, {})):
                result = c.collect("google", {"customer": configured})
            self.assertTrue(all(row["status"] == "unknown" for row in result))

    def test_unreturned_or_invalid_archived_flag_is_not_assumed_active(self):
        for archived in (None, "false", 0):
            with self.subTest(archived=archived), patch.object(c, "_http_json", return_value=({"users": [fixtures.GoogleTests.user(archived=archived)]}, {})):
                result = c.collect("google", {})
            self.assertTrue(all(row["status"] == "unknown" for row in result))

    def test_mixed_customer_inventory_remains_a_coverage_gap(self):
        with patch.object(c, "_http_json", return_value=({"users": [fixtures.GoogleTests.user(), fixtures.GoogleTests.user("id2", customerId="C456")]}, {})):
            result = c.collect("google", {})
        self.assertEqual(result[-1]["status"], "unknown")
        self.assertFalse(result[-1]["data"]["inventory_complete"])

    def test_falsy_pagination_token_is_invalid_instead_of_inventing_complete(self):
        for token in (False, 0, "", []):
            with self.subTest(token=token), patch.object(c, "_http_json", return_value=({"users": [fixtures.GoogleTests.user()], "nextPageToken": token}, {})):
                result = c.collect("google", {})
            self.assertEqual(result[-1]["status"], "unknown")
            self.assertFalse(result[-1]["data"]["inventory_complete"])

    def test_user_observation_time_is_preserved_from_each_page(self):
        responses = [({"users": [fixtures.GoogleTests.user()], "nextPageToken": "next"}, {}),
                     ({"users": [fixtures.GoogleTests.user("id2")]}, {})]
        stamps = iter("2026-01-01T00:00:%02d+00:00" % index for index in range(30))
        with patch.object(c, "_http_json", side_effect=responses), patch.object(c, "_now", side_effect=lambda: next(stamps)):
            result = c.collect("google", {})
        self.assertEqual(result[0]["observed_at"], result[1]["observed_at"])
        self.assertEqual(result[2]["observed_at"], result[3]["observed_at"])
        self.assertLess(result[0]["observed_at"], result[2]["observed_at"])


class AwsScopeSecurityTests(unittest.TestCase):
    setUp = fixtures.AwsTests.setUp

    def test_caller_identity_is_recorded_on_every_aws_resource(self):
        result = c.collect("aws", {"expected_account_id": "123456789012"})
        self.assertTrue(all(row["resource"].startswith("account:123456789012/") for row in result))
        self.assertTrue(all(row["data"]["account_id"] == "123456789012" for row in result))
        self.assertTrue(all(row["data"]["expected_account_id_verified"] is True for row in result))
        self.clients["s3"].get_public_access_block.assert_called_once_with(Bucket="private-bucket", ExpectedBucketOwner="123456789012")

    def test_wrong_account_or_missing_identity_stops_before_control_reads(self):
        for identity in ({"Account": "999999999999"}, {}, {"Account": 123456789012}):
            with self.subTest(identity=identity):
                self.clients["sts"].get_caller_identity.return_value = identity
                result = c.collect("aws", {"expected_account_id": "123456789012"})
                self.assertEqual(len(result), 4)
                self.assertTrue(all(row["status"] == "unknown" for row in result))
                self.clients["iam"].get_account_summary.assert_not_called()
                self.clients["s3"].list_buckets.assert_not_called()

    def test_invalid_account_pin_does_not_initialize_sdk(self):
        for account in (123456789012, "12345", "12345678901x", ""):
            with self.subTest(account=account), patch.object(c, "_aws_session") as session:
                result = c.collect("aws", {"expected_account_id": account})
                session.assert_not_called()
                self.assertTrue(all(row["status"] == "unknown" for row in result))

    def test_root_mfa_and_ebs_flags_do_not_coerce_types(self):
        for value in (True, "1", 1.0, 2):
            self.clients["iam"].get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": value}}
            self.clients["ec2"].get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": "true"}
            result = {row["control_id"]: row for row in c.collect("aws", {})}
            self.assertEqual(result["AWS-ROOT-MFA"]["status"], "unknown")
            self.assertEqual(result["AWS-EBS-ENCRYPTION"]["status"], "unknown")

    def test_unreturned_home_region_does_not_invent_logging_evidence(self):
        self.clients["cloudtrail"].describe_trails.return_value = {"trailList": [{"Name": "audit"}]}
        result = c.collect("aws", {})
        trail = next(row for row in result if row["control_id"] == "AWS-CLOUDTRAIL")
        self.assertEqual(trail["status"], "unknown")
        self.clients["cloudtrail"].get_trail_status.assert_not_called()

    def test_bucket_pagination_falsy_values_remain_unknown(self):
        for token in (False, 0, "", []):
            self.clients["s3"].list_buckets.return_value = {"Buckets": [{"Name": "private-bucket"}], "ContinuationToken": token}
            result = c.collect("aws", {})
            gaps = [row for row in result if row["control_id"] == "AWS-S3-PUBLIC" and row["status"] == "unknown"]
            self.assertEqual(len(gaps), 1)

    def test_aws_sdk_ignores_configured_endpoint_overrides(self):
        self.client_patch.stop()
        config_module = MagicMock()
        session = MagicMock()
        with patch.object(c.importlib, "import_module", return_value=config_module):
            c._aws_client(session, "sts", "us-east-1")
        self.assertIs(config_module.Config.call_args.kwargs["ignore_configured_endpoint_urls"], True)


if __name__ == "__main__":
    unittest.main()
