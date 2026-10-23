"""Offline connector tests. No fixture uses credentials or contacts a real account."""

import io
import json
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse

from cleartrail import connectors as c


def github_repo(name="app", branch="main"):
    return {"name": name, "default_branch": branch, "owner": {"login": "acme"}, "full_name": "acme/" + name}


def github_api(protected=True, protection=None, org_info=None):
    if protection is None:
        protection = {"required_pull_request_reviews": {"required_approving_review_count": 1},
                      "required_status_checks": {"contexts": ["ci"]},
                      "enforce_admins": {"enabled": True}}

    def request(url, token, budget, github=False):
        budget.check()
        path = urlparse(url).path
        if path == "/orgs/acme":
            return ({"login": "acme", "two_factor_requirement_enabled": True} if org_info is None else org_info), {}
        if path == "/orgs/acme/repos":
            return [github_repo()], {}
        if path.endswith("/protection"):
            if isinstance(protection, Exception):
                raise protection
            return protection, {}
        if path.endswith("/branches/main"):
            return {"name": "main", "protected": protected}, {}
        raise AssertionError("Unexpected URL")
    return request


class GitHubTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict("os.environ", {"GITHUB_TOKEN": "test-canary-secret"}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_missing_credential_and_config_token_is_ignored(self):
        with patch.dict("os.environ", {}, clear=True), patch.object(c, "_http_json") as request:
            result = c.collect("github", {"org": "acme", "token": "config-secret"})
        self.assertEqual({r["control_id"] for r in result}, set(c.CONTROL_IDS["github"]))
        self.assertTrue(all(r["status"] == "unknown" for r in result))
        self.assertNotIn("config-secret", json.dumps(result))
        request.assert_not_called()

    def test_all_supported_classic_fields_pass(self):
        with patch.object(c, "_http_json", side_effect=github_api()):
            result = c.collect("github", {"org": "acme"})
        self.assertEqual(len(result), 4)
        self.assertTrue(all(r["status"] == "pass" for r in result))
        self.assertFalse(result[1]["data"]["rulesets_evaluated"])

    def test_missing_organization_mfa_is_unknown(self):
        with patch.object(c, "_http_json", side_effect=github_api(org_info={})):
            result = c.collect("github", {"org": "acme"})
        self.assertEqual(result[0]["status"], "unknown")

    def test_unprotected_branch_requires_both_explicit_false_and_404(self):
        for protected, expected in ((False, "fail"), (True, "unknown"), (None, "unknown")):
            with self.subTest(protected=protected):
                with patch.object(c, "_http_json", side_effect=github_api(
                        protected, c.CollectionError("Not found", 404))):
                    result = c.collect("github", {"org": "acme"})
                self.assertEqual([r["status"] for r in result[1:]], [expected] * 3)

    def test_permission_error_does_not_become_a_control_failure(self):
        with patch.object(c, "_http_json", side_effect=github_api(
                False, c.CollectionError("API permission denied", 403))):
            result = c.collect("github", {"org": "acme"})
        self.assertTrue(all(r["status"] == "unknown" for r in result[1:]))

    def test_zero_review_count_empty_checks_and_admin_bypass_fail(self):
        protection = {"required_pull_request_reviews": {"required_approving_review_count": 0},
                      "required_status_checks": {"checks": [], "contexts": []},
                      "enforce_admins": {"enabled": False}}
        with patch.object(c, "_http_json", side_effect=github_api(protection=protection)):
            result = c.collect("github", {"org": "acme"})
        self.assertEqual([r["status"] for r in result[1:]], ["fail"] * 3)

    def test_missing_fields_are_not_assumed_disabled(self):
        with patch.object(c, "_http_json", side_effect=github_api(protection={})):
            result = c.collect("github", {"org": "acme"})
        self.assertEqual([r["status"] for r in result[1:]], ["unknown"] * 3)

    def test_repository_pagination_does_not_follow_untrusted_link(self):
        normal = github_api()
        visited = []

        def request(url, *args):
            visited.append(url)
            parsed = urlparse(url)
            if parsed.path == "/orgs/acme/repos":
                if parse_qs(parsed.query)["page"] == ["1"]:
                    return [github_repo()], {
                        "Link": '<https://untrusted.invalid/steal>; rel="next"'}
                return [github_repo("api")], {}
            return normal(url, *args)

        with patch.object(c, "_http_json", side_effect=request):
            result = c.collect("github", {"org": "acme"})
        self.assertEqual(len(result), 7)
        self.assertTrue(all(url.startswith("https://api.github.com/") for url in visited))

    def test_partial_inventory_retains_observed_evidence_and_adds_unknown(self):
        normal = github_api()

        def request(url, *args):
            if "/repos?" in url and "page=1" in url:
                return [github_repo()], {"Link": '<unused>; rel="next"'}
            if "/repos?" in url:
                raise c.CollectionError("API rate limit reached", 429)
            return normal(url, *args)

        with patch.object(c, "_http_json", side_effect=request):
            result = c.collect("github", {"org": "acme"})
        self.assertEqual(len(result), 7)
        self.assertEqual(sum(r["status"] == "unknown" for r in result), 3)
        self.assertTrue(all(r["data"]["complete"] is False for r in result if r["status"] == "unknown"))

    def test_secret_echo_in_allowlisted_identity_is_redacted(self):
        normal = github_api()

        def request(url, *args):
            if "/repos?" in url:
                return [github_repo("test-canary-secret")], {}
            return normal(url, *args)

        with patch.object(c, "_http_json", side_effect=request):
            result = c.collect("github", {"org": "acme"})
        self.assertNotIn("test-canary-secret", json.dumps(result))


class HttpTests(unittest.TestCase):
    def test_http_error_body_and_message_are_never_exported(self):
        error = HTTPError("https://api.github.com/example", 403, "raw-secret", {}, io.BytesIO(b"raw-secret"))
        with patch.object(c, "build_opener") as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaises(c.CollectionError) as caught:
                c._http_json("https://api.github.com/example", "raw-secret", c._Budget(), True)
        self.assertEqual(caught.exception.status, 403)
        self.assertNotIn("raw-secret", str(caught.exception))

    def test_network_error_is_generic(self):
        with patch.object(c, "build_opener") as opener:
            opener.return_value.open.side_effect = URLError("raw-secret")
            with self.assertRaises(c.CollectionError) as caught:
                c._http_json("https://api.github.com/example", "raw-secret", c._Budget())
        self.assertNotIn("raw-secret", str(caught.exception))

    def test_request_is_get_and_has_timeout(self):
        with patch.object(c, "build_opener") as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.read.return_value = b'{"safe": true}'
            response.headers = {}
            data, headers = c._http_json("https://api.github.com/example", "credential", c._Budget())
        self.assertEqual(data, {"safe": True})
        args, kwargs = opener.return_value.open.call_args
        self.assertEqual(args[0].get_method(), "GET")
        self.assertEqual(kwargs["timeout"], c.HTTP_TIMEOUT)

    def test_response_size_bound(self):
        with patch.object(c, "MAX_RESPONSE_BYTES", 2), patch.object(c, "build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b"123"
            with self.assertRaises(c.CollectionError):
                c._http_json("https://api.github.com/example", "credential", c._Budget())

    def test_expired_budget_stops_before_network(self):
        budget = c._Budget()
        budget.deadline = 0
        with patch.object(c, "build_opener") as opener:
            with self.assertRaises(c.CollectionError):
                c._http_json("https://api.github.com/example", "credential", budget)
            opener.assert_not_called()


class GoogleTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict("os.environ", {"GOOGLE_ACCESS_TOKEN": "google-canary-secret"}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    @staticmethod
    def user(user_id="id-1", admin=True, enrolled=True, enforced=True, **extra):
        return dict({"id": user_id, "customerId": "C123", "suspended": False, "archived": False, "isAdmin": admin,
                     "isEnrolledIn2Sv": enrolled, "isEnforcedIn2Sv": enforced}, **extra)

    def test_paginated_active_users_admin_policy_and_pseudonyms(self):
        visited = []

        def request(url, *args):
            visited.append(parse_qs(urlparse(url).query))
            if "pageToken" not in visited[-1]:
                return {"users": [self.user(primaryEmail="private@example.com")], "nextPageToken": "page-2"}, {}
            return {"users": [self.user("id-2", enforced=False), self.user("id-3", suspended=True)]}, {}

        with patch.object(c, "_http_json", side_effect=request):
            result = c.collect("google", {"customer": "my_customer"})
        self.assertEqual(len(result), 5)
        self.assertEqual(result[-1]["status"], "pass")
        self.assertEqual(result[-1]["data"]["active_super_admin_count_observed"], 2)
        self.assertEqual(visited[1]["pageToken"], ["page-2"])
        self.assertEqual(sum(r["status"] == "fail" for r in result), 1)
        self.assertNotIn("private@example.com", json.dumps(result))
        self.assertNotIn('"id-1"', json.dumps(result))
        self.assertTrue(all(r["resource"].startswith("user:") for r in result[:-1]))

    def test_enrolled_is_distinct_from_enforced(self):
        with patch.object(c, "_http_json", return_value=({"users": [self.user(enforced=False)]}, {})):
            result = c.collect("google", {})
        self.assertEqual([r["status"] for r in result], ["pass", "fail", "fail"])
        self.assertIn("organizational policy", result[-1]["data"]["policy"])

    def test_incomplete_pagination_cannot_pass_admin_policy(self):
        responses = [({"users": [self.user(), self.user("id-2")], "nextPageToken": "next"}, {}),
                     c.CollectionError("API permission denied", 403)]
        with patch.object(c, "_http_json", side_effect=responses):
            result = c.collect("google", {})
        self.assertEqual(result[-1]["status"], "unknown")
        self.assertFalse(result[-1]["data"]["inventory_complete"])
        self.assertEqual(sum(r["resource"] == "Workspace user inventory" for r in result), 2)

    def test_missing_user_fields_are_unknown(self):
        with patch.object(c, "_http_json", return_value=({"users": [{"id": "id-1", "suspended": False}]}, {})):
            result = c.collect("google", {})
        self.assertTrue(all(r["status"] == "unknown" for r in result))

    def test_repeated_token_stops_and_marks_incomplete(self):
        with patch.object(c, "_http_json", side_effect=[
                ({"users": [self.user()], "nextPageToken": "repeat"}, {}),
                ({"users": [self.user("id-2")], "nextPageToken": "repeat"}, {})]) as request:
            result = c.collect("google", {})
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result[-1]["status"], "unknown")

    def test_empty_directory_is_not_a_pass(self):
        with patch.object(c, "_http_json", return_value=({}, {})):
            result = c.collect("google", {})
        self.assertEqual(len(result), 3)
        self.assertTrue(all(r["status"] == "unknown" for r in result))


class FakeAwsError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code, "Message": "raw-canary-secret"}}
        super().__init__("raw-canary-secret in exception")


class AwsTests(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock()
        self.session.region_name = "us-east-1"
        self.clients = {name: MagicMock() for name in ("sts", "iam", "cloudtrail", "ec2", "s3")}
        self.clients["sts"].get_caller_identity.return_value = {"Account": "123456789012"}
        self.clients["iam"].get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        self.clients["cloudtrail"].describe_trails.return_value = {
            "trailList": [{"Name": "audit", "HomeRegion": "us-east-1", "IsMultiRegionTrail": True}]}
        self.clients["cloudtrail"].get_trail_status.return_value = {"IsLogging": True}
        self.clients["ec2"].get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": True}
        self.clients["s3"].list_buckets.return_value = {"Buckets": [{"Name": "private-bucket"}]}
        self.clients["s3"].get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": dict.fromkeys(
                ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"], True)}
        self.session_patch = patch.object(c, "_aws_session", return_value=self.session)
        self.client_patch = patch.object(c, "_aws_client", side_effect=lambda session, name, region=None: self.clients[name])
        self.session_patch.start()
        self.client_patch.start()
        self.addCleanup(self.session_patch.stop)
        self.addCleanup(self.client_patch.stop)

    def test_all_fields_pass_and_regional_scope_is_recorded(self):
        result = c.collect("aws", {"region": "us-east-1"})
        self.assertEqual(len(result), 4)
        self.assertTrue(all(r["status"] == "pass" for r in result))
        trail = next(r for r in result if r["control_id"] == "AWS-CLOUDTRAIL")
        self.assertTrue(trail["data"]["IsMultiRegionTrail"])
        self.assertFalse(trail["data"]["event_selectors_evaluated"])
        self.clients["cloudtrail"].describe_trails.assert_called_once_with(includeShadowTrails=True)

    def test_trail_status_uses_home_region(self):
        self.clients["cloudtrail"].describe_trails.return_value = {
            "trailList": [{"Name": "audit", "HomeRegion": "eu-west-1", "IsMultiRegionTrail": True}]}
        c.collect("aws", {"region": "us-east-1"})
        self.assertTrue(any(call.args == (self.session, "cloudtrail", "eu-west-1")
                            for call in c._aws_client.call_args_list))

    def test_missing_and_false_fields_are_distinct(self):
        self.clients["iam"].get_account_summary.return_value = {"SummaryMap": {}}
        self.clients["ec2"].get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": False}
        result = {r["control_id"]: r for r in c.collect("aws", {"region": "us-east-1"})}
        self.assertEqual(result["AWS-ROOT-MFA"]["status"], "unknown")
        self.assertEqual(result["AWS-EBS-ENCRYPTION"]["status"], "fail")

    def test_sdk_errors_do_not_export_credentials_or_api_messages(self):
        self.clients["iam"].get_account_summary.side_effect = FakeAwsError("AccessDenied")
        self.clients["cloudtrail"].get_trail_status.side_effect = FakeAwsError("ExpiredToken")
        result = c.collect("aws", {"region": "us-east-1"})
        self.assertNotIn("raw-canary-secret", json.dumps(result))
        self.assertEqual(sum(r["status"] == "unknown" for r in result), 2)

    def test_bucket_missing_guardrail_is_fail_but_permission_error_unknown(self):
        self.clients["s3"].list_buckets.return_value = {"Buckets": [{"Name": "one"}, {"Name": "two"}]}
        self.clients["s3"].get_public_access_block.side_effect = [
            FakeAwsError("NoSuchPublicAccessBlockConfiguration"), FakeAwsError("AccessDenied")]
        result = [r for r in c.collect("aws", {}) if r["control_id"] == "AWS-S3-PUBLIC"]
        self.assertEqual([r["status"] for r in result], ["fail", "unknown"])
        self.assertIn("does not establish public exposure", result[0]["summary"])

    def test_bucket_inventory_pagination_and_partial_failure(self):
        self.clients["s3"].list_buckets.side_effect = [
            {"Buckets": [{"Name": "one"}], "ContinuationToken": "page-2"},
            FakeAwsError("AccessDenied")]
        result = [r for r in c.collect("aws", {}) if r["control_id"] == "AWS-S3-PUBLIC"]
        self.assertEqual([r["status"] for r in result], ["pass", "unknown"])
        self.assertFalse(result[-1]["data"]["complete"])
        self.clients["s3"].list_buckets.assert_called_with(MaxBuckets=1000, ContinuationToken="page-2")

    def test_repeated_bucket_token_is_bounded(self):
        self.clients["s3"].list_buckets.side_effect = [
            {"Buckets": [{"Name": "one"}], "ContinuationToken": "repeat"},
            {"Buckets": [{"Name": "two"}], "ContinuationToken": "repeat"}]
        result = c.collect("aws", {})
        self.assertEqual(self.clients["s3"].list_buckets.call_count, 2)
        self.assertEqual(result[-1]["status"], "unknown")

    def test_missing_region_does_not_invent_a_default(self):
        self.session.region_name = None
        result = c.collect("aws", {})
        self.assertEqual([r["status"] for r in result if r["control_id"] in ("AWS-CLOUDTRAIL", "AWS-EBS-ENCRYPTION")],
                         ["unknown", "unknown"])
        self.clients["ec2"].get_ebs_encryption_by_default.assert_not_called()

    def test_missing_optional_sdk_returns_unknown_for_all_controls(self):
        with patch.object(c, "_aws_session", side_effect=ImportError):
            result = c.collect("aws", {})
        self.assertEqual(len(result), 4)
        self.assertTrue(all(r["status"] == "unknown" for r in result))


if __name__ == "__main__":
    unittest.main()
