"""Read-only configuration collectors. Credentials are resolved from the environment.

Only allowlisted configuration fields enter evidence. API bodies, exception messages,
access tokens and Google user addresses are never copied into the report. Findings
describe a point-in-time setting, not a certification or a complete security review.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import math
import os
import re
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


CONTROL_IDS = {
    "github": ("GH-MFA", "GH-REVIEW", "GH-CI", "GH-ADMIN"),
    "google": ("GOOGLE-2SV", "GOOGLE-2SV-ENFORCED", "GOOGLE-ADMINS"),
    "aws": ("AWS-ROOT-MFA", "AWS-CLOUDTRAIL", "AWS-S3-PUBLIC", "AWS-EBS-ENCRYPTION"),
}
MAX_PAGES = 50
MAX_RESOURCES = 1000
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
COLLECTION_SECONDS = 180
HTTP_TIMEOUT = 15
HTTP_ATTEMPTS = 3
MAX_HTTP_REQUESTS = 2200
_SECRET_ENV = (
    "GITHUB_TOKEN", "GH_TOKEN", "GOOGLE_ACCESS_TOKEN", "GOOGLE_WORKSPACE_ACCESS_TOKEN",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
)


class CollectionError(Exception):
    """Safe, deliberately generic collection failure; never includes an API body."""

    def __init__(self, reason: str, status: int | None = None):
        self.reason = reason
        self.status = status
        super().__init__(reason)


class _Budget:
    def __init__(self):
        self.deadline = time.monotonic() + COLLECTION_SECONDS
        self.requests = 0

    def check(self):
        if time.monotonic() >= self.deadline:
            raise CollectionError("Collection time limit reached; remaining scope was not checked.")

    def request(self):
        self.check()
        if self.requests >= MAX_HTTP_REQUESTS:
            raise CollectionError("API request limit reached; remaining scope was not checked.")
        self.requests += 1


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _text(value, limit=1024):
    return isinstance(value, str) and 0 < len(value) <= limit and not any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Ambiguous JSON object")
        result[key] = value
    return result


def _invalid_json_constant(value):
    raise ValueError("Invalid JSON numeric constant")


def _json_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Invalid JSON numeric range")
    return number


class _NoRedirect(HTTPRedirectHandler):
    # Prevent a redirect from forwarding an Authorization header to a different host.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_json(url: str, token: str, budget: _Budget, github: bool = False):
    budget.check()
    # A single origin allowlist applies before any Authorization header is built.
    # Never trust pagination URLs, redirects, or a caller-supplied endpoint.
    try:
        parsed = urlsplit(url)
    except (TypeError, ValueError):
        raise CollectionError("API endpoint is invalid.") from None
    if (parsed.scheme != "https" or parsed.netloc not in ("api.github.com", "admin.googleapis.com")
            or parsed.username is not None or parsed.password is not None or parsed.fragment
            or not _text(token, 16384) or not _text(url, 32768)):
        raise CollectionError("API endpoint or environment credential is invalid.")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json",
               "User-Agent": "ClearTrail-evidence-collector"}
    if github:
        headers.update({"Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"})
    for attempt in range(HTTP_ATTEMPTS):
        budget.request()
        try:
            request = Request(url, headers=headers, method="GET")
            timeout = min(HTTP_TIMEOUT, max(0.001, budget.deadline - time.monotonic()))
            with build_opener(_NoRedirect()).open(request, timeout=timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                budget.check()
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise CollectionError("API response exceeded the size limit; scope is incomplete.")
                return json.loads(raw, object_pairs_hook=_json_object,
                                  parse_constant=_invalid_json_constant, parse_float=_json_float), dict(response.headers.items())
        except HTTPError as exc:
            status = exc.code
            retry_after = (exc.headers or {}).get("Retry-After")
            exc.close()
            delay = float(2 ** attempt) / 4
            # Long server-directed backoffs are surfaced to the user, never ignored.
            if retry_after is not None:
                delay = float(retry_after) if re.fullmatch(r"[0-9]{1,3}", str(retry_after)) else 999
            if (status in (429, 500, 502, 503, 504) and attempt + 1 < HTTP_ATTEMPTS
                    and delay <= 2 and time.monotonic() + delay < budget.deadline):
                time.sleep(delay)
                continue
            messages = {
                401: "API authentication failed; check the environment credential.",
                403: "API permission denied or rate limited; verify read permissions and retry later.",
                404: "API resource or configuration not found; visibility may be restricted.",
                429: "API rate limit reached; retry later.",
            }
            raise CollectionError(messages.get(status, "API request failed; verify API access."), status) from None
        except (URLError, OSError, ValueError, TypeError, RecursionError):
            raise CollectionError("API request or JSON decoding failed; verify connectivity and credentials.") from None


def _row(control: str, provider: str, resource: str, status: str,
         summary: str, data: dict | None = None, source: str = "Collector prerequisite check", remediation: str = "",
         observed_at: str | None = None):
    result = {"control_id": control, "provider": provider, "resource": resource,
              "status": status, "summary": summary, "data": data or {}, "source": source,
              "observed_at": observed_at or _now()}
    if remediation:
        result["remediation"] = remediation
    return result


def _unknown(controls, provider, resource, summary, source="Collector prerequisite check", data=None):
    return [_row(c, provider, resource, "unknown", summary, data, source) for c in controls]


def _redact(value):
    if isinstance(value, dict):
        return {_redact(key) if isinstance(key, str) else key: _redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        for name in _SECRET_ENV:
            secret = os.environ.get(name)
            if secret:
                value = value.replace(secret, "[REDACTED]")
        return value
    return value


def _boolean(value):
    return value if type(value) is bool else None


def collect(provider: str, config: dict) -> list[dict]:
    """Collect one provider using environment credentials and caller supplied scope.

    GitHub: ``org`` + GITHUB_TOKEN (or GH_TOKEN). Google: ``customer`` +
    GOOGLE_ACCESS_TOKEN (or GOOGLE_WORKSPACE_ACCESS_TOKEN). AWS: optional
    ``profile`` and ``region`` using boto3's standard credential chain. Tokens in
    config are intentionally ignored so a settings file need not contain secrets.
    """
    if not isinstance(provider, str):
        raise ValueError("Unknown provider; choose github, google, or aws.")
    provider = provider.lower().strip()
    if provider not in CONTROL_IDS:
        raise ValueError("Unknown provider; choose github, google, or aws.")
    if not isinstance(config, dict):
        return _unknown(CONTROL_IDS[provider], provider, "Configured scope",
                        "Provider configuration must be an object.")
    budget = _Budget()
    try:
        result = {"github": _github, "google": _google, "aws": _aws}[provider](config, budget)
    except Exception:
        # Third-party SDKs, malformed responses, and configuration exceptions may
        # contain credentials. Preserve an explicit gap without exporting them.
        result = _unknown(CONTROL_IDS[provider], provider, "Configured scope",
                          "Collection could not complete; verify configuration, response format, and API access.")
    return _redact(result)


def _github(config, budget):
    org = config.get("org")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not isinstance(org, str) or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", org):
        return _unknown(CONTROL_IDS["github"], "github", "GitHub organization",
                        "Set a valid GitHub organization name in configuration.")
    expected = config.get("expected_repositories")
    valid_name = lambda name: isinstance(name, str) and bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name)) and name not in (".", "..")
    if expected is not None and (not isinstance(expected, list) or len(expected) > MAX_RESOURCES
            or any(not valid_name(name) for name in expected)
            or len({name.casefold() for name in expected}) != len(expected)):
        return _unknown(CONTROL_IDS["github"], "github", org,
                        "Expected repositories must be a bounded list of unique repository names.")
    if not token:
        return _unknown(CONTROL_IDS["github"], "github", org,
                        "Set GITHUB_TOKEN in the environment with organization and repository read access.")
    base = "https://api.github.com"
    org_path = "/orgs/" + quote(org, safe="")
    org_source = "GitHub REST GET " + base + org_path
    rows = []
    try:
        info, _ = _http_json(base + org_path, token, budget, True)
        if (not isinstance(info, dict) or not isinstance(info.get("login"), str)
                or info["login"].casefold() != org.casefold()):
            raise CollectionError("Unexpected organization response; MFA setting was not checked.")
        enabled = _boolean(info.get("two_factor_requirement_enabled"))
        rows.append(_row("GH-MFA", "github", org,
                         "unknown" if enabled is None else "pass" if enabled else "fail",
                         "Organization MFA requirement is enabled." if enabled else
                         "Organization MFA requirement is disabled." if enabled is False else
                         "MFA requirement was not returned; organization-owner visibility may be needed.",
                         {"two_factor_requirement_enabled": enabled}, org_source,
                         "Require two-factor authentication for organization access." if enabled is False else ""))
    except CollectionError as exc:
        rows += _unknown(("GH-MFA",), "github", org, exc.reason, org_source)

    branch_controls = ("GH-REVIEW", "GH-CI", "GH-ADMIN")
    repos = []
    seen = set()
    inventory_error = ""
    list_source = "GitHub REST GET " + base + org_path + "/repos (all token-visible repositories)"
    for page in range(1, MAX_PAGES + 1):
        try:
            payload, headers = _http_json(base + org_path + "/repos?" + urlencode(
                {"type": "all", "per_page": 100, "page": page}), token, budget, True)
            if not isinstance(payload, list) or len(payload) > 100 or any(not isinstance(r, dict) for r in payload):
                raise CollectionError("Unexpected repository inventory response; scope is incomplete.")
            for repo in payload:
                name = repo.get("name")
                owner = repo.get("owner")
                if (not valid_name(name) or name.casefold() in seen
                        or not isinstance(owner, dict) or not isinstance(owner.get("login"), str)
                        or owner["login"].casefold() != org.casefold()
                        or not isinstance(repo.get("full_name"), str)
                        or repo["full_name"].casefold() != (org + "/" + name).casefold()):
                    raise CollectionError("Invalid or repeated repository inventory; scope is incomplete.")
                if len(repos) >= MAX_RESOURCES:
                    raise CollectionError("Repository resource limit reached; scope is incomplete.")
                seen.add(name.casefold())
                repos.append(repo)
            link = next((v for k, v in headers.items() if k.lower() == "link"), "")
            if not isinstance(link, str) or len(link) > 32768:
                raise CollectionError("Invalid repository pagination header; scope is incomplete.")
            # Link is only a pagination signal: never send credentials to a supplied URL.
            if not re.search(r';\s*rel=[\"\']?next\b', link) and len(payload) < 100:
                break
            if page == MAX_PAGES:
                inventory_error = "Repository page limit reached; scope is incomplete."
        except CollectionError as exc:
            inventory_error = exc.reason
            break
    if inventory_error:
        rows += _unknown(branch_controls, "github", org + "/repository inventory",
                         inventory_error, list_source, {"repositories_returned": len(repos), "complete": False})
    elif not repos:
        rows += _unknown(branch_controls, "github", org + "/repository inventory",
                         "No repositories were visible; confirm the token includes the intended private repositories.", list_source)
    if expected:
        for missing in sorted(name for name in expected if name.casefold() not in seen):
            rows += _unknown(branch_controls, "github", org + "/" + missing,
                             "Expected repository was not visible in the collected inventory; verify token access and configured scope.",
                             list_source, {"expected_repository_visible": False, "complete": False})
    for repo in repos:
        resource = org + "/" + repo["name"]
        branch = repo.get("default_branch")
        source = "GitHub REST GET /repos/{owner}/{repo}/branches/{default_branch}/protection"
        if not _text(branch, 1024):
            rows += _unknown(branch_controls, "github", resource,
                             "Repository has no returned default branch; protection was not checked.", source)
            continue
        path = "/repos/" + quote(org, safe="") + "/" + quote(repo["name"], safe="") + "/branches/" + quote(branch, safe="")
        source = "GitHub REST GET " + base + path + "/protection"
        resource += ":" + branch
        try:
            branch_info, _ = _http_json(base + path, token, budget, True)
            if not isinstance(branch_info, dict) or branch_info.get("name") != branch:
                raise CollectionError("Unexpected branch response; branch protection was not checked.")
            try:
                protection, _ = _http_json(base + path + "/protection", token, budget, True)
            except CollectionError as exc:
                if exc.status == 404 and branch_info.get("protected") is False:
                    rows += [_row(control, "github", resource, "fail",
                                  "Default branch reports unprotected and classic protection returned 404.",
                                  {"protected": False, "classic_protection_http_status": 404}, source,
                                  "Configure and review default-branch protection for the required policy.") for control in branch_controls]
                elif exc.status == 404:
                    rows += _unknown(branch_controls, "github", resource,
                                     "Classic protection is unavailable; rulesets or restricted visibility require manual review.",
                                     source, {"protected": _boolean(branch_info.get("protected")), "rulesets_evaluated": False})
                else:
                    rows += _unknown(branch_controls, "github", resource, exc.reason, source)
                continue
            if not isinstance(protection, dict):
                raise CollectionError("Unexpected protection response; policy fields were not checked.")
            rows += _github_protection(resource, protection, source)
        except CollectionError as exc:
            rows += _unknown(branch_controls, "github", resource, exc.reason, source)
    for row in rows:
        row["data"].setdefault("repository_visibility_scope", "token-visible repositories only")
        row["data"].setdefault("organization_wide_visibility_verified", False)
    return rows


def _github_protection(resource, protection, source):
    reviews = protection.get("required_pull_request_reviews")
    count = reviews.get("required_approving_review_count") if isinstance(reviews, dict) else None
    review_state = (count >= 1) if type(count) is int and 0 <= count <= 6 else None
    if "required_pull_request_reviews" in protection and reviews is None:
        review_state = False
    checks = protection.get("required_status_checks")
    check_count = None
    if isinstance(checks, dict):
        values = []
        malformed = False
        for field in ("checks", "contexts"):
            if field not in checks:
                continue
            items = checks[field]
            if not isinstance(items, list) or len(items) > MAX_RESOURCES:
                malformed = True
                break
            if field == "contexts":
                valid = all(_text(item) for item in items)
            else:
                valid = all(isinstance(item, dict) and _text(item.get("context"))
                            and (item.get("app_id") is None or type(item["app_id"]) is int and item["app_id"] >= -1)
                            for item in items)
            if not valid:
                malformed = True
                break
            values.append(len(items))
        if values and not malformed:
            check_count = max(values)
    ci_state = check_count > 0 if check_count is not None else None
    if "required_status_checks" in protection and checks is None:
        ci_state = False
    admins = protection.get("enforce_admins")
    admin_state = _boolean(admins.get("enabled")) if isinstance(admins, dict) else None
    items = [
        ("GH-REVIEW", review_state, {"required_approving_review_count": count if type(count) is int else None},
         "At least one approving review is required by classic protection.",
         "Classic protection does not require an approving review.",
         "Require at least one approving review before merging."),
        ("GH-CI", ci_state, {"required_status_check_count": check_count},
         "Classic protection requires status checks before merging.",
         "Classic protection does not require any status checks.",
         "Select required CI status checks for the default branch."),
        ("GH-ADMIN", admin_state, {"enforce_admins": admin_state},
         "Classic branch protection applies to administrators.",
         "Administrators can bypass classic branch protection.",
         "Apply branch protection to administrators and review other bypass permissions."),
    ]
    return [_row(control, "github", resource, "unknown" if state is None else "pass" if state else "fail",
                 good if state else bad if state is False else "Expected classic protection field was not returned; review manually.",
                 dict(data, rulesets_evaluated=False), source, fix if state is False else "")
            for control, state, data, good, bad, fix in items]


def _google(config, budget):
    customer = config.get("customer", "my_customer")
    token = os.environ.get("GOOGLE_ACCESS_TOKEN") or os.environ.get("GOOGLE_WORKSPACE_ACCESS_TOKEN")
    controls = CONTROL_IDS["google"]
    source = "Google Admin SDK Directory GET /admin/directory/v1/users (customer, admin_view)"
    if not isinstance(customer, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", customer):
        return _unknown(controls, "google", "Workspace customer", "Set a valid Workspace customer ID.", source)
    if not token:
        return _unknown(controls, "google", "Workspace customer",
                        "Set GOOGLE_ACCESS_TOKEN with admin.directory.user.readonly scope and authorized admin access.", source)
    users = []
    seen_ids, seen_tokens = set(), set()
    page_token = None
    error = ""
    observed_customer = None if customer == "my_customer" else customer
    last_observed = _now()
    for page in range(MAX_PAGES):
        params = {"customer": customer, "maxResults": 500, "projection": "full", "viewType": "admin_view",
                  "fields": "users(id,customerId,suspended,archived,isAdmin,isEnrolledIn2Sv,isEnforcedIn2Sv),nextPageToken"}
        if page_token:
            params["pageToken"] = page_token
        try:
            data, _ = _http_json("https://admin.googleapis.com/admin/directory/v1/users?" + urlencode(params), token, budget)
            last_observed = _now()
            if not isinstance(data, dict) or not isinstance(data.get("users", []), list):
                raise CollectionError("Unexpected Workspace user inventory; scope is incomplete.")
            if len(data.get("users", [])) > 500:
                raise CollectionError("Workspace page exceeded the requested size; scope is incomplete.")
            for user in data.get("users", []):
                if not isinstance(user, dict) or not _text(user.get("id"), 256) or user["id"] in seen_ids:
                    raise CollectionError("Invalid or repeated Workspace user inventory; scope is incomplete.")
                user_customer = user.get("customerId")
                if not isinstance(user_customer, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", user_customer):
                    raise CollectionError("Workspace customer identity was not returned; scope is incomplete.")
                if observed_customer is None:
                    observed_customer = user_customer
                elif observed_customer != user_customer:
                    raise CollectionError("Workspace customer identity did not match the collected scope; scope is incomplete.")
                if len(users) >= MAX_RESOURCES:
                    raise CollectionError("Workspace user limit reached; scope is incomplete.")
                users.append((user, last_observed))
                seen_ids.add(user["id"])
            page_token = data.get("nextPageToken")
            if page_token is None:
                break
            if not _text(page_token, 8192) or page_token in seen_tokens:
                raise CollectionError("Workspace pagination repeated or was invalid; scope is incomplete.")
            seen_tokens.add(page_token)
            if page == MAX_PAGES - 1:
                error = "Workspace page limit reached; scope is incomplete."
        except CollectionError as exc:
            error = exc.reason
            break
    rows, admins, active_count = [], 0, 0
    uncertain_admins = False
    for user, observed_at in users:
        if user.get("suspended") is True or user.get("archived") is True:
            continue
        active = _boolean(user.get("suspended")) is False and _boolean(user.get("archived")) is False
        if not active:
            uncertain_admins = True
        else:
            active_count += 1
            if _boolean(user.get("isAdmin")) is None:
                uncertain_admins = True
            elif user["isAdmin"]:
                admins += 1
        identity = "google\x00" + user["customerId"] + "\x00" + user["id"]
        resource = "user:" + hashlib.sha256(identity.encode()).hexdigest()[:32]
        for control, field, label in (("GOOGLE-2SV", "isEnrolledIn2Sv", "enrolled"),
                                      ("GOOGLE-2SV-ENFORCED", "isEnforcedIn2Sv", "enforced")):
            state = _boolean(user.get(field)) if active else None
            summary = ("Active user has two-step verification " + label + "." if state else
                       "Active user does not have two-step verification " + label + "." if state is False else
                       "User activity or two-step verification field was not returned; review manually.")
            rows.append(_row(control, "google", resource,
                             "unknown" if state is None else "pass" if state else "fail", summary,
                             {field: state, "customer_id": user["customerId"],
                              "identity": "SHA-256 pseudonym scoped to provider, Workspace customer, and Directory user ID"}, source,
                             "Review and apply the organization's two-step verification policy." if state is False else "",
                             observed_at=observed_at))
    if error:
        rows += _unknown(controls[:2], "google", "Workspace user inventory", error, source,
                         {"users_returned": len(users), "complete": False})
    elif not rows:
        rows += _unknown(controls[:2], "google", "Workspace active users",
                         "No active users were returned; confirm the intended customer and permissions.", source)
    state = None if error or uncertain_admins or not active_count else admins >= 2
    rows.append(_row("GOOGLE-ADMINS", "google", "Workspace customer",
                     "unknown" if state is None else "pass" if state else "fail",
                     "Active super-admin count is incomplete; review directory coverage and permissions." if state is None else
                     "At least two active super admins meet this operational resilience policy." if state else
                     "Fewer than two active super admins meet this operational resilience policy.",
                     {"customer_id": observed_customer, "configured_customer": customer,
                      "active_super_admin_count_observed": admins, "active_users_observed": active_count,
                      "inventory_complete": not bool(error), "policy": "At least two active super admins; organizational policy, not a universal compliance requirement"},
                     source, "Review emergency access and super-admin ownership against your policy." if state is False else "",
                     observed_at=last_observed))
    return rows


def _aws_session(config):
    boto3 = importlib.import_module("boto3")
    return boto3.Session(profile_name=config.get("profile") or None,
                         region_name=config.get("region") or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or None)


def _aws_client(session, service, region=None):
    sdk_config = importlib.import_module("botocore.config").Config(
        connect_timeout=5, read_timeout=10, retries={"total_max_attempts": 2, "mode": "standard"},
        ignore_configured_endpoint_urls=True)
    kwargs = {"config": sdk_config}
    if region:
        kwargs["region_name"] = region
    return session.client(service, **kwargs)


def _aws_reason(exc):
    if isinstance(exc, CollectionError):
        return exc.reason
    # Exception text may contain credentials, request URLs, or customer metadata.
    response = getattr(exc, "response", {})
    error = response.get("Error", {}) if isinstance(response, dict) else {}
    code = error.get("Code") if isinstance(error, dict) else None
    if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
        return "AWS permission denied; verify the required read-only IAM actions."
    if code in ("ExpiredToken", "InvalidClientTokenId", "UnrecognizedClientException", "SignatureDoesNotMatch"):
        return "AWS authentication failed; refresh the configured credential source."
    return "AWS request failed; verify credentials, region, SDK version, permissions, and connectivity."


def _aws(config, budget):
    expected_account = config.get("expected_account_id")
    if expected_account is not None and (not isinstance(expected_account, str)
            or not re.fullmatch(r"[0-9]{12}", expected_account)):
        return _unknown(CONTROL_IDS["aws"], "aws", "AWS account",
                        "Expected AWS account ID must contain exactly twelve digits.")
    if any(key in config and (not _text(config[key], 128)) for key in ("profile", "region")):
        return _unknown(CONTROL_IDS["aws"], "aws", "AWS account",
                        "AWS profile and region must be non-empty strings when configured.")
    try:
        session = _aws_session(config)
    except ImportError:
        return _unknown(CONTROL_IDS["aws"], "aws", "AWS account",
                        "Install the optional boto3 dependency to collect AWS evidence.")
    except Exception:
        return _unknown(CONTROL_IDS["aws"], "aws", "AWS account",
                        "AWS credential session could not be initialized; check profile and environment settings.")
    region = config.get("region") or getattr(session, "region_name", None)
    try:
        budget.check()
        identity = _aws_client(session, "sts", region).get_caller_identity()
        account_id = identity.get("Account") if isinstance(identity, dict) else None
        if not isinstance(account_id, str) or not re.fullmatch(r"[0-9]{12}", account_id):
            raise CollectionError("AWS caller account identity was not returned; account scope is unverified.")
        if expected_account is not None and expected_account != account_id:
            raise CollectionError("AWS caller account differs from expected_account_id; no controls were collected.")
    except Exception as exc:
        return _unknown(CONTROL_IDS["aws"], "aws", "AWS account", _aws_reason(exc), "AWS STS GetCallerIdentity")
    rows = []
    source = "AWS IAM GetAccountSummary"
    try:
        budget.check()
        result = _aws_client(session, "iam").get_account_summary()
        value = result.get("SummaryMap", {}).get("AccountMFAEnabled")
        state = value == 1 if type(value) is int and value in (0, 1) else None
        rows.append(_row("AWS-ROOT-MFA", "aws", "AWS account",
                         "unknown" if state is None else "pass" if state else "fail",
                         "Account summary reports root-account MFA enabled." if state else
                         "Account summary reports root-account MFA disabled; review root credential management." if state is False else
                         "AccountMFAEnabled was not returned; root MFA could not be checked.",
                         {"AccountMFAEnabled": value if type(value) is int and value in (0, 1) else None}, source,
                         "Review root credentials and configure MFA or centralized root access as appropriate." if state is False else ""))
    except Exception as exc:
        rows += _unknown(("AWS-ROOT-MFA",), "aws", "AWS account", _aws_reason(exc), source)

    if not _aws_region(region):
        rows += _unknown(("AWS-CLOUDTRAIL", "AWS-EBS-ENCRYPTION"), "aws", "AWS region",
                         "Configure an AWS region; regional checks were not run.")
    else:
        rows += _aws_cloudtrail(session, region, budget)
        source = "AWS EC2 GetEbsEncryptionByDefault (configured region only)"
        try:
            budget.check()
            result = _aws_client(session, "ec2", region).get_ebs_encryption_by_default()
            value = _boolean(result.get("EbsEncryptionByDefault"))
            rows.append(_row("AWS-EBS-ENCRYPTION", "aws", region,
                             "unknown" if value is None else "pass" if value else "fail",
                             "EBS encryption by default is enabled for new volumes in this region." if value else
                             "EBS encryption by default is disabled in this region." if value is False else
                             "EBS default encryption setting was not returned.",
                             {"EbsEncryptionByDefault": value, "region": region, "existing_volumes_evaluated": False}, source,
                             "Enable EBS encryption by default in this region and separately review existing volumes." if value is False else ""))
        except Exception as exc:
            rows += _unknown(("AWS-EBS-ENCRYPTION",), "aws", region, _aws_reason(exc), source)
    rows += _aws_s3(session, budget, account_id)
    for row in rows:
        row["data"]["account_id"] = account_id
        row["data"]["expected_account_id_verified"] = expected_account is not None
        row["resource"] = "account:" + account_id + "/" + row["resource"]
    return rows


def _aws_region(region):
    return isinstance(region, str) and len(region) <= 64 and bool(re.fullmatch(r"[a-z]{2,8}(?:-[a-z0-9]+){2,5}", region))


def _aws_cloudtrail(session, region, budget):
    source = "AWS CloudTrail DescribeTrails(includeShadowTrails=True), GetTrailStatus in trail home region"
    rows = []
    try:
        budget.check()
        client = _aws_client(session, "cloudtrail", region)
        trails = client.describe_trails(includeShadowTrails=True).get("trailList")
        if not isinstance(trails, list):
            raise CollectionError("Trail inventory was not returned; regional scope is incomplete.")
        if not trails:
            return [_row("AWS-CLOUDTRAIL", "aws", region, "fail", "No trails were returned for the configured region.",
                         {"region": region, "trail_count": 0}, source, "Review and configure logging coverage for this region.")]
        seen = set()
        for trail in trails[:MAX_RESOURCES]:
            if not isinstance(trail, dict):
                raise CollectionError("Invalid trail inventory; regional scope is incomplete.")
            name = trail.get("TrailARN") or trail.get("Name")
            if not _text(name, 2048) or name in seen:
                raise CollectionError("Invalid or repeated trail identity; regional scope is incomplete.")
            seen.add(name)
            home_region = trail.get("HomeRegion")
            if not _aws_region(home_region):
                rows += _unknown(("AWS-CLOUDTRAIL",), "aws", name,
                                 "Trail home region was not returned or was invalid; logging could not be checked.", source,
                                 {"region": region, "event_selectors_evaluated": False, "delivery_health_evaluated": False})
                continue
            data = {"region": region, "home_region": home_region,
                    "IsMultiRegionTrail": _boolean(trail.get("IsMultiRegionTrail")),
                    "event_selectors_evaluated": False, "delivery_health_evaluated": False}
            try:
                budget.check()
                home_client = client if home_region == region else _aws_client(session, "cloudtrail", home_region)
                status = home_client.get_trail_status(Name=name)
                state = _boolean(status.get("IsLogging"))
                data["IsLogging"] = state
                rows.append(_row("AWS-CLOUDTRAIL", "aws", name,
                                 "unknown" if state is None else "pass" if state else "fail",
                                 "Trail reports logging enabled; event coverage and delivery health require separate review." if state else
                                 "Trail reports logging disabled." if state is False else "Trail logging status was not returned.",
                                 data, source, "Review and enable required CloudTrail logging." if state is False else ""))
            except Exception as exc:
                rows += _unknown(("AWS-CLOUDTRAIL",), "aws", name, _aws_reason(exc), source, data)
        if len(trails) > MAX_RESOURCES:
            raise CollectionError("Trail resource limit reached; regional scope is incomplete.")
    except Exception as exc:
        rows += _unknown(("AWS-CLOUDTRAIL",), "aws", region + "/trail inventory", _aws_reason(exc), source)
    return rows


def _aws_s3(session, budget, account_id=None):
    source = "AWS S3 ListBuckets, GetPublicAccessBlock (bucket-level settings only; general-purpose buckets)"
    rows, seen, tokens = [], set(), set()
    token = None
    try:
        client = _aws_client(session, "s3")
        for page in range(MAX_PAGES):
            budget.check()
            kwargs = {"MaxBuckets": 1000}
            if token:
                kwargs["ContinuationToken"] = token
            payload = client.list_buckets(**kwargs)
            buckets = payload.get("Buckets")
            if not isinstance(buckets, list):
                raise CollectionError("Bucket inventory was not returned; scope is incomplete.")
            for bucket in buckets:
                if (not isinstance(bucket, dict) or not _text(bucket.get("Name"), 63)
                        or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", bucket["Name"])
                        or bucket["Name"] in seen):
                    raise CollectionError("Invalid or repeated bucket inventory; scope is incomplete.")
                if len(seen) >= MAX_RESOURCES:
                    raise CollectionError("Bucket resource limit reached; scope is incomplete.")
                name = bucket["Name"]
                seen.add(name)
                try:
                    budget.check()
                    params = {"Bucket": name}
                    if account_id:
                        params["ExpectedBucketOwner"] = account_id
                    flags = client.get_public_access_block(**params).get("PublicAccessBlockConfiguration")
                    if not isinstance(flags, dict):
                        raise CollectionError("Bucket public-access block fields were not returned.")
                    data = {key: _boolean(flags.get(key)) for key in
                            ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
                    state = None if None in data.values() else all(data.values())
                    rows.append(_row("AWS-S3-PUBLIC", "aws", name,
                                     "unknown" if state is None else "pass" if state else "fail",
                                     "All four bucket-level public-access blocks are enabled." if state else
                                     "One or more bucket-level public-access blocks are disabled; this does not establish public exposure." if state is False else
                                     "One or more public-access block fields were not returned.",
                                     data, source, "Review bucket and account-level public-access policy; enable required bucket guardrails." if state is False else ""))
                except Exception as exc:
                    error = getattr(exc, "response", {})
                    code = error.get("Error", {}).get("Code") if isinstance(error, dict) and isinstance(error.get("Error", {}), dict) else None
                    if code == "NoSuchPublicAccessBlockConfiguration":
                        rows.append(_row("AWS-S3-PUBLIC", "aws", name, "fail",
                                         "No bucket-level public-access block is configured; this does not establish public exposure.",
                                         {"bucket_level_configuration_present": False}, source,
                                         "Review account-level protections and configure the required bucket guardrails."))
                    else:
                        rows += _unknown(("AWS-S3-PUBLIC",), "aws", name, _aws_reason(exc), source)
            token = payload.get("ContinuationToken")
            if token is None:
                break
            if not _text(token, 8192) or token in tokens:
                raise CollectionError("Bucket pagination repeated or was invalid; scope is incomplete.")
            tokens.add(token)
            if page == MAX_PAGES - 1:
                raise CollectionError("Bucket page limit reached; scope is incomplete.")
        if not rows:
            rows += _unknown(("AWS-S3-PUBLIC",), "aws", "S3 bucket inventory",
                             "No general-purpose buckets were returned; verify the intended account and scope.", source)
    except Exception as exc:
        rows += _unknown(("AWS-S3-PUBLIC",), "aws", "S3 bucket inventory", _aws_reason(exc), source,
                         {"buckets_returned": len(seen), "complete": False})
    return rows
