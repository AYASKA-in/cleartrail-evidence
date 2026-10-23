# ClearTrail local setup

For a hosted service serving multiple customers, use [HOSTED_DEPLOYMENT.md](HOSTED_DEPLOYMENT.md). The instructions below apply to the separate local CLI and loopback dashboard.

Use Python 3.10 or newer. Core collection, dashboard, SQLite storage and ZIP exports use the Python standard library. Run commands from the project folder. An optional virtual environment keeps the AWS dependency separate:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[aws]"
```

Use that environment's Python for subsequent commands if installed. The AWS extra requires `boto3>=1.35.99,<2`, including support for the paginated S3 bucket inventory used by this collector. GitHub and Google collection require no third-party Python packages.

## Configuration and credentials

```powershell
Copy-Item -LiteralPath .\config.example.json -Destination .\config.json
```

Edit the copy. This example enables all three providers; enable only the accounts you intend to inspect:

```json
{
  "organization": "Example company",
  "providers": {
    "github": { "enabled": true, "org": "example-org" },
    "google": { "enabled": true, "customer": "my_customer" },
    "aws": { "enabled": true, "profile": "default", "region": "us-east-1" }
  }
}
```

The supplied `config.example.json` enables GitHub only. A provider absent from configuration, or set to `"enabled": false`, is skipped and its controls remain unknown. Omitting `enabled` from a configured provider enables it. Configuration holds scope, not secrets: credential fields and unknown configuration keys are rejected. The application does not load `.env` files automatically.

Set tokens only in the process environment of the terminal that launches ClearTrail. This PowerShell example prompts without echoing a token or placing it in command history:

```powershell
$env:GITHUB_TOKEN = [System.Net.NetworkCredential]::new("", (Read-Host "GitHub token" -AsSecureString)).Password
$env:GOOGLE_ACCESS_TOKEN = [System.Net.NetworkCredential]::new("", (Read-Host "Google access token" -AsSecureString)).Password
```

Set only the variable for the provider you enabled. The connector also accepts `GH_TOKEN` and `GOOGLE_WORKSPACE_ACCESS_TOKEN` as fallback aliases. AWS resolves credentials through boto3's standard chain, including a selected local profile, temporary role credentials or AWS environment variables. The example profile is `default`; remove `profile` to allow the normal default chain. Prefer temporary credentials from an existing approved role/session. ClearTrail does not create credentials, configure IAM, log in, or refresh Google tokens.

## GitHub permissions and scope

Use a fine-grained token or existing GitHub App token limited to the organization and repositories you intend to inspect. Choose repository **Administration: read** for the classic branch-protection endpoint, and **Contents: read** for the default-branch lookup. Repository metadata access supports inventory. The implementation issues only GET requests. GitHub documents the endpoint requirements in [Get branch protection](https://docs.github.com/en/rest/branches/branch-protection#get-branch-protection) and [Get a branch](https://docs.github.com/en/rest/branches/branches#get-a-branch).

Organization MFA is read from `GET /orgs/{org}`. GitHub documents that complete organization details require authenticated organization-owner visibility; the endpoint itself lists no additional fine-grained permission requirement. An insufficiently visible MFA field remains unknown. The documented classic-token route uses the broader `admin:org` scope; it is not the recommended default for this collector. See [Get an organization](https://docs.github.com/en/rest/orgs/orgs#get-an-organization).

Ensure organization approval and any required SSO authorization are satisfied for your chosen token. ClearTrail cannot know about private repositories the token cannot see, so inspect the returned inventory against your intended population. Its three branch checks use classic protection on each returned repository's default branch. It does not evaluate GitHub Rulesets, custom production branches, bypass policies beyond the returned classic admin flag, or whether actual merged pull requests were reviewed. A protected branch with unavailable classic rules is unknown and needs manual review. The live API base is `https://api.github.com`; self-hosted GitHub Enterprise Server is not configured in this version.

## Google Workspace permissions and scope

Enable the Admin SDK API for your existing Google Cloud project and obtain a short-lived OAuth bearer access token authorized for the intended Workspace administrator and customer, with:

```text
https://www.googleapis.com/auth/admin.directory.user.readonly
```

The administrator must have appropriate Directory user read access. If your organization uses domain-wide delegation, that setup and authorized admin impersonation happen outside ClearTrail. The application accepts an already minted token; there is no hosted consent flow, service-account JSON import or automatic refresh. See Google's [Directory authorization guide](https://developers.google.com/workspace/admin/directory/v1/guides/authorizing) and [users.list reference](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/list).

`customer` defaults to `my_customer`; an explicit customer ID may be used. The connector requests an administrator view with only user IDs, suspended/archived flags, super-admin status and 2-step enrollment/enforcement fields. Suspended and archived users are excluded when identified. Missing activity or security fields remain unknown. Google's [User resource](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users) defines the enrollment and enforcement flags.

Exported user resources use the first 16 hexadecimal characters of a SHA-256 hash of the Directory user ID. These are stable pseudonyms, not anonymization: a holder of the original IDs can correlate them. The two-super-admin threshold is ClearTrail's recovery policy choice, not a universal SOC 2 or ISO requirement. It does not assess administrator MFA strength, break-glass handling or privileged role assignments beyond that count.

## AWS permissions and scope

Install the AWS extra, select the intended account/profile and configure one region. The following read policy covers the implemented APIs. Replace `123456789012` with your account ID and narrow trail/bucket resources where practical. This example uses the standard `aws` partition; adjust ARNs for other partitions.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadAccountAndRegionalInventory",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountSummary",
        "cloudtrail:DescribeTrails",
        "ec2:GetEbsEncryptionByDefault",
        "s3:ListAllMyBuckets"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReadTrailLoggingStatus",
      "Effect": "Allow",
      "Action": "cloudtrail:GetTrailStatus",
      "Resource": "arn:aws:cloudtrail:*:123456789012:trail/*"
    },
    {
      "Sid": "ReadBucketPublicAccessBlocks",
      "Effect": "Allow",
      "Action": "s3:GetBucketPublicAccessBlock",
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
```

Inventory/account/default-setting actions in the first statement require wildcard resource scope; this is not a wildcard action grant. Bucket inventory covers the selected account's general-purpose buckets. Restricting the last statement to specific bucket ARNs can produce unknown results for other discovered buckets. If a returned organization trail belongs to another account, separately authorize its exact trail ARN where permitted; do not assume the example account-scoped trail statement covers it. Existing permissions boundaries, organization policies, session policies and resource policies can further restrict these reads.

The collector maps the following API responses to evidence:

| API | Evidence and boundary |
| --- | --- |
| [IAM GetAccountSummary](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html) | Reads `AccountMFAEnabled`; review centralized root-access arrangements separately. |
| [CloudTrail DescribeTrails](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DescribeTrails.html), [GetTrailStatus](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html) | Discovers trails including shadow trails for the configured region, then checks `IsLogging` in each trail's home region. This does not establish multi-region coverage, event-selector coverage or delivery health. |
| [EC2 GetEbsEncryptionByDefault](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetEbsEncryptionByDefault.html) | Checks default encryption for new volumes in the configured region only, not existing volumes or all regions. |
| [S3 ListBuckets](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html), [GetPublicAccessBlock](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html) | Lists general-purpose buckets and reads the four bucket-level public-access block flags. It does not read objects, effective account/organization policy, bucket policies or ACLs; a failed guardrail check does not prove public exposure. |

## Run and review

```powershell
python -m cleartrail serve --config config.json --port 8091
```

Open the complete private launch URL printed by the server, including `#access=...`, and start collection. Do not share that capability. Alternatively:

```powershell
python -m cleartrail collect --config config.json --output exports\review-001.zip
python -m cleartrail verify exports\review-001.zip
```

The dashboard and default CLI commands share `.cleartrail/live.sqlite3`. `--demo` uses `.cleartrail/demo.sqlite3`; demo output is clearly labeled synthetic. Use `--db` consistently when choosing another file. A dashboard refuses a database whose latest snapshot belongs to the other mode. Human notes are saved separately and enter reports only after the next collection. `export` uses the latest stored snapshot and does not refresh provider data.

An exported ZIP includes a printable HTML report, CSV control index, JSON snapshot/evidence and an unsigned SHA-256 manifest. Keep a trusted copy or separately trusted manifest hash if integrity matters. Verification detects inconsistencies relative to that manifest and cannot prove who collected the evidence, provider truth, audit-period operation or auditor acceptance. Share a reviewed copy with your auditor through your organization's approved channel.

## Collection limits and results

The current limits are fixed in the connector code:

- At most 50 inventory pages and 1,000 resources per provider inventory; incomplete scope produces unknown evidence alongside any collected findings.
- GitHub/Google HTTP calls use a 15-second request timeout and a 4 MiB response limit. Redirects are refused so authorization headers are not forwarded to another host.
- Each provider has a 180-second budget checked before further API work. An in-flight request may finish after that budget, so it is not a strict total elapsed-time deadline. Providers run sequentially.
- AWS SDK clients use a 5-second connect timeout, 10-second read timeout and at most two total attempts. The EBS setting covers one configured region. CloudTrail inventory begins in that region, with status calls to returned home regions.
- There is no automatic polling schedule or rate-limit retry queue. Refresh an expired credential or wait for an upstream rate limit, then start a new collection.

Pass means the observed setting met this specific check. Fail means a known setting missed the local policy. Unknown means missing configuration, permissions, unsupported settings, API errors, empty/limited inventory or absent fields prevent a defensible decision. A control with both known failures and unknown scope stays failed and displays an incomplete-coverage flag. Human notes never turn a self-attestation into an automated pass. Review resource scope and timestamps as well as the headline result.

## Local data handling

The local UI binds to `127.0.0.1`, exchanges a private launch capability for an expiring HttpOnly session, and checks exact hosts, origins and CSRF tokens. This is a single-user boundary. The separate hosted application supplies OIDC, tenant isolation and roles. Keep it on a trusted local machine; do not expose it through a public tunnel or reverse proxy as a shared service.

Credentials stay in the process environment or AWS credential source and are excluded from browser configuration and exported observations. Allowlisted API fields are persisted, rather than full response bodies. Evidence still contains sensitive repository/bucket/trail identifiers, security settings, stable user pseudonyms, organization details and any notes you enter. The SQLite database and ZIP files are not encrypted by this application. Use local access controls, encrypted storage and your own retention policy; avoid putting secrets in owner/note fields.

Default `.cleartrail/`, `exports/`, `.env`, `config.json` and SQLite files are ignored by Git. Custom export paths may not be ignored, so inspect Git status before sharing source. The raw REA vendor-reference capture is local research provenance and is excluded from source distribution. Software is free under MIT; upstream accounts, infrastructure, API usage and independent audits can still incur costs.


Version 0.2 records provider observation timestamps and a configuration fingerprint. Configure `expected_repositories` as a distinct list of GitHub repository names to detect expected resources hidden from the token. Set AWS `expected_account_id` to the intended 12-digit account ID; a mismatch prevents downstream collection. STS identity is always checked. Local databases are pinned to their original organization and demo/live mode, so use a new database when changing either.

For a verified local backup and snapshot integrity check:

```powershell
python -m cleartrail backup --db .cleartrail/live.sqlite3 --output backups/review.sqlite3
python -m cleartrail doctor --db .cleartrail/live.sqlite3
```

Backups refuse overwrite. Keep backup files and keys under your own access and retention controls.
