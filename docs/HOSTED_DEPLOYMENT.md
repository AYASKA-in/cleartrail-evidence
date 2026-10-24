# Hosted deployment

The hosted application is separate from the loopback-only local server.
Read [HARDENING.md](HARDENING.md) and complete its launch gates before customer
onboarding. There is no default user, password, registration endpoint or
authentication bypass. A configured OIDC provider is required in every mode.

## Components and prerequisites

- Python 3.10+ for source execution; the image pins Python 3.12.15.
- PostgreSQL with a dedicated database and **NOSUPERUSER NOBYPASSRLS** runtime
  role. Use a private network and TLS with certificate verification for remote
  database connections. SQLite is accepted only for explicit loopback tests or
  development; production configuration rejects it.
- A confidential OIDC web client with authorization code flow and S256 PKCE.
  Register exactly `https://YOUR_HOST/auth/callback`, enable required MFA at the
  IdP, and obtain the initial administrator's exact `iss` and `sub` claims.
- HTTPS ingress in front of the API, preserving the configured Host. Shared
  request/connection/rate limits, a 128 KiB default body limit and a 1 MiB limit
  specifically for `/api/documents/upload`, a 10-second client-body timeout, and
  a 64-connection upstream concurrency budget are starting limits. The app still
  enforces its tighter base64-plus-metadata upload budget and 512 KiB file limit.
- A secret manager or securely delivered environment for the database URL, OIDC
  client secret, session-state signing secret and vault key ring. Never put real
  values in a Dockerfile, image, source ZIP, issue, screenshot or commit.

## Configure and bootstrap

Install the reproducible runtime and package from a reviewed release:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-hosted.lock
.\.venv\Scripts\python.exe -m pip install --no-deps .
Copy-Item -LiteralPath .env.hosted.example -Destination .env.hosted
```

Populate the example using your secret manager. Source execution reads real
process environment variables; it does not automatically load `.env.hosted`.
Compose loads that file explicitly. `CLEARTRAIL_PUBLIC_URL` is the exact origin
with no trailing slash. The issuer must exactly match the IdP discovery document.
Generate independent random session and Fernet secrets using the example's
commands. Production requires HTTPS URLs and PostgreSQL, checks the database
role and RLS installation, and refuses to start against an uninitialized schema.

Use a migration role that owns the schema, then run the web/worker with a
separate DML-only role. Both roles must lack superuser/BYPASSRLS. After migration,
grant runtime `USAGE` on the schema and `SELECT, INSERT, UPDATE, DELETE` on the
`ct_*` tables; do not grant CREATE, schema ownership or membership in the
migration role. `ct_schema` needs SELECT only. Do not expose database credentials
or the database port to customers. Use a dedicated database/schema with a pinned
search path and no untrusted schema creators.

With the migration role configured in the environment:

```powershell
python -m cleartrail.hosted_admin migrate
```

With the runtime role configured, bootstrap the initial workspace explicitly:

```powershell
python -m cleartrail.hosted_admin create-tenant --name "Example customer" --issuer "https://identity.example.com" --subject "VERIFIED_IDP_SUBJECT"
```

Issuer/subject, rather than email or domain, grant membership. The first member
is an administrator. The administrator can add identities and set admin, operator
or auditor roles in the dashboard. Removing or downgrading membership affects
existing sessions on their next request. The final administrator cannot be
removed or downgraded. Every new customer needs a separate workspace.

## Run

For an internal staging process behind your HTTPS ingress:

```powershell
python -m uvicorn cleartrail.hosted:create_app --factory --host 127.0.0.1 --port 8080 --no-proxy-headers --no-access-log --limit-concurrency 64 --timeout-keep-alive 5
python -m cleartrail.hosted_worker
```

Run the worker in a separate process/service. The API queues work; it never runs
a cloud collection inside a request. `--once` processes at most one queued job
for supervised batch execution. Stop signals drain the current job, which is
bounded to 650 seconds plus credential exchange/commit. Allow a 700-second drain.
Unexpected termination expires the lease after 720 seconds; the next worker
marks it failed with `worker_lost`. It does not silently publish partial success
or automatically re-run a collection against changed credentials.

For the supplied container layout:

```powershell
docker compose build
# Use migration-role credentials for this one-shot command only.
docker compose --profile maintenance run --rm migrate
# Restore runtime-role credentials before starting the services.
docker compose up -d api worker scheduler
```

Compose publishes the API only on the host loopback address, uses non-root users,
a read-only root filesystem, private temporary memory, dropped capabilities and
resource budgets. Provision PostgreSQL, HTTPS ingress and secrets separately.
There is no public application API port or automatic application deployment. Hosting,
provider services, identity infrastructure and audits can have costs despite the
MIT-licensed software being free.

Disable ingress query-string logging on `/auth/callback`; authorization codes
must not enter logs. Do not enable Uvicorn access logging without a scrubber.
Trust proxy headers only after explicitly restricting trusted proxy addresses;
this application uses its configured public URL for callback/origin checks.
Never publish the local `python -m cleartrail serve` service through a tunnel.

## Connect customers

An administrator uses **Integrations** to save provider scope and encrypted
credentials. The API never returns credential plaintext. Credential revocation
removes the stored envelope; also revoke the token at its provider when needed.

- GitHub: organization-approved read token and exact organization name. Declare
  expected repository names to detect token visibility gaps. Classic protection
  is checked; ruleset-only protection still requires review. Token installation,
  automatic refresh and webhook onboarding are future work.
- Google: exact customer ID and admin-authorized Directory read access token.
  `my_customer` is rejected by hosted configuration. Tokens expire; renewal is
  currently an explicit administrator action, not a background refresh flow.
- AWS: expected 12-digit account, one EBS region, read-only customer role ARN and
  the service-generated workspace external ID shown in the form. The server rejects customer-supplied substitutes and IDs belonging to another workspace. The role's trust policy must permit only the
  deployed worker principal and require `sts:ExternalId`. The worker identity
  needs only `sts:AssumeRole` for approved roles. Do not grant it general read
  access across customer accounts. Each workspace receives an independently generated, unique external ID; copy that exact value into the customer role trust policy. Static customer
  access keys and AWS profiles are rejected. Collection verifies the STS account
  and passes expected owner for S3. See [SETUP.md](SETUP.md) for read permissions.

At most one queued/running job exists per tenant, 48 collections per rolling day,
5,000 retained snapshots and 100 members. Quotas prevent accidental runaway
usage; they are not a substitute for ingress limits or a complete retention
policy. Deletion/retention/legal-hold automation is a launch gate.

## Operations and recovery

`GET /healthz` returns liveness only. `GET /readyz` checks schema/RLS/role/database
readiness and returns 503 on failure, without exposing connection details. Both
require the configured Host but no customer session. Monitor worker liveness,
queue age, failed/expired leases, database connections/storage, provider rate
limits, ingress errors and disk/memory budgets. Central alert integration and
SLOs must be supplied by the hosting operator.

Use managed encrypted PostgreSQL backups/PITR with a separate backup role and
test restoration into a separate environment. Verify backup-role RLS behavior;
`pg_dump` as a restricted runtime role can fail rather than capture all tenants.
Back up the vault keys separately and restrict restore access. A database backup
without its matching keys cannot recover credentials. Define and test RPO/RTO.

Rotate vault keys by delivering `NEW_KEY,OLD_KEY` to all API/worker instances,
running the following for every tenant, verifying a staged collection, then
removing the old key only after reviewing the backup recovery policy:

```powershell
python -m cleartrail.hosted_admin rotate-vault --tenant TENANT_UUID
python -m cleartrail.hosted_admin audit --tenant TENANT_UUID
```

Save each audit head in an independently controlled append-only store. Later use
`audit --tenant TENANT_UUID --expected-head SHA256` to compare the current chain
to that trusted head at the same boundary. A head advances after every event;
compare a saved head only when no new events are expected, or externally retain
and verify the complete event history. An unsigned, unanchored chain cannot
detect full database rewrites or deletion of its tail.

## API boundary

All evidence/configuration/member/audit routes require an opaque session cookie.
Cookies are HttpOnly, Secure in production, host-only, SameSite=Strict and expire
after eight hours. OIDC protocol state uses a separate five-minute signed Lax
cookie. Mutation requests require exact Origin, `application/json`, the session's
`X-ClearTrail-Token`, and `X-ClearTrail-Workspace` matching its active workspace.
The UI supplies those headers. Changing workspace revalidates membership.

| Route | Roles | Purpose |
|---|---|---|
| GET `/api/state`, `/api/export`, `/api/report`, `/api/csv`, `/api/audit` | All members | Read current workspace; exports accept one `run_id` |
| POST `/api/workspace` | All members | Select an authorized workspace |
| POST `/api/scan`, `/api/attest` | Admin, operator | Queue collection / save a self-attestation |
| POST `/api/integration`, `/api/config`, `/api/credentials` | Admin | Update provider scope/secrets; integration save is atomic |
| GET/POST `/api/members` | Admin | Inspect/change exact-subject membership |
| POST `/api/logout` | Signed-in user | Revoke current opaque session |

The UI cannot submit tenant IDs to evidence read/write routes. A guessed snapshot
ID from another customer returns 404. A stale workspace header returns 409 and
requires reloading. No shared unauthenticated demo mode exists in the hosted API.

## Verification and dependency maintenance

```powershell
python -m pip install '.[dev]'
python -m pytest -q
python -m pip_audit -r requirements-hosted.lock --strict
python -m build
```

For PostgreSQL tests, use an empty disposable database owned by a dedicated
non-superuser role; set `CLEARTRAIL_TEST_POSTGRES_URL`, then run
`python -m pytest tests/test_hosted_postgres.py -q`. The tests create tenants and
leave data for inspection. Destroy the entire disposable database afterwards.
Never use an existing customer database. CI configures an ephemeral service.

To update runtime pins, review `requirements-hosted.in`, resolve with pip-tools,
then attach published hashes without downloading all platform wheels:

```powershell
python -m pip install pip-tools
python -m piptools compile --strip-extras --no-emit-index-url --no-emit-trusted-host --output-file .cleartrail/requirements-resolved.txt requirements-hosted.in
python scripts/hash_lock.py .cleartrail/requirements-resolved.txt
python -m pip install --require-hashes -r requirements-hosted.lock
```

Review the lock diff, audit, tests and Linux container build before release.
Schema version 5 explicitly migrates versions 1–4 while preserving source evidence, schedules, ciphertext and jobs. A version 1 upgrade leaves scheduling disabled. Migration is idempotent; future incompatible schemas still need reviewed migrations and recovery plans before deployment.

## Governance in 0.6

Schema 5 adds `ct_governance_records`, `ct_governance_versions` and
`ct_governance_reviews`. Grant the runtime role DML on these tables after the
schema-owner migration. Forced RLS is required on 17 tenant-scoped tables.
Vault rotation and backups include governance payloads. Read
[GOVERNANCE.md](GOVERNANCE.md) for approval/evidence-link semantics and limits.
For a credit-funded Mumbai staging candidate, see
[AWS_STAGING.md](AWS_STAGING.md). That template has not been provisioned in AWS.


## Recurring collection in 0.3

Run `python -m cleartrail.hosted_scheduler` as a separate supervised process, alongside the worker. Schedules start disabled; a workspace administrator enables them in Monitoring. See [MONITORING.md](MONITORING.md) for cadence, freshness, quota/missed-run behavior, notices and the explicit v1-to-v2 database upgrade. Grant the runtime role DML permissions on the new tables after migrating with the schema-owner role.

## Team evidence in 0.5

See [TEAM_EVIDENCE.md](TEAM_EVIDENCE.md) for encrypted uploads, version history,
independent review, auditor visibility and the schema 4 upgrade. Grant runtime
DML on the document tables when upgrading from before 0.4. File contents live in PostgreSQL
and use the vault key ring; database backups alone cannot recover them without
the applicable keys. Vault rotation now includes uploaded files. No extra storage
volume or paid service is required for evidence storage. [SCANNING.md](SCANNING.md)
describes the optional private ClamAV profile required for PDF/modern Office files.
The API's final image is pinned to Python 3.12/Alpine, runs without pip/ensurepip,
and remains read-only/non-root with restricted resources. Install dependencies
in your build environment, then rebuild; do not mutate the running image.

Use [AUDIT_PACKAGES.md](AUDIT_PACKAGES.md) for document-inclusive exports,
[RECOVERY.md](RECOVERY.md) for backup/restore and [LIVE_VALIDATION.md](LIVE_VALIDATION.md)
for read-only provider checks using your real test organizations. The API's
in-process budgets are 120/minute per session/IP pair and 600/minute per ASGI
client IP, per replica. Configure shared ingress limits and explicitly trusted
proxy addresses for the actual deployment; never trust arbitrary forwarded
headers. Docker's default `--no-proxy-headers` treats ingress as the client.
