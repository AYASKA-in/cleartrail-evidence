# ClearTrail: product gaps and a free-software development roadmap

Research date: 23 October 2026. Baseline: ClearTrail 0.2 source in this workspace.
Scope: compare the shared Vanta/Drata evidence workflow with what our code
actually implements, then identify a practical path without mandatory paid
software services. No application behavior was changed during this study.

## Finding

ClearTrail already implements the narrow collection → checks → linked evidence
→ portable snapshot export loop. It has a useful security foundation. It does
not yet implement the ongoing evidence-management and audit-collaboration
workflows described by the reference products. The strongest next investment
is that lifecycle, rather than simply increasing the check count.

The subagent produced [13 vendor findings](research/vendor-comparison-2026-10-23.md)
using official documentation and a new REA capture. These are observations of
published documentation, not authenticated vendor behavior, recovered backend
algorithms or a feature-parity test. Availability can vary by vendor plan and
interface. No vendor pricing or investment return was established.

## What we have, verified in source

| Implemented capability | Evidence in this repository | Boundary |
|---|---|---|
| 14 original controls: 11 automated and 3 manual | `cleartrail/catalog.py:3` | GitHub 4, Google 3, AWS 4; three manual notes. Partial framework references, not a full SOC 2/ISO program. |
| Read-only provider collection | `cleartrail/connectors.py:185` | GitHub classic default-branch protection; Google user 2SV/admin checks; selected AWS account/region settings. |
| Point-in-time observations and provenance | `cleartrail/core.py:68` | Collection window, scope fingerprint, explicit unknowns and immutable saved snapshots. |
| Hosted identity and customer isolation | `cleartrail/hosted_auth.py:131`, `hosted_repository.py:132` | One configured OIDC issuer; application workspace memberships and roles. PostgreSQL runtime validation is still pending. |
| Encrypted credentials and isolated collection | `cleartrail/vault.py:27`, `isolated.py:139`, `hosted_worker.py:16` | Vault key rotation and account-bound AWS role access; Google bearer-token renewal remains manual. |
| Durable on-demand collection | `cleartrail/hosted_repository.py:326`, `hosted_worker.py:67` | Queue, single flight and leased jobs. Polling the queue is not a recurring collection scheduler. |
| History, team notes and audit chain | `cleartrail/hosted_repository.py:313`, `:391`, `:407` | Self-attestations and change events; no independent artifact-review workflow or external audit anchor service. |
| Verifiable HTML/CSV/JSON ZIP package | `cleartrail/reports.py:92`, `:254` | One saved run at a time; unsigned manifest. A trusted manifest digest supports integrity, not source authenticity. |
| Security regression and deployment artifacts | `docs/VALIDATION.md`, `Dockerfile`, `.github/workflows/ci.yml` | Prior recorded run: 233 tests and 259 subtests passed, five skipped. This research did not rerun that suite or execute remote CI. |

The missing-capability assessment is bounded to the current `cleartrail/`
application modules, routes, persistence definitions and existing project docs.
It does not claim that no external deployment scripts or third-party services
could supply an equivalent behavior.

## What is missing, and what to build

P0 is required before real customer onboarding. P1 is the next useful product
release. P2 broadens the compliance program after the main evidence loop works.
Effort sizes are relative scope estimates, not delivery dates.

| Priority / size | Capability and current gap | Free implementation path and acceptance test |
|---|---|---|
| P0 / M | Prove hosted isolation and recovery; code exists but real PostgreSQL, IdP/cloud and restore exercises remain unverified | Run the provided PostgreSQL RLS/concurrency job, real OIDC login and two-customer provider tests. Restore a backup plus vault keys into a separate environment. Verify cross-tenant reads/writes fail and expired workers cannot publish. |
| P0 / M | Versioned migrations and historical catalogs | The validator currently requires the current catalog/version and exact catalog population. Preserve historical catalog/rule versions and add explicit database migrations before expanding or importing checks. An old exported run must still verify after a new release. |
| P0 / M | Operational monitoring, retention and offboarding | Add worker heartbeat, queue age/failed-job alerts, shared ingress limits, data/attachment quotas, customer export/deletion and retention decisions. Test expiry, deletion races and backup recovery. Keep legal holds and audit retention explicit. |
| P1 / M | Recurring collection, freshness and change detection | Extend the existing PostgreSQL job queue with per-tenant schedules, cadence, next-due time and a unique schedule occurrence. Add stale/missed/error states and finding differences. Restart two schedulers and prove one job per occurrence, no stale pass presented as current, and a missed-run notice. |
| P1 / L | Easy, durable integration onboarding | GitHub App installation and short-lived tokens; Google authorization-code connection with encrypted refresh-token rotation/revocation; original AWS role/trust template and permission preflight. Test expiry, reduced scopes and revoked installations. Login OIDC and provider OAuth are separate flows. |
| P1 / L | Evidence files and independent review | Add tenant-scoped artifacts, immutable versions, owners, effective dates, renewal dates, reviewer decisions and control links. Use an encrypted local volume initially, with a replaceable object-storage interface. Apply upload/type/size checks, safe downloads and malware scanning. A replacement file must not rewrite an already approved version. |
| P1 / M | Remediation and exceptions | Add stable findings across runs, owner, due date, comments, status and verification. Record acceptance separately with approver, reason, compensating control and expiry. An accepted exception must not erase the underlying failed observation or become an automatic pass. |
| P1 / L | Audit-period packaging and scoped collaboration | Add engagement, start/end dates, scoped assets/controls, requested samples and approved evidence versions. Export included/missing/stale/excluded inventories with source timestamps. Grant auditors only selected engagement evidence with expiry and download logging. A guessed sibling engagement/artifact ID must fail. |
| P1 / M | Deeper coverage using existing scanners | Import bounded Prowler OCSF and Trivy/Checkov JSON or SARIF reports through versioned adapters. Keep producer/version, source time, account/resource scope, raw-file digest and parsing diagnostics. A missing/error result must stay unknown; imported timestamps are source claims, not independently authenticated facts. |
| P2 / L | Policies and actual access reviews | Add policy draft/approval/publication and version-bound acknowledgments. Build account/role inventories, identity correlation, frozen review populations, reviewer decisions and verified removal tasks. A text note remains self-attestation, not proof that every entitlement was reviewed. |
| P2 / M–L | People, assets, risks and vendors | Directory/CSV reconciliation, joiner/leaver tasks, asset ownership/classification, original risk scoring/treatment/acceptance, and vendor review dates linked to evidence. Start with structured records and exports; avoid unnecessary sensitive HR uploads. |
| P2 / M | Optional downstream integrations and notifications | Start with in-app notifications and downloadable tasks, then customer-configured SMTP/webhooks/ticket systems with delivery outbox, bounded retries and egress controls. Never include secrets in alerts. No paid AI API is needed for these workflows. |

The product findings behind these priorities are documented separately:
[monitoring](https://help.drata.com/en/articles/13391811-monitoring-overview),
[evidence lifecycle](https://help.drata.com/en/articles/13404035-evidence-overview),
[auditor collaboration](https://help.drata.com/en/articles/13773092-using-the-drata-audit-portal-new-experience),
[access-review campaigns](https://help.drata.com/en/articles/13557396-run-an-access-review),
and the subagent's remaining primary references. These sources describe the
reference workflow; our implementation designs above are independent proposals.

## Reuse free tools where they help

These projects already exist. ClearTrail should be the understandable evidence
and review workflow around suitable outputs, rather than reimplement every
scanner. Integration suitability below is a design recommendation, not something
already shipped or tested in our application.

| Project | Proposed use | Important boundary |
|---|---|---|
| [Prowler OSS](https://github.com/prowler-cloud/prowler) | Broader cloud configuration findings; normalize OCSF output into evidence | Its repository uses [Apache 2.0](https://raw.githubusercontent.com/prowler-cloud/prowler/master/LICENSE). Keep provider/rule versions and a documented mapping; scanner pass does not establish an entire framework requirement. [Official output example](https://prowler.com/workshops/defcon-2026). |
| [Trivy](https://github.com/aquasecurity/trivy) | Dependency/container vulnerabilities, IaC checks, SBOM and secret-detection evidence | [Apache 2.0](https://raw.githubusercontent.com/aquasecurity/trivy/main/LICENSE); ingest its [structured reports](https://trivy.dev/docs/latest/configuration/reporting/). Retain redacted findings and fingerprints rather than detected secret values. |
| [Checkov](https://github.com/bridgecrewio/checkov) | Local infrastructure-as-code policy results | [Apache 2.0](https://raw.githubusercontent.com/bridgecrewio/checkov/main/LICENSE). Use the local checks needed by the feature; do not assume every associated Prisma Cloud service is free. The README documents `--skip-download` for avoiding its remediation-guide API call. |
| [CISO Assistant Community](https://github.com/intuitem/ciso-assistant-community) | Evaluate a separate GRC companion or interoperability target for broader program records | Its [license file](https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/LICENSE.md) distinguishes AGPL community code and a commercial enterprise directory. Do not treat the repository or enterprise features as MIT assets to copy into ClearTrail. Review licenses for the exact components selected. |

Start with file imports produced by a trusted operator or customer CI. Do not
execute user-supplied plugins or arbitrary scanner commands in the hosted worker.
Validate imported schemas, resource populations and byte/record limits, bind every
artifact to its tenant, and preserve the raw producer result separately from its
review interpretation. Pin and audit any scanner versions we later distribute.

Our existing strict 14-control schema cannot simply accept arbitrary scanner JSON.
Introduce a versioned external-finding model and an explicit mapping registry;
do not bypass the current integrity validator to make an import appear to work.

## Recommended development order

1. Close the existing hosted launch-validation gates and design catalog/schema
   compatibility. Keep tests that prove old runs and packages remain readable.
2. Build recurring collection plus visible freshness on the existing three
   providers. Add an in-app missed-run notice and a source-population change view.
3. Add versioned evidence files, ownership and an independent review decision.
4. Add an audit engagement and a complete period-scoped export, then restrict
   auditor access to that engagement.
5. Add Prowler import first; Trivy and Checkov adapters next where customer demand
   warrants them. Expand native GitHub ruleset and Google/AWS population coverage.
6. Extend to access-review campaigns, policy acknowledgments and risk/vendor/asset
   records after the main evidence loop is usable.

The first coherent milestone should demonstrate: a scheduled GitHub collection,
a later stale/changed finding, an assigned remediation, an uploaded policy
version approved by a reviewer, and an audit-period package that transparently
lists missing evidence. That is a more useful acceptance scenario than a headline
claim about hundreds of checks.

## Suggested identity and hosting setup

For a no-license-fee staging environment, use **Keycloak + PostgreSQL + the
ClearTrail API/worker in containers on hardware you already own**. This is a
recommendation, not a newly deployed environment. Keycloak has a documented
[Docker setup](https://www.keycloak.org/getting-started/getting-started-docker)
and an [Apache 2.0 project license](https://github.com/keycloak/keycloak/blob/main/LICENSE.txt).
Its quickstart uses development settings/example credentials; use appropriate
production settings and unique secrets before external access.

Use one ClearTrail identity realm initially. The current app accepts one trusted
OIDC issuer and keeps customers as application workspaces; one separate realm
per customer would require additional issuer-routing and authorization work.
Keep the initial staging environment private. Later place the hosted API behind
HTTPS on an operated Linux host with encrypted backups and monitored workers.

If the first users already have Google identities, [Google OIDC](https://developers.google.com/identity/openid-connect/openid-connect)
is an alternative that avoids operating a separate identity server. Register a
client and exact callback, then grant explicit issuer/subject workspace membership.
Signing in with Google does not also authorize Directory evidence collection.

Free managed tiers are an optional evaluation route, not the default production
plan. [Render's own free-service documentation](https://render.com/docs/free)
says those instances should not be used for production and restricts which service
types are free; our deployment needs a background worker as well as a web app.
[Neon offers a quota-limited free Postgres plan](https://neon.com/pricing), but
the role/RLS behavior, recovery needs and complete application deployment still
need validation. Neither is an assurance of costless customer hosting.

## What “free” can realistically mean

Keep ClearTrail's core MIT-licensed, require no paid AI service, support self-hosting,
and make all customer evidence exportable in documented formats. Prefer the
existing PostgreSQL queue over introducing another required hosted service.
Allow optional externally supplied scanner reports and storage backends.

There can be zero additional software-license fees using the proposed stack.
That does not remove hardware, electricity, internet, storage, backups, provider
subscriptions, maintenance or independent audit costs. Do not promise unlimited
free multi-customer hosting, certification, auditor acceptance, customer adoption
or investment return from this study.

Before broadening scope, have a few startup security owners and an independent
auditor inspect a synthetic period package and its gap inventory. That validation
has not happened yet. Existing products demonstrate available workflows, not
that a new implementation has proven demand or satisfies every audit requirement.


## Implementation update: 0.3

The comparison above remains the dated 0.2 baseline. The first implementation slice now adds opt-in schedules, evidence freshness, missed-run/worker-delay visibility, scoped notice acknowledgment, frozen historical catalogs and a v1-to-v2 database migration. Real PostgreSQL and Linux container tests now pass. Evidence attachments/approvals, audit-period packages, scanner imports, richer access reviews and live customer IdP/cloud validation remain outstanding. See [MONITORING.md](MONITORING.md) and [VALIDATION.md](VALIDATION.md) for exact scope and test results.

## Implementation update: 0.4

The second slice adds encrypted UTF-8 text/Markdown/CSV attachments in PostgreSQL,
owner assignment, immutable versions, expiry, append-only independent decisions,
safe downloads and approved-version auditor access. Tenant locking enforces
quotas and rejects stale concurrent edits. Encryption binds immutable metadata
and includes existing vault rotation. This uses the existing database instead of
the initially proposed filesystem volume, so uploads and metadata commit together
and share the database backup boundary. See [TEAM_EVIDENCE.md](TEAM_EVIDENCE.md).
PDF/Office/image quarantine and scanning, document-inclusive audit-period exports,
engagement-scoped collaboration, lifecycle/offboarding, remediation, scanner imports
and live customer identity/provider validation remain development gaps.


## Implementation update: 0.5

Fresh ClamAV scanning and bounded PDF/macro-free Office uploads, authenticated
scan provenance, document-inclusive period packages and offline verification are
implemented. Real local Keycloak browser flows, desktop/mobile QA, killed-worker
PostgreSQL logical recovery, legacy migration and internal security/image review
were exercised. Google OIDC callback compatibility and a staging guide are included.
A Google OIDC staging guide uses a dedicated subdomain; no live
Google client, GitHub scope or Workspace/AWS test accounts were supplied.

Remaining development includes broader controls and cloud population coverage,
GitHub App onboarding, durable Google collector identity refresh, lifecycle/retention
and customer deletion, engagement-scoped sharing, risk/remediation/access-review
workflows, scanner imports, signed exports and independently retained audit anchors.
Operational launch still needs actual hosting/TLS/IdP/provider validation, external
alerts, off-host PITR, capacity/soak evidence and independent security/auditor review.
See [RELEASE_GATES.md](RELEASE_GATES.md). The software remains MIT-licensed; operated
hosting, provider subscriptions and independent audit costs are not made free by it.
