# Recurring monitoring — ClearTrail 0.3

This release adds hosted collection schedules, freshness status and in-app
operational notices. It uses the existing PostgreSQL job queue and isolated
worker; no paid scheduler, AI service, Redis or extra hosted service is required.
The local CLI/dashboard continues to collect on demand.

## Enable monitoring

Start the API, worker and separate scheduler using the hosted deployment guide.
Sign in as a workspace administrator and open **Monitoring**. Choose hourly,
six-hourly, twelve-hourly, daily or weekly collection and a freshness policy.
Freshness must cover at least the collection interval and cannot exceed 720 hours.
The defaults are daily collection and 25-hour freshness, with scheduling disabled.

Every workspace, including an existing migrated workspace, starts with scheduling
disabled. An administrator explicitly enables it. Enabling or changing frequency
makes a run due immediately; a freshness-only adjustment preserves the next due
time. Disabling a schedule stops future dispatches without cancelling queued or
running jobs. Operators can still start on-demand collections; auditors are read-only.

```powershell
python -m cleartrail.hosted_scheduler
python -m cleartrail.hosted_worker
```

Run these as separate supervised processes. The scheduler polls every 30 seconds
and never calls cloud APIs. The worker executes leased collection jobs. Both need
the hosted runtime configuration and database access. For one supervised pass:

```powershell
python -m cleartrail.hosted_scheduler --once
python -m cleartrail.hosted_worker --once
```

The supplied Compose file includes the scheduler with a read-only filesystem,
non-root user, dropped capabilities and CPU/memory/PID limits:

```powershell
docker compose up -d api worker scheduler
```

## Cadence, concurrency and recovery

Due times are UTC epoch seconds based on the database clock. Each dispatch is
one tenant-locked transaction: it checks the schedule, active jobs and quota;
captures the current configuration and notes; creates a job and uniquely keyed
schedule occurrence; advances the due time; and records the audit event.
Multiple scheduler replicas cannot create duplicate jobs for an occurrence.
Existing per-tenant single-flight and 48-collections-per-day limits still apply.

An active on-demand or scheduled job defers dispatch without advancing its due
time. Quota exhaustion similarly holds the due time and creates a deduplicated
notice. Dispatch resumes when a worker finishes and quota permits it.

After downtime, the scheduler records missed earlier periods and queues one
latest-due collection. It does not enqueue a backlog storm. That late collection
observes the provider state **at its actual collection time**; it does not recover
or fabricate evidence from missed historical periods. The occurrence and audit
event preserve due time, dispatch time, schedule revision and missed count.

An overdue schedule becomes visible after ten minutes. A job queued for ten
minutes is marked delayed; an expired running lease is visible until a worker
recovers it as failed. These are in-app operational indicators, not an external
paging or worker-heartbeat system. The hosting operator must still monitor and
alert on the processes and database through their infrastructure.

## Evidence freshness is separate from check outcomes

Saved snapshots and exported packages are never rewritten as time passes.
The dashboard labels metrics as snapshot results and displays live monitoring
status separately. A known failing setting can have recent evidence; recent
evidence is not a passing control or a compliance conclusion.

| Status | Meaning |
|---|---|
| Recent evidence | Provider observations are within the policy window for the current configuration/catalog and have no unknown collection gaps. Review pass/fail outcomes separately. |
| Incomplete collection | A configured provider has missing or unknown evidence, even if the snapshot is recent. |
| Stale evidence | A provider's oldest observation reaches the freshness threshold. Prior results remain historical. |
| Collection failed | The newest job failed. The earlier successful snapshot remains available. |
| Scope/catalog changed | Current configuration or current control rules differ from the saved snapshot; collect again. |
| No evidence/providers | No snapshot or no configured sources. This cannot imply a healthy security posture. |
| Clock error | Snapshot time is more than five minutes ahead of the database clock. Check time synchronization. |
| Snapshot updating | A collection committed during polling. Refresh to avoid pairing newer health metadata with an older snapshot. |

Freshness is calculated for enabled automated providers, using their oldest
observation in the latest snapshot. Manual notes remain unverified human-review
items; document renewal/approval workflows are a later product milestone.

Small hash-checked monitoring projections support compact polling without reading
the full evidence document on every refresh. A corrupted projection fails closed
with HTTP 503. An operator can rebuild this derived cache from a verified source:

```powershell
python -m cleartrail.hosted_admin rebuild-monitoring --tenant TENANT_UUID
```

Rebuilding does not modify source evidence. Corrupted source evidence must be
investigated/restored rather than silently rewritten or rehashed.

## Notices and audit history

The Monitoring page shows the latest notice of each type: collection failure,
missed/delayed occurrence and quota block. This bounds operational notice rows;
collection and schedule events remain in the append-only application audit chain.
A new event replaces that type's visible notice, increments its event count and
requires a fresh acknowledgment. An old notice ID cannot acknowledge a newer one.

Admins and operators can acknowledge a notice; auditors cannot. Acknowledgment
is tenant-scoped, audited and idempotent. It does not fix an outage, erase a
failure, change freshness or change any saved pass/fail result. No email, Slack
or webhook alert delivery is implemented in this release.

## Upgrade from 0.2

Back up the hosted database and vault keys. Stop old API/worker instances, run
the explicit migration as the schema-owner role, grant the runtime role DML
access to the newly created `ct_*` tables, then start the 0.3 API, worker and
scheduler. Do not run the old binary against the new schema.

```powershell
python -m cleartrail.hosted_admin migrate
```

Schema version 2 adds schedules, occurrences, notices, monitoring projections and
latest-job pointers, plus a run-history index. The migration checks existing run
hashes, backfills derived state and preserves existing evidence documents, jobs,
credentials, notes and audit rows. It is idempotent and refuses unknown future
schema versions. Fresh schedules remain disabled. PostgreSQL migration and RLS
tests exercise a real non-superuser role.

The `2026.10.1` control catalog is frozen in a hash-pinned packaged JSON file.
Historical runs validate against their declared registered catalog. Add a new
catalog version when changing rules; never edit a published historical file or
remove its registry entry. Version 0.2 packages retain exact HTML/CSV regeneration
support, covered by a synthetic golden fixture produced by the installed 0.2
wheel. Unknown generator/rendering versions still fail validation. Unsigned
hashes establish integrity relative to a trusted manifest, not provider authenticity.

## API additions

`GET /api/state` now includes `schedule`, `collection_health` and `notifications`.
`POST /api/schedule` accepts exactly `enabled`, `interval_hours`, `freshness_hours`
and requires an administrator. `POST /api/notifications/acknowledge` accepts
exactly `id` and requires an admin/operator. Both mutations use the existing
session, Origin, CSRF and active-workspace checks; foreign notice IDs return 404.

## Remaining launch work

Live customer IdP/provider permissions, visual UI QA, measured load/soak tests,
managed backup/PITR restoration, external audit anchoring and an independent
security review remain release gates. This milestone does not implement evidence
file uploads, reviewer approvals, engagement-scoped auditor sharing, audit-period
packages or third-party scanner imports. See the product roadmap for those next
steps; the new scheduling infrastructure can support them without a paid queue.
