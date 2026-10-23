# Backup and recovery runbook

Back up PostgreSQL, the deployed release/configuration and the applicable vault
key ring. Store database backups and keys encrypted under separate access controls.
A database dump alone cannot decrypt credentials or uploaded files. Keep retired
keys for retained backups and legal holds; key rotation is not a reason to destroy
all old recovery keys. ClamAV definitions can be updated/rebuilt separately.
Your IdP, DNS/TLS and secret store have their own recovery procedures.

## Backup

Use a dedicated operator backup identity. Forced RLS prevents a normal application
role from dumping all tenants; the backup identity needs explicitly controlled
cross-tenant access. Never grant BYPASSRLS or schema ownership to the API role.
Use libpq service/password files or your secret store, not passwords in shell
history, connection arguments or logs. Require database TLS verification outside
a trusted local transport.

For a maintenance-window logical backup, fence/quiesce API writes, scheduler and
workers, record externally retained audit heads, then run a consistent dump:

```sh
pg_dump --dbname=service=cleartrail_backup --format=custom --file=PRIVATE_BACKUP_PATH
```

Protect file permissions and encrypt before transferring off-host. Inventory the
release version, schema version, backup checksum/time, vault key identifiers,
audit anchors and monitoring/schedule state. Keep the keys themselves out of
that inventory. Automate failure/age checks in the operator's monitoring system.

## Restore rehearsal

1. Restore into a **new, isolated database**, never over the only customer copy.
   Fence old workers so a recovered deployment cannot operate beside a stale copy.
2. Recreate reviewed owner/runtime roles and restore schema, data, grants and
   ownership using the operator identity:

   ```sh
   pg_restore --dbname=service=cleartrail_restore --exit-on-error --single-transaction PRIVATE_BACKUP_PATH
   ```

3. Restore the applicable key ring securely. Start with the release that produced
   the backup. If upgrading, run the explicit migration with the owner role while
   services remain stopped. Runtime remains NOSUPERUSER/NOBYPASSRLS with no schema
   CREATE and SELECT-only access to `ct_schema`.
4. Check `/readyz`, forced RLS on all 14 scoped tables, unscoped empty reads and
   foreign-tenant denial. Compare `hosted_admin audit --tenant ... --expected-head ...`
   against retained pre-backup anchors. Verify snapshot digests, document bytes,
   approval history and credential decryption. Deliberately test rejection with a
   wrong recovery key in the isolated copy.
5. Invalidate restored `ct_sessions` during the fenced maintenance window and
   require fresh OIDC sign-in. Treat resurrected provider credentials according
   to the provider's rotation/revocation policy. The operator can perform the
   explicit session-table deletion through the reviewed database maintenance
   identity; this is not a public application endpoint.
6. Inspect queued/running jobs and schedules before resuming dispatch. A killed
   worker retains its durable lease for up to 720 seconds; after expiry it becomes
   `worker_lost`, not successful. Do not shorten healthy production leases to hurry
   recovery. Missed schedule periods are coalesced, not fabricated historical runs.
7. Resume one worker/scheduler, then API traffic. Verify notices, job completion,
   package verification and new audit events. Measure recovery duration and data
   loss against your agreed RPO/RTO and record the result.

## What was actually exercised

The local PostgreSQL 17.11 drill quiesced the QA API, dumped a database while a real
worker/collector child was blocked by a QA-only fault fixture, killed that worker
container, restored into a separate database, verified anchors/keys/files/RLS and
restarted the API. Wrong keys and foreign-tenant reads failed. Restored sessions
were invalidated and the browser required fresh real Keycloak authentication.
The last successful snapshot stayed unchanged and the interrupted job became
failed with a notice. For test duration, **only the disposable restored fixture's
lease was explicitly advanced to expiry**; the full twelve-minute wait was not
measured. No fault-injection option was added to the production worker.

The observed end-to-end local outage was 81.38 seconds, including operator/tool
steps. Quiesced committed fixture data was preserved. These are rehearsal
measurements, not a production recovery SLA or proof of off-host disaster recovery.

For continuous operation, configure encrypted off-host backups plus WAL archiving
and PostgreSQL point-in-time recovery appropriate to the actual hosting platform.
WAL/PITR, geographic loss, actual IdP recovery and a sustained production recovery
SLA were not exercised in this local logical-restore drill. Rehearse those against
the selected deployment before promising customer RPO/RTO. Review retention and
deletion obligations before defining backup expiry.
