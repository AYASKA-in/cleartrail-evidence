"""Transactional tenant-scoped persistence for the hosted service.

All tenant data uses composite keys and explicit scope predicates. PostgreSQL
additionally forces RLS with a transaction-local tenant context. No API accepts
an arbitrary workspace ID as a substitute for an authenticated membership.
"""
from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from contextlib import contextmanager

from sqlalchemy import (MetaData, Table, Column, String, Text, Integer, BigInteger, UniqueConstraint, inspect,
                        ForeignKey, ForeignKeyConstraint, CheckConstraint, Index,
                        create_engine, select, insert, update, delete, and_, func, text as sql)
from sqlalchemy.pool import StaticPool

from .catalog import CATALOG
from .validation import canonical, digest, strict_json_loads, text, validate_config, validate_run
from .vault import Vault
from .errors import EvidenceIntegrityError
from .monitoring import (DEFAULT_INTERVAL_HOURS, DEFAULT_FRESHNESS_HOURS, SCHEDULE_GRACE_SECONDS,
                         validate_schedule, evidence_health, monitoring_projection)
from .document_repository import DocumentRepository

SCHEMA_VERSION = 4
ROLES = {"admin", "operator", "auditor"}
meta = MetaData()
schema = Table("ct_schema", meta, Column("version", Integer, primary_key=True))
tenants = Table("ct_tenants", meta, Column("id", String(36), primary_key=True),
                Column("name", String(200), nullable=False), Column("config", Text, nullable=False),
                Column("aws_external_id", String(43), nullable=False, unique=True),
                Column("created_at", BigInteger, nullable=False))


def tenant_table(name, *columns, constraints=()):
    return Table("ct_" + name, meta,
                 Column("tenant_id", String(36), ForeignKey("ct_tenants.id"), primary_key=True),
                 *columns, *constraints)


members = tenant_table("members", Column("issuer", String(512), primary_key=True),
                       Column("subject", String(255), primary_key=True), Column("role", String(16), nullable=False),
                       constraints=(CheckConstraint("role IN ('admin', 'operator', 'auditor')"),))
credentials = tenant_table("credentials", Column("provider", String(16), primary_key=True),
                           Column("envelope", Text, nullable=False), Column("updated_at", BigInteger, nullable=False))
notes = tenant_table("notes", Column("control_id", String(40), primary_key=True), Column("document", Text, nullable=False))
revisions = tenant_table("revisions", Column("id", String(36), primary_key=True), Column("document", Text, nullable=False))
runs = tenant_table("runs", Column("id", String(40), primary_key=True), Column("collected_at", String(40), nullable=False),
                    Column("document", Text, nullable=False), Column("sha256", String(64), nullable=False),
                    Column("summary", Text, nullable=False))
run_timeline = Index("ct_run_timeline", runs.c.tenant_id, runs.c.collected_at, runs.c.id)
jobs = tenant_table("jobs", Column("id", String(36), primary_key=True), Column("status", String(16), nullable=False),
                    Column("created_at", BigInteger, nullable=False), Column("finished_at", BigInteger),
                    Column("lease_until", BigInteger), Column("lease_token", String(64)),
                    Column("config", Text, nullable=False), Column("attestations", Text, nullable=False),
                    Column("run_id", String(40)), Column("error", String(64)),
                    constraints=(CheckConstraint("status IN ('queued', 'running', 'succeeded', 'failed')"),
                                 ForeignKeyConstraint(["tenant_id", "run_id"], ["ct_runs.tenant_id", "ct_runs.id"])))
Index("ct_one_active_job", jobs.c.tenant_id, unique=True,
      postgresql_where=jobs.c.status.in_(["queued", "running"]), sqlite_where=jobs.c.status.in_(["queued", "running"]))
Index("ct_job_queue", jobs.c.status, jobs.c.created_at)
audit = tenant_table("audit", Column("sequence", Integer, primary_key=True), Column("event", Text, nullable=False),
                     Column("previous_hash", String(64), nullable=False), Column("event_hash", String(64), nullable=False))
sessions = Table("ct_sessions", meta, Column("token_hash", String(64), primary_key=True),
                 Column("issuer", String(512), nullable=False), Column("subject", String(255), nullable=False),
                 Column("active_tenant", String(36), ForeignKey("ct_tenants.id"), nullable=False),
                 Column("csrf", String(43), nullable=False), Column("expires_at", BigInteger, nullable=False))
Index("ct_session_expiry", sessions.c.expires_at)
schedules = tenant_table("schedules", Column("enabled", Integer, nullable=False),
                         Column("interval_hours", Integer, nullable=False), Column("freshness_hours", Integer, nullable=False),
                         Column("revision", Integer, nullable=False), Column("next_due_at", BigInteger),
                         Column("updated_at", BigInteger, nullable=False), Column("last_dispatched_at", BigInteger),
                         Column("blocked_reason", String(32)),
                         constraints=(CheckConstraint("enabled IN (0,1)"),
                                      CheckConstraint("interval_hours IN (1,6,12,24,168)"),
                                      CheckConstraint("freshness_hours >= interval_hours AND freshness_hours <= 720")))
occurrences = tenant_table("schedule_occurrences", Column("revision", Integer, primary_key=True),
                           Column("due_at", BigInteger, primary_key=True), Column("job_id", String(36), nullable=False),
                           Column("missed_count", Integer, nullable=False), Column("dispatched_at", BigInteger, nullable=False),
                           constraints=(ForeignKeyConstraint(["tenant_id", "job_id"], ["ct_jobs.tenant_id", "ct_jobs.id"]),))
notifications = tenant_table("notifications", Column("kind", String(40), primary_key=True),
                             Column("id", String(36), nullable=False), Column("fingerprint", String(64), nullable=False),
                             Column("document", Text, nullable=False), Column("created_at", BigInteger, nullable=False),
                             Column("read_at", BigInteger), Column("event_count", Integer, nullable=False),
                             constraints=(UniqueConstraint("tenant_id", "id"),))
monitoring = tenant_table("monitoring", Column("snapshot_id", String(40), nullable=False),
                          Column("document", Text, nullable=False), Column("sha256", String(64), nullable=False),
                          constraints=(ForeignKeyConstraint(["tenant_id", "snapshot_id"], ["ct_runs.tenant_id", "ct_runs.id"]),))
job_heads = tenant_table("job_heads", Column("job_id", String(36), nullable=False),
                         constraints=(ForeignKeyConstraint(["tenant_id", "job_id"], ["ct_jobs.tenant_id", "ct_jobs.id"]),))
documents = tenant_table("documents", Column("id", String(36), primary_key=True),
                         Column("title", String(160), nullable=False), Column("control_ids", Text, nullable=False),
                         Column("owner", String(255), nullable=False), Column("revision", Integer, nullable=False),
                         Column("created_at", BigInteger, nullable=False))
document_versions = tenant_table("document_versions", Column("id", String(36), primary_key=True),
                                 Column("document_id", String(36), nullable=False), Column("number", Integer, nullable=False),
                                 Column("filename", String(100), nullable=False), Column("size", Integer, nullable=False),
                                 Column("sha256", String(64), nullable=False), Column("uploaded_by", String(255), nullable=False),
                                 Column("owner_at_upload", String(255), nullable=False), Column("created_at", BigInteger, nullable=False),
                                 Column("expires_at", BigInteger), Column("envelope", Text, nullable=False), Column("scan", Text),
                                 constraints=(ForeignKeyConstraint(["tenant_id", "document_id"], ["ct_documents.tenant_id", "ct_documents.id"]),
                                              UniqueConstraint("tenant_id", "document_id", "number"),
                                              CheckConstraint("number BETWEEN 1 AND 20 AND size BETWEEN 1 AND 524288")))
document_reviews = tenant_table("document_reviews", Column("id", String(36), primary_key=True),
                                Column("version_id", String(36), nullable=False), Column("sequence", Integer, nullable=False),
                                Column("decision", String(16), nullable=False), Column("reviewer", String(255), nullable=False),
                                Column("comment", String(2000), nullable=False), Column("created_at", BigInteger, nullable=False),
                                constraints=(ForeignKeyConstraint(["tenant_id", "version_id"], ["ct_document_versions.tenant_id", "ct_document_versions.id"]),
                                             UniqueConstraint("tenant_id", "version_id", "sequence"),
                                             CheckConstraint("decision IN ('approved','rejected','withdrawn') AND sequence BETWEEN 1 AND 20")))
SCOPED = (credentials, notes, revisions, runs, jobs, audit, schedules, occurrences, notifications, monitoring, job_heads,
          documents, document_versions, document_reviews)


def _json(value):
    return canonical(value).decode("utf-8")


def tenant_id(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("Invalid workspace identifier.")
    return value


class Repository(DocumentRepository):
    def __init__(self, settings):
        self.settings = settings
        options = {"pool_pre_ping": True}
        if settings.database_url.startswith("sqlite"):
            options.update(connect_args={"check_same_thread": False, "timeout": 15})
            if settings.database_url.endswith(":memory:"):
                options["poolclass"] = StaticPool
        else:
            options.update(pool_size=5, max_overflow=5, pool_timeout=10,
                           connect_args={"connect_timeout": 10, "options": "-c statement_timeout=15000 -c lock_timeout=10000"})
        self.engine = create_engine(settings.database_url, **options)
        if self.engine.dialect.name == "sqlite":
            from sqlalchemy import event
            @event.listens_for(self.engine, "connect")
            def sqlite_pragmas(dbapi, _):
                dbapi.execute("PRAGMA foreign_keys=ON")
        self.vault = Vault(settings.vault_keys)

    def migrate(self):
        """Explicit operator action. The web process never mutates the schema."""
        with self.engine.begin() as db:
            if self.engine.dialect.name == "postgresql":
                db.execute(sql("SELECT pg_advisory_xact_lock(648236173)"))
            versions = list(db.execute(select(schema.c.version)).scalars()) if inspect(db).has_table(schema.name) else []
            if versions not in ([], [1], [2], [3], [SCHEMA_VERSION]):
                raise ValueError("Unsupported hosted schema version.")
            # Additive migrations preserve existing evidence, jobs and audit rows.
            meta.create_all(db)
            if "scan" not in {column["name"] for column in inspect(db).get_columns(document_versions.name)}:
                db.execute(sql("ALTER TABLE ct_document_versions ADD COLUMN scan TEXT"))
            run_timeline.create(db, checkfirst=True)
            if not versions:
                db.execute(insert(schema).values(version=SCHEMA_VERSION))
            if self.engine.dialect.name == "postgresql":
                for table in SCOPED:
                    db.execute(sql(f"ALTER TABLE {table.name} ENABLE ROW LEVEL SECURITY"))
                    db.execute(sql(f"ALTER TABLE {table.name} FORCE ROW LEVEL SECURITY"))
                    exists = db.execute(sql("SELECT 1 FROM pg_policies WHERE schemaname=current_schema() AND tablename=:name AND policyname='ct_scope'"), {"name": table.name}).first()
                    if not exists:
                        db.execute(sql(f"CREATE POLICY ct_scope ON {table.name} USING (tenant_id = current_setting('cleartrail.tenant', true)) WITH CHECK (tenant_id = current_setting('cleartrail.tenant', true))"))
            if versions == [1]:
                for tenant in db.execute(select(tenants.c.id)).scalars().all():
                    if self.engine.dialect.name == "postgresql":
                        db.execute(sql("SELECT set_config('cleartrail.tenant', :tenant, true)"), {"tenant": tenant})
                    row = db.execute(select(runs).where(runs.c.tenant_id == tenant).order_by(runs.c.collected_at.desc(), runs.c.id.desc()).limit(1)).mappings().first()
                    if row:
                        snapshot = validate_run(strict_json_loads(row["document"]))
                        if digest(snapshot) != row["sha256"]:
                            raise EvidenceIntegrityError("Stored snapshot integrity failed during migration.")
                        self._project(db, tenant, snapshot)
                    latest_job = db.execute(select(jobs.c.id).where(jobs.c.tenant_id == tenant).order_by(jobs.c.status.in_(["queued", "running"]).desc(), jobs.c.created_at.desc(), jobs.c.finished_at.desc(), jobs.c.id.desc()).limit(1)).scalar()
                    if latest_job:
                        db.execute(insert(job_heads).values(tenant_id=tenant, job_id=latest_job))
            if versions in ([1], [2], [3]):
                db.execute(update(schema).values(version=SCHEMA_VERSION))

    def ready(self):
        with self.engine.connect() as db:
            if list(db.execute(select(schema.c.version)).scalars()) != [SCHEMA_VERSION]:
                raise ValueError("Run the explicit schema migration before serving traffic.")
            if self.settings.environment == "production":
                role = db.execute(sql("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user")).one()
                if role[0] or role[1]:
                    raise ValueError("Hosted database role must not bypass row-level security.")
                count = db.execute(sql("SELECT count(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relname IN ('ct_credentials','ct_notes','ct_revisions','ct_runs','ct_jobs','ct_audit','ct_schedules','ct_schedule_occurrences','ct_notifications','ct_monitoring','ct_job_heads','ct_documents','ct_document_versions','ct_document_reviews') AND relrowsecurity AND relforcerowsecurity")).scalar_one()
                if count != len(SCOPED):
                    raise ValueError("Tenant row-level security is not installed.")
        return True

    @contextmanager
    def scoped(self, tenant, *, lock=False):
        tenant_id(tenant)
        with self.engine.begin() as db:
            if self.engine.dialect.name == "sqlite" and lock:
                db.exec_driver_sql("BEGIN IMMEDIATE")
            if self.engine.dialect.name == "postgresql":
                db.execute(sql("SELECT set_config('cleartrail.tenant', :tenant, true)"), {"tenant": tenant})
            statement = select(tenants).where(tenants.c.id == tenant)
            if lock:
                statement = statement.with_for_update()
            row = db.execute(statement).mappings().first()
            if not row:
                raise LookupError("Workspace not found.")
            yield db, row

    def _audit(self, db, tenant, actor, action, data):
        last = db.execute(select(audit).where(audit.c.tenant_id == tenant).order_by(audit.c.sequence.desc()).limit(1)).mappings().first()
        sequence, previous = (last["sequence"] + 1, last["event_hash"]) if last else (1, "0" * 64)
        event = {"sequence": sequence, "tenant_id": tenant, "at": int(time.time()),
                 "actor": actor, "action": action, "data": data, "previous_hash": previous}
        db.execute(insert(audit).values(tenant_id=tenant, sequence=sequence, event=_json(event), previous_hash=previous, event_hash=digest(event)))

    def create_tenant(self, name, issuer, subject):
        name, issuer, subject = text(name, maximum=200), text(issuer, maximum=512), text(subject, maximum=255)
        if issuer != self.settings.oidc_issuer:
            raise ValueError("Membership issuer must match the configured identity provider.")
        tenant = str(uuid.uuid4())
        with self.engine.begin() as db:
            db.execute(insert(tenants).values(id=tenant, name=name, config=_json(validate_config({"organization": name})), aws_external_id=secrets.token_urlsafe(32), created_at=int(time.time())))
            db.execute(insert(members).values(tenant_id=tenant, issuer=issuer, subject=subject, role="admin"))
            if self.engine.dialect.name == "postgresql":
                db.execute(sql("SELECT set_config('cleartrail.tenant', :tenant, true)"), {"tenant": tenant})
            self._audit(db, tenant, "operator-cli", "workspace.created", {"initial_admin": subject})
        return tenant

    def list_workspaces(self, issuer, subject):
        with self.engine.connect() as db:
            return [dict(r) for r in db.execute(select(tenants.c.id, tenants.c.name, members.c.role).join(members).where(members.c.issuer == issuer, members.c.subject == subject).order_by(tenants.c.created_at, tenants.c.id)).mappings()]

    def create_session(self, issuer, subject):
        workspaces = self.list_workspaces(issuer, subject)
        if not workspaces:
            raise PermissionError("Workspace membership required.")
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        values = dict(token_hash=hashlib.sha256(token.encode()).hexdigest(), issuer=issuer, subject=subject,
                      active_tenant=workspaces[0]["id"], csrf=csrf, expires_at=int(time.time()) + self.settings.session_seconds)
        with self.engine.begin() as db:
            db.execute(delete(sessions).where(sessions.c.expires_at <= int(time.time())))
            db.execute(insert(sessions).values(**values))
        return {**values, "token": token, "expires_in": self.settings.session_seconds}

    def session(self, token):
        hashed = hashlib.sha256(token.encode()).hexdigest()
        with self.engine.connect() as db:
            row = db.execute(select(sessions, members.c.role).join(members, and_(members.c.tenant_id == sessions.c.active_tenant, members.c.issuer == sessions.c.issuer, members.c.subject == sessions.c.subject)).where(sessions.c.token_hash == hashed, sessions.c.expires_at > int(time.time()))).mappings().first()
            return dict(row) if row else None

    def revoke_session(self, token):
        with self.engine.begin() as db:
            db.execute(delete(sessions).where(sessions.c.token_hash == hashlib.sha256(token.encode()).hexdigest()))

    def select_workspace(self, token, tenant):
        tenant_id(tenant)
        with self.engine.begin() as db:
            session = db.execute(select(sessions).where(sessions.c.token_hash == hashlib.sha256(token.encode()).hexdigest(), sessions.c.expires_at > int(time.time())).with_for_update()).mappings().first()
            if not session or not db.execute(select(members.c.role).where(members.c.tenant_id == tenant, members.c.issuer == session["issuer"], members.c.subject == session["subject"])).first():
                raise PermissionError("Workspace membership required.")
            db.execute(update(sessions).where(sessions.c.token_hash == session["token_hash"]).values(active_tenant=tenant))

    def member_list(self, tenant):
        with self.scoped(tenant) as (db, _):
            return [dict(r) for r in db.execute(select(members.c.issuer, members.c.subject, members.c.role).where(members.c.tenant_id == tenant).order_by(members.c.subject)).mappings()]

    def set_member(self, tenant, actor, subject, role):
        subject = text(subject, maximum=255)
        if role is not None and (not isinstance(role, str) or role not in ROLES):
            raise ValueError("Invalid member role.")
        issuer = self.settings.oidc_issuer
        with self.scoped(tenant, lock=True) as (db, _):
            self._require_role(db, tenant, actor, {"admin"})
            existing = db.execute(select(members).where(members.c.tenant_id == tenant, members.c.issuer == issuer, members.c.subject == subject)).mappings().first()
            admins = db.execute(select(func.count()).select_from(members).where(members.c.tenant_id == tenant, members.c.role == "admin")).scalar_one()
            if existing and existing["role"] == "admin" and role != "admin" and admins <= 1:
                raise ValueError("The workspace must retain at least one administrator.")
            db.execute(delete(members).where(members.c.tenant_id == tenant, members.c.issuer == issuer, members.c.subject == subject))
            if role is not None:
                if db.execute(select(func.count()).select_from(members).where(members.c.tenant_id == tenant)).scalar_one() >= 100:
                    raise ValueError("Workspace member quota reached.")
                db.execute(insert(members).values(tenant_id=tenant, issuer=issuer, subject=subject, role=role))
            # Existing sessions recheck membership and role on every request.
            self._audit(db, tenant, actor, "membership.changed", {"subject": subject, "role": role})

    def _require_role(self, db, tenant, actor, allowed):
        role = db.execute(select(members.c.role).where(members.c.tenant_id == tenant, members.c.issuer == self.settings.oidc_issuer, members.c.subject == actor)).scalar()
        if role not in allowed:
            raise PermissionError("Your workspace role does not allow this action.")

    def config(self, tenant):
        with self.scoped(tenant) as (_, row):
            return strict_json_loads(row["config"])

    def aws_external_id(self, tenant):
        with self.scoped(tenant) as (_, row):
            return row["aws_external_id"]

    def set_config(self, tenant, actor, value):
        value = self._hosted_config(value)
        with self.scoped(tenant, lock=True) as (db, row):
            self._require_role(db, tenant, actor, {"admin"})
            if value["organization"] != row["name"]:
                raise ValueError("Configuration organization must match the workspace name.")
            db.execute(update(tenants).where(tenants.c.id == tenant).values(config=_json(value)))
            self._audit(db, tenant, actor, "configuration.changed", {"config_sha256": digest(value)})

    @staticmethod
    def _hosted_config(value):
        value = validate_config(value)
        aws = value["providers"].get("aws", {})
        if "profile" in aws or (aws.get("enabled", True) and aws and "expected_account_id" not in aws):
            raise ValueError("Hosted AWS requires an expected account ID and uses an assumed role.")
        google = value["providers"].get("google", {})
        if google.get("customer") == "my_customer":
            raise ValueError("Use the explicit Google Workspace customer ID for hosted collection.")
        return value

    def set_integration(self, tenant, actor, provider, settings, value):
        if not isinstance(provider, str) or provider not in {"github", "google", "aws"}:
            raise ValueError("Unknown provider.")
        envelope = self.vault.seal(tenant, provider, value) if value is not None else None
        with self.scoped(tenant, lock=True) as (db, row):
            self._require_role(db, tenant, actor, {"admin"})
            config = strict_json_loads(row["config"])
            config["providers"][provider] = settings
            config = self._hosted_config(config)
            if provider == "aws" and value is not None and value["role_arn"].split(":")[4] != settings.get("expected_account_id"):
                raise ValueError("AWS role and expected account must match.")
            if provider == "aws" and value is not None and value["external_id"] != row["aws_external_id"]:
                raise ValueError("Use this workspace's service-generated external ID.")
            db.execute(update(tenants).where(tenants.c.id == tenant).values(config=_json(config)))
            if envelope:
                db.execute(delete(credentials).where(credentials.c.tenant_id == tenant, credentials.c.provider == provider))
                db.execute(insert(credentials).values(tenant_id=tenant, provider=provider, envelope=envelope, updated_at=int(time.time())))
            self._audit(db, tenant, actor, "integration.changed", {"provider": provider, "config_sha256": digest(config), "credential_updated": envelope is not None})

    def credential_status(self, tenant):
        with self.scoped(tenant) as (db, _):
            return [dict(r) for r in db.execute(select(credentials.c.provider, credentials.c.updated_at).where(credentials.c.tenant_id == tenant)).mappings()]

    def set_credential(self, tenant, actor, provider, value):
        envelope = self.vault.seal(tenant, provider, value) if value is not None else None
        if provider not in {"github", "google", "aws"}:
            raise ValueError("Unknown credential provider.")
        with self.scoped(tenant, lock=True) as (db, row):
            self._require_role(db, tenant, actor, {"admin"})
            if provider == "aws" and value is not None and value["external_id"] != row["aws_external_id"]:
                raise ValueError("Use this workspace's service-generated external ID.")
            db.execute(delete(credentials).where(credentials.c.tenant_id == tenant, credentials.c.provider == provider))
            if envelope:
                db.execute(insert(credentials).values(tenant_id=tenant, provider=provider, envelope=envelope, updated_at=int(time.time())))
            self._audit(db, tenant, actor, "credential.changed", {"provider": provider, "present": envelope is not None})

    def worker_credentials(self, tenant):
        with self.scoped(tenant) as (db, _):
            return {r["provider"]: self.vault.open(tenant, r["provider"], r["envelope"]) for r in db.execute(select(credentials).where(credentials.c.tenant_id == tenant)).mappings()}

    def rotate_credentials(self, tenant):
        with self.scoped(tenant, lock=True) as (db, _):
            rows = list(db.execute(select(credentials).where(credentials.c.tenant_id == tenant)).mappings())
            for row in rows:
                envelope = self.vault.seal(tenant, row["provider"], self.vault.open(tenant, row["provider"], row["envelope"]))
                db.execute(update(credentials).where(credentials.c.tenant_id == tenant, credentials.c.provider == row["provider"]).values(envelope=envelope))
            self.rotate_document_keys(db, tenant)
            self._audit(db, tenant, "operator-cli", "vault.rotated", {"count": len(rows), "documents_rotated": True})
            return len(rows)

    def _notes(self, db, tenant):
        return {r["control_id"]: strict_json_loads(r["document"]) for r in db.execute(select(notes).where(notes.c.tenant_id == tenant)).mappings()}

    def attestations(self, tenant):
        with self.scoped(tenant) as (db, _):
            return self._notes(db, tenant)

    def attest(self, tenant, actor, control_id, owner, note):
        if not isinstance(control_id, str) or control_id not in CATALOG or CATALOG[control_id]["provider"] != "manual":
            raise ValueError("Select a manual control.")
        from .core import now
        document = {"owner": text(owner, maximum=120), "note": text(note, maximum=4000, multiline=True),
                    "recorded_at": now(), "kind": "self-attestation", "independently_verified": False}
        with self.scoped(tenant, lock=True) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator"})
            db.execute(delete(notes).where(notes.c.tenant_id == tenant, notes.c.control_id == control_id))
            db.execute(insert(notes).values(tenant_id=tenant, control_id=control_id, document=_json(document)))
            db.execute(insert(revisions).values(tenant_id=tenant, id=str(uuid.uuid4()), document=_json({"control_id": control_id, **document})))
            self._audit(db, tenant, actor, "attestation.saved", {"control_id": control_id, "sha256": digest(document)})

    def enqueue(self, tenant, actor):
        with self.scoped(tenant, lock=True) as (db, row):
            self._require_role(db, tenant, actor, {"admin", "operator"})
            active = db.execute(select(jobs).where(jobs.c.tenant_id == tenant, jobs.c.status.in_(["queued", "running"]))).mappings().first()
            if active:
                return self._public_job(active)
            now = self._clock(db)
            if self._quota_reached(db, tenant, now):
                raise ValueError("Collection quota reached. Contact the service operator.")
            job = self._insert_job(db, tenant, row, now)
            self._audit(db, tenant, actor, "collection.queued", {"job_id": job["id"], "config_sha256": digest(strict_json_loads(row["config"]))})
            return self._public_job(job)

    @staticmethod
    def _public_job(row):
        return {"id": row["id"], "status": row["status"], "running": row["status"] in {"queued", "running"},
                "error": row.get("error"), "run_id": row.get("run_id"),
                "created_at": row.get("created_at"), "finished_at": row.get("finished_at"), "lease_until": row.get("lease_until")}

    def latest_job(self, tenant):
        with self.scoped(tenant) as (db, _):
            row = db.execute(select(jobs).join(job_heads, and_(job_heads.c.tenant_id == jobs.c.tenant_id, job_heads.c.job_id == jobs.c.id)).where(jobs.c.tenant_id == tenant)).mappings().first()
            return self._public_job(row) if row else {"running": False, "error": None, "status": "idle"}

    @staticmethod
    def _clock(db):
        if db.dialect.name == "postgresql":
            return int(db.execute(sql("SELECT EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)")).scalar_one())
        return int(db.execute(sql("SELECT strftime('%s', 'now')")).scalar_one())

    @staticmethod
    def _quota_reached(db, tenant, now):
        recent = db.execute(select(func.count()).select_from(jobs).where(jobs.c.tenant_id == tenant, jobs.c.created_at > now - 86400)).scalar_one()
        count = db.execute(select(func.count()).select_from(runs).where(runs.c.tenant_id == tenant)).scalar_one()
        return recent >= 48 or count >= 5000

    def _insert_job(self, db, tenant, workspace, now):
        job = dict(tenant_id=tenant, id=str(uuid.uuid4()), status="queued", created_at=now,
                   config=workspace["config"], attestations=_json(self._notes(db, tenant)))
        db.execute(insert(jobs).values(**job))
        db.execute(delete(job_heads).where(job_heads.c.tenant_id == tenant))
        db.execute(insert(job_heads).values(tenant_id=tenant, job_id=job["id"]))
        return job

    @staticmethod
    def _project(db, tenant, snapshot):
        latest = db.execute(select(runs.c.id).where(runs.c.tenant_id == tenant).order_by(runs.c.collected_at.desc(), runs.c.id.desc()).limit(1)).scalar()
        if latest != snapshot["id"]:
            return
        value = monitoring_projection(snapshot)
        db.execute(delete(monitoring).where(monitoring.c.tenant_id == tenant))
        db.execute(insert(monitoring).values(tenant_id=tenant, snapshot_id=snapshot["id"], document=_json(value), sha256=digest(value)))

    def schedule(self, tenant):
        with self.scoped(tenant) as (db, _):
            row = db.execute(select(schedules).where(schedules.c.tenant_id == tenant)).mappings().first()
            if not row:
                return {"enabled": False, "interval_hours": DEFAULT_INTERVAL_HOURS, "freshness_hours": DEFAULT_FRESHNESS_HOURS,
                        "revision": 0, "next_due_at": None, "last_dispatched_at": None, "blocked_reason": None}
            return {key: bool(value) if key == "enabled" else value for key, value in row.items() if key != "tenant_id"}

    def set_schedule(self, tenant, actor, value):
        value = validate_schedule(value)
        with self.scoped(tenant, lock=True) as (db, _):
            self._require_role(db, tenant, actor, {"admin"})
            old = db.execute(select(schedules).where(schedules.c.tenant_id == tenant)).mappings().first()
            if old and all(old[key] == int(item) for key, item in value.items()):
                return
            now = self._clock(db)
            revision = old["revision"] + 1 if old else 1
            # A freshness-only adjustment keeps the dispatch cadence intact.
            due = (old["next_due_at"] if old and old["enabled"] and value["enabled"]
                   and old["interval_hours"] == value["interval_hours"] else now) if value["enabled"] else None
            db.execute(delete(schedules).where(schedules.c.tenant_id == tenant))
            db.execute(insert(schedules).values(tenant_id=tenant, enabled=int(value["enabled"]), interval_hours=value["interval_hours"],
                                                freshness_hours=value["freshness_hours"], revision=revision, next_due_at=due,
                                                updated_at=now, last_dispatched_at=old["last_dispatched_at"] if old else None))
            self._audit(db, tenant, actor, "schedule.changed", {**value, "revision": revision})

    def _notice(self, db, tenant, kind, document, occurrence, now):
        fingerprint = digest({"kind": kind, "occurrence": occurrence})
        old = db.execute(select(notifications).where(notifications.c.tenant_id == tenant, notifications.c.kind == kind)).mappings().first()
        if old and old["fingerprint"] == fingerprint:
            return
        db.execute(delete(notifications).where(notifications.c.tenant_id == tenant, notifications.c.kind == kind))
        db.execute(insert(notifications).values(tenant_id=tenant, kind=kind, id=str(uuid.uuid4()), fingerprint=fingerprint,
                                                document=_json(document), created_at=now, read_at=None,
                                                event_count=old["event_count"] + 1 if old else 1))

    def notification_list(self, tenant):
        with self.scoped(tenant) as (db, _):
            return [{"id": r["id"], "kind": r["kind"], "created_at": r["created_at"], "read_at": r["read_at"],
                     "event_count": r["event_count"], "details": strict_json_loads(r["document"])}
                    for r in db.execute(select(notifications).where(notifications.c.tenant_id == tenant).order_by(notifications.c.created_at.desc(), notifications.c.kind)).mappings()]

    def acknowledge_notification(self, tenant, actor, notice_id):
        tenant_id(notice_id)
        with self.scoped(tenant, lock=True) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator"})
            row = db.execute(select(notifications).where(notifications.c.tenant_id == tenant, notifications.c.id == notice_id)).mappings().first()
            if not row:
                raise LookupError("Notification not found.")
            if row["read_at"] is None:
                db.execute(update(notifications).where(notifications.c.tenant_id == tenant, notifications.c.id == notice_id).values(read_at=self._clock(db)))
                self._audit(db, tenant, actor, "notification.acknowledged", {"notification_id": notice_id})

    def collection_health(self, tenant, config, schedule, job):
        with self.scoped(tenant) as (db, _):
            row = db.execute(select(monitoring).where(monitoring.c.tenant_id == tenant)).mappings().first()
            try:
                projection = strict_json_loads(row["document"]) if row else None
            except ValueError:
                raise EvidenceIntegrityError("Monitoring projection integrity failed.") from None
            if row and digest(projection) != row["sha256"]:
                raise EvidenceIntegrityError("Monitoring projection integrity failed.")
            now = self._clock(db)
        health = evidence_health(projection, config, schedule["freshness_hours"], now, job)
        due = schedule["next_due_at"]
        health["schedule_status"] = ("disabled" if not schedule["enabled"] else "blocked" if schedule["blocked_reason"]
                                     else "overdue" if due is not None and now >= due + SCHEDULE_GRACE_SECONDS
                                     else "due" if due is not None and now >= due else "scheduled")
        health["schedule_lag_seconds"] = max(0, now - due) if due is not None else 0
        health["worker_status"] = ("queue_delayed" if job.get("status") == "queued" and now - job["created_at"] >= SCHEDULE_GRACE_SECONDS
                                   else "lease_expired" if job.get("status") == "running" and job.get("lease_until", now + 1) <= now
                                   else job.get("status", "idle"))
        return health

    def rebuild_monitoring(self, tenant):
        with self.scoped(tenant, lock=True) as (db, _):
            row = db.execute(select(runs).where(runs.c.tenant_id == tenant).order_by(runs.c.collected_at.desc(), runs.c.id.desc()).limit(1)).mappings().first()
            if not row:
                return False
            snapshot = validate_run(strict_json_loads(row["document"]))
            if digest(snapshot) != row["sha256"]:
                raise EvidenceIntegrityError("Stored snapshot integrity failed.")
            self._project(db, tenant, snapshot)
            self._audit(db, tenant, "operator-cli", "monitoring.rebuilt", {"snapshot_id": snapshot["id"]})
            return True

    def dispatch_due(self):
        """One transaction per tenant; multiple schedulers are safe and bounded.

        Old missed slots are coalesced into one latest-due occurrence. Active jobs
        and quotas defer dispatch without losing its due time or creating a storm.
        """
        with self.engine.connect() as db:
            ids = list(db.execute(select(tenants.c.id).order_by(tenants.c.id)).scalars())
        dispatched = 0
        for tenant in ids:
            with self.scoped(tenant, lock=True) as (db, workspace):
                schedule = db.execute(select(schedules).where(schedules.c.tenant_id == tenant)).mappings().first()
                now = self._clock(db)
                if not schedule or not schedule["enabled"] or schedule["next_due_at"] > now:
                    continue
                active = db.execute(select(jobs.c.id).where(jobs.c.tenant_id == tenant, jobs.c.status.in_(["queued", "running"]))).first()
                if active:
                    continue
                if self._quota_reached(db, tenant, now):
                    if schedule["blocked_reason"] != "quota_reached":
                        db.execute(update(schedules).where(schedules.c.tenant_id == tenant).values(blocked_reason="quota_reached"))
                        self._audit(db, tenant, "scheduler", "schedule.blocked", {"code": "quota_reached", "due_at": schedule["next_due_at"]})
                    self._notice(db, tenant, "schedule_blocked", {"code": "quota_reached"}, f'{schedule["revision"]}:{schedule["next_due_at"]}', now)
                    continue
                interval = schedule["interval_hours"] * 3600
                missed = (now - schedule["next_due_at"]) // interval
                due = schedule["next_due_at"] + missed * interval
                job = self._insert_job(db, tenant, workspace, now)
                db.execute(insert(occurrences).values(tenant_id=tenant, revision=schedule["revision"], due_at=due,
                                                       job_id=job["id"], missed_count=missed, dispatched_at=now))
                db.execute(update(schedules).where(schedules.c.tenant_id == tenant).values(next_due_at=due + interval,
                                                                                          last_dispatched_at=now, blocked_reason=None))
                self._audit(db, tenant, "scheduler", "collection.scheduled", {"job_id": job["id"], "due_at": due,
                                                                               "revision": schedule["revision"], "missed_count": missed})
                if missed or now - due >= SCHEDULE_GRACE_SECONDS:
                    self._notice(db, tenant, "missed_collection", {"missed_count": missed, "delay_seconds": now - due, "due_at": due}, job["id"], now)
                dispatched += 1
        return dispatched

    def claim(self):
        # Queue discovery is global; all job contents and updates are scoped.
        with self.engine.connect() as db:
            ids = list(db.execute(select(tenants.c.id).order_by(tenants.c.created_at, tenants.c.id)).scalars())
        secrets.SystemRandom().shuffle(ids)
        for tenant in ids:
            with self.scoped(tenant, lock=True) as (db, _):
                stale = list(db.execute(select(jobs).where(jobs.c.tenant_id == tenant, jobs.c.status == "running", jobs.c.lease_until <= int(time.time()))).mappings())
                for row in stale:
                    db.execute(update(jobs).where(jobs.c.tenant_id == tenant, jobs.c.id == row["id"]).values(status="failed", error="worker_lost", finished_at=int(time.time()), lease_token=None))
                    self._audit(db, tenant, "worker", "collection.failed", {"job_id": row["id"], "code": "worker_lost"})
                    self._notice(db, tenant, "collection_failed", {"job_id": row["id"], "code": "worker_lost"}, "job:" + row["id"], self._clock(db))
                row = db.execute(select(jobs).where(jobs.c.tenant_id == tenant, jobs.c.status == "queued").order_by(jobs.c.created_at).with_for_update(skip_locked=True).limit(1)).mappings().first()
                if row:
                    token = secrets.token_hex(32)
                    db.execute(update(jobs).where(jobs.c.tenant_id == tenant, jobs.c.id == row["id"]).values(status="running", lease_token=token, lease_until=int(time.time()) + 720))
                    self._audit(db, tenant, "worker", "collection.started", {"job_id": row["id"]})
                    return dict(row, lease_token=token, config=strict_json_loads(row["config"]), attestations=strict_json_loads(row["attestations"]))
        return None

    def finish(self, job, snapshot=None, error=None):
        if snapshot is not None:
            validate_run(snapshot, allow_legacy=False)
            if snapshot["demo"] or snapshot["config_fingerprint"] != digest(job["config"]):
                raise ValueError("Worker result does not match its job scope.")
        if error not in {None, "collector_failed", "collector_timeout", "credential_unavailable", "invalid_snapshot", "credential_in_output", "output_limit", "invalid_request"}:
            error = "collector_failed"
        if (snapshot is None) == (error is None):
            raise ValueError("Job completion requires exactly one result.")
        tenant = job["tenant_id"]
        with self.scoped(tenant, lock=True) as (db, _):
            current = db.execute(select(jobs).where(jobs.c.tenant_id == tenant, jobs.c.id == job["id"], jobs.c.status == "running", jobs.c.lease_token == job["lease_token"], jobs.c.lease_until > int(time.time()))).mappings().first()
            if not current:
                raise ValueError("Collection lease expired or was superseded.")
            if snapshot and snapshot["config_fingerprint"] != digest(strict_json_loads(current["config"])):
                raise ValueError("Worker snapshot differs from the persisted job scope.")
            if snapshot:
                db.execute(insert(runs).values(tenant_id=tenant, id=snapshot["id"], collected_at=snapshot["collected_at"], document=_json(snapshot), sha256=digest(snapshot), summary=_json(snapshot["summary"])))
                self._project(db, tenant, snapshot)
            db.execute(update(jobs).where(jobs.c.tenant_id == tenant, jobs.c.id == job["id"]).values(status="failed" if error else "succeeded", error=error, run_id=snapshot["id"] if snapshot else None, finished_at=int(time.time()), lease_token=None))
            self._audit(db, tenant, "worker", "collection.failed" if error else "collection.saved", {"job_id": job["id"], "code": error, "run_id": snapshot["id"] if snapshot else None, "sha256": digest(snapshot) if snapshot else None})
            if error:
                self._notice(db, tenant, "collection_failed", {"job_id": job["id"], "code": error}, "job:" + job["id"], self._clock(db))

    def history(self, tenant):
        with self.scoped(tenant) as (db, _):
            return [{"id": r["id"], "collected_at": r["collected_at"], "demo": False, "summary": strict_json_loads(r["summary"])} for r in db.execute(select(runs.c.id, runs.c.collected_at, runs.c.summary).where(runs.c.tenant_id == tenant).order_by(runs.c.collected_at.desc(), runs.c.id.desc()).limit(20)).mappings()]

    def get_run(self, tenant, run_id=None):
        with self.scoped(tenant) as (db, _):
            query = select(runs).where(runs.c.tenant_id == tenant)
            query = query.where(runs.c.id == run_id) if run_id else query.order_by(runs.c.collected_at.desc(), runs.c.id.desc()).limit(1)
            row = db.execute(query).mappings().first()
            if not row:
                return None
            document = strict_json_loads(row["document"])
            if digest(document) != row["sha256"]:
                raise EvidenceIntegrityError("Stored snapshot integrity failed.")
            return validate_run(document, allow_legacy=False)

    def audit_verify(self, tenant, expected_head=None):
        with self.scoped(tenant) as (db, _):
            previous, count = "0" * 64, 0
            for row in db.execute(select(audit).where(audit.c.tenant_id == tenant).order_by(audit.c.sequence)).mappings():
                event = strict_json_loads(row["event"])
                count += 1
                if row["sequence"] != count or event["sequence"] != count or event["tenant_id"] != tenant or row["previous_hash"] != previous or event["previous_hash"] != previous or digest(event) != row["event_hash"]:
                    raise ValueError("Audit chain integrity failed.")
                previous = row["event_hash"]
            if expected_head and not secrets.compare_digest(expected_head, previous):
                raise ValueError("Audit head does not match the trusted external anchor.")
            return {"tenant_id": tenant, "events": count, "head_sha256": previous, "externally_anchored": expected_head is not None}
