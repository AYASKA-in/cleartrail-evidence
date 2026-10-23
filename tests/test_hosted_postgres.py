"""Real PostgreSQL RLS and concurrent-claim checks. CI supplies a disposable DB.

The database URL must use a dedicated non-superuser role. Never point these
tests at a customer database. Each run creates unique tenants and preserves
the schema for inspection; CI destroys the entire database after the job.
"""
import os
import secrets
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select, insert, text, update
from sqlalchemy.exc import DBAPIError

from cleartrail.core import build_run
from cleartrail.hosted_repository import (Repository, credentials, occurrences, notifications, schedules,
                                         monitoring, job_heads, schema, documents, document_versions, document_reviews)
from cleartrail.documents import DocumentConflict
from test_documents import payload
from cleartrail.hosted_settings import HostedSettings

URL = os.environ.get("CLEARTRAIL_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not URL, reason="Disposable PostgreSQL not configured")


@pytest.fixture
def pg():
    settings = HostedSettings(database_url=URL, public_url="https://cleartrail.example",
                              oidc_issuer="https://identity.example", oidc_client_id="test",
                              oidc_client_secret=secrets.token_urlsafe(32), session_secret=secrets.token_urlsafe(48),
                              vault_keys=(Fernet.generate_key().decode(),))
    repo = Repository(settings)
    repo.migrate()
    repo.ready()
    a = repo.create_tenant("RLS A " + secrets.token_hex(4), settings.oidc_issuer, "alice")
    b = repo.create_tenant("RLS B " + secrets.token_hex(4), settings.oidc_issuer, "bob")
    yield repo, a, b
    repo.engine.dispose()


def test_rls_fails_closed_without_context_and_rejects_other_tenant_writes(pg):
    repo, a, b = pg
    repo.set_credential(a, "alice", "github", {"token": secrets.token_urlsafe(32)})
    repo.set_credential(b, "bob", "github", {"token": secrets.token_urlsafe(32)})
    with repo.engine.connect() as db:
        assert list(db.execute(select(credentials))) == []
    with repo.scoped(a) as (db, _):
        # Deliberately omit the WHERE predicate: RLS must retain the boundary.
        visible = list(db.execute(select(credentials)).mappings())
        assert len(visible) == 1 and visible[0]["tenant_id"] == a
    with pytest.raises(DBAPIError):
        with repo.scoped(a) as (db, _):
            db.execute(insert(credentials).values(tenant_id=b, provider="google", envelope="forged", updated_at=0))
    with repo.engine.connect() as db:
        assert list(db.execute(select(credentials))) == []  # pooled context was reset


def test_parallel_workers_cannot_claim_or_finish_a_job_twice(pg):
    repo, a, b = pg
    queued = repo.enqueue(a, "alice")
    with ThreadPoolExecutor(max_workers=4) as pool:
        claimed = [value for value in pool.map(lambda _: repo.claim(), range(4)) if value and value["tenant_id"] == a]
    assert len(claimed) == 1 and claimed[0]["id"] == queued["id"]
    job = claimed[0]
    snapshot = build_run(job["config"], [], {})
    repo.finish(job, snapshot)
    with pytest.raises(ValueError):
        repo.finish(job, snapshot)
    assert repo.get_run(b, snapshot["id"]) is None


def test_runtime_rejects_superuser_or_missing_rls(pg):
    repo, a, b = pg
    assert repo.ready()
    with repo.engine.connect() as db:
        assert db.execute(text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user")).scalar_one() is False


def test_concurrent_schedulers_create_one_tenant_scoped_occurrence(pg):
    repo, a, b = pg
    repo.set_schedule(a, "alice", {"enabled": True, "interval_hours": 24, "freshness_hours": 25})
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(lambda _: repo.dispatch_due(), range(4))) == 1
    with repo.scoped(a) as (db, _):
        assert len(list(db.execute(select(occurrences)))) == 1
        assert len(list(db.execute(select(schedules)))) == 1
    with repo.scoped(b) as (db, _):
        assert list(db.execute(select(occurrences))) == []
        assert list(db.execute(select(schedules))) == []
        assert list(db.execute(select(notifications))) == []
    with repo.engine.connect() as db:
        assert list(db.execute(select(schedules))) == []
    # Drain this test's queued job so subsequent shared-database fixtures cannot
    # accidentally claim it when verifying another tenant's worker behavior.
    job = repo.claim()
    assert job["tenant_id"] == a
    repo.finish(job, error="collector_failed")


def test_v1_upgrade_preserves_postgres_evidence_and_restores_rls(pg):
    repo, a, b = pg
    repo.enqueue(a, "alice")
    job = repo.claim()
    assert job["tenant_id"] == a
    snapshot = build_run(job["config"], [], {})
    repo.finish(job, snapshot)
    # Only the explicitly disposable test database is used. Remove the additive
    # v2 tables to reproduce the real v1 shape, preserving all v1 business data.
    with repo.engine.begin() as db:
        for table in (document_reviews, document_versions, documents, job_heads, monitoring, notifications, occurrences, schedules):
            table.drop(db)
        db.execute(update(schema).values(version=1))
    with pytest.raises(ValueError):
        repo.ready()
    repo.migrate()
    assert repo.ready() and repo.get_run(a) == snapshot
    assert repo.latest_job(a)["id"] == job["id"]
    assert repo.schedule(a)["enabled"] is False
    with repo.scoped(b) as (db, _):
        assert list(db.execute(select(monitoring).where(monitoring.c.tenant_id == a))) == []


def test_document_rls_versions_and_concurrent_reviews(pg):
    repo, a, b = pg
    repo.set_member(a, "alice", "reviewer", "operator")
    first = repo.upload_document(a, "alice", payload())
    repo.review_document(a, "reviewer", first["version_id"], "approved", "Reviewed bytes", None)
    with repo.engine.connect() as db:
        for table in (documents, document_versions, document_reviews):
            assert list(db.execute(select(table))) == []
    with repo.scoped(b) as (db, _):
        for table in (documents, document_versions, document_reviews):
            assert list(db.execute(select(table))) == []
    with repo.scoped(a) as (db, _):
        for table in (documents, document_versions, document_reviews):
            assert {row["tenant_id"] for row in db.execute(select(table)).mappings()} == {a}
    with pytest.raises(DBAPIError):
        with repo.scoped(a) as (db, _):
            db.execute(insert(documents).values(tenant_id=b, id=secrets.token_hex(16), title="Forged",
                                               control_ids='["MAN-ACCESS"]', owner="bob", revision=1, created_at=0))
    value = payload(document_id=first["document_id"], expected_version_id=first["version_id"], expected_revision=1)
    def replace_once(_):
        try:
            return repo.upload_document(a, "alice", value)
        except DocumentConflict:
            return None
    with ThreadPoolExecutor(max_workers=4) as pool:
        uploaded = [item for item in pool.map(replace_once, range(4)) if item]
    assert len(uploaded) == 1
    version = uploaded[0]["version_id"]
    def review_once(_):
        try:
            return repo.review_document(a, "reviewer", version, "approved", "Reviewed exact version", None)
        except DocumentConflict:
            return None
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert len([item for item in pool.map(review_once, range(4)) if item]) == 1
    assert repo.document_detail(a, "alice", first["document_id"])["versions"][0]["status"] == "approved"
    assert repo.audit_verify(a)["events"] >= 6
