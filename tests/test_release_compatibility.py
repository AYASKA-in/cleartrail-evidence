"""Golden fixtures produced by the independently installed 0.2.0 wheel."""
import base64
import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from cleartrail.catalog import CATALOG
from cleartrail.catalog_registry import get_catalog
from cleartrail.hosted_repository import Repository, schema, SCHEMA_VERSION
from cleartrail.hosted_settings import HostedSettings
from cleartrail.reports import verify_bundle
from cleartrail.validation import digest, validate_run

FIXTURES = Path(__file__).with_name("fixtures")


def test_published_0_2_bundle_still_verifies_and_regenerates_its_views(tmp_path):
    body = base64.b64decode((FIXTURES / "cleartrail_0_2_demo.b64").read_text())
    assert hashlib.sha256(body).hexdigest() == "20201042a69365d1e2eb91e2f3b3f9aaa55a92e6b7f866e570b973905f4f8d1a"
    path = tmp_path / "old.zip"
    path.write_bytes(body)
    assert verify_bundle(path)["rendered_views_verified"]


def test_historical_catalog_does_not_follow_mutations_to_current_runtime_catalog():
    snapshot = json.loads((FIXTURES / "cleartrail_0_2_live.json").read_text())
    with patch.dict(CATALOG, {"FAKE-NEW-CONTROL": {"id": "FAKE-NEW-CONTROL"}}):
        assert validate_run(snapshot) == snapshot
    copied = get_catalog("2026.10.1")
    copied["GH-MFA"]["title"] = "Changed local copy"
    assert get_catalog("2026.10.1")["GH-MFA"]["title"] != copied["GH-MFA"]["title"]
    for version in ("../../config", "future", [], None):
        with pytest.raises(ValueError):
            get_catalog(version)


def legacy_database(tmp_path, *, damaged=False, version=1):
    path = tmp_path / "legacy.db"
    snapshot_text = (FIXTURES / "cleartrail_0_2_live.json").read_text()
    snapshot = json.loads(snapshot_text)
    tenant, job_id = str(uuid.uuid4()), str(uuid.uuid4())
    with sqlite3.connect(path) as db:
        db.executescript((FIXTURES / "hosted_schema_v1.sql").read_text())
        db.execute("INSERT INTO ct_schema(version) VALUES (?)", (version,))
        db.execute("INSERT INTO ct_tenants VALUES (?,?,?,?,?)", (tenant, snapshot["organization"], json.dumps(snapshot["provenance"]["scope"]), "synthetic-external-id".ljust(43,"x"), 1))
        db.execute("INSERT INTO ct_members VALUES (?,?,?,?)", (tenant, "https://identity.example", "owner", "admin"))
        db.execute("INSERT INTO ct_runs VALUES (?,?,?,?,?,?)", (tenant, snapshot["id"], snapshot["collected_at"], snapshot_text, "0" * 64 if damaged else digest(snapshot), json.dumps(snapshot["summary"])))
        db.execute("INSERT INTO ct_jobs(tenant_id,id,status,created_at,finished_at,config,attestations,run_id) VALUES (?,?,?,?,?,?,?,?)",
                   (tenant, job_id, "succeeded", 1, 2, json.dumps(snapshot["provenance"]["scope"]), "{}", snapshot["id"]))
    settings = HostedSettings(database_url="sqlite:///" + path.as_posix(), public_url="http://127.0.0.1",
                              oidc_issuer="https://identity.example", oidc_client_id="test", oidc_client_secret="test-secret",
                              session_secret="synthetic-session-secret-for-migration-12345", vault_keys=(Fernet.generate_key().decode(),), environment="test")
    return Repository(settings), tenant, snapshot, snapshot_text, job_id


def test_v1_migration_preserves_evidence_and_jobs_and_disables_new_schedules(tmp_path):
    repo, tenant, snapshot, original, job_id = legacy_database(tmp_path)
    try:
        with pytest.raises(ValueError):
            repo.ready()
        repo.migrate()
        assert repo.ready()
        assert repo.get_run(tenant) == snapshot
        assert repo.latest_job(tenant)["id"] == job_id
        assert not repo.schedule(tenant)["enabled"] and repo.dispatch_due() == 0
        assert repo.notification_list(tenant) == []
        with repo.engine.connect() as db:
            assert db.exec_driver_sql("SELECT document FROM ct_runs").scalar_one() == original
            assert db.execute(select(schema.c.version)).scalar_one() == SCHEMA_VERSION
        repo.migrate()
        assert repo.get_run(tenant) == snapshot
    finally:
        repo.engine.dispose()


def test_damaged_evidence_blocks_migration_without_advancing_schema(tmp_path):
    repo, tenant, snapshot, original, job_id = legacy_database(tmp_path, damaged=True)
    try:
        with pytest.raises(ValueError, match="integrity"):
            repo.migrate()
        with repo.engine.connect() as db:
            assert db.execute(select(schema.c.version)).scalar_one() == 1
            assert db.exec_driver_sql("SELECT document FROM ct_runs").scalar_one() == original
    finally:
        repo.engine.dispose()


def test_future_schema_is_rejected_before_creating_new_tables(tmp_path):
    repo, tenant, snapshot, original, job_id = legacy_database(tmp_path, version=999)
    try:
        with pytest.raises(ValueError, match="schema"):
            repo.migrate()
        with repo.engine.connect() as db:
            assert not db.exec_driver_sql("SELECT name FROM sqlite_master WHERE name='ct_schedules'").first()
    finally:
        repo.engine.dispose()
