"""Recurring dispatch, stale evidence and tenant-isolated operational notices."""
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from sqlalchemy import func, select, update

from cleartrail.core import build_run
from cleartrail.hosted_repository import Repository, occurrences, monitoring
from cleartrail.monitoring import evidence_health, monitoring_projection, validate_schedule
from cleartrail.validation import validate_config
from test_hosted import setup as setup, login, finish_run

POLICY = {"enabled": True, "interval_hours": 24, "freshness_hours": 25}


def test_schedules_default_disabled_and_require_admin(setup):
    settings, repo, a, b, client, app = setup
    assert repo.schedule(a)["enabled"] is False and repo.dispatch_due() == 0
    repo.set_member(a, "alice", "operator", "operator")
    repo.set_member(a, "alice", "auditor", "auditor")
    for subject in ("operator", "auditor"):
        headers = login(setup, subject)
        assert client.post("/api/schedule", json=POLICY, headers=headers).status_code == 403
    headers = login(setup)
    assert client.post("/api/schedule", json=POLICY, headers={**headers, "X-ClearTrail-Workspace": b}).status_code == 409
    assert client.post("/api/schedule", json=POLICY, headers=headers).status_code == 200
    assert repo.schedule(a)["enabled"] and not repo.schedule(b)["enabled"]


@pytest.mark.parametrize("policy", [None, {}, {**POLICY, "enabled": "true"}, {**POLICY, "interval_hours": True},
                                       {**POLICY, "interval_hours": 2}, {**POLICY, "freshness_hours": 23},
                                       {**POLICY, "freshness_hours": 721}, {**POLICY, "tenant_id": "forged"}])
def test_policy_input_is_strict(policy):
    with pytest.raises(ValueError):
        validate_schedule(policy)


def test_duplicate_schedulers_enqueue_once_and_capture_current_notes(setup):
    settings, repo, a, b, client, app = setup
    repo.attest(a, "alice", "MAN-POLICY", "Owner", "Original note")
    repo.set_schedule(a, "alice", POLICY)
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(lambda _: repo.dispatch_due(), range(4))) == 1
    assert repo.dispatch_due() == 0
    repo.attest(a, "alice", "MAN-POLICY", "Owner", "Later note")
    claimed = repo.claim()
    assert claimed["tenant_id"] == a and claimed["attestations"]["MAN-POLICY"]["note"] == "Original note"
    assert repo.latest_job(b)["status"] == "idle"
    with repo.scoped(a) as (db, _):
        assert db.execute(select(func.count()).select_from(occurrences).where(occurrences.c.tenant_id == a)).scalar_one() == 1
    # New repository/process instance preserves due time and occurrence identity.
    reopened = Repository(settings)
    try:
        assert reopened.dispatch_due() == 0
    finally:
        reopened.engine.dispose()


def test_downtime_coalesces_missed_occurrences_without_a_catchup_storm(setup):
    repo, a = setup[1:3]
    repo.set_schedule(a, "alice", POLICY)
    first_due = repo.schedule(a)["next_due_at"]
    recovered_at = first_due + 3 * 86400 + 900
    with patch.object(repo, "_clock", return_value=recovered_at):
        assert repo.dispatch_due() == 1 and repo.dispatch_due() == 0
    with repo.scoped(a) as (db, _):
        occurrence = db.execute(select(occurrences).where(occurrences.c.tenant_id == a)).mappings().one()
        assert occurrence["missed_count"] == 3
    notice = repo.notification_list(a)[0]
    assert notice["kind"] == "missed_collection" and notice["details"]["missed_count"] == 3
    assert repo.schedule(a)["next_due_at"] == first_due + 4 * 86400


def test_active_manual_job_defers_scheduling_without_advancing_due_time(setup):
    repo, a = setup[1:3]
    repo.set_schedule(a, "alice", POLICY)
    due = repo.schedule(a)["next_due_at"]
    manual = repo.enqueue(a, "alice")
    assert repo.dispatch_due() == 0 and repo.schedule(a)["next_due_at"] == due
    job = repo.claim()
    assert job["id"] == manual["id"]
    repo.finish(job, build_run(job["config"], [], {}))
    assert repo.dispatch_due() == 1
    assert repo.latest_job(a)["id"] != manual["id"]


def test_quota_blocks_without_notification_or_audit_storm_then_recovers(setup):
    repo, a = setup[1:3]
    repo.set_schedule(a, "alice", POLICY)
    with patch.object(repo, "_quota_reached", return_value=True):
        assert repo.dispatch_due() == 0
        head = repo.audit_verify(a)
        assert repo.dispatch_due() == 0 and repo.audit_verify(a) == head
    assert repo.schedule(a)["blocked_reason"] == "quota_reached"
    assert len(repo.notification_list(a)) == 1
    assert repo.dispatch_due() == 1 and repo.schedule(a)["blocked_reason"] is None


def test_schedule_idempotence_and_disabling_do_not_cancel_queued_work(setup):
    repo, a = setup[1:3]
    repo.set_schedule(a, "alice", POLICY)
    original = repo.schedule(a)
    repo.set_schedule(a, "alice", POLICY)
    assert repo.schedule(a) == original
    assert repo.dispatch_due() == 1
    queued = repo.latest_job(a)["id"]
    repo.set_schedule(a, "alice", {**POLICY, "enabled": False})
    assert repo.schedule(a)["next_due_at"] is None and repo.dispatch_due() == 0
    assert repo.claim()["id"] == queued


def test_notifications_are_tenant_scoped_and_stale_ack_cannot_hide_new_failure(setup):
    settings, repo, a, b, client, app = setup
    repo.enqueue(a, "alice")
    repo.finish(repo.claim(), error="collector_timeout")
    first = repo.notification_list(a)[0]
    assert repo.notification_list(b) == []
    headers = login(setup, "bob")
    assert client.post("/api/notifications/acknowledge", json={"id": first["id"]}, headers=headers).status_code == 404
    repo.enqueue(a, "alice")
    repo.finish(repo.claim(), error="collector_failed")
    latest = repo.notification_list(a)[0]
    assert latest["id"] != first["id"] and latest["event_count"] == 2 and latest["read_at"] is None
    headers = login(setup)
    assert client.post("/api/notifications/acknowledge", json={"id": first["id"]}, headers=headers).status_code == 404
    assert client.post("/api/notifications/acknowledge", json={"id": latest["id"]}, headers=headers).status_code == 200
    head = repo.audit_verify(a)
    assert client.post("/api/notifications/acknowledge", json={"id": latest["id"]}, headers=headers).status_code == 200
    assert repo.audit_verify(a) == head


def test_health_changes_with_clock_without_loading_or_modifying_full_snapshot(setup):
    settings, repo, a, b, client, app = setup
    repo.set_config(a, "alice", {"organization": "Customer A", "providers": {"github": {"org": "example"}}})
    repo.enqueue(a, "alice")
    job = repo.claim()
    # No source records: recent data cannot claim complete evidence.
    snapshot = build_run(job["config"], [], {})
    repo.finish(job, snapshot)
    login(setup)
    with patch.object(repo, "get_run", side_effect=AssertionError("full snapshot read during polling")):
        response = client.get("/api/state?since=" + snapshot["id"])
        assert response.status_code == 200 and response.json()["collection_health"]["status"] == "incomplete"
        with patch.object(repo, "_clock", return_value=int(time.time()) + 26 * 3600):
            state = client.get("/api/state?since=" + snapshot["id"]).json()
            assert state["collection_health"]["status"] == "stale"
    assert repo.get_run(a) == snapshot
    repo.set_config(a, "alice", {"organization": "Customer A", "providers": {"github": {"org": "changed"}}})
    assert client.get("/api/state").json()["collection_health"]["status"] == "scope_changed"


def test_latest_failed_job_is_visible_even_when_jobs_share_a_timestamp(setup):
    repo, a = setup[1:3]
    finish_run(repo, a, "alice")
    failed = repo.enqueue(a, "alice")
    repo.finish(repo.claim(), error="collector_failed")
    assert repo.latest_job(a)["id"] == failed["id"] and repo.latest_job(a)["status"] == "failed"
    newer = repo.enqueue(a, "alice")
    assert repo.latest_job(a)["id"] == newer["id"] and repo.latest_job(a)["status"] == "queued"


def test_overdue_dispatch_and_worker_backlog_are_visible(setup):
    repo, a = setup[1:3]
    repo.set_schedule(a, "alice", POLICY)
    now = repo.schedule(a)["next_due_at"] + 601
    with patch.object(repo, "_clock", return_value=now):
        health = repo.collection_health(a, repo.config(a), repo.schedule(a), repo.latest_job(a))
        assert health["schedule_status"] == "overdue"
    repo.dispatch_due()
    with patch.object(repo, "_clock", return_value=now):
        health = repo.collection_health(a, repo.config(a), repo.schedule(a), repo.latest_job(a))
        assert health["worker_status"] == "queue_delayed"


def test_manual_passed_snapshot_does_not_claim_current_evidence_after_failed_collection():
    config = validate_config({"providers": {"github": {"org": "example"}}})
    # A complete source fixture proves known failing settings can still be recent.
    from cleartrail.core import demo_observations
    run = build_run(config, demo_observations(), {}, demo=True)
    before = evidence_health(monitoring_projection(run), config, 25, time.time(), {"status": "succeeded"})
    assert before["status"] == "current"
    after = evidence_health(monitoring_projection(run), config, 25, time.time(), {"status": "failed"})
    assert after["status"] == "collection_failed"
    assert any(c["status"] == "fail" for c in run["checks"])
    with patch("cleartrail.monitoring.CURRENT_CATALOG_VERSION", "future"):
        assert evidence_health(monitoring_projection(run), config, 25, time.time(), {})["status"] == "catalog_changed"


def test_freshness_change_preserves_next_due_time(setup):
    repo, a = setup[1:3]
    repo.set_schedule(a, "alice", POLICY)
    repo.dispatch_due()
    due = repo.schedule(a)["next_due_at"]
    repo.set_schedule(a, "alice", {**POLICY, "freshness_hours": 48})
    assert repo.schedule(a)["next_due_at"] == due


def test_newer_health_cannot_label_an_older_snapshot_current_during_poll_race(setup):
    repo, a, client = setup[1], setup[2], setup[4]
    old = finish_run(repo, a, "alice")
    finish_run(repo, a, "alice")
    login(setup)
    with patch.object(repo, "get_run", return_value=old):
        response = client.get("/api/state")
    assert response.status_code == 200
    assert response.json()["collection_health"]["status"] == "updating"


def test_auditor_cannot_acknowledge_shared_notices(setup):
    repo, a, client = setup[1], setup[2], setup[4]
    repo.set_member(a, "alice", "reviewer", "auditor")
    repo.enqueue(a, "alice")
    repo.finish(repo.claim(), error="collector_failed")
    notice = repo.notification_list(a)[0]
    headers = login(setup, "reviewer")
    assert client.post("/api/notifications/acknowledge", json={"id":notice["id"]}, headers=headers).status_code == 403
    assert repo.notification_list(a)[0]["read_at"] is None


def test_corrupted_monitoring_cache_fails_closed_and_can_be_rebuilt(setup):
    repo, a, client = setup[1], setup[2], setup[4]
    snapshot = finish_run(repo, a, "alice")
    login(setup)
    with repo.scoped(a) as (db, _):
        db.execute(update(monitoring).where(monitoring.c.tenant_id == a).values(sha256="0"*64))
    response = client.get("/api/state?since=" + snapshot["id"])
    assert response.status_code == 503 and response.json()["code"] == "evidence_integrity_failed"
    assert repo.rebuild_monitoring(a)
    assert client.get("/api/state").status_code == 200
    assert repo.get_run(a) == snapshot
