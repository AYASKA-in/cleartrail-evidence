"""Storage durability and evidence-validation boundary regressions."""
import copy
import sqlite3

import pytest

from cleartrail.core import Store, collect_run
from cleartrail.validation import canonical, digest, strict_json_loads, validate_run


def test_workspace_identity_prevents_accidental_cross_customer_reuse(tmp_path):
    store = Store(tmp_path / "scope.db")
    collect_run(store, {"organization": "First customer"})
    with pytest.raises(ValueError):
        collect_run(store, {"organization": "Second customer"})
    with pytest.raises(ValueError):
        collect_run(store, {"organization": "First customer"}, True)


def test_online_backup_restores_history_and_attestation_revisions(tmp_path):
    store = Store(tmp_path / "live.db")
    store.attest("MAN-POLICY", "Owner", "Initial policy review")
    first = collect_run(store, {})
    store.attest("MAN-POLICY", "Owner", "Updated policy review")
    second = collect_run(store, {})
    target = tmp_path / "backup.db"
    store.backup(target)
    restored = Store(target)
    assert restored.get_run(first["id"]) == first
    assert restored.latest() == second
    assert restored.health()["ok"]
    with sqlite3.connect(target) as db:
        assert db.execute("SELECT count(*) FROM attestation_revisions").fetchone()[0] == 2
    with pytest.raises(FileExistsError):
        store.backup(target)


def test_local_collection_lease_is_cross_instance_and_released_after_failure(tmp_path):
    first, second = Store(tmp_path / "lease.db"), Store(tmp_path / "lease.db")
    with pytest.raises(RuntimeError):
        with first.collection("Your organization", False):
            with pytest.raises(ValueError):
                with second.collection("Your organization", False):
                    pytest.fail("Second instance obtained an active collection lease")
            raise RuntimeError("worker interrupted")
    assert collect_run(second, {})["summary"]["passed"] == 0


def test_database_snapshot_edit_is_detected(tmp_path):
    path = tmp_path / "evidence.db"
    store = Store(path)
    snapshot = collect_run(store, {})
    with sqlite3.connect(path) as db:
        modified = dict(snapshot, organization="Other customer")
        db.execute("UPDATE runs SET document=?", (canonical(modified).decode(),))
    with pytest.raises(ValueError, match="integrity"):
        store.latest()


@pytest.mark.parametrize("raw", ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '\ufffd\ud800', '[[[[['])
def test_ambiguous_or_malformed_json_is_rejected(raw):
    with pytest.raises(ValueError):
        strict_json_loads(raw)


@pytest.mark.parametrize("mutation", [
    lambda r: r["summary"].update(passed=14),
    lambda r: r["checks"][0].update(evidence_ids=[]),
    lambda r: r["checks"][0].update(status="fail"),
    lambda r: r.update(config_fingerprint="0" * 64),
    lambda r: r["evidence"][0].update(status=[]),
    lambda r: r["evidence"].append(copy.deepcopy(r["evidence"][0])),
    lambda r: r["evidence"][0].update(provider="aws"),
    lambda r: r["checks"][0].update(title="False claim"),
])
def test_semantically_forged_snapshots_are_rejected(tmp_path, mutation):
    snapshot = collect_run(Store(tmp_path / "demo.db"), {}, True)
    mutation(snapshot)
    with pytest.raises(ValueError):
        validate_run(snapshot)


def test_rehashing_cannot_promote_self_attestation_to_verified(tmp_path):
    store = Store(tmp_path / "notes.db")
    store.attest("MAN-POLICY", "Owner", "Reviewed policy")
    snapshot = collect_run(store, {})
    record = snapshot["evidence"][0]
    original_id = record["id"]
    record["data"]["independently_verified"] = True
    record["sha256"] = digest({k:v for k,v in record.items() if k not in {"id", "sha256"}})
    record["id"] = "ev_" + record["sha256"][:20]
    for check in snapshot["checks"]:
        check["evidence_ids"] = [record["id"] if value == original_id else value for value in check["evidence_ids"]]
    with pytest.raises(ValueError, match="self-attestation"):
        validate_run(snapshot)


def test_direct_html_renderer_escapes_even_malformed_summary_values(tmp_path):
    from cleartrail.reports import report_html
    snapshot = collect_run(Store(tmp_path / "render.db"), {}, True)
    snapshot["summary"]["passed"] = '<script>alert("summary")</script>'
    rendered = report_html(snapshot).decode()
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
