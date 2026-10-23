"""Evidence lifecycle authorization, integrity, concurrency and resource limits."""
import base64
import time
from dataclasses import replace
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select, update

from cleartrail.documents import MAX_FILE_BYTES, MAX_UPLOAD_BODY
from cleartrail.hosted_repository import Repository, documents, document_versions, document_reviews, schema
from test_hosted import setup as setup, login


def payload(**overrides):
    return {"document_id": None, "title": "Access review", "control_ids": ["MAN-ACCESS"],
            "owner": "alice", "filename": "access-review.txt",
            "content_base64": base64.b64encode(b"Customer evidence: all access reviewed.\n").decode(),
            "expires_at": None, "expected_version_id": None, "expected_revision": None, **overrides}


def upload(setup, **overrides):
    result = setup[4].post("/api/documents/upload", json=payload(**overrides), headers=login(setup))
    assert result.status_code == 200, result.text
    return result.json()


def add_reviewers(setup):
    repo, a = setup[1:3]
    repo.set_member(a, "alice", "reviewer", "operator")
    repo.set_member(a, "alice", "auditor", "auditor")


def review(setup, version_id, *, decision="approved", expected=None, subject="reviewer"):
    return setup[4].post("/api/documents/review", json={"version_id": version_id, "decision": decision,
                         "comment": "Reviewed exact version against access register.", "expected_review_id": expected}, headers=login(setup, subject))


def test_immutable_versions_independent_reviews_and_auditor_visibility(setup):
    add_reviewers(setup)
    client = setup[4]
    first = upload(setup)
    assert review(setup, first["version_id"], subject="alice").status_code == 403
    login(setup, "auditor")
    assert client.get("/api/documents").json()["documents"] == []
    assert client.get("/api/documents/versions/" + first["version_id"] + "/download").status_code == 404
    approved = review(setup, first["version_id"])
    assert approved.status_code == 200
    login(setup, "auditor")
    assert len(client.get("/api/documents").json()["documents"]) == 1
    downloaded = client.get("/api/documents/versions/" + first["version_id"] + "/download")
    assert downloaded.content == base64.b64decode(payload()["content_base64"])
    assert downloaded.headers["content-type"].startswith("text/plain")
    assert downloaded.headers["content-disposition"] == 'attachment; filename="access-review.txt"'
    assert downloaded.headers["x-content-type-options"] == "nosniff"
    second = upload(setup, document_id=first["document_id"], expected_version_id=first["version_id"], expected_revision=1,
                    content_base64=base64.b64encode(b"Revised review, not approved yet.").decode())
    login(setup, "auditor")
    assert client.get("/api/documents").json()["documents"] == []
    detail = client.get("/api/documents/" + first["document_id"]).json()
    assert len(detail["versions"]) == 1 and detail["versions"][0]["id"] == first["version_id"]
    assert client.get("/api/documents/versions/" + second["version_id"] + "/download").status_code == 404
    assert review(setup, first["version_id"], expected=approved.json()["id"]).status_code == 409
    assert review(setup, second["version_id"]).status_code == 200
    login(setup)
    detail = client.get("/api/documents/" + first["document_id"]).json()
    assert len(detail["versions"]) == 2 and detail["versions"][1]["reviews"][0]["id"] == approved.json()["id"]
    assert setup[1].audit_verify(setup[2])["events"] >= 7


def test_cross_tenant_ids_and_auditor_writes_are_denied(setup):
    first = upload(setup)
    client = setup[4]
    headers = login(setup, "bob")
    assert client.get("/api/documents/" + first["document_id"]).status_code == 404
    assert client.get("/api/documents/versions/" + first["version_id"] + "/download").status_code == 404
    assert client.get("/api/documents").json()["documents"] == []
    assert client.post("/api/documents/assign", json={"document_id": first["document_id"], "owner": "bob", "expected_revision": 1}, headers=headers).status_code == 404
    assert review(setup, first["version_id"], subject="bob").status_code == 404
    assert client.post("/api/documents/upload", json=payload(document_id=first["document_id"], owner="bob"), headers=login(setup, "bob")).status_code == 404
    add_reviewers(setup)
    headers = login(setup, "auditor")
    assert client.post("/api/documents/upload", json=payload(), headers=headers).status_code == 403
    assert review(setup, first["version_id"], subject="auditor").status_code == 403
    assert client.get("/api/documents/owners").status_code == 403


@pytest.mark.parametrize("changes", [
    {"filename": "../secret.txt"}, {"filename": 'quote".txt'}, {"filename": "active.html"},
    {"filename": "payload.pdf"}, {"filename": "macro.docm"}, {"filename": "bad\r\n.txt"},
    {"content_base64": "%%%"}, {"content_base64": ""}, {"content_base64": "AP8="},
    {"content_base64": base64.b64encode(b"hidden\x00binary").decode()},
    {"content_base64": base64.b64encode("hidden\u202eevil".encode()).decode()},
    {"title": "bad\u202espoof"}, {"control_ids": []}, {"control_ids": ["NOT-A-CONTROL"]},
    {"control_ids": ["MAN-ACCESS", "MAN-ACCESS"]}, {"control_ids": [[]]},
    {"expires_at": True}, {"expires_at": 1}, {"owner": "foreign-person"},
    {"expected_revision": True}, {"unexpected": "field"},
])
def test_invalid_uploads_do_not_publish_partial_items(setup, changes):
    headers = login(setup)
    assert setup[4].post("/api/documents/upload", json=payload(**changes), headers=headers).status_code in {400, 403, 409}
    assert setup[1].document_list(setup[2], "alice")["documents"] == []


def test_upload_body_budget_and_authentication_before_large_allocation(setup):
    client = setup[4]
    assert client.post("/api/documents/upload", content=b"x" * (MAX_UPLOAD_BODY + 1), headers={"Origin": setup[0].public_url}).status_code == 401
    headers = login(setup)
    assert client.post("/api/documents/upload", content=b"x" * (MAX_UPLOAD_BODY + 1), headers=headers).status_code == 413
    assert client.post("/api/scan", content=b"x" * 131073, headers=headers).status_code == 413
    content = base64.b64encode(b"x" * MAX_FILE_BYTES).decode()
    assert client.post("/api/documents/upload", json=payload(content_base64=content), headers=headers).status_code == 200
    assert client.post("/api/documents/upload", json=payload(content_base64=content + "AAAA"), headers=headers).status_code == 400
    assert client.post("/api/documents/upload", json=payload(), headers={**headers, "X-ClearTrail-Workspace": setup[3]}).status_code == 409
    assert client.post("/api/documents/upload", json=payload(), headers={**headers, "X-ClearTrail-Token": "bad"}).status_code == 403


def test_ownership_changes_and_stale_forms_cannot_bypass_review(setup):
    add_reviewers(setup)
    result = upload(setup)
    client = setup[4]
    headers = login(setup)
    value = {"document_id": result["document_id"], "owner": "reviewer", "expected_revision": 1}
    assert client.post("/api/documents/assign", json=value, headers=headers).status_code == 200
    assert client.post("/api/documents/assign", json=value, headers=headers).status_code == 409
    assert review(setup, result["version_id"]).status_code == 403
    assert review(setup, result["version_id"], subject="alice").status_code == 403
    assert client.post("/api/documents/upload", json=payload(document_id=result["document_id"], expected_version_id=result["version_id"], expected_revision=1), headers=login(setup)).status_code == 409


def test_append_only_decisions_withdrawal_expiry_and_stale_review(setup):
    add_reviewers(setup)
    result = upload(setup, expires_at=int(time.time()) + 3600)
    first = review(setup, result["version_id"])
    assert first.status_code == 200
    assert review(setup, result["version_id"], decision="withdrawn").status_code == 409
    second = review(setup, result["version_id"], decision="withdrawn", expected=first.json()["id"])
    assert second.status_code == 200
    login(setup, "auditor")
    assert setup[4].get("/api/documents").json()["documents"] == []
    with patch.object(Repository, "_clock", return_value=int(time.time()) + 7200):
        assert review(setup, result["version_id"], expected=second.json()["id"]).status_code == 400
        login(setup)
        assert setup[4].get("/api/documents").json()["documents"][0]["latest_version"]["status"] == "expired"
    with setup[1].scoped(setup[2]) as (db, _):
        assert len(list(db.execute(select(document_reviews)))) == 2


def test_content_encryption_metadata_binding_tampering_and_rotation(setup):
    add_reviewers(setup)
    first, second = upload(setup), upload(setup, title="Other review")
    settings, repo, a = setup[:3]
    with repo.scoped(a) as (db, _):
        row = db.execute(select(document_versions).where(document_versions.c.id == first["version_id"])).mappings().one()
        old_envelope = row["envelope"]
        assert "Customer evidence" not in old_envelope
        # Swapping authenticated ciphertext between valid rows must fail.
        db.execute(update(document_versions).where(document_versions.c.id == second["version_id"]).values(envelope=old_envelope))
    login(setup)
    assert setup[4].get("/api/documents/versions/" + second["version_id"] + "/download").status_code == 503
    assert review(setup, second["version_id"]).status_code == 503
    new_key = Fernet.generate_key().decode()
    rotating = Repository(replace(settings, vault_keys=(new_key, *settings.vault_keys)))
    try:
        # A damaged row blocks the entire transaction rather than partial rotation.
        with pytest.raises(ValueError):
            rotating.rotate_credentials(a)
        with repo.scoped(a) as (db, _):
            assert db.execute(select(document_versions.c.envelope).where(document_versions.c.id == first["version_id"])).scalar_one() == old_envelope
        with repo.scoped(a) as (db, _):
            db.execute(update(document_versions).where(document_versions.c.id == second["version_id"]).values(envelope="broken"))
        # Repair from the known synthetic fixture using the unchanged original context.
        from cleartrail.documents import seal_file
        with repo.scoped(a) as (db, _):
            original = db.execute(select(document_versions).where(document_versions.c.id == second["version_id"])).mappings().one()
            db.execute(update(document_versions).where(document_versions.c.id == second["version_id"]).values(envelope=seal_file(repo.vault.cipher, original, base64.b64decode(payload()["content_base64"]))))
        rotating.rotate_credentials(a)
        new_only = Repository(replace(settings, vault_keys=(new_key,)))
        try:
            assert new_only.download_document(a, "alice", first["version_id"])[1] == base64.b64decode(payload()["content_base64"])
        finally:
            new_only.engine.dispose()
    finally:
        rotating.engine.dispose()


def test_quotas_and_revocation_recheck_inside_repository(setup):
    add_reviewers(setup)
    with patch("cleartrail.document_repository.MAX_DOCUMENTS", 1):
        first = upload(setup)
        assert setup[4].post("/api/documents/upload", json=payload(), headers=login(setup)).status_code == 400
    with patch("cleartrail.document_repository.MAX_WORKSPACE_BYTES", 1):
        assert setup[4].post("/api/documents/upload", json=payload(), headers=login(setup)).status_code == 400
    with patch("cleartrail.document_repository.MAX_VERSIONS", 1):
        assert setup[4].post("/api/documents/upload", json=payload(document_id=first["document_id"], expected_version_id=first["version_id"], expected_revision=1), headers=login(setup)).status_code == 400
    setup[1].set_member(setup[2], "alice", "reviewer", None)
    with pytest.raises(PermissionError):
        setup[1].review_document(setup[2], "reviewer", first["version_id"], "approved", "Reviewed", None)


def test_schema_two_upgrade_is_additive_and_idempotent(setup):
    repo = setup[1]
    with repo.engine.begin() as db:
        for table in (document_reviews, document_versions, documents):
            table.drop(db)
        db.execute(update(schema).values(version=2))
    with pytest.raises(ValueError):
        repo.ready()
    repo.migrate()
    assert repo.ready() and repo.document_list(setup[2], "alice")["documents"] == []
    repo.migrate()
    upload(setup)


def test_final_review_slot_cannot_lock_in_an_approval(setup):
    add_reviewers(setup)
    result = upload(setup)
    with patch("cleartrail.document_repository.MAX_REVIEWS", 2):
        first = review(setup, result["version_id"])
        assert first.status_code == 200
        assert review(setup, result["version_id"], expected=first.json()["id"]).status_code == 400
        assert review(setup, result["version_id"], decision="withdrawn", expected=first.json()["id"]).status_code == 200
    login(setup, "auditor")
    assert setup[4].get("/api/documents").json()["documents"] == []


@pytest.mark.parametrize("field,value", [("filename", "changed.txt"), ("size", 1), ("sha256", "0" * 64),
                                         ("expires_at", 1999999999), ("owner_at_upload", "forged-owner")])
def test_immutable_metadata_is_authenticated_not_just_the_content_hash(setup, field, value):
    add_reviewers(setup)
    result = upload(setup)
    with setup[1].scoped(setup[2]) as (db, _):
        db.execute(update(document_versions).where(document_versions.c.id == result["version_id"]).values(**{field: value}))
    assert setup[4].get("/api/documents/versions/" + result["version_id"] + "/download").status_code == 503
    assert review(setup, result["version_id"]).status_code == 503


def test_multiline_review_rationale_is_preserved(setup):
    add_reviewers(setup)
    result = upload(setup)
    rationale = "Population matched.\nNo unexplained entitlements."
    saved = setup[1].review_document(setup[2], "reviewer", result["version_id"], "approved", rationale, None)
    assert saved["comment"] == rationale


def test_owner_can_withdraw_historical_approval_after_reviewer_leaves(setup):
    add_reviewers(setup)
    first = upload(setup)
    approved = review(setup, first["version_id"]).json()
    upload(setup, document_id=first["document_id"], expected_version_id=first["version_id"], expected_revision=1)
    setup[1].set_member(setup[2], "alice", "reviewer", None)
    assert review(setup, first["version_id"], decision="withdrawn", expected=approved["id"], subject="alice").status_code == 200
    login(setup, "auditor")
    assert setup[4].get("/api/documents/versions/" + first["version_id"] + "/download").status_code == 404
    login(setup)
    history = setup[4].get("/api/documents/" + first["document_id"]).json()["versions"][1]["reviews"]
    assert [item["decision"] for item in history] == ["approved", "withdrawn"]


def test_withdrawal_can_revoke_sharing_even_when_file_is_corrupt(setup):
    add_reviewers(setup)
    result = upload(setup)
    approved = review(setup, result["version_id"]).json()
    with setup[1].scoped(setup[2]) as (db, _):
        db.execute(update(document_versions).where(document_versions.c.id == result["version_id"]).values(envelope="damaged"))
    assert review(setup, result["version_id"], decision="withdrawn", expected=approved["id"], subject="alice").status_code == 200
    login(setup, "auditor")
    assert setup[4].get("/api/documents/versions/" + result["version_id"] + "/download").status_code == 404
