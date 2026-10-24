"""Private recovery and list navigation must preserve authorization and identity."""
import copy

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select, update

from cleartrail.documents import DocumentConflict
from cleartrail.errors import EvidenceIntegrityError
from cleartrail.hosted_repository import drafts, member_profiles, schema
from cleartrail.vault import Vault
from cleartrail.workspace_ux import page_query, DRAFT_TTL
from test_hosted import setup as setup, login
from test_governance import payload
from test_documents import payload as file_payload


def test_private_draft_is_encrypted_actor_scoped_and_workspace_scoped(setup):
    settings, repo, a, b, client, _ = setup
    repo.set_member(a, "alice", "reviewer", "operator")
    saved = repo.save_draft(a, "alice", "governance:new", {"title": "Sensitive unfinished risk"}, None)
    assert saved["draft"]["revision"]
    assert repo.draft(a, "reviewer", "governance:new")["draft"] is None
    assert repo.draft(b, "bob", "governance:new")["draft"] is None
    with repo.scoped(a) as (db, _):
        raw = db.execute(select(drafts)).mappings().one()
        assert "Sensitive" not in raw["envelope"]
    repo.revoke_session(repo.create_session(settings.oidc_issuer, "alice")["token"])
    login(setup)
    assert client.get("/api/drafts?key=governance:new").json()["draft"]["fields"]["title"] == "Sensitive unfinished risk"


def test_draft_cas_expiry_deletion_and_role_changes(setup, monkeypatch):
    _, repo, a, _, _, _ = setup
    repo.set_member(a, "alice", "operator", "operator")
    first = repo.save_draft(a, "operator", "governance:new", {"title": "Draft A"}, None)["draft"]
    with pytest.raises(DocumentConflict):
        repo.save_draft(a, "operator", "governance:new", {"title": "Lost update"}, None)
    next_ = repo.save_draft(a, "operator", "governance:new", {"title": "Draft B"}, first["revision"])["draft"]
    with pytest.raises(DocumentConflict):
        repo.save_draft(a, "operator", "governance:new", None, first["revision"])
    repo.save_draft(a, "operator", "governance:new", None, next_["revision"])
    assert repo.draft(a, "operator", "governance:new")["draft"] is None
    saved = repo.save_draft(a, "operator", "governance:new", {"title": "Expiring"}, None)["draft"]
    with monkeypatch.context() as clock:
        clock.setattr(repo, "_clock", lambda db: saved["updated_at"] + DRAFT_TTL + 1)
        assert repo.draft(a, "operator", "governance:new")["draft"] is None
        repo.save_draft(a, "operator", "governance:new", {"title": "New"}, None)
    repo.set_member(a, "alice", "operator", "auditor")
    with pytest.raises(PermissionError):
        repo.draft(a, "operator", "governance:new")
    repo.set_member(a, "alice", "operator", "operator")
    assert repo.draft(a, "operator", "governance:new")["draft"] is None


@pytest.mark.parametrize("fields", [{"token": "secret"}, {"file": "bytes"}, {"title": "x" * 4001}, {"title": "spoof\u202er"}, {"evidence": ["x"] * 15}, {"title": 4}])
def test_draft_fields_are_bounded_and_credentials_files_rejected(setup, fields):
    with pytest.raises(ValueError):
        setup[1].save_draft(setup[2], "alice", "governance:new", fields, None)


def test_draft_binding_tamper_and_key_rotation(setup):
    _, repo, a, _, _, _ = setup
    saved = repo.save_draft(a, "alice", "governance:new", {"title": "Retain during rotation"}, None)
    old = repo.vault
    key = Fernet.generate_key().decode()
    repo.vault = Vault((key, *repo.settings.vault_keys))
    repo.rotate_credentials(a)
    repo.vault = Vault((key,))
    assert repo.draft(a, "alice", "governance:new")["draft"]["revision"] == saved["draft"]["revision"]
    with repo.scoped(a, lock=True) as (db, _):
        db.execute(update(drafts).where(drafts.c.tenant_id == a).values(key="governance:other"))
    with pytest.raises(EvidenceIntegrityError):
        repo.draft(a, "alice", "governance:other")
    repo.vault = old


def test_draft_quota_and_schedule_permissions(setup):
    _, repo, a, _, _, _ = setup
    repo.set_member(a, "alice", "operator", "operator")
    with pytest.raises(PermissionError):
        repo.save_draft(a, "operator", "schedule:policy", {"freshness_hours": "48"}, None)
    for n in range(20):
        repo.save_draft(a, "alice", f"governance:record{n}", {"title": "Unfinished"}, None)
    with pytest.raises(ValueError, match="limit"):
        repo.save_draft(a, "alice", "governance:more", {"title": "Too many"}, None)


def test_draft_api_requires_session_csrf_scope_and_known_query(setup):
    client = setup[4]
    assert client.get("/api/drafts?key=governance:new").status_code == 401
    headers = login(setup)
    value = {"key": "governance:new", "fields": {"title": "Private"}, "expected_revision": None}
    assert client.post("/api/drafts", json=value).status_code == 403
    assert client.post("/api/drafts", json=value, headers={**headers, "X-ClearTrail-Workspace": setup[3]}).status_code == 409
    assert client.post("/api/drafts", json=value, headers=headers).status_code == 200
    for suffix in ("key=governance:new&key=governance:other", "key=governance:new&tenant_id=elsewhere", "key=integration:new"):
        assert client.get("/api/drafts?" + suffix).status_code == 400


def test_labels_are_admin_governed_never_identity_and_preserve_subjects(setup):
    _, repo, a, b, client, _ = setup
    repo.set_member(a, "alice", "operator", "operator")
    with pytest.raises(PermissionError):
        repo.set_identity_label(a, "operator", "alice", "Impersonate")
    with pytest.raises(ValueError):
        repo.set_identity_label(a, "alice", "not-a-member", "Someone")
    repo.set_identity_label(a, "alice", "alice", "Security owner")
    repo.set_identity_label(a, "alice", "operator", "Security owner")
    assert repo.identity_labels(b, "bob", ["alice"]) == {}
    assert repo.member_list(a)[0]["subject"] == "alice"
    login(setup)
    assert client.get("/api/documents/owners").json()["identity_labels"]["alice"] == "Security owner"
    assert repo.audit_verify(a)["events"] >= 4
    with pytest.raises(ValueError):
        repo.set_identity_label(a, "alice", "alice", "Danger\u202e label")


def test_governance_pages_search_entire_authorized_population_and_stable_order(setup):
    _, repo, a, b, client, _ = setup
    ids = []
    for n in range(31):
        ids.append(repo.save_governance(a, "alice", payload(title=f"Risk {n:02}"))["record_id"])
    repo.save_governance(b, "bob", payload(title="Other customer secret", owner="bob"))
    repo.set_identity_label(a, "alice", "alice", "Café owner")
    login(setup)
    first = client.get("/api/governance?page=1&page_size=10&sort=title").json()
    second = client.get("/api/governance?page=2&page_size=10&sort=title").json()
    assert first["pagination"] == {"page": 1, "page_size": 10, "pages": 4, "total": 31, "available": 31}
    assert not {r["record_id"] for r in first["records"]} & {r["record_id"] for r in second["records"]}
    found = client.get("/api/governance?query=Risk%2030%20cafe").json()
    assert [r["title"] for r in found["records"]] == ["Risk 30"]
    assert "Other customer" not in str(first)
    repo.set_member(a, "alice", "auditor", "auditor")
    login(setup, "auditor")
    hidden = client.get("/api/governance?page_size=10").json()
    assert hidden["pagination"]["total"] == 0 and hidden["identity_labels"] == {}
    assert hidden["summary"] == {"pending": 0, "overdue": 0, "applicability": 0}


def test_document_pagination_and_count_clamping(setup):
    _, repo, a, _, client, _ = setup
    for n in range(12):
        value = copy.deepcopy(file_payload())
        value["title"] = f"Policy {n:02}"
        repo.upload_document(a, "alice", value)
    login(setup)
    data = client.get("/api/documents?page=999&page_size=10&sort=title").json()
    assert data["pagination"]["page"] == 2 and len(data["documents"]) == 2
    assert data["documents"][-1]["title"] == "Policy 11"


@pytest.mark.parametrize("pairs", [[("page", "0")], [("page_size", "1000")], [("page", "1"), ("page", "2")], [("tenant_id", "x")], [("sort", "arbitrary_sql")], [("query", "x" * 201)]])
def test_invalid_library_queries_are_rejected(pairs):
    with pytest.raises(ValueError):
        page_query(pairs, "governance")


def test_schema_five_additive_upgrade_is_explicit_and_idempotent(setup):
    _, repo, a, _, _, _ = setup
    record = repo.save_governance(a, "alice", payload())
    with repo.engine.begin() as db:
        db.execute(update(schema).values(version=5))
        drafts.drop(db)
        member_profiles.drop(db)
    with pytest.raises(ValueError):
        repo.ready()
    repo.migrate()
    repo.migrate()
    assert repo.ready()
    assert repo.governance_detail(a, "alice", record["record_id"])["versions"][0]["title"] == "Access governance"


@pytest.mark.parametrize("kind", ["risk", "applicability", "internal_audit", "management_review", "corrective_action"])
def test_every_governance_form_field_can_be_recovered_without_completion(setup, kind):
    value=payload(kind)
    fields={key:str(item) for key,item in value["payload"]["data"].items()}
    fields.update(kind=kind,title="Incomplete draft",owner="alice",evidence=[],related=[])
    setup[1].save_draft(setup[2],"alice","governance:new-"+kind,fields,None)
    recovered=setup[1].draft(setup[2],"alice","governance:new-"+kind)["draft"]["fields"]
    assert recovered==fields


def test_private_index_is_bounded_and_never_leaks_other_people_or_workspaces(setup):
    _,repo,a,b,client,_=setup
    repo.set_member(a,"alice","operator","operator")
    repo.save_draft(a,"alice","governance:new-risk",{"title":"Mine"},None)
    repo.save_draft(a,"operator","governance:new-risk",{"title":"Other actor"},None)
    repo.save_draft(b,"bob","governance:new-risk",{"title":"Other customer"},None)
    headers=login(setup)
    result=client.get("/api/draft-index").json()
    assert [d["title"] for d in result["drafts"]]==["Mine"]
    assert client.get("/api/draft-index?subject=operator").status_code==400
    own=result["drafts"][0]
    assert client.post("/api/drafts",json={"key":own["key"],"fields":None,"expected_revision":own["revision"]},headers=headers).status_code==200
    assert repo.draft_index(a,"operator")["drafts"][0]["title"]=="Other actor"


def test_accessibility_harness_is_opt_in_loopback_only_and_keeps_authentication(setup, tmp_path):
    import importlib.util
    from pathlib import Path
    from types import SimpleNamespace
    from fastapi.testclient import TestClient
    spec = importlib.util.spec_from_file_location("ui_qa", Path(__file__).resolve().parents[1] / "scripts/serve_ui_qa.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    axe = tmp_path / "axe.min.js"
    axe.write_text("/* test-only fixture */")
    assert setup[4].get("/qa/page").status_code == 404
    for settings in (SimpleNamespace(environment="production", public_url="http://127.0.0.1"),
                     SimpleNamespace(environment="test", public_url="http://external.example")):
        with pytest.raises(ValueError):
            module.make_harness(settings, axe)
    app = module.make_harness(setup[0], axe)
    with TestClient(app, base_url=setup[0].public_url) as client:
        assert client.get("/qa/page").status_code == 200
        assert "#qa-run" in client.get("/qa/audit.js").text
        assert client.get("/qa/axe.js").headers["content-type"].startswith("text/javascript")
        assert client.get("/api/draft-index").status_code == 401
