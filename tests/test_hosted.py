"""Security regressions for tenant boundaries, sessions, jobs, and the vault."""
import hashlib
import secrets
import time
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from cleartrail.core import build_run
from cleartrail.hosted import create_app
from cleartrail.hosted_repository import Repository, audit, credentials, jobs, runs, sessions
from cleartrail.hosted_settings import HostedSettings
from cleartrail.vault import Vault


@pytest.fixture
def setup(tmp_path):
    settings = HostedSettings(database_url="sqlite:///" + (tmp_path / "hosted.db").as_posix(),
                              public_url="http://127.0.0.1", oidc_issuer="https://identity.example",
                              oidc_client_id="cleartrail", oidc_client_secret=secrets.token_urlsafe(32),
                              session_secret=secrets.token_urlsafe(48), vault_keys=(Fernet.generate_key().decode(),), environment="test")
    repo = Repository(settings)
    repo.migrate()
    a = repo.create_tenant("Customer A", settings.oidc_issuer, "alice")
    b = repo.create_tenant("Customer B", settings.oidc_issuer, "bob")
    app = create_app(settings, repo)
    with TestClient(app, base_url=settings.public_url) as client:
        yield settings, repo, a, b, client, app
    repo.engine.dispose()


def login(setup, subject="alice"):
    settings, repo, a, b, client, app = setup
    session = repo.create_session(settings.oidc_issuer, subject)
    client.cookies.set(settings.cookie_name, session["token"])
    return {"Origin": settings.public_url, "X-ClearTrail-Token": session["csrf"], "X-ClearTrail-Workspace": session["active_tenant"]}


def finish_run(repo, tenant, subject):
    repo.enqueue(tenant, subject)
    job = repo.claim()
    assert job["tenant_id"] == tenant
    snapshot = build_run(job["config"], [], job["attestations"])
    repo.finish(job, snapshot)
    return snapshot


def test_anonymous_reads_and_writes_are_denied(setup):
    client = setup[4]
    for route in ("state", "members", "audit", "export", "report", "csv"):
        assert client.get("/api/" + route).status_code == 401
    for route in ("scan", "attest", "config", "credentials", "members", "workspace", "logout"):
        assert client.post("/api/" + route, json={}, headers={"Origin": setup[0].public_url}).status_code == 401
    assert client.get("/healthz").json() == {"ok": True}
    assert client.get("/readyz").json() == {"ready": True}


def test_static_assets_use_explicit_types_with_nosniff(setup):
    for route, media in (("/", "text/html"), ("/app.js", "text/javascript"), ("/style.css", "text/css")):
        result = setup[4].get(route)
        assert result.status_code == 200
        assert result.headers["content-type"].split(";")[0] == media
        assert result.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("authenticated", [False, True])
def test_unrelated_cookie_churn_cannot_reset_request_budgets(setup, authenticated):
    cookie = ""
    if authenticated:
        settings, repo = setup[:2]
        identity = repo.create_session(settings.oidc_issuer, "alice")
        cookie = settings.cookie_name + "=" + identity["token"] + "; "
    # Freeze the window so this cannot flake across a real minute boundary.
    from unittest.mock import patch
    with patch("cleartrail.hosted.time.monotonic", return_value=1000):
        for number in range(120):
            assert setup[4].get("/api/auth", headers={"Cookie": cookie + "unused=" + str(number)}).status_code == 200
        response = setup[4].get("/api/auth", headers={"Cookie": cookie + "unused=changed"})
    assert response.status_code == 429 and response.headers["Retry-After"] == "60"


def test_tenant_state_history_and_downloads_do_not_cross_boundaries(setup):
    settings, repo, a, b, client, app = setup
    first = finish_run(repo, a, "alice")
    second = finish_run(repo, b, "bob")
    login(setup)
    state = client.get("/api/state").json()
    assert state["workspace_id"] == a
    assert state["run"]["id"] == first["id"]
    assert second["id"] not in str(state)
    assert client.get("/api/export?run_id=" + second["id"]).status_code == 404
    assert client.get("/api/report?run_id=" + second["id"]).status_code == 404
    assert client.get("/api/csv?run_id=" + second["id"]).status_code == 404
    assert client.get("/api/export?run_id=" + first["id"]).status_code == 200
    assert repo.get_run(a, second["id"]) is None


def test_workspace_switch_requires_actual_membership(setup):
    settings, repo, a, b, client, app = setup
    headers = login(setup)
    assert client.post("/api/workspace", json={"tenant_id": b}, headers=headers).status_code == 403
    repo.set_member(b, "bob", "alice", "auditor")
    assert client.post("/api/workspace", json={"tenant_id": b}, headers=headers).status_code == 200
    state = client.get("/api/state").json()
    assert state["workspace_id"] == b and state["role"] == "auditor"


def test_stale_tab_cannot_write_into_new_active_workspace(setup):
    settings, repo, a, b, client, app = setup
    headers = login(setup)
    repo.set_member(b, "bob", "alice", "operator")
    assert client.post("/api/workspace", json={"tenant_id": b}, headers=headers).status_code == 200
    assert client.post("/api/scan", json={}, headers=headers).status_code == 409
    assert repo.latest_job(b)["status"] == "idle"
    assert client.post("/api/scan", json={}, headers={**headers, "X-ClearTrail-Workspace": b}).status_code == 202


def test_integration_save_is_atomic_and_unknown_fields_are_rejected(setup):
    settings, repo, a, b, client, app = setup
    headers = login(setup)
    payload = {"provider":"github", "settings":{"org":"example"}, "credentials":{"token":"too-short"}}
    assert client.post("/api/integration", json=payload, headers=headers).status_code == 400
    assert repo.config(a)["providers"] == {} and repo.credential_status(a) == []
    payload["credentials"]["token"] = secrets.token_urlsafe(32)
    assert client.post("/api/integration", json=payload, headers=headers).status_code == 200
    assert repo.config(a)["providers"]["github"]["org"] == "example"
    assert repo.worker_credentials(b) == {}
    assert payload["credentials"]["token"] not in client.get("/api/state").text


def test_customer_cannot_choose_another_workspaces_aws_external_id(setup):
    settings, repo, a, b, client, app = setup
    assert repo.aws_external_id(a) != repo.aws_external_id(b)
    headers = login(setup)
    payload = {"provider":"aws", "settings":{"expected_account_id":"123456789012", "region":"us-east-1"},
               "credentials":{"role_arn":"arn:aws:iam::123456789012:role/ClearTrailReadOnly", "external_id":repo.aws_external_id(b)}}
    assert client.post("/api/integration", json=payload, headers=headers).status_code == 400
    assert repo.worker_credentials(a) == {} and repo.config(a)["providers"] == {}
    payload["credentials"]["external_id"] = repo.aws_external_id(a)
    assert client.post("/api/integration", json=payload, headers=headers).status_code == 200


def test_polling_unchanged_snapshot_does_not_reload_document(setup):
    repo, a = setup[1:3]
    snapshot = finish_run(repo, a, "alice")
    login(setup)
    from unittest.mock import patch
    with patch.object(repo, "get_run", side_effect=AssertionError("unnecessary snapshot load")):
        result = setup[4].get("/api/state?since=" + snapshot["id"])
    assert result.status_code == 200 and result.json()["unchanged"]
    assert result.json()["run"] is None


@pytest.mark.parametrize("route,payload", [
    ("scan", {}), ("attest", {"control_id": "MAN-POLICY", "owner": "Alice", "note": "Review"}),
    ("config", {"config": {}}), ("credentials", {"provider": "github", "credentials": {"token": "x" * 32}}),
    ("members", {"subject": "mallory", "role": "admin"})])
def test_auditors_cannot_mutate(route, payload, setup):
    repo, a = setup[1:3]
    repo.set_member(a, "alice", "reviewer", "auditor")
    headers = login(setup, "reviewer")
    assert setup[4].post("/api/" + route, json=payload, headers=headers).status_code == 403


def test_operator_can_collect_but_not_change_credentials_or_members(setup):
    repo, a = setup[1:3]
    repo.set_member(a, "alice", "operator", "operator")
    headers = login(setup, "operator")
    client = setup[4]
    assert client.post("/api/scan", json={}, headers=headers).status_code == 202
    assert client.post("/api/members", json={"subject": "intruder", "role": "admin"}, headers=headers).status_code == 403
    assert client.post("/api/config", json={"config": {}}, headers=headers).status_code == 403
    assert client.get("/api/members").status_code == 403


def test_permission_changes_and_revocation_affect_existing_sessions(setup):
    repo, a, client = setup[1], setup[2], setup[4]
    repo.set_member(a, "alice", "operator", "operator")
    headers = login(setup, "operator")
    repo.set_member(a, "alice", "operator", "auditor")
    assert client.post("/api/scan", json={}, headers=headers).status_code == 403
    repo.set_member(a, "alice", "operator", None)
    assert client.get("/api/state").status_code == 401
    with pytest.raises(ValueError):
        repo.set_member(a, "alice", "alice", None)


@pytest.mark.parametrize("headers", [{}, {"Origin": "https://evil.example"}, {"Origin": "http://127.0.0.1", "X-ClearTrail-Token": "x" * 43}])
def test_mutation_csrf_boundary(setup, headers):
    login(setup)
    assert setup[4].post("/api/scan", json={}, headers=headers).status_code == 403


def test_cookie_capabilities_are_hashed_expired_and_revocable(setup):
    settings, repo, a, b, client, app = setup
    headers = login(setup)
    token = client.cookies.get(settings.cookie_name)
    with repo.engine.connect() as db:
        rows = list(db.execute(select(sessions)).mappings())
    assert token not in str(rows)
    assert rows[0]["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    with repo.engine.begin() as db:
        db.execute(update(sessions).values(expires_at=int(time.time()) - 1))
    assert client.get("/api/state").status_code == 401
    headers = login(setup)
    assert client.post("/api/logout", headers=headers).status_code == 200
    assert client.get("/api/state").status_code == 401


def test_credential_encryption_context_and_key_rotation(setup):
    settings, repo, a, b, client, app = setup
    token = secrets.token_urlsafe(32)
    repo.set_credential(a, "alice", "github", {"token": token})
    with repo.scoped(a) as (db, _):
        envelope = db.execute(select(credentials.c.envelope).where(credentials.c.tenant_id == a)).scalar_one()
    assert token not in envelope
    assert repo.worker_credentials(a)["github"]["token"] == token
    assert repo.worker_credentials(b) == {}
    for tenant, provider in ((b, "github"), (a, "google")):
        with pytest.raises(ValueError):
            repo.vault.open(tenant, provider, envelope)
    new_key = Fernet.generate_key().decode()
    repo.vault = Vault((new_key,) + settings.vault_keys)
    assert repo.rotate_credentials(a) == 1
    repo.vault = Vault((new_key,))
    assert repo.worker_credentials(a)["github"]["token"] == token
    login(setup)
    assert token not in setup[4].get("/api/state").text
    assert token not in str(repo.audit_verify(a))


def test_jobs_are_single_flight_durable_and_lease_bound(setup):
    settings, repo, a, b, client, app = setup
    queued = repo.enqueue(a, "alice")
    assert repo.enqueue(a, "alice")["id"] == queued["id"]
    job = repo.claim()
    assert job["id"] == queued["id"]
    assert repo.claim() is None
    stale = dict(job, lease_token="invalid")
    snapshot = build_run(job["config"], [], {})
    with pytest.raises(ValueError):
        repo.finish(stale, snapshot)
    repo.finish(job, snapshot)
    assert repo.latest_job(a)["status"] == "succeeded"
    assert repo.latest_job(b)["status"] == "idle"
    with pytest.raises(ValueError):
        repo.finish(job, snapshot)
    # Reopening the repository preserves snapshots and queue state.
    reopened = Repository(settings)
    assert reopened.get_run(a)["id"] == snapshot["id"]
    reopened.engine.dispose()


def test_expired_worker_lease_cannot_publish(setup):
    repo, a = setup[1:3]
    repo.enqueue(a, "alice")
    job = repo.claim()
    with repo.scoped(a) as (db, _):
        db.execute(update(jobs).where(jobs.c.tenant_id == a).values(lease_until=int(time.time()) - 1))
    with pytest.raises(ValueError):
        repo.finish(job, build_run(job["config"], [], {}))
    assert repo.claim() is None
    assert repo.latest_job(a)["error"] == "worker_lost"


def test_audit_chain_and_stored_snapshot_integrity(setup):
    repo, a = setup[1:3]
    finish_run(repo, a, "alice")
    head = repo.audit_verify(a)
    assert repo.audit_verify(a, head["head_sha256"])["externally_anchored"]
    with pytest.raises(ValueError):
        repo.audit_verify(a, "0" * 64)
    with repo.scoped(a) as (db, _):
        db.execute(update(runs).where(runs.c.tenant_id == a).values(document="{}"))
    with pytest.raises(ValueError):
        repo.get_run(a)
    with repo.scoped(a) as (db, _):
        db.execute(update(audit).where(audit.c.tenant_id == a, audit.c.sequence == 1).values(event_hash="f" * 64))
    with pytest.raises(ValueError):
        repo.audit_verify(a)


def test_notes_and_config_are_captured_when_enqueued(setup):
    repo, a = setup[1:3]
    repo.attest(a, "alice", "MAN-POLICY", "Alice", "Original review")
    repo.enqueue(a, "alice")
    repo.attest(a, "alice", "MAN-POLICY", "Alice", "Later review")
    job = repo.claim()
    assert job["attestations"]["MAN-POLICY"]["note"] == "Original review"
    assert setup[1].attestations(setup[3]) == {}


@pytest.mark.parametrize("config", [
    {"organization": "Customer A", "providers": {"aws": {"profile": "default"}}},
    {"organization": "Customer A", "providers": {"aws": {"region": "us-east-1"}}},
    {"organization": "Customer A", "providers": {"google": {"customer": "my_customer"}}},
    {"organization": "Customer B"},
    {"organization": "Customer A", "token": "secret"}])
def test_hosted_config_rejects_ambient_and_ambiguous_scope(setup, config):
    with pytest.raises(ValueError):
        setup[1].set_config(setup[2], "alice", config)


def test_http_headers_queries_and_body_are_strict(setup):
    client = setup[4]
    headers = login(setup)
    assert client.get("/api/state", headers={"Host": "evil.example"}).status_code == 403
    assert client.get("/api/state", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.get("/api/state?tenant_id=" + setup[3]).status_code == 400
    assert client.post("/api/scan", content='{"x":1,"x":2}', headers={**headers, "Content-Type": "application/json"}).status_code == 400
    assert client.post("/api/scan", content=b"x" * (128 * 1024 + 1), headers=headers).status_code == 413
    assert client.get("/?name=../../hosted_settings.py").headers["content-type"].startswith("text/html")
    response = client.get("/api/state")
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert client.get("/docs").status_code == 404


def test_no_public_registration_or_identity_claim_login(setup):
    client = setup[4]
    assert client.post("/api/session", json={"issuer": setup[0].oidc_issuer, "subject": "alice"}).status_code == 404
    assert client.get("/auth/callback?code=forged&state=" + "x" * 43).status_code == 400
    assert client.get("/api/state").status_code == 401


@pytest.mark.parametrize("change", [
    {"environment": "production"}, {"public_url": "http://untrusted.example"},
    {"public_url": "https://host.example"}, {"session_secret": "a" * 48},
    {"vault_keys": ()}, {"oidc_issuer": "http://identity.example"},
    {"public_url": "http://127.0.0.1/"}])
def test_settings_fail_closed(setup, change):
    with pytest.raises(ValueError):
        replace(setup[0], **change)


def test_oidc_login_uses_pkce_nonce_and_only_verifiable_membership(setup):
    settings, repo, a, b, client, app = setup
    auth = app.state.auth
    auth._metadata = AsyncMock(return_value={})
    # Use the real authorization URL builder and signed state cookie; only the
    # token exchange is substituted here. Signature validation has separate tests.
    auth.client.server_metadata.update(authorization_endpoint="https://identity.example/authorize", token_endpoint="https://identity.example/token")
    auth.client.server_metadata["_loaded_at"] = time.time()
    response = client.get("/auth/login", follow_redirects=False)
    from urllib.parse import parse_qs, urlsplit
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["code_challenge_method"] == ["S256"] and query["nonce"] and query["state"]
    assert "httponly" in response.headers["set-cookie"].lower()
    claims = {"iss": settings.oidc_issuer, "sub": "alice", "aud": settings.oidc_client_id}
    auth.client.authorize_access_token = AsyncMock(return_value={"id_token": "verified-in-exchange", "userinfo": claims})
    callback = client.get("/auth/callback", params={"code": "example-code", "state": query["state"][0]}, follow_redirects=False)
    assert callback.status_code == 303
    assert "HttpOnly" in callback.headers["set-cookie"] and "SameSite=strict" in callback.headers["set-cookie"]
    assert client.get("/api/state").status_code == 200


@pytest.mark.parametrize("claim_change", [{"iss": "https://attacker.example"}, {"sub": "outsider"}, {"aud": "other-client"}, {"aud": ["cleartrail", "other"], "azp": "other"}])
def test_oidc_callback_rejects_wrong_identity_or_audience(setup, claim_change):
    settings, repo, a, b, client, app = setup
    auth = app.state.auth
    auth._metadata = AsyncMock(return_value={})
    auth.client.server_metadata.update(authorization_endpoint="https://identity.example/authorize")
    auth.client.server_metadata["_loaded_at"] = time.time()
    response = client.get("/auth/login", follow_redirects=False)
    from urllib.parse import parse_qs, urlsplit
    state = parse_qs(urlsplit(response.headers["location"]).query)["state"][0]
    claims = {"iss": settings.oidc_issuer, "sub": "alice", "aud": settings.oidc_client_id, **claim_change}
    auth.client.authorize_access_token = AsyncMock(return_value={"id_token": "verified-in-exchange", "userinfo": claims})
    callback = client.get("/auth/callback", params={"code": "example-code", "state": state}, follow_redirects=False)
    assert callback.status_code in {400, 403}
    assert client.get("/api/state").status_code == 401


@pytest.mark.parametrize("case", ["google", "outsider", "duplicate", "unknown", "control", "oversize", "other-issuer"])
def test_google_callback_information_never_grants_membership(setup, case):
    from urllib.parse import parse_qs, urlsplit

    settings, repo, a, b, client, app = setup
    auth = app.state.auth
    issuer = settings.oidc_issuer if case == "other-issuer" else "https://accounts.google.com"
    auth.settings = replace(settings, oidc_issuer=issuer)
    repo.settings = auth.settings
    if case != "other-issuer":
        repo.create_tenant("Google fixture", issuer, "alice")
    auth._metadata = AsyncMock(return_value={})
    auth.client.server_metadata.update(authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth", _loaded_at=time.time())
    response = client.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlsplit(response.headers["location"]).query)["state"][0]
    claims = {"iss": issuer, "sub": "outsider" if case == "outsider" else "alice", "aud": settings.oidc_client_id}
    auth.client.authorize_access_token = AsyncMock(return_value={"id_token": "verified-in-exchange", "userinfo": claims})
    params = [("code", "example-code"), ("state", state), ("scope", "openid"), ("authuser", "0"), ("hd", "customer.example"), ("prompt", "consent")]
    if case == "duplicate":
        params.append(("hd", "attacker.example"))
    elif case == "unknown":
        params.append(("tenant_id", a))
    elif case == "control":
        params.append(("scope", "openid\x00"))
        params = [pair for pair in params if pair != ("scope", "openid")]
    elif case == "oversize":
        params = [(name, "x" * 2049 if name == "scope" else value) for name, value in params]
    result = client.get("/auth/callback", params=params, follow_redirects=False)
    assert result.status_code == (303 if case == "google" else 403 if case == "outsider" else 400)
    assert client.get("/api/state").status_code == (200 if case == "google" else 401)
