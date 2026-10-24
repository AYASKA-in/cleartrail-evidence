"""Governance authorization, immutable approvals, dependency and export boundaries."""

import copy
import hashlib
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select, update

from cleartrail import governance as g
from cleartrail.documents import DocumentConflict
from cleartrail.errors import EvidenceIntegrityError
from cleartrail.hosted_repository import governance_versions, document_versions, schema
from cleartrail.vault import Vault
from test_hosted import setup as setup, login
from test_documents import add_reviewers, upload, review as document_review


def payload(kind="risk", **overrides):
    data = {
        "risk": {
            "scope": "Customer platform",
            "scenario": "Unreviewed privileged access",
            "likelihood": 4,
            "impact": 5,
            "treatment": "mitigate",
            "plan": "Quarterly access reviews",
            "residual_likelihood": 2,
            "residual_impact": 3,
            "review_date": "2027-01-01",
        },
        "applicability": {
            "reference": "A.5.1",
            "applicability": "applicable",
            "basis": "Customer contractual scope",
            "implementation": "planned",
            "description": "Document the policy review",
            "review_date": "2027-01-01",
        },
        "internal_audit": {
            "scope": "Access lifecycle",
            "criteria": "Customer policy revision 2",
            "auditor": "reviewer",
            "period_start": "2026-01-01",
            "period_end": "2026-10-01",
            "findings": "One delayed review",
            "conclusion": "Track corrective action",
            "review_date": "2027-01-01",
        },
        "management_review": {
            "review_date": "2026-10-01",
            "participants": "Security lead, CEO",
            "inputs": "Audit findings and risks",
            "decisions": "Fund access automation",
            "actions": "Owner to implement in November",
            "next_review_date": "2027-01-01",
        },
        "corrective_action": {
            "finding": "Delayed access review",
            "cause": "Missing reminder",
            "action": "Add scheduled reminder",
            "due_date": "2026-12-01",
            "state": "open",
            "verification": "Verification planned after rollout",
            "review_date": "2027-01-01",
        },
    }[kind]
    return {
        "record_id": None,
        "kind": kind,
        "title": "Access governance",
        "owner": "alice",
        "expected_revision": None,
        "payload": {
            "data": data,
            "evidence_version_ids": [],
            "related_version_ids": [],
        },
        **overrides,
    }


def save(setup, value=None, subject="alice"):
    return setup[4].post(
        "/api/governance/save", json=value or payload(), headers=login(setup, subject)
    )


def review(setup, version, decision="approved", expected=None, subject="reviewer"):
    return setup[4].post(
        "/api/governance/review",
        json={
            "version_id": version,
            "decision": decision,
            "comment": "Reviewed exact record and supporting references",
            "expected_review_id": expected,
        },
        headers=login(setup, subject),
    )


def exported(setup, tmp_path):
    response = setup[4].post(
        "/api/governance/export", json={}, headers=login(setup, "auditor")
    )
    assert response.status_code == 200, response.text
    path = tmp_path / "register.json"
    path.write_bytes(response.content)
    digest = response.headers["x-cleartrail-sha256"]
    assert hashlib.sha256(response.content).hexdigest() == digest
    assert g.verify_governance(path, digest)["valid"] is True
    return path, response.json(), digest


@pytest.mark.parametrize("kind", sorted(g.KINDS))
def test_all_record_types_immutable_independent_and_exportable(setup, tmp_path, kind):
    add_reviewers(setup)
    first = save(setup, payload(kind)).json()
    assert review(setup, first["version_id"], subject="alice").status_code == 403
    login(setup, "auditor")
    assert setup[4].get("/api/governance").json()["records"] == []
    assert review(setup, first["version_id"]).status_code == 200
    path, register, digest = exported(setup, tmp_path)
    assert register["records"][0]["payload"] == payload(kind)["payload"]
    if kind == "risk":
        assert register["records"][0]["risk_scores"] == {
            "inherent": {"score": 20, "band": "critical"},
            "residual": {"score": 6, "band": "medium"},
        }
    changed = payload(
        kind,
        record_id=first["record_id"],
        expected_revision=1,
        title="New pending version",
    )
    assert save(setup, changed).status_code == 200
    assert save(setup, changed).status_code == 409
    login(setup, "auditor")
    assert setup[4].get("/api/governance").json()["records"] == []
    detail = setup[4].get("/api/governance/" + first["record_id"]).json()
    assert detail["revision"] is None and len(detail["versions"]) == 1
    assert detail["versions"][0]["id"] == first["version_id"]
    # Portable verification requires no hosted, ORM or cryptography dependencies.
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            "import sys;sys.path.insert(0,sys.argv[1]);from cleartrail.governance import verify_governance;assert verify_governance(sys.argv[2],sys.argv[3])['valid']",
            str(__import__("pathlib").Path(__file__).resolve().parents[1]),
            str(path),
            digest,
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "field,value",
    [
        ("likelihood", True),
        ("impact", 0),
        ("residual_impact", 6),
        ("review_date", "2027-02-30"),
        ("scope", "bad\u202espoof"),
        ("treatment", "ignore"),
        ("plan", "x" * 3001),
    ],
)
def test_strict_risk_fields(setup, field, value):
    data = payload()
    data["payload"]["data"][field] = value
    assert save(setup, data).status_code == 400
    assert setup[1].governance_list(setup[2], "alice")["records"] == []


@pytest.mark.parametrize(
    "kind,changes",
    [
        ("applicability", {"reference": "A.8.35"}),
        (
            "applicability",
            {"applicability": "not_applicable", "implementation": "implemented"},
        ),
        ("internal_audit", {"auditor": "alice"}),
        ("internal_audit", {"period_end": "2025-01-01"}),
        ("management_review", {"next_review_date": "2026-10-01"}),
        ("corrective_action", {"state": "ignored"}),
    ],
)
def test_type_specific_invalid_decisions_are_rejected(setup, kind, changes):
    add_reviewers(setup)
    value = payload(kind)
    value["payload"]["data"].update(changes)
    assert save(setup, value).status_code == 400


def test_risk_scoring_policy_and_reference_population():
    assert len(g.ANNEX_REFERENCES) == len(set(g.ANNEX_REFERENCES)) == 93
    for likelihood, impact, band in (
        (1, 4, "low"),
        (1, 5, "medium"),
        (2, 5, "high"),
        (4, 4, "critical"),
    ):
        data = payload()["payload"]["data"]
        data.update(likelihood=likelihood, impact=impact)
        assert g.risk_scores(data)["inherent"] == {
            "score": likelihood * impact,
            "band": band,
        }


def test_auth_csrf_roles_and_cross_tenant_links(setup):
    client = setup[4]
    for endpoint in ("/api/governance", "/api/governance/options"):
        assert client.get(endpoint).status_code == 401
    assert (
        client.post("/api/governance/save", json=payload()).status_code == 403
    )  # missing Origin
    first = save(setup).json()
    assert (
        save(
            setup,
            payload(record_id=first["record_id"], owner="bob", expected_revision=1),
            "bob",
        ).status_code
        == 404
    )
    assert client.get("/api/governance/" + first["record_id"]).status_code == 404
    assert review(setup, first["version_id"], subject="bob").status_code == 404
    foreign = payload(owner="bob")
    foreign["payload"]["related_version_ids"] = [first["version_id"]]
    assert save(setup, foreign, "bob").status_code == 404
    add_reviewers(setup)
    assert save(setup, subject="auditor").status_code == 403
    headers = login(setup)
    assert (
        client.post(
            "/api/governance/save",
            json=payload(),
            headers={**headers, "X-ClearTrail-Workspace": setup[3]},
        ).status_code
        == 409
    )
    assert (
        client.post(
            "/api/governance/save",
            json=payload(),
            headers={**headers, "X-ClearTrail-Token": "wrong"},
        ).status_code
        == 403
    )
    assert client.get("/api/governance?tenant_id=" + setup[3]).status_code == 400


def test_applicability_unique_immutable_reference_and_evidence_gate(setup, tmp_path):
    add_reviewers(setup)
    data = payload("applicability")
    data["payload"]["data"]["implementation"] = "implemented"
    first = save(setup, data).json()
    assert review(setup, first["version_id"]).status_code == 400
    assert save(setup, data).status_code == 409
    doc = upload(setup)
    assert document_review(setup, doc["version_id"]).status_code == 200
    data.update(record_id=first["record_id"], expected_revision=1)
    data["payload"]["evidence_version_ids"] = [doc["version_id"]]
    second = save(setup, data).json()
    assert review(setup, second["version_id"]).status_code == 200
    exported(setup, tmp_path)
    approval = setup[1].document_detail(setup[2], "alice", doc["document_id"])[
        "versions"
    ][0]["reviews"][-1]["id"]
    assert (
        document_review(
            setup,
            doc["version_id"],
            decision="withdrawn",
            expected=approval,
            subject="alice",
        ).status_code
        == 200
    )
    response = setup[4].post("/api/governance/export", json={}, headers=login(setup))
    assert (
        response.status_code == 409
    )  # approval never masks a later evidence withdrawal
    data["payload"]["data"]["reference"] = "A.5.2"
    data["expected_revision"] = 2
    assert save(setup, data).status_code == 409


def test_related_risk_export_closure_and_withdrawal(setup, tmp_path):
    add_reviewers(setup)
    risk = save(setup).json()
    approval = review(setup, risk["version_id"]).json()
    soa = payload("applicability")
    soa["payload"]["related_version_ids"] = [risk["version_id"]]
    second = save(setup, soa).json()
    assert review(setup, second["version_id"]).status_code == 200
    newer = payload(record_id=risk["record_id"], expected_revision=1, owner="reviewer")
    assert save(setup, newer).status_code == 200
    _, register, _ = exported(setup, tmp_path)
    assert {r["id"] for r in register["records"]} == {
        risk["version_id"],
        second["version_id"],
    }
    assert (
        review(
            setup, risk["version_id"], "withdrawn", approval["id"], "alice"
        ).status_code
        == 200
    )
    assert (
        setup[4]
        .post("/api/governance/export", json={}, headers=login(setup))
        .status_code
        == 409
    )
    self_link = payload(record_id=risk["record_id"], expected_revision=2)
    self_link["payload"]["related_version_ids"] = [risk["version_id"]]
    assert save(setup, self_link).status_code == 400


def test_tampered_ciphertext_fails_closed_but_can_withdraw(setup):
    add_reviewers(setup)
    first = save(setup).json()
    approved = review(setup, first["version_id"]).json()
    with setup[1].scoped(setup[2]) as (db, _):
        db.execute(
            update(governance_versions)
            .values(title="tampered metadata")
            .where(governance_versions.c.id == first["version_id"])
        )
    login(setup)
    assert setup[4].get("/api/governance").status_code == 503
    assert (
        review(
            setup, first["version_id"], "withdrawn", approved["id"], "alice"
        ).status_code
        == 200
    )
    login(setup, "auditor")
    assert setup[4].get("/api/governance").json()["records"] == []


def test_parallel_saves_and_reviews_observe_optimistic_revision(setup):
    add_reviewers(setup)
    repo, tenant = setup[1:3]
    first = repo.save_governance(tenant, "alice", payload())
    change = payload(record_id=first["record_id"], expected_revision=1)

    def attempt(_):
        try:
            return repo.save_governance(tenant, "alice", change)
        except DocumentConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        saved = [r for r in pool.map(attempt, range(2)) if r]
    assert len(saved) == 1
    second = saved[0]
    approved = repo.review_governance(
        tenant, "reviewer", second["version_id"], "approved", "Verified", None
    )
    with pytest.raises(DocumentConflict):
        repo.review_governance(
            tenant, "reviewer", second["version_id"], "rejected", "Stale form", None
        )
    assert approved["sequence"] == 1


def test_key_rotation_is_validated_and_atomic(setup):
    repo, tenant = setup[1:3]
    repo.save_governance(tenant, "alice", payload())
    with repo.scoped(tenant) as (db, _):
        before = db.execute(select(governance_versions.c.envelope)).scalar_one()
    old = setup[0].vault_keys[0]
    new = Fernet.generate_key().decode()
    repo.vault = Vault((new, old))
    repo.rotate_credentials(tenant)
    with repo.scoped(tenant) as (db, _):
        after = db.execute(select(governance_versions)).mappings().one()
        assert after["envelope"] != before
        assert g.open_payload(Vault((new,)).cipher, after) == payload()["payload"]
    doc = upload(setup)
    with repo.scoped(tenant) as (db, _):
        file_before = db.execute(
            select(document_versions.c.envelope).where(
                document_versions.c.id == doc["version_id"]
            )
        ).scalar_one()
        db.execute(update(governance_versions).values(envelope="corrupt"))
    repo.vault = Vault((Fernet.generate_key().decode(), new, old))
    with pytest.raises(EvidenceIntegrityError):
        repo.rotate_credentials(tenant)
    with repo.scoped(tenant) as (db, _):
        assert (
            db.execute(
                select(document_versions.c.envelope).where(
                    document_versions.c.id == doc["version_id"]
                )
            ).scalar_one()
            == file_before
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "decision_type",
        "cycle",
        "risk_bool",
        "extra",
        "digest",
        "duplicate",
        "unknown_generator",
    ],
)
def test_portable_verifier_rejects_tampered_register(setup, tmp_path, mutation):
    add_reviewers(setup)
    first = save(setup).json()
    assert review(setup, first["version_id"]).status_code == 200
    path, register, digest = exported(setup, tmp_path)
    record = register["records"][0]
    if mutation == "decision_type":
        record["reviews"][0]["decision"] = []
    elif mutation == "cycle":
        record["payload"]["related_version_ids"] = [record["id"]]
        raw = g.canonical(record["payload"])
        record.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    elif mutation == "risk_bool":
        record["risk_scores"]["inherent"]["score"] = True
    elif mutation == "extra":
        record["unexpected"] = 1
    elif mutation == "digest":
        record["sha256"] = "0" * 64
    elif mutation == "duplicate":
        register["records"].append(copy.deepcopy(record))
    elif mutation == "unknown_generator":
        register["generator"] = "99.0.0"
    path.write_text(json.dumps(register), encoding="utf-8")
    with pytest.raises(ValueError):
        g.verify_governance(path)
    with pytest.raises(ValueError):
        g.verify_governance(path, digest)


def test_quotas_reserve_withdrawal_and_schema_upgrade(setup, monkeypatch):
    add_reviewers(setup)
    first = save(setup).json()
    with monkeypatch.context() as context:
        context.setattr(g, "MAX_RECORDS", 1)
        assert save(setup).status_code == 400
        context.setattr(g, "MAX_VERSIONS", 1)
        assert (
            save(
                setup, payload(record_id=first["record_id"], expected_revision=1)
            ).status_code
            == 400
        )
    approved = review(setup, first["version_id"]).json()
    with monkeypatch.context() as context:
        context.setattr(g, "MAX_REVIEWS", 2)
        assert (
            review(setup, first["version_id"], expected=approved["id"]).status_code
            == 400
        )
        assert (
            review(
                setup, first["version_id"], "withdrawn", approved["id"], "alice"
            ).status_code
            == 200
        )
    repo, tenant = setup[1:3]
    before = repo.governance_detail(tenant, "alice", first["record_id"])
    with repo.engine.begin() as db:
        db.execute(update(schema).values(version=4))
    repo.migrate()
    repo.migrate()
    assert repo.governance_detail(tenant, "alice", first["record_id"]) == before
    assert repo.ready()
