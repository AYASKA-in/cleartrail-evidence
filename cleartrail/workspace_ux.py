"""Bounded private drafts, governed identity labels and authorized list pages."""
from __future__ import annotations

import math
import re
import unicodedata
import uuid

from cryptography.fernet import InvalidToken
from sqlalchemy import select, insert, update, delete, func

from .documents import DocumentConflict, passive_text
from .errors import EvidenceIntegrityError
from .validation import canonical, strict_json_loads

DRAFT_TTL = 7 * 86400
MAX_DRAFTS = 20
MAX_DRAFT_BYTES = 32768
# No credentials, identity administration, review decisions or file bytes.
DRAFT_FIELDS = {
    "governance": {"kind", "title", "owner", "scope", "scenario", "likelihood", "impact", "treatment", "plan",
                   "residual_likelihood", "residual_impact", "review_date", "reference", "applicability", "basis",
                   "implementation", "description", "auditor", "criteria", "period_start", "period_end", "findings", "conclusion",
                   "participants", "inputs", "decisions", "actions", "next_review_date", "finding", "cause", "action",
                   "due_date", "state", "verification", "evidence", "related"},
    "document": {"title", "owner", "control_ids", "expires_at"},
    "schedule": {"enabled", "interval_hours", "freshness_hours"},
    "attestation": {"owner", "note"},
}
BINDINGS = ("tenant_id", "issuer", "subject", "key", "role", "revision", "updated_at", "expires_at")


def draft_key(key):
    if not isinstance(key, str) or not re.fullmatch(r"(?:governance|document|schedule|attestation):[a-zA-Z0-9_-]{1,64}", key):
        raise ValueError("Invalid draft key.")
    return key.split(":", 1)[0]


def draft_value(key, value):
    kind = draft_key(key)
    if not isinstance(value, dict) or not value or set(value) - DRAFT_FIELDS[kind]:
        raise ValueError("Unsupported draft fields. Files and credentials cannot be saved as drafts.")
    for field, item in value.items():
        if isinstance(item, list):
            if field not in {"evidence", "related", "control_ids"} or len(item) > 14 or any(not isinstance(v, str) or len(v) > 80 for v in item):
                raise ValueError("Invalid draft selection.")
        elif not isinstance(item, str) or len(item) > 4000 or any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} and c not in "\n\r\t" for c in item):
            raise ValueError("Invalid draft text.")
    if len(canonical(value)) > MAX_DRAFT_BYTES:
        raise ValueError("Draft exceeds 32 KiB.")
    return value


def open_draft(cipher, row):
    try:
        value = strict_json_loads(cipher.decrypt(row["envelope"].encode("ascii")))
        if set(value) != {"context", "fields"} or value["context"] != {k: row[k] for k in BINDINGS}:
            raise ValueError()
        return draft_value(row["key"], value["fields"])
    except (InvalidToken, ValueError, TypeError, KeyError, UnicodeError):
        raise EvidenceIntegrityError("Draft envelope could not be verified.") from None


def normalize(value):
    return "".join(c for c in unicodedata.normalize("NFKD", str(value or "")) if not unicodedata.combining(c)).lower().strip()


def page_query(pairs, kind):
    allowed = {"page", "page_size", "query", "status", "sort"} | ({"kind"} if kind == "governance" else set())
    if len(pairs) != len(dict(pairs)) or set(dict(pairs)) - allowed:
        raise ValueError("Unsupported or duplicate library query.")
    values = dict(pairs)
    page, size = values.get("page", "1"), values.get("page_size", "25")
    if not re.fullmatch(r"[1-9][0-9]{0,4}", page) or size not in {"10", "25", "50"}:
        raise ValueError("Choose a valid page and a page size of 10, 25 or 50.")
    query = values.get("query", "")
    if len(query) > 200 or any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in query):
        raise ValueError("Search must be at most 200 plain characters.")
    status = values.get("status", "all")
    if status not in {"all", "pending", "approved", "rejected", "withdrawn", "overdue" if kind == "governance" else "expired"}:
        raise ValueError("Invalid review filter.")
    record_kind = values.get("kind", "all")
    if record_kind not in {"all", "risk", "applicability", "internal_audit", "management_review", "corrective_action"}:
        raise ValueError("Invalid record type.")
    sort = values.get("sort", "newest")
    if sort not in {"newest", "oldest", "title", "owner", "review_date"}:
        raise ValueError("Invalid library order.")
    return {"page": int(page), "page_size": int(size), "query": query, "status": status, "kind": record_kind, "sort": sort}


class WorkspaceUXRepository:
    def draft_index(self, tenant, actor):
        from .hosted_repository import drafts, members
        with self.scoped(tenant) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator"})
            role = db.execute(select(members.c.role).where(members.c.tenant_id == tenant,
                members.c.issuer == self.settings.oidc_issuer, members.c.subject == actor)).scalar_one()
            rows = db.execute(select(drafts).where(drafts.c.tenant_id == tenant, drafts.c.subject == actor,
                drafts.c.issuer == self.settings.oidc_issuer, drafts.c.role == role,
                drafts.c.expires_at > self._clock(db)).order_by(drafts.c.updated_at.desc(), drafts.c.key).limit(MAX_DRAFTS)).mappings()
            result = []
            for row in rows:
                fields = open_draft(self.vault.cipher, row)
                result.append({"key": row["key"], "title": fields.get("title", row["key"])[:160],
                               **{k: row[k] for k in ("revision", "updated_at", "expires_at")}})
            return {"drafts": result, "limit": MAX_DRAFTS}

    def identity_labels(self, tenant, actor, subjects):
        from .hosted_repository import member_profiles
        with self.scoped(tenant) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator", "auditor"})
            return {row.subject: row.label for row in db.execute(select(member_profiles.c.subject, member_profiles.c.label).where(
                member_profiles.c.tenant_id == tenant, member_profiles.c.issuer == self.settings.oidc_issuer,
                member_profiles.c.subject.in_(set(subjects))))}

    def set_identity_label(self, tenant, actor, subject, label):
        from .hosted_repository import member_profiles, members
        subject = passive_text(subject, maximum=255)
        if not isinstance(label, str):
            raise ValueError("Display label must be text.")
        label = passive_text(label, maximum=80) if label.strip() else ""
        with self.scoped(tenant, lock=True) as (db, _):
            self._require_role(db, tenant, actor, {"admin"})
            if not db.execute(select(members.c.subject).where(members.c.tenant_id == tenant,
                members.c.issuer == self.settings.oidc_issuer, members.c.subject == subject)).first():
                raise ValueError("Choose a current workspace member.")
            db.execute(delete(member_profiles).where(member_profiles.c.tenant_id == tenant, member_profiles.c.subject == subject))
            if label:
                db.execute(insert(member_profiles).values(tenant_id=tenant, issuer=self.settings.oidc_issuer, subject=subject, label=label))
            self._audit(db, tenant, actor, "identity.label_changed", {"subject": subject, "label": label})

    def _draft_role(self, db, tenant, actor, key):
        from .hosted_repository import members
        allowed = {"admin"} if draft_key(key) == "schedule" else {"admin", "operator"}
        self._require_role(db, tenant, actor, allowed)
        return db.execute(select(members.c.role).where(members.c.tenant_id == tenant,
            members.c.issuer == self.settings.oidc_issuer, members.c.subject == actor)).scalar_one()

    def draft(self, tenant, actor, key):
        from .hosted_repository import drafts
        with self.scoped(tenant) as (db, _):
            role = self._draft_role(db, tenant, actor, key)
            row = db.execute(select(drafts).where(drafts.c.tenant_id == tenant, drafts.c.subject == actor,
                drafts.c.issuer == self.settings.oidc_issuer, drafts.c.key == key,
                drafts.c.role == role, drafts.c.expires_at > self._clock(db))).mappings().first()
            return {"draft": {"fields": open_draft(self.vault.cipher, row), "revision": row["revision"],
                              "updated_at": row["updated_at"], "expires_at": row["expires_at"]} if row else None}

    def save_draft(self, tenant, actor, key, fields, expected_revision):
        from .hosted_repository import drafts
        if expected_revision is not None and (not isinstance(expected_revision, str) or not re.fullmatch(r"[a-f0-9]{32}", expected_revision)):
            raise ValueError("Invalid draft revision.")
        if fields is not None:
            draft_value(key, fields)
        with self.scoped(tenant, lock=True) as (db, _):
            role = self._draft_role(db, tenant, actor, key)
            now = self._clock(db)
            # Cleanup is bounded by the workspace/user quota. Never publish drafts.
            db.execute(delete(drafts).where(drafts.c.tenant_id == tenant, drafts.c.expires_at <= now))
            where = (drafts.c.tenant_id == tenant, drafts.c.subject == actor, drafts.c.key == key)
            row = db.execute(select(drafts).where(*where)).mappings().first()
            if expected_revision != (row["revision"] if row else None):
                raise DocumentConflict("Another tab changed this draft. Reopen it before replacing it.")
            if fields is None:
                db.execute(delete(drafts).where(*where))
                return {"draft": None}
            count = db.execute(select(func.count()).select_from(drafts).where(drafts.c.tenant_id == tenant, drafts.c.subject == actor)).scalar_one()
            if not row and count >= MAX_DRAFTS:
                raise ValueError("Private draft limit reached. Discard an old draft before creating another.")
            values = dict(tenant_id=tenant, issuer=self.settings.oidc_issuer, subject=actor, key=key, role=role,
                          revision=uuid.uuid4().hex, updated_at=now, expires_at=now + DRAFT_TTL)
            envelope = self.vault.cipher.encrypt(canonical({"context": values, "fields": fields})).decode("ascii")
            db.execute(delete(drafts).where(*where))
            db.execute(insert(drafts).values(**values, envelope=envelope))
            return {"draft": {k: values[k] for k in ("revision", "updated_at", "expires_at")}}

    def rotate_workspace_keys(self, db, tenant):
        from .hosted_repository import drafts
        for row in db.execute(select(drafts).where(drafts.c.tenant_id == tenant)).mappings().all():
            fields = open_draft(self.vault.cipher, row)
            envelope = self.vault.cipher.encrypt(canonical({"context": {k: row[k] for k in BINDINGS}, "fields": fields})).decode("ascii")
            db.execute(update(drafts).where(drafts.c.tenant_id == tenant, drafts.c.subject == row["subject"], drafts.c.key == row["key"]).values(envelope=envelope))

    def library_page(self, tenant, actor, kind, query):
        # Existing quotas bound the authorized projection (100 documents / 250
        # governance records). Filter before slicing; never count hidden records.
        data = self.governance_list(tenant, actor) if kind == "governance" else self.document_list(tenant, actor)
        key = "records" if kind == "governance" else "documents"
        items = data[key]
        labels = self.identity_labels(tenant, actor, [r["owner"] for r in items])
        summary = {"pending": sum(r["status"] == "pending" for r in items),
                   "overdue": sum(r["overdue"] for r in items),
                   "applicability": sum(r["kind"] == "applicability" for r in items)} if kind == "governance" else {}
        result = []
        for row in items:
            status = row["status"] if kind == "governance" else row["latest_version"]["status"]
            if query["status"] != "all" and not (row.get("overdue") if query["status"] == "overdue" else status == query["status"]):
                continue
            if kind == "governance" and query["kind"] != "all" and row["kind"] != query["kind"]:
                continue
            values = [row["title"], row["owner"], labels.get(row["owner"], "")]
            values += [row["kind"].replace("_", " "), row["reference"]] if kind == "governance" else [row["latest_version"]["filename"], *row["control_ids"]]
            if all(term in normalize(" ".join(str(v or "") for v in values)) for term in normalize(query["query"]).split()):
                result.append(row)
        def order(row):
            sort = query["sort"]
            if sort == "title":
                value = normalize(row["title"])
            elif sort == "owner":
                value = normalize(labels.get(row["owner"], row["owner"]))
            elif sort == "review_date":
                value = row["payload"]["data"].get("next_review_date", row["payload"]["data"]["review_date"]) if kind == "governance" else row["latest_version"]["expires_at"] or 10**15
            else:
                value = row["created_at"]
            return value, row.get("record_id", row.get("id"))
        result.sort(key=order, reverse=query["sort"] == "newest")
        total = len(result)
        pages = max(1, math.ceil(total / query["page_size"]))
        page = min(query["page"], pages)
        visible = result[(page - 1) * query["page_size"]:page * query["page_size"]]
        data.update({key: visible, "identity_labels": {r["owner"]: labels[r["owner"]] for r in visible if r["owner"] in labels},
                     "summary": summary, "pagination": {"page": page, "page_size": query["page_size"], "pages": pages, "total": total, "available": len(items)}})
        return data
