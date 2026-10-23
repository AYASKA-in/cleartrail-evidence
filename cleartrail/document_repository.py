"""Transactional evidence ownership, immutable versions and independent review."""
from __future__ import annotations

import hashlib
import re
import uuid

from sqlalchemy import select, insert, update, func, and_

from .catalog import CATALOG
from .documents import (DocumentConflict, DocumentNotFound, MAX_DOCUMENTS, MAX_VERSIONS, MAX_REVIEWS, MAX_WORKSPACE_BYTES,
                        passive_text, validate_file, seal_file, open_file, version_status)
from .validation import canonical, strict_json_loads
from .scanning import scan_upload


def tables():
    # Deferred import keeps SQL metadata and migration registration in one place.
    from .hosted_repository import documents, document_versions, document_reviews
    return documents, document_versions, document_reviews


def identifier(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("Invalid document identifier.")
    return value


class DocumentRepository:
    def audit_options(self, tenant, actor):
        d, v, r = tables()
        with self.scoped(tenant) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator", "auditor"})
            heads = select(r.c.version_id, func.max(r.c.sequence).label("sequence")).where(r.c.tenant_id == tenant).group_by(r.c.version_id).subquery()
            statement = select(d.c.id.label("document_id"), d.c.title, v.c.id, v.c.number, v.c.filename, v.c.created_at, v.c.expires_at).select_from(v.join(
                d, and_(d.c.tenant_id == v.c.tenant_id, d.c.id == v.c.document_id)).join(heads, heads.c.version_id == v.c.id).join(
                r, and_(r.c.tenant_id == v.c.tenant_id, r.c.version_id == v.c.id, r.c.sequence == heads.c.sequence))).where(
                v.c.tenant_id == tenant, r.c.decision == "approved", (v.c.expires_at.is_(None) | (v.c.expires_at > self._clock(db)))).order_by(d.c.title, v.c.number.desc())
            return [dict(row) for row in db.execute(statement).mappings()]

    def document_owners(self, tenant, actor):
        with self.scoped(tenant) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator"})
            from .hosted_repository import members
            return list(db.execute(select(members.c.subject).where(
                members.c.tenant_id == tenant, members.c.issuer == self.settings.oidc_issuer,
                members.c.role.in_(["admin", "operator"])).order_by(members.c.subject)).scalars())

    def upload_document(self, tenant, actor, value):
        d, v, r = tables()
        raw = validate_file(value["filename"], value["content_base64"])
        # Reject before contacting the scanner if repository callers lack access.
        with self.scoped(tenant) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator"})
        scan = scan_upload(self.settings, value["filename"], raw)
        title = passive_text(value["title"], maximum=160)
        owner = passive_text(value["owner"], maximum=255)
        controls = value["control_ids"]
        if not isinstance(controls, list) or not 1 <= len(controls) <= len(CATALOG) or any(
            not isinstance(item, str) or item not in CATALOG for item in controls
        ) or len(set(controls)) != len(controls):
            raise ValueError("Choose distinct registered controls.")
        controls = sorted(controls)
        document_id = identifier(value["document_id"]) if value["document_id"] is not None else str(uuid.uuid4())
        expected = value["expected_version_id"]
        if expected is not None:
            identifier(expected)
        with self.scoped(tenant, lock=True) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator"})
            self._require_role(db, tenant, owner, {"admin", "operator"})
            now = self._clock(db)
            expiry = value["expires_at"]
            if expiry is not None and (type(expiry) is not int or not now < expiry <= now + 366 * 86400 * 10):
                raise ValueError("Expiry must be in the next ten years.")
            item = db.execute(select(d).where(d.c.tenant_id == tenant, d.c.id == document_id)).mappings().first()
            if value["document_id"] is not None and item is None:
                raise DocumentNotFound("Document not found.")
            head = db.execute(select(v.c.id, v.c.number).where(v.c.tenant_id == tenant, v.c.document_id == document_id).order_by(v.c.number.desc()).limit(1)).mappings().first()
            if expected != (head["id"] if head else None) or (item and (
                value["expected_revision"] != item["revision"] or type(value["expected_revision"]) is not int
            )) or (not item and value["expected_revision"] is not None):
                raise DocumentConflict()
            if item and (title != item["title"] or controls != strict_json_loads(item["control_ids"]) or owner != item["owner"]):
                raise DocumentConflict()
            number = head["number"] + 1 if head else 1
            used = db.execute(select(func.coalesce(func.sum(v.c.size), 0)).where(v.c.tenant_id == tenant)).scalar_one()
            count = db.execute(select(func.count()).select_from(d).where(d.c.tenant_id == tenant)).scalar_one()
            if number > MAX_VERSIONS or used + len(raw) > MAX_WORKSPACE_BYTES or (not item and count >= MAX_DOCUMENTS):
                raise ValueError("Workspace document quota reached.")
            version = {"tenant_id": tenant, "id": str(uuid.uuid4()), "document_id": document_id,
                       "number": number, "filename": value["filename"], "size": len(raw),
                       "sha256": hashlib.sha256(raw).hexdigest(), "uploaded_by": actor,
                       "owner_at_upload": owner, "created_at": now, "expires_at": expiry, "scan": canonical(scan).decode()}
            if not item:
                db.execute(insert(d).values(tenant_id=tenant, id=document_id, title=title,
                                           control_ids=canonical(controls).decode(), owner=owner, revision=1, created_at=now))
            else:
                db.execute(update(d).where(d.c.tenant_id == tenant, d.c.id == document_id).values(revision=item["revision"] + 1))
            db.execute(insert(v).values(**version, envelope=seal_file(self.vault.cipher, version, raw)))
            self._audit(db, tenant, actor, "document.uploaded", {**version, "scan": scan, "title": title, "control_ids": controls})
        return {"document_id": document_id, "version_id": version["id"]}

    def assign_document(self, tenant, actor, document_id, owner, expected_revision):
        d, v, r = tables()
        identifier(document_id)
        owner = passive_text(owner, maximum=255)
        with self.scoped(tenant, lock=True) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator"})
            self._require_role(db, tenant, owner, {"admin", "operator"})
            item = db.execute(select(d).where(d.c.tenant_id == tenant, d.c.id == document_id)).mappings().first()
            if not item:
                raise DocumentNotFound("Document not found.")
            if type(expected_revision) is not int or expected_revision != item["revision"]:
                raise DocumentConflict()
            if owner != item["owner"]:
                db.execute(update(d).where(d.c.tenant_id == tenant, d.c.id == document_id).values(owner=owner, revision=item["revision"] + 1))
                self._audit(db, tenant, actor, "document.assigned", {"document_id": document_id, "previous_owner": item["owner"], "owner": owner})

    def review_document(self, tenant, actor, version_id, decision, comment, expected_review_id):
        d, v, r = tables()
        identifier(version_id)
        if expected_review_id is not None:
            identifier(expected_review_id)
        if not isinstance(decision, str) or decision not in {"approved", "rejected", "withdrawn"}:
            raise ValueError("Invalid review decision.")
        comment = passive_text(comment, maximum=2000, multiline=True)
        with self.scoped(tenant, lock=True) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator"})
            version = db.execute(select(v).where(v.c.tenant_id == tenant, v.c.id == version_id)).mappings().first()
            if not version:
                raise DocumentNotFound("Version not found.")
            item = db.execute(select(d).where(d.c.tenant_id == tenant, d.c.id == version["document_id"])).mappings().one()
            if decision != "withdrawn" and actor in {version["uploaded_by"], version["owner_at_upload"], item["owner"]}:
                raise PermissionError("An independent reviewer is required.")
            latest = db.execute(select(v.c.id).where(v.c.tenant_id == tenant, v.c.document_id == item["id"]).order_by(v.c.number.desc()).limit(1)).scalar_one()
            previous = self._document_review(db, tenant, version_id)
            if (decision != "withdrawn" and latest != version_id) or expected_review_id != (previous["id"] if previous else None):
                raise DocumentConflict()
            now = self._clock(db)
            if decision == "approved" and version["expires_at"] is not None and version["expires_at"] <= now:
                raise ValueError("Expired evidence cannot be approved.")
            # Approval must verify the exact encrypted bytes, even if the reviewer
            # previously downloaded the file before storage was damaged.
            if decision != "withdrawn":
                open_file(self.vault.cipher, version)
            sequence = previous["sequence"] + 1 if previous else 1
            if sequence > MAX_REVIEWS or (sequence == MAX_REVIEWS and decision == "approved"):
                raise ValueError("Version review quota reached.")
            review = {"id": str(uuid.uuid4()), "version_id": version_id, "sequence": sequence,
                      "decision": decision, "reviewer": actor, "comment": comment, "created_at": now}
            db.execute(insert(r).values(tenant_id=tenant, **review))
            self._audit(db, tenant, actor, "document.reviewed", {**review, "document_id": item["id"], "sha256": version["sha256"]})
            return review

    @staticmethod
    def _document_review(db, tenant, version_id):
        r = tables()[2]
        row = db.execute(select(r).where(r.c.tenant_id == tenant, r.c.version_id == version_id).order_by(r.c.sequence.desc()).limit(1)).mappings().first()
        return {key: value for key, value in row.items() if key != "tenant_id"} if row else None

    def _document_versions(self, db, tenant, document_id):
        v = tables()[1]
        columns = [column for column in v.c if column.name not in {"tenant_id", "envelope"}]
        return [{**dict(row), "scan": strict_json_loads(row["scan"]) if row["scan"] is not None else None} for row in db.execute(select(*columns).where(v.c.tenant_id == tenant, v.c.document_id == document_id).order_by(v.c.number.desc())).mappings()]

    def document_list(self, tenant, actor):
        d, v, r = tables()
        with self.scoped(tenant) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator", "auditor"})
            now = self._clock(db)
            from .hosted_repository import members
            role = db.execute(select(members.c.role).where(members.c.tenant_id == tenant, members.c.issuer == self.settings.oidc_issuer, members.c.subject == actor)).scalar_one()
            # Load only latest-version metadata; never fetch ciphertext in a list
            # request or issue one query per document/review.
            heads = select(v.c.document_id, func.max(v.c.number).label("number")).where(
                v.c.tenant_id == tenant).group_by(v.c.document_id).subquery()
            columns = [column for column in v.c if column.name not in {"tenant_id", "envelope"}]
            versions = [{**dict(row), "scan": strict_json_loads(row["scan"]) if row["scan"] is not None else None} for row in db.execute(select(*columns).join(heads, and_(
                v.c.document_id == heads.c.document_id, v.c.number == heads.c.number)).where(v.c.tenant_id == tenant)).mappings()]
            by_document = {row["document_id"]: row for row in versions}
            review_heads = select(r.c.version_id, func.max(r.c.sequence).label("sequence")).where(
                r.c.tenant_id == tenant, r.c.version_id.in_([row["id"] for row in versions])).group_by(r.c.version_id).subquery()
            reviews = {row["version_id"]: {key: value for key, value in row.items() if key != "tenant_id"}
                       for row in db.execute(select(r).join(review_heads, and_(
                           r.c.version_id == review_heads.c.version_id, r.c.sequence == review_heads.c.sequence)).where(r.c.tenant_id == tenant)).mappings()}
            result = []
            for row in db.execute(select(d).where(d.c.tenant_id == tenant).order_by(d.c.created_at.desc(), d.c.id)).mappings():
                # An upload may commit between reads under READ COMMITTED. A new
                # item missing from the captured heads appears on the next refresh.
                if row["id"] not in by_document:
                    continue
                head = by_document[row["id"]]
                review = reviews.get(head["id"])
                status = version_status(head, review, now)
                if role == "auditor" and status != "approved":
                    continue
                result.append({**dict(row), "control_ids": strict_json_loads(row["control_ids"]),
                               "latest_version": {**head, "review": review, "status": status}})
            used = db.execute(select(func.coalesce(func.sum(v.c.size), 0)).where(v.c.tenant_id == tenant)).scalar_one()
            return {"documents": result, "used_bytes": used if role != "auditor" else None,
                    "controls": [{"id": key, "title": value["title"]} for key, value in CATALOG.items()],
                    "limits": {"file_bytes": 524288, "workspace_bytes": MAX_WORKSPACE_BYTES,
                               "documents": MAX_DOCUMENTS, "versions_per_document": MAX_VERSIONS}}

    def document_detail(self, tenant, actor, document_id):
        d, v, r = tables()
        identifier(document_id)
        with self.scoped(tenant) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator", "auditor"})
            from .hosted_repository import members
            role = db.execute(select(members.c.role).where(members.c.tenant_id == tenant, members.c.issuer == self.settings.oidc_issuer, members.c.subject == actor)).scalar_one()
            item = db.execute(select(d).where(d.c.tenant_id == tenant, d.c.id == document_id)).mappings().first()
            if not item:
                raise DocumentNotFound("Document not found.")
            now, versions = self._clock(db), []
            saved_versions = self._document_versions(db, tenant, document_id)
            reviews_by_version = {}
            for row in db.execute(select(r).where(r.c.tenant_id == tenant, r.c.version_id.in_(
                [version["id"] for version in saved_versions])).order_by(r.c.sequence)).mappings():
                reviews_by_version.setdefault(row["version_id"], []).append({key: value for key, value in row.items() if key not in {"tenant_id", "version_id"}})
            for version in saved_versions:
                reviews = reviews_by_version.get(version["id"], [])
                status = version_status(version, reviews[-1] if reviews else None, now)
                if role != "auditor" or status == "approved":
                    versions.append({**version, "reviews": reviews, "status": status})
            if not versions:
                raise DocumentNotFound("Document not found.")
            return {**dict(item), "control_ids": strict_json_loads(item["control_ids"]), "versions": versions}

    def download_document(self, tenant, actor, version_id):
        d, v, r = tables()
        identifier(version_id)
        with self.scoped(tenant, lock=True) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator", "auditor"})
            from .hosted_repository import members
            role = db.execute(select(members.c.role).where(members.c.tenant_id == tenant, members.c.issuer == self.settings.oidc_issuer, members.c.subject == actor)).scalar_one()
            version = db.execute(select(v).where(v.c.tenant_id == tenant, v.c.id == version_id)).mappings().first()
            if not version or (role == "auditor" and version_status(version, self._document_review(db, tenant, version_id), self._clock(db)) != "approved"):
                raise DocumentNotFound("Version not found.")
            raw = open_file(self.vault.cipher, version)
            self._audit(db, tenant, actor, "document.downloaded", {"version_id": version_id, "sha256": version["sha256"]})
            return version["filename"], raw

    def rotate_document_keys(self, db, tenant):
        """Participates in the existing all-or-nothing tenant vault rotation."""
        v = tables()[1]
        for row in db.execute(select(v).where(v.c.tenant_id == tenant)).mappings():
            raw = open_file(self.vault.cipher, row)
            db.execute(update(v).where(v.c.tenant_id == tenant, v.c.id == row["id"]).values(envelope=seal_file(self.vault.cipher, row, raw)))

    def audit_package(self, tenant, actor, value):
        from .audit_packages import period, inventory, package_bytes, MAX_SELECTION
        from .catalog_registry import CURRENT_CATALOG_VERSION
        from .hosted_repository import runs, audit
        from .reports import bundle_bytes
        from .validation import validate_run, digest, timestamp
        first, last = period(value["period_start"], value["period_end"])
        selected = value["version_ids"]
        if not isinstance(selected, list) or len(selected) > MAX_SELECTION or any(not isinstance(item, str) for item in selected) or len(set(selected)) != len(selected):
            raise ValueError("Select up to 100 distinct evidence versions.")
        for item in selected:
            identifier(item)
        run_id = value["run_id"]
        if run_id is not None and (not isinstance(run_id, str) or not re.fullmatch(r"run_[a-f0-9]{32}", run_id)):
            raise ValueError("Invalid snapshot selection.")
        d, v, r = tables()
        with self.scoped(tenant, lock=True) as (db, workspace):
            self._require_role(db, tenant, actor, {"admin", "operator", "auditor"})
            now = self._clock(db)
            if last.timestamp() > now + 60:
                raise ValueError("Audit periods cannot end in the future.")
            snapshot, snapshot_bytes = None, None
            if run_id is not None:
                row = db.execute(select(runs).where(runs.c.tenant_id == tenant, runs.c.id == run_id)).mappings().first()
                if not row:
                    raise DocumentNotFound("Snapshot not found.")
                run = validate_run(strict_json_loads(row["document"]))
                if digest(run) != row["sha256"]:
                    from .errors import EvidenceIntegrityError
                    raise EvidenceIntegrityError("Stored snapshot integrity failed.")
                if run["demo"] or not first <= timestamp(run["collected_at"]) < last:
                    raise ValueError("Select a live snapshot collected within the audit period.")
                snapshot = {"id": run["id"], "sha256": row["sha256"], "collected_at": run["collected_at"],
                            "control_statuses": {check["id"]: check["status"] for check in run["checks"]}}
                snapshot_bytes = bundle_bytes(run)
            files, entries = {}, []
            for version_id in selected:
                version = db.execute(select(v).where(v.c.tenant_id == tenant, v.c.id == version_id)).mappings().first()
                review = self._document_review(db, tenant, version_id)
                if not version or version_status(version, review, now) != "approved":
                    raise DocumentNotFound("Approved, unexpired version not found.")
                item = db.execute(select(d).where(d.c.tenant_id == tenant, d.c.id == version["document_id"])).mappings().one()
                from .documents import file_kind
                path = f'documents/{version_id}.{file_kind(version["filename"])}'
                files[path] = open_file(self.vault.cipher, version)
                reviews = [{key: value for key, value in row.items() if key not in {"tenant_id", "version_id"}}
                           for row in db.execute(select(r).where(r.c.tenant_id == tenant, r.c.version_id == version_id).order_by(r.c.sequence)).mappings()]
                entries.append({"id": item["id"], "title": item["title"], "owner": item["owner"],
                                "control_ids": strict_json_loads(item["control_ids"]), "path": path,
                                "version": {**{key: value for key, value in version.items() if key not in {"tenant_id", "document_id", "envelope", "scan"}},
                                            "scan": strict_json_loads(version["scan"]) if version["scan"] is not None else None}, "reviews": reviews})
            head = db.execute(select(audit.c.event_hash).where(audit.c.tenant_id == tenant).order_by(audit.c.sequence.desc()).limit(1)).scalar()
            index = {"schema_version": 1, "tenant_id": tenant, "organization": workspace["name"], "created_at": now,
                     "period_start": value["period_start"], "period_end": value["period_end"], "catalog_version": CURRENT_CATALOG_VERSION,
                     "snapshot": snapshot, "documents": entries, "control_inventory": [], "audit_head_before_export": head,
                     "limitations": "Customer assertions as of export; declared period is not proof of full-period operating effectiveness. Unsigned manifest; later withdrawals cannot recall this package."}
            index["control_inventory"] = inventory(index)
            raw, manifest_sha = package_bytes(index, files, snapshot_bytes)
            self._audit(db, tenant, actor, "audit_package.exported", {"run_id": run_id, "version_ids": selected,
                        "manifest_sha256": manifest_sha, "period_start": value["period_start"], "period_end": value["period_end"]})
            return raw, manifest_sha
