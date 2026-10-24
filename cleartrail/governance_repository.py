"""Encrypted, versioned governance records with independent approval."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, insert, update, func, and_

from . import governance as g
from .documents import (
    DocumentConflict,
    DocumentNotFound,
    passive_text,
    version_status,
    open_file,
)
from .validation import canonical


def tables():
    from .hosted_repository import (
        governance_records,
        governance_versions,
        governance_reviews,
    )

    return governance_records, governance_versions, governance_reviews


class GovernanceRepository:
    @staticmethod
    def _governance_reviews(db, tenant, version):
        reviews = tables()[2]
        return [
            {key: value for key, value in row.items() if key != "tenant_id"}
            for row in db.execute(
                select(reviews)
                .where(reviews.c.tenant_id == tenant, reviews.c.version_id == version)
                .order_by(reviews.c.sequence)
            ).mappings()
        ]

    @staticmethod
    def _governance_heads(db, tenant):
        records, versions, _ = tables()
        return (
            db.execute(
                select(versions)
                .join(
                    records,
                    and_(
                        records.c.tenant_id == versions.c.tenant_id,
                        records.c.id == versions.c.record_id,
                        records.c.revision == versions.c.number,
                    ),
                )
                .where(versions.c.tenant_id == tenant)
                .order_by(versions.c.created_at.desc(), versions.c.id)
            )
            .mappings()
            .all()
        )

    def _governance_view(self, db, tenant, row, reviews=None):
        payload = g.open_payload(self.vault.cipher, row)
        if reviews is None:
            reviews = self._governance_reviews(db, tenant, row["id"])
        due = payload["data"].get("next_review_date", payload["data"]["review_date"])
        today = datetime.fromtimestamp(self._clock(db), timezone.utc).date().isoformat()
        return {
            **{key: row[key] for key in g.BINDINGS},
            "payload": payload,
            "reviews": reviews,
            "status": reviews[-1]["decision"] if reviews else "pending",
            "overdue": due < today,
            "risk_scores": g.risk_scores(payload["data"])
            if row["kind"] == "risk"
            else None,
        }

    def governance_list(self, tenant, actor):
        with self.scoped(tenant) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator", "auditor"})
            # _require_role validates permission; resolve the role without trusting client state.
            from .hosted_repository import members

            role = db.execute(
                select(members.c.role).where(
                    members.c.tenant_id == tenant,
                    members.c.issuer == self.settings.oidc_issuer,
                    members.c.subject == actor,
                )
            ).scalar_one()
            result, histories = [], {}
            heads = self._governance_heads(db, tenant)
            review_table = tables()[2]
            if heads:
                for review in db.execute(
                    select(review_table)
                    .where(
                        review_table.c.tenant_id == tenant,
                        review_table.c.version_id.in_([r["id"] for r in heads]),
                    )
                    .order_by(review_table.c.sequence)
                ).mappings():
                    histories.setdefault(review["version_id"], []).append(
                        {k: v for k, v in review.items() if k != "tenant_id"}
                    )
            for row in heads:
                reviews = histories.get(row["id"], [])
                if role == "auditor" and (
                    not reviews or reviews[-1]["decision"] != "approved"
                ):
                    continue
                result.append(self._governance_view(db, tenant, row, reviews))
            return {
                "records": result,
                "reference_count": len(g.ANNEX_REFERENCES),
                "limits": {"records": g.MAX_RECORDS, "versions": g.MAX_VERSIONS},
            }

    def governance_detail(self, tenant, actor, record_id):
        records, versions, _ = tables()
        g.identifier(record_id)
        with self.scoped(tenant) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator", "auditor"})
            from .hosted_repository import members

            role = db.execute(
                select(members.c.role).where(
                    members.c.tenant_id == tenant,
                    members.c.issuer == self.settings.oidc_issuer,
                    members.c.subject == actor,
                )
            ).scalar_one()
            head = (
                db.execute(
                    select(records).where(
                        records.c.tenant_id == tenant, records.c.id == record_id
                    )
                )
                .mappings()
                .first()
            )
            if not head:
                raise DocumentNotFound()
            visible = []
            for row in db.execute(
                select(versions)
                .where(
                    versions.c.tenant_id == tenant, versions.c.record_id == record_id
                )
                .order_by(versions.c.number.desc())
            ).mappings():
                reviews = self._governance_reviews(db, tenant, row["id"])
                if role == "auditor" and (
                    not reviews or reviews[-1]["decision"] != "approved"
                ):
                    continue
                visible.append(self._governance_view(db, tenant, row, reviews))
            if not visible:
                raise DocumentNotFound()
            return {
                "record_id": record_id,
                "revision": head["revision"] if role != "auditor" else None,
                "versions": visible,
            }

    def governance_options(self, tenant, actor):
        owners = self.document_owners(tenant, actor)
        records = self.governance_list(tenant, actor)["records"]
        return {
            "owners": owners,
            "evidence": self.audit_options(tenant, actor),
            "related": [
                {
                    "id": r["id"],
                    "title": r["title"],
                    "kind": r["kind"],
                    "number": r["number"],
                }
                for r in records
                if r["status"] == "approved"
            ],
            "annex_references": list(g.ANNEX_REFERENCES),
        }

    def _governance_links(self, db, tenant, kind, payload, *, approved=False):
        """Tenant lock serializes link validation against withdrawals/expiry."""
        from .hosted_repository import document_versions

        versions = tables()[1]
        for version_id in payload["evidence_version_ids"]:
            row = (
                db.execute(
                    select(document_versions).where(
                        document_versions.c.tenant_id == tenant,
                        document_versions.c.id == version_id,
                    )
                )
                .mappings()
                .first()
            )
            if not row:
                raise DocumentNotFound()
            if approved:
                if (
                    version_status(
                        row,
                        self._document_review(db, tenant, version_id),
                        self._clock(db),
                    )
                    != "approved"
                ):
                    raise DocumentConflict()
                open_file(self.vault.cipher, row)
        for version_id in payload["related_version_ids"]:
            row = (
                db.execute(
                    select(versions).where(
                        versions.c.tenant_id == tenant, versions.c.id == version_id
                    )
                )
                .mappings()
                .first()
            )
            if not row:
                raise DocumentNotFound()
            if kind == "applicability" and row["kind"] != "risk":
                raise ValueError(
                    "Applicability relationships must reference risk versions."
                )
            if approved:
                history = self._governance_reviews(db, tenant, version_id)
                if not history or history[-1]["decision"] != "approved":
                    raise DocumentConflict()
                g.open_payload(self.vault.cipher, row)

    def save_governance(self, tenant, actor, value):
        records, versions, _ = tables()
        kind = value["kind"]
        payload = g.validate_payload(kind, value["payload"])
        title = passive_text(value["title"], maximum=160)
        owner = passive_text(value["owner"], maximum=255)
        record_id = (
            g.identifier(value["record_id"])
            if value["record_id"] is not None
            else str(uuid.uuid4())
        )
        expected = value["expected_revision"]
        reference = payload["data"]["reference"] if kind == "applicability" else None
        raw = canonical(payload)
        with self.scoped(tenant, lock=True) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator"})
            self._require_role(db, tenant, owner, {"admin", "operator"})
            if kind == "internal_audit":
                self._require_role(
                    db,
                    tenant,
                    payload["data"]["auditor"],
                    {"admin", "operator", "auditor"},
                )
                if payload["data"]["auditor"] == owner:
                    raise ValueError(
                        "The audit assessor must differ from the responsible owner."
                    )
            head = (
                db.execute(
                    select(records).where(
                        records.c.tenant_id == tenant, records.c.id == record_id
                    )
                )
                .mappings()
                .first()
            )
            if value["record_id"] is not None and not head:
                raise DocumentNotFound()
            if head and (
                type(expected) is not int
                or expected != head["revision"]
                or kind != head["kind"]
                or reference != head["reference"]
            ):
                raise DocumentConflict()
            if not head and expected is not None:
                raise DocumentConflict()
            if (
                not head
                and db.execute(
                    select(func.count())
                    .select_from(records)
                    .where(records.c.tenant_id == tenant)
                ).scalar_one()
                >= g.MAX_RECORDS
            ):
                raise ValueError("Governance record quota reached.")
            if (
                not head
                and reference is not None
                and db.execute(
                    select(records.c.id).where(
                        records.c.tenant_id == tenant,
                        records.c.kind == kind,
                        records.c.reference == reference,
                    )
                ).first()
            ):
                raise DocumentConflict()
            number = head["revision"] + 1 if head else 1
            used = db.execute(
                select(func.coalesce(func.sum(versions.c.size), 0)).where(
                    versions.c.tenant_id == tenant
                )
            ).scalar_one()
            if number > g.MAX_VERSIONS or used + len(raw) > g.MAX_TOTAL_BYTES:
                raise ValueError("Governance version or storage quota reached.")
            self._governance_links(db, tenant, kind, payload)
            if (
                payload["related_version_ids"]
                and db.execute(
                    select(versions.c.id).where(
                        versions.c.tenant_id == tenant,
                        versions.c.record_id == record_id,
                        versions.c.id.in_(payload["related_version_ids"]),
                    )
                ).first()
            ):
                raise ValueError("A record cannot depend on its own revisions.")
            now = self._clock(db)
            if not head:
                db.execute(
                    insert(records).values(
                        tenant_id=tenant,
                        id=record_id,
                        kind=kind,
                        reference=reference,
                        revision=number,
                    )
                )
            else:
                db.execute(
                    update(records)
                    .where(records.c.tenant_id == tenant, records.c.id == record_id)
                    .values(revision=number)
                )
            row = {
                "tenant_id": tenant,
                "id": str(uuid.uuid4()),
                "record_id": record_id,
                "number": number,
                "kind": kind,
                "title": title,
                "owner": owner,
                "reference": reference,
                "created_by": actor,
                "created_at": now,
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            db.execute(
                insert(versions).values(
                    **row, envelope=g.seal(self.vault.cipher, row, payload)
                )
            )
            self._audit(
                db,
                tenant,
                actor,
                "governance.version_created",
                {
                    "record_id": record_id,
                    "version_id": row["id"],
                    "kind": kind,
                    "number": number,
                    "sha256": row["sha256"],
                },
            )
            return {"record_id": record_id, "version_id": row["id"], "revision": number}

    def review_governance(
        self, tenant, actor, version_id, decision, comment, expected_review_id
    ):
        records, versions, reviews = tables()
        g.identifier(version_id)
        if expected_review_id is not None:
            g.identifier(expected_review_id)
        if not isinstance(decision, str) or decision not in {
            "approved",
            "rejected",
            "withdrawn",
        }:
            raise ValueError("Invalid review decision.")
        comment = passive_text(comment, maximum=2000, multiline=True)
        with self.scoped(tenant, lock=True) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator"})
            row = (
                db.execute(
                    select(versions).where(
                        versions.c.tenant_id == tenant, versions.c.id == version_id
                    )
                )
                .mappings()
                .first()
            )
            if not row:
                raise DocumentNotFound()
            head = (
                db.execute(
                    select(records).where(
                        records.c.tenant_id == tenant, records.c.id == row["record_id"]
                    )
                )
                .mappings()
                .one()
            )
            current_owner = db.execute(
                select(versions.c.owner).where(
                    versions.c.tenant_id == tenant,
                    versions.c.record_id == row["record_id"],
                    versions.c.number == head["revision"],
                )
            ).scalar_one()
            history = self._governance_reviews(db, tenant, version_id)
            if expected_review_id != (history[-1]["id"] if history else None) or (
                decision != "withdrawn" and row["number"] != head["revision"]
            ):
                raise DocumentConflict()
            if decision != "withdrawn" and actor in {
                row["owner"],
                row["created_by"],
                current_owner,
            }:
                raise PermissionError("An independent reviewer is required.")
            if decision != "withdrawn":
                payload = g.open_payload(self.vault.cipher, row)
                if decision == "approved":
                    self._governance_links(
                        db, tenant, row["kind"], payload, approved=True
                    )
                    if (
                        g.needs_evidence(row["kind"], payload["data"])
                        and not payload["evidence_version_ids"]
                    ):
                        raise ValueError(
                            "Implemented controls and completed actions need approved evidence."
                        )
            sequence = len(history) + 1
            if sequence > g.MAX_REVIEWS or (
                sequence == g.MAX_REVIEWS and decision == "approved"
            ):
                raise ValueError("Review quota reached.")
            review = {
                "id": str(uuid.uuid4()),
                "version_id": version_id,
                "sequence": sequence,
                "decision": decision,
                "reviewer": actor,
                "comment": comment,
                "created_at": self._clock(db),
            }
            db.execute(insert(reviews).values(tenant_id=tenant, **review))
            self._audit(
                db,
                tenant,
                actor,
                "governance.reviewed",
                {
                    "version_id": version_id,
                    "decision": decision,
                    "review_id": review["id"],
                    "sha256": row["sha256"],
                },
            )
            return review

    def governance_export(self, tenant, actor):
        from . import __version__

        versions = tables()[1]
        with self.scoped(tenant, lock=True) as (db, _):
            self._require_role(db, tenant, actor, {"admin", "operator", "auditor"})
            result, pending, seen = [], [], set()
            for row in self._governance_heads(db, tenant):
                history = self._governance_reviews(db, tenant, row["id"])
                if history and history[-1]["decision"] == "approved":
                    pending.append(row["id"])
            while pending:
                version_id = pending.pop()
                if version_id in seen:
                    continue
                if len(seen) >= 500:
                    raise ValueError("Register dependency budget reached.")
                seen.add(version_id)
                row = (
                    db.execute(
                        select(versions).where(
                            versions.c.tenant_id == tenant, versions.c.id == version_id
                        )
                    )
                    .mappings()
                    .first()
                )
                if not row:
                    raise DocumentNotFound()
                view = self._governance_view(db, tenant, row)
                if view["status"] != "approved":
                    raise DocumentConflict()
                self._governance_links(
                    db, tenant, row["kind"], view["payload"], approved=True
                )
                result.append(
                    {
                        key: value
                        for key, value in view.items()
                        if key not in {"status", "overdue"}
                    }
                )
                pending.extend(view["payload"]["related_version_ids"])
            if not result:
                raise DocumentConflict()
            value = {
                "format": g.EXPORT_FORMAT,
                "schema": 1,
                "generator": __version__,
                "tenant_id": tenant,
                "exported_at": self._clock(db),
                "records": sorted(result, key=lambda r: r["id"]),
                "limitations": g.LIMITATIONS,
            }
            raw = canonical(value)
            if len(raw) > g.MAX_EXPORT:
                raise ValueError("Register export budget reached.")
            sha = hashlib.sha256(raw).hexdigest()
            self._audit(
                db,
                tenant,
                actor,
                "governance.exported",
                {"versions": sorted(seen), "sha256": sha},
            )
            return raw, sha

    def rotate_governance_keys(self, db, tenant):
        versions = tables()[1]
        for row in db.execute(
            select(versions).where(versions.c.tenant_id == tenant)
        ).mappings():
            payload = g.open_payload(self.vault.cipher, row)
            db.execute(
                update(versions)
                .where(versions.c.tenant_id == tenant, versions.c.id == row["id"])
                .values(envelope=g.seal(self.vault.cipher, row, payload))
            )
