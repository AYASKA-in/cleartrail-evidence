"""Original governance record schemas, not reproductions of licensed standards.

Framework references describe context. A reviewed record never changes an
automated setting result or certifies operating effectiveness.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import date
from pathlib import Path

from .documents import passive_text
from .validation import canonical, strict_json_loads

KINDS = {
    "risk",
    "applicability",
    "internal_audit",
    "management_review",
    "corrective_action",
}
ANNEX_REFERENCES = tuple(
    f"A.{group}.{number}"
    for group, count in ((5, 37), (6, 8), (7, 14), (8, 34))
    for number in range(1, count + 1)
)
MAX_RECORDS, MAX_VERSIONS, MAX_REVIEWS = 250, 20, 20
MAX_PAYLOAD, MAX_TOTAL_BYTES, MAX_EXPORT = 16384, 20 * 1024 * 1024, 12 * 1024 * 1024
FIELDS = {
    "risk": {
        "scope",
        "scenario",
        "likelihood",
        "impact",
        "treatment",
        "plan",
        "residual_likelihood",
        "residual_impact",
        "review_date",
    },
    "applicability": {
        "reference",
        "applicability",
        "basis",
        "implementation",
        "description",
        "review_date",
    },
    "internal_audit": {
        "scope",
        "criteria",
        "auditor",
        "period_start",
        "period_end",
        "findings",
        "conclusion",
        "review_date",
    },
    "management_review": {
        "review_date",
        "participants",
        "inputs",
        "decisions",
        "actions",
        "next_review_date",
    },
    "corrective_action": {
        "finding",
        "cause",
        "action",
        "due_date",
        "state",
        "verification",
        "review_date",
    },
}
DATES = {"review_date", "next_review_date", "due_date", "period_start", "period_end"}
SCORES = {"likelihood", "impact", "residual_likelihood", "residual_impact"}
EXPORT_FORMAT = "cleartrail-governance-register"


def identifier(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("Use a canonical record identifier.")
    return value


def ids(values, maximum=10):
    if (
        not isinstance(values, list)
        or len(values) > maximum
        or any(not isinstance(v, str) for v in values)
        or len(set(values)) != len(values)
    ):
        raise ValueError("Choose distinct bounded version references.")
    return [identifier(v) for v in values]


def iso_date(value):
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value)
        or date.fromisoformat(value).isoformat() != value
    ):
        raise ValueError("Use a calendar date in YYYY-MM-DD format.")
    return value


def validate_data(kind, value):
    if (
        not isinstance(kind, str)
        or kind not in KINDS
        or not isinstance(value, dict)
        or set(value) != FIELDS[kind]
    ):
        raise ValueError("Invalid governance fields.")
    result = {}
    for key, item in value.items():
        if key in SCORES:
            if type(item) is not int or not 1 <= item <= 5:
                raise ValueError("Likelihood and impact must be integers from 1 to 5.")
            result[key] = item
        elif key in DATES:
            result[key] = iso_date(item)
        else:
            result[key] = passive_text(
                item, maximum=3000 if key != "auditor" else 255, multiline=True
            )
    if kind == "risk" and result["treatment"] not in {
        "mitigate",
        "accept",
        "avoid",
        "transfer",
    }:
        raise ValueError("Invalid risk treatment.")
    if kind == "applicability":
        if result["reference"] not in ANNEX_REFERENCES or result[
            "applicability"
        ] not in {"applicable", "not_applicable"}:
            raise ValueError("Invalid applicability reference or decision.")
        allowed = (
            {"planned", "in_progress", "implemented"}
            if result["applicability"] == "applicable"
            else {"not_applicable"}
        )
        if result["implementation"] not in allowed:
            raise ValueError("Implementation state does not match applicability.")
    if kind == "internal_audit" and result["period_end"] < result["period_start"]:
        raise ValueError("The audit end date precedes its start.")
    if (
        kind == "management_review"
        and result["next_review_date"] <= result["review_date"]
    ):
        raise ValueError("The next management review must follow this review.")
    if kind == "corrective_action" and result["state"] not in {
        "open",
        "in_progress",
        "completed",
    }:
        raise ValueError("Invalid corrective action state.")
    if len(canonical(result)) > MAX_PAYLOAD:
        raise ValueError("Governance record exceeds its size budget.")
    return result


def risk_scores(data):
    def score(likelihood, impact):
        value = likelihood * impact
        return {
            "score": value,
            "band": "critical"
            if value >= 16
            else "high"
            if value >= 10
            else "medium"
            if value >= 5
            else "low",
        }

    return {
        "inherent": score(data["likelihood"], data["impact"]),
        "residual": score(data["residual_likelihood"], data["residual_impact"]),
    }


def needs_evidence(kind, data):
    return (kind == "applicability" and data["implementation"] == "implemented") or (
        kind == "corrective_action" and data["state"] == "completed"
    )


BINDINGS = (
    "tenant_id",
    "id",
    "record_id",
    "number",
    "kind",
    "title",
    "owner",
    "reference",
    "created_by",
    "created_at",
    "size",
    "sha256",
)


def seal(cipher, row, payload):
    return cipher.encrypt(
        canonical(
            {
                "schema": 1,
                "context": {key: row[key] for key in BINDINGS},
                "payload": payload,
            }
        )
    ).decode("ascii")


def open_payload(cipher, row):
    from cryptography.fernet import InvalidToken
    from .errors import EvidenceIntegrityError

    try:
        value = strict_json_loads(cipher.decrypt(row["envelope"].encode("ascii")))
        if (
            set(value) != {"schema", "context", "payload"}
            or type(value["schema"]) is not int
            or value["schema"] != 1
            or value["context"] != {key: row[key] for key in BINDINGS}
        ):
            raise ValueError("Context mismatch.")
        payload = validate_payload(row["kind"], value["payload"])
        raw = canonical(payload)
        if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise ValueError("Payload mismatch.")
        return payload
    except (
        InvalidToken,
        ValueError,
        KeyError,
        TypeError,
        UnicodeError,
        RecursionError,
    ):
        raise EvidenceIntegrityError(
            "Governance record failed integrity checks."
        ) from None


def validate_payload(kind, value):
    if not isinstance(value, dict) or set(value) != {
        "data",
        "evidence_version_ids",
        "related_version_ids",
    }:
        raise ValueError("Invalid record payload.")
    result = {
        "data": validate_data(kind, value["data"]),
        "evidence_version_ids": ids(value["evidence_version_ids"]),
        "related_version_ids": ids(value["related_version_ids"]),
    }
    if len(canonical(result)) > MAX_PAYLOAD:
        raise ValueError("Record payload is too large.")
    return result


def verify_governance(path, expected_sha256=None):
    try:
        return _verify_governance(path, expected_sha256)
    except (TypeError, KeyError, RecursionError, AttributeError):
        raise ValueError("Malformed governance register.") from None


def _verify_governance(path, expected_sha256=None):
    """Validate a bounded register without importing hosted/crypto dependencies."""
    path = Path(path)
    with path.open("rb") as stream:
        raw = stream.read(MAX_EXPORT + 1)
    if len(raw) > MAX_EXPORT:
        raise ValueError("Register exceeds its export budget.")
    sha = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str)
        or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
        or sha != expected_sha256
    ):
        raise ValueError("Register does not match the trusted digest.")
    value = strict_json_loads(raw)
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "format",
            "schema",
            "generator",
            "tenant_id",
            "exported_at",
            "records",
            "limitations",
        }
        or value["format"] != EXPORT_FORMAT
        or type(value["schema"]) is not int
        or value["schema"] != 1
    ):
        raise ValueError("Unsupported governance register.")
    identifier(value["tenant_id"])
    if (
        type(value["exported_at"]) is not int
        or value["exported_at"] < 0
        or value["generator"] != "0.6.0"
        or value["limitations"] != LIMITATIONS
    ):
        raise ValueError("Invalid register metadata.")
    records = value["records"]
    if not isinstance(records, list) or not 1 <= len(records) <= 500:
        raise ValueError("Invalid register population.")
    seen, versions, identities, all_reviews, references = set(), {}, {}, set(), {}
    for record in records:
        if (
            not isinstance(record, dict)
            or set(record) != set(BINDINGS) | {"payload", "reviews", "risk_scores"}
            or record["tenant_id"] != value["tenant_id"]
        ):
            raise ValueError("Invalid record context.")
        identifier(record["id"])
        identifier(record["record_id"])
        if (
            record["id"] in seen
            or type(record["number"]) is not int
            or not 1 <= record["number"] <= MAX_VERSIONS
        ):
            raise ValueError("Invalid or duplicate version.")
        seen.add(record["id"])
        identity = (record["kind"], record["reference"])
        if (
            record["record_id"] in identities
            and identities[record["record_id"]] != identity
        ):
            raise ValueError("Record identity changed between versions.")
        identities[record["record_id"]] = identity
        if len(identities) > MAX_RECORDS:
            raise ValueError("Record quota exceeded.")
        version_key = (record["record_id"], record["number"])
        if version_key in versions:
            raise ValueError("Duplicate record revision.")
        versions[version_key] = record["id"]
        for key in ("title", "owner", "created_by"):
            passive_text(record[key], maximum=160 if key == "title" else 255)
        if (
            type(record["created_at"]) is not int
            or not 0 <= record["created_at"] <= value["exported_at"]
        ):
            raise ValueError("Invalid record time.")
        payload = validate_payload(record["kind"], record["payload"])
        if record["reference"] != (
            payload["data"]["reference"] if record["kind"] == "applicability" else None
        ):
            raise ValueError("Invalid applicability context.")
        if record["reference"] is not None:
            if (
                record["reference"] in references
                and references[record["reference"]] != record["record_id"]
            ):
                raise ValueError("Duplicate applicability record.")
            references[record["reference"]] = record["record_id"]
        if (
            type(record["size"]) is not int
            or record["size"] != len(canonical(payload))
            or record["sha256"] != hashlib.sha256(canonical(payload)).hexdigest()
        ):
            raise ValueError("Invalid payload digest.")
        if canonical(record["risk_scores"]) != canonical(
            risk_scores(payload["data"]) if record["kind"] == "risk" else None
        ):
            raise ValueError("Invalid risk calculation.")
        if (
            record["kind"] == "internal_audit"
            and payload["data"]["auditor"] == record["owner"]
        ):
            raise ValueError("The audit assessor must be independent of the owner.")
        reviews = record["reviews"]
        if not isinstance(reviews, list) or not 1 <= len(reviews) <= MAX_REVIEWS:
            raise ValueError("Independent approval is required.")
        previous_time = record["created_at"]
        for sequence, review in enumerate(reviews, 1):
            if not isinstance(review, dict) or set(review) != {
                "id",
                "version_id",
                "sequence",
                "decision",
                "reviewer",
                "comment",
                "created_at",
            }:
                raise ValueError("Invalid review history.")
            identifier(review["id"])
            if (
                review["id"] in all_reviews
                or review["version_id"] != record["id"]
                or type(review["sequence"]) is not int
                or review["sequence"] != sequence
                or review["decision"] not in {"approved", "rejected", "withdrawn"}
            ):
                raise ValueError("Invalid review sequence.")
            all_reviews.add(review["id"])
            passive_text(review["reviewer"], maximum=255)
            passive_text(review["comment"], maximum=2000, multiline=True)
            if review["decision"] != "withdrawn" and review["reviewer"] in {
                record["owner"],
                record["created_by"],
            }:
                raise ValueError("Review is not independent.")
            if (
                type(review["created_at"]) is not int
                or not previous_time <= review["created_at"] <= value["exported_at"]
            ):
                raise ValueError("Invalid review time.")
            previous_time = review["created_at"]
        if reviews[-1]["decision"] != "approved" or (
            len(reviews) == MAX_REVIEWS and reviews[-1]["decision"] == "approved"
        ):
            raise ValueError("Version is not approved.")
        if (
            needs_evidence(record["kind"], payload["data"])
            and not payload["evidence_version_ids"]
        ):
            raise ValueError("Supporting evidence is required.")
    by_id = {r["id"]: r for r in records}
    for record in records:
        links = record["payload"]["related_version_ids"]
        if any(link not in seen for link in links):
            raise ValueError("Referenced governance versions are missing.")
        if any(
            by_id[link]["created_at"] > record["created_at"]
            or by_id[link]["record_id"] == record["record_id"]
            for link in links
        ):
            raise ValueError("Invalid governance dependency.")
        if record["kind"] == "applicability" and any(
            by_id[link]["kind"] != "risk" for link in links
        ):
            raise ValueError("Applicability relationships must reference risks.")
    # Iterative graph walk: attacker-controlled nesting never consumes the call stack.
    active, done = set(), set()
    for root in by_id:
        stack = [(root, False)]
        while stack:
            node, leaving = stack.pop()
            if leaving:
                active.remove(node)
                done.add(node)
            elif node not in done:
                if node in active:
                    raise ValueError("Cyclic governance dependencies.")
                active.add(node)
                stack.append((node, True))
                stack.extend(
                    (link, False)
                    for link in by_id[node]["payload"]["related_version_ids"]
                )
    return {
        "valid": True,
        "records": len(records),
        "sha256": sha,
        "trusted_digest_matched": expected_sha256 is not None,
        "limitations": LIMITATIONS,
    }


LIMITATIONS = "Unsigned customer governance records, approved as of export. Linked evidence files are not embedded or authenticated by this register; use document audit packages for their bytes. Approval, risk scores and framework references do not establish certification, provider truth or period operating effectiveness. Later withdrawals cannot recall exports."
