"""Bounded, strict boundaries for configuration and portable evidence records.

This module has no storage or network side effects and is shared by both editions.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from datetime import datetime

from .catalog_registry import CURRENT_CATALOG_VERSION, get_catalog

CATALOG_VERSION = CURRENT_CATALOG_VERSION

MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_EVIDENCE = 12000
STATES = {"pass", "fail", "unknown", "manual"}
SECRET_FIELDS = {"token", "access_token", "refresh_token", "authorization", "password", "private_key", "client_secret", "aws_secret_access_key", "aws_session_token"}


def canonical(value) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid JSON data.") from exc


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_json_loads(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("Duplicate JSON object keys are not permitted.")
            result[key] = item
        return result

    def invalid_constant(_):
        raise ValueError("Non-finite JSON values are not permitted.")

    try:
        return json.loads(value, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (TypeError, UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid JSON document.") from exc


def text(value, *, maximum=4000, empty=False, multiline=False):
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise ValueError("A text field is missing or outside its size limit.")
    if any((ord(c) < 32 and (not multiline or c not in "\t\n\r")) or 0xD800 <= ord(c) <= 0xDFFF or ord(c) == 127 for c in value):
        raise ValueError("A text field contains unsupported characters.")
    return value


def timestamp(value):
    text(value, maximum=64)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid evidence timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Evidence timestamps must include a timezone.")
    return parsed


def bounded_json(value, *, reject_secrets=False):
    remaining = [200000]

    def visit(item, depth):
        remaining[0] -= 1
        if depth > 20 or remaining[0] < 0:
            raise ValueError("JSON data exceeds structural limits.")
        if isinstance(item, dict):
            for key, child in item.items():
                text(key, maximum=256, empty=True)
                if reject_secrets and key.casefold().replace("-", "_") in SECRET_FIELDS:
                    raise ValueError("Credential fields must not enter evidence.")
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, str):
            text(item, maximum=16384, empty=True, multiline=True)
        elif type(item) is float:
            if not math.isfinite(item):
                raise ValueError("Non-finite JSON values are not permitted.")
        elif item is not None and type(item) not in {bool, int}:
            raise ValueError("Unsupported evidence value type.")
        elif type(item) is int and abs(item) > 2 ** 63 - 1:
            raise ValueError("Evidence integer exceeds its range.")

    visit(value, 0)


def validate_config(config: dict) -> dict:
    """Return a fresh normalized scope. Credentials are rejected, never ignored."""
    if not isinstance(config, dict) or set(config) - {"organization", "providers"}:
        raise ValueError("Configuration accepts only organization and providers; keep credentials outside it.")
    organization = text(config.get("organization", "Your organization"), maximum=200).strip()
    providers = config.get("providers", {})
    if not isinstance(providers, dict) or set(providers) - {"github", "google", "aws"}:
        raise ValueError("Providers must be github, google, or aws objects.")
    allowed = {"github": {"enabled", "org", "expected_repositories"}, "google": {"enabled", "customer"},
               "aws": {"enabled", "profile", "region", "expected_account_id"}}
    result = {"organization": organization, "providers": {}}
    for provider, settings in providers.items():
        if not isinstance(settings, dict) or set(settings) - allowed[provider]:
            raise ValueError("Provider configuration contains unsupported fields. Credentials do not belong in configuration.")
        enabled = settings.get("enabled", True)
        if type(enabled) is not bool:
            raise ValueError("Provider enabled flags must be booleans.")
        clean = {"enabled": enabled}
        for key, value in settings.items():
            if key == "enabled":
                continue
            if key == "expected_repositories":
                if not isinstance(value, list) or not value or len(value) > 1000 or any(not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", v) for v in value) or len({v.casefold() for v in value}) != len(value):
                    raise ValueError("Expected repositories must be a distinct list of repository names.")
                clean[key] = sorted(value, key=str.casefold)
            else:
                clean[key] = text(value, maximum=200).strip()
        if "org" in clean and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", clean["org"]):
            raise ValueError("Configure a valid GitHub organization name.")
        if "expected_account_id" in clean and not re.fullmatch(r"[0-9]{12}", clean["expected_account_id"]):
            raise ValueError("AWS expected_account_id must contain 12 digits.")
        if "region" in clean and not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+", clean["region"]):
            raise ValueError("Configure a valid AWS region name.")
        result["providers"][provider] = clean
    return result


def summarize_checks(checks, evidence):
    counts = Counter(c["status"] for c in checks)
    total = len(checks)
    return dict(total=total, passed=counts["pass"], failed=counts["fail"], unknown=counts["unknown"],
                manual=counts["manual"], evidence_count=len(evidence),
                pass_percent=round(100 * counts["pass"] / total) if total else 0,
                coverage_percent=round(100 * (counts["pass"] + counts["fail"]) / total) if total else 0)


def rollup(control, records):
    states = {r["status"] for r in records}
    if control["provider"] == "manual":
        return "manual"
    if "fail" in states:
        return "fail"
    return "pass" if states == {"pass"} else "unknown"


def validate_run(run: dict, *, allow_legacy=True) -> dict:
    """Reject structurally or logically inconsistent evidence, including valid rehashes.

    Integrity is relative to this record, never a claim of source authenticity.
    """
    if not isinstance(run, dict) or type(run.get("schema_version")) is not int:
        raise ValueError("Invalid snapshot object or schema version.")
    version = run["schema_version"]
    if version not in {1, 2} or (version == 1 and not allow_legacy):
        raise ValueError("Unsupported evidence schema version.")
    base = {"id", "organization", "collected_at", "demo", "checks", "evidence", "summary", "schema_version", "scope"}
    extra = {"catalog_version", "config_fingerprint", "collection_started_at", "provenance"} if version == 2 else set()
    if set(run) != base | extra:
        raise ValueError("Snapshot fields do not match the declared schema.")
    catalog = get_catalog(run["catalog_version"] if version == 2 else "2026.10.1")
    if not isinstance(run["id"], str) or not re.fullmatch(r"run_[a-f0-9]{16,32}", run["id"]):
        raise ValueError("Invalid snapshot identifier.")
    if type(run["demo"]) is not bool:
        raise ValueError("Snapshot demo flag must be a boolean.")
    text(run["organization"], maximum=200)
    text(run["scope"], maximum=4000, multiline=True)
    finished = timestamp(run["collected_at"])
    started = None
    if version == 2:
        if not isinstance(run["config_fingerprint"], str) or not re.fullmatch(r"[a-f0-9]{64}", run["config_fingerprint"]):
            raise ValueError("Unsupported catalog version or invalid scope fingerprint.")
        started = timestamp(run["collection_started_at"])
        if finished < started:
            raise ValueError("Collection completion precedes its start.")
        provenance = run["provenance"]
        if not isinstance(provenance, dict) or set(provenance) != {"collector", "collector_version", "scope", "collection_mode"} or provenance["collector"] != "cleartrail" or provenance["collection_mode"] != ("demo" if run["demo"] else "live"):
            raise ValueError("Invalid snapshot provenance.")
        text(provenance["collector_version"], maximum=40)
        if validate_config(provenance["scope"]) != provenance["scope"] or digest(provenance["scope"]) != run["config_fingerprint"] or provenance["scope"]["organization"] != run["organization"]:
            raise ValueError("Scope fingerprint or organization does not match provenance.")
    evidence = run["evidence"]
    checks = run["checks"]
    if not isinstance(evidence, list) or len(evidence) > MAX_EVIDENCE or not isinstance(checks, list) or len(checks) != len(catalog):
        raise ValueError("Invalid evidence or control population.")
    by_id = {}
    by_control = {cid: [] for cid in catalog}
    evidence_fields = {"id", "sha256", "control_id", "provider", "resource", "status", "summary", "data", "source", "collected_at", "demo"}
    for item in evidence:
        if not isinstance(item, dict) or set(item) != evidence_fields:
            raise ValueError("Invalid evidence record fields.")
        cid = item["control_id"]
        if not isinstance(cid, str) or cid not in catalog or item["provider"] != catalog[cid]["provider"]:
            raise ValueError("Evidence provider or control identity does not match.")
        if not isinstance(item["status"], str) or item["status"] not in STATES or (item["provider"] == "manual") != (item["status"] == "manual") or type(item["demo"]) is not bool or item["demo"] != run["demo"]:
            raise ValueError("Invalid evidence outcome or demonstration flag.")
        for key in ("resource", "summary", "source"):
            text(item[key], maximum=4000, multiline=key == "summary")
        observed = timestamp(item["collected_at"])
        if version == 2 and not started <= observed <= finished:
            raise ValueError("Observation timestamp falls outside the collection window.")
        if not isinstance(item["data"], dict):
            raise ValueError("Evidence data must be an object.")
        bounded_json(item["data"], reject_secrets=True)
        if version == 2 and item["provider"] == "manual":
            data = item["data"]
            if (set(data) != {"owner", "note", "recorded_at", "kind", "independently_verified"}
                    or data["kind"] != "self-attestation" or data["independently_verified"] is not False):
                raise ValueError("Manual evidence must remain an unverified self-attestation.")
            text(data["owner"], maximum=120)
            text(data["note"], maximum=4000, multiline=True)
            timestamp(data["recorded_at"])
            if data["owner"] != item["resource"]:
                raise ValueError("Manual evidence owner does not match its resource.")
        if len(canonical(item["data"])) > 128 * 1024:
            raise ValueError("Evidence data exceeds its size limit.")
        sha = digest({key: value for key, value in item.items() if key not in {"id", "sha256"}})
        if item["sha256"] != sha or item["id"] != "ev_" + sha[:20]:
            raise ValueError("Evidence record integrity failed.")
        if item["id"] in by_id:
            raise ValueError("Duplicate evidence identifier.")
        by_id[item["id"]] = item
        by_control[cid].append(item)
    check_fields = {"id", "title", "provider", "category", "frameworks", "remediation", "status", "summary", "evidence_ids", "resource_count", "has_unknown", "owner"}
    seen = set()
    for check in checks:
        if not isinstance(check, dict) or set(check) != check_fields:
            raise ValueError("Invalid control record fields.")
        cid = check["id"]
        if not isinstance(cid, str) or cid not in catalog or cid in seen:
            raise ValueError("Invalid or duplicate control identity.")
        seen.add(cid)
        known = catalog[cid]
        if check["provider"] != known["provider"] or not isinstance(check["frameworks"], dict) or set(check["frameworks"]) != {"SOC 2", "ISO 27001:2022"}:
            raise ValueError("Control source or framework references are invalid.")
        if version == 2 and any(check[key] != known[key] for key in ("title", "category", "frameworks", "remediation")):
            raise ValueError("Control metadata does not match the catalog version.")
        for key in ("title", "category", "remediation", "summary", "owner"):
            text(check[key], maximum=4000, multiline=key in {"summary", "remediation"})
        for reference in check["frameworks"].values():
            text(reference, maximum=100)
        records = by_control[cid]
        ids = check["evidence_ids"]
        if not isinstance(ids, list) or any(not isinstance(eid, str) for eid in ids) or len(set(ids)) != len(ids) or set(ids) != {r["id"] for r in records}:
            raise ValueError("Control evidence references do not match the evidence population.")
        if check["status"] != rollup(known, records) or type(check["resource_count"]) is not int or check["resource_count"] != len(records) or type(check["has_unknown"]) is not bool or check["has_unknown"] != any(r["status"] == "unknown" for r in records):
            raise ValueError("Control rollup is inconsistent with its evidence.")
    summary = run["summary"]
    if not isinstance(summary, dict) or any(type(value) is not int for value in summary.values()) or summary != summarize_checks(checks, evidence):
        raise ValueError("Snapshot summary does not match its controls.")
    if len(canonical(run)) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Snapshot exceeds its size limit.")
    return run
