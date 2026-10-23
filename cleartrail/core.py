"""Snapshot persistence and control-level rollups with explicit coverage gaps."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from .catalog import CATALOG, PROVIDERS
from .storage import Store
from .validation import (CATALOG_VERSION, canonical as canonical, digest, rollup, summarize_checks, timestamp,
                         validate_config, validate_run)
from . import __version__


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def demo_observations() -> list[dict]:
    """Synthetic fixtures never call an external account."""
    values = [
        ("GH-MFA", "northstar-labs", "pass", {"two_factor_requirement_enabled": True}),
        ("GH-REVIEW", "northstar-labs/api", "pass", {"required_approving_review_count": 2}),
        ("GH-REVIEW", "northstar-labs/web", "pass", {"required_approving_review_count": 1}),
        ("GH-CI", "northstar-labs/api", "pass", {"required_checks": ["test", "lint"]}),
        ("GH-CI", "northstar-labs/web", "pass", {"required_checks": ["test"]}),
        ("GH-ADMIN", "northstar-labs/api", "pass", {"enforce_admins": True}),
        ("GH-ADMIN", "northstar-labs/web", "fail", {"enforce_admins": False}),
        ("AWS-ROOT-MFA", "123456789012", "pass", {"AccountMFAEnabled": 1}),
        ("AWS-CLOUDTRAIL", "organization-trail", "pass", {"IsLogging": True, "IsMultiRegionTrail": True}),
        ("AWS-S3-PUBLIC", "northstar-audit-logs", "pass", {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}),
        ("AWS-S3-PUBLIC", "northstar-assets", "fail", {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}),
        ("AWS-EBS-ENCRYPTION", "us-east-1", "pass", {"EbsEncryptionByDefault": True}),
        ("GOOGLE-2SV", "active users (12)", "pass", {"active_users": 12, "enrolled": 12}),
        ("GOOGLE-2SV-ENFORCED", "active users (12)", "fail", {"active_users": 12, "enforced": 10}),
        ("GOOGLE-ADMINS", "northstar.example", "pass", {"active_super_admins": 2}),
    ]
    return [dict(control_id=cid, provider=CATALOG[cid]["provider"], resource=resource, status=status,
                 summary=("Configuration meets this check." if status == "pass" else "Configuration needs attention."),
                 data=data, source="Synthetic demonstration fixture") for cid, resource, status, data in values]


def summarize(checks: list[dict], evidence: list[dict]) -> dict:
    return summarize_checks(checks, evidence)


def collect_observations(config: dict, demo: bool = False) -> list[dict]:
    from .connectors import collect
    observations = demo_observations() if demo else []
    if not demo:
        for provider in ("github", "google", "aws"):
            settings = config.get("providers", {}).get(provider)
            if settings is None or settings.get("enabled", True) is False:
                continue
            try:
                rows = collect(provider, settings)
                if not isinstance(rows, list) or any(not isinstance(row, dict) or row.get("control_id") not in CATALOG or CATALOG[row["control_id"]]["provider"] != provider or row.get("provider") != provider for row in rows):
                    raise ValueError("Invalid collector output.")
                observations.extend(rows)
            except Exception:
                for control in CATALOG.values():
                    if control["provider"] == provider:
                        observations.append(dict(control_id=control["id"], provider=provider, resource=PROVIDERS[provider],
                                                 status="unknown", summary="Collection failed. Check credentials, permissions, and connectivity.",
                                                 data={"collection_error": True}, source="Collector", observed_at=now()))
    return observations


def build_run(config: dict, observations: list[dict], attestations: dict, demo: bool = False,
              collection_started_at: str | None = None) -> dict:
    config = validate_config(config)
    completed = now()
    started = collection_started_at or completed
    # Callers passing previously collected observations must supply the window.
    start_time, end_time = timestamp(started), timestamp(completed)
    evidence = []
    ids = set()
    observations = list(observations)
    for cid, attestation in attestations.items():
        if cid not in CATALOG or CATALOG[cid]["provider"] != "manual":
            raise ValueError("Invalid attestation control.")
        observations.append(dict(control_id=cid, provider="manual", resource=attestation["owner"], status="manual",
                                 summary="Self-attestation recorded; independent document review is required.",
                                 data=attestation, source="Team self-attestation"))
    for observation in observations:
        if not isinstance(observation, dict) or observation.get("control_id") not in CATALOG:
            raise ValueError("Invalid observation control.")
        item = {k: observation.get(k) for k in ("control_id", "provider", "resource", "status", "summary", "data", "source")}
        observed = observation.get("observed_at", completed)
        if not start_time <= timestamp(observed) <= end_time:
            raise ValueError("Observation timestamp falls outside its collection window.")
        item.update(collected_at=observed, demo=demo)
        item["sha256"] = digest(item)
        item["id"] = "ev_" + item["sha256"][:20]
        if item["id"] not in ids:
            ids.add(item["id"])
            evidence.append(item)
    checks = []
    for cid, control in CATALOG.items():
        records = [e for e in evidence if e["control_id"] == cid]
        status = rollup(control, records)
        summary = ("A configuration gap was found." if status == "fail" else
                   "All collected resources meet this check." if status == "pass" else
                   "Human review required." if status == "manual" else "Evidence is incomplete or the integration is not configured.")
        checks.append(dict(control, status=status, summary=summary, evidence_ids=[e["id"] for e in records],
                           resource_count=len(records), has_unknown=any(e["status"] == "unknown" for e in records),
                           owner=records[0]["resource"] if records and status == "manual" else "Unassigned"))
    run = dict(id="run_" + uuid.uuid4().hex, organization=config["organization"],
               collected_at=completed, collection_started_at=started, demo=demo, checks=checks, evidence=evidence,
               summary=summarize(checks, evidence), schema_version=2, catalog_version=CATALOG_VERSION,
               config_fingerprint=digest(config), provenance={"collector":"cleartrail", "collector_version":__version__,
                                                             "scope":config, "collection_mode":"demo" if demo else "live"},
               scope="Point-in-time configuration checks for configured sources, observed during the stated collection window. Not a certification or a full SOC 2 / ISO 27001 assessment.")
    return validate_run(run, allow_legacy=False)


def collect_run(store: Store, config: dict, demo: bool = False) -> dict:
    config = validate_config(config)
    with store.collection(config["organization"], demo):
        started = now()
        observations = collect_observations(config, demo)
        run = build_run(config, observations, store.attestations(), demo, started)
        store.save_run(run)
        return run
