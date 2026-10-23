"""Live monitoring metadata, kept separate from immutable evidence outcomes."""
from __future__ import annotations

from .validation import digest, timestamp
from .catalog_registry import CURRENT_CATALOG_VERSION

DEFAULT_INTERVAL_HOURS = 24
DEFAULT_FRESHNESS_HOURS = 25
SCHEDULE_GRACE_SECONDS = 600


def validate_schedule(value):
    if not isinstance(value, dict) or set(value) != {"enabled", "interval_hours", "freshness_hours"}:
        raise ValueError("Supply enabled, interval_hours and freshness_hours.")
    if type(value["enabled"]) is not bool:
        raise ValueError("Schedule enabled must be a boolean.")
    interval, freshness = value["interval_hours"], value["freshness_hours"]
    if type(interval) is not int or interval not in {1, 6, 12, 24, 168}:
        raise ValueError("Choose hourly, 6-hourly, 12-hourly, daily or weekly collection.")
    if type(freshness) is not int or not interval <= freshness <= 720:
        raise ValueError("Freshness must cover the collection interval and be at most 720 hours.")
    return dict(value)


def monitoring_projection(run):
    """Small immutable-source projection for polling, without the full evidence."""
    oldest = {}
    for record in run["evidence"]:
        provider = record["provider"]
        if provider != "manual":
            observed = record["collected_at"]
            if provider not in oldest or timestamp(observed) < timestamp(oldest[provider]):
                oldest[provider] = observed
    return {"id": run["id"], "collected_at": run["collected_at"], "config_fingerprint": run.get("config_fingerprint"),
            "catalog_version": run.get("catalog_version"),
            "checks": [{"provider": c["provider"], "status": c["status"], "has_unknown": c["has_unknown"]}
                       for c in run["checks"] if c["provider"] != "manual"],
            "evidence": [{"provider": p, "collected_at": value} for p, value in sorted(oldest.items())]}


def evidence_health(run, config, freshness_hours, now_epoch, latest_job):
    """Describe current relevance without changing saved pass/fail results."""
    providers = {name for name, value in config["providers"].items() if value.get("enabled", True)}
    result = {"status": "missing", "snapshot_id": run["id"] if run else None,
              "freshness_hours": freshness_hours, "providers": {}, "age_seconds": None,
              "message": "No snapshot has been collected for this workspace."}
    if not providers:
        result.update(status="no_sources", message="Configure a provider before relying on automated evidence.")
        return result
    if not run:
        if latest_job.get("status") == "failed":
            result.update(status="collection_failed", message="Collection failed; no saved snapshot is available.")
        return result
    finished = timestamp(run["collected_at"]).timestamp()
    result["age_seconds"] = max(0, int(now_epoch - finished))
    if finished > now_epoch + 300:
        result.update(status="clock_error", message="Snapshot time is ahead of the service clock. Check time synchronization.")
        return result
    if run.get("config_fingerprint") != digest(config):
        result.update(status="scope_changed", message="Provider scope changed. Collect a new snapshot for the current configuration.")
        return result
    if run.get("catalog_version") != CURRENT_CATALOG_VERSION:
        result.update(status="catalog_changed", message="The control catalog changed. Collect a new snapshot for the current rules.")
        return result
    for provider in sorted(providers):
        checks = [c for c in run["checks"] if c["provider"] == provider]
        records = [e for e in run["evidence"] if e["provider"] == provider]
        oldest = min((timestamp(e["collected_at"]).timestamp() for e in records), default=finished)
        age = max(0, int(now_epoch - oldest))
        incomplete = not records or not checks or any(c["status"] == "unknown" or c["has_unknown"] for c in checks)
        state = "stale" if age >= freshness_hours * 3600 else "incomplete" if incomplete else "current"
        result["providers"][provider] = {"status": state, "age_seconds": age, "incomplete": incomplete}
    states = {p["status"] for p in result["providers"].values()}
    if "stale" in states:
        result.update(status="stale", message="Evidence is older than the workspace freshness policy. Saved results are historical.")
    elif "incomplete" in states:
        result.update(status="incomplete", message="The latest snapshot has collection coverage gaps. Review unknown evidence.")
    else:
        result.update(status="current", message="Evidence is recent for the configured scope. Review individual check outcomes.")
    if latest_job.get("status") == "failed":
        result.update(status="collection_failed", message="The latest collection failed. The displayed snapshot is from an earlier collection.")
    return result
