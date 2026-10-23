"""Operator-run live provider validation; missing access never becomes a pass."""
from __future__ import annotations

from datetime import datetime, timezone

from .isolated import run_isolated_collection
from .hosted_worker import collector_credentials
from .validation import digest

PROVIDERS = ("github", "google", "aws")


def validate_providers(repo, tenant):
    repo.ready()
    config = repo.config(tenant)
    stored = repo.worker_credentials(tenant)
    report = {"schema_version": 1, "checked_at": datetime.now(timezone.utc).isoformat(),
              "tenant_id": tenant, "scope_sha256": digest(config), "provider_validation_complete": False,
              "providers": {}, "limitation": "Read-only access and supported population checks only; not certification, a penetration test or an identity/infrastructure release approval."}
    eligible = {}
    for provider in PROVIDERS:
        settings = config["providers"].get(provider)
        status = {"status": "blocked", "code": "not_configured"}
        if settings and settings.get("enabled", True):
            status["code"] = "credential_missing"
            if provider in stored:
                status["code"] = "scope_incomplete"
                scoped = (provider == "github" and settings.get("org") and settings.get("expected_repositories")) or (
                    provider == "google" and settings.get("customer") and settings["customer"] != "my_customer") or (
                    provider == "aws" and settings.get("expected_account_id") and settings.get("region"))
                if scoped:
                    eligible[provider] = settings
                    status = {"status": "pending", "code": "collection_required"}
        report["providers"][provider] = status
    for provider, settings in eligible.items():
        scoped_config = {**config, "providers": {provider: settings}}
        try:
            credentials = collector_credentials(scoped_config, {provider: stored[provider]}, tenant=tenant)
            snapshot = run_isolated_collection(scoped_config, credentials, {}, timeout=650)
            checks = [check for check in snapshot["checks"] if check["provider"] == provider]
            counts = {status: sum(check["status"] == status for check in checks) for status in ("pass", "fail", "unknown")}
            verified = bool(checks) and counts["unknown"] == 0
            report["providers"][provider] = {"status": "verified" if verified else "incomplete", "code": "supported_checks_observed" if verified else "unknown_or_incomplete_coverage", "check_counts": counts, "snapshot_sha256": digest(snapshot), "snapshot_id": snapshot["id"], "provider_scope_sha256": digest(settings)}
        except Exception:
            # SDK and child errors may include secrets. Never put exception text,
            # provider responses, people or resource inventories in diagnostics.
            report["providers"][provider] = {"status": "failed", "code": "collection_or_credentials_failed"}
    report["provider_validation_complete"] = all(value["status"] == "verified" for value in report["providers"].values())
    return report
