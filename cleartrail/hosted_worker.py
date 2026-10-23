"""Durable job worker; one private collection subprocess per leased job."""
from __future__ import annotations

import argparse
import logging
import signal
import threading

from .hosted_repository import Repository
from .hosted_settings import HostedSettings
from .isolated import IsolatedCollectionError, run_isolated_collection

LOGGER = logging.getLogger(__name__)


def collector_credentials(config, stored, *, tenant):
    result = {}
    for provider, settings in config["providers"].items():
        if not settings.get("enabled", True) or provider not in stored:
            continue
        credential = stored[provider]
        if provider == "github":
            result["GITHUB_TOKEN"] = credential["token"]
        elif provider == "google":
            result["GOOGLE_ACCESS_TOKEN"] = credential["access_token"]
        elif provider == "aws":
            expected = settings.get("expected_account_id")
            if not expected or credential["role_arn"].split(":")[4] != expected:
                raise ValueError("AWS role does not match the expected account.")
            import boto3
            from botocore.config import Config
            # Only this parent worker uses its workload identity, solely to assume
            # the customer's read-only role. No ambient identity reaches collectors.
            client = boto3.client("sts", region_name=settings.get("region", "us-east-1"),
                                  config=Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 2},
                                                ignore_configured_endpoint_urls=True))
            response = client.assume_role(RoleArn=credential["role_arn"], ExternalId=credential["external_id"],
                                          RoleSessionName="cleartrail-" + tenant, DurationSeconds=900)
            values = response["Credentials"]
            result.update(AWS_ACCESS_KEY_ID=values["AccessKeyId"], AWS_SECRET_ACCESS_KEY=values["SecretAccessKey"],
                          AWS_SESSION_TOKEN=values["SessionToken"])
    return result


def process_one(repo):
    job = repo.claim()
    if not job:
        return False
    try:
        try:
            credentials = collector_credentials(job["config"], repo.worker_credentials(job["tenant_id"]), tenant=job["tenant_id"])
        except Exception:
            repo.finish(job, error="credential_unavailable")
            return True
        try:
            snapshot = run_isolated_collection(job["config"], credentials, job["attestations"], timeout=650)
            repo.finish(job, snapshot=snapshot)
        except IsolatedCollectionError as exc:
            repo.finish(job, error=exc.code)
    except Exception:
        # A failed commit remains leased and is recovered as worker_lost. Never
        # mark a job successful before the snapshot and audit event commit.
        LOGGER.error("collection_commit_failed job_id=%s", job["id"])
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description="ClearTrail hosted collection worker")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    stop = threading.Event()
    for kind in (signal.SIGTERM, signal.SIGINT):
        signal.signal(kind, lambda *_: stop.set())
    repo = Repository(HostedSettings.from_env())
    repo.ready()
    try:
        while not stop.is_set():
            worked = process_one(repo)
            if args.once:
                break
            if not worked:
                stop.wait(3)
    finally:
        repo.engine.dispose()


if __name__ == "__main__":
    main()
