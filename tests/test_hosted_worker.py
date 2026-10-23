import secrets
from unittest.mock import patch, MagicMock

from cryptography.fernet import Fernet

from cleartrail.hosted_repository import Repository
from cleartrail.hosted_settings import HostedSettings
from cleartrail.hosted_worker import collector_credentials, process_one
from cleartrail.isolated import IsolatedCollectionError


def repository(tmp_path):
    settings = HostedSettings(database_url="sqlite:///" + (tmp_path / "worker.db").as_posix(),
                              public_url="http://127.0.0.1", oidc_issuer="https://identity.example", oidc_client_id="test",
                              oidc_client_secret="test-secret", session_secret=secrets.token_urlsafe(48),
                              vault_keys=(Fernet.generate_key().decode(),), environment="test")
    repo = Repository(settings)
    repo.migrate()
    tenant = repo.create_tenant("Worker tenant", settings.oidc_issuer, "owner")
    return repo, tenant


def test_worker_completes_real_isolated_no_provider_job(tmp_path):
    repo, tenant = repository(tmp_path)
    try:
        repo.enqueue(tenant, "owner")
        assert process_one(repo)
        assert repo.latest_job(tenant)["status"] == "succeeded"
        snapshot = repo.get_run(tenant)
        assert not snapshot["demo"] and snapshot["summary"]["passed"] == 0
        assert repo.audit_verify(tenant)["events"] == 4
        assert not process_one(repo)
    finally:
        repo.engine.dispose()


def test_worker_records_bounded_generic_failure(tmp_path):
    repo, tenant = repository(tmp_path)
    try:
        repo.enqueue(tenant, "owner")
        with patch("cleartrail.hosted_worker.run_isolated_collection", side_effect=IsolatedCollectionError("collector_timeout")):
            assert process_one(repo)
        assert repo.get_run(tenant) is None
        assert repo.latest_job(tenant)["error"] == "collector_timeout"
    finally:
        repo.engine.dispose()


def test_aws_uses_expected_account_external_id_and_temporary_credentials():
    client = MagicMock()
    client.assume_role.return_value = {"Credentials": {"AccessKeyId":"temporary-key", "SecretAccessKey":"temporary-secret", "SessionToken":"temporary-session"}}
    config = {"providers": {"aws": {"expected_account_id":"123456789012", "region":"us-east-1"}}}
    stored = {"aws": {"role_arn":"arn:aws:iam::123456789012:role/ReadOnly", "external_id":"unique-workspace-external-id"}}
    with patch("boto3.client", return_value=client) as create:
        output = collector_credentials(config, stored, tenant="a-workspace")
        assert set(output) == {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}
        assert client.assume_role.call_args.kwargs["ExternalId"] == stored["aws"]["external_id"]
        assert client.assume_role.call_args.kwargs["DurationSeconds"] == 900
        assert create.call_args.kwargs["config"].ignore_configured_endpoint_urls
    config["providers"]["aws"]["expected_account_id"] = "999999999999"
    import pytest
    with patch("boto3.client") as create:
        with pytest.raises(ValueError):
            collector_credentials(config, stored, tenant="a-workspace")
        create.assert_not_called()
