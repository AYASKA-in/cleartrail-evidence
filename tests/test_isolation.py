import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from cleartrail.core import build_run
from cleartrail.isolated import IsolatedCollectionError, _child_environment, run_isolated_collection
from cleartrail.validation import canonical


def test_isolated_child_cannot_inherit_parent_credentials_or_profile():
    with patch.dict(os.environ, {"GITHUB_TOKEN": "parent-github-secret", "GOOGLE_ACCESS_TOKEN": "parent-google-secret", "AWS_PROFILE": "admin", "AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://evil.example", "PYTHONPATH": "untrusted"}):
        result = run_isolated_collection({"organization": "Isolated", "providers": {"github": {"org": "example"}}}, {}, {})
        assert result["summary"]["passed"] == 0
        assert "parent-github-secret" not in str(result)
        assert os.environ["GITHUB_TOKEN"] == "parent-github-secret"
        env = _child_environment(Path(tempfile.gettempdir()))
        assert not set(env) & {"GITHUB_TOKEN", "GOOGLE_ACCESS_TOKEN", "AWS_PROFILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "PYTHONPATH"}


def test_wall_clock_timeout_kills_and_reaps_child():
    with pytest.raises(IsolatedCollectionError) as error:
        run_isolated_collection({}, {}, {}, timeout=0.00001)
    assert error.value.code == "collector_timeout"


@pytest.mark.parametrize("raw", [b"[]", b"{bad", b'{"x":1,"x":2}', canonical(build_run({"organization": "wrong"}, [], {}))])
def test_malformed_or_wrong_scope_output_fails_closed(raw):
    with patch("cleartrail.isolated._execute", return_value=raw):
        with pytest.raises(IsolatedCollectionError):
            run_isolated_collection({"organization": "correct"}, {}, {})


def test_secret_cannot_escape_in_evidence():
    config = {"organization": "Tenant"}
    snapshot = build_run(config, [], {"MAN-POLICY": {"owner": "Owner", "note": "a-secret-value-123456", "recorded_at": "2026-10-23T00:00:00+00:00", "kind":"self-attestation", "independently_verified":False}})
    with patch("cleartrail.isolated._execute", return_value=canonical(snapshot)):
        with pytest.raises(IsolatedCollectionError) as error:
            run_isolated_collection(config, {"GITHUB_TOKEN": "a-secret-value-123456"}, {})
    assert error.value.code == "credential_in_output"


@pytest.mark.parametrize("config,credentials", [
    ({"providers": {"aws": {"profile": "admin"}}}, {}),
    ({}, {"AWS_ACCESS_KEY_ID": "incomplete"}), ({}, {"AWS_PROFILE": "admin"})])
def test_unscoped_credentials_and_profiles_are_rejected(config, credentials):
    with pytest.raises(IsolatedCollectionError) as error:
        run_isolated_collection(config, credentials, {})
    assert error.value.code == "invalid_request"
