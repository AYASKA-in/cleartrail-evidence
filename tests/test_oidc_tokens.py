"""Exercise Authlib's actual signature and OIDC claim checks without an IdP."""
import asyncio
import secrets
import time
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet
from joserfc import jwt
from joserfc.jwk import RSAKey

from cleartrail.hosted_auth import HostedAuth
from cleartrail.hosted_settings import HostedSettings


@pytest.fixture
def oidc():
    settings = HostedSettings(database_url="sqlite:///:memory:", public_url="http://127.0.0.1",
                              oidc_issuer="https://identity.example", oidc_client_id="cleartrail",
                              oidc_client_secret="client-secret", session_secret=secrets.token_urlsafe(48),
                              vault_keys=(Fernet.generate_key().decode(),), environment="test")
    auth = HostedAuth(settings, None)
    key = RSAKey.generate_key(2048, parameters={"kid": "signing-key"})
    auth.client.load_server_metadata = AsyncMock(return_value={"issuer": settings.oidc_issuer, "id_token_signing_alg_values_supported": ["RS256"]})
    auth.client.fetch_jwk_set = AsyncMock(return_value={"keys": [key.as_dict(private=False)]})
    claims = {"iss": settings.oidc_issuer, "sub": "alice", "aud": settings.oidc_client_id,
              "iat": int(time.time()), "exp": int(time.time()) + 300, "nonce": "expected-nonce"}
    return auth, key, claims


def parse(auth, token):
    return asyncio.run(auth.client.parse_id_token({"id_token": token, "access_token": "test-access-token"},
                                                  nonce="expected-nonce", claims_options=auth.claims_options, leeway=0))


def test_actual_signed_id_token_is_verified(oidc):
    auth, key, claims = oidc
    token = jwt.encode({"alg": "RS256", "kid": "signing-key"}, claims, key)
    assert parse(auth, token)["sub"] == "alice"


@pytest.mark.parametrize("change", [{"nonce": "other"}, {"iss": "https://attacker.example"},
                                       {"aud": "other"}, {"exp": 1}, {"sub": None}, {"iat": 9999999999}])
def test_actual_id_token_rejects_invalid_claims(oidc, change):
    auth, key, claims = oidc
    token = jwt.encode({"alg": "RS256", "kid": "signing-key"}, {**claims, **change}, key)
    with pytest.raises(Exception):
        parse(auth, token)


def test_wrong_signature_is_rejected(oidc):
    auth, key, claims = oidc
    other = RSAKey.generate_key(2048, parameters={"kid": "signing-key"})
    token = jwt.encode({"alg": "RS256", "kid": "signing-key"}, claims, other)
    with pytest.raises(Exception):
        parse(auth, token)


def test_missing_nonce_is_rejected(oidc):
    auth, key, claims = oidc
    del claims["nonce"]
    with pytest.raises(Exception):
        parse(auth, jwt.encode({"alg": "RS256", "kid": "signing-key"}, claims, key))
