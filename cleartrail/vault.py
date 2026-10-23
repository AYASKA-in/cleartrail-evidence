"""Versioned authenticated credential envelopes, bound to tenant and provider."""
from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from .validation import canonical, strict_json_loads, text


def validate_credential(provider, value):
    if not isinstance(value, dict):
        raise ValueError("Credentials must be an object.")
    expected = {"github": {"token"}, "google": {"access_token"}, "aws": {"role_arn", "external_id"}}
    if not isinstance(provider, str) or provider not in expected or set(value) != expected[provider]:
        raise ValueError("Unsupported credential fields.")
    clean = {key: text(item, maximum=16384 if provider != "aws" else 256) for key, item in value.items()}
    if provider == "aws":
        import re
        if not re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,128}", clean["role_arn"]):
            raise ValueError("A valid AWS role ARN is required.")
        if not re.fullmatch(r"[A-Za-z0-9+=,.@:/_-]{16,256}", clean["external_id"]):
            raise ValueError("Use a unique external ID of at least 16 characters.")
    elif len(next(iter(clean.values()))) < 16:
        raise ValueError("Credential is too short.")
    return clean


class Vault:
    def __init__(self, keys):
        self.cipher = MultiFernet([Fernet(key.encode("ascii")) for key in keys])

    def seal(self, tenant, provider, value):
        return self.cipher.encrypt(canonical({"version": 1, "tenant": tenant, "provider": provider,
                                              "credentials": validate_credential(provider, value)})).decode("ascii")

    def open(self, tenant, provider, envelope):
        try:
            value = strict_json_loads(self.cipher.decrypt(envelope.encode("ascii")))
            if set(value) != {"version", "tenant", "provider", "credentials"} or value["version"] != 1 or value["tenant"] != tenant or value["provider"] != provider:
                raise ValueError("Credential context mismatch.")
            return validate_credential(provider, value["credentials"])
        except (InvalidToken, ValueError, TypeError, KeyError, UnicodeError):
            raise ValueError("Credential envelope could not be verified.") from None
