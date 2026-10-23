"""Fail-closed configuration for the independently deployed hosted service."""
from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from sqlalchemy.engine import make_url


@dataclass(frozen=True)
class HostedSettings:
    database_url: str
    public_url: str
    oidc_issuer: str
    oidc_client_id: str
    oidc_client_secret: str
    session_secret: str
    vault_keys: tuple[str, ...]
    environment: str = "production"
    session_seconds: int = 28800
    cookie_name: str = "cleartrail_hosted_session"
    scanner_host: str | None = None
    scanner_port: int = 3310
    scanner_timeout_seconds: int = 30
    scanner_max_age_hours: int = 72

    def __post_init__(self):
        if self.environment not in {"production", "development", "test"}:
            raise ValueError("Invalid CLEARTRAIL_ENV.")
        for value in (self.public_url, self.oidc_issuer):
            parsed = urlsplit(value)
            if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError("Public URL and OIDC issuer must be absolute origins or issuer paths.")
            if parsed.scheme != "https" and not (self.environment != "production" and parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}):
                raise ValueError("Hosted production URLs require HTTPS.")
        if urlsplit(self.public_url).path not in {"", "/"} or self.public_url.endswith("/"):
            raise ValueError("CLEARTRAIL_PUBLIC_URL must be an origin without a trailing slash.")
        database = make_url(self.database_url)
        if self.environment == "production":
            if database.drivername != "postgresql+psycopg":
                raise ValueError("Production requires PostgreSQL with the psycopg driver.")
            if database.username in {"postgres", "root"}:
                raise ValueError("Production requires a dedicated non-superuser database role.")
        elif database.get_backend_name() not in {"postgresql", "sqlite"}:
            raise ValueError("Unsupported database backend.")
        if database.get_backend_name() == "sqlite" and urlsplit(self.public_url).hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("SQLite is restricted to loopback development and tests.")
        if not 900 <= self.session_seconds <= 28800:
            raise ValueError("Sessions must expire within 15 minutes to 8 hours.")
        if len(self.session_secret) < 32 or len(set(self.session_secret)) < 12:
            raise ValueError("Set a randomly generated session secret of at least 32 characters.")
        if not self.oidc_client_id or not self.oidc_client_secret or not self.vault_keys:
            raise ValueError("OIDC credentials and vault keys are required.")
        for key in self.vault_keys:
            Fernet(key.encode("ascii"))
        if self.scanner_host is not None and (not isinstance(self.scanner_host, str) or not self.scanner_host or len(self.scanner_host) > 253 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:" for c in self.scanner_host)):
            raise ValueError("Invalid private scanner host.")
        if type(self.scanner_port) is not int or not 1 <= self.scanner_port <= 65535 or type(self.scanner_timeout_seconds) is not int or not 1 <= self.scanner_timeout_seconds <= 60 or type(self.scanner_max_age_hours) is not int or not 1 <= self.scanner_max_age_hours <= 168:
            raise ValueError("Invalid scanner limits.")

    @property
    def secure_cookies(self):
        return self.environment == "production" or self.public_url.startswith("https://")

    @classmethod
    def from_env(cls):
        def required(name):
            value = os.environ.get("CLEARTRAIL_" + name, "")
            if not value:
                raise ValueError("Missing CLEARTRAIL_" + name + ".")
            return value
        return cls(database_url=required("DATABASE_URL"), public_url=required("PUBLIC_URL"),
                   oidc_issuer=required("OIDC_ISSUER"), oidc_client_id=required("OIDC_CLIENT_ID"),
                   oidc_client_secret=required("OIDC_CLIENT_SECRET"), session_secret=required("SESSION_SECRET"),
                   vault_keys=tuple(required("VAULT_KEYS").split(",")),
                   environment=os.environ.get("CLEARTRAIL_ENV", "production"),
                   scanner_host=os.environ.get("CLEARTRAIL_SCANNER_HOST") or None,
                   scanner_port=int(os.environ.get("CLEARTRAIL_SCANNER_PORT", "3310")),
                   scanner_timeout_seconds=int(os.environ.get("CLEARTRAIL_SCANNER_TIMEOUT_SECONDS", "30")),
                   scanner_max_age_hours=int(os.environ.get("CLEARTRAIL_SCANNER_MAX_AGE_HOURS", "72")))
