"""OIDC authorization-code login and opaque database-backed hosted sessions.

Identity is the verified (issuer, subject) pair. Email, domain, and tenant claims
never grant membership. Provider tokens are discarded after ID-token validation.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import secrets
import time
from urllib.parse import urlsplit

from authlib.integrations.starlette_client import OAuth
from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import JSONResponse, RedirectResponse

AUTH_STATE_SECONDS = 300
CAPABILITY = re.compile(r"[A-Za-z0-9_-]{43}\Z", re.ASCII)
SIGNING_ALGORITHMS = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
LOGGER = logging.getLogger(__name__)


class HostedAuth:
    def __init__(self, settings, repository):
        self.settings = settings
        self.repository = repository
        self.origin = settings.public_url.rstrip("/")
        self.host = urlsplit(self.origin).netloc
        self.callback_url = self.origin + "/auth/callback"
        self.oauth = OAuth()
        self.oauth.register(
            name="cleartrail_oidc", client_id=settings.oidc_client_id,
            client_secret=settings.oidc_client_secret,
            server_metadata_url=settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration",
            client_kwargs={"scope": "openid", "code_challenge_method": "S256", "timeout": 10,
                           "follow_redirects": False, "trust_env": False},
        )
        self.client = self.oauth.create_client("cleartrail_oidc")
        self.claims_options = {
            "iss": {"essential": True, "value": settings.oidc_issuer},
            "aud": {"essential": True, "values": [settings.oidc_client_id]},
            "sub": {"essential": True}, "exp": {"essential": True},
            "iat": {"essential": True}, "nonce": {"essential": True},
        }

    @staticmethod
    def _deny(status, code, message):
        raise HTTPException(status_code=status, detail={"error": message, "code": code})

    def _boundary(self, request: Request, mutate=False, allow_cross_site=False):
        for name in ("host", "origin", "cookie", "authorization", "x-cleartrail-token", "sec-fetch-site"):
            values = request.headers.getlist(name)
            if len(values) > 1 or any(any(ord(char) < 32 or ord(char) == 127 for char in value) for value in values):
                self._deny(400, "ambiguous_headers", "Invalid request headers.")
        if request.headers.get("host") != self.host:
            self._deny(403, "host_rejected", "Request host is not allowed.")
        origin = request.headers.get("origin")
        if (origin is not None and origin != self.origin) or (mutate and origin != self.origin):
            self._deny(403, "origin_rejected", "Request must originate from this application.")
        if not allow_cross_site and request.headers.get("sec-fetch-site", "same-origin") not in {"same-origin", "none"}:
            self._deny(403, "origin_rejected", "Request must originate from this application.")

    def _session_token(self, request):
        candidates = []
        for item in request.headers.get("cookie", "").split(";"):
            name, separator, value = item.strip().partition("=")
            if separator and name == self.settings.cookie_name:
                candidates.append(value)
        if len(candidates) != 1 or not CAPABILITY.fullmatch(candidates[0]):
            return None
        return candidates[0]

    def require_session(self, request: Request, mutate=False) -> dict:
        self._boundary(request, mutate=mutate)
        token = self._session_token(request)
        session = self.repository.session(token) if token else None
        if not isinstance(session, dict) or session.get("issuer") != self.settings.oidc_issuer or not isinstance(session.get("subject"), str) or not session["subject"]:
            self._deny(401, "authentication_required", "Sign in to access this workspace.")
        if mutate:
            csrf, expected = request.headers.get("x-cleartrail-token", ""), session.get("csrf")
            if not isinstance(expected, str) or not CAPABILITY.fullmatch(csrf) or not CAPABILITY.fullmatch(expected) or not secrets.compare_digest(csrf, expected):
                self._deny(403, "csrf_rejected", "Invalid session request token.")
        return dict(session, token=token)

    def _endpoint_allowed(self, value):
        if not isinstance(value, str):
            return False
        parts = urlsplit(value)
        if not parts.hostname or parts.username or parts.password or parts.fragment:
            return False
        if parts.scheme == "https":
            try:
                return ipaddress.ip_address(parts.hostname).is_global
            except ValueError:
                return parts.hostname.lower() not in {"localhost", "localhost.localdomain"}
        return (self.settings.environment != "production" and parts.scheme == "http"
                and parts.hostname in {"127.0.0.1", "localhost", "::1"})

    async def _metadata(self):
        metadata = await self.client.load_server_metadata()
        if metadata.get("issuer") != self.settings.oidc_issuer:
            raise ValueError("Invalid provider metadata")
        if not all(self._endpoint_allowed(metadata.get(key)) for key in ("authorization_endpoint", "token_endpoint", "jwks_uri")):
            raise ValueError("Invalid provider endpoint")
        algorithms = metadata.get("id_token_signing_alg_values_supported", ["RS256"])
        if not isinstance(algorithms, list) or not algorithms or any(not isinstance(item, str) for item in algorithms):
            raise ValueError("Invalid provider algorithms")
        accepted = [item for item in algorithms if item in SIGNING_ALGORITHMS]
        if not accepted:
            raise ValueError("Provider must support asymmetric ID token signing")
        # Authlib uses these exact algorithm names for signature verification.
        self.client.server_metadata["id_token_signing_alg_values_supported"] = accepted
        return metadata

    @staticmethod
    def _query(request, allowed):
        pairs = list(request.query_params.multi_items())
        if any(key not in allowed for key, _ in pairs) or len({key for key, _ in pairs}) != len(pairs):
            raise ValueError("Invalid authorization response")
        return dict(pairs)

    def _authorization_query(self, request):
        allowed = {"code", "state", "iss", "session_state", "error", "error_description", "error_uri"}
        # Google returns these informational fields in its code response. Never
        # use them for identity, domain membership or authorization; only the
        # signature-verified ID token and explicit membership establish access.
        informational = {"scope", "authuser", "hd", "prompt"} if self.settings.oidc_issuer == "https://accounts.google.com" else set()
        query = self._query(request, allowed | informational)
        for name in informational & query.keys():
            value = query[name]
            if len(value) > 2048 or any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise ValueError("Invalid authorization response")
        return query

    @staticmethod
    def _safe_failure(status, code, message):
        LOGGER.warning("authentication_error code=%s", code)
        return JSONResponse({"error": message, "code": code}, status_code=status, headers={"Cache-Control": "no-store"})

    def install(self, app):
        # This cookie stores only short-lived protocol state, nonce, and PKCE.
        # Authenticated identities and provider tokens never enter this cookie.
        app.add_middleware(SessionMiddleware, secret_key=self.settings.session_secret,
                           session_cookie="cleartrail_oidc_state", max_age=AUTH_STATE_SECONDS,
                           same_site="lax", https_only=self.settings.secure_cookies, path="/auth")

        @app.get("/api/auth")
        async def auth_mode(request: Request):
            self._boundary(request)
            return JSONResponse({"mode": "oidc", "login_url": "/auth/login"}, headers={"Cache-Control": "no-store"})

        @app.get("/auth/login")
        async def login(request: Request):
            self._boundary(request)
            request.session.clear()
            try:
                self._query(request, set())
                await self._metadata()
                request.session["auth_started_at"] = time.time()
                return await self.client.authorize_redirect(request, self.callback_url,
                                                            state=secrets.token_urlsafe(32), nonce=secrets.token_urlsafe(32),
                                                            code_verifier=secrets.token_urlsafe(48), response_type="code")
            except Exception:
                request.session.clear()
                return self._safe_failure(503, "identity_provider_unavailable", "Sign-in is temporarily unavailable. Try again later.")

        @app.get("/auth/callback")
        async def callback(request: Request):
            self._boundary(request, allow_cross_site=True)
            old_token = self._session_token(request)
            try:
                query = self._authorization_query(request)
                started = request.session.get("auth_started_at")
                if isinstance(started, bool) or not isinstance(started, (int, float)) or not 0 <= time.time() - started <= AUTH_STATE_SECONDS:
                    raise ValueError("Authorization flow expired")
                if query.get("error") or query.get("iss", self.settings.oidc_issuer) != self.settings.oidc_issuer:
                    raise ValueError("Invalid authorization response")
                if not CAPABILITY.fullmatch(query.get("state", "")) or not query.get("code") or len(query["code"]) > 2048 or any(ord(char) < 32 for char in query["code"]):
                    raise ValueError("Invalid authorization response")
                await self._metadata()
                tokens = await self.client.authorize_access_token(request, claims_options=self.claims_options, leeway=30)
                claims = tokens.get("userinfo")
                if not isinstance(tokens.get("id_token"), str) or not isinstance(claims, dict):
                    raise ValueError("Verified ID token required")
                issuer, subject = claims.get("iss"), claims.get("sub")
                audience = claims.get("aud")
                if issuer != self.settings.oidc_issuer or not isinstance(subject, str) or not subject or len(subject) > 255:
                    raise ValueError("Invalid identity")
                if audience != self.settings.oidc_client_id and not (isinstance(audience, list) and self.settings.oidc_client_id in audience):
                    raise ValueError("Invalid audience")
                if ((isinstance(audience, list) and len(audience) > 1) or "azp" in claims) and claims.get("azp") != self.settings.oidc_client_id:
                    raise ValueError("Invalid authorized party")
                memberships = await run_in_threadpool(self.repository.list_workspaces, issuer, subject)
                if not memberships:
                    return self._safe_failure(403, "membership_required", "Your identity has no workspace membership. Contact the workspace administrator.")
                # The repository independently verifies membership and generates a
                # fresh opaque token. Never reuse a supplied browser session ID.
                session = await run_in_threadpool(self.repository.create_session, issuer, subject)
                if not isinstance(session, dict) or not isinstance(session.get("token"), str) or not CAPABILITY.fullmatch(session["token"]):
                    raise ValueError("Session creation failed")
                if old_token:
                    await run_in_threadpool(self.repository.revoke_session, old_token)
                response = RedirectResponse("/", status_code=303, headers={"Cache-Control": "no-store"})
                response.set_cookie(self.settings.cookie_name, session["token"], max_age=min(session.get("expires_in", self.settings.session_seconds), self.settings.session_seconds),
                                    httponly=True, secure=self.settings.secure_cookies, samesite="strict", path="/")
                return response
            except Exception:
                return self._safe_failure(400, "sign_in_failed", "Sign-in could not be verified. Start a new sign-in attempt.")
            finally:
                request.session.clear()

        @app.post("/api/logout")
        async def logout(request: Request):
            session = await run_in_threadpool(self.require_session, request, mutate=True)
            await run_in_threadpool(self.repository.revoke_session, session["token"])
            request.session.clear()
            response = JSONResponse({"authenticated": False}, headers={"Cache-Control": "no-store"})
            response.delete_cookie(self.settings.cookie_name, path="/", httponly=True,
                                   secure=self.settings.secure_cookies, samesite="strict")
            return response
