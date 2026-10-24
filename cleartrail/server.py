"""Bounded loopback service with explicit single-user access capabilities.

Launch capabilities are exchanged for expiring browser sessions. This boundary
does not protect against malicious code running as the same operating-system user.
"""
from __future__ import annotations

import http.client
import json
import logging
import re
import secrets
import socket
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlsplit

from .catalog import CATALOG
from .core import Store, collect_run
from .reports import bundle_bytes, controls_csv, report_html

STATIC = Path(__file__).parent / "static"
MAX_BODY_BYTES = 16_384
MAX_HEADER_BYTES = 16_384
MAX_REQUEST_THREADS = 16
REQUEST_TIMEOUT_SECONDS = 5
SESSION_SECONDS = 8 * 60 * 60
MAX_SESSIONS = 64
LOGIN_LIMIT = 10
LOGIN_WINDOW_SECONDS = 60
COLLECTION_SHUTDOWN_SECONDS = 10
CAPABILITY = re.compile(r"[A-Za-z0-9_-]{43}\Z", re.ASCII)
RUN_ID = re.compile(r"run_[0-9a-f]{16,32}\Z", re.ASCII)
LOGGER = logging.getLogger(__name__)


class _HeaderBudget:
    def __init__(self, stream):
        self.stream = stream
        self.remaining = MAX_HEADER_BYTES

    def readline(self, limit=-1):
        line = self.stream.readline(min(limit, self.remaining + 1) if limit >= 0 else self.remaining + 1)
        self.remaining -= len(line)
        if self.remaining < 0:
            raise http.client.LineTooLong("request header block")
        return line

    def __getattr__(self, name):
        return getattr(self.stream, name)


class _BoundedServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = MAX_REQUEST_THREADS
    allow_reuse_address = False

    def __init__(self, *args, **kwargs):
        self._request_slots = threading.BoundedSemaphore(MAX_REQUEST_THREADS)
        self.collection_thread = None
        self.stopping = threading.Event()
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        # Refuse before allocating a worker, without waiting on slow clients.
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()

    def handle_error(self, request, client_address):
        LOGGER.warning("request_error code=handler_failure")

    def server_close(self):
        self.stopping.set()
        super().server_close()
        worker = self.collection_thread
        if worker and worker is not threading.current_thread():
            worker.join(COLLECTION_SHUTDOWN_SECONDS)
            if worker.is_alive():
                LOGGER.warning("collection_shutdown code=collection_still_finishing")


def create_server(store: Store, config: dict, demo: bool = False, port: int = 8090) -> HTTPServer:
    previous = store.latest()
    if previous is not None and previous["demo"] != demo:
        raise ValueError("This database belongs to a different mode. Use --demo for demo evidence, or choose a separate live database.")
    bootstrap_token = secrets.token_urlsafe(32)
    state = {"running": False, "error": None, "error_code": None, "request_id": None}
    job_lock = threading.Lock()
    access_lock = threading.Lock()
    sessions: dict[str, dict] = {}
    login_attempts = deque()

    def work(request_id):
        try:
            collect_run(store, config, demo)
        except Exception:
            with job_lock:
                state.update(error="Collection could not be saved. Check local storage and configuration.",
                             error_code="collection_failed", request_id=request_id)
            LOGGER.warning("collection_error code=collection_failed request_id=%s", request_id)
        finally:
            with job_lock:
                state["running"] = False

    class Handler(BaseHTTPRequestHandler):
        server_version = "ClearTrail"
        sys_version = ""
        protocol_version = "HTTP/1.0"

        def setup(self):
            self.request.settimeout(REQUEST_TIMEOUT_SECONDS)
            super().setup()
            self.request_id = secrets.token_hex(8)

        def parse_request(self):
            original = self.rfile
            self.rfile = _HeaderBudget(original)
            try:
                return super().parse_request()
            finally:
                self.rfile = original

        def log_message(self, fmt, *args):
            pass

        def send_error(self, code, message=None, explain=None):
            self.close_connection = True
            self.error(code, "invalid_request", "Invalid request.")

        def reply(self, code, data, kind="application/json; charset=utf-8", filename=None, cookie=None):
            if not isinstance(data, bytes):
                data = json.dumps(data, ensure_ascii=True, allow_nan=False).encode("utf-8")
            self.close_connection = True
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.send_header("X-Request-ID", self.request_id)
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
            if filename:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            if getattr(self, "command", "") != "HEAD":
                self.wfile.write(data)

        def error(self, status, code, message):
            return self.reply(status, {"error": message, "code": code, "request_id": self.request_id})

        def boundary(self):
            singleton = ("Host", "Origin", "Cookie", "Content-Length", "Content-Type", "Authorization", "X-ClearTrail-Token", "X-ClearTrail-CSRF", "Sec-Fetch-Site")
            for name in singleton:
                values = self.headers.get_all(name, [])
                if len(values) > 1 or any("\r" in value or "\n" in value or "\0" in value for value in values):
                    self.error(400, "ambiguous_headers", "Invalid request headers.")
                    return False
            if self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Expect"):
                self.error(400, "unsupported_framing", "Unsupported request framing.")
                return False
            host = self.headers.get("Host", "")
            if host not in {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}:
                self.error(403, "loopback_required", "Loopback host required.")
                return False
            expected_origin = "http://" + host
            origin = self.headers.get("Origin")
            if (origin is not None and origin != expected_origin) or (self.command == "POST" and origin != expected_origin):
                self.error(403, "origin_rejected", "Request must originate from this dashboard.")
                return False
            if self.headers.get("Sec-Fetch-Site", "same-origin") not in {"same-origin", "none"}:
                self.error(403, "origin_rejected", "Request must originate from this dashboard.")
                return False
            length = self.headers.get("Content-Length")
            if length is not None and (not length.isascii() or not length.isdecimal() or len(length) > 8):
                self.error(400, "invalid_length", "Invalid content length.")
                return False
            if self.command in {"GET", "HEAD"} and length not in {None, "0"}:
                self.error(400, "unexpected_body", "Request body is not supported.")
                return False
            return True

        def route(self):
            try:
                if any(ord(char) < 32 for char in self.path) or len(self.path) > 2048:
                    raise ValueError()
                parts = urlsplit(self.path)
                if parts.scheme or parts.netloc or parts.fragment or not parts.path.startswith("/") or "%" in parts.path:
                    raise ValueError()
                query = parse_qs(parts.query, keep_blank_values=True, strict_parsing=True, max_num_fields=2, errors="strict") if parts.query else {}
                key = "since" if parts.path == "/api/state" else "run_id"
                if query and (parts.path not in {"/api/state", "/api/export", "/api/report", "/api/csv"} or set(query) != {key}
                              or len(query[key]) != 1 or not RUN_ID.fullmatch(query[key][0])):
                    raise ValueError()
                return parts.path, query.get(key, [None])[0]
            except (ValueError, UnicodeError):
                self.error(400, "invalid_path", "Invalid request path or query.")
                return None

        def session(self):
            candidates = []
            for item in self.headers.get("Cookie", "").split(";"):
                name, sep, value = item.strip().partition("=")
                if sep and name == self.server.session_cookie_name:
                    candidates.append(value)
            if len(candidates) != 1 or not CAPABILITY.fullmatch(candidates[0]):
                return None
            with access_lock:
                value = sessions.get(candidates[0])
                if value and value["expires"] <= time.monotonic():
                    sessions.pop(candidates[0], None)
                    value = None
                return (candidates[0], dict(value)) if value else None

        def require_session(self, mutation=False):
            value = self.session()
            if value is None:
                self.error(401, "authentication_required", "Unlock this dashboard using the access token printed in your terminal.")
                return None
            if mutation:
                csrf = self.headers.get("X-ClearTrail-Token", "")
                if not CAPABILITY.fullmatch(csrf) or not secrets.compare_digest(csrf, value[1]["csrf"]):
                    self.error(403, "csrf_rejected", "Invalid session request token.")
                    return None
            return value

        def json_body(self):
            kind = self.headers.get("Content-Type", "")
            if kind.lower().replace(" ", "") not in {"application/json", "application/json;charset=utf-8"}:
                self.error(415, "json_required", "Content-Type must be application/json.")
                return None
            if self.headers.get("Content-Length") is None:
                self.error(411, "length_required", "Content-Length is required.")
                return None
            length = int(self.headers["Content-Length"])
            if length > MAX_BODY_BYTES:
                self.error(413, "body_too_large", "Request too large.")
                return None
            try:
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError()
                def unique_pairs(pairs):
                    value = {}
                    for key, item in pairs:
                        if key in value:
                            raise ValueError()
                        value[key] = item
                    return value
                def reject_constant(_):
                    raise ValueError()
                data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs, parse_constant=reject_constant)
                if not isinstance(data, dict):
                    raise ValueError()
                return data
            except (ValueError, UnicodeError, RecursionError):
                self.error(400, "invalid_json", "Request must contain a valid JSON object.")
                return None
            except (TimeoutError, socket.timeout):
                self.error(408, "request_timeout", "Request body timed out.")
                return None

        def do_GET(self):
            try:
                self.get_request()
            except (BrokenPipeError, ConnectionError, TimeoutError):
                return
            except Exception:
                LOGGER.warning("request_error code=internal_error request_id=%s", self.request_id)
                self.error(500, "internal_error", "Unable to complete request. Check local storage and configuration.")

        def get_request(self):
            if not self.boundary():
                return
            route = self.route()
            if route is None:
                return
            path, run_id = route
            if path == "/api/health":
                return self.reply(200, {"status": "ok"})
            session = None
            if path.startswith("/api/"):
                session = self.require_session()
                if session is None:
                    return
            if path == "/api/state":
                providers = config.get("providers", {})
                safe = {p: {key: entry.get(key) for key in ("org", "customer", "profile", "region", "enabled") if key in entry}
                        for p, entry in providers.items() if p in {"github", "google", "aws"} and isinstance(entry, dict)}
                with job_lock:
                    job = dict(state)
                unchanged = bool(run_id and store.latest_id() == run_id)
                return self.reply(200, dict(run=None if unchanged else store.latest(), unchanged=unchanged,
                                            history=store.history(), demo=demo, csrf=session[1]["csrf"], job=job,
                                            config=dict(organization=config.get("organization", "Your organization"), providers=safe),
                                            catalog=list(CATALOG.values()), attestations=store.attestations()))
            if path in {"/api/export", "/api/report", "/api/csv"}:
                run = store.get_run(run_id) if run_id else store.latest()
                if run is None:
                    return self.error(404, "snapshot_not_found", "Snapshot not found. Collect evidence before exporting.")
                if path == "/api/export":
                    return self.reply(200, bundle_bytes(run), "application/zip", f'cleartrail-{run["id"]}.zip')
                if path == "/api/csv":
                    return self.reply(200, controls_csv(run), "text/csv; charset=utf-8", "controls.csv")
                return self.reply(200, report_html(run), "text/html; charset=utf-8")
            assets = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"), "/workspace-ui.js": ("workspace-ui.js", "text/javascript"), "/style.css": ("style.css", "text/css")}
            if path in assets:
                name, mime = assets[path]
                return self.reply(200, (STATIC / name).read_bytes(), mime + "; charset=utf-8")
            return self.error(404, "not_found", "Not found.")

        def do_HEAD(self):
            self.do_GET()

        def do_POST(self):
            try:
                self.post_request()
            except (BrokenPipeError, ConnectionError, TimeoutError):
                return
            except Exception:
                LOGGER.warning("request_error code=internal_error request_id=%s", self.request_id)
                self.error(500, "internal_error", "Unable to complete request. Check local storage and configuration.")

        def post_request(self):
            if not self.boundary():
                return
            route = self.route()
            if route is None:
                return
            path, _ = route
            session = None
            if path != "/api/session":
                session = self.require_session(mutation=True)
                if session is None:
                    return
            data = self.json_body()
            if data is None:
                return
            if path == "/api/session":
                now = time.monotonic()
                with access_lock:
                    while login_attempts and login_attempts[0] <= now - LOGIN_WINDOW_SECONDS:
                        login_attempts.popleft()
                    if len(login_attempts) >= LOGIN_LIMIT:
                        return self.error(429, "login_rate_limited", "Too many unlock attempts. Try again in one minute.")
                    login_attempts.append(now)
                    token = data.get("token")
                    if set(data) != {"token"} or not isinstance(token, str) or not CAPABILITY.fullmatch(token) or not secrets.compare_digest(token, bootstrap_token):
                        return self.error(403, "access_rejected", "Invalid dashboard access token.")
                    for key in [key for key, item in sessions.items() if item["expires"] <= now]:
                        sessions.pop(key, None)
                    if len(sessions) >= MAX_SESSIONS:
                        sessions.pop(next(iter(sessions)))
                    key, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                    sessions[key] = {"csrf": csrf, "expires": now + SESSION_SECONDS}
                cookie = f"{self.server.session_cookie_name}={key}; Path=/api; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}"
                return self.reply(200, {"authenticated": True, "csrf": csrf, "expires_in": SESSION_SECONDS}, cookie=cookie)
            if path == "/api/logout":
                if data:
                    return self.error(400, "invalid_fields", "No request fields are expected.")
                with access_lock:
                    sessions.pop(session[0], None)
                return self.reply(200, {"authenticated": False}, cookie=f"{self.server.session_cookie_name}=; Path=/api; HttpOnly; SameSite=Strict; Max-Age=0")
            if path == "/api/scan":
                if data:
                    return self.error(400, "invalid_fields", "No request fields are expected.")
                with job_lock:
                    if self.server.stopping.is_set():
                        return self.error(503, "service_stopping", "Service is shutting down.")
                    if state["running"]:
                        return self.error(409, "collection_running", "A collection is already running.")
                    state.update(running=True, error=None, error_code=None, request_id=self.request_id)
                    worker = threading.Thread(target=work, args=(self.request_id,), name="cleartrail-collection", daemon=False)
                    self.server.collection_thread = worker
                    try:
                        worker.start()
                    except Exception:
                        state["running"] = False
                        raise
                return self.reply(202, {"started": True, "request_id": self.request_id})
            if path == "/api/attest":
                if set(data) != {"control_id", "owner", "note"} or any(not isinstance(data.get(key), str) for key in ("control_id", "owner", "note")):
                    return self.error(400, "invalid_attestation", "A control ID, owner, and note must be provided as text.")
                try:
                    store.attest(data["control_id"], data["owner"], data["note"])
                except ValueError:
                    return self.error(400, "invalid_attestation", "Choose a team evidence control and provide an owner (1–120 characters) and note (1–4000 characters).")
                return self.reply(200, {"saved": True, "message": "Note saved. Run collection to include it in the next snapshot and export."})
            return self.error(404, "not_found", "Not found.")

    server = _BoundedServer(("127.0.0.1", port), Handler)
    server.session_cookie_name = f"cleartrail_session_{server.server_port}"
    server.bootstrap_token = bootstrap_token
    server.bootstrap_url = f"http://127.0.0.1:{server.server_port}/#access={bootstrap_token}"
    return server
