"""Hosted application factory. Authentication is mandatory in every mode."""
from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from .hosted_auth import HostedAuth
from .hosted_repository import Repository
from .hosted_settings import HostedSettings
from .reports import bundle_bytes, controls_csv, report_html
from .validation import strict_json_loads
from .errors import EvidenceIntegrityError
from .documents import DocumentConflict, DocumentNotFound, MAX_UPLOAD_BODY
from .scanning import ScannerUnavailable, FileRejected

LOGGER = logging.getLogger(__name__)
STATIC = Path(__file__).with_name("static")
MAX_BODY = 128 * 1024


async def body(request, fields):
    if request.headers.get("content-type", "").lower().split(";", 1)[0] != "application/json":
        raise HTTPException(415, "Use application/json.")
    try:
        value = strict_json_loads(await request.body())
        if not isinstance(value, dict) or set(value) != set(fields):
            raise ValueError()
        return value
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(400, "Invalid JSON request fields.") from None


def create_app(settings=None, repository=None):
    settings = settings or HostedSettings.from_env()
    repo = repository or Repository(settings)

    @asynccontextmanager
    async def lifespan(app):
        repo.ready()
        yield
        repo.engine.dispose()

    app = FastAPI(title="ClearTrail", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.repository, app.state.settings = repo, settings
    auth = HostedAuth(settings, repo)
    app.state.auth = auth
    auth.install(app)
    # Per-process burst control complements the database collection quota.
    # The ingress must enforce a shared connection/rate budget across replicas.
    budgets = OrderedDict()
    budget_lock = asyncio.Lock()
    upload_slots = asyncio.Semaphore(2)
    export_slots = asyncio.Semaphore(1)

    @app.middleware("http")
    async def boundary(request, call_next):
        request_id = secrets.token_hex(12)
        try:
            hosts = request.headers.getlist("host")
            if hosts != [urlsplit(settings.public_url).netloc]:
                return JSONResponse({"error": "Request host is not allowed."}, status_code=403)
            upload = request.url.path == "/api/documents/upload" and request.method == "POST"
            limit = MAX_UPLOAD_BODY if upload else MAX_BODY
            if upload:
                # Authenticate before allocating the larger upload buffer.
                identity = await run_in_threadpool(auth.require_session, request, mutate=True)
                if identity["role"] not in {"admin", "operator"}:
                    raise HTTPException(403, "Your workspace role does not allow this action.")
                if request.headers.getlist("x-cleartrail-workspace") != [identity["active_tenant"]]:
                    raise HTTPException(409, "Workspace changed. Reload before saving.")
            lengths = request.headers.getlist("content-length")
            if len(lengths) > 1 or (lengths and (not re.fullmatch(r"[0-9]{1,9}", lengths[0]) or int(lengths[0]) > limit)) or request.headers.get("content-encoding"):
                return JSONResponse({"error": "Invalid request body length or encoding."}, status_code=413)
            if lengths and request.headers.get("transfer-encoding"):
                return JSONResponse({"error": "Ambiguous request framing."}, status_code=400)
            if len(request.scope.get("query_string", b"")) > 4096 or len(request.url.path) > 1024:
                return JSONResponse({"error": "Request target is too long."}, status_code=414)
            chunks, size = [], 0
            async def read_chunks():
                nonlocal size
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > limit:
                        raise HTTPException(413, "Request body is too large.")
                    chunks.append(chunk)
            await asyncio.wait_for(read_chunks(), timeout=10)
            request._body = b"".join(chunks)
            if lengths and size != int(lengths[0]):
                return JSONResponse({"error": "Request body length mismatch."}, status_code=400)
            if request.url.path not in {"/healthz", "/readyz", "/", "/app.js", "/workspace-ui.js", "/style.css"}:
                # Unrelated cookie changes must not reset a session's budget.
                # The IP bucket also bounds random capabilities and session churn.
                import hashlib
                address = (request.client.host if request.client else "unknown").encode()
                token = (auth._session_token(request) or "anonymous").encode()
                keys = (("ip:" + hashlib.sha256(address).hexdigest(), 600),
                        ("session:" + hashlib.sha256(address + b"\0" + token).hexdigest(), 120))
                exceeded = False
                async with budget_lock:
                    tick = int(time.monotonic()) // 60
                    for key, ceiling in keys:
                        old_tick, count = budgets.pop(key, (tick, 0))
                        count = count + 1 if old_tick == tick else 1
                        budgets[key] = (tick, count)
                        exceeded = exceeded or count > ceiling
                    while len(budgets) > 10000:
                        budgets.popitem(last=False)
                if exceeded:
                    return JSONResponse({"error": "Request rate exceeded."}, status_code=429, headers={"Retry-After": "60"})
            response = await call_next(request)
        except HTTPException as exc:
            response = JSONResponse({"error": str(exc.detail)}, status_code=exc.status_code)
        except (TimeoutError, asyncio.TimeoutError):
            response = JSONResponse({"error": "Request timed out."}, status_code=408)
        except Exception:
            LOGGER.error("request_failed request_id=%s", request_id)
            response = JSONResponse({"error": "The request could not be completed.", "request_id": request_id}, status_code=500)
        response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                                 "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
                                 "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                                 "X-Request-ID": request_id,
                                 "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'" + (" 'unsafe-inline'" if request.url.path == "/api/report" else "") + "; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'"})
        if settings.secure_cookies:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.middleware("http")
    async def all_response_headers(request, call_next):
        # Include protocol rejections and authentication errors as well as 200s.
        response = await call_next(request)
        response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                                 "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
                                 "Permissions-Policy": "camera=(), microphone=(), geolocation=()"})
        if "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        if settings.secure_cookies:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        detail = exc.detail
        return JSONResponse(detail if isinstance(detail, dict) else {"error": str(detail)}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        return JSONResponse({"error": "Invalid request."}, status_code=400)

    @app.exception_handler(ValueError)
    async def invalid_value(request, exc):
        # Validation messages are constant application text, never raw SDK errors.
        return JSONResponse({"error": "The supplied value is invalid or exceeds a workspace limit."}, status_code=400)

    @app.exception_handler(EvidenceIntegrityError)
    async def integrity_failure(request, exc):
        LOGGER.error("stored_evidence_integrity_failed")
        return JSONResponse({"error": "Stored evidence failed integrity checks. Contact the service operator.",
                             "code": "evidence_integrity_failed"}, status_code=503)

    @app.exception_handler(PermissionError)
    async def forbidden(request, exc):
        return JSONResponse({"error": "Your workspace role does not allow this action."}, status_code=403)

    @app.exception_handler(DocumentConflict)
    async def document_conflict(request, exc):
        return JSONResponse({"error": "This evidence changed. Reload its details before saving."}, status_code=409)

    @app.exception_handler(DocumentNotFound)
    async def missing_resource(request, exc):
        return JSONResponse({"error": "Resource not found in this workspace."}, status_code=404)

    @app.exception_handler(ScannerUnavailable)
    async def unavailable_scanner(request, exc):
        return JSONResponse({"error": "The scanner is unavailable, stale or could not complete this scan. No file was published.", "code": "scanner_unavailable"}, status_code=503, headers={"Retry-After": "30"})

    @app.exception_handler(FileRejected)
    async def rejected_file(request, exc):
        return JSONResponse({"error": "Security scanning rejected this file. No file was published.", "code": "file_rejected"}, status_code=422)

    @app.get("/healthz")
    def health():
        return {"ok": True}

    @app.get("/readyz")
    def ready():
        try:
            repo.ready()
            return {"ready": True}
        except Exception:
            return JSONResponse({"ready": False}, status_code=503)

    def asset(filename):
        def static_file():
            # OS MIME registries can label .js as text/plain; nosniff then
            # correctly blocks execution. Serve our fixed assets explicitly.
            media = {"index.html": "text/html", "app.js": "text/javascript", "workspace-ui.js": "text/javascript", "style.css": "text/css"}
            return FileResponse(STATIC / filename, media_type=media[filename])
        return static_file

    for route, filename in (("/", "index.html"), ("/app.js", "app.js"), ("/workspace-ui.js", "workspace-ui.js"), ("/style.css", "style.css")):
        # A request query can never select another filesystem path.
        app.add_api_route(route, asset(filename), methods=["GET"], include_in_schema=False)

    def session(request, mutate=False, roles=None):
        identity = auth.require_session(request, mutate=mutate)
        if roles and identity["role"] not in roles:
            raise PermissionError()
        return identity

    async def async_session(request, roles=None):
        identity = await run_in_threadpool(session, request, True, roles)
        if request.headers.getlist("x-cleartrail-workspace") != [identity["active_tenant"]]:
            raise HTTPException(409, "Workspace changed. Reload before saving.")
        return identity

    @app.get("/api/state")
    def state(request: Request):
        identity = session(request)
        tenant = identity["active_tenant"]
        pairs = list(request.query_params.multi_items())
        if len(pairs) > 1 or (pairs and (pairs[0][0] != "since" or not re.fullmatch(r"run_[a-f0-9]{32}", pairs[0][1]))):
            raise HTTPException(400, "Invalid state query.")
        history = repo.history(tenant)
        unchanged = bool(pairs and history and pairs[0][1] == history[0]["id"])
        config, schedule, job = repo.config(tenant), repo.schedule(tenant), repo.latest_job(tenant)
        snapshot = None if unchanged else repo.get_run(tenant)
        health = repo.collection_health(tenant, config, schedule, job)
        expected_id = history[0]["id"] if unchanged else snapshot["id"] if snapshot else None
        if health["snapshot_id"] != expected_id:
            # A worker can commit between these reads. Never attach a newer
            # snapshot's "current" label to the older data the browser retained.
            health.update(status="updating", message="A new snapshot is available. Refresh to load its evidence.")
        return {"mode": "hosted", "demo": False, "csrf": identity["csrf"], "role": identity["role"], "subject": identity["subject"],
                "workspace_id": tenant, "workspaces": repo.list_workspaces(identity["issuer"], identity["subject"]),
                "config": config, "run": snapshot, "unchanged": unchanged, "job": job,
                "history": history, "attestations": repo.attestations(tenant),
                "credentials": repo.credential_status(tenant),
                "aws_external_id": repo.aws_external_id(tenant) if identity["role"] == "admin" else None,
                "schedule": schedule, "collection_health": health,
                "notifications": repo.notification_list(tenant),
                "limits": {"daily_collections": 48, "retained_snapshots": 5000}}

    @app.get("/api/documents")
    def document_list(request: Request):
        identity = session(request)
        return repo.document_list(identity["active_tenant"], identity["subject"])

    @app.get("/api/documents/owners")
    def document_owners(request: Request):
        identity = session(request, roles={"admin", "operator"})
        return {"owners": repo.document_owners(identity["active_tenant"], identity["subject"])}

    @app.post("/api/documents/upload")
    async def document_upload(request: Request):
        identity = await async_session(request, {"admin", "operator"})
        value = await body(request, {"document_id", "title", "control_ids", "owner", "filename", "content_base64",
                                     "expires_at", "expected_version_id", "expected_revision"})
        try:
            await asyncio.wait_for(upload_slots.acquire(), timeout=1)
        except asyncio.TimeoutError:
            raise HTTPException(429, "Upload scanning is busy. Retry shortly.") from None
        try:
            return await run_in_threadpool(repo.upload_document, identity["active_tenant"], identity["subject"], value)
        finally:
            upload_slots.release()

    @app.post("/api/audit-packages")
    async def audit_package(request: Request):
        identity = await async_session(request, {"admin", "operator", "auditor"})
        value = await body(request, {"run_id", "version_ids", "period_start", "period_end"})
        try:
            await asyncio.wait_for(export_slots.acquire(), timeout=1)
        except asyncio.TimeoutError:
            raise HTTPException(429, "Package generation is busy. Retry shortly.") from None
        try:
            raw, manifest_sha = await run_in_threadpool(repo.audit_package, identity["active_tenant"], identity["subject"], value)
            return Response(raw, media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="cleartrail-audit-package.zip"', "X-ClearTrail-Manifest-SHA256": manifest_sha})
        finally:
            export_slots.release()

    @app.get("/api/audit-package-options")
    def audit_package_options(request: Request):
        identity = session(request)
        return {"versions": repo.audit_options(identity["active_tenant"], identity["subject"])}

    @app.get("/api/governance")
    def governance_list(request: Request):
        identity = session(request)
        if request.query_params:
            raise HTTPException(400, "Governance queries cannot select a workspace.")
        return repo.governance_list(identity["active_tenant"], identity["subject"])

    @app.get("/api/governance/options")
    def governance_options(request: Request):
        identity = session(request, roles={"admin", "operator"})
        if request.query_params:
            raise HTTPException(400, "Invalid governance query.")
        return repo.governance_options(identity["active_tenant"], identity["subject"])

    @app.post("/api/governance/save")
    async def governance_save(request: Request):
        identity = await async_session(request, {"admin", "operator"})
        value = await body(request, {"record_id", "kind", "title", "owner", "expected_revision", "payload"})
        return await run_in_threadpool(repo.save_governance, identity["active_tenant"], identity["subject"], value)

    @app.post("/api/governance/review")
    async def governance_review(request: Request):
        identity = await async_session(request, {"admin", "operator"})
        value = await body(request, {"version_id", "decision", "comment", "expected_review_id"})
        return await run_in_threadpool(repo.review_governance, identity["active_tenant"], identity["subject"], **value)

    @app.post("/api/governance/export")
    async def governance_export(request: Request):
        identity = await async_session(request, {"admin", "operator", "auditor"})
        await body(request, set())
        try:
            await asyncio.wait_for(export_slots.acquire(), timeout=1)
        except asyncio.TimeoutError:
            return JSONResponse({"error": "Another export is running. Try again shortly."}, status_code=429, headers={"Retry-After": "5"})
        try:
            raw, sha = await run_in_threadpool(repo.governance_export, identity["active_tenant"], identity["subject"])
            return Response(raw, media_type="application/json", headers={"Content-Disposition": 'attachment; filename="cleartrail-governance-register.json"', "X-ClearTrail-SHA256": sha})
        finally:
            export_slots.release()

    @app.get("/api/governance/{record_id}")
    def governance_detail(request: Request, record_id: str):
        identity = session(request)
        if request.query_params:
            raise HTTPException(400, "Invalid governance query.")
        return repo.governance_detail(identity["active_tenant"], identity["subject"], record_id)

    @app.post("/api/documents/assign")
    async def document_assign(request: Request):
        identity = await async_session(request, {"admin", "operator"})
        value = await body(request, {"document_id", "owner", "expected_revision"})
        await run_in_threadpool(repo.assign_document, identity["active_tenant"], identity["subject"], **value)
        return {"saved": True}

    @app.post("/api/documents/review")
    async def document_review(request: Request):
        identity = await async_session(request, {"admin", "operator"})
        value = await body(request, {"version_id", "decision", "comment", "expected_review_id"})
        return await run_in_threadpool(repo.review_document, identity["active_tenant"], identity["subject"], **value)

    @app.get("/api/documents/versions/{version_id}/download")
    def document_download(request: Request, version_id: str):
        identity = session(request)
        filename, raw = repo.download_document(identity["active_tenant"], identity["subject"], version_id)
        from .documents import file_kind, TEXT_EXTENSIONS
        return Response(raw, media_type="text/plain; charset=utf-8" if file_kind(filename) in TEXT_EXTENSIONS else "application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="{filename}"', "X-ClearTrail-Content": "customer-supplied-evidence"})

    @app.get("/api/documents/{document_id}")
    def document_detail(request: Request, document_id: str):
        identity = session(request)
        return repo.document_detail(identity["active_tenant"], identity["subject"], document_id)

    @app.post("/api/schedule")
    async def set_schedule(request: Request):
        identity = await async_session(request, {"admin"})
        value = await body(request, {"enabled", "interval_hours", "freshness_hours"})
        await run_in_threadpool(repo.set_schedule, identity["active_tenant"], identity["subject"], value)
        return {"saved": True}

    @app.post("/api/notifications/acknowledge")
    async def acknowledge_notification(request: Request):
        identity = await async_session(request, {"admin", "operator"})
        value = await body(request, {"id"})
        try:
            await run_in_threadpool(repo.acknowledge_notification, identity["active_tenant"], identity["subject"], value["id"])
        except LookupError:
            raise HTTPException(404, "Notification not found in this workspace.") from None
        return {"saved": True}

    @app.post("/api/workspace")
    async def workspace(request: Request):
        identity = await async_session(request)
        value = await body(request, {"tenant_id"})
        await run_in_threadpool(repo.select_workspace, identity["token"], value["tenant_id"])
        return {"selected": True}

    @app.post("/api/scan", status_code=202)
    async def scan(request: Request):
        identity = await async_session(request, {"admin", "operator"})
        await body(request, set())
        return await run_in_threadpool(repo.enqueue, identity["active_tenant"], identity["subject"])

    @app.post("/api/attest")
    async def attest(request: Request):
        identity = await async_session(request, {"admin", "operator"})
        value = await body(request, {"control_id", "owner", "note"})
        await run_in_threadpool(repo.attest, identity["active_tenant"], identity["subject"], **value)
        return {"saved": True, "message": "Note saved. Collect a new snapshot to include it in reports."}

    @app.post("/api/config")
    async def config(request: Request):
        identity = await async_session(request, {"admin"})
        value = await body(request, {"config"})
        await run_in_threadpool(repo.set_config, identity["active_tenant"], identity["subject"], value["config"])
        return {"saved": True}

    @app.post("/api/credentials")
    async def credential(request: Request):
        identity = await async_session(request, {"admin"})
        value = await body(request, {"provider", "credentials"})
        await run_in_threadpool(repo.set_credential, identity["active_tenant"], identity["subject"], value["provider"], value["credentials"])
        return {"saved": True}

    @app.post("/api/integration")
    async def integration(request: Request):
        identity = await async_session(request, {"admin"})
        value = await body(request, {"provider", "settings", "credentials"})
        await run_in_threadpool(repo.set_integration, identity["active_tenant"], identity["subject"], value["provider"], value["settings"], value["credentials"])
        return {"saved": True}

    @app.get("/api/members")
    def list_members(request: Request):
        identity = session(request, roles={"admin"})
        return {"members": repo.member_list(identity["active_tenant"])}

    @app.post("/api/members")
    async def membership(request: Request):
        identity = await async_session(request, {"admin"})
        value = await body(request, {"subject", "role"})
        await run_in_threadpool(repo.set_member, identity["active_tenant"], identity["subject"], value["subject"], value["role"])
        return {"saved": True}

    @app.get("/api/audit")
    def audit_head(request: Request):
        identity = session(request)
        return repo.audit_verify(identity["active_tenant"])

    def download(request, kind):
        identity = session(request)
        pairs = list(request.query_params.multi_items())
        if len(pairs) > 1 or (pairs and (pairs[0][0] != "run_id" or not re.fullmatch(r"run_[a-f0-9]{32}", pairs[0][1]))):
            raise HTTPException(400, "Invalid snapshot query.")
        snapshot = repo.get_run(identity["active_tenant"], pairs[0][1] if pairs else None)
        if snapshot is None:
            raise HTTPException(404, "Snapshot not found in this workspace.")
        renderer, media, suffix = {"export": (bundle_bytes, "application/zip", "zip"),
                                   "report": (report_html, "text/html", "html"),
                                   "csv": (controls_csv, "text/csv", "csv")}[kind]
        headers = {"Content-Disposition": ("inline" if kind == "report" else "attachment") + f'; filename="cleartrail-{snapshot["id"]}.{suffix}"'}
        return Response(renderer(snapshot), media_type=media, headers=headers)

    @app.get("/api/export")
    def export(request: Request):
        return download(request, "export")

    @app.get("/api/report")
    def report(request: Request):
        return download(request, "report")

    @app.get("/api/csv")
    def csv(request: Request):
        return download(request, "csv")

    return app
