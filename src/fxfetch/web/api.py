"""Version-one LAN API. All target access enters the explicit job action."""

import asyncio
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import asdict
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..config import Settings
from ..core.classify import classify_input, normalize_entry_url
from ..core.errors import FxfetchError
from ..core.lan import client_allowed
from ..core.qr import decode_image
from ..core.tls_policy import web_tls_policy
from ..security import contained_path, password_matches, token_hash
from ..service import JobService
from ..store import Store


class BoundaryMiddleware:
    def __init__(self, app: ASGIApp, settings: Settings, store: Store):
        self.app, self.settings, self.store = app, settings, store
        self.upload_busy = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        peer = scope.get("client")
        if not client_allowed(peer[0] if peer else None, self.settings.allowed_networks):
            await JSONResponse({"error": {"code": "lan_access_only"}}, status_code=403)(scope, receive, send)
            return
        headers = {key.decode().lower(): value.decode("latin-1") for key, value in scope["headers"]}
        host = headers.get("host", "").lower()
        if host not in self.settings.allowed_hosts:
            await JSONResponse({"error": {"code": "invalid_host"}}, status_code=400)(scope, receive, send)
            return
        if scope["method"] not in ("GET", "HEAD", "OPTIONS"):
            if headers.get("origin") != f"{scope['scheme']}://{host}":
                await JSONResponse({"error": {"code": "invalid_origin"}}, status_code=403)(
                    scope, receive, send
                )
                return
        maximum = self.settings.limits.max_upload_bytes if scope["path"] == "/api/qr-images" else 64 * 1024
        try:
            if int(headers.get("content-length", "0")) > maximum:
                raise ValueError
        except ValueError:
            await JSONResponse({"error": {"code": "request_too_large"}}, status_code=413)(
                scope, receive, send
            )
            return
        # Authenticate before multipart parsing/spooling, not only inside the endpoint.
        if scope["path"].startswith("/api/") and scope["path"] not in ("/api/login", "/api/session"):
            cookie = SimpleCookie()
            try:
                cookie.load(headers.get("cookie", ""))
                token = cookie["fxfetch_session"].value if "fxfetch_session" in cookie else ""
            except CookieError:
                token = ""
            current = await run_in_threadpool(self.store.session, token_hash(token)) if token else None
            error = "authentication_required" if current is None else None
            if current and scope["method"] not in ("GET", "HEAD"):
                if not secrets.compare_digest(headers.get("x-csrf-token", ""), current["csrf"]):
                    error = "invalid_csrf"
            if error:
                await JSONResponse({"detail": error}, status_code=401 if current is None else 403)(
                    scope, receive, send
                )
                return
        uploading = scope["path"] == "/api/qr-images" and scope["method"] == "POST"
        if uploading:
            if self.upload_busy:
                await JSONResponse({"detail": "decoder_busy"}, status_code=429)(scope, receive, send)
                return
            self.upload_busy = True
            try:
                buffered = bytearray()
                deadline = time.monotonic() + 30
                while True:
                    message = await asyncio.wait_for(
                        receive(), timeout=max(0.01, deadline - time.monotonic())
                    )
                    if message["type"] == "http.disconnect":
                        raise HTTPException(400, detail="upload_disconnected")
                    chunk = message.get("body", b"")
                    if len(buffered) + len(chunk) > maximum:
                        raise HTTPException(413, detail="request_too_large")
                    buffered.extend(chunk)
                    if not message.get("more_body", False):
                        break
                original_receive = receive
                delivered = False

                async def replay_receive() -> Message:
                    nonlocal delivered
                    if not delivered:
                        delivered = True
                        return {"type": "http.request", "body": bytes(buffered), "more_body": False}
                    return await original_receive()

                receive = replay_receive
            except (HTTPException, TimeoutError) as exc:
                self.upload_busy = False
                code = str(exc.detail) if isinstance(exc, HTTPException) else "upload_timeout"
                status = exc.status_code if isinstance(exc, HTTPException) else 408
                await JSONResponse({"error": {"code": code}}, status_code=status)(scope, receive, send)
                return
        size = 0
        started = False

        async def bounded_receive() -> Message:
            nonlocal size
            message = await receive()
            size += len(message.get("body", b""))
            if size > maximum:
                raise HTTPException(413, detail="request_too_large")
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                # FastAPI's multipart parser can translate a receive exception to 400.
                if size > maximum:
                    message["status"] = 413
                extra = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cache-control", b"no-store"),
                    (
                        b"content-security-policy",
                        b"default-src 'self'; script-src 'self'; style-src 'self'; "
                        b"img-src 'self' blob: data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
                    ),
                ]
                message["headers"] = list(message.get("headers", [])) + extra
            await send(message)

        try:
            await self.app(scope, bounded_receive, guarded_send)
        except HTTPException as exc:
            if started:
                raise
            await JSONResponse({"error": {"code": str(exc.detail)}}, status_code=exc.status_code)(
                scope, receive, send
            )
        finally:
            if uploading:
                self.upload_busy = False


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(StrictModel):
    password: str = Field(min_length=1, max_length=1024)


class TLSInput(StrictModel):
    tls_policy: Literal['auto', 'strict'] = 'auto'
    ignore_tls_errors: StrictBool | None = None

    @model_validator(mode='after')
    def validate_tls_choice(self):
        self.tls_policy = web_tls_policy({key: getattr(self, key) for key in self.model_fields_set
                                         if key in {'tls_policy', 'ignore_tls_errors'}})
        return self


class JobInput(TLSInput):
    url: str | None = Field(default=None, max_length=8192)
    image_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    candidate_id: str | None = Field(default=None, max_length=80)


class PreviewInput(StrictModel):
    url: str = Field(min_length=1, max_length=8192)


class BuildInput(StrictModel):
    candidate_id: str = Field(min_length=1, max_length=80)


class ContinuationInput(TLSInput):
    candidate_id: str = Field(min_length=1, max_length=80)


class EmptyInput(StrictModel):
    pass


def create_app(settings: Settings, *, service: JobService | None = None) -> FastAPI:
    jobs = service or JobService(settings)
    decode_lock = asyncio.Lock()
    attempts: dict[str, deque[float]] = defaultdict(deque)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        jobs.start()
        try:
            yield
        finally:
            await run_in_threadpool(jobs.close)

    app = FastAPI(
        title="fxfetch", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )
    app.state.service = jobs
    app.add_middleware(BoundaryMiddleware, settings=settings, store=jobs.store)

    @app.exception_handler(FxfetchError)
    async def domain_error(request: Request, exc: FxfetchError):
        status = (
            404
            if exc.code == "not_found"
            else 409
            if exc.code
            in {
                "idempotency_conflict",
                "queue_full",
                "image_queue_full",
                "invalid_build_source",
                "invalid_continuation",
                "candidate_already_selected",
                "continuation_active",
                "continuation_limit",
                "continuation_cycle",
                "analysis_active",
                "analysis_source_unavailable",
                "analysis_queue_full",
                "analysis_limit",
            }
            else 503
            if exc.code in {"build_unavailable", "analysis_unavailable"}
            else 400
        )
        return JSONResponse({"error": {"code": exc.code, "message": exc.message}}, status_code=status)

    async def session(request: Request) -> dict:
        token = request.cookies.get("fxfetch_session", "")
        item = await run_in_threadpool(jobs.store.session, token_hash(token)) if token else None
        if item is None:
            raise HTTPException(401, detail="authentication_required")
        if request.method not in ("GET", "HEAD"):
            if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), item["csrf"]):
                raise HTTPException(403, detail="invalid_csrf")
        return item

    def idem(value: str | None) -> str:
        if value is None or not 8 <= len(value) <= 128 or not value.isascii():
            raise HTTPException(400, detail="idempotency_key_required")
        return value

    @app.get("/api/session")
    async def get_session(request: Request):
        token = request.cookies.get("fxfetch_session", "")
        value = await run_in_threadpool(jobs.store.session, token_hash(token)) if token else None
        return {
            "authenticated": bool(value),
            "csrf_token": value["csrf"] if value else None,
            "expires": value["expires"] if value else None,
        }

    @app.post("/api/login")
    async def login(value: Login, request: Request):
        address = request.client.host if request.client else "unknown"
        now = time.monotonic()
        if len(attempts) > 1024:
            attempts.clear()
        queue = attempts[address]
        while queue and queue[0] < now - 60:
            queue.popleft()
        if len(queue) >= 5:
            raise HTTPException(429, detail="login_rate_limited")
        queue.append(now)
        valid = await run_in_threadpool(password_matches, value.password, settings.password_hash)
        if not valid:
            raise HTTPException(401, detail="invalid_credentials")
        token = secrets.token_urlsafe(32)
        value_session = await run_in_threadpool(
            jobs.store.new_session, token_hash(token), settings.session_seconds
        )
        response = JSONResponse(
            {"authenticated": True, "csrf_token": value_session["csrf"], "expires": value_session["expires"]}
        )
        response.set_cookie(
            "fxfetch_session",
            token,
            max_age=settings.session_seconds,
            httponly=True,
            secure=settings.secure_cookie,
            samesite="strict",
            path="/",
        )
        return response

    @app.post("/api/logout")
    async def logout(current: Annotated[dict, Depends(session)]):
        await run_in_threadpool(jobs.store.logout, current["id"])
        response = JSONResponse({"authenticated": False})
        response.delete_cookie("fxfetch_session", path="/")
        return response

    @app.get("/api/capabilities")
    async def capabilities(current: Annotated[dict, Depends(session)]):
        return await run_in_threadpool(jobs.capabilities)

    @app.post("/api/preview")
    async def preview(value: PreviewInput, current: Annotated[dict, Depends(session)]):
        parsed = classify_input(normalize_entry_url(value.url))
        return {
            "kind": parsed.kind,
            "url": parsed.original,
            "request_url": parsed.request_url,
            "original_input": value.url,
            "normalized": parsed.original != value.url,
            "network_requests": 0,
        }

    @app.post("/api/qr-images")
    async def qr(current: Annotated[dict, Depends(session)], file: Annotated[UploadFile, File()]):
        # Authentication is evaluated before file content is used; ASGI enforces the multipart wire limit.
        if decode_lock.locked():
            await file.close()
            raise HTTPException(429, detail="decoder_busy")
        async with decode_lock:
            await run_in_threadpool(jobs.cleanup_images)
            directory = jobs.store.root / "images"
            directory.mkdir(exist_ok=True)
            path = directory / (secrets.token_hex(16) + ".image")
            try:
                size = 0
                with path.open("xb") as stream:
                    while data := await file.read(64 * 1024):
                        size += len(data)
                        if size > settings.limits.max_image_bytes:
                            raise HTTPException(413, detail="image_too_large")
                        stream.write(data)
                thumbnail = path.with_name(path.name + ".jpg")
                result = asdict(
                    await run_in_threadpool(decode_image, path, settings.limits, thumbnail_path=thumbnail)
                )
                if result["status"] == "invalid_image":
                    raise HTTPException(415, detail=result.get("reason_code") or "invalid_image")
                if (
                    result["status"] in ("failed", "timed_out", "limit_exceeded")
                    and result.get("reason_code") != "qr_candidates"
                ):
                    # No invalid/partial image is registered as an accepted upload.
                    raise HTTPException(422, detail=result.get("reason_code") or result["status"])
                identifier = await run_in_threadpool(
                    jobs.store.add_image,
                    current["id"],
                    str(path.relative_to(jobs.store.root)),
                    result,
                    settings.limits.image_ttl_seconds,
                    settings.limits.max_pending_images,
                )
                return {
                    "id": identifier,
                    **result,
                    "thumbnail_url": f"/api/qr-images/{identifier}/thumbnail"
                    if result.get("thumbnail_available")
                    else None,
                }
            except Exception:
                path.unlink(missing_ok=True)
                path.with_name(path.name + ".jpg").unlink(missing_ok=True)
                raise
            finally:
                await file.close()

    @app.get("/api/qr-images/{identifier}/thumbnail")
    async def thumbnail(identifier: str, current: Annotated[dict, Depends(session)]):
        value = await run_in_threadpool(jobs.store.image, current["id"], identifier)
        if not value["result"].get("thumbnail_available"):
            raise HTTPException(404, detail="thumbnail_unavailable")
        return FileResponse(contained_path(jobs.store.root, value["path"] + ".jpg"), media_type="image/jpeg")

    @app.post("/api/jobs", status_code=202)
    async def create_job(
        value: JobInput,
        current: Annotated[dict, Depends(session)],
        idempotency_key: Annotated[str | None, Header()] = None,
    ):
        return await run_in_threadpool(
            jobs.create_job, current["id"], idem(idempotency_key), value.model_dump(exclude={'ignore_tls_errors'})
        )

    @app.delete("/api/jobs")
    async def clear_jobs(current: Annotated[dict, Depends(session)]):
        async with decode_lock:
            return await run_in_threadpool(jobs.clear_jobs, current["id"])

    @app.get("/api/jobs")
    async def list_jobs(current: Annotated[dict, Depends(session)]):
        values = await run_in_threadpool(jobs.store.list_jobs, current["id"])
        return {
            "jobs": [
                {
                    "id": item["id"],
                    "state": item["state"],
                    "outcome": item["outcome"],
                    "created": item["created"],
                    "url": item["input"]["entry_url"],
                    "active_builds": item["active_builds"],
                    "active_analyses": item["active_analyses"],
                }
                for item in values
            ]
        }

    @app.get("/api/jobs/{identifier}")
    async def get_job(identifier: str, current: Annotated[dict, Depends(session)]):
        return await run_in_threadpool(jobs.get_job, current["id"], identifier)

    @app.post("/api/jobs/{identifier}/analyses", status_code=202)
    async def create_analysis(
        identifier: str,
        current: Annotated[dict, Depends(session)],
        value: EmptyInput | None = None,
        idempotency_key: Annotated[str | None, Header()] = None,
    ):
        return await run_in_threadpool(
            jobs.analysis.create, current["id"], identifier, idem(idempotency_key)
        )

    @app.get("/api/jobs/{identifier}/analyses/{analysis_id}")
    async def get_analysis(
        identifier: str, analysis_id: str, current: Annotated[dict, Depends(session)]
    ):
        return await run_in_threadpool(jobs.analysis.get, current["id"], identifier, analysis_id)

    @app.post("/api/jobs/{identifier}/analyses/{analysis_id}/cancel")
    async def cancel_analysis(
        identifier: str, analysis_id: str, current: Annotated[dict, Depends(session)]
    ):
        return await run_in_threadpool(jobs.analysis.cancel, current["id"], identifier, analysis_id)

    @app.get("/api/jobs/{identifier}/analyses/{analysis_id}/report.zip")
    async def analysis_report(
        identifier: str, analysis_id: str, current: Annotated[dict, Depends(session)]
    ):
        path, filename = await run_in_threadpool(
            jobs.analysis.report_file, current["id"], identifier, analysis_id
        )
        return FileResponse(
            path, media_type="application/zip", filename=filename,
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/api/jobs/{identifier}/continue", status_code=202)
    async def continue_job(
        identifier: str,
        value: ContinuationInput,
        current: Annotated[dict, Depends(session)],
        idempotency_key: Annotated[str | None, Header()] = None,
    ):
        return await run_in_threadpool(
            jobs.continue_job, current["id"], identifier, idem(idempotency_key), value.candidate_id,
            tls_policy=value.tls_policy,
        )

    @app.post("/api/jobs/{identifier}/cancel")
    async def cancel_job(identifier: str, current: Annotated[dict, Depends(session)]):
        return await run_in_threadpool(jobs.cancel_job, current["id"], identifier)

    @app.post("/api/jobs/{identifier}/web-apk-builds", status_code=202)
    async def build(
        identifier: str,
        value: BuildInput,
        current: Annotated[dict, Depends(session)],
        idempotency_key: Annotated[str | None, Header()] = None,
    ):
        return await run_in_threadpool(
            jobs.create_build, current["id"], identifier, idem(idempotency_key), value.candidate_id
        )

    @app.get("/api/jobs/{identifier}/web-apk-builds/{build_id}")
    async def get_build(identifier: str, build_id: str, current: Annotated[dict, Depends(session)]):
        return await run_in_threadpool(jobs.get_build, current["id"], identifier, build_id)

    @app.post("/api/jobs/{identifier}/web-apk-builds/{build_id}/cancel")
    async def cancel_build(identifier: str, build_id: str, current: Annotated[dict, Depends(session)]):
        return await run_in_threadpool(jobs.cancel_build, current["id"], identifier, build_id)

    @app.get("/api/jobs/{identifier}/artifacts/{artifact_id}")
    async def artifact(identifier: str, artifact_id: str, current: Annotated[dict, Depends(session)]):
        value = await run_in_threadpool(jobs.store.artifact, current["id"], identifier, artifact_id)
        path = contained_path(jobs.store.root, value["path"])
        return FileResponse(path, media_type="application/octet-stream", filename=value["filename"])

    @app.get("/api/jobs/{identifier}/rejected-files/{file_id}")
    async def rejected_file(identifier: str, file_id: str, current: Annotated[dict, Depends(session)]):
        stream, metadata = await run_in_threadpool(jobs.rejected_file, current['id'], identifier, file_id)

        def chunks():
            try:
                remaining = metadata['size']
                while remaining and (block := stream.read(min(65536, remaining))):
                    remaining -= len(block)
                    yield block
            finally:
                stream.close()

        return StreamingResponse(
            chunks(), media_type='application/octet-stream', background=BackgroundTask(stream.close),
            headers={'Cache-Control': 'no-store', 'Content-Length': str(metadata['size']),
                     'Content-Disposition': f'attachment; filename="{metadata["filename"]}"',
                     'X-Content-Type-Options': 'nosniff'},
        )

    @app.get("/api/jobs/{identifier}/data-package")
    async def data_package(identifier: str, current: Annotated[dict, Depends(session)]):
        path, filename = await run_in_threadpool(
            jobs.data_package_file, current["id"], identifier
        )
        return FileResponse(
            path,
            media_type="application/zip",
            filename=filename,
            headers={"Cache-Control": "no-store"},
        )

    static = Path(__file__).parent / "static"
    if static.is_dir():
        app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/")
    async def index():
        return FileResponse(static / "index.html", media_type="text/html")

    return app
